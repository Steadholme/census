//! In-memory workforce authority, machine-auth and directory integration contract.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use census::config::Config;
use census::directory::{Identity, InMemoryDirectory};
use census::store::{InMemoryStore, Store};
use census::{app, build_dev_state, now_secs, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

const TOKEN: &str = "census-workforce-fixture-token-0000000000000001";
const CSRF: &str = "workforce-csrf-fixture";

#[tokio::test]
async fn machine_auth_monotonic_replay_and_cursor_contract() {
    let (state, _) = workforce_state();
    let initial = intake("evt-1", "dedupe-1", 1, "active", "Engineering", 10);

    let no_token = call(
        &state,
        json_request(Method::POST, "/internal/v1/workforce/intake", &initial)
            .header("x-auth-subject", "u_admin")
            .body(Body::from(initial.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(no_token.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        no_token.header(header::WWW_AUTHENTICATE),
        Some("Bearer realm=\"census-workforce\"")
    );

    let wrong = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &initial,
            "wrong",
        ),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);

    let zero_version = intake("evt-zero", "dedupe-zero", 0, "active", "Engineering", 10);
    let zero_version = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &zero_version,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(zero_version.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(&zero_version)["code"],
        "source_version_must_be_positive"
    );

    let created = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &initial,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let created_body: Value = serde_json::from_str(&created.body).unwrap();
    assert_eq!(created_body["replayed"], false);
    assert_eq!(created_body["change"]["cursor"], 1);
    assert_eq!(created_body["change"]["kind"], "joiner");
    assert_eq!(created_body["record"]["subject"], "user:u_alice");
    assert_eq!(created_body["record"]["keystone_subject"], "u_alice");

    let replay = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &initial,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(replay.status, StatusCode::OK);
    let replay_body: Value = serde_json::from_str(&replay.body).unwrap();
    assert_eq!(replay_body["replayed"], true);
    assert_eq!(replay_body["change"]["cursor"], 1);

    let changed_same_event = intake("evt-1", "dedupe-1", 1, "active", "Finance", 10);
    let conflict = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &changed_same_event,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(json_body(&conflict)["code"], "workforce_event_conflict");

    let stale = intake("evt-stale", "dedupe-stale", 1, "leave", "Engineering", 11);
    let stale = call(
        &state,
        authorized_json(Method::POST, "/internal/v1/workforce/intake", &stale, TOKEN),
    )
    .await;
    assert_eq!(stale.status, StatusCode::CONFLICT);
    assert_eq!(json_body(&stale)["code"], "workforce_stale_version");

    let suspended = intake("evt-2", "dedupe-2", 2, "suspended", "Engineering", 12);
    let moved = call(
        &state,
        authorized_json(
            Method::PUT,
            "/internal/v1/workforce/records/user:u_alice",
            &suspended,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(moved.status, StatusCode::OK);
    assert_eq!(json_body(&moved)["change"]["kind"], "mover");

    let terminated = intake("evt-3", "dedupe-3", 3, "terminated", "Engineering", 13);
    let leaver = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &terminated,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(leaver.status, StatusCode::OK);
    assert_eq!(json_body(&leaver)["change"]["kind"], "leaver");

    let first_page = call(
        &state,
        authorized_empty(
            Method::GET,
            "/internal/v1/workforce/changes?after=0&limit=1",
            TOKEN,
        ),
    )
    .await;
    assert_eq!(first_page.status, StatusCode::OK);
    let first_page = json_body(&first_page);
    assert_eq!(first_page["items"].as_array().unwrap().len(), 1);
    assert_eq!(first_page["next_cursor"], 1);
    assert_eq!(first_page["has_more"], true);

    let leavers = call(
        &state,
        authorized_empty(
            Method::GET,
            "/internal/v1/workforce/changes?after=0&limit=10&kind=leaver&subject=user:u_alice",
            TOKEN,
        ),
    )
    .await;
    let leavers = json_body(&leavers);
    assert_eq!(leavers["items"].as_array().unwrap().len(), 1);
    assert_eq!(leavers["items"][0]["cursor"], 3);
    assert_eq!(leavers["items"][0]["old_state"]["source_version"], 2);
    assert_eq!(leavers["items"][0]["new_state"]["source_version"], 3);
    assert_eq!(leavers["next_cursor"], 3);

    let mismatch = call(
        &state,
        authorized_json(
            Method::PUT,
            "/internal/v1/workforce/records/user:u_bob",
            &terminated,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert_eq!(json_body(&mismatch)["code"], "subject_path_mismatch");
}

#[tokio::test]
async fn workforce_and_keystone_state_filter_directory_and_own_org_fields() {
    let (state, store) = workforce_state();
    let active = intake(
        "evt-active",
        "dedupe-active",
        1,
        "active",
        "Authoritative",
        now_secs() - 1,
    );
    let response = call(
        &state,
        authorized_json(
            Method::POST,
            "/internal/v1/workforce/intake",
            &active,
            TOKEN,
        ),
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED);

    let profile_form = "display_name=Alice&title=Engineer&department=Attacker&manager_sub=&phone=&location=&timezone=&locale=en&avatar_url=&bio=&csrf_token=workforce-csrf-fixture";
    let profile = Request::builder()
        .method(Method::POST)
        .uri("/api/profile")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "u_alice")
        .header("x-auth-email", "alice@example.invalid")
        .body(Body::from(profile_form))
        .unwrap();
    let saved = call(&state, profile).await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER);
    let stored_profile = store
        .get_profile("u_alice")
        .await
        .unwrap()
        .expect("profile");
    assert_eq!(stored_profile.department, "Authoritative");
    assert_eq!(stored_profile.manager_sub, "u_bob");

    let feed = call(
        &state,
        Request::builder()
            .uri("/api/people")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let feed_body = json_body(&feed);
    assert_eq!(feed_body["count"], 2);
    let alice = feed_body["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|person| person["sub"] == "u_alice")
        .unwrap();
    assert_eq!(alice["department"], "Authoritative");
    assert_eq!(alice["manager_sub"], "u_bob");

    // A future leaver record locks org facts immediately but does not remove the person before
    // its effective time; Access Governance consumes the event now and schedules due-at removal.
    let mut future_bob = intake(
        "evt-future-bob",
        "dedupe-future-bob",
        1,
        "terminated",
        "Future Authority",
        now_secs() + 3600,
    );
    future_bob["subject"] = json!("user:u_bob");
    future_bob["manager_subject"] = Value::Null;
    future_bob["provenance"]["record_id"] = json!("worker-bob");
    assert_eq!(
        call(
            &state,
            authorized_json(
                Method::POST,
                "/internal/v1/workforce/intake",
                &future_bob,
                TOKEN,
            ),
        )
        .await
        .status,
        StatusCode::CREATED
    );
    let future_feed = call(
        &state,
        Request::builder()
            .uri("/api/people")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let future_body = json_body(&future_feed);
    assert_eq!(future_body["count"], 2);
    let bob = future_body["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|person| person["sub"] == "u_bob")
        .unwrap();
    assert_eq!(bob["department"], "Future Authority");

    let suspended = intake(
        "evt-suspend",
        "dedupe-suspend",
        2,
        "suspended",
        "Authoritative",
        now_secs() - 1,
    );
    assert_eq!(
        call(
            &state,
            authorized_json(
                Method::POST,
                "/internal/v1/workforce/intake",
                &suspended,
                TOKEN,
            ),
        )
        .await
        .status,
        StatusCode::OK
    );
    let feed = call(
        &state,
        Request::builder()
            .uri("/api/people")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let feed_body = json_body(&feed);
    assert_eq!(feed_body["count"], 1);
    assert!(!feed.body.contains("alice@example.invalid"));

    let mut disabled_state = state.clone();
    disabled_state.directory = Arc::new(InMemoryDirectory::with_disabled_subjects(
        vec![
            identity("u_alice", "alice@example.invalid"),
            identity("u_bob", "bob@example.invalid"),
        ],
        ["u_bob".to_string()],
    ));
    let disabled_feed = call(
        &disabled_state,
        Request::builder()
            .uri("/api/people")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(json_body(&disabled_feed)["count"], 0);
    assert!(!disabled_feed.body.contains("bob@example.invalid"));
}

fn workforce_state() -> (AppState, Arc<InMemoryStore>) {
    let store = Arc::new(InMemoryStore::new());
    let mut state = build_dev_state();
    state.config = Arc::new(Config::dev().with_workforce_service_token(TOKEN));
    state.store = store.clone();
    state.directory = Arc::new(InMemoryDirectory::with_identities(vec![
        identity("u_alice", "alice@example.invalid"),
        identity("u_bob", "bob@example.invalid"),
    ]));
    (state, store)
}

fn identity(sub: &str, email: &str) -> Identity {
    Identity {
        sub: sub.to_string(),
        email: email.to_string(),
    }
}

fn intake(
    event_id: &str,
    dedupe_key: &str,
    version: i64,
    status: &str,
    department: &str,
    effective_at: i64,
) -> Value {
    json!({
        "event_id": event_id,
        "dedupe_key": dedupe_key,
        "correlation_id": format!("corr-{event_id}"),
        "subject": "user:u_alice",
        "employment_status": status,
        "manager_subject": "user:u_bob",
        "org_unit_id": "org-engineering",
        "department": department,
        "effective_at": effective_at,
        "source": "fixture-hris",
        "source_version": version,
        "observed_at": effective_at,
        "provenance": {
            "system": "fixture-hris",
            "record_id": "worker-alice",
            "attributes": {"tenant": "fixture"}
        }
    })
}

fn json_request(method: Method, uri: &str, value: &Value) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, value.to_string().len())
}

fn authorized_json(method: Method, uri: &str, value: &Value, token: &str) -> Request<Body> {
    json_request(method, uri, value)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(value.to_string()))
        .unwrap()
}

fn authorized_empty(method: Method, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

struct ResponseData {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl ResponseData {
    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn call(state: &AppState, request: Request<Body>) -> ResponseData {
    let response = app(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    ResponseData {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn json_body(response: &ResponseData) -> Value {
    serde_json::from_str(&response.body).unwrap()
}
