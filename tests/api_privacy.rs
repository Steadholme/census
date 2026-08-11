//! Response privacy, wire-shape, and error-redaction contract.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use census::directory::{Identity, InMemoryDirectory};
use census::fixtures::{synthetic_state, FailingDirectory, FailingStore};
use census::store::{Group, InMemoryStore, Profile, Store};
use census::{app, AppState};
use tower::ServiceExt;

const PRIVATE_DETAIL: &str =
    "sqlx StoreError host=private.example.invalid password=fixture-not-public";
const CSRF: &str = "fixture-csrf-token";

#[tokio::test]
async fn every_route_has_the_frozen_cache_policy_and_no_vary() {
    let state = seeded_state().await;
    let cases = [
        (Method::GET, "/healthz", "no-store"),
        (Method::GET, "/", "private, no-store"),
        (Method::GET, "/u/fixture-person", "private, no-store"),
        (Method::POST, "/api/profile", "private, no-store"),
        (Method::GET, "/groups", "private, no-store"),
        (Method::GET, "/groups/fixture-group", "private, no-store"),
        (Method::POST, "/api/groups", "private, no-store"),
        (
            Method::POST,
            "/api/groups/fixture-group/members",
            "private, no-store",
        ),
        (
            Method::POST,
            "/api/groups/fixture-group/children",
            "private, no-store",
        ),
        (Method::GET, "/api/people", "private, no-store"),
        (Method::GET, "/not-a-route", "private, no-store"),
    ];

    for (method, uri, expected) in cases {
        let response = call(&state, request(method, uri, Body::empty())).await;
        assert_eq!(
            response.header(header::CACHE_CONTROL),
            Some(expected),
            "{uri} cache policy"
        );
        assert!(
            !response.headers.contains_key(header::VARY),
            "{uri} must not emit Vary"
        );
    }
}

#[tokio::test]
async fn redirects_and_curated_errors_keep_the_same_private_contract() {
    let state = seeded_state().await;
    let cases = [
        authenticated_form(
            "/api/profile",
            &format!("display_name=Fixture&csrf_token={CSRF}"),
        ),
        authenticated_form("/api/groups", &format!("name=&csrf_token={CSRF}")),
        authenticated_form(
            "/api/groups",
            &format!("name=Fixture+Group&csrf_token={CSRF}"),
        ),
        request(Method::GET, "/u/fixture-missing", Body::empty()),
    ];
    let expected_statuses = [
        StatusCode::SEE_OTHER,
        StatusCode::BAD_REQUEST,
        StatusCode::CONFLICT,
        StatusCode::NOT_FOUND,
    ];

    for (request, expected_status) in cases.into_iter().zip(expected_statuses) {
        let response = call(&state, request).await;
        assert_eq!(response.status, expected_status);
        assert_eq!(
            response.header(header::CACHE_CONTROL),
            Some("private, no-store")
        );
        assert!(!response.headers.contains_key(header::VARY));
    }

    let unauthorized = call(&state, request(Method::POST, "/api/groups", Body::empty())).await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized.header(header::WWW_AUTHENTICATE),
        Some("Bearer")
    );
}

#[tokio::test]
async fn people_feed_has_exactly_ten_safe_dto_keys() {
    let state = seeded_state().await;
    let response = call(&state, request(Method::GET, "/api/people", Body::empty())).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.header(header::CACHE_CONTROL),
        Some("private, no-store")
    );
    assert!(!response.headers.contains_key(header::VARY));

    let value: serde_json::Value = serde_json::from_str(&response.body).expect("people JSON");
    assert_eq!(value["count"], 1);
    let person = value["people"]
        .as_array()
        .and_then(|people| people.first())
        .and_then(serde_json::Value::as_object)
        .expect("one DTO");
    let actual: BTreeSet<&str> = person.keys().map(String::as_str).collect();
    let expected = BTreeSet::from([
        "sub",
        "email",
        "display_name",
        "title",
        "department",
        "manager_sub",
        "phone",
        "location",
        "timezone",
        "locale",
    ]);
    assert_eq!(actual, expected);
    assert_eq!(person.len(), 10);
    assert!(!response.body.contains("password"));
    assert!(!response.body.contains("credential"));
}

#[tokio::test]
async fn unavailable_feed_is_safe_json_for_each_authoritative_source() {
    let cases: [(AppState, &str); 2] = [
        (
            synthetic_state(
                Arc::new(FailingDirectory::new(PRIVATE_DETAIL)),
                Arc::new(InMemoryStore::new()),
            ),
            "identity source unavailable",
        ),
        (
            synthetic_state(
                fixture_directory(),
                Arc::new(FailingStore::profile_reads(PRIVATE_DETAIL)),
            ),
            "profile store unavailable",
        ),
    ];

    for (state, detail) in cases {
        let response = call(&state, request(Method::GET, "/api/people", Body::empty())).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.header(header::CACHE_CONTROL),
            Some("private, no-store")
        );
        assert!(!response.headers.contains_key(header::VARY));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response.body).expect("503 JSON"),
            serde_json::json!({"error": "unavailable", "detail": detail})
        );
        assert_private_detail_absent(&response.body);
    }
}

#[tokio::test]
async fn write_failure_is_a_generic_redacted_500() {
    let state = synthetic_state(
        fixture_directory(),
        Arc::new(FailingStore::writes(PRIVATE_DETAIL)),
    );
    let form = format!("display_name=Fixture&csrf_token={CSRF}");
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/profile")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "fixture-person")
        .header("x-auth-email", "person@example.invalid")
        .body(Body::from(form))
        .expect("write request");
    let response = call(&state, request).await;

    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.header(header::CACHE_CONTROL),
        Some("private, no-store")
    );
    assert!(!response.headers.contains_key(header::VARY));
    assert!(response
        .body
        .contains("Something went wrong — nothing was saved."));
    assert_private_detail_absent(&response.body);
}

async fn seeded_state() -> AppState {
    let store = Arc::new(InMemoryStore::new());
    store
        .upsert_profile(&Profile {
            sub: "fixture-person".to_string(),
            display_name: "Fixture Person".to_string(),
            title: "Cartographer".to_string(),
            department: "Research".to_string(),
            manager_sub: String::new(),
            phone: "000".to_string(),
            location: "Fixture Room".to_string(),
            timezone: "Etc/UTC".to_string(),
            locale: "en".to_string(),
            bio: "Synthetic profile".to_string(),
            avatar_url: String::new(),
            updated_at: 1_700_000_000,
        })
        .await
        .expect("seed profile");
    store
        .create_group(&Group {
            id: "fixture-group".to_string(),
            name: "Fixture Group".to_string(),
            description: "Synthetic group".to_string(),
            created_at: 1_700_000_001,
        })
        .await
        .expect("seed group");
    synthetic_state(fixture_directory(), store)
}

fn fixture_directory() -> Arc<InMemoryDirectory> {
    Arc::new(InMemoryDirectory::with_identities(vec![Identity {
        sub: "fixture-person".to_string(),
        email: "person@example.invalid".to_string(),
    }]))
}

struct ResponseView {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl ResponseView {
    fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

async fn call(state: &AppState, request: Request<Body>) -> ResponseView {
    let response = app(state.clone()).oneshot(request).await.expect("response");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    ResponseView {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn request(method: Method, uri: &str, body: Body) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if method == Method::POST {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    builder.body(body).expect("request")
}

fn authenticated_form(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"))
        .header("x-auth-subject", "fixture-person")
        .header("x-auth-email", "person@example.invalid")
        .body(Body::from(body.to_string()))
        .expect("authenticated form")
}

fn assert_private_detail_absent(body: &str) {
    for private in [
        PRIVATE_DETAIL,
        "sqlx",
        "StoreError",
        "private.example.invalid",
        "fixture-not-public",
    ] {
        assert!(!body.contains(private), "response leaked {private:?}");
    }
}
