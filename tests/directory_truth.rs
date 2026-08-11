//! Truth-surface contract for authoritative read failures and population bounds.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use census::directory::{Identity, InMemoryDirectory};
use census::fixtures::{synthetic_state, FailingDirectory, FailingStore, OverflowDirectory};
use census::handlers::people::{assemble_people, ReadError};
use census::store::{Group, InMemoryStore, Store};
use census::{app, AppState};
use tower::ServiceExt;

const PRIVATE_DETAIL: &str = "sqlx fixture host=private.example.invalid secret=not-public";

#[tokio::test]
async fn assemble_people_distinguishes_identity_and_profile_failures() {
    let identity_failure = synthetic_state(
        Arc::new(FailingDirectory::new(PRIVATE_DETAIL)),
        Arc::new(InMemoryStore::new()),
    );
    match assemble_people(&identity_failure, None).await {
        Err(ReadError::Identity(_)) => {}
        Err(ReadError::Store(_)) => panic!("identity failure was mislabeled as store failure"),
        Ok(_) => panic!("identity failure became a healthy directory"),
    }

    let profile_failure = synthetic_state(
        one_person_directory(),
        Arc::new(FailingStore::profile_reads(PRIVATE_DETAIL)),
    );
    match assemble_people(&profile_failure, None).await {
        Err(ReadError::Store(_)) => {}
        Err(ReadError::Identity(_)) => panic!("profile failure was mislabeled as identity failure"),
        Ok(_) => panic!("profile failure became a healthy directory"),
    }
}

#[tokio::test]
async fn identity_outage_orients_at_root_but_fails_closed_on_dossiers_and_feed() {
    let store = Arc::new(InMemoryStore::new());
    let group = fixture_group();
    store.create_group(&group).await.expect("seed group");
    let state = synthetic_state(Arc::new(FailingDirectory::new(PRIVATE_DETAIL)), store);

    let (status, body) = call(
        &state,
        get_auth("/", "fixture-viewer", "viewer@example.invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Identity source unavailable"));
    assert!(body.contains("roll is withheld"));
    assert!(
        !body.contains(r#"href="/u/fixture-viewer""#),
        "gateway chrome may name the viewer, but the withheld roll must not fabricate a row"
    );
    assert!(!body.contains("1 person"));
    assert!(!body.contains(PRIVATE_DETAIL));

    let (status, body) = call(&state, get("/u/fixture-viewer")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("identity source unavailable"));
    assert!(!body.contains(PRIVATE_DETAIL));

    let (status, body) = call(&state, get("/groups")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Identity source unavailable"));
    assert!(body.contains("Fixture Group"));

    let (status, body) = call(&state, get("/groups/fixture-group")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("identity source unavailable"));
    assert!(!body.contains(PRIVATE_DETAIL));

    let (status, body) = call(&state, get("/api/people")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("safe JSON envelope"),
        serde_json::json!({
            "error": "unavailable",
            "detail": "identity source unavailable"
        })
    );
    assert!(!body.contains(PRIVATE_DETAIL));
}

#[tokio::test]
async fn profile_and_group_outages_follow_the_frozen_degrade_map() {
    let profile_failure = synthetic_state(
        one_person_directory(),
        Arc::new(FailingStore::profile_reads(PRIVATE_DETAIL)),
    );

    let (status, body) = call(&profile_failure, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Profiles unavailable"));
    assert!(body.contains("person@example.invalid"));
    assert!(!body.contains(PRIVATE_DETAIL));

    for path in ["/u/fixture-person", "/groups", "/api/people"] {
        let (status, body) = call(&profile_failure, get(path)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert!(
            !body.contains(PRIVATE_DETAIL),
            "{path} leaked backend detail"
        );
    }

    let group_failure = synthetic_state(
        one_person_directory(),
        Arc::new(FailingStore::group_reads(PRIVATE_DETAIL)),
    );
    let (status, body) = call(&group_failure, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Groups unavailable"));
    assert!(!body.contains(PRIVATE_DETAIL));

    let (status, body) = call(&group_failure, get("/groups")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("group store unavailable"));
    assert!(!body.contains(PRIVATE_DETAIL));

    let (status, body) = call(&group_failure, get("/api/people")).await;
    assert_eq!(status, StatusCode::OK, "people feed does not read groups");
    assert!(body.contains("fixture-person"));

    let both_failure = synthetic_state(
        Arc::new(FailingDirectory::new(PRIVATE_DETAIL)),
        Arc::new(FailingStore::all_reads(PRIVATE_DETAIL)),
    );
    let (status, body) = call(&both_failure, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Directory sources unavailable"));
    assert!(!body.contains(PRIVATE_DETAIL));
}

#[tokio::test]
async fn proven_empty_and_real_no_results_are_not_outages() {
    let empty = synthetic_state(
        Arc::new(InMemoryDirectory::new()),
        Arc::new(InMemoryStore::new()),
    );
    let (status, body) = call(
        &empty,
        get_auth("/", "fixture-viewer", "viewer@example.invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0 people enumerated by the identity source"));
    assert!(body.contains("viewer@example.invalid"));
    assert!(body.contains("prov prov--provisional"));
    assert!(body.contains("No one else is on the roll yet"));
    assert!(!body.contains("unavailable"));

    let populated = synthetic_state(
        Arc::new(OverflowDirectory::new(2)),
        Arc::new(InMemoryStore::new()),
    );
    let (status, body) = call(&populated, get("/?q=not-present")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("0 of 2 people"));
    assert!(body.contains(r#"<li class="roll__empty">No matches</li>"#));
    assert!(!body.contains("unavailable"));

    let (status, _) = call(&populated, get("/u/fixture-missing")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn population_bound_copy_is_exact_at_1999_2000_and_2001() {
    let cases = [
        (1_999, "1,999 people on the roll", false),
        (2_000, "2,000 people on the roll", false),
        (2_001, "Showing the first 2,000 people", true),
    ];

    for (count, expected, overflow) in cases {
        let state = synthetic_state(
            Arc::new(OverflowDirectory::new(count)),
            Arc::new(InMemoryStore::new()),
        );
        let (status, body) = call(&state, get("/")).await;
        assert_eq!(status, StatusCode::OK, "count={count}");
        assert!(
            body.contains(expected),
            "count={count}: missing {expected:?}"
        );
        assert_eq!(
            body.contains(
                "More people exist than shown — the roll stops at a survey bound of 2,000."
            ),
            overflow,
            "count={count}: overflow note disagrees with proof"
        );
        assert_eq!(body.contains("class=\"bound\""), overflow, "count={count}");
        assert_forbidden_copy_absent(&body, count);
    }
}

fn assert_forbidden_copy_absent(body: &str, count: usize) {
    let lower = body.to_lowercase();
    for forbidden in [
        "no people found",
        "completeness not verified",
        "membership changes are audited",
        "verified",
        "approved",
        "seniority",
        "online",
        "owner",
        "steward",
    ] {
        assert!(
            !lower.contains(forbidden),
            "count={count}: forbidden wording {forbidden:?}"
        );
    }
    for suffix in ["1,999+", "2,000+", "people+", "people +"] {
        assert!(
            !lower.contains(suffix),
            "count={count}: unproven plus-suffix {suffix:?}"
        );
    }
}

fn one_person_directory() -> Arc<InMemoryDirectory> {
    Arc::new(InMemoryDirectory::with_identities(vec![Identity {
        sub: "fixture-person".to_string(),
        email: "person@example.invalid".to_string(),
    }]))
}

fn fixture_group() -> Group {
    Group {
        id: "fixture-group".to_string(),
        name: "Fixture Group".to_string(),
        description: "Synthetic only".to_string(),
        created_at: 1_700_000_000,
    }
}

async fn call(state: &AppState, request: Request<Body>) -> (StatusCode, String) {
    let response = app(state.clone()).oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("GET")
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .expect("authenticated GET")
}
