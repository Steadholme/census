//! Cross-writer DOM contract for the Living Organization Atlas fragments.
//!
//! These assertions intentionally bind Rust-emitted fragments to the Step 5 template skeleton.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use census::directory::{Identity, InMemoryDirectory};
use census::fixtures::{synthetic_state, FailingStore, OverflowDirectory};
use census::store::{Group, GroupChild, InMemoryStore, Membership, Profile, Store};
use census::{app, AppState};
use tower::ServiceExt;

#[tokio::test]
async fn directory_fragments_keep_list_provenance_legend_and_contour_semantics() {
    let state = atlas_state().await;
    let body = ok_body(
        &state,
        get_auth("/", "fixture-viewer", "viewer@example.invalid"),
    )
    .await;

    assert!(body.contains(r#"<ul class="roll">"#));
    assert!(body.contains(r#"<li class="roll__row">"#));
    assert!(body.contains(r#"<span class="roll__index" aria-hidden="true">"#));
    assert!(body.contains(r#"class="prov prov--provisional""#));
    assert!(body.contains(r#"<section class="legend" aria-label="Provenance legend">"#));
    assert!(body.contains(r#"<li class="legend__item">"#));
    assert!(body.contains("Unmarked rows are enumerated by the identity source."));
    assert!(body.contains(r#"<span class="contour__open">declared manager not shown</span>"#));
    assert!(body.contains(r#"<ul class="org-tree" aria-label="Declared reporting lines">"#));
    assert!(!body.contains(r#"class="prov prov--enumerated""#));
}

#[tokio::test]
async fn dossier_and_group_fragments_expose_exception_provenance_via_and_readonly_state() {
    let state = atlas_state().await;

    let profile_only = ok_body(&state, get("/u/fixture-profile-only")).await;
    assert!(profile_only.contains(r#"class="prov-note prov--profile-only" role="note""#));
    assert!(profile_only.contains("Profile-only"));

    let detail = ok_body(
        &state,
        get_auth(
            "/groups/fixture-parent",
            "fixture-viewer",
            "viewer@example.invalid",
        ),
    )
    .await;
    assert!(detail.contains(r#"<ul class="members">"#));
    assert!(detail.contains(r#"<li class="member">"#));
    assert!(detail.contains(r#"class="prov prov--profile-only""#));
    assert!(detail.contains(r#"class="prov prov--subject-only""#));
    assert!(detail.contains(r#"class="member__via""#));
    assert!(detail.contains("via Child Group"));

    let groups_readonly = ok_body(&state, get("/groups")).await;
    assert!(groups_readonly.contains(r#"<p class="readonly-note">"#));
    assert!(groups_readonly
        .contains("No gateway identity accompanied this request — this page is read-only."));
    assert!(!groups_readonly.contains(r#"<form class="member-add""#));

    let detail_readonly = ok_body(&state, get("/groups/fixture-parent")).await;
    assert!(detail_readonly.contains(r#"<p class="readonly-note">"#));
    assert!(!detail_readonly.contains(r#"<form class="member-add""#));
}

#[tokio::test]
async fn outage_and_overflow_fragments_have_frozen_live_region_roles() {
    let outage = synthetic_state(
        Arc::new(InMemoryDirectory::with_identities(vec![identity(
            "fixture-person",
            "person@example.invalid",
        )])),
        Arc::new(FailingStore::profile_reads("private synthetic detail")),
    );
    let body = ok_body(&outage, get("/")).await;
    assert!(body.contains(
        r#"<section class="alert alert--down banner" role="status" aria-labelledby="banner-title">"#
    ));
    assert!(body.contains(r#"<h2 id="banner-title">Profiles unavailable</h2>"#));

    let overflow = synthetic_state(
        Arc::new(OverflowDirectory::new(2_001)),
        Arc::new(InMemoryStore::new()),
    );
    let body = ok_body(&overflow, get("/")).await;
    assert!(body.contains(r#"<p class="bound" role="note">"#));
    assert!(body.contains(r#"<span class="bound__mark" aria-hidden="true"></span>"#));
    assert!(
        body.contains("More people exist than shown — the roll stops at a survey bound of 2,000.")
    );
}

async fn atlas_state() -> AppState {
    let store = Arc::new(InMemoryStore::new());
    for profile in [
        Profile {
            sub: "fixture-enumerated".to_string(),
            display_name: "Enumerated Person".to_string(),
            title: "Contour recorder".to_string(),
            department: "Atlas".to_string(),
            manager_sub: "fixture-manager-not-shown".to_string(),
            phone: String::new(),
            location: "Fixture Room".to_string(),
            timezone: "Etc/UTC".to_string(),
            locale: "en".to_string(),
            bio: "Synthetic record".to_string(),
            avatar_url: String::new(),
            updated_at: 1_700_000_000,
        },
        Profile {
            sub: "fixture-profile-only".to_string(),
            display_name: "Profile Only Person".to_string(),
            title: "Archivist".to_string(),
            department: "Atlas".to_string(),
            manager_sub: String::new(),
            phone: String::new(),
            location: "Fixture Room".to_string(),
            timezone: "Etc/UTC".to_string(),
            locale: "en".to_string(),
            bio: "Synthetic record".to_string(),
            avatar_url: String::new(),
            updated_at: 1_700_000_001,
        },
    ] {
        store.upsert_profile(&profile).await.expect("seed profile");
    }

    let parent = Group {
        id: "fixture-parent".to_string(),
        name: "Parent Group".to_string(),
        description: "Synthetic parent".to_string(),
        created_at: 1_700_000_002,
    };
    let child = Group {
        id: "fixture-child".to_string(),
        name: "Child Group".to_string(),
        description: "Synthetic child".to_string(),
        created_at: 1_700_000_003,
    };
    store.create_group(&parent).await.expect("seed parent");
    store.create_group(&child).await.expect("seed child");
    store
        .add_group_child(&GroupChild {
            parent_group_id: parent.id.clone(),
            child_group_id: child.id.clone(),
            added_at: 1_700_000_004,
        })
        .await
        .expect("seed nested group");
    for membership in [
        Membership {
            group_id: child.id.clone(),
            sub: "fixture-profile-only".to_string(),
            role: "archivist".to_string(),
            joined_at: 1_700_000_005,
        },
        Membership {
            group_id: child.id,
            sub: "fixture-subject-only".to_string(),
            role: "correspondent".to_string(),
            joined_at: 1_700_000_006,
        },
    ] {
        store
            .add_member(&membership)
            .await
            .expect("seed membership");
    }

    synthetic_state(
        Arc::new(InMemoryDirectory::with_identities(vec![identity(
            "fixture-enumerated",
            "enumerated@example.invalid",
        )])),
        store,
    )
}

fn identity(sub: &str, email: &str) -> Identity {
    Identity {
        sub: sub.to_string(),
        email: email.to_string(),
    }
}

async fn ok_body(state: &AppState, request: Request<Body>) -> String {
    let response = app(state.clone()).oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    String::from_utf8_lossy(&bytes).into_owned()
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
