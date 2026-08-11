//! Synthetic-only Census fixture server for the browser truth gate.
//!
//! Select a deterministic scenario with `CENSUS_FIXTURE`; the server always listens on
//! `127.0.0.1:9131` and never connects to estate services or databases.

use std::net::SocketAddr;
use std::sync::Arc;

use census::directory::{Directory, Identity, InMemoryDirectory};
use census::fixtures::{synthetic_state, FailingDirectory, FailingStore, OverflowDirectory};
use census::store::{Group, GroupChild, InMemoryStore, Membership, Profile, Store};
use census::AppState;

const LISTEN_ADDR: &str = "127.0.0.1:9131";
const BACKEND_DETAIL: &str = "synthetic backend detail that must remain log-only";
const TEMPLATE_MARKER_CORPUS: &str = "{{CSS}} {{TOPBAR}} {{BANNER}} {{BOUNDARY}} {{LEGEND}} {{QUERY}} {{DEPARTMENT_OPTIONS}} {{GROUP_OPTIONS}} {{COUNT}} {{ROWS}} {{GROUPS}} {{ORG_CHART}} {{NAME_TEXT}} {{AVATAR}} {{NAME}} {{TITLE_LINE}} {{EMAIL_LINE}} {{UPDATED}} {{PROVENANCE}} {{DETAILS}} {{REPORTS}} {{BIO}} {{EDIT}} {{CREATE_FORM}} {{CSRF}} {{CARDS}} {{MEMBER_FORM}} {{CHILD_FORM}} {{GROUP_ID}} {{DESCRIPTION}} {{CREATED}} {{DIRECT_COUNT}} {{RESOLVED_COUNT}} {{DIRECT_MEMBERS}} {{RESOLVED_MEMBERS}} {{CHILD_GROUPS}} {{PARENT_GROUPS}} {{PERSON_OPTIONS}} {{CHILD_GROUP_OPTIONS}}";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let scenario = std::env::var("CENSUS_FIXTURE").unwrap_or_else(|_| "populated".to_string());
    let state = match build_scenario(&scenario).await {
        Some(state) => state,
        None => {
            eprintln!(
                "unknown CENSUS_FIXTURE={scenario}; expected one of: {}",
                SCENARIOS.join(",")
            );
            std::process::exit(2);
        }
    };

    let addr: SocketAddr = LISTEN_ADDR.parse().expect("fixed fixture address is valid");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|error| panic!("failed to bind fixture server at {addr}: {error}"));

    tracing::info!(%addr, %scenario, "Census synthetic fixture listening");
    axum::serve(listener, census::app(state))
        .await
        .expect("fixture server error");
}

const SCENARIOS: &[&str] = &[
    "populated",
    "empty",
    "no-results",
    "identity-unavailable",
    "profile-unavailable",
    "group-unavailable",
    "both-unavailable",
    "n1999",
    "n2000",
    "n2001",
    "hostile-data",
    "missing-identity",
];

async fn build_scenario(name: &str) -> Option<AppState> {
    match name {
        "populated" | "no-results" => {
            let store = Arc::new(InMemoryStore::new());
            seed_populated(store.as_ref()).await;
            Some(synthetic_state(populated_directory(), store))
        }
        "empty" => Some(synthetic_state(
            Arc::new(InMemoryDirectory::new()),
            Arc::new(InMemoryStore::new()),
        )),
        "identity-unavailable" => {
            let store = Arc::new(InMemoryStore::new());
            seed_populated(store.as_ref()).await;
            Some(synthetic_state(
                Arc::new(FailingDirectory::new(BACKEND_DETAIL)),
                store,
            ))
        }
        "profile-unavailable" => Some(synthetic_state(
            populated_directory(),
            Arc::new(FailingStore::profile_reads(BACKEND_DETAIL)),
        )),
        "group-unavailable" => Some(synthetic_state(
            populated_directory(),
            Arc::new(FailingStore::group_reads(BACKEND_DETAIL)),
        )),
        "both-unavailable" => Some(synthetic_state(
            Arc::new(FailingDirectory::new(BACKEND_DETAIL)),
            Arc::new(FailingStore::all_reads(BACKEND_DETAIL)),
        )),
        "n1999" => Some(overflow_state(1_999)),
        "n2000" => Some(overflow_state(2_000)),
        "n2001" => Some(overflow_state(2_001)),
        "hostile-data" => {
            let store = Arc::new(InMemoryStore::new());
            seed_hostile(store.as_ref()).await;
            Some(synthetic_state(hostile_directory(), store))
        }
        "missing-identity" => {
            let store = Arc::new(InMemoryStore::new());
            seed_missing_identity(store.as_ref()).await;
            Some(synthetic_state(Arc::new(InMemoryDirectory::new()), store))
        }
        _ => None,
    }
}

fn overflow_state(count: usize) -> AppState {
    synthetic_state(
        Arc::new(OverflowDirectory::new(count)),
        Arc::new(InMemoryStore::new()),
    )
}

fn populated_directory() -> Arc<dyn Directory> {
    Arc::new(InMemoryDirectory::with_identities(vec![
        identity("fixture-alice", "alice@example.invalid"),
        identity("fixture-bob", "bob@example.invalid"),
        identity("fixture-cora", "cora@example.invalid"),
    ]))
}

fn hostile_directory() -> Arc<dyn Directory> {
    Arc::new(InMemoryDirectory::with_identities(vec![identity(
        "fixture-hostile",
        "hostile@example.invalid",
    )]))
}

fn identity(sub: &str, email: &str) -> Identity {
    Identity {
        sub: sub.to_string(),
        email: email.to_string(),
    }
}

async fn seed_populated(store: &InMemoryStore) {
    for profile in [
        profile(
            "fixture-alice",
            "Alice Atlas",
            "Cartographer",
            "Research",
            "fixture-bob",
        ),
        profile("fixture-bob", "Bob Boundary", "Survey lead", "Research", ""),
        profile(
            "fixture-cora",
            "Cora Contour",
            "Field recorder",
            "Operations",
            "fixture-missing-manager",
        ),
    ] {
        store.upsert_profile(&profile).await.expect("seed profile");
    }

    let atlas = group("fixture-group-atlas", "Atlas Guild", "Maps living systems");
    let field = group("fixture-group-field", "Field Notes", "Records observations");
    store.create_group(&atlas).await.expect("seed atlas group");
    store.create_group(&field).await.expect("seed field group");
    store
        .add_member(&membership(&atlas.id, "fixture-alice", "cartographer"))
        .await
        .expect("seed direct membership");
    store
        .add_member(&membership(&field.id, "fixture-cora", "recorder"))
        .await
        .expect("seed nested membership");
    store
        .add_group_child(&GroupChild {
            parent_group_id: atlas.id,
            child_group_id: field.id,
            added_at: 1_700_000_003,
        })
        .await
        .expect("seed child group");
}

async fn seed_hostile(store: &InMemoryStore) {
    let long_name = format!("{} {}", "界".repeat(60), "e\u{301}".repeat(30));
    store
        .upsert_profile(&Profile {
            sub: "fixture-hostile".to_string(),
            display_name: format!("\u{202e}{long_name} 🧭 {TEMPLATE_MARKER_CORPUS}"),
            title: format!("<script>title()</script> {TEMPLATE_MARKER_CORPUS}"),
            department: format!("研🧭e\u{301}究部門<&>-Δ🌐 {}", "界".repeat(120)),
            manager_sub: "fixture-off-canvas-manager".to_string(),
            phone: "000-000-0000".to_string(),
            location: "A".repeat(160),
            timezone: "Etc/UTC".to_string(),
            locale: "en".to_string(),
            bio: format!(
                "<script>alert('fixture')</script> {TEMPLATE_MARKER_CORPUS} {}",
                "bio ".repeat(1_700)
            ),
            avatar_url: "javascript:alert('fixture')".to_string(),
            updated_at: 1_700_000_004,
        })
        .await
        .expect("seed hostile profile");

    let group = group(
        "fixture-group-hostile",
        &format!("<img src=x onerror=alert(1)> {TEMPLATE_MARKER_CORPUS}"),
        &format!("Synthetic hostile group {TEMPLATE_MARKER_CORPUS}"),
    );
    store
        .create_group(&group)
        .await
        .expect("seed hostile group");
    store
        .add_member(&membership(&group.id, "fixture-hostile", &"r".repeat(160)))
        .await
        .expect("seed hostile membership");
}

async fn seed_missing_identity(store: &InMemoryStore) {
    store
        .upsert_profile(&profile(
            "fixture-profile-only",
            "Profile Without Identity",
            "Recorded profile",
            "Archive",
            "",
        ))
        .await
        .expect("seed profile-only record");

    let group = group(
        "fixture-group-orphans",
        "Unplaced Records",
        "Synthetic provenance boundary",
    );
    store.create_group(&group).await.expect("seed orphan group");
    store
        .add_member(&membership(&group.id, "fixture-profile-only", "archivist"))
        .await
        .expect("seed profile-only membership");
    store
        .add_member(&membership(
            &group.id,
            "fixture-subject-only",
            "correspondent",
        ))
        .await
        .expect("seed subject-only membership");
}

fn profile(sub: &str, name: &str, title: &str, department: &str, manager_sub: &str) -> Profile {
    Profile {
        sub: sub.to_string(),
        display_name: name.to_string(),
        title: title.to_string(),
        department: department.to_string(),
        manager_sub: manager_sub.to_string(),
        phone: String::new(),
        location: "Fixture room".to_string(),
        timezone: "Etc/UTC".to_string(),
        locale: "en".to_string(),
        bio: "Synthetic fixture record.".to_string(),
        avatar_url: String::new(),
        updated_at: 1_700_000_001,
    }
}

fn group(id: &str, name: &str, description: &str) -> Group {
    Group {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        created_at: 1_700_000_002,
    }
}

fn membership(group_id: &str, sub: &str, role: &str) -> Membership {
    Membership {
        group_id: group_id.to_string(),
        sub: sub.to_string(),
        role: role.to_string(),
        joined_at: 1_700_000_003,
    }
}
