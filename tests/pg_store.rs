//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset the test
//! prints a note and returns early — it never fails the default `cargo test` run, which stays
//! database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! docker run --rm -d -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=census \
//!   -p 127.0.0.1:55470:5432 postgres:18-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55470/census \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! The `Store` trait is async: each method `.await`s sqlx natively (no `block_in_place`), so it
//! runs on any Tokio scheduler — this test stays on `multi_thread` for parallel queries.

use census::store::{Group, Membership, PgStore, Profile, Store, StoreError};
use census::now_secs;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url).await.expect("connect TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    let now = now_secs();

    // --- profiles: upsert is insert-then-update ----------------------------
    let mut profile = Profile {
        sub: "u_alice".to_string(),
        display_name: "Alice".to_string(),
        title: "Engineer".to_string(),
        bio: "Builds things.".to_string(),
        avatar_url: "https://cdn.w33d.xyz/a.png".to_string(),
        updated_at: now,
    };
    pg.upsert_profile(&profile).await.expect("insert profile");
    let fetched = pg.get_profile("u_alice").await.expect("fetch profile");
    assert_eq!(fetched.display_name, "Alice");

    profile.display_name = "Alice A.".to_string();
    profile.title = "Staff Engineer".to_string();
    profile.updated_at = now + 1;
    pg.upsert_profile(&profile).await.expect("update profile");
    let refetched = pg.get_profile("u_alice").await.expect("refetch");
    assert_eq!(refetched.display_name, "Alice A.");
    assert_eq!(refetched.title, "Staff Engineer");
    assert!(pg.list_profiles().await.iter().any(|p| p.sub == "u_alice"));

    // --- groups: create + unique-name conflict -----------------------------
    let group = Group {
        id: "grp_eng".to_string(),
        name: "Engineering".to_string(),
        description: "Builds the estate".to_string(),
        created_at: now,
    };
    pg.create_group(&group).await.expect("create group");
    let dup = Group {
        id: "grp_other".to_string(),
        name: "Engineering".to_string(),
        description: String::new(),
        created_at: now,
    };
    assert!(
        matches!(pg.create_group(&dup).await, Err(StoreError::Conflict(_))),
        "duplicate group name rejected"
    );
    assert_eq!(pg.get_group("grp_eng").await.expect("get group").name, "Engineering");
    assert!(pg.list_groups().await.iter().any(|g| g.id == "grp_eng"));

    // --- memberships: add (idempotent re-role), list both ways, remove -----
    let m = Membership {
        group_id: "grp_eng".to_string(),
        sub: "u_alice".to_string(),
        role: "member".to_string(),
        joined_at: now,
    };
    pg.add_member(&m).await.expect("add member");
    // Re-add with a new role -> ON CONFLICT DO UPDATE (no duplicate row).
    let m2 = Membership {
        role: "maintainer".to_string(),
        ..m.clone()
    };
    pg.add_member(&m2).await.expect("re-role member");

    let members = pg.members_of("grp_eng").await;
    assert_eq!(members.len(), 1, "idempotent on (group_id, sub)");
    assert_eq!(members[0].role, "maintainer", "role updated in place");

    let groups_of = pg.groups_of("u_alice").await;
    assert_eq!(groups_of.len(), 1);
    assert_eq!(groups_of[0].group_id, "grp_eng");

    pg.remove_member("grp_eng", "u_alice").await.expect("remove member");
    assert!(pg.members_of("grp_eng").await.is_empty(), "member removed");
    assert!(pg.groups_of("u_alice").await.is_empty());

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + profile upsert/get/list + group \
         create/conflict/get/list + membership add/re-role/list/remove against real Postgres"
    );
}
