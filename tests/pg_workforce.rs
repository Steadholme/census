//! Real PostgreSQL workforce/JML concurrency, fencing, readiness and filtered cursor proof.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use census::store::{PgStore, Store, StoreError, WORKFORCE_SCHEMA_VERSION};
use census::workforce::{
    EmploymentStatus, JmlChangeKind, WorkforceChangeQuery, WorkforceIntake, WorkforceProvenance,
    WorkforceRecord,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_workforce_is_transactional_monotonic_and_filterable() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("NOTE: TEST_DATABASE_URL not set — skipping PostgreSQL workforce proof");
        return;
    };

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let subject = format!("wf_pg_{unique}");
    let source = format!("hris-{unique}");
    let store_a = Arc::new(PgStore::connect(&url).await.expect("connect store A"));
    let store_b = Arc::new(PgStore::connect(&url).await.expect("connect store B"));
    store_a.migrate().await.expect("migrate");
    store_a.migrate().await.expect("migration idempotent");
    let readiness = store_a.workforce_readiness().await.expect("readiness");
    assert!(readiness.ready());
    assert_eq!(readiness.current_version, WORKFORCE_SCHEMA_VERSION);
    let constraint_pool = sqlx::PgPool::connect(&url)
        .await
        .expect("constraint proof pool");
    let constraint_state: (i64, Option<bool>) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, BOOL_AND(convalidated) \
         FROM pg_constraint \
         WHERE conname IN ('ck_workforce_records_source_version_positive', \
                           'ck_workforce_changes_source_version_positive')",
    )
    .fetch_one(&constraint_pool)
    .await
    .expect("positive source-version constraints");
    assert_eq!(constraint_state, (2, Some(true)));
    constraint_pool.close().await;

    let first = command(&subject, &source, "event-1", "dedupe-1", 1, "Core");
    let first_result = store_a
        .intake_workforce(&first)
        .await
        .expect("first intake");
    assert!(!first_result.replayed);
    assert_eq!(first_result.change.kind, JmlChangeKind::Joiner);

    let replay = store_b
        .intake_workforce(&first)
        .await
        .expect("exact replay");
    assert!(replay.replayed);
    assert_eq!(replay.change.cursor, first_result.change.cursor);

    let mut altered_event = first.clone();
    altered_event.record.department = "Tampered".to_string();
    assert_conflict(
        store_b.intake_workforce(&altered_event).await,
        "workforce_event_conflict",
    );

    // Two separate Census instances race different payloads at the same next source version.
    // The subject advisory lock and transactional version check admit exactly one.
    let contender_a = command(&subject, &source, "event-2a", "dedupe-2a", 2, "Platform");
    let contender_b = command(&subject, &source, "event-2b", "dedupe-2b", 2, "Security");
    let (result_a, result_b) = tokio::join!(
        store_a.intake_workforce(&contender_a),
        store_b.intake_workforce(&contender_b)
    );
    let successes = [&result_a, &result_b]
        .into_iter()
        .filter(|result| result.is_ok())
        .count();
    assert_eq!(successes, 1, "exactly one source version 2 wins");
    let failures: Vec<_> = [result_a, result_b]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    assert_eq!(failures.len(), 1);
    assert!(matches!(
        &failures[0],
        StoreError::Conflict(code) if code == "workforce_stale_version"
    ));

    let mut leaver = command(&subject, &source, "event-3", "dedupe-3", 3, "Platform");
    leaver.record.employment_status = EmploymentStatus::Terminated;
    let leaver = store_a
        .intake_workforce(&leaver)
        .await
        .expect("leaver intake");
    assert_eq!(leaver.change.kind, JmlChangeKind::Leaver);
    assert_eq!(leaver.change.old_state.unwrap().source_version, 2);

    let current = store_b
        .get_workforce_record(&subject)
        .await
        .expect("current record")
        .expect("record exists");
    assert_eq!(current.source_version, 3);
    assert_eq!(current.employment_status, EmploymentStatus::Terminated);

    let page = store_a
        .workforce_changes(&WorkforceChangeQuery {
            after: 0,
            limit: 10,
            subject: Some(subject.clone()),
            source: Some(source.clone()),
            kind: Some(JmlChangeKind::Leaver),
        })
        .await
        .expect("filtered leaver feed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].event_id, format!("{subject}:event-3"));
    assert_eq!(page.next_cursor, page.items[0].cursor);
    assert!(!page.has_more);

    let all = store_a
        .workforce_changes(&WorkforceChangeQuery {
            after: 0,
            limit: 10,
            subject: Some(subject.clone()),
            source: None,
            kind: None,
        })
        .await
        .expect("subject feed");
    assert_eq!(all.items.len(), 3);
    assert!(all
        .items
        .windows(2)
        .all(|window| window[0].cursor < window[1].cursor));
    assert_eq!(all.items[0].kind, JmlChangeKind::Joiner);
    assert_eq!(all.items[2].kind, JmlChangeKind::Leaver);

    let mut takeover = command(&subject, "another-source", "event-4", "dedupe-4", 4, "Core");
    takeover.record.provenance.system = "another-source".to_string();
    assert_conflict(
        store_a.intake_workforce(&takeover).await,
        "workforce_source_conflict",
    );

    let dedupe_reuse = command(&subject, &source, "event-new", "dedupe-1", 4, "Core");
    assert_conflict(
        store_a.intake_workforce(&dedupe_reuse).await,
        "workforce_dedupe_conflict",
    );

    // Leave a shared developer database clean; the sequence intentionally remains monotonic.
    let cleanup = sqlx::PgPool::connect(&url).await.expect("cleanup pool");
    sqlx::query("DELETE FROM workforce_changes WHERE subject = $1")
        .bind(&subject)
        .execute(&cleanup)
        .await
        .expect("cleanup changes");
    sqlx::query("DELETE FROM workforce_records WHERE subject = $1")
        .bind(&subject)
        .execute(&cleanup)
        .await
        .expect("cleanup record");
    cleanup.close().await;
}

fn command(
    subject: &str,
    source: &str,
    event_id: &str,
    dedupe_key: &str,
    source_version: i64,
    department: &str,
) -> WorkforceIntake {
    WorkforceIntake {
        event_id: format!("{subject}:{event_id}"),
        dedupe_key: format!("{subject}:{dedupe_key}"),
        correlation_id: format!("{subject}:corr:{event_id}"),
        record: WorkforceRecord {
            subject: subject.to_string(),
            employment_status: EmploymentStatus::Active,
            manager_subject: Some("u_manager".to_string()),
            org_unit_id: "org-core".to_string(),
            department: department.to_string(),
            effective_at: 1_800_000_000,
            source: source.to_string(),
            source_version,
            observed_at: 1_800_000_000 + source_version,
            provenance: WorkforceProvenance {
                system: source.to_string(),
                record_id: subject.to_string(),
                attributes: BTreeMap::from([("tenant".to_string(), "fixture".to_string())]),
            },
        },
    }
}

fn assert_conflict(
    result: Result<census::workforce::WorkforceIntakeResult, StoreError>,
    expected: &str,
) {
    assert!(
        matches!(result, Err(StoreError::Conflict(code)) if code == expected),
        "expected conflict {expected}"
    );
}
