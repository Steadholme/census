//! The editable profile/group layer and authoritative workforce/JML ledger (Census's OWN database).
//!
//! `Store` is a small async trait with an in-memory and a PostgreSQL implementation, mirroring the
//! keystone/inkwell/sanctum seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT, PK/UNIQUE/NOT
//! NULL/DEFAULT, `INSERT .. ON CONFLICT .. DO UPDATE`, parameterized queries, plain `CREATE INDEX`)
//! and runtime queries (no compile-time macros), so the build needs NO database and the same
//! statements later run unchanged on FusionDB over pgwire.
//!
//! The methods are `async`: the axum handlers `.await` them directly on the serving runtime, and
//! `PgStore` drives sqlx natively — there is NO `block_in_place` and NO sync-over-async bridge, so a
//! DB round-trip never blocks a worker thread. The few write paths are serialized through a
//! `tokio::sync::Mutex` so a concurrent group-create / membership edit cannot interleave.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use thiserror::Error;

use crate::config::{DIRECTORY_LIMIT, GROUP_LIMIT};
use crate::now_secs;
use crate::workforce::{
    classify_change, WorkforceChange, WorkforceChangePage, WorkforceChangeQuery, WorkforceIntake,
    WorkforceIntakeResult, WorkforceReadiness, WorkforceRecord,
};

pub const WORKFORCE_SCHEMA_VERSION: i64 = 2;

/// An editable profile (maps 1:1 to a `profiles` row). `sub` is the Keystone subject.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    pub sub: String,
    pub display_name: String,
    pub title: String,
    pub department: String,
    pub manager_sub: String,
    pub phone: String,
    pub location: String,
    pub timezone: String,
    pub locale: String,
    pub bio: String,
    pub avatar_url: String,
    pub updated_at: i64,
}

/// A group (maps 1:1 to a `groups` row).
#[derive(Clone, Debug)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: i64,
}

/// A membership edge (maps 1:1 to a `memberships` row).
#[derive(Clone, Debug)]
pub struct Membership {
    pub group_id: String,
    pub sub: String,
    pub role: String,
    pub joined_at: i64,
}

/// A nested-group edge: `parent_group_id` contains `child_group_id`.
#[derive(Clone, Debug)]
pub struct GroupChild {
    pub parent_group_id: String,
    pub child_group_id: String,
    pub added_at: i64,
}

/// Storage failure surfaced to the handler layer.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A group with this name already exists (the UNIQUE(name) guard).
    #[error("name already exists: {0}")]
    Conflict(String),
    /// Backend I/O failure (mapped to a 500).
    #[error("store error: {0}")]
    Backend(String),
}

/// A bounded page from a store collection.
#[derive(Clone, Debug)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub overflow: bool,
}

/// Pluggable profile / group / membership store.
#[async_trait]
pub trait Store: Send + Sync {
    // --- profiles ---------------------------------------------------------
    /// All stored profiles (capped). The directory joins these onto Keystone identities.
    async fn list_profiles(&self) -> Result<Page<Profile>, StoreError>;
    /// One profile by Keystone subject.
    async fn get_profile(&self, sub: &str) -> Result<Option<Profile>, StoreError>;
    /// Insert-or-update a profile keyed by `sub`.
    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError>;

    // --- groups -----------------------------------------------------------
    /// All groups, name-ordered (capped).
    async fn list_groups(&self) -> Result<Page<Group>, StoreError>;
    /// One group by id.
    async fn get_group(&self, id: &str) -> Result<Option<Group>, StoreError>;
    /// Insert a new group. Errors with [`StoreError::Conflict`] if the name is taken.
    async fn create_group(&self, group: &Group) -> Result<(), StoreError>;

    // --- memberships ------------------------------------------------------
    /// Members of one group, join-ordered.
    async fn members_of(&self, group_id: &str) -> Result<Vec<Membership>, StoreError>;
    /// Groups one subject belongs to.
    async fn groups_of(&self, sub: &str) -> Result<Vec<Membership>, StoreError>;
    /// Add (or, on a re-add, re-role) a member. Idempotent on `(group_id, sub)`.
    async fn add_member(&self, m: &Membership) -> Result<(), StoreError>;
    /// Remove a member edge. A no-op if the edge does not exist.
    async fn remove_member(&self, group_id: &str, sub: &str) -> Result<(), StoreError>;

    // --- nested groups -----------------------------------------------------
    /// Direct child groups contained by one group.
    async fn child_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError>;
    /// Direct parent groups that contain one group.
    async fn parent_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError>;
    /// Add one nested group edge. Idempotent on `(parent_group_id, child_group_id)`.
    async fn add_group_child(&self, edge: &GroupChild) -> Result<(), StoreError>;
    /// Remove one nested group edge. A no-op if the edge does not exist.
    async fn remove_group_child(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), StoreError>;

    // --- workforce authority / JML ----------------------------------------
    /// Bounded latest workforce records. The default keeps legacy test doubles source-compatible.
    async fn list_workforce_records(&self) -> Result<Page<WorkforceRecord>, StoreError> {
        Ok(Page {
            items: Vec::new(),
            overflow: false,
        })
    }
    async fn get_workforce_record(
        &self,
        _subject: &str,
    ) -> Result<Option<WorkforceRecord>, StoreError> {
        Ok(None)
    }
    async fn intake_workforce(
        &self,
        _intake: &WorkforceIntake,
    ) -> Result<WorkforceIntakeResult, StoreError> {
        Err(StoreError::Backend(
            "workforce intake is not supported by this store".to_string(),
        ))
    }
    async fn workforce_changes(
        &self,
        query: &WorkforceChangeQuery,
    ) -> Result<WorkforceChangePage, StoreError> {
        Ok(WorkforceChangePage {
            items: Vec::new(),
            next_cursor: query.after,
            has_more: false,
        })
    }
    async fn workforce_readiness(&self) -> Result<WorkforceReadiness, StoreError> {
        Ok(WorkforceReadiness {
            current_version: WORKFORCE_SCHEMA_VERSION,
            expected_version: WORKFORCE_SCHEMA_VERSION,
        })
    }
}

/// Resolve direct and nested members for a group without relying on backend-specific recursive SQL.
pub async fn recursive_members_of(
    store: &dyn Store,
    group_id: &str,
) -> Result<Vec<Membership>, StoreError> {
    let mut seen_groups = HashSet::new();
    let mut stack = vec![group_id.to_string()];
    let mut by_sub: HashMap<String, Membership> = HashMap::new();

    while let Some(id) = stack.pop() {
        if !seen_groups.insert(id.clone()) {
            continue;
        }
        for m in store.members_of(&id).await? {
            by_sub.entry(m.sub.clone()).or_insert(m);
        }
        for edge in store.child_groups_of(&id).await? {
            stack.push(edge.child_group_id);
        }
    }

    let mut members: Vec<Membership> = by_sub.into_values().collect();
    members.sort_by_key(|member| (member.sub.clone(), member.group_id.clone()));
    Ok(members)
}

/// True if adding `parent -> child` would create a nested-group cycle.
pub async fn would_create_group_cycle(
    store: &dyn Store,
    parent: &str,
    child: &str,
) -> Result<bool, StoreError> {
    if parent == child {
        return Ok(true);
    }
    let mut seen = HashSet::new();
    let mut stack = vec![child.to_string()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for edge in store.child_groups_of(&id).await? {
            if edge.child_group_id == parent {
                return Ok(true);
            }
            stack.push(edge.child_group_id);
        }
    }
    Ok(false)
}

// --------------------------------------------------------------------------------------
// In-memory store (the default; keeps the whole service database-free for dev + tests).
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct InMemoryStore {
    profiles: Mutex<HashMap<String, Profile>>,
    groups: Mutex<Vec<Group>>,
    memberships: Mutex<Vec<Membership>>,
    group_children: Mutex<Vec<GroupChild>>,
    workforce: Mutex<InMemoryWorkforce>,
}

#[derive(Default)]
struct InMemoryWorkforce {
    records: HashMap<String, WorkforceRecord>,
    changes: Vec<WorkforceChange>,
    event_index: HashMap<String, usize>,
    dedupe_index: HashMap<(String, String), usize>,
    next_cursor: i64,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    // The std `Mutex` is fine throughout: each critical section is fully synchronous (no `.await`
    // inside), so a guard is never held across a yield point.
    async fn list_profiles(&self) -> Result<Page<Profile>, StoreError> {
        let mut v: Vec<Profile> = self
            .profiles
            .lock()
            .expect("profiles lock poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|profile| profile.sub.clone());
        let overflow = v.len() > DIRECTORY_LIMIT;
        v.truncate(DIRECTORY_LIMIT);
        Ok(Page { items: v, overflow })
    }

    async fn get_profile(&self, sub: &str) -> Result<Option<Profile>, StoreError> {
        Ok(self
            .profiles
            .lock()
            .expect("profiles lock poisoned")
            .get(sub)
            .cloned())
    }

    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.profiles
            .lock()
            .expect("profiles lock poisoned")
            .insert(profile.sub.clone(), profile.clone());
        Ok(())
    }

    async fn list_groups(&self) -> Result<Page<Group>, StoreError> {
        let mut v: Vec<Group> = self.groups.lock().expect("groups lock poisoned").clone();
        v.sort_by_key(|group| group.name.to_lowercase());
        let overflow = v.len() > GROUP_LIMIT;
        v.truncate(GROUP_LIMIT);
        Ok(Page { items: v, overflow })
    }

    async fn get_group(&self, id: &str) -> Result<Option<Group>, StoreError> {
        Ok(self
            .groups
            .lock()
            .expect("groups lock poisoned")
            .iter()
            .find(|g| g.id == id)
            .cloned())
    }

    async fn create_group(&self, group: &Group) -> Result<(), StoreError> {
        let mut groups = self.groups.lock().expect("groups lock poisoned");
        if groups
            .iter()
            .any(|g| g.name.eq_ignore_ascii_case(&group.name))
        {
            return Err(StoreError::Conflict(group.name.clone()));
        }
        groups.push(group.clone());
        Ok(())
    }

    async fn members_of(&self, group_id: &str) -> Result<Vec<Membership>, StoreError> {
        let mut v: Vec<Membership> = self
            .memberships
            .lock()
            .expect("memberships lock poisoned")
            .iter()
            .filter(|m| m.group_id == group_id)
            .cloned()
            .collect();
        v.sort_by_key(|membership| (membership.joined_at, membership.sub.clone()));
        Ok(v)
    }

    async fn groups_of(&self, sub: &str) -> Result<Vec<Membership>, StoreError> {
        Ok(self
            .memberships
            .lock()
            .expect("memberships lock poisoned")
            .iter()
            .filter(|m| m.sub == sub)
            .cloned()
            .collect())
    }

    async fn add_member(&self, m: &Membership) -> Result<(), StoreError> {
        let mut ms = self.memberships.lock().expect("memberships lock poisoned");
        match ms
            .iter_mut()
            .find(|e| e.group_id == m.group_id && e.sub == m.sub)
        {
            Some(existing) => existing.role = m.role.clone(),
            None => ms.push(m.clone()),
        }
        Ok(())
    }

    async fn remove_member(&self, group_id: &str, sub: &str) -> Result<(), StoreError> {
        self.memberships
            .lock()
            .expect("memberships lock poisoned")
            .retain(|m| !(m.group_id == group_id && m.sub == sub));
        Ok(())
    }

    async fn child_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        let mut v: Vec<GroupChild> = self
            .group_children
            .lock()
            .expect("group_children lock poisoned")
            .iter()
            .filter(|e| e.parent_group_id == group_id)
            .cloned()
            .collect();
        v.sort_by_key(|edge| (edge.added_at, edge.child_group_id.clone()));
        Ok(v)
    }

    async fn parent_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        let mut v: Vec<GroupChild> = self
            .group_children
            .lock()
            .expect("group_children lock poisoned")
            .iter()
            .filter(|e| e.child_group_id == group_id)
            .cloned()
            .collect();
        v.sort_by_key(|edge| (edge.added_at, edge.parent_group_id.clone()));
        Ok(v)
    }

    async fn add_group_child(&self, edge: &GroupChild) -> Result<(), StoreError> {
        let mut edges = self
            .group_children
            .lock()
            .expect("group_children lock poisoned");
        if !edges.iter().any(|e| {
            e.parent_group_id == edge.parent_group_id && e.child_group_id == edge.child_group_id
        }) {
            edges.push(edge.clone());
        }
        Ok(())
    }

    async fn remove_group_child(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), StoreError> {
        self.group_children
            .lock()
            .expect("group_children lock poisoned")
            .retain(|e| {
                !(e.parent_group_id == parent_group_id && e.child_group_id == child_group_id)
            });
        Ok(())
    }

    async fn list_workforce_records(&self) -> Result<Page<WorkforceRecord>, StoreError> {
        let guard = self.workforce.lock().expect("workforce lock poisoned");
        let mut items: Vec<_> = guard.records.values().cloned().collect();
        items.sort_by_key(|record| record.subject.clone());
        let overflow = items.len() > DIRECTORY_LIMIT;
        items.truncate(DIRECTORY_LIMIT);
        Ok(Page { items, overflow })
    }

    async fn get_workforce_record(
        &self,
        subject: &str,
    ) -> Result<Option<WorkforceRecord>, StoreError> {
        Ok(self
            .workforce
            .lock()
            .expect("workforce lock poisoned")
            .records
            .get(subject)
            .cloned())
    }

    async fn intake_workforce(
        &self,
        intake: &WorkforceIntake,
    ) -> Result<WorkforceIntakeResult, StoreError> {
        let payload_hash = intake
            .payload_hash()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let mut guard = self.workforce.lock().expect("workforce lock poisoned");

        if let Some(index) = guard.event_index.get(&intake.event_id).copied() {
            let existing = guard
                .changes
                .get(index)
                .expect("workforce event index must reference a change");
            if existing.payload_hash == payload_hash
                && existing.dedupe_key == intake.dedupe_key
                && existing.source == intake.record.source
            {
                return Ok(WorkforceIntakeResult {
                    replayed: true,
                    record: existing.new_state.clone(),
                    change: existing.clone(),
                });
            }
            return Err(StoreError::Conflict("workforce_event_conflict".to_string()));
        }

        if guard
            .dedupe_index
            .contains_key(&(intake.record.source.clone(), intake.dedupe_key.clone()))
        {
            return Err(StoreError::Conflict(
                "workforce_dedupe_conflict".to_string(),
            ));
        }

        let old_state = guard.records.get(&intake.record.subject).cloned();
        if let Some(current) = old_state.as_ref() {
            if current.source != intake.record.source {
                return Err(StoreError::Conflict(
                    "workforce_source_conflict".to_string(),
                ));
            }
            if intake.record.source_version <= current.source_version {
                return Err(StoreError::Conflict("workforce_stale_version".to_string()));
            }
        }

        guard.next_cursor += 1;
        let change = WorkforceChange {
            cursor: guard.next_cursor,
            event_id: intake.event_id.clone(),
            dedupe_key: intake.dedupe_key.clone(),
            source: intake.record.source.clone(),
            source_version: intake.record.source_version,
            kind: classify_change(old_state.as_ref(), &intake.record),
            subject: intake.record.subject.clone(),
            effective_at: intake.record.effective_at,
            old_state,
            new_state: intake.record.clone(),
            correlation_id: intake.correlation_id.clone(),
            provenance: intake.record.provenance.clone(),
            payload_hash,
            recorded_at: now_secs(),
        };
        let index = guard.changes.len();
        guard.event_index.insert(intake.event_id.clone(), index);
        guard.dedupe_index.insert(
            (intake.record.source.clone(), intake.dedupe_key.clone()),
            index,
        );
        guard
            .records
            .insert(intake.record.subject.clone(), intake.record.clone());
        guard.changes.push(change.clone());
        Ok(WorkforceIntakeResult {
            replayed: false,
            record: intake.record.clone(),
            change,
        })
    }

    async fn workforce_changes(
        &self,
        query: &WorkforceChangeQuery,
    ) -> Result<WorkforceChangePage, StoreError> {
        let guard = self.workforce.lock().expect("workforce lock poisoned");
        let mut matching = guard.changes.iter().filter(|change| {
            change.cursor > query.after
                && query
                    .subject
                    .as_ref()
                    .is_none_or(|subject| &change.subject == subject)
                && query
                    .source
                    .as_ref()
                    .is_none_or(|source| &change.source == source)
                && query.kind.is_none_or(|kind| change.kind == kind)
        });
        let mut items: Vec<_> = matching
            .by_ref()
            .take(query.limit.saturating_add(1))
            .cloned()
            .collect();
        let has_more = items.len() > query.limit;
        items.truncate(query.limit);
        let next_cursor = items.last().map_or(query.after, |change| change.cursor);
        Ok(WorkforceChangePage {
            items,
            next_cursor,
            has_more,
        })
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed store (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `CENSUS_STORE=postgres`. Each method drives sqlx natively and the handlers
// `.await` it on the serving runtime — NO `block_in_place`, NO sync-over-async. Writes are
// serialized through a `tokio::sync::Mutex` so a concurrent group-create / membership upsert cannot
// interleave (the DB still enforces UNIQUE(name) + PK(group_id, sub) as the backstop).

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use tokio::sync::Mutex as AsyncMutex;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool` + a write serializer.
pub struct PgStore {
    pool: PgPool,
    write_lock: AsyncMutex<()>,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool,
            write_lock: AsyncMutex::new(()),
        }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS profiles (\
                 sub TEXT PRIMARY KEY, \
                 display_name TEXT NOT NULL DEFAULT '', \
                 title TEXT NOT NULL DEFAULT '', \
                 department TEXT NOT NULL DEFAULT '', \
                 manager_sub TEXT NOT NULL DEFAULT '', \
                 phone TEXT NOT NULL DEFAULT '', \
                 location TEXT NOT NULL DEFAULT '', \
                 timezone TEXT NOT NULL DEFAULT '', \
                 locale TEXT NOT NULL DEFAULT '', \
                 bio TEXT NOT NULL DEFAULT '', \
                 avatar_url TEXT NOT NULL DEFAULT '', \
                 updated_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "ALTER TABLE profiles ADD COLUMN IF NOT EXISTS department TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE profiles ADD COLUMN IF NOT EXISTS manager_sub TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE profiles ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE profiles ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE profiles ADD COLUMN IF NOT EXISTS locale TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS groups (\
                 id TEXT PRIMARY KEY, \
                 name TEXT UNIQUE NOT NULL, \
                 description TEXT NOT NULL DEFAULT '', \
                 created_at BIGINT NOT NULL DEFAULT 0\
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS memberships (\
                 group_id TEXT NOT NULL, \
                 sub TEXT NOT NULL, \
                 role TEXT NOT NULL DEFAULT 'member', \
                 joined_at BIGINT NOT NULL DEFAULT 0, \
                 PRIMARY KEY (group_id, sub)\
             )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS group_children (\
                 parent_group_id TEXT NOT NULL, \
                 child_group_id TEXT NOT NULL, \
                 added_at BIGINT NOT NULL DEFAULT 0, \
                 PRIMARY KEY (parent_group_id, child_group_id)\
             )",
        )
        .execute(&self.pool)
        .await?;

        // Backs the per-group + per-subject membership lookups.
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_memberships_group ON memberships (group_id)")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_memberships_sub ON memberships (sub)")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_group_children_parent ON group_children (parent_group_id)",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_group_children_child ON group_children (child_group_id)",
        )
        .execute(&self.pool)
        .await?;

        // Incremental workforce/JML schema. Keep it transactionally applied and tracked so
        // readiness can distinguish liveness from an incomplete authority schema.
        let mut tx = self.pool.begin().await?;
        sqlx::raw_sql(include_str!("../migrations/0001_workforce_jml.sql"))
            .execute(&mut *tx)
            .await?;
        sqlx::raw_sql(include_str!(
            "../migrations/0002_positive_source_version.sql"
        ))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    fn profile_from_row(row: &sqlx::postgres::PgRow) -> Result<Profile, sqlx::Error> {
        Ok(Profile {
            sub: row.try_get("sub")?,
            display_name: row.try_get("display_name")?,
            title: row.try_get("title")?,
            department: row.try_get("department")?,
            manager_sub: row.try_get("manager_sub")?,
            phone: row.try_get("phone")?,
            location: row.try_get("location")?,
            timezone: row.try_get("timezone")?,
            locale: row.try_get("locale")?,
            bio: row.try_get("bio")?,
            avatar_url: row.try_get("avatar_url")?,
            updated_at: row.try_get("updated_at")?,
        })
    }

    fn group_from_row(row: &sqlx::postgres::PgRow) -> Result<Group, sqlx::Error> {
        Ok(Group {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            created_at: row.try_get("created_at")?,
        })
    }

    fn membership_from_row(row: &sqlx::postgres::PgRow) -> Result<Membership, sqlx::Error> {
        Ok(Membership {
            group_id: row.try_get("group_id")?,
            sub: row.try_get("sub")?,
            role: row.try_get("role")?,
            joined_at: row.try_get("joined_at")?,
        })
    }

    fn group_child_from_row(row: &sqlx::postgres::PgRow) -> Result<GroupChild, sqlx::Error> {
        Ok(GroupChild {
            parent_group_id: row.try_get("parent_group_id")?,
            child_group_id: row.try_get("child_group_id")?,
            added_at: row.try_get("added_at")?,
        })
    }

    fn workforce_record_from_json(value: String) -> Result<WorkforceRecord, sqlx::Error> {
        serde_json::from_str(&value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
    }

    fn workforce_record_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<WorkforceRecord, sqlx::Error> {
        Ok(WorkforceRecord {
            subject: row.try_get("subject")?,
            employment_status: row
                .try_get::<String, _>("employment_status")?
                .parse()
                .map_err(|error: String| sqlx::Error::Decode(error.into()))?,
            manager_subject: row.try_get("manager_subject")?,
            org_unit_id: row.try_get("org_unit_id")?,
            department: row.try_get("department")?,
            effective_at: row.try_get("effective_at")?,
            source: row.try_get("source")?,
            source_version: row.try_get("source_version")?,
            observed_at: row.try_get("observed_at")?,
            provenance: serde_json::from_str(&row.try_get::<String, _>("provenance")?)
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
        })
    }

    fn workforce_change_from_row(
        row: &sqlx::postgres::PgRow,
    ) -> Result<WorkforceChange, sqlx::Error> {
        let old_state = row
            .try_get::<Option<String>, _>("old_state")?
            .map(Self::workforce_record_from_json)
            .transpose()?;
        Ok(WorkforceChange {
            cursor: row.try_get("cursor")?,
            event_id: row.try_get("event_id")?,
            dedupe_key: row.try_get("dedupe_key")?,
            source: row.try_get("source")?,
            source_version: row.try_get("source_version")?,
            kind: row
                .try_get::<String, _>("kind")?
                .parse()
                .map_err(|error: String| sqlx::Error::Decode(error.into()))?,
            subject: row.try_get("subject")?,
            effective_at: row.try_get("effective_at")?,
            old_state,
            new_state: Self::workforce_record_from_json(row.try_get("new_state")?)?,
            correlation_id: row.try_get("correlation_id")?,
            provenance: serde_json::from_str(&row.try_get::<String, _>("provenance")?)
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
            payload_hash: row.try_get("payload_hash")?,
            recorded_at: row.try_get("recorded_at")?,
        })
    }

    async fn list_profiles_async(&self) -> Result<Page<Profile>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT sub, display_name, title, department, manager_sub, phone, location, timezone, locale, \
                    bio, avatar_url, updated_at \
             FROM profiles ORDER BY sub ASC LIMIT $1",
        )
        .bind(DIRECTORY_LIMIT as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let overflow = rows.len() > DIRECTORY_LIMIT;
        let mut items: Vec<Profile> = rows
            .iter()
            .map(Self::profile_from_row)
            .collect::<Result<_, _>>()?;
        items.truncate(DIRECTORY_LIMIT);
        Ok(Page { items, overflow })
    }

    async fn get_profile_async(&self, sub: &str) -> Result<Option<Profile>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT sub, display_name, title, department, manager_sub, phone, location, timezone, locale, \
                    bio, avatar_url, updated_at \
             FROM profiles WHERE sub = $1",
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(Self::profile_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn upsert_profile_async(&self, p: &Profile) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO profiles (sub, display_name, title, department, manager_sub, phone, \
                                    location, timezone, locale, bio, avatar_url, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (sub) DO UPDATE SET \
                 display_name = $2, title = $3, department = $4, manager_sub = $5, phone = $6, \
                 location = $7, timezone = $8, locale = $9, bio = $10, avatar_url = $11, updated_at = $12",
        )
        .bind(&p.sub)
        .bind(&p.display_name)
        .bind(&p.title)
        .bind(&p.department)
        .bind(&p.manager_sub)
        .bind(&p.phone)
        .bind(&p.location)
        .bind(&p.timezone)
        .bind(&p.locale)
        .bind(&p.bio)
        .bind(&p.avatar_url)
        .bind(p.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_groups_async(&self) -> Result<Page<Group>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, description, created_at \
             FROM groups ORDER BY name ASC LIMIT $1",
        )
        .bind(GROUP_LIMIT as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let overflow = rows.len() > GROUP_LIMIT;
        let mut items: Vec<Group> = rows
            .iter()
            .map(Self::group_from_row)
            .collect::<Result<_, _>>()?;
        items.truncate(GROUP_LIMIT);
        Ok(Page { items, overflow })
    }

    async fn get_group_async(&self, id: &str) -> Result<Option<Group>, sqlx::Error> {
        let row = sqlx::query("SELECT id, name, description, created_at FROM groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Self::group_from_row(&r)?)),
            None => Ok(None),
        }
    }

    async fn create_group_async(&self, g: &Group) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO groups (id, name, description, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(&g.id)
        .bind(&g.name)
        .bind(&g.description)
        .bind(g.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn members_of_async(&self, group_id: &str) -> Result<Vec<Membership>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT group_id, sub, role, joined_at FROM memberships \
             WHERE group_id = $1 ORDER BY joined_at ASC, sub ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::membership_from_row).collect()
    }

    async fn groups_of_async(&self, sub: &str) -> Result<Vec<Membership>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT group_id, sub, role, joined_at FROM memberships \
             WHERE sub = $1 ORDER BY joined_at ASC",
        )
        .bind(sub)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::membership_from_row).collect()
    }

    async fn add_member_async(&self, m: &Membership) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO memberships (group_id, sub, role, joined_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (group_id, sub) DO UPDATE SET role = $3",
        )
        .bind(&m.group_id)
        .bind(&m.sub)
        .bind(&m.role)
        .bind(m.joined_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_member_async(&self, group_id: &str, sub: &str) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query("DELETE FROM memberships WHERE group_id = $1 AND sub = $2")
            .bind(group_id)
            .bind(sub)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn child_groups_of_async(&self, group_id: &str) -> Result<Vec<GroupChild>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT parent_group_id, child_group_id, added_at FROM group_children \
             WHERE parent_group_id = $1 ORDER BY added_at ASC, child_group_id ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::group_child_from_row).collect()
    }

    async fn parent_groups_of_async(&self, group_id: &str) -> Result<Vec<GroupChild>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT parent_group_id, child_group_id, added_at FROM group_children \
             WHERE child_group_id = $1 ORDER BY added_at ASC, parent_group_id ASC",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::group_child_from_row).collect()
    }

    async fn add_group_child_async(&self, edge: &GroupChild) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "INSERT INTO group_children (parent_group_id, child_group_id, added_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (parent_group_id, child_group_id) DO UPDATE SET added_at = $3",
        )
        .bind(&edge.parent_group_id)
        .bind(&edge.child_group_id)
        .bind(edge.added_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn remove_group_child_async(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), sqlx::Error> {
        let _guard = self.write_lock.lock().await;
        sqlx::query(
            "DELETE FROM group_children WHERE parent_group_id = $1 AND child_group_id = $2",
        )
        .bind(parent_group_id)
        .bind(child_group_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_workforce_records_async(&self) -> Result<Page<WorkforceRecord>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT subject, employment_status, manager_subject, org_unit_id, department, \
                    effective_at, source, source_version, observed_at, \
                    provenance::TEXT AS provenance \
             FROM workforce_records ORDER BY subject ASC LIMIT $1",
        )
        .bind(DIRECTORY_LIMIT as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let overflow = rows.len() > DIRECTORY_LIMIT;
        let mut items: Vec<_> = rows
            .iter()
            .map(Self::workforce_record_from_row)
            .collect::<Result<_, _>>()?;
        items.truncate(DIRECTORY_LIMIT);
        Ok(Page { items, overflow })
    }

    async fn get_workforce_record_async(
        &self,
        subject: &str,
    ) -> Result<Option<WorkforceRecord>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT subject, employment_status, manager_subject, org_unit_id, department, \
                    effective_at, source, source_version, observed_at, \
                    provenance::TEXT AS provenance \
             FROM workforce_records WHERE subject = $1",
        )
        .bind(subject)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref()
            .map(Self::workforce_record_from_row)
            .transpose()
    }

    async fn intake_workforce_async(
        &self,
        intake: &WorkforceIntake,
    ) -> Result<WorkforceIntakeResult, StoreError> {
        let payload_hash = intake
            .payload_hash()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;

        // Deterministic transaction-scoped locks prevent first-write, event-id and dedupe races
        // across separate Census instances. Sorted acquisition avoids cross-subject deadlocks.
        let mut lock_keys = [
            format!("dedupe:{}:{}", intake.record.source, intake.dedupe_key),
            format!("event:{}", intake.event_id),
            format!("subject:{}", intake.record.subject),
        ];
        lock_keys.sort();
        for key in lock_keys {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7331))")
                .bind(key)
                .execute(&mut *tx)
                .await
                .map_err(|error| StoreError::Backend(error.to_string()))?;
        }

        let existing_event = sqlx::query(
            "SELECT cursor, event_id, dedupe_key, source, source_version, kind, subject, \
                    effective_at, old_state::TEXT AS old_state, new_state::TEXT AS new_state, \
                    correlation_id, provenance::TEXT AS provenance, payload_hash, \
                    recorded_at FROM workforce_changes WHERE event_id = $1",
        )
        .bind(&intake.event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        if let Some(row) = existing_event {
            let change = Self::workforce_change_from_row(&row)
                .map_err(|error| StoreError::Backend(error.to_string()))?;
            if change.payload_hash == payload_hash
                && change.dedupe_key == intake.dedupe_key
                && change.source == intake.record.source
            {
                tx.commit()
                    .await
                    .map_err(|error| StoreError::Backend(error.to_string()))?;
                return Ok(WorkforceIntakeResult {
                    replayed: true,
                    record: change.new_state.clone(),
                    change,
                });
            }
            return Err(StoreError::Conflict("workforce_event_conflict".to_string()));
        }

        let duplicate = sqlx::query(
            "SELECT event_id FROM workforce_changes WHERE source = $1 AND dedupe_key = $2",
        )
        .bind(&intake.record.source)
        .bind(&intake.dedupe_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        if duplicate.is_some() {
            return Err(StoreError::Conflict(
                "workforce_dedupe_conflict".to_string(),
            ));
        }

        let current_row = sqlx::query(
            "SELECT subject, employment_status, manager_subject, org_unit_id, department, \
                    effective_at, source, source_version, observed_at, \
                    provenance::TEXT AS provenance \
             FROM workforce_records WHERE subject = $1 FOR UPDATE",
        )
        .bind(&intake.record.subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| StoreError::Backend(error.to_string()))?;
        let old_state = current_row
            .as_ref()
            .map(Self::workforce_record_from_row)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        if let Some(current) = old_state.as_ref() {
            if current.source != intake.record.source {
                return Err(StoreError::Conflict(
                    "workforce_source_conflict".to_string(),
                ));
            }
            if intake.record.source_version <= current.source_version {
                return Err(StoreError::Conflict("workforce_stale_version".to_string()));
            }
        }

        let provenance = serde_json::to_string(&intake.record.provenance)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let old_json = old_state
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let new_json = serde_json::to_string(&intake.record)
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let recorded_at = now_secs();

        sqlx::query(
            "INSERT INTO workforce_records (subject, employment_status, manager_subject, \
                 org_unit_id, department, effective_at, source, source_version, observed_at, \
                 provenance, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::JSONB, $11) \
             ON CONFLICT (subject) DO UPDATE SET employment_status = EXCLUDED.employment_status, \
                 manager_subject = EXCLUDED.manager_subject, org_unit_id = EXCLUDED.org_unit_id, \
                 department = EXCLUDED.department, effective_at = EXCLUDED.effective_at, \
                 source = EXCLUDED.source, source_version = EXCLUDED.source_version, \
                 observed_at = EXCLUDED.observed_at, provenance = EXCLUDED.provenance, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(&intake.record.subject)
        .bind(intake.record.employment_status.as_str())
        .bind(&intake.record.manager_subject)
        .bind(&intake.record.org_unit_id)
        .bind(&intake.record.department)
        .bind(intake.record.effective_at)
        .bind(&intake.record.source)
        .bind(intake.record.source_version)
        .bind(intake.record.observed_at)
        .bind(provenance.clone())
        .bind(recorded_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| StoreError::Backend(error.to_string()))?;

        let kind = classify_change(old_state.as_ref(), &intake.record);
        let cursor: i64 = sqlx::query(
            "INSERT INTO workforce_changes (event_id, dedupe_key, source, source_version, kind, \
                 subject, effective_at, old_state, new_state, correlation_id, provenance, \
                 payload_hash, recorded_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::JSONB, $9::JSONB, $10, \
                     $11::JSONB, $12, $13) \
             RETURNING cursor",
        )
        .bind(&intake.event_id)
        .bind(&intake.dedupe_key)
        .bind(&intake.record.source)
        .bind(intake.record.source_version)
        .bind(kind.as_str())
        .bind(&intake.record.subject)
        .bind(intake.record.effective_at)
        .bind(old_json)
        .bind(new_json)
        .bind(&intake.correlation_id)
        .bind(provenance)
        .bind(&payload_hash)
        .bind(recorded_at)
        .fetch_one(&mut *tx)
        .await
        .and_then(|row| row.try_get("cursor"))
        .map_err(|error| StoreError::Backend(error.to_string()))?;

        tx.commit()
            .await
            .map_err(|error| StoreError::Backend(error.to_string()))?;
        let change = WorkforceChange {
            cursor,
            event_id: intake.event_id.clone(),
            dedupe_key: intake.dedupe_key.clone(),
            source: intake.record.source.clone(),
            source_version: intake.record.source_version,
            kind,
            subject: intake.record.subject.clone(),
            effective_at: intake.record.effective_at,
            old_state,
            new_state: intake.record.clone(),
            correlation_id: intake.correlation_id.clone(),
            provenance: intake.record.provenance.clone(),
            payload_hash,
            recorded_at,
        };
        Ok(WorkforceIntakeResult {
            replayed: false,
            record: intake.record.clone(),
            change,
        })
    }

    async fn workforce_changes_async(
        &self,
        query: &WorkforceChangeQuery,
    ) -> Result<WorkforceChangePage, sqlx::Error> {
        let kind = query.kind.map(|value| value.as_str().to_string());
        let rows = sqlx::query(
            "SELECT cursor, event_id, dedupe_key, source, source_version, kind, subject, \
                    effective_at, old_state::TEXT AS old_state, new_state::TEXT AS new_state, \
                    correlation_id, provenance::TEXT AS provenance, payload_hash, \
                    recorded_at FROM workforce_changes \
             WHERE cursor > $1 \
               AND ($2::TEXT IS NULL OR subject = $2) \
               AND ($3::TEXT IS NULL OR source = $3) \
               AND ($4::TEXT IS NULL OR kind = $4) \
             ORDER BY cursor ASC LIMIT $5",
        )
        .bind(query.after)
        .bind(query.subject.as_deref())
        .bind(query.source.as_deref())
        .bind(kind.as_deref())
        .bind(query.limit as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let has_more = rows.len() > query.limit;
        let mut items: Vec<_> = rows
            .iter()
            .take(query.limit)
            .map(Self::workforce_change_from_row)
            .collect::<Result<_, _>>()?;
        let next_cursor = items.last().map_or(query.after, |change| change.cursor);
        items.shrink_to_fit();
        Ok(WorkforceChangePage {
            items,
            next_cursor,
            has_more,
        })
    }

    async fn workforce_readiness_async(&self) -> Result<WorkforceReadiness, sqlx::Error> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(version), 0)::BIGINT AS current_version \
             FROM census_schema_migrations",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(WorkforceReadiness {
            current_version: row.try_get("current_version")?,
            expected_version: WORKFORCE_SCHEMA_VERSION,
        })
    }
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505) — the name clash.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_profiles(&self) -> Result<Page<Profile>, StoreError> {
        self.list_profiles_async().await.map_err(|e| {
            tracing::error!(error = %e, "pg list_profiles failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn get_profile(&self, sub: &str) -> Result<Option<Profile>, StoreError> {
        self.get_profile_async(sub).await.map_err(|e| {
            tracing::error!(error = %e, "pg get_profile failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.upsert_profile_async(profile)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_groups(&self) -> Result<Page<Group>, StoreError> {
        self.list_groups_async().await.map_err(|e| {
            tracing::error!(error = %e, "pg list_groups failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn get_group(&self, id: &str) -> Result<Option<Group>, StoreError> {
        self.get_group_async(id).await.map_err(|e| {
            tracing::error!(error = %e, "pg get_group failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn create_group(&self, group: &Group) -> Result<(), StoreError> {
        self.create_group_async(group).await.map_err(|e| {
            if is_unique_violation(&e) {
                StoreError::Conflict(group.name.clone())
            } else {
                StoreError::Backend(e.to_string())
            }
        })
    }

    async fn members_of(&self, group_id: &str) -> Result<Vec<Membership>, StoreError> {
        self.members_of_async(group_id).await.map_err(|e| {
            tracing::error!(error = %e, "pg members_of failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn groups_of(&self, sub: &str) -> Result<Vec<Membership>, StoreError> {
        self.groups_of_async(sub).await.map_err(|e| {
            tracing::error!(error = %e, "pg groups_of failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn add_member(&self, m: &Membership) -> Result<(), StoreError> {
        self.add_member_async(m)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn remove_member(&self, group_id: &str, sub: &str) -> Result<(), StoreError> {
        self.remove_member_async(group_id, sub)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn child_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        self.child_groups_of_async(group_id).await.map_err(|e| {
            tracing::error!(error = %e, "pg child_groups_of failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn parent_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        self.parent_groups_of_async(group_id).await.map_err(|e| {
            tracing::error!(error = %e, "pg parent_groups_of failed");
            StoreError::Backend(e.to_string())
        })
    }

    async fn add_group_child(&self, edge: &GroupChild) -> Result<(), StoreError> {
        self.add_group_child_async(edge)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn remove_group_child(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), StoreError> {
        self.remove_group_child_async(parent_group_id, child_group_id)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_workforce_records(&self) -> Result<Page<WorkforceRecord>, StoreError> {
        self.list_workforce_records_async().await.map_err(|error| {
            tracing::error!(%error, "pg list_workforce_records failed");
            StoreError::Backend(error.to_string())
        })
    }

    async fn get_workforce_record(
        &self,
        subject: &str,
    ) -> Result<Option<WorkforceRecord>, StoreError> {
        self.get_workforce_record_async(subject)
            .await
            .map_err(|error| {
                tracing::error!(%error, "pg get_workforce_record failed");
                StoreError::Backend(error.to_string())
            })
    }

    async fn intake_workforce(
        &self,
        intake: &WorkforceIntake,
    ) -> Result<WorkforceIntakeResult, StoreError> {
        self.intake_workforce_async(intake).await
    }

    async fn workforce_changes(
        &self,
        query: &WorkforceChangeQuery,
    ) -> Result<WorkforceChangePage, StoreError> {
        self.workforce_changes_async(query).await.map_err(|error| {
            tracing::error!(%error, "pg workforce_changes failed");
            StoreError::Backend(error.to_string())
        })
    }

    async fn workforce_readiness(&self) -> Result<WorkforceReadiness, StoreError> {
        self.workforce_readiness_async().await.map_err(|error| {
            tracing::error!(%error, "pg workforce readiness failed");
            StoreError::Backend(error.to_string())
        })
    }
}
