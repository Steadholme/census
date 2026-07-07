//! The editable profile / group / membership layer (Census's OWN database).
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

/// Pluggable profile / group / membership store.
#[async_trait]
pub trait Store: Send + Sync {
    // --- profiles ---------------------------------------------------------
    /// All stored profiles (capped). The directory joins these onto Keystone identities.
    async fn list_profiles(&self) -> Vec<Profile>;
    /// One profile by Keystone subject.
    async fn get_profile(&self, sub: &str) -> Option<Profile>;
    /// Insert-or-update a profile keyed by `sub`.
    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError>;

    // --- groups -----------------------------------------------------------
    /// All groups, name-ordered (capped).
    async fn list_groups(&self) -> Vec<Group>;
    /// One group by id.
    async fn get_group(&self, id: &str) -> Option<Group>;
    /// Insert a new group. Errors with [`StoreError::Conflict`] if the name is taken.
    async fn create_group(&self, group: &Group) -> Result<(), StoreError>;

    // --- memberships ------------------------------------------------------
    /// Members of one group, join-ordered.
    async fn members_of(&self, group_id: &str) -> Vec<Membership>;
    /// Groups one subject belongs to.
    async fn groups_of(&self, sub: &str) -> Vec<Membership>;
    /// Add (or, on a re-add, re-role) a member. Idempotent on `(group_id, sub)`.
    async fn add_member(&self, m: &Membership) -> Result<(), StoreError>;
    /// Remove a member edge. A no-op if the edge does not exist.
    async fn remove_member(&self, group_id: &str, sub: &str) -> Result<(), StoreError>;

    // --- nested groups -----------------------------------------------------
    /// Direct child groups contained by one group.
    async fn child_groups_of(&self, group_id: &str) -> Vec<GroupChild>;
    /// Direct parent groups that contain one group.
    async fn parent_groups_of(&self, group_id: &str) -> Vec<GroupChild>;
    /// Add one nested group edge. Idempotent on `(parent_group_id, child_group_id)`.
    async fn add_group_child(&self, edge: &GroupChild) -> Result<(), StoreError>;
    /// Remove one nested group edge. A no-op if the edge does not exist.
    async fn remove_group_child(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), StoreError>;
}

/// Resolve direct and nested members for a group without relying on backend-specific recursive SQL.
pub async fn recursive_members_of(store: &dyn Store, group_id: &str) -> Vec<Membership> {
    let mut seen_groups = HashSet::new();
    let mut stack = vec![group_id.to_string()];
    let mut by_sub: HashMap<String, Membership> = HashMap::new();

    while let Some(id) = stack.pop() {
        if !seen_groups.insert(id.clone()) {
            continue;
        }
        for m in store.members_of(&id).await {
            by_sub.entry(m.sub.clone()).or_insert(m);
        }
        for edge in store.child_groups_of(&id).await {
            stack.push(edge.child_group_id);
        }
    }

    let mut members: Vec<Membership> = by_sub.into_values().collect();
    members.sort_by(|a, b| a.sub.cmp(&b.sub).then_with(|| a.group_id.cmp(&b.group_id)));
    members
}

/// True if adding `parent -> child` would create a nested-group cycle.
pub async fn would_create_group_cycle(store: &dyn Store, parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    let mut seen = HashSet::new();
    let mut stack = vec![child.to_string()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        for edge in store.child_groups_of(&id).await {
            if edge.child_group_id == parent {
                return true;
            }
            stack.push(edge.child_group_id);
        }
    }
    false
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
    async fn list_profiles(&self) -> Vec<Profile> {
        let mut v: Vec<Profile> = self
            .profiles
            .lock()
            .expect("profiles lock poisoned")
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.sub.cmp(&b.sub));
        v.truncate(DIRECTORY_LIMIT);
        v
    }

    async fn get_profile(&self, sub: &str) -> Option<Profile> {
        self.profiles
            .lock()
            .expect("profiles lock poisoned")
            .get(sub)
            .cloned()
    }

    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.profiles
            .lock()
            .expect("profiles lock poisoned")
            .insert(profile.sub.clone(), profile.clone());
        Ok(())
    }

    async fn list_groups(&self) -> Vec<Group> {
        let mut v: Vec<Group> = self.groups.lock().expect("groups lock poisoned").clone();
        v.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        v.truncate(GROUP_LIMIT);
        v
    }

    async fn get_group(&self, id: &str) -> Option<Group> {
        self.groups
            .lock()
            .expect("groups lock poisoned")
            .iter()
            .find(|g| g.id == id)
            .cloned()
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

    async fn members_of(&self, group_id: &str) -> Vec<Membership> {
        let mut v: Vec<Membership> = self
            .memberships
            .lock()
            .expect("memberships lock poisoned")
            .iter()
            .filter(|m| m.group_id == group_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.joined_at
                .cmp(&b.joined_at)
                .then_with(|| a.sub.cmp(&b.sub))
        });
        v
    }

    async fn groups_of(&self, sub: &str) -> Vec<Membership> {
        self.memberships
            .lock()
            .expect("memberships lock poisoned")
            .iter()
            .filter(|m| m.sub == sub)
            .cloned()
            .collect()
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

    async fn child_groups_of(&self, group_id: &str) -> Vec<GroupChild> {
        let mut v: Vec<GroupChild> = self
            .group_children
            .lock()
            .expect("group_children lock poisoned")
            .iter()
            .filter(|e| e.parent_group_id == group_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.added_at
                .cmp(&b.added_at)
                .then_with(|| a.child_group_id.cmp(&b.child_group_id))
        });
        v
    }

    async fn parent_groups_of(&self, group_id: &str) -> Vec<GroupChild> {
        let mut v: Vec<GroupChild> = self
            .group_children
            .lock()
            .expect("group_children lock poisoned")
            .iter()
            .filter(|e| e.child_group_id == group_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| {
            a.added_at
                .cmp(&b.added_at)
                .then_with(|| a.parent_group_id.cmp(&b.parent_group_id))
        });
        v
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

    async fn list_profiles_async(&self) -> Result<Vec<Profile>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT sub, display_name, title, department, manager_sub, phone, location, timezone, locale, \
                    bio, avatar_url, updated_at \
             FROM profiles ORDER BY sub ASC LIMIT $1",
        )
        .bind(DIRECTORY_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::profile_from_row).collect()
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

    async fn list_groups_async(&self) -> Result<Vec<Group>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, name, description, created_at \
             FROM groups ORDER BY name ASC LIMIT $1",
        )
        .bind(GROUP_LIMIT as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(Self::group_from_row).collect()
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
}

/// True when a sqlx error is a UNIQUE/PK violation (Postgres SQLSTATE 23505) — the name clash.
fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"))
}

#[async_trait]
impl Store for PgStore {
    async fn list_profiles(&self) -> Vec<Profile> {
        self.list_profiles_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_profiles failed");
            Vec::new()
        })
    }

    async fn get_profile(&self, sub: &str) -> Option<Profile> {
        self.get_profile_async(sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_profile failed");
            None
        })
    }

    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        self.upsert_profile_async(profile)
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    async fn list_groups(&self) -> Vec<Group> {
        self.list_groups_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_groups failed");
            Vec::new()
        })
    }

    async fn get_group(&self, id: &str) -> Option<Group> {
        self.get_group_async(id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_group failed");
            None
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

    async fn members_of(&self, group_id: &str) -> Vec<Membership> {
        self.members_of_async(group_id).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg members_of failed");
            Vec::new()
        })
    }

    async fn groups_of(&self, sub: &str) -> Vec<Membership> {
        self.groups_of_async(sub).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg groups_of failed");
            Vec::new()
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

    async fn child_groups_of(&self, group_id: &str) -> Vec<GroupChild> {
        self.child_groups_of_async(group_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg child_groups_of failed");
                Vec::new()
            })
    }

    async fn parent_groups_of(&self, group_id: &str) -> Vec<GroupChild> {
        self.parent_groups_of_async(group_id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg parent_groups_of failed");
                Vec::new()
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
}
