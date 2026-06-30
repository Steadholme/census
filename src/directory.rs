//! The authoritative identity source — a READ-ONLY view over the Keystone `users` table.
//!
//! Census layers its editable profile/group data over the real identities Keystone owns. It NEVER
//! writes here and NEVER selects `password_hash` — only `(sub, email)`. The seam mirrors cortex's
//! federated sources: handlers depend only on the async [`Directory`] trait, so an in-memory fake
//! ([`InMemoryDirectory`], used by tests and the zero-config dev path) and a live [`PgDirectory`]
//! over `KEYSTONE_DATABASE_URL` are interchangeable behind `Arc<dyn Directory>`.
//!
//! RESILIENCE: the Keystone pool is built lazily ([`PgPoolOptions::connect_lazy`]) so a down shared
//! DB never blocks startup; a failed enumeration logs and yields an EMPTY list rather than erroring
//! the page. The directory page always still renders (the viewer is merged in by the handler).

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::config::DIRECTORY_LIMIT;

/// Per-source acquire timeout — a down Keystone DB fails fast (and yields empty) instead of hanging.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);

/// One real identity from Keystone. NEVER carries a credential — only the subject + email.
#[derive(Clone, Debug)]
pub struct Identity {
    pub sub: String,
    pub email: String,
}

/// Read-only identity source.
#[async_trait]
pub trait Directory: Send + Sync {
    /// Every known identity (capped). An unreachable source yields an empty list, never an error.
    async fn list_identities(&self) -> Vec<Identity>;
    /// One identity by subject, if present.
    async fn get_identity(&self, sub: &str) -> Option<Identity>;
}

// ---------------------------------------------------------------------------
// In-memory directory (zero-config dev + tests): holds a fixed identity list.
// ---------------------------------------------------------------------------

/// An in-memory [`Directory`]. Empty by default (so the dev/test path needs no Keystone DB); tests
/// seed a fixed identity list.
#[derive(Default)]
pub struct InMemoryDirectory {
    identities: Vec<Identity>,
}

impl InMemoryDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a directory over a fixed identity list (tests).
    pub fn with_identities(identities: Vec<Identity>) -> Self {
        Self { identities }
    }
}

#[async_trait]
impl Directory for InMemoryDirectory {
    async fn list_identities(&self) -> Vec<Identity> {
        let mut v = self.identities.clone();
        v.truncate(DIRECTORY_LIMIT);
        v
    }

    async fn get_identity(&self, sub: &str) -> Option<Identity> {
        self.identities.iter().find(|i| i.sub == sub).cloned()
    }
}

// ---------------------------------------------------------------------------
// Postgres-backed directory (read-only over the shared Keystone DB).
// ---------------------------------------------------------------------------

/// Build a lazily-connected, read-only pool to the Keystone DSN. Never touches the network here —
/// a down shared DB is discovered (and tolerated as empty) only when the first query runs.
pub fn lazy_pool(dsn: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_lazy(dsn)
}

/// READ-ONLY Keystone-backed [`Directory`]. Selects ONLY `(sub, email)` — never `password_hash`.
pub struct PgDirectory {
    pool: PgPool,
}

impl PgDirectory {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn list_identities_async(&self) -> Result<Vec<Identity>, sqlx::Error> {
        let rows = sqlx::query("SELECT sub, email FROM users ORDER BY email ASC LIMIT $1")
            .bind(DIRECTORY_LIMIT as i64)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(Identity {
                    sub: r.try_get("sub")?,
                    email: r.try_get("email")?,
                })
            })
            .collect()
    }

    async fn get_identity_async(&self, sub: &str) -> Result<Option<Identity>, sqlx::Error> {
        let row = sqlx::query("SELECT sub, email FROM users WHERE sub = $1")
            .bind(sub)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(r) => Ok(Some(Identity {
                sub: r.try_get("sub")?,
                email: r.try_get("email")?,
            })),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl Directory for PgDirectory {
    async fn list_identities(&self) -> Vec<Identity> {
        self.list_identities_async().await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "keystone directory enumeration failed — empty list");
            Vec::new()
        })
    }

    async fn get_identity(&self, sub: &str) -> Option<Identity> {
        self.get_identity_async(sub).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "keystone identity lookup failed");
            None
        })
    }
}
