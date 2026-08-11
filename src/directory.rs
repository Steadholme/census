//! The authoritative identity source — a READ-ONLY view over the Keystone `users` table.
//!
//! Census layers its editable profile/group data over the real identities Keystone owns. It NEVER
//! writes here and NEVER selects `password_hash` — only `(sub, email)`. The seam mirrors cortex's
//! federated sources: handlers depend only on the async [`Directory`] trait, so an in-memory fake
//! ([`InMemoryDirectory`], used by tests and the zero-config dev path) and a live [`PgDirectory`]
//! over `KEYSTONE_DATABASE_URL` are interchangeable behind `Arc<dyn Directory>`.
//!
//! RESILIENCE: the Keystone pool is built lazily ([`PgPoolOptions::connect_lazy`]) so a down shared
//! DB never blocks startup. Read failures remain explicit so handlers can distinguish an outage
//! from a proven empty directory.

use std::collections::HashSet;
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

/// A directory read failure. The inner detail is log-only and must never reach an HTTP body.
#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error("directory backend error")]
    Backend(String),
}

/// One bounded page from the authoritative identity source.
#[derive(Clone, Debug)]
pub struct IdentityPage {
    pub items: Vec<Identity>,
    pub overflow: bool,
}

/// Read-only identity source.
#[async_trait]
pub trait Directory: Send + Sync {
    /// Every known identity (capped), plus proof that the cap was crossed.
    async fn list_identities(&self) -> Result<IdentityPage, DirectoryError>;
    /// One identity by subject, if present.
    async fn get_identity(&self, sub: &str) -> Result<Option<Identity>, DirectoryError>;
}

// ---------------------------------------------------------------------------
// In-memory directory (zero-config dev + tests): holds a fixed identity list.
// ---------------------------------------------------------------------------

/// An in-memory [`Directory`]. Empty by default (so the dev/test path needs no Keystone DB); tests
/// seed a fixed identity list.
#[derive(Default)]
pub struct InMemoryDirectory {
    identities: Vec<Identity>,
    disabled_subjects: HashSet<String>,
}

impl InMemoryDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a directory over a fixed identity list (tests).
    pub fn with_identities(identities: Vec<Identity>) -> Self {
        Self {
            identities,
            disabled_subjects: HashSet::new(),
        }
    }

    /// Test/dev constructor that models Keystone-disabled identities without changing the safe
    /// public identity DTO.
    pub fn with_disabled_subjects(
        identities: Vec<Identity>,
        disabled_subjects: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            identities,
            disabled_subjects: disabled_subjects.into_iter().collect(),
        }
    }
}

#[async_trait]
impl Directory for InMemoryDirectory {
    async fn list_identities(&self) -> Result<IdentityPage, DirectoryError> {
        let mut v: Vec<_> = self
            .identities
            .iter()
            .filter(|identity| !self.disabled_subjects.contains(&identity.sub))
            .cloned()
            .collect();
        let overflow = v.len() > DIRECTORY_LIMIT;
        v.truncate(DIRECTORY_LIMIT);
        Ok(IdentityPage { items: v, overflow })
    }

    async fn get_identity(&self, sub: &str) -> Result<Option<Identity>, DirectoryError> {
        if self.disabled_subjects.contains(sub) {
            return Ok(None);
        }
        Ok(self.identities.iter().find(|i| i.sub == sub).cloned())
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

    async fn list_identities_async(&self) -> Result<IdentityPage, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT sub, email FROM users WHERE disabled = false ORDER BY email ASC LIMIT $1",
        )
        .bind(DIRECTORY_LIMIT as i64 + 1)
        .fetch_all(&self.pool)
        .await?;
        let overflow = rows.len() > DIRECTORY_LIMIT;
        let mut items: Vec<Identity> = rows
            .iter()
            .map(|r| {
                Ok(Identity {
                    sub: r.try_get("sub")?,
                    email: r.try_get("email")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        items.truncate(DIRECTORY_LIMIT);
        Ok(IdentityPage { items, overflow })
    }

    async fn get_identity_async(&self, sub: &str) -> Result<Option<Identity>, sqlx::Error> {
        let row = sqlx::query("SELECT sub, email FROM users WHERE sub = $1 AND disabled = false")
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
    async fn list_identities(&self) -> Result<IdentityPage, DirectoryError> {
        self.list_identities_async().await.map_err(|e| {
            tracing::warn!(error = %e, "keystone directory enumeration failed");
            DirectoryError::Backend(e.to_string())
        })
    }

    async fn get_identity(&self, sub: &str) -> Result<Option<Identity>, DirectoryError> {
        self.get_identity_async(sub).await.map_err(|e| {
            tracing::warn!(error = %e, "keystone identity lookup failed");
            DirectoryError::Backend(e.to_string())
        })
    }
}
