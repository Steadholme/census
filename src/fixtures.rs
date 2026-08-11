//! Synthetic, always-compiled fixtures used by integration and browser truth gates.
//!
//! All values are intentionally non-live (`example.invalid`) and contain no estate credentials.

use std::sync::Arc;

use async_trait::async_trait;

use crate::audit::AuditSink;
use crate::config::Config;
use crate::directory::{Directory, DirectoryError, Identity, IdentityPage};
use crate::store::{
    Group, GroupChild, InMemoryStore, Membership, Page, Profile, Store, StoreError,
};
use crate::AppState;

/// A directory double whose reads always fail with log-only detail.
pub struct FailingDirectory {
    detail: String,
}

impl FailingDirectory {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

#[async_trait]
impl Directory for FailingDirectory {
    async fn list_identities(&self) -> Result<IdentityPage, DirectoryError> {
        Err(DirectoryError::Backend(self.detail.clone()))
    }

    async fn get_identity(&self, _sub: &str) -> Result<Option<Identity>, DirectoryError> {
        Err(DirectoryError::Backend(self.detail.clone()))
    }
}

/// A deterministic directory with an arbitrary population, including overflow boundaries.
pub struct OverflowDirectory {
    identities: Vec<Identity>,
}

impl OverflowDirectory {
    pub fn new(count: usize) -> Self {
        let identities = (0..count)
            .map(|index| synthetic_identity(index + 1))
            .collect();
        Self { identities }
    }
}

#[async_trait]
impl Directory for OverflowDirectory {
    async fn list_identities(&self) -> Result<IdentityPage, DirectoryError> {
        const LIMIT: usize = crate::config::DIRECTORY_LIMIT;
        let mut items = self.identities.clone();
        let overflow = items.len() > LIMIT;
        items.truncate(LIMIT);
        Ok(IdentityPage { items, overflow })
    }

    async fn get_identity(&self, sub: &str) -> Result<Option<Identity>, DirectoryError> {
        Ok(self.identities.iter().find(|item| item.sub == sub).cloned())
    }
}

/// Selectively failing store backed by a real in-memory implementation for unaffected surfaces.
pub struct FailingStore {
    inner: InMemoryStore,
    profile_reads: bool,
    group_reads: bool,
    writes: bool,
    detail: String,
}

impl FailingStore {
    pub fn profile_reads(detail: impl Into<String>) -> Self {
        Self::with_failures(true, false, false, detail)
    }

    pub fn group_reads(detail: impl Into<String>) -> Self {
        Self::with_failures(false, true, false, detail)
    }

    pub fn all_reads(detail: impl Into<String>) -> Self {
        Self::with_failures(true, true, false, detail)
    }

    pub fn writes(detail: impl Into<String>) -> Self {
        Self::with_failures(false, false, true, detail)
    }

    pub fn with_failures(
        profile_reads: bool,
        group_reads: bool,
        writes: bool,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            inner: InMemoryStore::new(),
            profile_reads,
            group_reads,
            writes,
            detail: detail.into(),
        }
    }

    fn error(&self) -> StoreError {
        StoreError::Backend(self.detail.clone())
    }
}

#[async_trait]
impl Store for FailingStore {
    async fn list_profiles(&self) -> Result<Page<Profile>, StoreError> {
        if self.profile_reads {
            Err(self.error())
        } else {
            self.inner.list_profiles().await
        }
    }

    async fn get_profile(&self, sub: &str) -> Result<Option<Profile>, StoreError> {
        if self.profile_reads {
            Err(self.error())
        } else {
            self.inner.get_profile(sub).await
        }
    }

    async fn upsert_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner.upsert_profile(profile).await
        }
    }

    async fn list_groups(&self) -> Result<Page<Group>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.list_groups().await
        }
    }

    async fn get_group(&self, id: &str) -> Result<Option<Group>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.get_group(id).await
        }
    }

    async fn create_group(&self, group: &Group) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner.create_group(group).await
        }
    }

    async fn members_of(&self, group_id: &str) -> Result<Vec<Membership>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.members_of(group_id).await
        }
    }

    async fn groups_of(&self, sub: &str) -> Result<Vec<Membership>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.groups_of(sub).await
        }
    }

    async fn add_member(&self, membership: &Membership) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner.add_member(membership).await
        }
    }

    async fn remove_member(&self, group_id: &str, sub: &str) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner.remove_member(group_id, sub).await
        }
    }

    async fn child_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.child_groups_of(group_id).await
        }
    }

    async fn parent_groups_of(&self, group_id: &str) -> Result<Vec<GroupChild>, StoreError> {
        if self.group_reads {
            Err(self.error())
        } else {
            self.inner.parent_groups_of(group_id).await
        }
    }

    async fn add_group_child(&self, edge: &GroupChild) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner.add_group_child(edge).await
        }
    }

    async fn remove_group_child(
        &self,
        parent_group_id: &str,
        child_group_id: &str,
    ) -> Result<(), StoreError> {
        if self.writes {
            Err(self.error())
        } else {
            self.inner
                .remove_group_child(parent_group_id, child_group_id)
                .await
        }
    }
}

pub fn synthetic_identity(index: usize) -> Identity {
    Identity {
        sub: format!("fixture-{index:04}"),
        email: format!("person-{index:04}@example.invalid"),
    }
}

pub fn synthetic_state(directory: Arc<dyn Directory>, store: Arc<dyn Store>) -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store,
        directory,
        audit: AuditSink::disabled(),
    }
}
