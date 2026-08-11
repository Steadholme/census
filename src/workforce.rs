//! Enterprise workforce authority and durable JML changefeed types.
//!
//! Census stores raw Keystone subjects internally. Machine API handlers translate them to the
//! estate-wide canonical `user:<sub>` form at the wire boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current employment state supplied by the authoritative workforce connector.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EmploymentStatus {
    Prehire,
    Active,
    Leave,
    Suspended,
    Terminated,
}

impl EmploymentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prehire => "prehire",
            Self::Active => "active",
            Self::Leave => "leave",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
        }
    }

    /// A suspended or terminated worker must not appear as an active directory person once the
    /// record's effective time has arrived.
    pub fn suppresses_active_directory(self) -> bool {
        matches!(self, Self::Suspended | Self::Terminated)
    }
}

impl fmt::Display for EmploymentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for EmploymentStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "prehire" => Ok(Self::Prehire),
            "active" => Ok(Self::Active),
            "leave" => Ok(Self::Leave),
            "suspended" => Ok(Self::Suspended),
            "terminated" => Ok(Self::Terminated),
            _ => Err(format!("unknown employment status: {value}")),
        }
    }
}

/// The access-governance lifecycle classification emitted for an accepted workforce record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JmlChangeKind {
    Joiner,
    Mover,
    Leaver,
}

impl JmlChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Joiner => "joiner",
            Self::Mover => "mover",
            Self::Leaver => "leaver",
        }
    }
}

impl fmt::Display for JmlChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JmlChangeKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "joiner" => Ok(Self::Joiner),
            "mover" => Ok(Self::Mover),
            "leaver" => Ok(Self::Leaver),
            _ => Err(format!("unknown JML change kind: {value}")),
        }
    }
}

/// Typed evidence describing which upstream connector and record produced the fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceProvenance {
    pub system: String,
    pub record_id: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// Latest authoritative record. Subjects are raw Keystone subjects at this storage layer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceRecord {
    pub subject: String,
    pub employment_status: EmploymentStatus,
    pub manager_subject: Option<String>,
    pub org_unit_id: String,
    pub department: String,
    pub effective_at: i64,
    pub source: String,
    pub source_version: i64,
    pub observed_at: i64,
    pub provenance: WorkforceProvenance,
}

/// One authenticated connector intake command. Event and dedupe identities are mandatory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceIntake {
    pub event_id: String,
    pub dedupe_key: String,
    pub correlation_id: String,
    pub record: WorkforceRecord,
}

impl WorkforceIntake {
    /// Stable SHA-256 over typed data. `BTreeMap` keeps provenance attributes canonical.
    pub fn payload_hash(&self) -> Result<String, serde_json::Error> {
        let payload = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(payload)))
    }
}

/// Durable, globally ordered workforce change. `cursor` is stable and monotonically increasing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceChange {
    pub cursor: i64,
    pub event_id: String,
    pub dedupe_key: String,
    pub source: String,
    pub source_version: i64,
    pub kind: JmlChangeKind,
    pub subject: String,
    pub effective_at: i64,
    pub old_state: Option<WorkforceRecord>,
    pub new_state: WorkforceRecord,
    pub correlation_id: String,
    pub provenance: WorkforceProvenance,
    pub payload_hash: String,
    pub recorded_at: i64,
}

/// Accepted intake outcome. Exact replay returns the original change and `replayed=true`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceIntakeResult {
    pub replayed: bool,
    pub record: WorkforceRecord,
    pub change: WorkforceChange,
}

/// Filtered cursor query. `after` is exclusive and `limit` is already bounded by the handler.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WorkforceChangeQuery {
    pub after: i64,
    pub limit: usize,
    pub subject: Option<String>,
    pub source: Option<String>,
    pub kind: Option<JmlChangeKind>,
}

/// One stable page from the durable changefeed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkforceChangePage {
    pub items: Vec<WorkforceChange>,
    pub next_cursor: i64,
    pub has_more: bool,
}

/// Schema status used by `/readyz`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkforceReadiness {
    pub current_version: i64,
    pub expected_version: i64,
}

impl WorkforceReadiness {
    pub fn ready(self) -> bool {
        self.current_version == self.expected_version
    }
}

pub fn classify_change(old: Option<&WorkforceRecord>, new: &WorkforceRecord) -> JmlChangeKind {
    match old {
        None => JmlChangeKind::Joiner,
        Some(previous)
            if new.employment_status == EmploymentStatus::Terminated
                && previous.employment_status != EmploymentStatus::Terminated =>
        {
            JmlChangeKind::Leaver
        }
        Some(previous)
            if previous.employment_status == EmploymentStatus::Terminated
                && new.employment_status != EmploymentStatus::Terminated =>
        {
            JmlChangeKind::Joiner
        }
        Some(_) => JmlChangeKind::Mover,
    }
}

/// Convert the public canonical subject to the raw Keystone subject Census stores.
pub fn raw_subject(canonical: &str) -> Result<String, &'static str> {
    let Some(raw) = canonical.strip_prefix("user:") else {
        return Err("subject must use canonical user:<sub> form");
    };
    if raw.is_empty() || raw.len() > 255 || raw.chars().any(|ch| ch.is_control() || ch == '/') {
        return Err("subject contains invalid characters");
    }
    Ok(raw.to_string())
}

pub fn canonical_subject(raw: &str) -> String {
    format!("user:{raw}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(status: EmploymentStatus) -> WorkforceRecord {
        WorkforceRecord {
            subject: "u_alice".to_string(),
            employment_status: status,
            manager_subject: None,
            org_unit_id: "eng".to_string(),
            department: "Engineering".to_string(),
            effective_at: 1,
            source: "hris".to_string(),
            source_version: 1,
            observed_at: 1,
            provenance: WorkforceProvenance {
                system: "hris".to_string(),
                record_id: "worker-1".to_string(),
                attributes: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn canonical_subject_boundary_is_explicit() {
        assert_eq!(raw_subject("user:u_alice").unwrap(), "u_alice");
        assert_eq!(canonical_subject("u_alice"), "user:u_alice");
        assert!(raw_subject("u_alice").is_err());
        assert!(raw_subject("service:alice").is_err());
    }

    #[test]
    fn jml_classification_handles_rehire_and_termination() {
        let active = record(EmploymentStatus::Active);
        let terminated = record(EmploymentStatus::Terminated);
        assert_eq!(classify_change(None, &active), JmlChangeKind::Joiner);
        assert_eq!(
            classify_change(Some(&active), &terminated),
            JmlChangeKind::Leaver
        );
        assert_eq!(
            classify_change(Some(&terminated), &active),
            JmlChangeKind::Joiner
        );
        assert_eq!(
            classify_change(Some(&active), &active),
            JmlChangeKind::Mover
        );
    }
}
