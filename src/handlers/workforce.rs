//! Bearer-authenticated enterprise workforce intake and durable JML changefeed.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit::AuditEvent;
use crate::store::StoreError;
use crate::workforce::{
    canonical_subject, raw_subject, EmploymentStatus, JmlChangeKind, WorkforceChange,
    WorkforceChangeQuery, WorkforceIntake, WorkforceProvenance, WorkforceRecord,
};
use crate::AppState;

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 500;
const MAX_ID_LEN: usize = 255;
const MAX_TEXT_LEN: usize = 1024;
const MIN_TOKEN_LEN: usize = 32;

#[derive(Debug, Deserialize)]
pub struct WorkforceIntakeRequest {
    pub event_id: String,
    pub dedupe_key: String,
    pub correlation_id: String,
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

#[derive(Debug, Serialize)]
pub struct WorkforceRecordDto {
    /// Estate-wide canonical principal.
    pub subject: String,
    /// Exact raw Keystone subject retained for identity correlation.
    pub keystone_subject: String,
    pub employment_status: EmploymentStatus,
    pub manager_subject: Option<String>,
    pub manager_keystone_subject: Option<String>,
    pub org_unit_id: String,
    pub department: String,
    pub effective_at: i64,
    pub source: String,
    pub source_version: i64,
    pub observed_at: i64,
    pub provenance: WorkforceProvenance,
}

impl From<WorkforceRecord> for WorkforceRecordDto {
    fn from(record: WorkforceRecord) -> Self {
        let manager_keystone_subject = record.manager_subject.clone();
        Self {
            subject: canonical_subject(&record.subject),
            keystone_subject: record.subject,
            employment_status: record.employment_status,
            manager_subject: manager_keystone_subject.as_deref().map(canonical_subject),
            manager_keystone_subject,
            org_unit_id: record.org_unit_id,
            department: record.department,
            effective_at: record.effective_at,
            source: record.source,
            source_version: record.source_version,
            observed_at: record.observed_at,
            provenance: record.provenance,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WorkforceChangeDto {
    pub cursor: i64,
    pub event_id: String,
    pub dedupe_key: String,
    pub source: String,
    pub source_version: i64,
    pub kind: JmlChangeKind,
    pub subject: String,
    pub keystone_subject: String,
    pub effective_at: i64,
    pub old_state: Option<WorkforceRecordDto>,
    pub new_state: WorkforceRecordDto,
    pub correlation_id: String,
    pub provenance: WorkforceProvenance,
    pub payload_hash: String,
    pub recorded_at: i64,
}

impl From<WorkforceChange> for WorkforceChangeDto {
    fn from(change: WorkforceChange) -> Self {
        Self {
            cursor: change.cursor,
            event_id: change.event_id,
            dedupe_key: change.dedupe_key,
            source: change.source,
            source_version: change.source_version,
            kind: change.kind,
            subject: canonical_subject(&change.subject),
            keystone_subject: change.subject,
            effective_at: change.effective_at,
            old_state: change.old_state.map(Into::into),
            new_state: change.new_state.into(),
            correlation_id: change.correlation_id,
            provenance: change.provenance,
            payload_hash: change.payload_hash,
            recorded_at: change.recorded_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct IntakeResponse {
    replayed: bool,
    record: WorkforceRecordDto,
    change: WorkforceChangeDto,
}

#[derive(Debug, Deserialize)]
pub struct ChangefeedParams {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_limit")]
    limit: usize,
    subject: Option<String>,
    source: Option<String>,
    kind: Option<JmlChangeKind>,
}

fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Debug, Serialize)]
struct ChangefeedResponse {
    items: Vec<WorkforceChangeDto>,
    next_cursor: i64,
    has_more: bool,
}

#[derive(Debug, Serialize)]
struct MachineErrorBody {
    error: &'static str,
    code: String,
}

pub(crate) struct MachineError {
    status: StatusCode,
    error: &'static str,
    code: String,
    authenticate: bool,
}

impl MachineError {
    fn invalid(code: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            code: code.into(),
            authenticate: false,
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            code: "workforce_service_token_required".to_string(),
            authenticate: true,
        }
    }

    fn unavailable(code: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            error: "unavailable",
            code: code.into(),
            authenticate: false,
        }
    }

    fn from_store(error: StoreError) -> Self {
        match error {
            StoreError::Conflict(code) => Self {
                status: StatusCode::CONFLICT,
                error: "conflict",
                code,
                authenticate: false,
            },
            StoreError::Backend(detail) => {
                tracing::error!(error = %detail, "workforce store operation failed");
                Self::unavailable("workforce_authority_unavailable")
            }
        }
    }
}

impl IntoResponse for MachineError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(MachineErrorBody {
                error: self.error,
                code: self.code,
            }),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.authenticate {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"census-workforce\""),
            );
        }
        response
    }
}

/// `POST /internal/v1/workforce/intake`.
pub(crate) async fn intake(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WorkforceIntakeRequest>,
) -> Result<Response, MachineError> {
    authorize(&state, &headers)?;
    persist_intake(&state, request, None).await
}

/// Exact idempotent upsert alias. Path and body canonical subjects must agree.
pub(crate) async fn put_record(
    State(state): State<AppState>,
    Path(subject): Path<String>,
    headers: HeaderMap,
    Json(request): Json<WorkforceIntakeRequest>,
) -> Result<Response, MachineError> {
    authorize(&state, &headers)?;
    persist_intake(&state, request, Some(&subject)).await
}

async fn persist_intake(
    state: &AppState,
    request: WorkforceIntakeRequest,
    path_subject: Option<&str>,
) -> Result<Response, MachineError> {
    if path_subject.is_some_and(|subject| subject != request.subject) {
        return Err(MachineError::invalid("subject_path_mismatch"));
    }
    let intake = validate_intake(request)?;
    let result = state
        .store
        .intake_workforce(&intake)
        .await
        .map_err(MachineError::from_store)?;
    // Watchtower receives only a non-blocking audit copy. The durable workforce_changes table is
    // the sole delivery source for Access Governance and remains authoritative if audit drops.
    state.audit.emit(AuditEvent::notice(
        if result.replayed {
            "census.workforce.replay"
        } else {
            "census.workforce.change"
        },
        &result.record.source,
        &canonical_subject(&result.record.subject),
        &format!(
            "{} source_version={} cursor={}",
            result.change.kind, result.record.source_version, result.change.cursor
        ),
    ));
    let status = if result.replayed || result.change.old_state.is_some() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    let mut response = (
        status,
        Json(IntakeResponse {
            replayed: result.replayed,
            record: result.record.into(),
            change: result.change.into(),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// `GET /internal/v1/workforce/records/{subject}`.
pub(crate) async fn get_record(
    State(state): State<AppState>,
    Path(subject): Path<String>,
    headers: HeaderMap,
) -> Result<Response, MachineError> {
    authorize(&state, &headers)?;
    let raw = raw_subject(&subject).map_err(MachineError::invalid)?;
    match state
        .store
        .get_workforce_record(&raw)
        .await
        .map_err(MachineError::from_store)?
    {
        Some(record) => {
            let mut response = Json(WorkforceRecordDto::from(record)).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(response)
        }
        None => Err(MachineError {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            code: "workforce_record_not_found".to_string(),
            authenticate: false,
        }),
    }
}

/// `GET /internal/v1/workforce/changes` with an exclusive stable cursor.
pub(crate) async fn changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ChangefeedParams>,
) -> Result<Response, MachineError> {
    authorize(&state, &headers)?;
    if params.after < 0 {
        return Err(MachineError::invalid("cursor_must_be_nonnegative"));
    }
    if !(1..=MAX_LIMIT).contains(&params.limit) {
        return Err(MachineError::invalid("limit_out_of_range"));
    }
    let subject = params
        .subject
        .as_deref()
        .map(raw_subject)
        .transpose()
        .map_err(MachineError::invalid)?;
    if let Some(source) = params.source.as_deref() {
        validate_identifier("source", source)?;
    }
    let page = state
        .store
        .workforce_changes(&WorkforceChangeQuery {
            after: params.after,
            limit: params.limit,
            subject,
            source: params.source,
            kind: params.kind,
        })
        .await
        .map_err(MachineError::from_store)?;
    let mut response = Json(ChangefeedResponse {
        items: page.items.into_iter().map(Into::into).collect(),
        next_cursor: page.next_cursor,
        has_more: page.has_more,
    })
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

fn validate_intake(request: WorkforceIntakeRequest) -> Result<WorkforceIntake, MachineError> {
    validate_identifier("event_id", &request.event_id)?;
    validate_identifier("dedupe_key", &request.dedupe_key)?;
    validate_identifier("correlation_id", &request.correlation_id)?;
    validate_identifier("source", &request.source)?;
    validate_identifier("org_unit_id", &request.org_unit_id)?;
    validate_identifier("provenance.system", &request.provenance.system)?;
    validate_identifier("provenance.record_id", &request.provenance.record_id)?;
    if request.department.len() > MAX_TEXT_LEN || request.department.chars().any(char::is_control) {
        return Err(MachineError::invalid("department_invalid"));
    }
    if request.source_version <= 0 {
        return Err(MachineError::invalid("source_version_must_be_positive"));
    }
    if request.effective_at < 0 || request.observed_at < 0 {
        return Err(MachineError::invalid("timestamp_must_be_nonnegative"));
    }
    if request.provenance.system != request.source {
        return Err(MachineError::invalid("provenance_source_mismatch"));
    }
    if request.provenance.attributes.len() > 64
        || request.provenance.attributes.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > MAX_ID_LEN
                || value.len() > MAX_TEXT_LEN
                || key.chars().any(char::is_control)
                || value.chars().any(char::is_control)
        })
    {
        return Err(MachineError::invalid("provenance_attributes_invalid"));
    }
    let subject = raw_subject(&request.subject).map_err(MachineError::invalid)?;
    let manager_subject = request
        .manager_subject
        .as_deref()
        .map(raw_subject)
        .transpose()
        .map_err(MachineError::invalid)?;
    if manager_subject.as_deref() == Some(subject.as_str()) {
        return Err(MachineError::invalid("manager_cannot_equal_subject"));
    }
    Ok(WorkforceIntake {
        event_id: request.event_id,
        dedupe_key: request.dedupe_key,
        correlation_id: request.correlation_id,
        record: WorkforceRecord {
            subject,
            employment_status: request.employment_status,
            manager_subject,
            org_unit_id: request.org_unit_id,
            department: request.department,
            effective_at: request.effective_at,
            source: request.source,
            source_version: request.source_version,
            observed_at: request.observed_at,
            provenance: request.provenance,
        },
    })
}

fn validate_identifier(field: &str, value: &str) -> Result<(), MachineError> {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(MachineError::invalid(format!("{field}_invalid")));
    }
    Ok(())
}

fn authorize(state: &AppState, headers: &HeaderMap) -> Result<(), MachineError> {
    let Some(expected) = state.config.workforce_service_token() else {
        return Err(MachineError::unavailable(
            "workforce_service_token_not_configured",
        ));
    };
    if expected.len() < MIN_TOKEN_LEN {
        return Err(MachineError::unavailable(
            "workforce_service_token_misconfigured",
        ));
    }
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(MachineError::unauthorized)?;
    if !constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        return Err(MachineError::unauthorized());
    }
    Ok(())
}

fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    let max_len = expected.len().max(presented.len());
    let mut difference = expected.len() ^ presented.len();
    for index in 0..max_len {
        difference |= usize::from(expected.get(index).copied().unwrap_or(0))
            ^ usize::from(presented.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn token_comparison_rejects_length_and_content_changes() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"same-more"));
        assert!(!constant_time_eq(b"same", b"sane"));
    }
}
