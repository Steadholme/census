//! Error type + responses.
//!
//! Form/page failures render a small branded HTML error page; the few machine paths still get a
//! sensible status code. 401s additionally carry `WWW-Authenticate`. Keeping one enum mirrors the
//! keystone/inkwell/sanctum error seam.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;

/// Safe public classification for an authoritative read outage.
#[derive(Clone, Copy, Debug, Error)]
pub enum UnavailableKind {
    #[error("identity source unavailable")]
    IdentitySource,
    #[error("profile store unavailable")]
    ProfileStore,
    #[error("group store unavailable")]
    GroupStore,
}

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/incomplete form input (empty name, etc.).
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// No gateway-injected identity, or a failed CSRF check.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but acting on something not owned by the viewer.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such person / group.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Name collision on group create (the UNIQUE(name) guard).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),

    /// An authoritative read source failed; the classification is safe for display.
    #[error("unavailable: {0}")]
    Unavailable(UnavailableKind),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String, bool) {
        match self {
            AppError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, d.clone(), false),
            AppError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, d.clone(), true),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, d.clone(), false),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, d.clone(), false),
            AppError::Conflict(d) => (StatusCode::CONFLICT, d.clone(), false),
            AppError::Internal(detail) => {
                tracing::error!(error = %detail, "census write failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Something went wrong — nothing was saved.".to_string(),
                    false,
                )
            }
            AppError::Unavailable(kind) => {
                (StatusCode::SERVICE_UNAVAILABLE, kind.to_string(), false)
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, description, www_authenticate) = self.parts();
        let body = crate::handlers::error_page(status, &description);
        let mut response = (status, Html(body)).into_response();
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// Store failures collapse to their HTTP shape: a name conflict is a 409, everything else 500.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::Conflict(_) => {
                AppError::Conflict("A group with this name already exists.".to_string())
            }
            crate::store::StoreError::Backend(m) => AppError::Internal(m),
        }
    }
}
