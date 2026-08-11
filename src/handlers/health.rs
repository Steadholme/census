//! Unauthenticated liveness probe.

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::AppState;

/// `GET /healthz` -> 200 OK (plain text). Used by the container HEALTHCHECK.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")], "ok")
}

#[derive(Serialize)]
struct ReadinessResponse {
    status: &'static str,
    schema_version: i64,
    expected_schema_version: i64,
}

/// `GET /readyz` proves the workforce/JML schema migration is current.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let (status, body) = match state.store.workforce_readiness().await {
        Ok(readiness) if readiness.ready() => (
            StatusCode::OK,
            ReadinessResponse {
                status: "ready",
                schema_version: readiness.current_version,
                expected_schema_version: readiness.expected_version,
            },
        ),
        Ok(readiness) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ReadinessResponse {
                status: "not_ready",
                schema_version: readiness.current_version,
                expected_schema_version: readiness.expected_version,
            },
        ),
        Err(error) => {
            tracing::error!(%error, "census readiness check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                ReadinessResponse {
                    status: "not_ready",
                    schema_version: 0,
                    expected_schema_version: crate::store::WORKFORCE_SCHEMA_VERSION,
                },
            )
        }
    };
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
