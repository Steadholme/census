//! Machine JSON people feed for other Steadholme services.
//!
//! `GET /api/people` returns the assembled directory (Keystone identities joined to their stored
//! profiles) as JSON. It carries the frozen ten safe directory/profile fields and NEVER a
//! credential. Served behind the same internal Sluice route; in-network service callers may also
//! reach it directly at `census:9130`.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::handlers::people::{assemble_people, viewer_identity, ReadError};
use crate::AppState;

/// One person in the JSON feed.
#[derive(Debug, Serialize)]
pub struct PersonDto {
    pub sub: String,
    pub email: String,
    pub display_name: String,
    pub title: String,
    pub department: String,
    pub manager_sub: String,
    pub phone: String,
    pub location: String,
    pub timezone: String,
    pub locale: String,
}

/// The JSON feed envelope.
#[derive(Debug, Serialize)]
pub struct PeopleResponse {
    pub count: usize,
    pub people: Vec<PersonDto>,
}

#[derive(Debug, Serialize)]
struct UnavailableResponse {
    error: &'static str,
    detail: &'static str,
}

/// `GET /api/people` — every directory identity joined to its profile, as JSON.
pub async fn people_json(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let viewer = viewer_identity(&headers);
    let assembled = match assemble_people(&state, viewer.as_ref()).await {
        Ok(assembled) => assembled,
        Err(error) => {
            let detail = match &error {
                ReadError::Identity(_) => "identity source unavailable",
                ReadError::Store(_) => "profile store unavailable",
            };
            tracing::error!(error = %error, "people feed unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(UnavailableResponse {
                    error: "unavailable",
                    detail,
                }),
            )
                .into_response();
        }
    };
    let count = assembled.identity_count;
    let dtos: Vec<PersonDto> = assembled
        .people
        .into_iter()
        .map(|p| PersonDto {
            sub: p.identity.sub,
            email: p.identity.email,
            display_name: p.profile.display_name,
            title: p.profile.title,
            department: p.profile.department,
            manager_sub: p.profile.manager_sub,
            phone: p.profile.phone,
            location: p.profile.location,
            timezone: p.profile.timezone,
            locale: p.profile.locale,
        })
        .collect();
    Json(PeopleResponse {
        count,
        people: dtos,
    })
    .into_response()
}
