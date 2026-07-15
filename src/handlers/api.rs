//! Machine JSON people feed for other Steadholme services.
//!
//! `GET /api/people` returns the assembled directory (Keystone identities joined to their stored
//! profiles) as JSON. It carries only safe directory fields — subject, email, display name, title —
//! NEVER a credential. Served behind the same internal Sluice route; in-network service callers may
//! also reach it directly at `census:9130`.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Serialize;

use crate::handlers::people::{assemble_people, viewer_identity};
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

/// `GET /api/people` — every directory identity joined to its profile, as JSON.
pub async fn people_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<PeopleResponse> {
    let viewer = viewer_identity(&headers);
    let people = assemble_people(&state, viewer.as_ref()).await;
    let dtos: Vec<PersonDto> = people
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
        count: dtos.len(),
        people: dtos,
    })
}
