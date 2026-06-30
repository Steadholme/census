//! Groups directory + the SSO-gated create / membership management.
//!
//! `GET /groups` lists every group with its members and inline management controls. `POST
//! /api/groups` creates a group; `POST /api/groups/{id}/members` adds or removes a member. Every
//! state-changing POST is keyed to the gateway-injected viewer, double-submit CSRF protected, and
//! emits a `census.group.change` audit event.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{MAX_NAME_CHARS, MAX_TITLE_CHARS};
use crate::error::AppError;
use crate::handlers::people::{assemble_people, viewer_identity};
use crate::handlers::{esc, fmt_date, html_with_cookie, redirect, topbar, APP_CSS};
use crate::store::{Group, Membership};
use crate::{now_nanos, now_secs, AppState};

const GROUPS_HTML: &str = include_str!("../../templates/groups.html");

/// Create-group form body.
#[derive(Debug, Deserialize)]
pub struct GroupForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Add/remove-member form body. The subject is a directory subject; the action is `add`|`remove`.
#[derive(Debug, Deserialize)]
pub struct MemberForm {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// `GET /groups` — the groups directory + create form + per-group membership management.
pub async fn groups_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let email = auth::display_email(&headers);
    let viewer = viewer_identity(&headers);
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    // Resolve subjects -> display labels once for the whole page (members + the add-member picker).
    let people = assemble_people(&state, viewer.as_ref()).await;
    let label_by_sub: HashMap<String, String> = people
        .iter()
        .map(|p| (p.identity.sub.clone(), p.label()))
        .collect();
    let mut options = String::new();
    for p in &people {
        options.push_str(&format!(
            r#"<option value="{sub}">{label}</option>"#,
            sub = esc(&p.identity.sub),
            label = esc(&p.label()),
        ));
    }

    let groups = state.store.list_groups().await;
    let mut cards = String::new();
    for g in &groups {
        let members = state.store.members_of(&g.id).await;
        let mut member_html = String::new();
        for m in &members {
            let name = label_by_sub
                .get(&m.sub)
                .cloned()
                .unwrap_or_else(|| m.sub.clone());
            member_html.push_str(&format!(
                r#"<li class="member">
  <a class="member__name" href="/u/{sub}">{name}</a>
  <span class="chip-role">{role}</span>
  <form class="inline-form" method="post" action="/api/groups/{gid}/members">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="action" value="remove">
    <input type="hidden" name="sub" value="{sub}">
    <button class="btn btn-danger btn-xs" type="submit" title="Remove member">Remove</button>
  </form>
</li>"#,
                sub = esc(&m.sub),
                name = esc(&name),
                role = esc(&m.role),
                gid = esc(&g.id),
                csrf = esc(&csrf),
            ));
        }
        if member_html.is_empty() {
            member_html.push_str(r#"<li class="chips__empty">No members yet</li>"#);
        }
        let desc = if g.description.trim().is_empty() {
            String::new()
        } else {
            format!(r#"<p class="group__desc">{}</p>"#, esc(&g.description))
        };
        cards.push_str(&format!(
            r#"<section class="card group-card">
  <div class="card__body">
    <div class="group__head">
      <h2 class="group__name">{name}</h2>
      <span class="group__meta">{count} {member_word} · created {created}</span>
    </div>
    {desc}
    <ul class="members">{members}</ul>
    <form class="member-add" method="post" action="/api/groups/{gid}/members">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <input type="hidden" name="action" value="add">
      <select name="sub" required aria-label="Person to add">
        <option value="" disabled selected>Add a person…</option>
        {options}
      </select>
      <input type="text" name="role" maxlength="160" placeholder="role (member)" aria-label="Role">
      <button class="btn btn-secondary btn-sm" type="submit">Add</button>
    </form>
  </div>
</section>"#,
            name = esc(&g.name),
            count = members.len(),
            member_word = plural(members.len(), "member", "members"),
            created = esc(&fmt_date(g.created_at)),
            desc = desc,
            members = member_html,
            gid = esc(&g.id),
            csrf = esc(&csrf),
            options = options,
        ));
    }
    if cards.is_empty() {
        cards.push_str(
            r#"<div class="empty-state"><h2>No groups yet</h2><p>Create the first group below.</p></div>"#,
        );
    }

    let body = GROUPS_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Groups", &email))
        .replace("{{CSRF}}", &esc(&csrf))
        .replace("{{CARDS}}", &cards);
    html_with_cookie(body, set_cookie)
}

/// `POST /api/groups` — create a group (unique name). CSRF-checked; emits `census.group.change`.
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<GroupForm>,
) -> Result<Response, AppError> {
    let (sub, actor_email) = auth::require_viewer(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let name = cap(form.name.trim(), MAX_NAME_CHARS);
    if name.is_empty() {
        return Err(AppError::InvalidRequest("group name is required".to_string()));
    }
    let description = cap(form.description.trim(), 2048);
    let group = Group {
        id: format!("grp_{}", now_nanos()),
        name: name.clone(),
        description,
        created_at: now_secs(),
    };
    state.store.create_group(&group).await?;
    tracing::info!(group = %group.id, "group created");

    let actor = actor_or_sub(actor_email, &sub);
    state.audit.emit(AuditEvent::notice(
        "census.group.change",
        &actor,
        &group.id,
        &format!("created group {name}"),
    ));

    Ok(redirect("/groups"))
}

/// `POST /api/groups/{id}/members` — add or remove a member. CSRF-checked; emits
/// `census.group.change`.
pub async fn members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<MemberForm>,
) -> Result<Response, AppError> {
    let (actor_sub, actor_email) = auth::require_viewer(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    // The group must exist (a 404 for a stale link, never a silent no-op).
    let group = state
        .store
        .get_group(&id)
        .await
        .ok_or_else(|| AppError::NotFound("no such group".to_string()))?;

    let target_sub = form.sub.trim().to_string();
    if target_sub.is_empty() {
        return Err(AppError::InvalidRequest("member subject is required".to_string()));
    }

    let actor = actor_or_sub(actor_email, &actor_sub);
    match form.action.trim() {
        "remove" => {
            state.store.remove_member(&group.id, &target_sub).await?;
            tracing::info!(group = %group.id, sub = %target_sub, "member removed");
            state.audit.emit(AuditEvent::notice(
                "census.group.change",
                &actor,
                &group.id,
                &format!("removed {target_sub} from {}", group.name),
            ));
        }
        // Default to add (the add-member form posts action=add).
        _ => {
            let role = {
                let r = cap(form.role.trim(), MAX_TITLE_CHARS);
                if r.is_empty() {
                    "member".to_string()
                } else {
                    r
                }
            };
            let m = Membership {
                group_id: group.id.clone(),
                sub: target_sub.clone(),
                role: role.clone(),
                joined_at: now_secs(),
            };
            state.store.add_member(&m).await?;
            tracing::info!(group = %group.id, sub = %target_sub, "member added");
            state.audit.emit(AuditEvent::notice(
                "census.group.change",
                &actor,
                &group.id,
                &format!("added {target_sub} to {} as {role}", group.name),
            ));
        }
    }

    Ok(redirect("/groups"))
}

fn actor_or_sub(email: String, sub: &str) -> String {
    if email.is_empty() {
        sub.to_string()
    } else {
        email
    }
}

/// Truncate a string to at most `n` chars.
fn cap(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect()
    } else {
        s.to_string()
    }
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}
