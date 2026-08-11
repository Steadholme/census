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
use crate::error::{AppError, UnavailableKind};
use crate::handlers::people::{assemble_people, viewer_identity, Person, Provenance, ReadError};
use crate::handlers::{
    app_css, esc, fmt_date, html_with_cookie, redirect, render_template, topbar,
};
use crate::store::{
    recursive_members_of, would_create_group_cycle, Group, GroupChild, Membership, Profile,
    StoreError,
};
use crate::{now_nanos, now_secs, AppState};

const GROUPS_HTML: &str = include_str!("../../templates/groups.html");
const GROUP_HTML: &str = include_str!("../../templates/group.html");

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

/// Add/remove-child-group form body.
#[derive(Debug, Deserialize)]
pub struct ChildGroupForm {
    #[serde(default)]
    pub child_group_id: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub csrf_token: String,
}

#[derive(Clone)]
struct MemberDisplay {
    label: String,
    provenance: Provenance,
}

struct PeopleIndex {
    by_sub: HashMap<String, MemberDisplay>,
    options: String,
    identity_available: bool,
    profiles_overflow: bool,
}

#[derive(Default)]
struct ProvenanceFlags {
    provisional: bool,
    profile_only: bool,
    subject_only: bool,
}

impl ProvenanceFlags {
    fn note(&mut self, provenance: Provenance) {
        match provenance {
            Provenance::Enumerated => {}
            Provenance::Provisional => self.provisional = true,
            Provenance::ProfileOnly => self.profile_only = true,
            Provenance::SubjectOnly => self.subject_only = true,
        }
    }

    fn any(&self) -> bool {
        self.provisional || self.profile_only || self.subject_only
    }
}

/// `GET /groups` — the groups directory + create form + per-group membership management.
pub async fn groups_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let viewer = viewer_identity(&headers);
    let can_mutate = viewer.is_some();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);

    // `/groups` deliberately remains orienting during an identity outage: stored group records
    // still render, but every member label falls back to its recorded subject. Profile-store
    // failure is not degradable because a partial label merge would look authoritative.
    let people = load_people_index(&state, viewer.as_ref(), true).await?;
    let group_page = state
        .store
        .list_groups()
        .await
        .map_err(group_store_unavailable)?;
    let groups = group_page.items;
    let render = RenderContext {
        people: &people,
        groups: &groups,
        csrf: &csrf,
        can_mutate,
    };
    let mut cards = String::new();
    let mut provenance = ProvenanceFlags::default();
    for g in &groups {
        let members = state
            .store
            .members_of(&g.id)
            .await
            .map_err(group_store_unavailable)?;
        let child_edges = state
            .store
            .child_groups_of(&g.id)
            .await
            .map_err(group_store_unavailable)?;
        let resolved_count = recursive_members_of(state.store.as_ref(), &g.id)
            .await
            .map_err(group_store_unavailable)?
            .len();
        cards.push_str(&render_group_card(
            g,
            &members,
            &child_edges,
            resolved_count,
            &render,
            &mut provenance,
        ));
    }
    if cards.is_empty() {
        cards.push_str(
            r#"<div class="empty-state"><h2>No groups yet</h2><p>Create the first group below.</p></div>"#,
        );
    }

    let banner = render_groups_channels(&people, &provenance);
    let boundary = if group_page.overflow {
        render_boundary(
            "More groups exist than shown — the registry stops at a survey bound of 1,000.",
        )
    } else {
        String::new()
    };
    let create_form = render_create_form(&csrf, can_mutate);
    let topbar = topbar("Groups", &email);
    let csrf = esc(&csrf);
    let body = render_template(
        GROUPS_HTML,
        &[
            ("{{CSS}}", app_css()),
            ("{{TOPBAR}}", &topbar),
            ("{{BANNER}}", &banner),
            ("{{BOUNDARY}}", &boundary),
            ("{{CREATE_FORM}}", &create_form),
            // Compatibility with the pre-Step-5 skeleton; this token may be absent.
            ("{{CSRF}}", &csrf),
            ("{{CARDS}}", &cards),
        ],
    );
    Ok(html_with_cookie(body, set_cookie))
}

/// `GET /groups/{id}` — detail page for one group, including nested groups and resolved members.
pub async fn group_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let viewer = viewer_identity(&headers);
    let can_mutate = viewer.is_some();
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let group = state
        .store
        .get_group(&id)
        .await
        .map_err(group_store_unavailable)?
        .ok_or_else(|| AppError::NotFound("no such group".to_string()))?;

    // Unlike the overview, a detail page fails closed when the identity source is unavailable:
    // otherwise a bare subject could be mistaken for the complete membership dossier.
    let people = load_people_index(&state, viewer.as_ref(), false).await?;
    let groups = state
        .store
        .list_groups()
        .await
        .map_err(group_store_unavailable)?
        .items;
    let members = state
        .store
        .members_of(&group.id)
        .await
        .map_err(group_store_unavailable)?;
    let child_edges = state
        .store
        .child_groups_of(&group.id)
        .await
        .map_err(group_store_unavailable)?;
    let parent_edges = state
        .store
        .parent_groups_of(&group.id)
        .await
        .map_err(group_store_unavailable)?;
    let resolved_members = recursive_members_of(state.store.as_ref(), &group.id)
        .await
        .map_err(group_store_unavailable)?;

    let render = RenderContext {
        people: &people,
        groups: &groups,
        csrf: &csrf,
        can_mutate,
    };
    let mut provenance = ProvenanceFlags::default();
    let direct_members = render_member_list(&members, &group, true, &render, &mut provenance);
    let resolved_member_rows =
        render_member_list(&resolved_members, &group, false, &render, &mut provenance);
    let child_group_rows = render_child_group_list(&child_edges, &group, true, &render);
    let parent_group_rows = render_parent_group_list(&parent_edges, &groups);
    let banner = render_groups_channels(&people, &provenance);
    let member_form = render_member_form(&group, &render);
    let child_form = render_child_form(&group, &render);

    let desc = if group.description.trim().is_empty() {
        r#"<p class="muted">No description.</p>"#.to_string()
    } else {
        format!(r#"<p class="group__desc">{}</p>"#, esc(&group.description))
    };
    let topbar = topbar("Group", &email);
    let csrf = esc(&csrf);
    let group_id = esc(&group.id);
    let group_name = esc(&group.name);
    let created = esc(&fmt_date(group.created_at));
    let direct_count = format_count(members.len());
    let resolved_count = format_count(resolved_members.len());
    let child_group_options = render_child_group_options(&groups, &group.id);
    let body = render_template(
        GROUP_HTML,
        &[
            ("{{CSS}}", app_css()),
            ("{{TOPBAR}}", &topbar),
            ("{{BANNER}}", &banner),
            ("{{MEMBER_FORM}}", &member_form),
            ("{{CHILD_FORM}}", &child_form),
            // Compatibility with the pre-Step-5 skeleton; these tokens may be absent.
            ("{{CSRF}}", &csrf),
            ("{{GROUP_ID}}", &group_id),
            ("{{NAME}}", &group_name),
            ("{{DESCRIPTION}}", &desc),
            ("{{CREATED}}", &created),
            ("{{DIRECT_COUNT}}", &direct_count),
            ("{{RESOLVED_COUNT}}", &resolved_count),
            ("{{DIRECT_MEMBERS}}", &direct_members),
            ("{{RESOLVED_MEMBERS}}", &resolved_member_rows),
            ("{{CHILD_GROUPS}}", &child_group_rows),
            ("{{PARENT_GROUPS}}", &parent_group_rows),
            ("{{PERSON_OPTIONS}}", &people.options),
            ("{{CHILD_GROUP_OPTIONS}}", &child_group_options),
        ],
    );
    Ok(html_with_cookie(body, set_cookie))
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
        return Err(AppError::InvalidRequest(
            "group name is required".to_string(),
        ));
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
        .map_err(group_store_unavailable)?
        .ok_or_else(|| AppError::NotFound("no such group".to_string()))?;

    let target_sub = form.sub.trim().to_string();
    if target_sub.is_empty() {
        return Err(AppError::InvalidRequest(
            "member subject is required".to_string(),
        ));
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

/// `POST /api/groups/{id}/children` — add or remove a nested group edge. CSRF-checked; emits
/// `census.group.change`.
pub async fn child_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ChildGroupForm>,
) -> Result<Response, AppError> {
    let (actor_sub, actor_email) = auth::require_viewer(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let parent = state
        .store
        .get_group(&id)
        .await
        .map_err(group_store_unavailable)?
        .ok_or_else(|| AppError::NotFound("no such group".to_string()))?;
    let child_group_id = form.child_group_id.trim().to_string();
    if child_group_id.is_empty() {
        return Err(AppError::InvalidRequest(
            "child group id is required".to_string(),
        ));
    }
    let child = state
        .store
        .get_group(&child_group_id)
        .await
        .map_err(group_store_unavailable)?
        .ok_or_else(|| AppError::NotFound("no such child group".to_string()))?;

    let actor = actor_or_sub(actor_email, &actor_sub);
    match form.action.trim() {
        "remove" => {
            state
                .store
                .remove_group_child(&parent.id, &child.id)
                .await?;
            tracing::info!(parent = %parent.id, child = %child.id, "child group removed");
            state.audit.emit(AuditEvent::notice(
                "census.group.change",
                &actor,
                &parent.id,
                &format!("removed child group {} from {}", child.name, parent.name),
            ));
        }
        _ => {
            if would_create_group_cycle(state.store.as_ref(), &parent.id, &child.id)
                .await
                .map_err(group_store_unavailable)?
            {
                return Err(AppError::InvalidRequest(
                    "nested group cycle is not allowed".to_string(),
                ));
            }
            let edge = GroupChild {
                parent_group_id: parent.id.clone(),
                child_group_id: child.id.clone(),
                added_at: now_secs(),
            };
            state.store.add_group_child(&edge).await?;
            tracing::info!(parent = %parent.id, child = %child.id, "child group added");
            state.audit.emit(AuditEvent::notice(
                "census.group.change",
                &actor,
                &parent.id,
                &format!("added child group {} to {}", child.name, parent.name),
            ));
        }
    }

    Ok(redirect(&format!("/groups/{}", parent.id)))
}

struct RenderContext<'a> {
    people: &'a PeopleIndex,
    groups: &'a [Group],
    csrf: &'a str,
    can_mutate: bool,
}

async fn load_people_index(
    state: &AppState,
    viewer: Option<&crate::directory::Identity>,
    degrade_identity_failure: bool,
) -> Result<PeopleIndex, AppError> {
    let assembled = match assemble_people(state, viewer).await {
        Ok(assembled) => assembled,
        Err(ReadError::Identity(error)) => {
            tracing::warn!(error = %error, "group labels unavailable with identity source");
            if !degrade_identity_failure {
                return Err(AppError::Unavailable(UnavailableKind::IdentitySource));
            }

            // Probe the profile store even though its labels are intentionally not used. This
            // distinguishes identity-only degradation from the frozen both-sources-failed 503.
            state
                .store
                .list_profiles()
                .await
                .map_err(profile_store_unavailable)?;
            return Ok(PeopleIndex {
                by_sub: HashMap::new(),
                options: String::new(),
                identity_available: false,
                profiles_overflow: false,
            });
        }
        Err(ReadError::Store(error)) => return Err(profile_store_unavailable(error)),
    };

    let profile_page = state
        .store
        .list_profiles()
        .await
        .map_err(profile_store_unavailable)?;
    let profiles_overflow = profile_page.overflow;
    let mut by_sub: HashMap<String, MemberDisplay> = HashMap::new();
    let mut options = String::new();

    for person in assembled.people {
        push_person_option(&mut options, &person);
        by_sub.insert(
            person.identity.sub.clone(),
            MemberDisplay {
                label: person.label(),
                provenance: person.provenance,
            },
        );
    }

    // Profiles absent from the successful identity page remain useful labels, but are marked as
    // profile-only instead of being promoted into enumerated people.
    for profile in profile_page.items {
        let sub = profile.sub.clone();
        by_sub.entry(sub).or_insert_with(|| MemberDisplay {
            label: profile_label(&profile),
            provenance: Provenance::ProfileOnly,
        });
    }

    Ok(PeopleIndex {
        by_sub,
        options,
        identity_available: true,
        profiles_overflow,
    })
}

fn push_person_option(html: &mut String, person: &Person) {
    html.push_str(&format!(
        r#"<option value="{sub}">{label}</option>"#,
        sub = esc(&person.identity.sub),
        label = esc(&person.label()),
    ));
}

fn profile_label(profile: &Profile) -> String {
    let display_name = profile.display_name.trim();
    if display_name.is_empty() {
        profile.sub.clone()
    } else {
        display_name.to_string()
    }
}

fn profile_store_unavailable(error: StoreError) -> AppError {
    tracing::error!(error = %error, "census profile read failed");
    AppError::Unavailable(UnavailableKind::ProfileStore)
}

fn group_store_unavailable(error: StoreError) -> AppError {
    tracing::error!(error = %error, "census group read failed");
    AppError::Unavailable(UnavailableKind::GroupStore)
}

fn render_group_card(
    group: &Group,
    members: &[Membership],
    child_edges: &[GroupChild],
    resolved_count: usize,
    context: &RenderContext<'_>,
    provenance: &mut ProvenanceFlags,
) -> String {
    let member_rows = render_member_list(members, group, true, context, provenance);
    let child_rows = render_child_group_list(child_edges, group, true, context);
    let member_form = render_member_form(group, context);
    let child_form = render_child_form(group, context);
    let description = if group.description.trim().is_empty() {
        String::new()
    } else {
        format!(r#"<p class="group__desc">{}</p>"#, esc(&group.description))
    };

    format!(
        r#"<section class="card group-card" aria-labelledby="gcard-{id}">
  <div class="card__body">
    <div class="group__head">
      <h2 class="group__name" id="gcard-{id}"><a href="/groups/{id}">{name}</a></h2>
      <span class="group__meta"><span class="num">{direct}</span> direct · <span class="num">{resolved}</span> resolved · <span class="num">{child_count}</span> {child_word} · created {created}</span>
    </div>
    {description}
    <h3 class="group__subhead">Direct members</h3>
    <ul class="members">{member_rows}</ul>
    {member_form}
    <h3 class="group__subhead">Child groups</h3>
    <ul class="members">{child_rows}</ul>
    {child_form}
  </div>
</section>"#,
        id = esc(&group.id),
        name = esc(&group.name),
        direct = format_count(members.len()),
        resolved = format_count(resolved_count),
        child_count = format_count(child_edges.len()),
        child_word = plural(child_edges.len(), "child group", "child groups"),
        created = esc(&fmt_date(group.created_at)),
    )
}

fn render_member_list(
    members: &[Membership],
    current_group: &Group,
    removable: bool,
    context: &RenderContext<'_>,
    provenance_flags: &mut ProvenanceFlags,
) -> String {
    if members.is_empty() {
        return r#"<li class="chips__empty">No members yet</li>"#.to_string();
    }
    let mut html = String::new();
    for m in members {
        let (name, provenance) = member_display(context.people, &m.sub);
        let provenance_tag = match provenance {
            Some(value) => {
                provenance_flags.note(value);
                render_provenance_tag(value)
            }
            None => String::new(),
        };
        let via = if !removable && m.group_id != current_group.id {
            format!(
                r#"<span class="member__via">via {}</span>"#,
                esc(&group_name(context.groups, &m.group_id))
            )
        } else {
            String::new()
        };
        let remove_form = if removable && context.can_mutate {
            format!(
                r#"<form class="inline-form" method="post" action="/api/groups/{gid}/members" aria-label="Remove {name} from {group}">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="action" value="remove">
    <input type="hidden" name="sub" value="{sub}">
    <button class="btn btn-danger btn-xs" type="submit">Remove <span class="sr-only">{name} from {group}</span></button>
  </form>"#,
                gid = esc(&current_group.id),
                csrf = esc(context.csrf),
                sub = esc(&m.sub),
                name = esc(&name),
                group = esc(&current_group.name),
            )
        } else {
            String::new()
        };
        html.push_str(&format!(
            r#"<li class="member">
  <a class="member__name" href="/u/{sub}">{name}</a>
  {provenance_tag}
  {via}
  <span class="chip-role">{role}</span>
  {remove_form}
</li>"#,
            sub = esc(&m.sub),
            name = esc(&name),
            provenance_tag = provenance_tag,
            via = via,
            role = esc(&m.role),
            remove_form = remove_form,
        ));
    }
    html
}

fn render_child_group_list(
    edges: &[GroupChild],
    parent_group: &Group,
    removable: bool,
    context: &RenderContext<'_>,
) -> String {
    if edges.is_empty() {
        return r#"<li class="chips__empty">No child groups</li>"#.to_string();
    }
    let mut html = String::new();
    for edge in edges {
        let name = group_name(context.groups, &edge.child_group_id);
        let remove_form = if removable && context.can_mutate {
            format!(
                r#"<form class="inline-form" method="post" action="/api/groups/{gid}/children" aria-label="Remove {child_name} from {parent_name}">
    <input type="hidden" name="csrf_token" value="{csrf}">
    <input type="hidden" name="action" value="remove">
    <input type="hidden" name="child_group_id" value="{child}">
    <button class="btn btn-danger btn-xs" type="submit">Remove <span class="sr-only">{child_name} from {parent_name}</span></button>
  </form>"#,
                gid = esc(&parent_group.id),
                csrf = esc(context.csrf),
                child = esc(&edge.child_group_id),
                child_name = esc(&name),
                parent_name = esc(&parent_group.name),
            )
        } else {
            String::new()
        };
        html.push_str(&format!(
            r#"<li class="member">
  <a class="member__name" href="/groups/{id}">{name}</a>
  <span class="chip-role">group</span>
  {remove_form}
</li>"#,
            id = esc(&edge.child_group_id),
            name = esc(&name),
            remove_form = remove_form,
        ));
    }
    html
}

fn render_parent_group_list(edges: &[GroupChild], groups: &[Group]) -> String {
    if edges.is_empty() {
        return r#"<li class="chips__empty">No parent groups</li>"#.to_string();
    }
    let mut html = String::new();
    for edge in edges {
        let name = group_name(groups, &edge.parent_group_id);
        html.push_str(&format!(
            r#"<li class="member">
  <a class="member__name" href="/groups/{id}">{name}</a>
  <span class="chip-role">parent</span>
</li>"#,
            id = esc(&edge.parent_group_id),
            name = esc(&name),
        ));
    }
    html
}

fn render_child_group_options(groups: &[Group], current_group_id: &str) -> String {
    let mut html = String::new();
    for group in groups {
        if group.id == current_group_id {
            continue;
        }
        html.push_str(&format!(
            r#"<option value="{id}">{name}</option>"#,
            id = esc(&group.id),
            name = esc(&group.name),
        ));
    }
    html
}

fn render_create_form(csrf: &str, can_mutate: bool) -> String {
    if !can_mutate {
        return readonly_note();
    }
    format!(
        r#"<form class="member-add" method="post" action="/api/groups" aria-label="Create a group">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <div class="member-add__field"><label for="create-group-name">Group name</label><input id="create-group-name" type="text" name="name" required maxlength="120" placeholder="Group name"></div>
  <div class="member-add__field"><label for="create-group-description">Description <span class="muted">(optional)</span></label><input id="create-group-description" type="text" name="description" maxlength="2048" placeholder="Description (optional)"></div>
  <button class="btn btn-primary" type="submit">Create</button>
</form>"#,
        csrf = esc(csrf),
    )
}

fn render_member_form(group: &Group, context: &RenderContext<'_>) -> String {
    if !context.can_mutate {
        return readonly_note();
    }
    format!(
        r#"<form class="member-add" method="post" action="/api/groups/{gid}/members" aria-label="Add a member to {group_name}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="action" value="add">
  <div class="member-add__field"><label for="add-sub-{gid}">Person</label><select id="add-sub-{gid}" name="sub" required><option value="" disabled selected>Add a person…</option>{options}</select></div>
  <div class="member-add__field"><label for="add-role-{gid}">Role <span class="muted">(descriptive, not permission)</span></label><input id="add-role-{gid}" type="text" name="role" maxlength="160" placeholder="member"></div>
  <button class="btn btn-secondary btn-sm" type="submit">Add</button>
</form>"#,
        gid = esc(&group.id),
        group_name = esc(&group.name),
        csrf = esc(context.csrf),
        options = context.people.options,
    )
}

fn render_child_form(group: &Group, context: &RenderContext<'_>) -> String {
    if !context.can_mutate {
        return readonly_note();
    }
    format!(
        r#"<form class="member-add" method="post" action="/api/groups/{gid}/children" aria-label="Add a child group to {group_name}">
  <input type="hidden" name="csrf_token" value="{csrf}">
  <input type="hidden" name="action" value="add">
  <div class="member-add__field"><label for="add-child-{gid}">Child group</label><select id="add-child-{gid}" name="child_group_id" required><option value="" disabled selected>Add a child group…</option>{options}</select></div>
  <button class="btn btn-secondary btn-sm" type="submit">Add child</button>
</form>"#,
        gid = esc(&group.id),
        group_name = esc(&group.name),
        csrf = esc(context.csrf),
        options = render_child_group_options(context.groups, &group.id),
    )
}

fn readonly_note() -> String {
    r#"<p class="readonly-note">No gateway identity accompanied this request — this page is read-only.</p>"#
        .to_string()
}

fn member_display(people: &PeopleIndex, sub: &str) -> (String, Option<Provenance>) {
    if !people.identity_available {
        return (sub.to_string(), None);
    }
    match people.by_sub.get(sub) {
        Some(display) => (display.label.clone(), Some(display.provenance)),
        // When the bounded profile page overflowed, absence from the page proves nothing about
        // whether a profile exists. Keep the subject label but do not fabricate subject-only.
        None if people.profiles_overflow => (sub.to_string(), None),
        None => (sub.to_string(), Some(Provenance::SubjectOnly)),
    }
}

fn render_provenance_tag(provenance: Provenance) -> String {
    let Some(class) = provenance.class() else {
        return String::new();
    };
    format!(
        r#"<span class="prov prov--{class}"><span class="prov__swatch" aria-hidden="true"></span><span class="prov__label">{class}</span></span>"#,
        class = class,
    )
}

fn render_groups_channels(people: &PeopleIndex, flags: &ProvenanceFlags) -> String {
    let mut html = String::new();
    if !people.identity_available {
        html.push_str(
            r#"<section class="alert alert--down banner" role="status" aria-labelledby="banner-title"><div class="alert__body"><h2 class="alert__title" id="banner-title">Identity source unavailable</h2><p>Names unavailable — the identity source is unreachable; recorded subjects are shown instead.</p></div></section>"#,
        );
    }
    if people.profiles_overflow {
        html.push_str(
            r#"<p class="section-note">Some profiles could not be read — the profile store exceeded its read bound.</p>"#,
        );
    }
    html.push_str(&render_legend(flags));
    html
}

fn render_legend(flags: &ProvenanceFlags) -> String {
    if !flags.any() {
        return String::new();
    }
    let mut items = String::from(
        r#"<li class="legend__item"><span class="legend__desc">Unmarked rows are enumerated by the identity source.</span></li>"#,
    );
    if flags.provisional {
        items.push_str(
            r#"<li class="legend__item"><span class="prov prov--provisional" aria-hidden="true"><span class="prov__swatch"></span></span> <span class="legend__word">provisional</span> — <span class="legend__desc">the signed-in viewer, before the identity source enumerates them</span></li>"#,
        );
    }
    if flags.profile_only {
        items.push_str(
            r#"<li class="legend__item"><span class="prov prov--profile-only" aria-hidden="true"><span class="prov__swatch"></span></span> <span class="legend__word">profile-only</span> — <span class="legend__desc">a stored profile without an enumerated identity</span></li>"#,
        );
    }
    if flags.subject_only {
        items.push_str(
            r#"<li class="legend__item"><span class="prov prov--subject-only" aria-hidden="true"><span class="prov__swatch"></span></span> <span class="legend__word">subject-only</span> — <span class="legend__desc">a recorded membership subject without an identity or profile</span></li>"#,
        );
    }
    format!(
        r#"<section class="legend" aria-label="Provenance legend"><h2 class="legend__title">Legend</h2><ul class="legend__items">{items}</ul></section>"#,
        items = items,
    )
}

fn render_boundary(copy: &str) -> String {
    format!(
        r#"<p class="bound" role="note"><span class="bound__mark" aria-hidden="true"></span>{}</p>"#,
        esc(copy)
    )
}

fn format_count(value: usize) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            formatted.push(',');
        }
        formatted.push(ch);
    }
    formatted
}

fn group_name(groups: &[Group], id: &str) -> String {
    groups
        .iter()
        .find(|g| g.id == id)
        .map(|g| g.name.clone())
        .unwrap_or_else(|| id.to_string())
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
