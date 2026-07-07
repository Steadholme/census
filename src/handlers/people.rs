//! Directory + person views and the SSO-gated profile edit.
//!
//! The directory (`GET /`) joins every Keystone identity to its editable profile and supports a
//! keyword filter; the person page (`GET /u/{sub}`) shows one profile plus its group memberships.
//! `POST /api/profile` edits the VIEWER's OWN profile — the subject is ALWAYS the gateway-injected
//! `X-Auth-Subject`, never a client field — behind a double-submit CSRF check, and emits a
//! `census.profile.update` audit event.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{MAX_BIO_CHARS, MAX_NAME_CHARS, MAX_TITLE_CHARS, MAX_URL_CHARS};
use crate::directory::Identity;
use crate::error::AppError;
use crate::handlers::{app_css, esc, fmt_date, html_with_cookie, initials, redirect, topbar};
use crate::markdown;
use crate::store::{recursive_members_of, Group, Profile};
use crate::{now_secs, AppState};

const DIRECTORY_HTML: &str = include_str!("../../templates/directory.html");
const PERSON_HTML: &str = include_str!("../../templates/person.html");

/// One assembled directory entry: a real identity joined to its (possibly default) profile.
#[derive(Clone)]
pub struct Person {
    pub identity: Identity,
    pub profile: Profile,
}

impl Person {
    /// The best display label: the profile display name, else the email, else the bare subject.
    pub fn label(&self) -> String {
        let dn = self.profile.display_name.trim();
        if !dn.is_empty() {
            dn.to_string()
        } else if !self.identity.email.is_empty() {
            self.identity.email.clone()
        } else {
            self.identity.sub.clone()
        }
    }
}

/// Query string for the directory keyword filter.
#[derive(Debug, Deserialize)]
pub struct DirectoryQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub dept: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
}

/// Profile-edit form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub department: String,
    #[serde(default)]
    pub manager_sub: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub timezone: String,
    #[serde(default)]
    pub locale: String,
    #[serde(default)]
    pub bio: String,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(default)]
    pub csrf_token: String,
}

/// Assemble the people directory: enumerate Keystone identities, merge in the signed-in viewer (so
/// you can always see + edit yourself even before Keystone enumerates you), and join each to its
/// stored profile. Sorted by display label. Shared by the directory view and the JSON feed.
pub async fn assemble_people(state: &AppState, viewer: Option<&Identity>) -> Vec<Person> {
    let identities = state.directory.list_identities().await;
    let profiles = state.store.list_profiles().await;
    let profile_by_sub: HashMap<String, Profile> =
        profiles.into_iter().map(|p| (p.sub.clone(), p)).collect();

    // De-dup by subject while merging the viewer in.
    let mut by_sub: HashMap<String, Identity> = HashMap::new();
    for id in identities {
        by_sub.insert(id.sub.clone(), id);
    }
    if let Some(v) = viewer {
        by_sub.entry(v.sub.clone()).or_insert_with(|| v.clone());
    }

    let mut people: Vec<Person> = by_sub
        .into_values()
        .map(|identity| {
            let profile = profile_by_sub
                .get(&identity.sub)
                .cloned()
                .unwrap_or_else(|| Profile {
                    sub: identity.sub.clone(),
                    ..Profile::default()
                });
            Person { identity, profile }
        })
        .collect();

    people.sort_by(|a, b| {
        a.label()
            .to_lowercase()
            .cmp(&b.label().to_lowercase())
            .then_with(|| a.identity.sub.cmp(&b.identity.sub))
    });
    people
}

/// True when the person matches the keyword across identity, rich profile fields, or group names.
fn matches(p: &Person, needle: &str, group_names: &[String]) -> bool {
    if needle.is_empty() {
        return true;
    }
    p.profile.display_name.to_lowercase().contains(needle)
        || p.identity.email.to_lowercase().contains(needle)
        || p.profile.title.to_lowercase().contains(needle)
        || p.profile.department.to_lowercase().contains(needle)
        || p.profile.location.to_lowercase().contains(needle)
        || p.profile.timezone.to_lowercase().contains(needle)
        || p.identity.sub.to_lowercase().contains(needle)
        || group_names
            .iter()
            .any(|name| name.to_lowercase().contains(needle))
}

/// `GET /` — the directory: identities joined to profiles, keyword-filtered, with a groups panel.
pub async fn directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DirectoryQuery>,
) -> Response {
    let email = auth::display_email(&headers);
    let viewer = viewer_identity(&headers);
    let needle = query.q.unwrap_or_default();
    let needle_lc = needle.trim().to_lowercase();
    let dept_filter = query.dept.unwrap_or_default();
    let dept_filter_lc = dept_filter.trim().to_lowercase();
    let group_filter = query.group.unwrap_or_default();
    let group_filter = group_filter.trim().to_string();

    let people = assemble_people(&state, viewer.as_ref()).await;
    let total = people.len();
    let groups = state.store.list_groups().await;

    let mut group_names_by_sub: HashMap<String, Vec<String>> = HashMap::new();
    let mut members_by_group: HashMap<String, HashSet<String>> = HashMap::new();
    for g in &groups {
        let members = recursive_members_of(state.store.as_ref(), &g.id).await;
        let mut subs = HashSet::new();
        for m in members {
            subs.insert(m.sub.clone());
            group_names_by_sub
                .entry(m.sub)
                .or_default()
                .push(g.name.clone());
        }
        members_by_group.insert(g.id.clone(), subs);
    }

    let mut departments: Vec<String> = people
        .iter()
        .filter_map(|p| {
            let dept = p.profile.department.trim();
            if dept.is_empty() {
                None
            } else {
                Some(dept.to_string())
            }
        })
        .collect();
    departments.sort_by_key(|d| d.to_lowercase());
    departments.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

    let mut rows = String::new();
    let mut shown = 0usize;
    let mut visible_people = Vec::new();
    for p in &people {
        if !dept_filter_lc.is_empty()
            && p.profile.department.trim().to_lowercase() != dept_filter_lc
        {
            continue;
        }
        if !group_filter.is_empty()
            && !members_by_group
                .get(&group_filter)
                .map(|subs| subs.contains(&p.identity.sub))
                .unwrap_or(false)
        {
            continue;
        }
        let group_names = group_names_by_sub
            .get(&p.identity.sub)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !matches(p, &needle_lc, group_names) {
            continue;
        }
        shown += 1;
        visible_people.push(p.clone());
        rows.push_str(&render_person_row(p));
    }
    if shown == 0 {
        rows.push_str(
            r#"<div class="empty-state"><h2>No people found</h2><p>No directory identity matches your search.</p></div>"#,
        );
    }

    // Groups panel: name + recursive member count, newest activity not tracked so name-ordered.
    let mut group_items = String::new();
    for g in &groups {
        let count = members_by_group
            .get(&g.id)
            .map(|subs| subs.len())
            .unwrap_or(0);
        group_items.push_str(&format!(
            r#"<li class="grouplist__item"><a href="/groups/{id}">{name}</a><span class="grouplist__count">{count}</span></li>"#,
            id = esc(&g.id),
            name = esc(&g.name),
            count = count,
        ));
    }
    if group_items.is_empty() {
        group_items.push_str(r#"<li class="grouplist__empty">No groups yet</li>"#);
    }

    let filters_active =
        !needle_lc.is_empty() || !dept_filter_lc.is_empty() || !group_filter.is_empty();
    let count_label = if !filters_active {
        format!("{total} {}", plural(total, "person", "people"))
    } else {
        format!("{shown} of {total} {}", plural(total, "person", "people"))
    };
    let org_chart = render_org_chart(&visible_people);

    let body = DIRECTORY_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Directory", &email))
        .replace("{{QUERY}}", &esc(needle.trim()))
        .replace(
            "{{DEPARTMENT_OPTIONS}}",
            &render_department_options(&departments, dept_filter.trim()),
        )
        .replace(
            "{{GROUP_OPTIONS}}",
            &render_group_options(&groups, &group_filter),
        )
        .replace("{{COUNT}}", &esc(&count_label))
        .replace("{{ROWS}}", &rows)
        .replace("{{GROUPS}}", &group_items)
        .replace("{{ORG_CHART}}", &org_chart);
    Html(body).into_response()
}

/// `GET /u/{sub}` — a person page: profile + group memberships. The owner additionally gets the
/// inline edit form.
pub async fn person(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(sub): Path<String>,
) -> Result<Response, AppError> {
    let email = auth::display_email(&headers);
    let viewer = viewer_identity(&headers);

    // Resolve the identity: prefer the Keystone directory; fall back to the viewer's own header
    // identity; finally accept a bare subject that has a stored profile (email unknown).
    let identity = match state.directory.get_identity(&sub).await {
        Some(id) => id,
        None => match &viewer {
            Some(v) if v.sub == sub => v.clone(),
            _ => {
                if state.store.get_profile(&sub).await.is_some() {
                    Identity {
                        sub: sub.clone(),
                        email: String::new(),
                    }
                } else {
                    return Err(AppError::NotFound("no such person".to_string()));
                }
            }
        },
    };

    let profile = state
        .store
        .get_profile(&sub)
        .await
        .unwrap_or_else(|| Profile {
            sub: sub.clone(),
            ..Profile::default()
        });

    let is_self = viewer.as_ref().map(|v| v.sub.as_str()) == Some(sub.as_str());
    let people = assemble_people(&state, viewer.as_ref()).await;
    let label_by_sub: HashMap<String, String> = people
        .iter()
        .map(|p| (p.identity.sub.clone(), p.label()))
        .collect();

    // Group memberships, with the group name resolved (skip a dangling edge whose group is gone).
    let memberships = state.store.groups_of(&sub).await;
    let mut group_html = String::new();
    for m in &memberships {
        if let Some(g) = state.store.get_group(&m.group_id).await {
            group_html.push_str(&format!(
                r#"<li class="chips__item"><a href="/groups/{gid}">{name}</a><span class="chip-role">{role}</span></li>"#,
                gid = esc(&g.id),
                name = esc(&g.name),
                role = esc(&m.role),
            ));
        }
    }
    if group_html.is_empty() {
        group_html.push_str(r#"<li class="chips__empty">No group memberships</li>"#);
    }

    let person = Person {
        identity: identity.clone(),
        profile: profile.clone(),
    };
    let label = person.label();
    let avatar = render_avatar(&profile.avatar_url, &label, "avatar--lg");
    let title_line = if profile.title.trim().is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="person__title">{}</div>"#,
            esc(&profile.title)
        )
    };
    let email_line = if identity.email.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="person__email"><a href="mailto:{e}">{e}</a></div>"#,
            e = esc(&identity.email)
        )
    };
    let bio_html = if profile.bio.trim().is_empty() {
        r#"<p class="muted">No bio yet.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="prose">{}</div>"#,
            markdown::render_html(&profile.bio)
        )
    };
    let manager_html = render_manager(&profile, &label_by_sub);
    let details_html = render_profile_details(&profile, &manager_html);
    let reports_html = render_direct_reports(&sub, &people);

    // The owner gets an inline edit form (CSRF-protected). Otherwise the section is empty.
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let edit_block = if is_self {
        render_edit_form(&csrf, &profile, &people)
    } else {
        String::new()
    };

    let page = PERSON_HTML
        .replace("{{CSS}}", app_css())
        .replace("{{TOPBAR}}", &topbar("Person", &email))
        .replace("{{NAME_TEXT}}", &esc(&label))
        .replace("{{AVATAR}}", &avatar)
        .replace("{{NAME}}", &esc(&label))
        .replace("{{TITLE_LINE}}", &title_line)
        .replace("{{EMAIL_LINE}}", &email_line)
        .replace("{{UPDATED}}", &esc(&fmt_date(profile.updated_at)))
        .replace("{{DETAILS}}", &details_html)
        .replace("{{REPORTS}}", &reports_html)
        .replace("{{BIO}}", &bio_html)
        .replace("{{GROUPS}}", &group_html)
        .replace("{{EDIT}}", &edit_block);

    // Only attach the freshly-minted CSRF cookie when we actually rendered the owner form.
    Ok(html_with_cookie(
        page,
        if is_self { set_cookie } else { None },
    ))
}

/// `POST /api/profile` — edit the VIEWER's own profile. Subject from `X-Auth-Subject`, CSRF-checked.
pub async fn update_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<Response, AppError> {
    let (sub, actor_email) = auth::require_viewer(&headers)?;
    auth::verify_csrf(&headers, &form.csrf_token)?;

    let display_name = cap(form.display_name.trim(), MAX_NAME_CHARS);
    let title = cap(form.title.trim(), MAX_TITLE_CHARS);
    let department = cap(form.department.trim(), MAX_TITLE_CHARS);
    let manager_sub = cap(form.manager_sub.trim(), MAX_NAME_CHARS);
    if manager_sub == sub {
        return Err(AppError::InvalidRequest(
            "manager cannot be the profile owner".to_string(),
        ));
    }
    if !manager_sub.is_empty() {
        let viewer = Identity {
            sub: sub.clone(),
            email: actor_email.clone(),
        };
        let people = assemble_people(&state, Some(&viewer)).await;
        let known_manager = people.iter().any(|p| p.identity.sub == manager_sub)
            || state.directory.get_identity(&manager_sub).await.is_some()
            || state.store.get_profile(&manager_sub).await.is_some();
        if !known_manager {
            return Err(AppError::InvalidRequest(
                "manager subject is unknown".to_string(),
            ));
        }
    }
    let phone = cap(form.phone.trim(), MAX_TITLE_CHARS);
    let location = cap(form.location.trim(), MAX_TITLE_CHARS);
    let timezone = cap(form.timezone.trim(), MAX_TITLE_CHARS);
    let locale = normalize_locale(&form.locale);
    let bio = cap(form.bio.trim(), MAX_BIO_CHARS);
    // Store only an allowlisted avatar URL; a rejected scheme (javascript:, data:, …) blanks it.
    let avatar_url = cap(
        &markdown::safe_avatar_url(&form.avatar_url).unwrap_or_default(),
        MAX_URL_CHARS,
    );

    let profile = Profile {
        sub: sub.clone(),
        display_name,
        title,
        department,
        manager_sub,
        phone,
        location,
        timezone,
        locale,
        bio,
        avatar_url,
        updated_at: now_secs(),
    };
    state.store.upsert_profile(&profile).await?;
    tracing::info!(sub = %sub, "profile updated");

    let actor = if actor_email.is_empty() {
        sub.clone()
    } else {
        actor_email
    };
    state.audit.emit(AuditEvent::info(
        "census.profile.update",
        &actor,
        &sub,
        "profile edited",
    ));

    let lang_cookie = if profile.locale.is_empty() {
        auth::clear_lang_cookie()
    } else {
        auth::lang_cookie(&profile.locale)
    };
    let mut resp = redirect(&format!("/u/{sub}"));
    if let Ok(value) = HeaderValue::from_str(&lang_cookie) {
        resp.headers_mut().append(header::SET_COOKIE, value);
    }
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

/// The viewer's identity from the gateway headers, if signed in.
pub fn viewer_identity(headers: &HeaderMap) -> Option<Identity> {
    auth::viewer_sub(headers).map(|sub| Identity {
        sub,
        email: auth::viewer_email(headers).unwrap_or_default(),
    })
}

/// One directory row: avatar + name (linking the person page) + title + email + bio excerpt.
fn render_person_row(p: &Person) -> String {
    let label = p.label();
    let avatar = render_avatar(&p.profile.avatar_url, &label, "avatar--sm");
    let title = if p.profile.title.trim().is_empty() {
        String::new()
    } else {
        format!(
            r#"<span class="row__title">{}</span>"#,
            esc(&p.profile.title)
        )
    };
    let email = if p.identity.email.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="row__email">{}</div>"#,
            esc(&p.identity.email)
        )
    };
    let mut meta = Vec::new();
    if !p.profile.department.trim().is_empty() {
        meta.push(p.profile.department.trim().to_string());
    }
    if !p.profile.location.trim().is_empty() {
        meta.push(p.profile.location.trim().to_string());
    }
    let meta = if meta.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="row__meta">{}</div>"#, esc(&meta.join(" · ")))
    };
    let excerpt = markdown::excerpt(&p.profile.bio, 140);
    let bio = if excerpt.is_empty() {
        String::new()
    } else {
        format!(r#"<p class="row__bio">{}</p>"#, esc(&excerpt))
    };
    format!(
        r#"<a class="person-row" href="/u/{sub}">
  {avatar}
  <div class="row__main">
    <div class="row__head"><span class="row__name">{name}</span>{title}</div>
    {email}
    {meta}
    {bio}
  </div>
</a>"#,
        sub = esc(&p.identity.sub),
        avatar = avatar,
        name = esc(&label),
        title = title,
        email = email,
        meta = meta,
        bio = bio,
    )
}

/// Render an avatar: a sanitized `<img>` when the URL is allowlisted, else an initials glyph.
fn render_avatar(avatar_url: &str, label: &str, size_class: &str) -> String {
    match markdown::safe_avatar_url(avatar_url) {
        Some(url) => format!(
            r#"<span class="avatar {size}"><img src="{url}" alt="" loading="lazy"></span>"#,
            size = size_class,
            url = esc(&url),
        ),
        None => format!(
            r#"<span class="avatar {size}" aria-hidden="true">{init}</span>"#,
            size = size_class,
            init = esc(&initials(label)),
        ),
    }
}

fn render_department_options(departments: &[String], selected: &str) -> String {
    let mut html = r#"<option value="">All departments</option>"#.to_string();
    for dept in departments {
        let selected_attr = if dept.eq_ignore_ascii_case(selected) {
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = esc(dept),
            selected = selected_attr,
            label = esc(dept),
        ));
    }
    html
}

fn render_group_options(groups: &[Group], selected: &str) -> String {
    let mut html = r#"<option value="">All groups</option>"#.to_string();
    for group in groups {
        let selected_attr = if group.id == selected {
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{id}"{selected}>{name}</option>"#,
            id = esc(&group.id),
            selected = selected_attr,
            name = esc(&group.name),
        ));
    }
    html
}

fn render_manager(profile: &Profile, label_by_sub: &HashMap<String, String>) -> String {
    let manager_sub = profile.manager_sub.trim();
    if manager_sub.is_empty() {
        return r#"<span class="muted">No manager</span>"#.to_string();
    }
    let label = label_by_sub
        .get(manager_sub)
        .cloned()
        .unwrap_or_else(|| manager_sub.to_string());
    format!(
        r#"<a href="/u/{sub}">{label}</a>"#,
        sub = esc(manager_sub),
        label = esc(&label),
    )
}

fn render_profile_details(profile: &Profile, manager_html: &str) -> String {
    let mut items = vec![format!(
        r#"<div class="detail"><dt>Manager</dt><dd>{}</dd></div>"#,
        manager_html
    )];
    for (label, value) in [
        ("Department", profile.department.trim()),
        ("Phone", profile.phone.trim()),
        ("Location", profile.location.trim()),
        ("Timezone", profile.timezone.trim()),
    ] {
        if !value.is_empty() {
            items.push(format!(
                r#"<div class="detail"><dt>{label}</dt><dd>{value}</dd></div>"#,
                label = esc(label),
                value = esc(value),
            ));
        }
    }
    format!(r#"<dl class="details-grid">{}</dl>"#, items.join(""))
}

fn render_direct_reports(sub: &str, people: &[Person]) -> String {
    let mut reports: Vec<&Person> = people
        .iter()
        .filter(|p| p.profile.manager_sub.trim() == sub)
        .collect();
    reports.sort_by(|a, b| a.label().to_lowercase().cmp(&b.label().to_lowercase()));
    if reports.is_empty() {
        return r#"<li class="chips__empty">No direct reports</li>"#.to_string();
    }
    let mut html = String::new();
    for report in reports {
        html.push_str(&format!(
            r#"<li class="chips__item"><a href="/u/{sub}">{label}</a></li>"#,
            sub = esc(&report.identity.sub),
            label = esc(&report.label()),
        ));
    }
    html
}

fn render_org_chart(people: &[Person]) -> String {
    if people.is_empty() {
        return r#"<div class="grouplist__empty">No people yet</div>"#.to_string();
    }

    let index_by_sub: HashMap<String, usize> = people
        .iter()
        .enumerate()
        .map(|(idx, p)| (p.identity.sub.clone(), idx))
        .collect();
    let mut children: HashMap<String, Vec<usize>> = HashMap::new();
    let mut roots = Vec::new();

    for (idx, p) in people.iter().enumerate() {
        let manager_sub = p.profile.manager_sub.trim();
        if !manager_sub.is_empty() && index_by_sub.contains_key(manager_sub) {
            children
                .entry(manager_sub.to_string())
                .or_default()
                .push(idx);
        } else {
            roots.push(idx);
        }
    }

    roots.sort_by(|a, b| {
        people[*a]
            .label()
            .to_lowercase()
            .cmp(&people[*b].label().to_lowercase())
    });
    for group in children.values_mut() {
        group.sort_by(|a, b| {
            people[*a]
                .label()
                .to_lowercase()
                .cmp(&people[*b].label().to_lowercase())
        });
    }

    let mut seen = HashSet::new();
    let mut html = String::new();
    for idx in roots {
        html.push_str(&render_org_node(idx, people, &children, &mut seen));
    }
    for idx in 0..people.len() {
        if !seen.contains(&people[idx].identity.sub) {
            html.push_str(&render_org_node(idx, people, &children, &mut seen));
        }
    }

    format!(r#"<ul class="org-tree">{html}</ul>"#)
}

fn render_org_node(
    idx: usize,
    people: &[Person],
    children: &HashMap<String, Vec<usize>>,
    seen: &mut HashSet<String>,
) -> String {
    let p = &people[idx];
    if !seen.insert(p.identity.sub.clone()) {
        return String::new();
    }
    let mut child_html = String::new();
    if let Some(child_indices) = children.get(&p.identity.sub) {
        for child_idx in child_indices {
            child_html.push_str(&render_org_node(*child_idx, people, children, seen));
        }
    }
    let child_list = if child_html.is_empty() {
        String::new()
    } else {
        format!(r#"<ul>{child_html}</ul>"#)
    };
    let mut meta = Vec::new();
    if !p.profile.title.trim().is_empty() {
        meta.push(p.profile.title.trim().to_string());
    }
    if !p.profile.department.trim().is_empty() {
        meta.push(p.profile.department.trim().to_string());
    }
    let meta = if meta.is_empty() {
        String::new()
    } else {
        format!(
            r#"<span class="org-card__meta">{}</span>"#,
            esc(&meta.join(" · "))
        )
    };
    format!(
        r#"<li class="org-node"><div class="org-card"><a href="/u/{sub}">{label}</a>{meta}</div>{children}</li>"#,
        sub = esc(&p.identity.sub),
        label = esc(&p.label()),
        meta = meta,
        children = child_list,
    )
}

/// The owner's inline profile edit form (CSRF-protected, posts to `/api/profile`).
fn render_edit_form(csrf: &str, profile: &Profile, people: &[Person]) -> String {
    let manager_options = render_manager_options(people, profile);
    let locale_options = render_locale_options(&profile.locale);
    format!(
        r#"<section class="card edit-card">
  <div class="card__body">
    <h2 class="edit-card__head">Edit your profile</h2>
    <form class="editor" method="post" action="/api/profile">
      <input type="hidden" name="csrf_token" value="{csrf}">
      <div class="field">
        <label for="display_name">Display name</label>
        <input type="text" id="display_name" name="display_name" maxlength="120" placeholder="Your name" value="{name}">
      </div>
      <div class="field">
        <label for="title">Title</label>
        <input type="text" id="title" name="title" maxlength="160" placeholder="e.g. Platform Engineer" value="{title}">
      </div>
      <div class="field-grid">
        <div class="field">
          <label for="department">Department</label>
          <input type="text" id="department" name="department" maxlength="160" placeholder="e.g. Engineering" value="{department}">
        </div>
        <div class="field">
          <label for="manager_sub">Manager</label>
          <select id="manager_sub" name="manager_sub">{manager_options}</select>
        </div>
      </div>
      <div class="field-grid">
        <div class="field">
          <label for="phone">Phone</label>
          <input type="text" id="phone" name="phone" maxlength="160" placeholder="+1 555 0100" value="{phone}">
        </div>
        <div class="field">
          <label for="location">Location</label>
          <input type="text" id="location" name="location" maxlength="160" placeholder="City, country" value="{location}">
        </div>
      </div>
      <div class="field-grid">
        <div class="field">
          <label for="timezone">Timezone</label>
          <input type="text" id="timezone" name="timezone" maxlength="160" placeholder="e.g. America/New_York" value="{timezone}">
        </div>
        <div class="field">
          <label for="locale">Language</label>
          <select id="locale" name="locale">{locale_options}</select>
        </div>
      </div>
      <div class="field">
        <label for="avatar_url">Avatar URL <span class="muted">(http/https)</span></label>
        <input type="text" id="avatar_url" name="avatar_url" maxlength="1024" placeholder="https://…" value="{avatar}">
      </div>
      <div class="field">
        <label for="bio">Bio <span class="muted">(Markdown)</span></label>
        <textarea id="bio" name="bio" class="editor__body" placeholder="A short bio in Markdown&hellip;">{bio}</textarea>
      </div>
      <div class="editor__actions">
        <button class="btn btn-primary" type="submit">Save profile</button>
      </div>
    </form>
  </div>
</section>"#,
        csrf = esc(csrf),
        name = esc(&profile.display_name),
        title = esc(&profile.title),
        department = esc(&profile.department),
        manager_options = manager_options,
        phone = esc(&profile.phone),
        location = esc(&profile.location),
        timezone = esc(&profile.timezone),
        locale_options = locale_options,
        avatar = esc(&profile.avatar_url),
        bio = esc(&profile.bio),
    )
}

fn render_locale_options(selected: &str) -> String {
    let selected = normalize_locale(selected);
    let mut html = String::new();
    for (code, label) in [
        ("", "System default"),
        ("en", "English"),
        ("zh", "中文"),
        ("ja", "日本語"),
    ] {
        let selected_attr = if code == selected { " selected" } else { "" };
        html.push_str(&format!(
            r#"<option value="{code}"{selected}>{label}</option>"#,
            code = esc(code),
            selected = selected_attr,
            label = esc(label),
        ));
    }
    html
}

fn render_manager_options(people: &[Person], profile: &Profile) -> String {
    let selected = profile.manager_sub.trim();
    let mut html = format!(
        r#"<option value=""{selected_attr}>No manager</option>"#,
        selected_attr = if selected.is_empty() { " selected" } else { "" }
    );
    let mut found_selected = selected.is_empty();
    for p in people {
        if p.identity.sub == profile.sub {
            continue;
        }
        let selected_attr = if p.identity.sub == selected {
            found_selected = true;
            " selected"
        } else {
            ""
        };
        html.push_str(&format!(
            r#"<option value="{sub}"{selected}>{label}</option>"#,
            sub = esc(&p.identity.sub),
            selected = selected_attr,
            label = esc(&p.label()),
        ));
    }
    if !found_selected && !selected.is_empty() {
        html.push_str(&format!(
            r#"<option value="{sub}" selected>{sub}</option>"#,
            sub = esc(selected),
        ));
    }
    html
}

fn normalize_locale(raw: &str) -> String {
    match raw.trim() {
        "en" => "en".to_string(),
        "zh" => "zh".to_string(),
        "ja" => "ja".to_string(),
        _ => String::new(),
    }
}

/// Truncate a string to at most `n` chars (defense against oversized submissions).
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
