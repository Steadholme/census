//! Directory + person views and the SSO-gated profile edit.
//!
//! The directory (`GET /`) joins every Keystone identity to its editable profile and supports a
//! keyword filter; the person page (`GET /u/{sub}`) shows one profile plus its group memberships.
//! `POST /api/profile` edits the VIEWER's OWN profile — the subject is ALWAYS the gateway-injected
//! `X-Auth-Subject`, never a client field — behind a double-submit CSRF check, and emits a
//! `census.profile.update` audit event.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use crate::audit::AuditEvent;
use crate::auth;
use crate::config::{MAX_BIO_CHARS, MAX_NAME_CHARS, MAX_TITLE_CHARS, MAX_URL_CHARS};
use crate::directory::Identity;
use crate::error::AppError;
use crate::handlers::{esc, fmt_date, html_with_cookie, initials, redirect, topbar, APP_CSS};
use crate::markdown;
use crate::store::Profile;
use crate::{now_secs, AppState};

const DIRECTORY_HTML: &str = include_str!("../../templates/directory.html");
const PERSON_HTML: &str = include_str!("../../templates/person.html");

/// One assembled directory entry: a real identity joined to its (possibly default) profile.
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
}

/// Profile-edit form body. Identity is NEVER taken from the form — only from the gateway headers.
#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub title: String,
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

/// True when the person matches the (already lowercased) keyword across name / email / title / sub.
fn matches(p: &Person, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    p.profile.display_name.to_lowercase().contains(needle)
        || p.identity.email.to_lowercase().contains(needle)
        || p.profile.title.to_lowercase().contains(needle)
        || p.identity.sub.to_lowercase().contains(needle)
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

    let people = assemble_people(&state, viewer.as_ref()).await;
    let total = people.len();

    let mut rows = String::new();
    let mut shown = 0usize;
    for p in &people {
        if !matches(p, &needle_lc) {
            continue;
        }
        shown += 1;
        rows.push_str(&render_person_row(p));
    }
    if shown == 0 {
        rows.push_str(
            r#"<div class="empty-state"><h2>No people found</h2><p>No directory identity matches your search.</p></div>"#,
        );
    }

    // Groups panel: name + member count, newest activity not tracked so name-ordered.
    let groups = state.store.list_groups().await;
    let mut group_items = String::new();
    for g in &groups {
        let count = state.store.members_of(&g.id).await.len();
        group_items.push_str(&format!(
            r#"<li class="grouplist__item"><a href="/groups">{name}</a><span class="grouplist__count">{count}</span></li>"#,
            name = esc(&g.name),
            count = count,
        ));
    }
    if group_items.is_empty() {
        group_items.push_str(r#"<li class="grouplist__empty">No groups yet</li>"#);
    }

    let count_label = if needle_lc.is_empty() {
        format!("{total} {}", plural(total, "person", "people"))
    } else {
        format!("{shown} of {total} {}", plural(total, "person", "people"))
    };

    let body = DIRECTORY_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Directory", &email))
        .replace("{{QUERY}}", &esc(needle.trim()))
        .replace("{{COUNT}}", &esc(&count_label))
        .replace("{{ROWS}}", &rows)
        .replace("{{GROUPS}}", &group_items);
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

    let profile = state.store.get_profile(&sub).await.unwrap_or_else(|| Profile {
        sub: sub.clone(),
        ..Profile::default()
    });

    let is_self = viewer.as_ref().map(|v| v.sub.as_str()) == Some(sub.as_str());

    // Group memberships, with the group name resolved (skip a dangling edge whose group is gone).
    let memberships = state.store.groups_of(&sub).await;
    let mut group_html = String::new();
    for m in &memberships {
        if let Some(g) = state.store.get_group(&m.group_id).await {
            group_html.push_str(&format!(
                r#"<li class="chips__item"><a href="/groups">{name}</a><span class="chip-role">{role}</span></li>"#,
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
        format!(r#"<div class="person__title">{}</div>"#, esc(&profile.title))
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

    // The owner gets an inline edit form (CSRF-protected). Otherwise the section is empty.
    let (csrf, set_cookie) = auth::ensure_csrf(&headers);
    let edit_block = if is_self {
        render_edit_form(&csrf, &profile)
    } else {
        String::new()
    };

    let page = PERSON_HTML
        .replace("{{CSS}}", APP_CSS)
        .replace("{{TOPBAR}}", &topbar("Person", &email))
        .replace("{{NAME_TEXT}}", &esc(&label))
        .replace("{{AVATAR}}", &avatar)
        .replace("{{NAME}}", &esc(&label))
        .replace("{{TITLE_LINE}}", &title_line)
        .replace("{{EMAIL_LINE}}", &email_line)
        .replace("{{UPDATED}}", &esc(&fmt_date(profile.updated_at)))
        .replace("{{BIO}}", &bio_html)
        .replace("{{GROUPS}}", &group_html)
        .replace("{{EDIT}}", &edit_block);

    // Only attach the freshly-minted CSRF cookie when we actually rendered the owner form.
    Ok(html_with_cookie(page, if is_self { set_cookie } else { None }))
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
        bio,
        avatar_url,
        updated_at: now_secs(),
    };
    state.store.upsert_profile(&profile).await?;
    tracing::info!(sub = %sub, "profile updated");

    let actor = if actor_email.is_empty() { sub.clone() } else { actor_email };
    state.audit.emit(AuditEvent::info(
        "census.profile.update",
        &actor,
        &sub,
        "profile edited",
    ));

    Ok(redirect(&format!("/u/{sub}")))
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
        format!(r#"<span class="row__title">{}</span>"#, esc(&p.profile.title))
    };
    let email = if p.identity.email.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="row__email">{}</div>"#, esc(&p.identity.email))
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
    {bio}
  </div>
</a>"#,
        sub = esc(&p.identity.sub),
        avatar = avatar,
        name = esc(&label),
        title = title,
        email = email,
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

/// The owner's inline profile edit form (CSRF-protected, posts to `/api/profile`).
fn render_edit_form(csrf: &str, profile: &Profile) -> String {
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
        avatar = esc(&profile.avatar_url),
        bio = esc(&profile.bio),
    )
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
