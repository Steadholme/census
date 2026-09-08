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
use crate::directory::{DirectoryError, Identity, IdentityPage};
use crate::error::{AppError, UnavailableKind};
use crate::handlers::{
    esc, fmt_date, html_with_cookie, initials, redirect, render_template, shell, theme_of,
};
use crate::markdown;
use crate::store::{recursive_members_of, Group, Page, Profile, StoreError};
use crate::workforce::WorkforceRecord;
use crate::{now_secs, AppState};

const DIRECTORY_HTML: &str = include_str!("../../templates/directory.html");
const PERSON_HTML: &str = include_str!("../../templates/person.html");

/// One assembled directory entry: a real identity joined to its (possibly default) profile.
#[derive(Clone)]
pub struct Person {
    pub identity: Identity,
    pub profile: Profile,
    pub provenance: Provenance,
}

/// The source fact behind a rendered person. Enumerated identities are deliberately unmarked.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Provenance {
    Enumerated,
    Provisional,
    ProfileOnly,
    SubjectOnly,
}

impl Provenance {
    pub fn class(self) -> Option<&'static str> {
        match self {
            Self::Enumerated => None,
            Self::Provisional => Some("provisional"),
            Self::ProfileOnly => Some("profile-only"),
            Self::SubjectOnly => Some("subject-only"),
        }
    }
}

/// A successful authoritative join, retaining identity-source count and bound truth.
pub struct Assembled {
    pub people: Vec<Person>,
    pub identity_count: usize,
    pub identity_overflow: bool,
}

/// A read failure from one of the two authoritative sources used by the people join.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Identity(#[from] DirectoryError),
    #[error(transparent)]
    Store(#[from] StoreError),
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
pub async fn assemble_people(
    state: &AppState,
    viewer: Option<&Identity>,
) -> Result<Assembled, ReadError> {
    let identities = state.directory.list_identities().await?;
    let profiles = state.store.list_profiles().await?;
    let workforce = state.store.list_workforce_records().await?;
    if workforce.overflow {
        return Err(ReadError::Store(StoreError::Backend(
            "workforce record bound exceeded".to_string(),
        )));
    }
    Ok(assemble_pages(identities, profiles, workforce, viewer))
}

fn assemble_pages(
    identities: IdentityPage,
    profiles: Page<Profile>,
    workforce: Page<WorkforceRecord>,
    viewer: Option<&Identity>,
) -> Assembled {
    let identity_overflow = identities.overflow;
    let profile_by_sub: HashMap<String, Profile> = profiles
        .items
        .into_iter()
        .map(|profile| (profile.sub.clone(), profile))
        .collect();
    let workforce_by_sub: HashMap<String, WorkforceRecord> = workforce
        .items
        .into_iter()
        .map(|record| (record.subject.clone(), record))
        .collect();
    let now = now_secs();

    let mut by_sub: HashMap<String, Person> = HashMap::new();
    for identity in identities.items {
        let authoritative = workforce_by_sub.get(&identity.sub);
        if authoritative.is_some_and(|record| {
            record.effective_at <= now && record.employment_status.suppresses_active_directory()
        }) {
            continue;
        }
        let mut profile = profile_by_sub
            .get(&identity.sub)
            .cloned()
            .unwrap_or_else(|| Profile {
                sub: identity.sub.clone(),
                ..Profile::default()
            });
        overlay_authoritative_org(&mut profile, authoritative);
        by_sub.insert(
            identity.sub.clone(),
            Person {
                identity,
                profile,
                provenance: Provenance::Enumerated,
            },
        );
    }
    if let Some(identity) = viewer {
        let authoritative = workforce_by_sub.get(&identity.sub);
        if !authoritative.is_some_and(|record| {
            record.effective_at <= now && record.employment_status.suppresses_active_directory()
        }) {
            by_sub
                .entry(identity.sub.clone())
                .or_insert_with(|| Person {
                    identity: identity.clone(),
                    profile: {
                        let mut profile = profile_by_sub
                            .get(&identity.sub)
                            .cloned()
                            .unwrap_or_else(|| Profile {
                                sub: identity.sub.clone(),
                                ..Profile::default()
                            });
                        overlay_authoritative_org(&mut profile, authoritative);
                        profile
                    },
                    provenance: Provenance::Provisional,
                });
        }
    }

    let mut people: Vec<Person> = by_sub.into_values().collect();
    people.sort_by_key(|person| (person.label().to_lowercase(), person.identity.sub.clone()));
    let identity_count = people
        .iter()
        .filter(|person| person.provenance == Provenance::Enumerated)
        .count();
    Assembled {
        people,
        identity_count,
        identity_overflow,
    }
}

fn overlay_authoritative_org(profile: &mut Profile, workforce: Option<&WorkforceRecord>) {
    let Some(workforce) = workforce else {
        return;
    };
    profile.department = workforce.department.clone();
    profile.manager_sub = workforce.manager_subject.clone().unwrap_or_default();
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

    let identity_result = state.directory.list_identities().await;
    let profile_result = state.store.list_profiles().await;
    let workforce_result = state.store.list_workforce_records().await;
    let identity_unavailable = identity_result.is_err();
    let profile_unavailable = profile_result.is_err();
    let workforce_unavailable = match &workforce_result {
        Ok(page) => page.overflow,
        Err(_) => true,
    };
    if let Err(error) = &identity_result {
        tracing::error!(%error, "identity source unavailable on directory");
    }
    if let Err(error) = &profile_result {
        tracing::error!(%error, "profile store unavailable on directory");
    }
    match &workforce_result {
        Err(error) => tracing::error!(%error, "workforce authority unavailable on directory"),
        Ok(page) if page.overflow => {
            tracing::error!("workforce record bound exceeded on directory")
        }
        Ok(_) => {}
    }
    let roll_unavailable = identity_unavailable || workforce_unavailable;
    // Newest observation across the workforce authority — the "Workforce sync" stat tile.
    let workforce_sync = workforce_result
        .as_ref()
        .ok()
        .and_then(|page| page.items.iter().map(|record| record.observed_at).max());

    let (people, total, identity_overflow) = match (
        identity_result.ok(),
        profile_result.ok(),
        workforce_result.ok().filter(|page| !page.overflow),
    ) {
        (Some(identities), Some(profiles), Some(workforce)) => {
            let assembled = assemble_pages(identities, profiles, workforce, viewer.as_ref());
            (
                assembled.people,
                assembled.identity_count,
                assembled.identity_overflow,
            )
        }
        (Some(identities), None, Some(workforce)) => {
            let assembled = assemble_pages(
                identities,
                Page {
                    items: Vec::new(),
                    overflow: false,
                },
                workforce,
                viewer.as_ref(),
            );
            (
                assembled.people,
                assembled.identity_count,
                assembled.identity_overflow,
            )
        }
        _ => (Vec::new(), 0, false),
    };

    let groups_result = state.store.list_groups().await;
    let mut groups = Vec::new();
    let mut groups_unavailable = false;
    match groups_result {
        Ok(page) => groups = page.items,
        Err(error) => {
            tracing::error!(error = %error, "group store unavailable on directory");
            groups_unavailable = true;
        }
    }

    let mut group_names_by_sub: HashMap<String, Vec<String>> = HashMap::new();
    let mut members_by_group: HashMap<String, HashSet<String>> = HashMap::new();
    for g in &groups {
        let members = match recursive_members_of(state.store.as_ref(), &g.id).await {
            Ok(members) => members,
            Err(error) => {
                tracing::error!(error = %error, group = %g.id, "group membership read failed");
                groups_unavailable = true;
                group_names_by_sub.clear();
                members_by_group.clear();
                break;
            }
        };
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
    let mut shown_enumerated = 0usize;
    let mut visible_people = Vec::new();
    for p in &people {
        if !dept_filter_lc.is_empty()
            && p.profile.department.trim().to_lowercase() != dept_filter_lc
        {
            continue;
        }
        if !groups_unavailable
            && !group_filter.is_empty()
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
        if p.provenance == Provenance::Enumerated {
            shown_enumerated += 1;
        }
        visible_people.push(p.clone());
        rows.push_str(&render_person_row(
            p,
            visible_people.len(),
            viewer.as_ref().map(|item| item.sub.as_str()) == Some(p.identity.sub.as_str()),
            group_names,
        ));
    }
    if roll_unavailable {
        rows = r#"<li class="roll__empty">The roll is withheld while an authoritative source is unavailable.</li>"#.to_string();
    } else if total == 0
        && needle_lc.is_empty()
        && dept_filter_lc.is_empty()
        && group_filter.is_empty()
    {
        rows.push_str(r#"<li class="roll__empty">No one else is on the roll yet.</li>"#);
    } else if shown == 0 {
        rows.push_str(r#"<li class="roll__empty">No matches</li>"#);
    }

    // Groups panel: name + recursive member count, newest activity not tracked so name-ordered.
    let mut group_items = String::new();
    if groups_unavailable {
        group_items.push_str(
            r#"<li class="grouplist__empty section-note">Groups unavailable — membership filters and counts are withheld.</li>"#,
        );
    } else {
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
    }
    if group_items.is_empty() {
        group_items.push_str(r#"<li class="grouplist__empty">No groups yet</li>"#);
    }

    let filters_active = !needle_lc.is_empty()
        || !dept_filter_lc.is_empty()
        || (!groups_unavailable && !group_filter.is_empty());
    let count_label = if roll_unavailable {
        "Authoritative source unavailable — roll withheld".to_string()
    } else if identity_overflow && !filters_active {
        format!("Showing the first {} people", format_count(total))
    } else if total == 0 {
        "0 people enumerated by the identity source".to_string()
    } else if !filters_active {
        format!(
            "{} {} on the roll",
            format_count(total),
            plural(total, "person", "people")
        )
    } else {
        format!(
            "{} of {} people",
            format_count(shown_enumerated),
            format_count(total)
        )
    };
    let org_chart = if roll_unavailable {
        r#"<p class="section-note">Reporting contours are withheld until authoritative sources return.</p>"#.to_string()
    } else {
        render_org_chart(&visible_people)
    };
    let banner = render_directory_banner(
        identity_unavailable,
        profile_unavailable,
        workforce_unavailable,
    );
    let boundary = if identity_overflow {
        render_boundary("More people exist than shown — the roll stops at a survey bound of 2,000.")
    } else {
        String::new()
    };
    let legend = render_legend(&visible_people);

    let provisional_shown = visible_people
        .iter()
        .filter(|person| person.provenance == Provenance::Provisional)
        .count();
    let stats = render_stats(
        roll_unavailable,
        total,
        groups_unavailable,
        groups.len(),
        departments.len(),
        provisional_shown,
        workforce_sync,
    );
    let query = esc(needle.trim());
    let department_options = render_department_options(&departments, dept_filter.trim());
    let group_options = render_group_options(&groups, &group_filter, groups_unavailable);
    let count = esc(&count_label);
    let body = render_template(
        &shell(DIRECTORY_HTML, "/", theme_of(&headers), Some(&email)),
        &[
            ("{{STATS}}", &stats),
            ("{{BANNER}}", &banner),
            ("{{BOUNDARY}}", &boundary),
            ("{{LEGEND}}", &legend),
            ("{{QUERY}}", &query),
            ("{{DEPARTMENT_OPTIONS}}", &department_options),
            ("{{GROUP_OPTIONS}}", &group_options),
            ("{{COUNT}}", &count),
            ("{{ROWS}}", &rows),
            ("{{GROUPS}}", &group_items),
            ("{{ORG_CHART}}", &org_chart),
        ],
    );
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

    let identity_result = state
        .directory
        .get_identity(&sub)
        .await
        .map_err(map_identity_unavailable)?;
    let stored_profile = state
        .store
        .get_profile(&sub)
        .await
        .map_err(map_profile_unavailable)?;

    let (identity, provenance) = match identity_result {
        Some(identity) => (identity, Provenance::Enumerated),
        None if viewer.as_ref().map(|item| item.sub.as_str()) == Some(sub.as_str()) => (
            viewer.clone().expect("viewer branch checked"),
            Provenance::Provisional,
        ),
        None if stored_profile.is_some() => (
            Identity {
                sub: sub.clone(),
                email: String::new(),
            },
            Provenance::ProfileOnly,
        ),
        None => return Err(AppError::NotFound("no such person".to_string())),
    };

    let profile = stored_profile.unwrap_or_else(|| Profile {
        sub: sub.clone(),
        ..Profile::default()
    });

    let is_self = viewer.as_ref().map(|v| v.sub.as_str()) == Some(sub.as_str());
    let people = assemble_people(&state, viewer.as_ref())
        .await
        .map_err(map_people_unavailable)?
        .people;
    let label_by_sub: HashMap<String, String> = people
        .iter()
        .map(|p| (p.identity.sub.clone(), p.label()))
        .collect();

    // Group memberships, with the group name resolved (skip a dangling edge whose group is gone).
    let memberships = state
        .store
        .groups_of(&sub)
        .await
        .map_err(map_group_unavailable)?;
    let mut group_html = String::new();
    for m in &memberships {
        if let Some(g) = state
            .store
            .get_group(&m.group_id)
            .await
            .map_err(map_group_unavailable)?
        {
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
        provenance,
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

    let name = esc(&label);
    let updated = esc(&updated_sentence(profile.updated_at));
    let prov_tag = render_prov_tag(provenance);
    let head_action = if is_self {
        r##"<a class="btn btn-secondary" href="#edit-profile">Edit profile</a>"##.to_string()
    } else if identity.email.is_empty() {
        String::new()
    } else {
        format!(
            r#"<a class="btn btn-secondary" href="mailto:{e}">Email</a>"#,
            e = esc(&identity.email)
        )
    };
    let report_count = count_chip_items(&reports_html);
    let group_count = count_chip_items(&group_html);
    let provenance = render_provenance(provenance);
    let page = render_template(
        &shell(PERSON_HTML, "/", theme_of(&headers), Some(&email)),
        &[
            ("{{NAME_TEXT}}", &name),
            ("{{PROV_TAG}}", &prov_tag),
            ("{{HEAD_ACTION}}", &head_action),
            ("{{REPORT_COUNT}}", &report_count),
            ("{{GROUP_COUNT}}", &group_count),
            ("{{AVATAR}}", &avatar),
            ("{{NAME}}", &name),
            ("{{TITLE_LINE}}", &title_line),
            ("{{EMAIL_LINE}}", &email_line),
            ("{{UPDATED}}", &updated),
            ("{{PROVENANCE}}", &provenance),
            ("{{DETAILS}}", &details_html),
            ("{{REPORTS}}", &reports_html),
            ("{{BIO}}", &bio_html),
            ("{{GROUPS}}", &group_html),
            ("{{EDIT}}", &edit_block),
        ],
    );

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

    let workforce = state
        .store
        .get_workforce_record(&sub)
        .await
        .map_err(map_profile_unavailable)?;
    let authoritative_org = workforce.as_ref();
    if authoritative_org.is_some_and(|record| {
        record.effective_at <= now_secs() && record.employment_status.suppresses_active_directory()
    }) {
        return Err(AppError::Forbidden(
            "workforce status does not permit profile updates".to_string(),
        ));
    }

    let display_name = cap(form.display_name.trim(), MAX_NAME_CHARS);
    let title = cap(form.title.trim(), MAX_TITLE_CHARS);
    // Department and manager become workforce-owned as soon as the record is effective. A
    // self-service form may still submit legacy fields, but cannot overwrite those facts.
    let department = authoritative_org.map_or_else(
        || cap(form.department.trim(), MAX_TITLE_CHARS),
        |record| record.department.clone(),
    );
    let manager_sub = authoritative_org.map_or_else(
        || cap(form.manager_sub.trim(), MAX_NAME_CHARS),
        |record| record.manager_subject.clone().unwrap_or_default(),
    );
    if manager_sub == sub {
        return Err(AppError::InvalidRequest(
            "manager cannot be the profile owner".to_string(),
        ));
    }
    if authoritative_org.is_none() && !manager_sub.is_empty() {
        let viewer = Identity {
            sub: sub.clone(),
            email: actor_email.clone(),
        };
        let people = assemble_people(&state, Some(&viewer))
            .await
            .map_err(map_people_unavailable)?
            .people;
        let known_manager = people.iter().any(|p| p.identity.sub == manager_sub)
            || state
                .directory
                .get_identity(&manager_sub)
                .await
                .map_err(map_identity_unavailable)?
                .is_some()
            || state
                .store
                .get_profile(&manager_sub)
                .await
                .map_err(map_profile_unavailable)?
                .is_some();
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

/// One ledger row: ordinal, identity, optional profile facts, and exception-only provenance.
fn render_person_row(p: &Person, ordinal: usize, is_self: bool, group_names: &[String]) -> String {
    let label = p.label();
    let avatar = render_avatar(&p.profile.avatar_url, &label, "avatar--sm");
    let title = if p.profile.title.trim().is_empty() {
        String::new()
    } else {
        format!(
            r#"<span class="roll__title">{}</span>"#,
            esc(&p.profile.title)
        )
    };
    let email = if p.identity.email.is_empty() {
        String::new()
    } else {
        format!(
            r#"<span class="roll__email">{}</span>"#,
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
        format!(
            r#"<span class="roll__meta">{}</span>"#,
            escape_roll_meta(&meta.join(" · "))
        )
    };
    let excerpt = markdown::excerpt(&p.profile.bio, 140);
    let bio = if excerpt.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="roll__bio">{}</span>"#, esc(&excerpt))
    };
    let you = if is_self {
        r#"<span class="roll__you">(you)</span>"#
    } else {
        ""
    };
    let provenance = render_prov_tag(p.provenance);
    let groups = render_roll_groups(group_names);
    format!(
        r#"<li class="roll__row">
  <a class="roll__entry" href="/u/{sub}">
  <span class="roll__index" aria-hidden="true">{ordinal:04}</span>
  {avatar}
  <span class="roll__main">
    <span class="roll__head"><span class="roll__name">{name}</span>{title}{you}{provenance}</span>
    {email}
    {meta}
    {bio}
  </span>
  {groups}
  </a>
</li>"#,
        sub = esc(&p.identity.sub),
        ordinal = ordinal,
        avatar = avatar,
        name = esc(&label),
        title = title,
        you = you,
        provenance = provenance,
        email = email,
        meta = meta,
        bio = bio,
        groups = groups,
    )
}

/// The group chips shown at the right of a roll row. Names only — a membership is descriptive,
/// so no count or role is repeated here. Beyond four chips the row states the remainder instead
/// of growing without bound.
fn render_roll_groups(group_names: &[String]) -> String {
    if group_names.is_empty() {
        return String::new();
    }
    const SHOWN: usize = 4;
    let mut html = String::from(r#"<span class="roll__groups">"#);
    for name in group_names.iter().take(SHOWN) {
        html.push_str(&format!(
            r#"<span class="gchip">{}</span>"#,
            esc(&cap(name, 28))
        ));
    }
    if group_names.len() > SHOWN {
        html.push_str(&format!(
            r#"<span class="gchip gchip--more">+{}</span>"#,
            group_names.len() - SHOWN
        ));
    }
    html.push_str("</span>");
    html
}

/// Escape directory metadata while adding copy-transparent wrap opportunities to hostile long
/// runs. Breaks are selected from the raw Unicode scalars before escaping, so an HTML entity can
/// never be split and multi-byte characters are never sliced between code points.
fn escape_roll_meta(value: &str) -> String {
    const BREAK_EVERY_SCALARS: usize = 16;

    let mut html = String::with_capacity(value.len());
    let mut run_start = 0;

    for (byte_index, ch) in value.char_indices() {
        if !ch.is_whitespace() {
            continue;
        }

        push_escaped_run_with_breaks(
            &mut html,
            &value[run_start..byte_index],
            BREAK_EVERY_SCALARS,
        );
        let whitespace_end = byte_index + ch.len_utf8();
        html.push_str(&esc(&value[byte_index..whitespace_end]));
        run_start = whitespace_end;
    }

    push_escaped_run_with_breaks(&mut html, &value[run_start..], BREAK_EVERY_SCALARS);
    html
}

fn push_escaped_run_with_breaks(html: &mut String, run: &str, interval: usize) {
    let mut chunk_start = 0;
    for (scalar_index, (byte_index, _)) in run.char_indices().enumerate() {
        if scalar_index > 0 && scalar_index.is_multiple_of(interval) {
            html.push_str(&esc(&run[chunk_start..byte_index]));
            html.push_str("<wbr>");
            chunk_start = byte_index;
        }
    }
    html.push_str(&esc(&run[chunk_start..]));
}

/// Render an avatar: a sanitized `<img>` when the URL is allowlisted, else an initials glyph.
fn render_avatar(avatar_url: &str, label: &str, size_class: &str) -> String {
    match markdown::safe_avatar_url(avatar_url) {
        Some(url) => format!(
            r#"<span class="avatar {size}"><img src="{url}" alt="" loading="lazy" referrerpolicy="no-referrer"></span>"#,
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

/// The five directory stat tiles: roll size, groups, departments, provisional marks, sync stamp.
///
/// Every tile is a name over a value; a withheld source renders an em dash rather than a zero, so
/// an outage never reads as an empty estate.
fn render_stats(
    roll_unavailable: bool,
    total: usize,
    groups_unavailable: bool,
    group_count: usize,
    department_count: usize,
    provisional: usize,
    workforce_sync: Option<i64>,
) -> String {
    let dash = "—".to_string();
    let people_value = if roll_unavailable {
        dash.clone()
    } else {
        format_count(total)
    };
    let (groups_value, departments_value) = if groups_unavailable {
        (dash.clone(), format_count(department_count))
    } else {
        (format_count(group_count), format_count(department_count))
    };
    let sync_value = match workforce_sync {
        Some(observed) if observed > 0 => fmt_date(observed),
        _ => dash.clone(),
    };
    let mut html = String::new();
    for (value, label, marked, mono) in [
        (people_value, "People", false, false),
        (groups_value, "Groups", false, false),
        (departments_value, "Departments", false, false),
        (
            format_count(provisional),
            "Provisional",
            provisional > 0,
            false,
        ),
        (sync_value, "Workforce sync", false, true),
    ] {
        html.push_str(&format!(
            r#"<div class="stat-tile{mark}"><div class="stat-tile__value{mono}">{value}</div><div class="stat-tile__label">{label}</div></div>"#,
            mark = if marked { " stat-tile--mark" } else { "" },
            mono = if mono { " mono" } else { "" },
            value = esc(&value),
            label = esc(label),
        ));
    }
    html
}

/// Count the rendered `chips__item` entries so a card head can carry the number. An empty-state
/// fragment (`chips__empty`) counts as zero.
fn count_chip_items(html: &str) -> String {
    format_count(html.matches(r#"<li class="chips__item">"#).count())
}

fn render_prov_tag(provenance: Provenance) -> String {
    provenance.class().map_or_else(String::new, |class| {
        format!(
            r#"<span class="prov prov--{class}">{class}</span>"#,
            class = esc(class),
        )
    })
}

fn render_provenance(provenance: Provenance) -> String {
    let Some(class) = provenance.class() else {
        return String::new();
    };
    let copy = match provenance {
        Provenance::Enumerated => return String::new(),
        Provenance::Provisional => {
            "Provisional — supplied by the current gateway identity, not enumerated by the identity source."
        }
        Provenance::ProfileOnly => {
            "Profile-only — profile details exist, but the identity source does not enumerate this subject."
        }
        Provenance::SubjectOnly => {
            "Subject-only — a membership names this subject without an identity or profile record."
        }
    };
    format!(
        r#"<p class="prov-note prov--{class}" role="note">{copy}</p>"#,
        class = esc(class),
        copy = esc(copy),
    )
}

fn render_legend(people: &[Person]) -> String {
    let present: HashSet<Provenance> = people
        .iter()
        .filter_map(|person| person.provenance.class().map(|_| person.provenance))
        .collect();
    if present.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for (provenance, copy) in [
        (
            Provenance::Provisional,
            "provisional — current gateway identity, absent from the source roll",
        ),
        (
            Provenance::ProfileOnly,
            "profile-only — saved profile without a source-roll identity",
        ),
        (
            Provenance::SubjectOnly,
            "subject-only — membership subject without identity or profile details",
        ),
    ] {
        if present.contains(&provenance) {
            let class = provenance.class().expect("non-enumerated provenance");
            items.push_str(&format!(
                r#"<li class="legend__item"><span class="prov prov--{class}">{class}</span> {copy}</li>"#,
                class = esc(class),
                copy = esc(copy),
            ));
        }
    }
    format!(
        r#"<section class="legend" aria-label="Provenance legend"><h2 class="legend__title">Source marks</h2><p>Unmarked rows are enumerated by the identity source.</p><ul class="legend__items">{items}</ul></section>"#,
    )
}

fn render_boundary(copy: &str) -> String {
    format!(
        r#"<p class="bound" role="note"><span class="bound__mark" aria-hidden="true"></span>{}</p>"#,
        esc(copy),
    )
}

fn render_directory_banner(
    identity_unavailable: bool,
    profile_unavailable: bool,
    workforce_unavailable: bool,
) -> String {
    let (title, copy) = match (
        identity_unavailable,
        profile_unavailable,
        workforce_unavailable,
    ) {
        (_, _, true) => (
            "Workforce authority unavailable",
            "The authoritative roll is withheld until workforce state can be verified.",
        ),
        (true, true, false) => (
            "Directory sources unavailable",
            "Identity and profile reads failed. The roll is withheld rather than presented as empty.",
        ),
        (true, false, false) => (
            "Identity source unavailable",
            "The authoritative roll is withheld until the identity source returns.",
        ),
        (false, true, false) => (
            "Profiles unavailable",
            "Identity rows remain visible without profile details; reporting contours are incomplete.",
        ),
        (false, false, false) => return String::new(),
    };
    format!(
        r#"<section class="alert alert--down banner" role="status" aria-labelledby="banner-title"><h2 id="banner-title">{title}</h2><p>{copy}</p></section>"#,
        title = esc(title),
        copy = esc(copy),
    )
}

fn updated_sentence(updated_at: i64) -> String {
    if updated_at > 0 {
        format!("Profile updated {}", fmt_date(updated_at))
    } else {
        "No profile details saved yet".to_string()
    }
}

fn map_identity_unavailable(error: DirectoryError) -> AppError {
    tracing::error!(error = %error, "identity source read failed");
    AppError::Unavailable(UnavailableKind::IdentitySource)
}

fn map_profile_unavailable(error: StoreError) -> AppError {
    tracing::error!(error = %error, "profile store read failed");
    AppError::Unavailable(UnavailableKind::ProfileStore)
}

fn map_group_unavailable(error: StoreError) -> AppError {
    tracing::error!(error = %error, "group store read failed");
    AppError::Unavailable(UnavailableKind::GroupStore)
}

fn map_people_unavailable(error: ReadError) -> AppError {
    match error {
        ReadError::Identity(error) => map_identity_unavailable(error),
        ReadError::Store(error) => map_profile_unavailable(error),
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
        let visible_department = bounded_option_label(dept);
        html.push_str(&format!(
            r#"<option value="{value}" aria-label="{full_department}" title="{full_department}"{selected}>{visible_department}</option>"#,
            value = esc(dept),
            full_department = esc(dept),
            selected = selected_attr,
            visible_department = esc(&visible_department),
        ));
    }
    html
}

fn render_group_options(groups: &[Group], selected: &str, unavailable: bool) -> String {
    let mut html = r#"<option value="">All groups</option>"#.to_string();
    if unavailable {
        html.push_str(r#"<option value="" disabled>Groups unavailable</option>"#);
        return html;
    }
    for group in groups {
        let selected_attr = if group.id == selected {
            " selected"
        } else {
            ""
        };
        let visible_name = bounded_option_label(&group.name);
        html.push_str(&format!(
            r#"<option value="{id}" aria-label="{full_name}" title="{full_name}"{selected}>{visible_name}</option>"#,
            id = esc(&group.id),
            full_name = esc(&group.name),
            selected = selected_attr,
            visible_name = esc(&visible_name),
        ));
    }
    html
}

/// Keep native selects intrinsically bounded even when stored labels contain hostile long runs.
/// The complete escaped label remains available through the option's accessible name and title.
fn bounded_option_label(label: &str) -> String {
    const MAX_VISIBLE_CHARS: usize = 16;

    let mut chars = label.chars();
    let visible: String = chars.by_ref().take(MAX_VISIBLE_CHARS).collect();
    if chars.next().is_some() {
        format!("{visible}…")
    } else {
        visible
    }
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
    reports.sort_by_key(|person| person.label().to_lowercase());
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
        return r#"<p class="grouplist__empty">No one is in this view.</p>"#.to_string();
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

    roots.sort_by_key(|index| people[*index].label().to_lowercase());
    for group in children.values_mut() {
        group.sort_by_key(|index| people[*index].label().to_lowercase());
    }

    let mut seen = HashSet::new();
    let visible_subs: HashSet<String> = index_by_sub.keys().cloned().collect();
    let mut html = String::new();
    for idx in roots {
        html.push_str(&render_org_node(
            idx,
            people,
            &children,
            &visible_subs,
            &mut seen,
        ));
    }
    for idx in 0..people.len() {
        if !seen.contains(&people[idx].identity.sub) {
            html.push_str(&render_org_node(
                idx,
                people,
                &children,
                &visible_subs,
                &mut seen,
            ));
        }
    }

    format!(r#"<ul class="org-tree" aria-label="Declared reporting lines">{html}</ul>"#)
}

fn render_org_node(
    idx: usize,
    people: &[Person],
    children: &HashMap<String, Vec<usize>>,
    visible_subs: &HashSet<String>,
    seen: &mut HashSet<String>,
) -> String {
    let p = &people[idx];
    if !seen.insert(p.identity.sub.clone()) {
        return String::new();
    }
    let mut child_html = String::new();
    if let Some(child_indices) = children.get(&p.identity.sub) {
        for child_idx in child_indices {
            child_html.push_str(&render_org_node(
                *child_idx,
                people,
                children,
                visible_subs,
                seen,
            ));
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
    let contour = if !p.profile.manager_sub.trim().is_empty()
        && !visible_subs.contains(p.profile.manager_sub.trim())
    {
        r#"<span class="contour__open">declared manager not shown</span>"#
    } else {
        ""
    };
    format!(
        r#"<li class="org-node"><div class="org-card"><a href="/u/{sub}">{label}</a>{meta}{contour}</div>{children}</li>"#,
        sub = esc(&p.identity.sub),
        label = esc(&p.label()),
        meta = meta,
        contour = contour,
        children = child_list,
    )
}

/// The owner's inline profile edit form (CSRF-protected, posts to `/api/profile`).
fn render_edit_form(csrf: &str, profile: &Profile, people: &[Person]) -> String {
    let manager_options = render_manager_options(people, profile);
    let locale_options = render_locale_options(&profile.locale);
    format!(
        r#"<section class="card edit-card" id="edit-profile">
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

#[cfg(test)]
mod roll_meta_tests {
    use super::*;

    #[test]
    fn row_meta_breaks_hostile_runs_without_changing_text_or_entities() {
        let department = format!(
            "{}<script>alert(\"x&y'\")</script>{}",
            "A".repeat(17),
            "界".repeat(17)
        );
        let location = format!("\u{2067}{}\u{2069}", "א".repeat(33));
        let person = Person {
            identity: Identity {
                sub: "hostile-meta".to_string(),
                email: String::new(),
            },
            profile: Profile {
                sub: "hostile-meta".to_string(),
                department: department.clone(),
                location: location.clone(),
                ..Profile::default()
            },
            provenance: Provenance::Enumerated,
        };

        let row = render_person_row(&person, 1, false, &[]);
        let meta = row
            .split_once(r#"<span class="roll__meta">"#)
            .and_then(|(_, tail)| tail.split_once("</span>"))
            .map(|(meta, _)| meta)
            .expect("row metadata span");
        let visible = format!("{department} · {location}");

        assert!(meta.contains("<wbr>"));
        assert_eq!(meta.replace("<wbr>", ""), esc(&visible));
        assert!(!meta.contains("<script>"));
        assert!(meta.contains("&lt;script&gt;"));
        for entity in ["&lt;", "&gt;", "&quot;", "&amp;", "&#x27;"] {
            assert!(
                meta.contains(entity),
                "escaped entity remains atomic: {entity}"
            );
        }

        let short = "Atlas · München";
        assert_eq!(escape_roll_meta(short), esc(short));
        assert!(!escape_roll_meta(short).contains("<wbr>"));
    }

    #[test]
    fn group_options_bound_visible_labels_and_preserve_full_accessible_names() {
        let name = format!("<img src=x> {}", "界".repeat(40));
        let group = Group {
            id: "fixture-group-hostile".to_string(),
            name: name.clone(),
            description: String::new(),
            created_at: 0,
        };

        let html = render_group_options(&[group], "fixture-group-hostile", false);
        let visible = bounded_option_label(&name);

        assert_eq!(visible.chars().count(), 17);
        assert!(visible.ends_with('…'));
        assert!(html.contains(r#"value="fixture-group-hostile""#));
        assert!(html.contains(r#" selected"#));
        assert!(html.contains(&format!(r#"aria-label="{}""#, esc(&name))));
        assert!(html.contains(&format!(r#"title="{}""#, esc(&name))));
        assert!(html.contains(&format!(">{}</option>", esc(&visible))));
        assert!(!html.contains("<img src=x>"));
    }

    #[test]
    fn department_options_bound_visible_labels_and_preserve_full_value_and_name() {
        let department = format!("研🧭e\u{301}究部門<&>-Δ🌐 {}", "界".repeat(120));
        let html = render_department_options(std::slice::from_ref(&department), &department);
        let visible = bounded_option_label(&department);

        assert_eq!(department.chars().count(), 134);
        assert_eq!(visible.chars().count(), 17);
        assert!(visible.ends_with('…'));
        assert_eq!(
            visible,
            format!("{}…", department.chars().take(16).collect::<String>())
        );
        assert!(html.contains(&format!(r#"value="{}""#, esc(&department))));
        assert!(html.contains(r#" selected"#));
        assert!(html.contains(&format!(r#"aria-label="{}""#, esc(&department))));
        assert!(html.contains(&format!(r#"title="{}""#, esc(&department))));
        assert!(html.contains(&format!(">{}</option>", esc(&visible))));
        assert!(!html.contains("<&>"));
    }

    #[test]
    fn bounded_option_label_leaves_short_unicode_labels_unchanged() {
        for label in ["Atlas", "日本語", "e\u{301}quipe"] {
            assert_eq!(bounded_option_label(label), label);
        }
    }
}
