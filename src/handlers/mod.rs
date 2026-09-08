//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `people` carries the directory + person views
//! and the profile edit; `groups` carries the groups directory + create/membership management;
//! `api` serves the machine JSON people feed.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and served as one immutable asset,
//! matching the Steadholme enterprise brand (the same look as the Keystone login UI): brand gradient,
//! indigo accent, cards, app-bar.

pub mod api;
pub mod groups;
pub mod health;
pub mod people;
pub mod workforce;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use std::sync::OnceLock;

/// Census-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");
const ERROR_HTML: &str = include_str!("../../templates/error.html");

pub const APP_CSS_PATH: &str = "/assets/census-20260908.css";

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system served by the stylesheet endpoint.
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

pub async fn app_css_asset() -> Response {
    let mut response = app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Cross-subdomain gateway logout (Census lives at people.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";

/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Replace placeholders found in the template without ever scanning inserted values again.
///
/// Chained `str::replace` calls can turn user-controlled text such as `{{ROWS}}` into a later
/// trusted HTML fragment. This renderer walks only the original template, so replacement values
/// are opaque bytes and cannot become second-pass template instructions.
pub fn render_template(template: &str, values: &[(&str, &str)]) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(offset) = remaining.find("{{") {
        rendered.push_str(&remaining[..offset]);
        remaining = &remaining[offset..];

        if let Some((token, value)) = values
            .iter()
            .find(|(token, _)| remaining.starts_with(*token))
        {
            rendered.push_str(value);
            remaining = &remaining[token.len()..];
        } else {
            rendered.push_str("{{");
            remaining = &remaining[2..];
        }
    }

    rendered.push_str(remaining);
    rendered
}

/// Compute a stable initials glyph (1–2 chars) for an avatar fallback. Takes the best available
/// label (display name, else email local-part). Pure presentation — always HTML-escaped by caller.
pub fn initials(label: &str) -> String {
    let mut chars = label
        .split(|c: char| c.is_whitespace() || c == '.' || c == '_' || c == '-' || c == '@')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.chars().next());
    let a = chars.next();
    let b = chars.next();
    match (a, b) {
        (Some(a), Some(b)) => format!("{}{}", a.to_uppercase(), b.to_uppercase()),
        (Some(a), None) => a.to_uppercase().to_string(),
        _ => "?".to_string(),
    }
}

/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time` only,
/// no extra C deps. `0` (never-stamped) renders as an em dash.
pub fn fmt_date(secs: i64) -> String {
    if secs <= 0 {
        return "—".to_string();
    }
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}

/// A 303 redirect (post/redirect/get).
pub fn redirect(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/")),
        )],
    )
        .into_response()
}

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
pub fn html_with_cookie(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(c) = set_cookie {
        if let Ok(value) = HeaderValue::from_str(&c) {
            resp.headers_mut().insert(header::SET_COOKIE, value);
        }
    }
    resp
}

/// Icons used across the console chrome (inline so no asset request is needed).
pub const ICON_MARK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>"##;
pub const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;

/// The console pages, in app-bar order.
pub const NAV: [(&str, &str); 2] = [("/", "People"), ("/groups", "Groups")];

/// Render the app bar: brand lockup + host + page pills; All apps, identity and Log out.
pub fn app_bar(active: &str, email: Option<&str>) -> String {
    let mut pills = String::new();
    for (href, label) in NAV {
        pills.push_str(&format!(
            r#"<a class="surf{state}" href="{href}"{aria}>{label}</a>"#,
            state = if href == active { " is-active" } else { "" },
            href = href,
            aria = if href == active {
                r#" aria-current="page""#
            } else {
                ""
            },
            label = label,
        ));
    }
    let chip = match email {
        Some(value) if !value.is_empty() && value != "—" => {
            let initial = value
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "S".to_string());
            format!(
                r#"<span class="userchip"><span class="userchip__avatar" aria-hidden="true">{initial}</span><span class="user-email">{email}</span></span>"#,
                initial = esc(&initial),
                email = esc(value),
            )
        }
        _ => {
            r#"<span class="user-email user-email--none">— (no gateway session)</span>"#.to_string()
        }
    };
    format!(
        r#"<header class="suitebar">
  <a class="suitebar__brand" href="/">
    <span class="brand-tile" aria-hidden="true">{mark}</span>
    <span class="suitebar__name"><b>Steadholme</b><span>People directory</span></span>
  </a>
  <span class="suitebar__host">people.w33d.xyz</span>
  <nav class="surfaces" aria-label="Census pages">{pills}</nav>
  <span class="suitebar__spacer"></span>
  <div class="suitebar__right">
    <a class="allapps" href="https://w33d.xyz">{grid}<span>All apps</span></a>
    {chip}
    <a class="btn btn-ghost btn-sm" href="{logout}">Log out</a>
  </div>
</header>"#,
        mark = ICON_MARK,
        pills = pills,
        grid = ICON_GRID,
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// The shared page footer.
pub const FOOTER: &str = r##"<footer class="v2-foot">
  <span class="v2-foot__lead">Steadholme · Census · people.w33d.xyz</span>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://access.w33d.xyz">Access</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;

/// Resolve the viewer's theme from the cookie header.
pub fn theme_of(headers: &axum::http::HeaderMap) -> &'static str {
    odyssey::resolve_theme(
        headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok()),
    )
}

/// Fill a page template's chrome placeholders: theme attributes, stylesheet, footer, app bar.
///
/// The app bar carries the one caller-supplied value in the chrome (the signed-in email), so it is
/// substituted last: no later `replace` pass can re-scan it and treat a `{{MARKER}}` inside an
/// address as a template instruction.
pub fn shell(template: &str, active: &str, theme: &str, email: Option<&str>) -> String {
    template
        .replace("{{THEME_ATTR}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{APPBAR}}", &app_bar(active, email))
}

/// Render the branded error document as one status tile.
pub fn error_page(status: StatusCode, message: &str) -> String {
    let reason = status.canonical_reason().unwrap_or("Error");
    ERROR_HTML
        .replace("{{THEME_ATTR}}", "")
        .replace("{{COLOR_SCHEME}}", "light dark")
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{APPBAR}}", &app_bar("/", None))
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(reason))
        .replace("{{MESSAGE}}", &esc(message))
}

#[cfg(test)]
mod tests {
    use super::render_template;

    #[test]
    fn inserted_marker_text_is_never_reprocessed() {
        let rendered = render_template(
            "first={{FIRST}}; second={{SECOND}}; again={{FIRST}}",
            &[
                ("{{FIRST}}", "{{SECOND}}<b>literal</b>"),
                ("{{SECOND}}", "trusted"),
            ],
        );

        assert_eq!(
            rendered,
            "first={{SECOND}}<b>literal</b>; second=trusted; again={{SECOND}}<b>literal</b>"
        );
    }

    #[test]
    fn unknown_template_markers_remain_literal() {
        let rendered = render_template(
            "known={{KNOWN}} unknown={{UNKNOWN}}",
            &[("{{KNOWN}}", "ok")],
        );
        assert_eq!(rendered, "known=ok unknown={{UNKNOWN}}");
    }
}
