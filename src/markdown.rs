//! Profile-bio markdown rendering + URL sanitization.
//!
//! SECURITY: bio rendering is SANITIZED at the event level so no raw HTML / `javascript:` survives
//! into the page (the bio is user-supplied markdown). Raw block + inline HTML events are converted
//! to escaped TEXT (so `<script>` renders as the literal characters, never a live tag), and
//! link/image destination URLs are scheme-allowlisted (http/https/mailto/tel + relative); anything
//! else (e.g. `javascript:`) is rewritten to `#`. The avatar URL is checked with the same
//! allowlist before it is ever used as an `<img src>`.

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};

/// Render sanitized HTML from a markdown `src` (the profile bio).
pub fn render_html(src: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);

    let parser = Parser::new_ext(src, options).map(sanitize_event);
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

/// Neutralize the only two event classes that can carry an XSS payload.
fn sanitize_event(event: Event<'_>) -> Event<'_> {
    match event {
        // Raw HTML -> escaped text (push_html escapes Text via escape_html).
        Event::Html(h) => Event::Text(h),
        Event::InlineHtml(h) => Event::Text(h),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: sanitize_url_cow(dest_url),
            title,
            id,
        }),
        Event::Start(Tag::Image {
            link_type,
            dest_url,
            title,
            id,
        }) => Event::Start(Tag::Image {
            link_type,
            dest_url: sanitize_url_cow(dest_url),
            title,
            id,
        }),
        other => other,
    }
}

fn sanitize_url_cow(url: CowStr<'_>) -> CowStr<'_> {
    if is_safe_url(&url) {
        url
    } else {
        CowStr::Borrowed("#")
    }
}

/// Sanitize an avatar URL for use in `<img src>`: only http/https/relative survive; anything else
/// (javascript:, data:, …) collapses to an empty string so the caller can drop the image.
pub fn safe_avatar_url(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_safe_url(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn is_safe_url(url: &str) -> bool {
    // Strip whitespace + control chars first, so `java\tscript:` can't slip past the scheme check.
    let cleaned: String = url
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_ascii_control())
        .collect::<String>()
        .to_ascii_lowercase();

    match cleaned.find(':') {
        Some(idx) => {
            let scheme = &cleaned[..idx];
            // A real scheme is non-empty and only `[a-z0-9+.-]`. If `scheme` contains `/`, `?`,
            // or `#`, the `:` belongs to a path/fragment, not a scheme -> treat as relative.
            let is_scheme = !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
            if is_scheme {
                matches!(scheme, "http" | "https" | "mailto" | "tel")
            } else {
                true // relative path / fragment
            }
        }
        None => true, // no scheme -> relative
    }
}

/// A short plain-text excerpt of `n` characters extracted from the markdown bio (ignores markup so
/// the directory card reads cleanly). Appends `…` when truncated.
pub fn excerpt(src: &str, n: usize) -> String {
    let options = Options::empty();
    let mut text = String::new();
    for event in Parser::new_ext(src, options) {
        match event {
            Event::Text(t) | Event::Code(t) => text.push_str(&t),
            Event::SoftBreak | Event::HardBreak | Event::End(_) if !text.ends_with(' ') => {
                text.push(' ');
            }
            _ => {}
        }
    }
    let text = text.trim();
    if text.chars().count() > n {
        let truncated: String = text.chars().take(n).collect();
        format!("{}…", truncated.trim_end())
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html = render_html("Hello **world**.");
        assert!(html.contains("<strong>world</strong>"));
    }

    #[test]
    fn escapes_raw_html_script() {
        let html = render_html("ok <script>alert(1)</script> done");
        assert!(
            !html.contains("<script>"),
            "raw script tag must not survive"
        );
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn neutralizes_javascript_link() {
        let html = render_html("[click](javascript:alert(1))");
        assert!(!html.contains("javascript:"), "js scheme link neutralized");
        assert!(html.contains("href=\"#\""));
    }

    #[test]
    fn avatar_url_allowlist() {
        assert_eq!(
            safe_avatar_url("https://cdn.w33d.xyz/a.png").as_deref(),
            Some("https://cdn.w33d.xyz/a.png")
        );
        assert_eq!(
            safe_avatar_url("/static/a.png").as_deref(),
            Some("/static/a.png")
        );
        assert_eq!(safe_avatar_url("javascript:alert(1)"), None);
        assert_eq!(safe_avatar_url("data:image/png;base64,AAAA"), None);
        assert_eq!(safe_avatar_url("   "), None);
    }
}
