//! End-to-end HTTP flow over the in-memory store + a seeded in-memory Keystone directory (NO
//! database).
//!
//! Drives the real `app` router via `tower::oneshot`, exactly like the rest of the estate. Covers:
//! health, the directory (empty + populated + keyword filter), the SSO/CSRF guards on the profile
//! edit, the bio markdown XSS sanitization + avatar allowlist, group create/conflict, membership
//! add/remove, and the JSON people feed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use census::directory::{Identity, InMemoryDirectory};
use census::{app, build_dev_state, AppState};
use tower::ServiceExt;

const CSRF: &str = "tok_csrf_for_tests";

/// A dev state whose directory is seeded with two real Keystone identities.
fn seeded_state() -> AppState {
    let mut state = build_dev_state();
    state.directory = Arc::new(InMemoryDirectory::with_identities(vec![
        Identity {
            sub: "u_alice".to_string(),
            email: "alice@holdfast.local".to_string(),
        },
        Identity {
            sub: "u_bob".to_string(),
            email: "bob@holdfast.local".to_string(),
        },
    ]));
    state
}

#[tokio::test]
async fn directory_and_profile_flow() {
    let state = seeded_state();

    // --- health ------------------------------------------------------------
    let (status, _) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);

    // --- directory lists the seeded identities -----------------------------
    let (status, body) = call(&state, get("/")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("alice@holdfast.local"), "alice in directory");
    assert!(body.contains("bob@holdfast.local"), "bob in directory");

    // --- keyword filter ----------------------------------------------------
    let (_, body) = call(&state, get("/?q=bob")).await;
    assert!(body.contains("bob@holdfast.local"), "bob matches filter");
    assert!(!body.contains("alice@holdfast.local"), "alice filtered out");

    // --- GET /u/{sub} for self mints a CSRF cookie + edit form -------------
    let resp = app(state.clone())
        .oneshot(get_auth("/u/u_alice", "u_alice", "alice@holdfast.local"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(set_cookie.contains("__Host-csrf="), "self page mints CSRF cookie");
    let html = body_of(resp).await;
    assert!(html.contains("Edit your profile"), "owner sees edit form");

    // --- POST /api/profile without identity -> 401 ------------------------
    let body = form(&[("display_name", "Nope"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/profile", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /api/profile with bad CSRF -> 401 ---------------------------
    let body = form(&[("display_name", "Nope"), ("csrf_token", "WRONG")]);
    let (status, _) =
        call(&state, post_csrf("/api/profile", &body, Some(("u_alice", "alice@holdfast.local")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- edit my own profile (bio markdown + a javascript: avatar) --------
    let bio = "Hi **there**. <script>alert(1)</script> [x](javascript:alert(2))";
    let body = form(&[
        ("display_name", "Alice Anderson"),
        ("title", "Platform Engineer"),
        ("avatar_url", "javascript:alert(3)"),
        ("bio", bio),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf("/api/profile", &body, Some(("u_alice", "alice@holdfast.local"))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(location, "/u/u_alice");

    // --- person page reflects the edit, sanitized -------------------------
    let (status, body) = call(&state, get("/u/u_alice")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Alice Anderson"), "display name updated");
    assert!(body.contains("Platform Engineer"), "title shown");
    assert!(body.contains("<strong>there</strong>"), "bio markdown rendered");
    assert!(!body.contains("<script>alert(1)"), "raw script escaped");
    assert!(!body.contains("javascript:alert"), "js: link + avatar neutralized");

    // --- directory now shows the display name + title ---------------------
    let (_, body) = call(&state, get("/")).await;
    assert!(body.contains("Alice Anderson"));
    assert!(body.contains("Platform Engineer"));

    // --- JSON people feed --------------------------------------------------
    let (status, body) = call(&state, get("/api/people")).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["count"], 2);
    let people = v["people"].as_array().unwrap();
    let alice = people
        .iter()
        .find(|p| p["sub"] == "u_alice")
        .expect("alice in feed");
    assert_eq!(alice["display_name"], "Alice Anderson");
    assert_eq!(alice["email"], "alice@holdfast.local");
    assert_eq!(alice["title"], "Platform Engineer");
}

#[tokio::test]
async fn groups_and_membership_flow() {
    let state = seeded_state();

    // --- create a group: no identity -> 401 -------------------------------
    let body = form(&[("name", "Engineering"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/groups", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- create a group: bad CSRF -> 401 ----------------------------------
    let body = form(&[("name", "Engineering"), ("csrf_token", "WRONG")]);
    let (status, _) =
        call(&state, post_csrf("/api/groups", &body, Some(("u_alice", "alice@holdfast.local")))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- create a group: success ------------------------------------------
    let body = form(&[
        ("name", "Engineering"),
        ("description", "Builds the estate"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) =
        call(&state, post_csrf("/api/groups", &body, Some(("u_alice", "alice@holdfast.local")))).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // --- duplicate name -> 409 --------------------------------------------
    let body = form(&[("name", "engineering"), ("csrf_token", CSRF)]);
    let (status, _) =
        call(&state, post_csrf("/api/groups", &body, Some(("u_alice", "alice@holdfast.local")))).await;
    assert_eq!(status, StatusCode::CONFLICT, "case-insensitive name clash rejected");

    // Discover the group id from the groups page (grp_… link in the member forms).
    let (_, page) = call(&state, get_auth("/groups", "u_alice", "alice@holdfast.local")).await;
    assert!(page.contains("Engineering"));
    assert!(page.contains("Builds the estate"));
    let gid = extract_group_id(&page).expect("group id on page");

    // --- add a member ------------------------------------------------------
    let body = form(&[
        ("action", "add"),
        ("sub", "u_bob"),
        ("role", "maintainer"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{gid}/members"),
            &body,
            Some(("u_alice", "alice@holdfast.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Group page lists bob with his role; bob's person page lists the group.
    let (_, page) = call(&state, get_auth("/groups", "u_alice", "alice@holdfast.local")).await;
    assert!(page.contains("maintainer"), "role shown on group page");
    let (_, bob) = call(&state, get("/u/u_bob")).await;
    assert!(bob.contains("Engineering"), "bob's page lists the group");

    // --- add to a non-existent group -> 404 -------------------------------
    let body = form(&[("action", "add"), ("sub", "u_bob"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf("/api/groups/grp_nope/members", &body, Some(("u_alice", "alice@holdfast.local"))),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- remove the member -------------------------------------------------
    let body = form(&[("action", "remove"), ("sub", "u_bob"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{gid}/members"),
            &body,
            Some(("u_alice", "alice@holdfast.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, bob) = call(&state, get("/u/u_bob")).await;
    assert!(bob.contains("No group memberships"), "membership removed");
}

#[tokio::test]
async fn unknown_person_is_404() {
    let state = seeded_state();
    let (status, _) = call(&state, get("/u/u_ghost")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, String) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn body_of(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn get_auth(uri: &str, sub: &str, email: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-auth-subject", sub)
        .header("x-auth-email", email)
        .body(Body::empty())
        .unwrap()
}

/// Build a urlencoded POST carrying the test CSRF cookie + (optionally) gateway identity.
fn post_csrf(uri: &str, body: &str, ident: Option<(&str, &str)>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("__Host-csrf={CSRF}"));
    if let Some((sub, email)) = ident {
        b = b.header("x-auth-subject", sub).header("x-auth-email", email);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Minimal application/x-www-form-urlencoded value encoder.
fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Pull the first `grp_…` id out of a rendered groups page (the member-form action paths).
fn extract_group_id(html: &str) -> Option<String> {
    let i = html.find("grp_")?;
    let rest = &html[i..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}
