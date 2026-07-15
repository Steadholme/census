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
            email: "alice@steadholme.local".to_string(),
        },
        Identity {
            sub: "u_bob".to_string(),
            email: "bob@steadholme.local".to_string(),
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
    assert!(body.contains("alice@steadholme.local"), "alice in directory");
    assert!(body.contains("bob@steadholme.local"), "bob in directory");

    // --- keyword filter ----------------------------------------------------
    let (_, body) = call(&state, get("/?q=bob")).await;
    assert!(body.contains("bob@steadholme.local"), "bob matches filter");
    assert!(!body.contains("alice@steadholme.local"), "alice filtered out");

    // --- GET /u/{sub} for self mints a CSRF cookie + edit form -------------
    let resp = app(state.clone())
        .oneshot(get_auth("/u/u_alice", "u_alice", "alice@steadholme.local"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        set_cookie.contains("__Host-csrf="),
        "self page mints CSRF cookie"
    );
    let html = body_of(resp).await;
    assert!(html.contains("Edit your profile"), "owner sees edit form");

    // --- POST /api/profile without identity -> 401 ------------------------
    let body = form(&[("display_name", "Nope"), ("csrf_token", CSRF)]);
    let (status, _) = call(&state, post_csrf("/api/profile", &body, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no X-Auth -> 401");

    // --- POST /api/profile with bad CSRF -> 401 ---------------------------
    let body = form(&[("display_name", "Nope"), ("csrf_token", "WRONG")]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/profile",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "CSRF mismatch -> 401");

    // --- edit my own profile (bio markdown + a javascript: avatar) --------
    let bio = "Hi **there**. <script>alert(1)</script> [x](javascript:alert(2))";
    let body = form(&[
        ("display_name", "Alice Anderson"),
        ("title", "Platform Engineer"),
        ("department", "Engineering"),
        ("manager_sub", "u_bob"),
        ("phone", "+1 555 0100"),
        ("location", "Berlin"),
        ("timezone", "Europe/Berlin"),
        ("locale", "ja"),
        ("avatar_url", "javascript:alert(3)"),
        ("bio", bio),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf(
            "/api/profile",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ))
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
    let lang_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(lang_cookie.contains("__Secure-lang=ja"));
    assert!(lang_cookie.contains("Domain=.w33d.xyz"));
    assert!(lang_cookie.contains("Path=/"));
    assert!(lang_cookie.contains("Secure"));
    assert!(lang_cookie.contains("HttpOnly"));
    assert!(lang_cookie.contains("SameSite=Lax"));
    assert!(lang_cookie.contains("Max-Age=31536000"));

    // --- person page reflects the edit, sanitized -------------------------
    let (status, body) = call(&state, get("/u/u_alice")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Alice Anderson"), "display name updated");
    assert!(body.contains("Platform Engineer"), "title shown");
    assert!(body.contains("Engineering"), "department shown");
    assert!(body.contains("+1 555 0100"), "phone shown");
    assert!(body.contains("Berlin"), "location shown");
    assert!(body.contains("Europe/Berlin"), "timezone shown");
    assert!(body.contains("bob@steadholme.local"), "manager shown");
    assert!(
        body.contains("<strong>there</strong>"),
        "bio markdown rendered"
    );
    assert!(!body.contains("<script>alert(1)"), "raw script escaped");
    assert!(
        !body.contains("javascript:alert"),
        "js: link + avatar neutralized"
    );
    let (_, owner_body) = call(
        &state,
        get_auth("/u/u_alice", "u_alice", "alice@steadholme.local"),
    )
    .await;
    assert!(
        owner_body.contains(r#"<option value="ja" selected>日本語</option>"#),
        "saved locale selected in edit form"
    );

    // --- directory now shows the display name + title ---------------------
    let (_, body) = call(&state, get("/")).await;
    assert!(body.contains("Alice Anderson"));
    assert!(body.contains("Platform Engineer"));
    assert!(body.contains("Engineering"));

    let (_, body) = call(&state, get("/?dept=Engineering")).await;
    assert!(
        body.contains("Alice Anderson"),
        "department filter includes Alice"
    );
    assert!(
        !body.contains("bob@steadholme.local"),
        "department filter excludes Bob"
    );

    let (_, bob) = call(&state, get("/u/u_bob")).await;
    assert!(bob.contains("Direct reports"));
    assert!(
        bob.contains("Alice Anderson"),
        "Bob sees Alice as direct report"
    );

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
    assert_eq!(alice["email"], "alice@steadholme.local");
    assert_eq!(alice["title"], "Platform Engineer");
    assert_eq!(alice["department"], "Engineering");
    assert_eq!(alice["manager_sub"], "u_bob");
    assert_eq!(alice["phone"], "+1 555 0100");
    assert_eq!(alice["location"], "Berlin");
    assert_eq!(alice["timezone"], "Europe/Berlin");
    assert_eq!(alice["locale"], "ja");

    // --- clearing language preference clears the estate-wide cookie ---------
    let body = form(&[
        ("display_name", "Alice Anderson"),
        ("title", "Platform Engineer"),
        ("department", "Engineering"),
        ("manager_sub", "u_bob"),
        ("phone", "+1 555 0100"),
        ("location", "Berlin"),
        ("timezone", "Europe/Berlin"),
        ("locale", ""),
        ("avatar_url", ""),
        ("bio", bio),
        ("csrf_token", CSRF),
    ]);
    let resp = app(state.clone())
        .oneshot(post_csrf(
            "/api/profile",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let lang_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(lang_cookie.contains("__Secure-lang=;"));
    assert!(lang_cookie.contains("Max-Age=0"));

    let (_, body) = call(&state, get("/api/people")).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let alice = v["people"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["sub"] == "u_alice")
        .expect("alice in feed after clearing locale");
    assert_eq!(alice["locale"], "");
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
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/groups",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // --- create a group: success ------------------------------------------
    let body = form(&[
        ("name", "Engineering"),
        ("description", "Builds the estate"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/groups",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // --- duplicate name -> 409 --------------------------------------------
    let body = form(&[("name", "engineering"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/groups",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "case-insensitive name clash rejected"
    );

    // Discover the Engineering group id from the groups page.
    let (_, page) = call(
        &state,
        get_auth("/groups", "u_alice", "alice@steadholme.local"),
    )
    .await;
    assert!(page.contains("Engineering"));
    assert!(page.contains("Builds the estate"));
    let eng_id = extract_group_id(&page).expect("group id on page");

    // --- create a child group ----------------------------------------------
    let body = form(&[
        ("name", "Platform"),
        ("description", "Runtime platform"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/groups",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = call(
        &state,
        get_auth("/groups", "u_alice", "alice@steadholme.local"),
    )
    .await;
    let ids = extract_group_ids(&page);
    let platform_id = ids
        .iter()
        .find(|id| *id != &eng_id)
        .expect("platform group id")
        .clone();

    // --- add a member to the child group -----------------------------------
    let body = form(&[
        ("action", "add"),
        ("sub", "u_bob"),
        ("role", "maintainer"),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{platform_id}/members"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // --- child group CSRF guard + success ----------------------------------
    let body = form(&[
        ("action", "add"),
        ("child_group_id", &platform_id),
        ("csrf_token", "WRONG"),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{eng_id}/children"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let body = form(&[
        ("action", "add"),
        ("child_group_id", &platform_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{eng_id}/children"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // Group page and detail resolve Bob through the child group.
    let (_, page) = call(
        &state,
        get_auth("/groups", "u_alice", "alice@steadholme.local"),
    )
    .await;
    assert!(page.contains("maintainer"), "role shown on group page");
    assert!(page.contains("Platform"), "child group shown");
    assert!(page.contains("1 resolved"), "recursive member count shown");
    let (_, detail) = call(
        &state,
        get_auth(
            &format!("/groups/{eng_id}"),
            "u_alice",
            "alice@steadholme.local",
        ),
    )
    .await;
    assert!(detail.contains("Resolved members"));
    assert!(detail.contains("bob@steadholme.local"));
    assert!(detail.contains("Platform"));

    let (_, filtered) = call(&state, get(&format!("/?group={eng_id}"))).await;
    assert!(
        filtered.contains("bob@steadholme.local"),
        "parent group filter includes nested member"
    );
    assert!(
        !filtered.contains("alice@steadholme.local"),
        "parent group filter excludes non-member"
    );

    let (_, bob) = call(&state, get("/u/u_bob")).await;
    assert!(
        bob.contains("Platform"),
        "bob's page lists direct child group"
    );

    // --- adding the parent as a child would create a cycle -> 400 -----------
    let body = form(&[
        ("action", "add"),
        ("child_group_id", &eng_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{platform_id}/children"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // --- add to a non-existent group -> 404 -------------------------------
    let body = form(&[("action", "add"), ("sub", "u_bob"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            "/api/groups/grp_nope/members",
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // --- remove the child group edge ---------------------------------------
    let body = form(&[
        ("action", "remove"),
        ("child_group_id", &platform_id),
        ("csrf_token", CSRF),
    ]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{eng_id}/children"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, platform_detail) = call(
        &state,
        get_auth(
            &format!("/groups/{platform_id}"),
            "u_alice",
            "alice@steadholme.local",
        ),
    )
    .await;
    assert!(platform_detail.contains("No parent groups"));

    // --- remove the member -------------------------------------------------
    let body = form(&[("action", "remove"), ("sub", "u_bob"), ("csrf_token", CSRF)]);
    let (status, _) = call(
        &state,
        post_csrf(
            &format!("/api/groups/{platform_id}/members"),
            &body,
            Some(("u_alice", "alice@steadholme.local")),
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
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

async fn body_of(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
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
        b = b
            .header("x-auth-subject", sub)
            .header("x-auth-email", email);
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
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// Pull the first `grp_…` id out of a rendered groups page (the member-form action paths).
fn extract_group_id(html: &str) -> Option<String> {
    extract_group_ids(html).into_iter().next()
}

/// Pull all unique `grp_…` ids out of rendered group links/forms/options, preserving first-seen order.
fn extract_group_ids(html: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find("grp_") {
        let candidate = &rest[i..];
        let end = candidate
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(candidate.len());
        let id = candidate[..end].to_string();
        if !ids.iter().any(|seen| seen == &id) {
            ids.push(id);
        }
        rest = &candidate[end..];
    }
    ids
}
