//! Census — the people directory, profiles & groups for the Steadholme stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + empty directory, no database) and
//! [`build_state_from_env`] (env-selected store + Keystone directory + Watchtower audit).
//! Integration tests consume [`app`] directly via `tower::oneshot`, exactly like the rest of the
//! estate.
//!
//! Census sits behind a Sluice `auth=sso` route at the subdomain ROOT (`people.w33d.xyz`); the
//! gateway forwards the path UNMODIFIED, so the routes below are the real paths. It is the
//! authoritative people directory layered over Keystone identities: it READS the shared Keystone
//! `users` table (subject + email only — NEVER the password hash) and owns the editable
//! profile / group / membership layer in its OWN database.
//!
//! Endpoints:
//! - `GET  /healthz`                     liveness (container HEALTHCHECK)
//! - `GET  /readyz`                      workforce schema readiness
//! - `GET  /`                            directory: every Keystone identity joined to its profile,
//!   keyword filter, with a groups panel
//! - `GET  /u/{sub}`                     a person page (profile + group memberships)
//! - `POST /api/profile`                 edit MY OWN profile (sub from X-Auth-Subject), CSRF
//! - `GET  /groups`                      groups directory + create / membership management
//! - `GET  /groups/{id}`                  group detail + nested membership resolution
//! - `POST /api/groups`                  create a group, CSRF
//! - `POST /api/groups/{id}/members`     add / remove a member, CSRF
//! - `POST /api/groups/{id}/children`    add / remove a child group, CSRF
//! - `GET  /api/people`                  JSON people feed for other services
//! - `POST /internal/v1/workforce/intake` bearer-authenticated workforce/JML intake
//! - `PUT  /internal/v1/workforce/records/{subject}` exact subject-bound intake alias
//! - `GET  /internal/v1/workforce/records/{subject}` current authoritative record
//! - `GET  /internal/v1/workforce/changes` durable exclusive-cursor JML changefeed

pub mod audit;
pub mod auth;
pub mod config;
pub mod directory;
pub mod error;
pub mod fixtures;
pub mod gateway_observe;
pub mod handlers;
pub mod markdown;
pub mod store;
pub mod workforce;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{header, HeaderValue, Request};
use axum::middleware::{from_fn, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::audit::AuditSink;
use crate::config::{env_nonempty, env_truthy, Config};
use crate::directory::{Directory, InMemoryDirectory, PgDirectory};
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc` / a cloneable sink).
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub directory: Arc<dyn Directory>,
    pub audit: AuditSink,
}

async fn private_no_store(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    if !response.headers().contains_key(header::CACHE_CONTROL) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
    response
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        .route("/readyz", get(handlers::health::readyz))
        .route(handlers::APP_CSS_PATH, get(handlers::app_css_asset))
        .route("/", get(handlers::people::directory))
        .route("/u/{sub}", get(handlers::people::person))
        .route("/api/profile", post(handlers::people::update_profile))
        .route("/groups", get(handlers::groups::groups_page))
        .route("/groups/{id}", get(handlers::groups::group_detail))
        .route("/api/groups", post(handlers::groups::create_group))
        .route("/api/groups/{id}/members", post(handlers::groups::members))
        .route(
            "/api/groups/{id}/children",
            post(handlers::groups::child_groups),
        )
        .route("/api/people", get(handlers::api::people_json))
        .route(
            "/internal/v1/workforce/intake",
            post(handlers::workforce::intake),
        )
        .route(
            "/internal/v1/workforce/records/{subject}",
            get(handlers::workforce::get_record).put(handlers::workforce::put_record),
        )
        .route(
            "/internal/v1/workforce/changes",
            get(handlers::workforce::changes),
        )
        // OBSERVATION ONLY — rejects nothing. Records which callers arrive without a gateway
        // signature so the exempt list is derived from production traffic rather than guessed,
        // before identity verification is switched on (2026-09-14 audit, finding A).
        .layer(axum::middleware::from_fn(
            gateway_observe::observe_gateway_identity,
        ))
        .with_state(state)
        .layer(from_fn(private_no_store))
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], an empty [`InMemoryDirectory`],
/// and a disabled audit sink (no network). Used by `main`'s memory mode and the integration tests,
/// so they need no database. Tests swap in their own store/directory.
pub fn build_dev_state() -> AppState {
    AppState {
        config: Arc::new(Config::dev()),
        store: Arc::new(InMemoryStore::new()),
        directory: Arc::new(InMemoryDirectory::new()),
        audit: AuditSink::disabled(),
    }
}

/// Build runtime state from the environment.
///
/// The store is selected by `CENSUS_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// The directory is the READ-ONLY Keystone view: when `KEYSTONE_DATABASE_URL` is set, a lazily
/// connected [`PgDirectory`] enumerates real identities (a down shared DB remains an explicit read
/// failure rather than masquerading as an empty directory); otherwise an empty
/// [`InMemoryDirectory`] is used. The audit sink is enabled by `AUDIT_ENABLED` +
/// `WATCHTOWER_URL` + `AUDIT_INGEST_TOKEN`. Workforce machine endpoints independently require
/// `CENSUS_WORKFORCE_SERVICE_TOKEN`; when it is absent they fail closed with 503 while ordinary
/// directory surfaces remain available. Returns an error string on misconfiguration so `main` can
/// fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();
    let store_kind = env_nonempty("CENSUS_STORE").unwrap_or_else(|| "memory".to_string());

    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = env_nonempty("DATABASE_URL")
                .ok_or_else(|| "CENSUS_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("CENSUS_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => {
            return Err(format!(
                "unknown CENSUS_STORE={other} (use memory|postgres)"
            ))
        }
    };

    let directory: Arc<dyn Directory> = match env_nonempty("KEYSTONE_DATABASE_URL") {
        Some(dsn) => {
            let pool =
                directory::lazy_pool(&dsn).map_err(|e| format!("KEYSTONE_DATABASE_URL: {e}"))?;
            tracing::info!("federating Keystone identity directory (read-only)");
            Arc::new(PgDirectory::new(pool))
        }
        None => {
            tracing::warn!(
                "KEYSTONE_DATABASE_URL unset — directory enumerates no Keystone identities (the \
                 signed-in viewer is still always visible). Set KEYSTONE_DATABASE_URL to populate."
            );
            Arc::new(InMemoryDirectory::new())
        }
    };

    let audit = AuditSink::start(
        env_truthy("AUDIT_ENABLED"),
        &env_nonempty("WATCHTOWER_URL").unwrap_or_default(),
        env_nonempty("AUDIT_INGEST_TOKEN").as_deref(),
    );

    Ok(AppState {
        config: Arc::new(config),
        store,
        directory,
        audit,
    })
}

/// Current wall-clock time in epoch seconds (the `updated_at` / `joined_at` / `created_at` stamp).
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Monotonic-ish nanosecond counter for group ids.
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos()
}
