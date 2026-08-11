//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty, so the
//! in-memory dev path boots with NO configuration and NO database — exactly like
//! inkwell/cortex/sanctum. Production overrides each via the environment. The store / Keystone
//! directory / audit credentials are resolved in [`crate::build_state_from_env`], not here.

/// Default listen address (all interfaces, internal-only port 9130).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:9130";
/// Hard cap on how many identities the directory enumerates / renders (keeps an unbounded org
/// view bounded; real pagination is a later concern, not a hypothetical to solve now).
pub const DIRECTORY_LIMIT: usize = 2000;
/// Hard cap on how many groups the groups page renders.
pub const GROUP_LIMIT: usize = 1000;
/// Field length caps (defense against oversized form submissions).
pub const MAX_NAME_CHARS: usize = 120;
pub const MAX_TITLE_CHARS: usize = 160;
pub const MAX_BIO_CHARS: usize = 8 * 1024;
pub const MAX_URL_CHARS: usize = 1024;

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Independent machine credential for workforce intake/changefeed. Never rendered or logged.
    workforce_service_token: Option<String>,
}

impl Config {
    /// Default development configuration (in-memory friendly, no database).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            workforce_service_token: None,
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        config.workforce_service_token = env_nonempty("CENSUS_WORKFORCE_SERVICE_TOKEN");
        config
    }

    pub fn workforce_service_token(&self) -> Option<&str> {
        self.workforce_service_token.as_deref()
    }

    /// Test/dev builder that avoids mutating process-global environment variables.
    pub fn with_workforce_service_token(mut self, token: impl Into<String>) -> Self {
        self.workforce_service_token = Some(token.into());
        self
    }
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field(
                "workforce_service_token_configured",
                &self.workforce_service_token.is_some(),
            )
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
pub fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// Interpret a boolean-ish env var (`on` / `true` / `1` / `yes`, case-insensitive).
pub fn env_truthy(key: &str) -> bool {
    matches!(
        std::env::var(key)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "on" | "true" | "1" | "yes"
    )
}
