//! Gateway identity OBSERVATION — records what enforcement *would* reject, and rejects nothing.
//!
//! This service currently trusts `X-Auth-Subject` with no signature check (2026-09-14 audit,
//! finding A). Before switching that on we need to know which real callers arrive WITHOUT a
//! gateway signature, because enforcement fails closed and every one of them would break:
//! container healthchecks, Beacon probes, `auth: public` asset routes, internal bearer callers,
//! cron and workers all reach these services without ever passing through Sluice.
//!
//! Deliberately **key-free**. The obvious way to run an observation period is to ship the key
//! first and enforce later, but `GATEWAY_HMAC_KEY` is symmetric — holding it is minting it — so
//! that window would hand an unverified service the estate's universal minting secret. The
//! outage risk lives entirely in requests that carry NO signature, and detecting those needs no
//! key at all. A signature that is present but invalid cannot be distinguished here; that is
//! acceptable, because legitimate gateway traffic always carries a valid one.
//!
//! Logging is deduplicated by (verdict, method, path) and re-logged at powers of ten, so a
//! healthcheck hitting `/healthz` every 10s produces a handful of lines rather than thousands,
//! while still showing volume — which is what separates a recurring legitimate caller from a
//! one-off probe.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const HEADER_SUBJECT: &str = "x-auth-subject";
const HEADER_EMAIL: &str = "x-auth-email";
const HEADER_GROUPS: &str = "x-auth-groups";
const HEADER_SIG: &str = "x-auth-sig";

/// Bound on distinct (verdict, method, path) keys retained, so a service with path parameters
/// cannot grow this map without limit.
const MAX_TRACKED: usize = 512;

fn seen() -> &'static Mutex<HashMap<String, u64>> {
    static SEEN: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How this request would fare once the gateway identity is enforced.
fn classify(headers: &axum::http::HeaderMap) -> &'static str {
    let present = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    };
    match (
        present(HEADER_SUBJECT),
        present(HEADER_SIG),
        present(HEADER_GROUPS) || present(HEADER_EMAIL),
    ) {
        // A signed identity. Whether the signature VERIFIES cannot be checked without the key;
        // genuine gateway traffic always does.
        (true, true, _) => "signed",
        // An identity with no signature: rejected under enforcement.
        (true, false, _) => "unsigned",
        // No subject but other identity headers: a partial envelope, always rejected.
        (false, _, true) => "partial",
        // No identity at all. Fine for a genuinely public path; rejected on a guarded one, so
        // every path reported here needs an explicit decision before enforcement.
        (false, _, false) => "anonymous",
    }
}

/// Observation middleware. Never alters the response.
pub async fn observe_gateway_identity(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let verdict = classify(req.headers());
    if verdict != "signed" {
        let method = req.method().clone();
        let path = req.uri().path().to_string();
        let key = format!("{verdict} {method} {path}");
        let count = {
            match seen().lock() {
                Ok(mut map) => {
                    if !map.contains_key(&key) && map.len() >= MAX_TRACKED {
                        // Cap reached: stop tracking new shapes rather than grow unbounded.
                        None
                    } else {
                        let c = map.entry(key).or_insert(0);
                        *c += 1;
                        Some(*c)
                    }
                }
                Err(_) => None,
            }
        };
        // First sighting, then powers of ten: enough to show volume without flooding.
        if let Some(c) = count {
            if c == 1 || c == 10 || c == 100 || c == 1_000 || c == 10_000 || c % 100_000 == 0 {
                tracing::warn!(
                    target: "gateway_observe",
                    verdict,
                    %method,
                    %path,
                    count = c,
                    "gateway identity would be REJECTED once enforced"
                );
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn classifies_a_signed_identity() {
        assert_eq!(
            classify(&headers(&[(HEADER_SUBJECT, "w33d"), (HEADER_SIG, "abc")])),
            "signed"
        );
    }

    #[test]
    fn classifies_an_unsigned_identity() {
        assert_eq!(classify(&headers(&[(HEADER_SUBJECT, "w33d")])), "unsigned");
    }

    #[test]
    fn classifies_a_partial_envelope() {
        assert_eq!(classify(&headers(&[(HEADER_GROUPS, "admins")])), "partial");
        assert_eq!(
            classify(&headers(&[(HEADER_EMAIL, "a@w33d.xyz")])),
            "partial"
        );
    }

    #[test]
    fn classifies_an_anonymous_request() {
        assert_eq!(classify(&HeaderMap::new()), "anonymous");
    }

    #[test]
    fn an_empty_header_value_is_not_an_identity() {
        assert_eq!(classify(&headers(&[(HEADER_SUBJECT, "   ")])), "anonymous");
    }
}
