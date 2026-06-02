//! Envelope-only audit logging.
//!
//! Every tool call and token validation emits a structured `tracing::info`
//! event at `target: "jmap_mcp::audit"`. The cluster's Alloy collector ships
//! these to Loki keyed by `target`.
//!
//! ## What is and isn't logged
//!
//! Envelope fields **are** logged: `event`, `user` (email/sub), `method`
//! (MCP tool name), `resource` (mailbox/email id when relevant), `outcome`,
//! `latency_ms`, `result_count`, `error_class`, `token_hash` (16 hex chars of
//! `sha256(bearer)`).
//!
//! Content fields **are not** logged: email bodies, subjects, recipient
//! addresses, attachment contents, bearer tokens (only their hash prefix),
//! or any user-supplied free-form text from tool params.

use std::time::Instant;

use rmcp::ErrorData;
use sha2::{Digest, Sha256};
use tracing::info;

/// Coarse outcome class for an audit event. Stable strings for Grafana/Loki.
#[allow(dead_code)]
pub mod outcome {
    pub const OK: &str = "ok";
    pub const ERROR: &str = "error";
    pub const DENIED: &str = "denied";
    pub const NOT_FOUND: &str = "not_found";
    pub const INVALID: &str = "invalid";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const ACTIVE: &str = "active";
    pub const INACTIVE: &str = "inactive";
    pub const RATE_LIMITED: &str = "rate_limited";
}

/// First 16 hex chars of `sha256(bearer)` — a stable pseudonymous token id
/// for correlation without ever logging the token.
#[must_use]
pub fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..8])
}

/// JSON-RPC application code: caller exceeded their per-minute quota.
pub const RATE_LIMITED_CODE: i32 = -32029;
/// JSON-RPC application code: the Logto bearer expired / was rejected by
/// Stalwart. Used by `react_to_auth_expiry` to mark the rewritten error.
pub const AUTH_EXPIRED_CODE: i32 = -32028;

#[must_use]
pub const fn error_class(err: &ErrorData) -> &'static str {
    match err.code.0 {
        -32700 => "parse",
        -32600 => "invalid_request",
        -32601 => "method_not_found",
        -32602 => "invalid_params",
        -32603 => "internal",
        RATE_LIMITED_CODE => "rate_limited",
        AUTH_EXPIRED_CODE => "auth_expired",
        _ => "other",
    }
}

/// Emit a `tool_call` audit event. Call at the END of every tool body, on
/// both success and error paths. Also bumps the matching Prometheus metric.
pub fn tool_call(
    tool: &'static str,
    user: &str,
    resource: Option<&str>,
    outcome: &'static str,
    started: Instant,
    result_count: Option<usize>,
    err_class: Option<&'static str>,
) {
    let elapsed = started.elapsed();
    // `resource` may be a raw, caller-supplied tool parameter (even on
    // validation-failure paths), so sanitise it before emission to stop an
    // attacker injecting newlines / fake `outcome=` fragments into logs.
    let safe_resource: Option<&str> = resource.map(|r| if is_safe_id(r) { r } else { "<invalid>" });
    info!(
        target: "jmap_mcp::audit",
        event = "tool_call",
        method = tool,
        user,
        resource = safe_resource,
        outcome,
        latency_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        result_count,
        error_class = err_class,
    );
    crate::metrics::record_tool_call(tool, outcome, elapsed);
}

/// Audit-safe JMAP id check: no whitespace/control chars, bounded length.
/// JMAP ids are server-assigned short opaque strings (RFC 8620 §1.2:
/// `[A-Za-z0-9_-]`, ≤255 chars) — anything else is caller junk.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
}

/// Emit an `introspect` (token-validation) audit event from the auth path.
pub fn introspect(token_hash: &str, outcome: &'static str, started: Instant, user: Option<&str>) {
    let elapsed = started.elapsed();
    info!(
        target: "jmap_mcp::audit",
        event = "introspect",
        token_hash,
        user,
        outcome,
        latency_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    );
    crate::metrics::record_introspect(outcome, elapsed);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_is_16_hex_chars() {
        let h = token_hash("any-bearer-string");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn is_safe_id_accepts_jmap_ids_and_emails() {
        assert!(is_safe_id("Mca12345"));
        assert!(is_safe_id("alice@kampong.social"));
        assert!(!is_safe_id("has space"));
        assert!(!is_safe_id("inject\noutcome=ok"));
        assert!(!is_safe_id(""));
    }

    #[test]
    fn error_class_maps_known_codes() {
        assert_eq!(
            error_class(&ErrorData::internal_error("x", None)),
            "internal"
        );
        assert_eq!(
            error_class(&ErrorData::invalid_params("x", None)),
            "invalid_params"
        );
    }

    #[test]
    fn outcomes_are_stable_strings() {
        assert_eq!(outcome::OK, "ok");
        assert_eq!(outcome::ERROR, "error");
        assert_eq!(outcome::RATE_LIMITED, "rate_limited");
    }
}
