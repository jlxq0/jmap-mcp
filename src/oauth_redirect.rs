//! Shared redirect URI validation for the OAuth proxy and DCR shim.

use anyhow::{Context, Result};
use url::Url;

/// Comma-separated redirect URI allowlist for proxied OAuth clients.
///
/// HTTPS and private-use callbacks match exactly. Loopback HTTP callbacks
/// match the configured host, path, and query while allowing the client to
/// choose its local listener port, as required for native OAuth clients.
pub const ENV_OAUTH_REDIRECT_URIS: &str = "JMAP_MCP_OAUTH_REDIRECT_URIS";

pub fn parse_allowlist(raw: &str, key: &str) -> Result<Vec<String>> {
    let mut uris = Vec::new();
    for uri in raw.split(',').map(str::trim).filter(|uri| !uri.is_empty()) {
        validate_redirect_uri(uri, key)?;
        if !uris.iter().any(|allowed| allowed == uri) {
            uris.push(uri.to_owned());
        }
    }
    if uris.is_empty() {
        anyhow::bail!("{key} must contain at least one redirect URI");
    }
    Ok(uris)
}

pub fn is_allowed_redirect_uri(allowed: &[String], uri: &str) -> bool {
    if validate_redirect_uri(uri, "redirect_uri").is_err() {
        return false;
    }

    let Ok(candidate) = Url::parse(uri) else {
        return false;
    };

    allowed
        .iter()
        .any(|configured| configured == uri || loopback_redirect_matches(configured, &candidate))
}

/// RFC 8252 loopback redirects use an ephemeral port. Keep every other URI
/// component pinned to the operator's allowlist entry so variable ports do not
/// become a general wildcard.
///
/// The entry-side loopback host check is redundant today — `validate_redirect_uri`
/// already refuses an `http` entry on a non-loopback host, so with the entry-scheme
/// check in place it can never be the deciding term. It is kept as the second lock:
/// if the validator ever loosens, this is what still refuses to relax the port for a
/// remote host. Mutating it alone therefore breaks no test, by construction.
fn loopback_redirect_matches(configured: &str, candidate: &Url) -> bool {
    let Ok(configured) = Url::parse(configured) else {
        return false;
    };

    configured.scheme() == "http"
        && candidate.scheme() == "http"
        && configured.host_str().is_some_and(is_loopback_host)
        && configured.host_str() == candidate.host_str()
        && configured.path() == candidate.path()
        && configured.query() == candidate.query()
}

/// Loopback hosts accepted for cleartext `http://` redirect URIs
/// (RFC 8252 §7.3). Anything else over `http` would put the authorization
/// code on the wire in cleartext.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn validate_redirect_uri(uri: &str, key: &str) -> Result<()> {
    if uri.trim() != uri || uri.is_empty() {
        anyhow::bail!(
            "{key} entries must be non-empty absolute URLs without surrounding whitespace"
        );
    }
    let url = Url::parse(uri).with_context(|| format!("invalid {key} redirect URI: {uri}"))?;
    match url.scheme() {
        "https" => {
            if url.host_str().is_none() {
                anyhow::bail!("{key} https entries must include a host: {uri}");
            }
        }
        // RFC 8252 §7.3 loopback interface redirection. Native apps bind an
        // ephemeral local port, so this is the one case where cleartext is
        // acceptable — but only on a loopback host.
        "http" => {
            let host = url.host_str().unwrap_or_default();
            if !is_loopback_host(host) {
                anyhow::bail!(
                    "{key} http entries are only allowed on loopback hosts \
                     (localhost, 127.0.0.1, [::1]): {uri}"
                );
            }
        }
        // RFC 8252 §7.1 private-use ("custom") URI schemes, e.g.
        // `cursor://…` / `grokbot://…` used by native MCP clients. The exact
        // allowlist in `is_allowed_redirect_uri` is the actual control — an
        // operator must list the URI explicitly — so this arm only rejects
        // structurally broken input.
        scheme => {
            if scheme.is_empty() {
                anyhow::bail!("{key} entries must have a scheme: {uri}");
            }
        }
    }
    if url.fragment().is_some() {
        anyhow::bail!("{key} entries must not contain URI fragments: {uri}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("{key} entries must not contain user info: {uri}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_matches_exact_redirect_uri_only() {
        let allowed = parse_allowlist("https://claude.ai/api/mcp/auth_callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai/api/mcp/auth_callback/"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://attacker.example/callback"
        ));
        // The RFC 8252 §7.3 port carve-out is loopback-only: an https callback
        // keeps its port pinned, so a redirect to another listener on the same
        // host is not smuggled in.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://claude.ai:8443/api/mcp/auth_callback"
        ));
    }

    /// RFC 8252 section 7.3 requires authorization servers to accept the
    /// ephemeral port selected by a native client's loopback listener. Claude
    /// Code uses this shape even when a preferred callback port is configured.
    #[test]
    fn loopback_allowlist_varies_only_the_port() {
        let allowed = parse_allowlist("http://localhost:8787/callback", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://127.0.0.1:49152/callback"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/other"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:49152/callback?next=evil"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:49152/callback"
        ));
    }

    /// The port carve-out keys off the *entry's* scheme, not just the request's.
    /// An operator who allowlists a TLS listener on a loopback host must not have
    /// it answered by a cleartext one: dropping the entry-scheme check turns
    /// `https://localhost:8443/cb` into a wildcard over `http://localhost:*/cb`,
    /// which is the authorization code in the clear.
    #[test]
    fn loopback_https_entry_is_not_downgraded_to_cleartext() {
        let allowed = parse_allowlist("https://localhost:8443/cb", "TEST").unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "https://localhost:8443/cb"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:3118/cb"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "http://localhost:8443/cb"
        ));
        // The port stays pinned for an https entry even on a loopback host.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "https://localhost:3118/cb"
        ));

        // The parser canonicalises `127.1` and `0177.0.0.1` to `127.0.0.1`
        // before the loopback host check, so an obfuscated spelling reaches the
        // relaxation by exactly the same path as the plain one. The entry-scheme
        // check is what stops all three; the shape of the host is not.
        for entry in [
            "https://127.0.0.1:8443/cb",
            "https://127.1:8443/cb",
            "https://0177.0.0.1:8443/cb",
        ] {
            let allowed = parse_allowlist(entry, "TEST").unwrap();
            assert!(
                !is_allowed_redirect_uri(&allowed, "http://127.0.0.1:3118/cb"),
                "{entry} must not be satisfied by cleartext"
            );
        }
    }

    #[test]
    fn allowlist_rejects_fragments_and_userinfo() {
        assert!(parse_allowlist("https://claude.ai/cb#frag", "TEST").is_err());
        assert!(parse_allowlist("https://user@claude.ai/cb", "TEST").is_err());
    }

    /// RFC 8252 §7.1 — native MCP clients (Cursor / Grok Bot desktop) register
    /// private-use scheme callbacks. They must survive `parse_allowlist` (which
    /// runs at startup over the env var) and then match exactly.
    #[test]
    fn allowlist_accepts_private_use_schemes() {
        let allowed = parse_allowlist(
            "cursor://anysphere.cursor-mcp/oauth/callback,grokbot://mcp/oauth/callback",
            "TEST",
        )
        .unwrap();

        assert!(is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback"
        ));
        assert!(is_allowed_redirect_uri(
            &allowed,
            "grokbot://mcp/oauth/callback"
        ));
        // Still exact-match: a different private-use URI is not smuggled in.
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "cursor://anysphere.cursor-mcp/oauth/callback/extra"
        ));
        assert!(!is_allowed_redirect_uri(
            &allowed,
            "evil://mcp/oauth/callback"
        ));
    }

    /// RFC 8252 §7.3 — loopback HTTP is allowed; any other cleartext host is
    /// not. This is a tightening: `http://` on an arbitrary host used to pass.
    #[test]
    fn http_is_loopback_only() {
        for uri in [
            "http://localhost:8787/callback",
            "http://127.0.0.1:8787/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_ok(), "should accept {uri}");
        }
        for uri in [
            "http://evil.example/callback",
            "http://localhost.evil.example/callback",
        ] {
            assert!(parse_allowlist(uri, "TEST").is_err(), "should reject {uri}");
        }
    }

    /// The exact set the deployment ships, parsed as one env value.
    #[test]
    fn deployed_allowlist_parses() {
        let raw = "https://claude.ai/api/mcp/auth_callback,\
                   https://claude.com/api/mcp/auth_callback,\
                   https://www.cursor.com/agents/mcp/oauth/callback,\
                   cursor://anysphere.cursor-mcp/oauth/callback,\
                   grokbot://mcp/oauth/callback,\
                   http://localhost:8787/callback,\
                   claude://claude.ai/oauth/callback,\
                   claude://oauth/callback,\
                   cowork://oauth/callback";
        let allowed = parse_allowlist(raw, ENV_OAUTH_REDIRECT_URIS).unwrap();
        assert_eq!(allowed.len(), 9);
    }
}
