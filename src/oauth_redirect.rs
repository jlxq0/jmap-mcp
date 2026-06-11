//! Shared redirect URI validation for the OAuth proxy and DCR shim.

use anyhow::{Context, Result};
use url::Url;

/// Comma-separated exact redirect URI allowlist for proxied OAuth clients.
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
    validate_redirect_uri(uri, "redirect_uri").is_ok()
        && allowed.iter().any(|allowed| allowed == uri)
}

fn validate_redirect_uri(uri: &str, key: &str) -> Result<()> {
    if uri.trim() != uri || uri.is_empty() {
        anyhow::bail!(
            "{key} entries must be non-empty absolute URLs without surrounding whitespace"
        );
    }
    let url = Url::parse(uri).with_context(|| format!("invalid {key} redirect URI: {uri}"))?;
    match url.scheme() {
        "http" | "https" => {}
        _ => anyhow::bail!("{key} entries must be absolute http(s) URLs: {uri}"),
    }
    if url.host_str().is_none() {
        anyhow::bail!("{key} entries must include a host: {uri}");
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
    }

    #[test]
    fn allowlist_rejects_fragments_and_userinfo() {
        assert!(parse_allowlist("https://claude.ai/cb#frag", "TEST").is_err());
        assert!(parse_allowlist("https://user@claude.ai/cb", "TEST").is_err());
    }
}
