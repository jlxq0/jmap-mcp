//! OAuth 2.0 Protected Resource Metadata (RFC 9728).
//!
//! claude.ai discovers our authorization server (Logto) by following the
//! `WWW-Authenticate` header on a 401 to this document. We expose the
//! minimum required to drive the OAuth dance: `resource`,
//! `authorization_servers`, `bearer_methods_supported`, and the scopes
//! claude needs to request to operate on the user's mailbox.

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub bearer_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
}

impl ProtectedResourceMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            resource: cfg.resource_url.clone(),
            authorization_servers: vec![cfg.authorization_server.clone()],
            bearer_methods_supported: vec!["header"],
            // Standard OIDC scopes Logto issues. `email`/`profile` let the
            // access/id token carry the user's address + name for whoami +
            // audit display. The mailbox authorisation itself is bound by
            // the token's audience (this resource) + Stalwart's OIDC
            // directory, not by a custom scope.
            scopes_supported: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
        }
    }
}

#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn protected_resource_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(ProtectedResourceMetadata::from_config(&cfg))
}

/// Build the `WWW-Authenticate` value our 401 responses set. claude.ai parses
/// `resource_metadata` and walks back to discover the authorization server.
pub fn www_authenticate_header(resource_url: &str) -> String {
    format!(r#"Bearer resource_metadata="{resource_url}/.well-known/oauth-protected-resource""#)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn test_config() -> Config {
        Config::new(
            "https://jmap-mcp.example.test",
            "https://login.example.test/oidc",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    #[test]
    fn metadata_shape() {
        let m = ProtectedResourceMetadata::from_config(&test_config());
        assert_eq!(m.resource, "https://jmap-mcp.example.test");
        assert_eq!(
            m.authorization_servers,
            vec!["https://login.example.test/oidc"]
        );
        assert!(m.bearer_methods_supported.contains(&"header"));
        assert!(m.scopes_supported.iter().any(|s| s == "openid"));
    }

    #[test]
    fn www_authenticate_includes_resource_metadata_url() {
        let h = www_authenticate_header("https://jmap-mcp.example.test");
        assert!(h.starts_with("Bearer "));
        assert!(h.contains(
            r#"resource_metadata="https://jmap-mcp.example.test/.well-known/oauth-protected-resource""#
        ));
    }
}
