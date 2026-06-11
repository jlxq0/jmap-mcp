//! OAuth 2.0 metadata + a Dynamic Client Registration shim.
//!
//! claude.ai onboards a remote MCP server purely through OAuth discovery +
//! **Dynamic Client Registration** (RFC 7591). Our `IdP` (Logto) exposes no DCR
//! endpoint, so a bare `authorization_servers: [Logto]` would dead-end the
//! connector at "couldn't register client".
//!
//! Fix: front Logto. We advertise *ourselves* as the authorization server in
//! the protected-resource metadata (RFC 9728), then serve RFC 8414
//! authorization-server metadata whose `authorize`/`token`/`jwks` endpoints
//! delegate straight to Logto but whose `registration_endpoint` points back at
//! our `/register` shim. The shim hands every caller one pre-provisioned Logto
//! public-SPA client (`JMAP_MCP_DCR_CLIENT_ID`, redirect URIs already
//! whitelisted in Logto). The access token claude.ai ultimately presents is
//! still a Logto JWT for our resource indicator — validated unchanged by
//! `logto_oidc`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::oauth_redirect::is_allowed_redirect_uri;

/// Scopes claude.ai should request. `offline_access` lets Logto mint a refresh
/// token so the connector survives access-token expiry without a re-login.
fn scopes_supported() -> Vec<String> {
    vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
        "offline_access".to_owned(),
    ]
}

// ---------------------------------------------------------------------------
// Protected Resource Metadata (RFC 9728)
// ---------------------------------------------------------------------------

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
            // Point at OURSELVES, not Logto: claude.ai then fetches our
            // /.well-known/oauth-authorization-server (which carries a
            // registration_endpoint). The authorize/token endpoints in that
            // document delegate to Logto.
            authorization_servers: vec![cfg.resource_url.clone()],
            bearer_methods_supported: vec!["header"],
            scopes_supported: scopes_supported(),
        }
    }
}

#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn protected_resource_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(ProtectedResourceMetadata::from_config(&cfg))
}

// ---------------------------------------------------------------------------
// Authorization Server Metadata (RFC 8414)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    pub response_types_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub scopes_supported: Vec<String>,
}

impl AuthorizationServerMetadata {
    pub fn from_config(cfg: &Config) -> Self {
        // `authorization_server` is the Logto OIDC base, e.g.
        // `https://login.kampong.social/oidc`.
        let logto = &cfg.authorization_server;
        let us = &cfg.resource_url;
        Self {
            // The issuer is *us* — this document is fetched from our origin and
            // RFC 8414 requires issuer to equal that origin.
            issuer: us.clone(),
            // authorize/token MUST be same-origin as the issuer or claude.ai's
            // connector refuses to redirect (mix-up defense). We proxy both to
            // Logto (see oauth_proxy). jwks stays on Logto — it's just keys and
            // not subject to the same-origin rule.
            authorization_endpoint: format!("{us}/authorize"),
            token_endpoint: format!("{us}/token"),
            jwks_uri: format!("{logto}/jwks"),
            userinfo_endpoint: format!("{logto}/me"),
            registration_endpoint: cfg
                .dcr_client_id
                .as_ref()
                .map(|_| format!("{}/register", cfg.resource_url)),
            response_types_supported: vec!["code"],
            grant_types_supported: vec!["authorization_code", "refresh_token"],
            code_challenge_methods_supported: vec!["S256"],
            // Our DCR client is a public PKCE SPA — no client secret.
            token_endpoint_auth_methods_supported: vec!["none"],
            scopes_supported: scopes_supported(),
        }
    }
}

#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn authorization_server_metadata(State(cfg): State<Config>) -> impl IntoResponse {
    Json(AuthorizationServerMetadata::from_config(&cfg))
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration shim (RFC 7591)
// ---------------------------------------------------------------------------

/// Returns the single pre-provisioned Logto public client for allowed
/// registrations. Because the proxy hides the real client redirect URI from
/// Logto, we enforce the same exact redirect URI allowlist before echoing
/// requested redirect URIs for protocol conformance.
#[allow(clippy::unused_async)] // Axum requires async handlers.
pub async fn register(State(cfg): State<Config>, body: Option<Json<Value>>) -> impl IntoResponse {
    let Some(client_id) = cfg.dcr_client_id else {
        return (
            StatusCode::NOT_FOUND,
            "dynamic client registration is not configured\n",
        )
            .into_response();
    };

    let redirect_uris: Vec<String> = body
        .as_ref()
        .and_then(|Json(v)| v.get("redirect_uris"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if redirect_uris
        .iter()
        .any(|uri| !is_allowed_redirect_uri(&cfg.oauth_redirect_uris, uri))
    {
        return (StatusCode::BAD_REQUEST, "unregistered redirect_uri\n").into_response();
    }

    let resp = json!({
        "client_id": client_id,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": redirect_uris,
        "scope": "openid profile email offline_access",
        "client_id_issued_at": now_unix(),
    });
    (StatusCode::CREATED, Json(resp)).into_response()
}

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
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
    fn protected_resource_points_at_self() {
        let m = ProtectedResourceMetadata::from_config(&test_config());
        assert_eq!(m.resource, "https://jmap-mcp.example.test");
        // We front the IdP: authorization_servers must be our own origin so
        // claude.ai fetches our DCR-enabled metadata.
        assert_eq!(
            m.authorization_servers,
            vec!["https://jmap-mcp.example.test"]
        );
        assert!(m.bearer_methods_supported.contains(&"header"));
        assert!(m.scopes_supported.iter().any(|s| s == "openid"));
    }

    #[test]
    fn as_metadata_is_same_origin_with_jwks_on_logto() {
        let m = AuthorizationServerMetadata::from_config(&test_config());
        assert_eq!(m.issuer, "https://jmap-mcp.example.test");
        // authorize/token are on OUR origin (proxied); jwks stays on Logto.
        assert_eq!(
            m.authorization_endpoint,
            "https://jmap-mcp.example.test/authorize"
        );
        assert_eq!(m.token_endpoint, "https://jmap-mcp.example.test/token");
        assert_eq!(m.jwks_uri, "https://login.example.test/oidc/jwks");
        assert!(m.code_challenge_methods_supported.contains(&"S256"));
        // No DCR client configured in the bare test config.
        assert!(m.registration_endpoint.is_none());
    }

    #[test]
    fn as_metadata_advertises_registration_when_configured() {
        let mut cfg = test_config();
        cfg.dcr_client_id = Some("abc123".to_owned());
        let m = AuthorizationServerMetadata::from_config(&cfg);
        assert_eq!(
            m.registration_endpoint.as_deref(),
            Some("https://jmap-mcp.example.test/register")
        );
    }

    #[tokio::test]
    async fn register_rejects_unregistered_redirect_uri() {
        let mut cfg = test_config();
        cfg.dcr_client_id = Some("abc123".to_owned());
        cfg.oauth_redirect_uris = vec!["https://claude.ai/api/mcp/auth_callback".to_owned()];
        let body = json!({
            "redirect_uris": ["https://attacker.example/cb"],
        });

        let response = register(State(cfg), Some(Json(body))).await.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_accepts_allowlisted_redirect_uri() {
        let mut cfg = test_config();
        cfg.dcr_client_id = Some("abc123".to_owned());
        cfg.oauth_redirect_uris = vec!["https://claude.ai/api/mcp/auth_callback".to_owned()];
        let body = json!({
            "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
        });

        let response = register(State(cfg), Some(Json(body))).await.into_response();

        assert_eq!(response.status(), StatusCode::CREATED);
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
