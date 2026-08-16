//! Transparent OAuth 2.0 proxy fronting Logto.
//!
//! claude.ai's connector requires the authorization server's `authorize` and
//! `token` endpoints to be **same-origin as the issuer** (a mix-up-attack
//! defense in the MCP auth spec). Logto lives on a different origin, so a
//! metadata document that points `authorization_endpoint` at Logto is rejected
//! and the connector never redirects the user to log in.
//!
//! So we proxy on our own origin and broker to Logto. Because Logto sees only
//! our callback URL, we must enforce the client redirect URI allowlist before
//! forwarding the flow:
//! - `GET /authorize` — validate and store the client's `redirect_uri`/`state`, then redirect
//!   to Logto's `/auth` with **our** callback + an opaque state, preserving
//!   everything else (PKCE `code_challenge`, `nonce`, `scope`, `resource`).
//! - `GET /oauth/callback` — Logto returns here; map the opaque state back and
//!   redirect to the client's original `redirect_uri` with the code + their
//!   state. `iss` is intentionally not forwarded (it would be Logto's, not
//!   ours).
//! - `POST /token` — relay the form to Logto's `/token`, rewriting
//!   allowlisted `redirect_uri` to our callback (Logto bound the code to it). PKCE verifier
//!   and the returned tokens pass through untouched — we mint nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use rand::RngCore;
use tracing::warn;
use url::Url;

use crate::oauth_redirect::is_allowed_redirect_uri;

/// How long a pending authorization (client redirect/state mapping) lives.
#[allow(clippy::duration_suboptimal_units)] // `from_secs` is clearer than mins here
const PENDING_TTL: Duration = Duration::from_secs(600);
/// Soft cap on concurrent pending authorizations; sweep on overflow.
const PENDING_CAP: usize = 2048;

#[derive(Clone)]
pub struct OAuthProxyState {
    inner: Arc<Inner>,
}

struct Inner {
    /// Logto OIDC base, e.g. `https://login.kampong.social/oidc`.
    logto_base: String,
    /// Our own callback, `{resource_url}/oauth/callback`.
    callback_url: String,
    http: reqwest::Client,
    allowed_redirect_uris: Vec<String>,
    /// Forced RFC 8707 `resource` sent to Logto (Stalwart's JWT audience).
    jmap_audience: String,
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    client_redirect_uri: String,
    client_state: Option<String>,
    created: Instant,
}

impl OAuthProxyState {
    pub fn new(
        logto_base: &str,
        resource_url: &str,
        allowed_redirect_uris: Vec<String>,
        jmap_audience: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("jmap-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Self {
            inner: Arc::new(Inner {
                logto_base: logto_base.trim_end_matches('/').to_owned(),
                callback_url: format!("{}/oauth/callback", resource_url.trim_end_matches('/')),
                http,
                allowed_redirect_uris,
                jmap_audience: jmap_audience.into(),
                pending: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn insert(&self, state: String, pending: Pending) {
        if let Ok(mut g) = self.inner.pending.lock() {
            if g.len() >= PENDING_CAP {
                let now = Instant::now();
                g.retain(|_, p| now.duration_since(p.created) < PENDING_TTL);
            }
            g.insert(state, pending);
        }
    }

    fn take(&self, state: &str) -> Option<Pending> {
        let p = {
            let mut g = self.inner.pending.lock().ok()?;
            g.remove(state)?
        };
        if Instant::now().duration_since(p.created) >= PENDING_TTL {
            return None;
        }
        Some(p)
    }
}

fn random_state() -> String {
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn parse_pairs(q: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(q.as_bytes())
        .into_owned()
        .collect()
}

/// Force the RFC 8707 `resource` we send to Logto to Stalwart's JWT
/// audience (`stalwart` by default).
///
/// Clients send `{origin}` or `{origin}/mcp` (RFC 9728). Logto then
/// mints `aud` equal to that indicator. Stalwart's OIDC directory
/// `requireAudience` is the Logto API resource **Stalwart Mail**
/// (`stalwart`), so an origin-aud token is rejected as `InvalidAudience`
/// and every tool call becomes MCP -32028. Rewrite here so the access
/// token Stalwart sees is the one it will accept. RFC 9728 metadata
/// and `/oauth/callback` stay on the origin; only the Logto `resource`
/// parameter changes.
fn apply_jmap_resource(pairs: &mut Vec<(String, String)>, jmap_audience: &str) {
    let mut saw = false;
    for (k, v) in pairs.iter_mut() {
        if k == "resource" {
            jmap_audience.clone_into(v);
            saw = true;
        }
    }
    if !saw {
        pairs.push(("resource".to_owned(), jmap_audience.to_owned()));
    }
}

/// `GET /authorize` — redirect to Logto, swapping in our callback + opaque
/// state while preserving PKCE/nonce/scope/resource.
pub async fn authorize(State(st): State<OAuthProxyState>, RawQuery(q): RawQuery) -> Response {
    let mut pairs = parse_pairs(&q.unwrap_or_default());

    let Some(client_redirect_uri) = pairs
        .iter()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.clone())
    else {
        return (StatusCode::BAD_REQUEST, "missing redirect_uri\n").into_response();
    };
    if !is_allowed_redirect_uri(&st.inner.allowed_redirect_uris, &client_redirect_uri) {
        return (StatusCode::BAD_REQUEST, "unregistered redirect_uri\n").into_response();
    }

    let client_state = pairs
        .iter()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.clone());

    let proxy_state = random_state();
    st.insert(
        proxy_state.clone(),
        Pending {
            client_redirect_uri,
            client_state,
            created: Instant::now(),
        },
    );

    let mut saw_state = false;
    for (k, v) in &mut pairs {
        if k == "redirect_uri" {
            v.clone_from(&st.inner.callback_url);
        } else if k == "state" {
            v.clone_from(&proxy_state);
            saw_state = true;
        }
    }
    if !saw_state {
        pairs.push(("state".to_owned(), proxy_state));
    }
    apply_jmap_resource(&mut pairs, &st.inner.jmap_audience);

    let qs = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    Redirect::to(&format!("{}/auth?{}", st.inner.logto_base, qs)).into_response()
}

/// `GET /oauth/callback` — Logto redirects here; bounce back to the client's
/// original `redirect_uri` with their state (not Logto's `iss`).
pub async fn callback(State(st): State<OAuthProxyState>, RawQuery(q): RawQuery) -> Response {
    let pairs: HashMap<String, String> = parse_pairs(&q.unwrap_or_default()).into_iter().collect();

    let Some(state) = pairs.get("state") else {
        return (StatusCode::BAD_REQUEST, "missing state\n").into_response();
    };
    let Some(pending) = st.take(state) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired state\n").into_response();
    };
    let Ok(mut url) = Url::parse(&pending.client_redirect_uri) else {
        return (StatusCode::BAD_REQUEST, "bad client redirect_uri\n").into_response();
    };

    {
        let mut qp = url.query_pairs_mut();
        if let Some(code) = pairs.get("code") {
            qp.append_pair("code", code);
        }
        if let Some(err) = pairs.get("error") {
            qp.append_pair("error", err);
        }
        if let Some(desc) = pairs.get("error_description") {
            qp.append_pair("error_description", desc);
        }
        if let Some(cs) = &pending.client_state {
            qp.append_pair("state", cs);
        }
    }
    Redirect::to(url.as_str()).into_response()
}

/// `POST /token` — relay the code/refresh exchange to Logto, rewriting
/// `redirect_uri` to our callback so it matches what Logto saw at `/authorize`.
pub async fn token(State(st): State<OAuthProxyState>, body: String) -> Response {
    let mut pairs = parse_pairs(&body);
    let is_authorization_code = pairs
        .iter()
        .any(|(k, v)| k == "grant_type" && v == "authorization_code");
    let mut saw_redirect_uri = false;
    for (k, v) in &mut pairs {
        if k == "redirect_uri" {
            if !is_allowed_redirect_uri(&st.inner.allowed_redirect_uris, v) {
                return (StatusCode::BAD_REQUEST, "unregistered redirect_uri\n").into_response();
            }
            saw_redirect_uri = true;
            v.clone_from(&st.inner.callback_url);
        }
    }
    apply_jmap_resource(&mut pairs, &st.inner.jmap_audience);
    if is_authorization_code && !saw_redirect_uri {
        return (StatusCode::BAD_REQUEST, "missing redirect_uri\n").into_response();
    }
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();

    let resp = st
        .inner
        .http
        .post(format!("{}/token", st.inner.logto_base))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await;

    match resp {
        Ok(r) => {
            let status = r.status();
            let content_type = r
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_owned();
            let bytes = r.bytes().await.unwrap_or_default();
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => {
            warn!(error = %e, "token proxy upstream error");
            (StatusCode::BAD_GATEWAY, "token endpoint upstream error\n").into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn callback_url_derived_from_resource() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc/",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/cb".to_owned()],
            "stalwart",
        );
        assert_eq!(
            st.inner.callback_url,
            "https://jmap-mcp.example.test/oauth/callback"
        );
        assert_eq!(st.inner.logto_base, "https://login.example.test/oidc");
    }

    #[test]
    fn pending_roundtrip_and_expiry_guard() {
        let st = OAuthProxyState::new(
            "https://l.test/oidc",
            "https://r.test",
            vec!["https://claude.ai/cb".to_owned()],
            "stalwart",
        );
        st.insert(
            "abc".to_owned(),
            Pending {
                client_redirect_uri: "https://claude.ai/cb".to_owned(),
                client_state: Some("xyz".to_owned()),
                created: Instant::now(),
            },
        );
        let p = st.take("abc").expect("present");
        assert_eq!(p.client_redirect_uri, "https://claude.ai/cb");
        assert_eq!(p.client_state.as_deref(), Some("xyz"));
        // consumed
        assert!(st.take("abc").is_none());
    }

    #[tokio::test]
    async fn authorize_rejects_unregistered_redirect_uri() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/api/mcp/auth_callback".to_owned()],
            "stalwart",
        );

        let response = authorize(
            State(st),
            RawQuery(Some(
                "client_id=abc&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb&response_type=code"
                    .to_owned(),
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authorize_forwards_only_allowed_redirect_uri_to_pending_state() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/api/mcp/auth_callback".to_owned()],
            "stalwart",
        );

        let response = authorize(
            State(st.clone()),
            RawQuery(Some(
                "client_id=abc&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&state=client-state&resource=https%3A%2F%2Fjmap-mcp.example.test%2F"
                    .to_owned(),
            )),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .expect("redirect location")
            .to_str()
            .unwrap();
        let upstream = Url::parse(location).unwrap();
        let params: HashMap<String, String> = upstream.query_pairs().into_owned().collect();
        assert_eq!(
            params.get("redirect_uri").map(String::as_str),
            Some("https://jmap-mcp.example.test/oauth/callback")
        );
        assert_eq!(params.get("resource").map(String::as_str), Some("stalwart"));
        let proxy_state = params.get("state").expect("proxy state");
        let pending = st.take(proxy_state).expect("pending state");
        assert_eq!(
            pending.client_redirect_uri,
            "https://claude.ai/api/mcp/auth_callback"
        );
        assert_eq!(pending.client_state.as_deref(), Some("client-state"));
    }

    #[tokio::test]
    async fn token_rejects_unregistered_authorization_code_redirect_uri() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/api/mcp/auth_callback".to_owned()],
            "stalwart",
        );

        let response = token(
            State(st),
            "grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb&code_verifier=v"
                .to_owned(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_rejects_missing_authorization_code_redirect_uri() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/api/mcp/auth_callback".to_owned()],
            "stalwart",
        );

        let response = token(
            State(st),
            "grant_type=authorization_code&code=abc&code_verifier=v".to_owned(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn apply_jmap_resource_rewrites_origin_and_mcp_path() {
        let mut pairs = vec![(
            "resource".to_owned(),
            "https://jmap-mcp.kampong.social/mcp".to_owned(),
        )];
        apply_jmap_resource(&mut pairs, "stalwart");
        assert_eq!(pairs, vec![("resource".to_owned(), "stalwart".to_owned())]);
        let mut pairs = vec![(
            "resource".to_owned(),
            "https://jmap-mcp.kampong.social/".to_owned(),
        )];
        apply_jmap_resource(&mut pairs, "stalwart");
        assert_eq!(pairs, vec![("resource".to_owned(), "stalwart".to_owned())]);
    }

    #[test]
    fn apply_jmap_resource_inserts_when_missing() {
        let mut pairs = vec![("scope".to_owned(), "openid".to_owned())];
        apply_jmap_resource(&mut pairs, "stalwart");
        assert_eq!(
            pairs,
            vec![
                ("scope".to_owned(), "openid".to_owned()),
                ("resource".to_owned(), "stalwart".to_owned()),
            ]
        );
    }

    #[test]
    fn random_state_is_unique_and_hex() {
        let a = random_state();
        let b = random_state();
        assert_ne!(a, b);
        assert_eq!(a.len(), 48);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
