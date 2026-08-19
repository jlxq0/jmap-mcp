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

use std::collections::{BTreeSet, HashMap};
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
/// Hard cap on concurrent pending authorizations.
const PENDING_CAP: usize = 2048;
/// OAuth state is opaque to us, but retaining arbitrarily large values makes
/// the public authorization endpoint an avoidable memory amplifier.
const MAX_CLIENT_STATE_BYTES: usize = 4096;

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
    pending: Mutex<PendingAuthorizations>,
}

struct Pending {
    client_redirect_uri: String,
    client_state: Option<String>,
    created: Instant,
}

#[derive(Default)]
struct PendingAuthorizations {
    by_state: HashMap<String, Pending>,
    by_age: BTreeSet<(Instant, String)>,
}

impl OAuthProxyState {
    pub fn new(logto_base: &str, resource_url: &str, allowed_redirect_uris: Vec<String>) -> Self {
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
                pending: Mutex::new(PendingAuthorizations::default()),
            }),
        }
    }

    fn insert(&self, state: String, pending: Pending) {
        if let Ok(mut g) = self.inner.pending.lock() {
            let now = Instant::now();
            while let Some((created, oldest_state)) = g.by_age.first().cloned() {
                let expired = now.saturating_duration_since(created) >= PENDING_TTL;
                if !expired && g.by_state.len() < PENDING_CAP {
                    break;
                }
                g.by_age.remove(&(created, oldest_state.clone()));
                g.by_state.remove(&oldest_state);
            }
            if let Some(replaced) = g.by_state.remove(&state) {
                g.by_age.remove(&(replaced.created, state.clone()));
            }
            g.by_age.insert((pending.created, state.clone()));
            g.by_state.insert(state, pending);
        }
    }

    fn take(&self, state: &str) -> Option<Pending> {
        let p = {
            let mut g = self.inner.pending.lock().ok()?;
            let p = g.by_state.remove(state)?;
            g.by_age.remove(&(p.created, state.to_owned()));
            p
        };
        if Instant::now().saturating_duration_since(p.created) >= PENDING_TTL {
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

/// Normalize an RFC 8707 `resource` indicator before proxying to Logto.
///
/// claude.ai sends `https://host/`; Logto matches the registered API
/// resource (`https://host`) byte-for-byte and rejects the slashed form
/// with `invalid_target`. After we advertise `resource = {origin}/mcp`,
/// clients send that path too. Logto's registered API resource (and the
/// JWT `aud` we validate) remains the origin, so strip a trailing `/mcp`.
fn normalize_resource(v: &mut String) {
    let trimmed = v.trim_end_matches('/');
    let s = trimmed.strip_suffix("/mcp").unwrap_or(trimmed).to_owned();
    if s != *v {
        *v = s;
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
    if client_state
        .as_ref()
        .is_some_and(|state| state.len() > MAX_CLIENT_STATE_BYTES)
    {
        return (StatusCode::BAD_REQUEST, "state is too large\n").into_response();
    }

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
        } else if k == "resource" {
            normalize_resource(v);
        }
    }
    if !saw_state {
        pairs.push(("state".to_owned(), proxy_state));
    }

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
        } else if k == "resource" {
            normalize_resource(v);
        }
    }
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

    #[test]
    fn pending_authorizations_are_hard_capped() {
        let st = OAuthProxyState::new(
            "https://l.test/oidc",
            "https://r.test",
            vec!["https://claude.ai/cb".to_owned()],
        );
        for i in 0..=PENDING_CAP {
            st.insert(
                format!("state-{i}"),
                Pending {
                    client_redirect_uri: "https://claude.ai/cb".to_owned(),
                    client_state: Some(format!("client-{i}")),
                    created: Instant::now(),
                },
            );
        }
        let pending = st.inner.pending.lock().unwrap();
        assert_eq!(pending.by_state.len(), PENDING_CAP);
        assert_eq!(pending.by_age.len(), PENDING_CAP);
        assert!(!pending.by_state.contains_key("state-0"));
        assert!(
            pending
                .by_state
                .contains_key(&format!("state-{PENDING_CAP}"))
        );
        drop(pending);
    }

    #[tokio::test]
    async fn authorize_rejects_oversized_client_state() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/cb".to_owned()],
        );
        let query = format!(
            "redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&state={}",
            "a".repeat(MAX_CLIENT_STATE_BYTES + 1)
        );
        let response = authorize(State(st), RawQuery(Some(query))).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authorize_rejects_unregistered_redirect_uri() {
        let st = OAuthProxyState::new(
            "https://login.example.test/oidc",
            "https://jmap-mcp.example.test",
            vec!["https://claude.ai/api/mcp/auth_callback".to_owned()],
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
        assert_eq!(
            params.get("resource").map(String::as_str),
            Some("https://jmap-mcp.example.test")
        );
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
        );

        let response = token(
            State(st),
            "grant_type=authorization_code&code=abc&code_verifier=v".to_owned(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn normalize_resource_strips_trailing_slash() {
        let mut a = "https://jmap-mcp.kampong.social/".to_owned();
        normalize_resource(&mut a);
        assert_eq!(a, "https://jmap-mcp.kampong.social");
        // already-canonical is untouched
        let mut b = "https://jmap-mcp.kampong.social".to_owned();
        normalize_resource(&mut b);
        assert_eq!(b, "https://jmap-mcp.kampong.social");
    }

    #[test]
    fn normalize_resource_strips_mcp_path() {
        let mut a = "https://jmap-mcp.kampong.social/mcp".to_owned();
        normalize_resource(&mut a);
        assert_eq!(a, "https://jmap-mcp.kampong.social");
        let mut b = "https://jmap-mcp.kampong.social/mcp/".to_owned();
        normalize_resource(&mut b);
        assert_eq!(b, "https://jmap-mcp.kampong.social");
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
