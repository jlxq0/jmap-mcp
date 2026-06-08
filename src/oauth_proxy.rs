//! Transparent OAuth 2.0 proxy fronting Logto.
//!
//! claude.ai's connector requires the authorization server's `authorize` and
//! `token` endpoints to be **same-origin as the issuer** (a mix-up-attack
//! defense in the MCP auth spec). Logto lives on a different origin, so a
//! metadata document that points `authorization_endpoint` at Logto is rejected
//! and the connector never redirects the user to log in.
//!
//! So we proxy on our own origin and broker to Logto:
//! - `GET /authorize` — store the client's `redirect_uri`/`state`, then redirect
//!   to Logto's `/auth` with **our** callback + an opaque state, preserving
//!   everything else (PKCE `code_challenge`, `nonce`, `scope`, `resource`).
//! - `GET /oauth/callback` — Logto returns here; map the opaque state back and
//!   redirect to the client's original `redirect_uri` with the code + their
//!   state. `iss` is intentionally not forwarded (it would be Logto's, not
//!   ours).
//! - `POST /token` — relay the form to Logto's `/token`, rewriting
//!   `redirect_uri` to our callback (Logto bound the code to it). PKCE verifier
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
    pending: Mutex<HashMap<String, Pending>>,
}

struct Pending {
    client_redirect_uri: String,
    client_state: Option<String>,
    created: Instant,
}

impl OAuthProxyState {
    pub fn new(logto_base: &str, resource_url: &str) -> Self {
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
    for (k, v) in &mut pairs {
        if k == "redirect_uri" {
            v.clone_from(&st.inner.callback_url);
        }
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
        );
        assert_eq!(
            st.inner.callback_url,
            "https://jmap-mcp.example.test/oauth/callback"
        );
        assert_eq!(st.inner.logto_base, "https://login.example.test/oidc");
    }

    #[test]
    fn pending_roundtrip_and_expiry_guard() {
        let st = OAuthProxyState::new("https://l.test/oidc", "https://r.test");
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
    fn random_state_is_unique_and_hex() {
        let a = random_state();
        let b = random_state();
        assert_ne!(a, b);
        assert_eq!(a.len(), 48);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
