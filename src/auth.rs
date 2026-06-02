//! Axum middleware: extract the `Authorization: Bearer <token>` header,
//! validate it against Logto (JWKS + RS256), and attach the resulting
//! `AuthenticatedIdentity` + raw `AccessToken` to the request extensions so
//! downstream handlers (and the rmcp tool layer) can read them.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::audit::{self, outcome};
use crate::config::Config;
use crate::last_used::{self, LastUsedTracker};
use crate::logto_oidc::LogtoValidationClient;
use crate::oauth_metadata::www_authenticate_header;

/// Newtype around the raw OAuth access token, stashed on request extensions
/// by `bearer_auth`. The Logto JWT doubles as the JMAP credential: tools
/// forward it verbatim to Stalwart (pass-through model). Wrapping it in a
/// dedicated type avoids collisions with other `String` extensions.
#[derive(Clone)]
pub struct AccessToken(pub String);

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AccessToken").field(&"<redacted>").finish()
    }
}

/// State the auth middleware needs. Cheap to clone (inner `Arc`s).
#[derive(Clone)]
pub struct AuthState {
    pub config: Config,
    pub logto: LogtoValidationClient,
    pub last_used: Arc<LastUsedTracker>,
}

/// Middleware plugged in via `axum::middleware::from_fn_with_state`.
pub async fn bearer_auth(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let Some(token) = extract_bearer(request.headers().get(header::AUTHORIZATION)) else {
        return unauthorized(&state.config.resource_url);
    };

    let started = std::time::Instant::now();
    let token_hash = audit::token_hash(&token);
    // Don't overwrite last_used when the request is `/token/introspect` —
    // that endpoint's job is to report the LAST real use; recording here
    // would hide the prior (possibly attacker-driven) use being audited.
    let is_introspect_path = request.uri().path() == "/token/introspect";
    match state.logto.validate_token(&token).await {
        Ok(Some(identity)) => {
            debug!(user_id = %identity.user_id, "authenticated request");
            audit::introspect(
                &token_hash,
                outcome::ACTIVE,
                started,
                identity.email.as_deref(),
            );
            if !is_introspect_path {
                let client_ip = last_used::parse_client_ip(
                    request
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok()),
                    state.config.trusted_proxy_hops,
                );
                state.last_used.record(&token_hash, client_ip);
            }
            // The rmcp streamable-http tower layer copies the request `Parts`
            // (including these extensions) into the tool handler's
            // `RequestContext.extensions`.
            request.extensions_mut().insert(identity);
            request.extensions_mut().insert(AccessToken(token));
            next.run(request).await
        }
        Ok(None) => {
            debug!("token rejected by Logto validation");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            unauthorized(&state.config.resource_url)
        }
        Err(e) => {
            warn!(error = %e, "Logto JWKS validation failure");
            audit::introspect(&token_hash, outcome::ERROR, started, None);
            internal_error()
        }
    }
}

/// Extract the bearer token from an `Authorization` header. Constant-time
/// scheme check; ASCII only; case-sensitive `Bearer` per RFC 6750.
fn extract_bearer(header: Option<&HeaderValue>) -> Option<String> {
    let raw = header?.to_str().ok()?;
    let raw = raw.trim();
    let (scheme, value) = raw.split_once(' ')?;
    if scheme.as_bytes().ct_eq(b"Bearer").unwrap_u8() != 1 {
        return None;
    }
    let token = value.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

fn unauthorized(resource_url: &str) -> Response {
    let header_value = www_authenticate_header(resource_url);
    let value =
        HeaderValue::from_str(&header_value).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, value);
    response
}

fn internal_error() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "token validation upstream error\n",
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn extracts_well_formed_bearer() {
        let h = HeaderValue::from_static("Bearer abc.def.ghi");
        assert_eq!(extract_bearer(Some(&h)).as_deref(), Some("abc.def.ghi"));
    }

    #[test]
    fn rejects_lowercase_scheme() {
        assert!(extract_bearer(Some(&HeaderValue::from_static("bearer abc"))).is_none());
    }

    #[test]
    fn rejects_basic_scheme() {
        assert!(extract_bearer(Some(&HeaderValue::from_static("Basic dXNlcjpwYXNz"))).is_none());
    }

    #[test]
    fn rejects_empty_token() {
        assert!(extract_bearer(Some(&HeaderValue::from_static("Bearer "))).is_none());
    }

    #[test]
    fn trims_whitespace_around_token() {
        let h = HeaderValue::from_static("Bearer   xyz   ");
        assert_eq!(extract_bearer(Some(&h)).as_deref(), Some("xyz"));
    }

    #[tokio::test]
    async fn unauthorized_has_www_authenticate() {
        let r = unauthorized("https://jmap-mcp.example.test");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        assert!(h.to_str().unwrap().contains("resource_metadata="));
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }
}
