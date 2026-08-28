//! Axum middleware: extract the `Authorization: Bearer <token>` header,
//! validate it against Logto (JWKS plus an asymmetric-algorithm allowlist),
//! and attach the resulting
//! `AuthenticatedIdentity` + raw `AccessToken` to the request extensions so
//! downstream handlers (and the rmcp tool layer) can read them.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::{debug, info, warn};

use crate::audit::{self, outcome};
use crate::config::Config;
use crate::last_used::{self, LastUsedTracker};
use crate::logto_oidc::LogtoValidationClient;
use crate::oauth_metadata::{www_authenticate_header, www_authenticate_invalid_token};

/// Which credential the caller presented, and therefore which one this server
/// is holding.
///
/// The distinction is kept explicit rather than inferred so that a validated
/// Logto token and a Stalwart app password never read as the same thing. Both
/// end up forwarded to Stalwart; only one of them was checked against Logto.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthScheme {
    /// `Authorization: Bearer <jwt>`, validated against Logto's JWKS.
    Bearer,
    /// `Authorization: Basic <base64>`, a Stalwart app password, validated by
    /// Stalwart itself. Only reachable when `allow_app_password` is on.
    Basic,
}

impl AuthScheme {
    /// The HTTP scheme token, and the only place the spelling is written.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bearer => "Bearer",
            Self::Basic => "Basic",
        }
    }
}

/// The caller's credential, stashed on request extensions by `bearer_auth` and
/// forwarded verbatim to Stalwart (pass-through model).
///
/// The scheme travels with the secret on purpose. Every outbound JMAP request
/// builds its `Authorization` header from [`AccessToken::header_value`], so no
/// call site can pick a scheme, and adding a second credential type cannot
/// silently send it under the first one's scheme.
#[derive(Clone)]
pub struct AccessToken {
    scheme: AuthScheme,
    secret: String,
}

impl AccessToken {
    /// A Logto JWT that has already been validated.
    #[must_use]
    pub const fn bearer(secret: String) -> Self {
        Self {
            scheme: AuthScheme::Bearer,
            secret,
        }
    }

    /// A Stalwart app password, base64 as the client sent it, that Stalwart has
    /// already accepted.
    #[must_use]
    pub const fn basic(secret: String) -> Self {
        Self {
            scheme: AuthScheme::Basic,
            secret,
        }
    }

    #[must_use]
    pub const fn scheme(&self) -> AuthScheme {
        self.scheme
    }

    /// The secret alone. For hashing and for Logto cache keys, never for a
    /// header: use [`Self::header_value`] so the scheme cannot be dropped.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The complete `Authorization` header value.
    #[must_use]
    pub fn header_value(&self) -> String {
        format!("{} {}", self.scheme.as_str(), self.secret)
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("scheme", &self.scheme)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// State the auth middleware needs. Cheap to clone (inner `Arc`s).
#[derive(Clone)]
pub struct AuthState {
    pub config: Config,
    pub logto: LogtoValidationClient,
    pub last_used: Arc<LastUsedTracker>,
    /// Used only to validate a Stalwart app password, by asking Stalwart. The
    /// JWT path never touches it.
    pub jmap: crate::jmap_client::JmapClient,
}

/// Middleware plugged in via `axum::middleware::from_fn_with_state`.
pub async fn bearer_auth(
    State(state): State<AuthState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let presented = extract_credential(
        request.headers().get(header::AUTHORIZATION),
        state.config.allow_app_password,
    );
    let Some(presented) = presented else {
        // No credential offered — a bare challenge, no `error` (RFC 6750 §3:
        // `error` is only for requests that actually presented one).
        return unauthorized(&www_authenticate_header(&state.config.resource_url));
    };

    let token = match presented {
        Presented::Jwt(t) => t,
        Presented::AppPassword(secret) => {
            return app_password_auth(state, request, next, secret).await;
        }
    };

    let started = std::time::Instant::now();
    let token_hash = audit::token_hash(&token);
    // Don't overwrite last_used when the request is `/token/introspect` —
    // that endpoint's job is to report the LAST real use; recording here
    // would hide the prior (possibly attacker-driven) use being audited.
    let is_introspect_path = request.uri().path() == "/token/introspect";
    match state.logto.validate_token(&token).await {
        Ok(Some(identity)) => {
            debug!(user_id = %identity.user_id, scheme = "Bearer", "authenticated request");
            audit::introspect(
                &token_hash,
                outcome::ACTIVE,
                started,
                identity.email.as_deref(),
            );
            if !is_introspect_path {
                record_ingress(&state, &request, &token_hash);
            }
            // The rmcp streamable-http tower layer copies the request `Parts`
            // (including these extensions) into the tool handler's
            // `RequestContext.extensions`.
            request.extensions_mut().insert(identity);
            request.extensions_mut().insert(AccessToken::bearer(token));
            next.run(request).await
        }
        Ok(None) => {
            debug!("token rejected by Logto validation");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            // A token WAS presented and refused — say so, so the client
            // re-runs OAuth instead of showing a wedged connector.
            unauthorized(&www_authenticate_invalid_token(&state.config.resource_url))
        }
        Err(e) => {
            warn!(error = %e, "Logto JWKS validation failure");
            audit::introspect(&token_hash, outcome::ERROR, started, None);
            internal_error()
        }
    }
}

/// Record the client address and log the ingress chain length.
///
/// One implementation for both credential paths: a second copy is how the two
/// drift into recording different things, and the chain length is a property of
/// the deployment rather than of which credential was presented.
fn record_ingress(state: &AuthState, request: &Request<Body>, token_hash: &str) {
    let xff_raw = request.headers().get("x-forwarded-for");
    let xff = xff_raw.and_then(|v| v.to_str().ok());
    // Count only, never the entries: they are sender-influenced and identify
    // people. The count is what `trusted_proxy_hops` must agree with, and
    // nothing else reports the chain length the pod actually sees.
    info!(
        xff_entries = last_used::xff_entry_count(xff_raw.map(axum::http::HeaderValue::as_bytes)),
        trusted_proxy_hops = state.config.trusted_proxy_hops,
        "ingress chain length"
    );
    let client_ip = last_used::parse_client_ip(xff, state.config.trusted_proxy_hops);
    state.last_used.record(token_hash, client_ip);
}

/// The `Basic` path: a Stalwart app password, validated by Stalwart.
///
/// Acceptance is the backend's answer, never a shape check. A credential is
/// good only if Stalwart returns a session that **belongs to somebody**; see
/// [`crate::jmap_client::JmapSession::is_authenticated`], because a 200 alone
/// is what Stalwart returns for a request carrying no credential at all.
///
/// No fallback runs from here. A refused app password is a 401, not a retry
/// against Logto, so the two validators never both get a turn at one request.
async fn app_password_auth(
    state: AuthState,
    mut request: Request<Body>,
    next: Next,
    secret: String,
) -> Response {
    let started = std::time::Instant::now();
    let token = AccessToken::basic(secret);
    let token_hash = audit::token_hash(token.secret());
    let is_introspect_path = request.uri().path() == "/token/introspect";

    match state.jmap.session_for(&token.header_value()).await {
        Ok(session) if session.is_authenticated() => {
            let email = session.username.clone();
            debug!(scheme = "Basic", "authenticated request");
            audit::introspect(&token_hash, outcome::ACTIVE, started, email.as_deref());
            if !is_introspect_path {
                record_ingress(&state, &request, &token_hash);
            }
            // No `exp`: an app password does not expire on its own, which is
            // exactly why it is a wider credential than the JWT and why the
            // deployment has to opt in.
            let identity = crate::logto_oidc::AuthenticatedIdentity {
                user_id: email.clone().unwrap_or_default(),
                email,
                name: None,
                exp: None,
            };
            request.extensions_mut().insert(identity);
            request.extensions_mut().insert(token);
            next.run(request).await
        }
        Ok(_) => {
            // 200 from Stalwart with nobody attached. Reachable if the
            // credential were ever dropped before the request went out.
            warn!("Stalwart returned an unauthenticated session for a presented app password");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            unauthorized(&www_authenticate_invalid_token(&state.config.resource_url))
        }
        Err(crate::jmap_client::JmapError::Unauthorized) => {
            debug!("app password refused by Stalwart");
            audit::introspect(&token_hash, outcome::INACTIVE, started, None);
            unauthorized(&www_authenticate_invalid_token(&state.config.resource_url))
        }
        Err(e) => {
            warn!(error = %e, "Stalwart unreachable while validating an app password");
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

/// Extract a Stalwart app password from `Authorization: Basic <base64>`.
///
/// Deliberately a separate function from [`extract_bearer`] rather than a
/// fallback inside it. The scheme the caller chose decides which validator
/// runs, so a garbage `Bearer` takes exactly the path it took before this
/// existed and cannot reach Stalwart by failing the JWT check first.
///
/// The base64 is not decoded here: it is forwarded to Stalwart verbatim, and
/// decoding it would put a password in a local variable for no purpose. Only
/// the shape is checked.
fn extract_basic(header: Option<&HeaderValue>) -> Option<String> {
    let raw = header?.to_str().ok()?.trim();
    let (scheme, value) = raw.split_once(' ')?;
    if scheme.as_bytes().ct_eq(b"Basic").unwrap_u8() != 1 {
        return None;
    }
    let secret = value.trim();
    if secret.is_empty() {
        return None;
    }
    Some(secret.to_owned())
}

/// What the caller presented, before anything has validated it.
enum Presented {
    /// To be checked against Logto.
    Jwt(String),
    /// To be checked against Stalwart. Only produced when the deployment has
    /// opted in.
    AppPassword(String),
}

fn extract_credential(header: Option<&HeaderValue>, allow_app_password: bool) -> Option<Presented> {
    if let Some(t) = extract_bearer(header) {
        return Some(Presented::Jwt(t));
    }
    if allow_app_password && let Some(b) = extract_basic(header) {
        return Some(Presented::AppPassword(b));
    }
    None
}

fn unauthorized(challenge: &str) -> Response {
    let value =
        HeaderValue::from_str(challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
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

    /// The `Bearer` path never accepts `Basic`, and that stayed true when the
    /// app-password path was added. Kept rather than deleted: the contract it
    /// records did not change, only what happens to a `Basic` header elsewhere.
    #[test]
    fn rejects_basic_scheme() {
        assert!(extract_bearer(Some(&HeaderValue::from_static("Basic dXNlcjpwYXNz"))).is_none());
    }

    #[test]
    fn basic_is_ignored_unless_the_deployment_opted_in() {
        let h = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        assert!(
            extract_credential(Some(&h), false).is_none(),
            "app passwords must not be reachable with the flag off"
        );
        assert!(matches!(
            extract_credential(Some(&h), true),
            Some(Presented::AppPassword(_))
        ));
    }

    /// The property that says this did not become a hole: a bearer the JWT
    /// validator will reject is still routed to the JWT validator, with the
    /// app-password path enabled. It never falls through to Stalwart.
    #[test]
    fn a_garbage_bearer_still_goes_to_the_jwt_path() {
        let h = HeaderValue::from_static("Bearer not-a-jwt");
        for allow in [false, true] {
            assert!(
                matches!(extract_credential(Some(&h), allow), Some(Presented::Jwt(_))),
                "allow_app_password={allow} must not change where a bearer goes"
            );
        }
    }

    #[test]
    fn empty_basic_credential_is_not_a_credential() {
        assert!(extract_basic(Some(&HeaderValue::from_static("Basic   "))).is_none());
        assert!(extract_credential(Some(&HeaderValue::from_static("Basic ")), true).is_none());
    }

    #[test]
    fn scheme_travels_with_the_secret() {
        assert_eq!(AccessToken::bearer("t".into()).header_value(), "Bearer t");
        assert_eq!(AccessToken::basic("t".into()).header_value(), "Basic t");
        // The secret alone is what gets hashed, so the two paths key the same
        // way into `last_used` and the rate limiter.
        assert_eq!(AccessToken::basic("t".into()).secret(), "t");
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
        let r = unauthorized(&www_authenticate_header("https://jmap-mcp.example.test"));
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        assert!(h.to_str().unwrap().contains("resource_metadata="));
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }

    /// No credential offered → bare challenge, no `error` (RFC 6750 §3).
    #[tokio::test]
    async fn missing_token_challenge_has_no_error_param() {
        let r = unauthorized(&www_authenticate_header("https://jmap-mcp.example.test"));
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        assert!(!h.to_str().unwrap().contains("error="));
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }

    /// A rejected credential → `error="invalid_token"`, which is what makes
    /// strict clients re-run OAuth rather than wedge.
    #[tokio::test]
    async fn rejected_token_challenge_signals_invalid_token() {
        let r = unauthorized(&www_authenticate_invalid_token(
            "https://jmap-mcp.example.test",
        ));
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let h = r.headers().get(header::WWW_AUTHENTICATE).unwrap();
        let v = h.to_str().unwrap();
        assert!(v.contains(r#"error="invalid_token""#));
        // The contracted resource-metadata URL is unchanged by the addition.
        assert!(v.contains(
            r#"resource_metadata="https://jmap-mcp.example.test/.well-known/oauth-protected-resource/mcp""#
        ));
        let _ = to_bytes(r.into_body(), 1024).await.unwrap();
    }
}
