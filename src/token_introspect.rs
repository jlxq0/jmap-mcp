//! `GET /token/introspect` — audit endpoint for the calling bearer.
//!
//! Returns envelope state for the bearer that authenticated the request:
//! the identity Logto reports, its expiry, and jmap-mcp's own last-used
//! record (timestamp + client IP from `X-Forwarded-For`). Lets the bearer's
//! owner spot a surprise IP — a strong "someone else is riding my bearer"
//! signal — without scraping operator logs.
//!
//! Protected by [`crate::auth::bearer_auth`]; returns only the caller's own
//! envelope data (no cross-tenant visibility).

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::audit;
use crate::auth::{AccessToken, AuthState};
use crate::last_used::LastUsedRecord;
use crate::logto_oidc::AuthenticatedIdentity;

#[derive(Debug, Serialize)]
pub struct TokenIntrospectResponse {
    /// Stable Logto user id (`sub`) for this bearer.
    pub user_id: String,
    /// Email Logto reports for this bearer, when the token carries it.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Token expiry (Unix epoch seconds).
    pub exp: Option<i64>,
    /// Short `sha256(bearer)[..8]` hex — the same id the operator-side audit
    /// log uses, so the user can cross-reference without exposing the bearer.
    pub token_hash: String,
    /// Most recent activity for this bearer.
    pub last_used: Option<LastUsedRecord>,
}

#[allow(clippy::unused_async)] // axum handlers must be async
pub async fn handler(State(state): State<AuthState>, request: Request) -> Response {
    let Some(identity) = request.extensions().get::<AuthenticatedIdentity>().cloned() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth middleware did not populate identity\n",
        )
            .into_response();
    };
    let Some(token) = request.extensions().get::<AccessToken>().cloned() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth middleware did not populate access token\n",
        )
            .into_response();
    };
    let token_hash = audit::token_hash(&token.0);
    let last_used = state.last_used.get(&token_hash);
    Json(TokenIntrospectResponse {
        user_id: identity.user_id,
        email: identity.email,
        name: identity.name,
        exp: identity.exp,
        token_hash,
        last_used,
    })
    .into_response()
}
