//! `jmap-mcp` — Remote MCP server exposing a Stalwart JMAP mailbox to
//! claude.ai. Ported from `matrix-mcp`.
//!
//! Inbound requests are authenticated against Logto (JWKS + RS256); the
//! validated bearer is forwarded verbatim to Stalwart on every JMAP call.
//! Stateless: no per-user store, no E2EE, no PVC.

mod audit;
mod audit_mailbox;
mod auth;
mod config;
mod content_sandbox;
mod jmap_client;
mod last_used;
mod logto_oidc;
mod mcp;
mod metrics;
mod oauth_metadata;
mod rate_limit;
mod session;
mod telemetry;
mod token_introspect;
mod url_safety;

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{AccessToken, AuthState, bearer_auth};
use crate::config::Config;
use crate::jmap_client::JmapClient;
use crate::logto_oidc::LogtoValidationClient;
use crate::mcp::JmapMcpService;
use crate::oauth_metadata::protected_resource_metadata;
use crate::rate_limit::{InitializeLimiter, Limiter, MAX_INITIALIZES_PER_IDENTITY};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    metrics::init();
    let cfg = Config::from_env()?;
    let bind_addr = cfg.bind_addr;
    let metrics_bind_addr = cfg.metrics_bind_addr;
    let app = build_app(cfg)?;

    let listener = TcpListener::bind(bind_addr).await?;
    info!(%bind_addr, "jmap-mcp listening (public)");

    let metrics_listener = TcpListener::bind(metrics_bind_addr).await?;
    info!(%metrics_bind_addr, "jmap-mcp metrics listening (internal)");
    let metrics_app = Router::new().route("/metrics", get(metrics::metrics_handler));

    tokio::select! {
        result = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()) => { result?; }
        result = axum::serve(metrics_listener, metrics_app)
            .with_graceful_shutdown(shutdown_signal()) => { result?; }
        () = shutdown_signal() => {}
    }
    Ok(())
}

fn build_app(cfg: Config) -> Result<Router> {
    let logto = LogtoValidationClient::new(&cfg.authorization_server, cfg.resource_url.clone())?;
    let jmap = JmapClient::new(
        &cfg.stalwart_jmap_base_url,
        cfg.stalwart_connect_ip.as_deref(),
    )?;
    let auth_state = AuthState {
        config: cfg.clone(),
        logto: logto.clone(),
        last_used: last_used::LastUsedTracker::new(),
    };
    let limiter = Arc::new(
        Limiter::new(cfg.rate_limit_reads_per_min, cfg.rate_limit_writes_per_min)
            .ok_or_else(|| anyhow::anyhow!("rate-limit quotas must be > 0"))?,
    );
    let download_max_bytes = cfg.download_max_bytes;
    let upload_max_bytes = cfg.upload_max_bytes;
    Ok(build_router(
        cfg,
        auth_state,
        jmap,
        logto,
        limiter,
        download_max_bytes,
        upload_max_bytes,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_router(
    cfg: Config,
    auth_state: AuthState,
    jmap: JmapClient,
    logto: LogtoValidationClient,
    limiter: Arc<Limiter>,
    download_max_bytes: u64,
    upload_max_bytes: usize,
) -> Router {
    let resource_host = parse_host(&cfg.resource_url);
    let mut allowed_hosts: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Some(h) = resource_host {
        allowed_hosts.push(h);
    }
    let audit_registry = audit_mailbox::AuditMailboxRegistry::new();
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(JmapMcpService::new(
                jmap.clone(),
                logto.clone(),
                Arc::clone(&limiter),
                download_max_bytes,
                upload_max_bytes,
                audit_registry.clone(),
            ))
        },
        Arc::new(session::CappedSessionManager::new()),
        StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts),
    );

    let initialize_limiter = Arc::new(InitializeLimiter::new(
        session::SESSION_KEEP_ALIVE,
        MAX_INITIALIZES_PER_IDENTITY,
    ));

    let mcp_routes = Router::new()
        .nest_service("/mcp", mcp_service)
        .route("/token/introspect", get(token_introspect::handler))
        .layer(middleware::from_fn_with_state(
            initialize_limiter,
            initialize_rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            auth_state.clone(),
            bearer_auth,
        ))
        .with_state(auth_state);

    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .merge(mcp_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(cfg)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Rejects fresh MCP session creation when the caller's per-identity
/// initialize bucket is exhausted. Only fires on POSTs to /mcp without an
/// `mcp-session-id` header (the rmcp `initialize` call).
async fn initialize_rate_limit(
    State(limiter): State<Arc<InitializeLimiter>>,
    request: Request<Body>,
    next: Next,
) -> axum::response::Response {
    if !is_fresh_mcp_session_request(&request) {
        return next.run(request).await;
    }
    let Some(token) = request.extensions().get::<AccessToken>() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing token extension\n",
        )
            .into_response();
    };
    let Some(identity) = request
        .extensions()
        .get::<crate::logto_oidc::AuthenticatedIdentity>()
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "authenticated request missing identity extension\n",
        )
            .into_response();
    };
    let bearer_hash = crate::audit::token_hash(&token.0);
    if limiter
        .check(&bearer_hash, Some(identity.user_id.as_str()))
        .is_err()
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "too many MCP initialize requests; try again later\n",
        )
            .into_response();
    }
    next.run(request).await
}

fn is_fresh_mcp_session_request(request: &Request<Body>) -> bool {
    request.method() == Method::POST && request.headers().get("mcp-session-id").is_none()
}

/// Best-effort `https://host:port/path` → `host[:port]` extraction.
fn parse_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_owned())
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("jmap_mcp=info,tower_http=info,axum=info,info"));
    let otel_layer = telemetry::try_build_otel_layer();
    let json_layer = std::env::var("JMAP_MCP_LOG_FORMAT").as_deref() == Ok("json");
    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(otel_layer);
    if json_layer {
        registry.with(fmt::layer().json()).init();
    } else {
        registry.with(fmt::layer().compact()).init();
    }
}

#[allow(clippy::expect_used)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler at startup");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler at startup");
    tokio::select! {
        _ = sigterm.recv() => info!("received SIGTERM"),
        _ = sigint.recv() => info!("received SIGINT"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

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

    fn router(cfg: Config) -> Router {
        let logto = LogtoValidationClient::new(&cfg.authorization_server, cfg.resource_url.clone())
            .unwrap();
        let jmap = JmapClient::new(&cfg.stalwart_jmap_base_url, None).unwrap();
        let auth_state = AuthState {
            config: cfg.clone(),
            logto: logto.clone(),
            last_used: crate::last_used::LastUsedTracker::new(),
        };
        let limiter = Arc::new(crate::rate_limit::Limiter::new(100_000, 100_000).unwrap());
        build_router(
            cfg,
            auth_state,
            jmap,
            logto,
            limiter,
            5 * 1024 * 1024,
            10 * 1024 * 1024,
        )
    }

    #[tokio::test]
    async fn health_is_public() {
        let app = router(test_config());
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mcp_without_token_returns_401() {
        let app = router(test_config());
        let r = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let www = r
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www.contains("resource_metadata="));
    }

    #[tokio::test]
    async fn metadata_endpoint_is_public() {
        let app = router(test_config());
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
}
