//! `jmap-mcp` — Remote MCP server exposing a Stalwart JMAP mailbox to
//! claude.ai. Ported from `matrix-mcp`.
//!
//! Inbound requests are authenticated against Logto (JWKS plus an allowlist
//! of asymmetric signing algorithms); the
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
mod oauth_proxy;
mod oauth_redirect;
mod rate_limit;
mod session;
mod telemetry;
mod token_introspect;
mod url_safety;

use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::auth::{AccessToken, AuthState, bearer_auth};
use crate::config::Config;
use crate::jmap_client::JmapClient;
use crate::logto_oidc::LogtoValidationClient;
use crate::mcp::JmapMcpService;
use crate::oauth_metadata::{authorization_server_metadata, protected_resource_metadata, register};
use crate::rate_limit::{InitializeLimiter, Limiter, MAX_INITIALIZES_PER_IDENTITY};

/// MCP JSON-RPC requests are small; cap the transport body before rmcp
/// collects it into memory. Four MiB leaves ample room for batched tool
/// arguments while preventing a valid bearer from exhausting the process.
const MCP_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

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
        jmap: jmap.clone(),
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
    // A declared From address that names no owner is granted to nobody. Say so
    // at `warn`: prod runs at `info`, and a grant that silently stopped
    // applying is exactly the kind of degradation this repository has been
    // caught by before.
    for addr in &cfg.unowned_from_addresses {
        tracing::warn!(
            address = %addr,
            "JMAP_MCP_EXTRA_FROM_ADDRESSES entry names no owner and is granted to nobody; \
             write it as owner@domain=address@domain"
        );
    }
    let extra_from_addresses = Arc::new(cfg.extra_from_addresses.clone());
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(JmapMcpService::new(
                jmap.clone(),
                logto.clone(),
                Arc::clone(&limiter),
                download_max_bytes,
                upload_max_bytes,
                audit_registry.clone(),
                Arc::clone(&extra_from_addresses),
            ))
        },
        Arc::new(session::CappedSessionManager::new()),
        StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts),
    );

    let initialize_limiter = Arc::new(InitializeLimiter::new(
        crate::rate_limit::INITIALIZE_REFILL_INTERVAL,
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
        .layer(RequestBodyLimitLayer::new(MCP_MAX_REQUEST_BYTES))
        .with_state(auth_state);

    Router::new()
        .route("/health", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        // RFC 9728 §3.1 path-aware variant. Clients that canonicalise this
        // server as `<origin>/mcp` probe `/.well-known/oauth-protected-resource/mcp`
        // FIRST; without this route they hit the catch-all 401 and can never
        // show a connect card. Serves the same document as the origin well-known
        // (`resource` = `<origin>/mcp`; JWT audience stays the origin).
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        // Authorization-server metadata (RFC 8414) + DCR shim (RFC 7591) that
        // front Logto so claude.ai's connector can self-register. Public — the
        // OAuth dance happens before any bearer exists.
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route("/register", post(register))
        // Transparent OAuth proxy: authorize/token must be same-origin as the
        // issuer for claude.ai to redirect. These broker to Logto. Public.
        .merge(
            Router::new()
                .route("/authorize", get(oauth_proxy::authorize))
                .route("/oauth/callback", get(oauth_proxy::callback))
                .route("/token", post(oauth_proxy::token))
                .with_state(oauth_proxy::OAuthProxyState::new(
                    &cfg.authorization_server,
                    &cfg.resource_url,
                    cfg.oauth_redirect_uris.clone(),
                )),
        )
        .merge(mcp_routes)
        .layer(TraceLayer::new_for_http())
        .with_state(cfg)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
    }))
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
    let bearer_hash = crate::audit::token_hash(token.secret());
    if limiter
        .check(&bearer_hash, Some(identity.user_id.as_str()))
        .is_err()
    {
        return initialize_rate_limited();
    }
    next.run(request).await
}

/// 429 for a throttled `initialize`.
///
/// Shaped as a JSON-RPC error rather than bare text: the client posted a
/// JSON-RPC `initialize`, and one that cannot parse the response has no way
/// to distinguish throttling from a broken server — it reports a dead
/// connector. `Retry-After` (seconds, per the bucket's refill rate) tells a
/// well-behaved client exactly how long to wait. `id` is null because the
/// body is not parsed at this layer (JSON-RPC 2.0 §5 allows null when the id
/// cannot be determined).
fn initialize_rate_limited() -> axum::response::Response {
    let retry_after = crate::rate_limit::INITIALIZE_REFILL_INTERVAL.as_secs();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": {
            "code": crate::audit::RATE_LIMITED_CODE,
            "message": format!(
                "Too many MCP session initializations for this identity. \
                 Retry in {retry_after}s; reuse the existing session where possible."
            ),
        },
    });
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (axum::http::header::RETRY_AFTER, retry_after.to_string()),
            (
                axum::http::header::CONTENT_TYPE,
                "application/json".to_owned(),
            ),
        ],
        axum::Json(body),
    )
        .into_response()
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

    use base64::Engine as _;

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
            jmap: jmap.clone(),
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
        assert_eq!(
            r.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(r.into_body(), usize::MAX)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["status"], "healthy");
        assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
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
        assert!(www.contains("oauth-protected-resource/mcp"));
    }

    #[tokio::test]
    async fn oversized_mcp_body_is_rejected_before_collection() {
        let app = router(test_config());
        let r = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::CONTENT_LENGTH, MCP_MAX_REQUEST_BYTES + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// A throttled initialize must be machine-readable: JSON-RPC body so the
    /// client can tell throttling from a broken server, and `Retry-After` so
    /// it backs off instead of hammering or declaring the connector dead.
    #[tokio::test]
    async fn initialize_429_is_json_rpc_with_retry_after() {
        let r = initialize_rate_limited();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);

        let retry_after = r
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .expect("Retry-After present")
            .to_str()
            .unwrap()
            .parse::<u64>()
            .expect("Retry-After is an integer number of seconds");
        assert_eq!(
            retry_after,
            crate::rate_limit::INITIALIZE_REFILL_INTERVAL.as_secs()
        );

        let bytes = axum::body::to_bytes(r.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON-RPC body");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], crate::audit::RATE_LIMITED_CODE);
    }

    /// The initialize bucket must absorb an ordinary reconnect storm. Cursor
    /// alone opens two sessions per connect, so a handful of connects cannot
    /// be allowed to lock the identity out of its first tool call.
    #[test]
    fn initialize_burst_absorbs_repeated_reconnects() {
        let limiter = crate::rate_limit::InitializeLimiter::new(
            crate::rate_limit::INITIALIZE_REFILL_INTERVAL,
            MAX_INITIALIZES_PER_IDENTITY,
        );
        // Ten back-to-back connects at two sessions each: all must pass.
        for i in 0..20 {
            assert!(
                limiter.check("bearer-hash", Some("user-sub")).is_ok(),
                "initialize {i} should not be throttled"
            );
        }
    }

    // ----- handler harness -----
    //
    // Drives a real `tools/call` through the router so an assertion can be made
    // on **what the caller receives**. A `?` discarded at a call site is
    // invisible to a unit test on either function and visible to a request that
    // gets a result where it should get an error, which is the whole of #31.
    //
    // Auth is a Stalwart app password against a mock backend. That is only
    // possible because of #25: before the Basic path an authenticated handler
    // test needed a Logto-signed JWT, so it meant mocking the JWKS, generating
    // a key and signing a token. The widening we were careful about is what
    // made the untested error path testable, and nobody planned that.

    /// A JMAP mock that answers every method this server asks for in one
    /// response. Each caller filters `methodResponses` by name, so one body
    /// satisfies `Mailbox/get`, `Identity/get`, `Email/get` and the two `set`s
    /// regardless of which was requested.
    async fn mock_jmap(html_body: Option<&str>) -> wiremock::MockServer {
        use wiremock::matchers::{method as wm, path as wp};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let mut body_values = serde_json::json!({ "b": { "value": "plain text" } });
        let mut email = serde_json::json!({
            "id": "email-1",
            "from": [{ "email": "someone@example.test" }],
            "to": [{ "email": "lucy@lindner.earth" }],
            "subject": "hello",
            "textBody": [{ "partId": "b", "type": "text/plain" }],
            "attachments": []
        });
        if let Some(html) = html_body {
            body_values["h"] = serde_json::json!({ "value": html });
            email["htmlBody"] = serde_json::json!([{ "partId": "h", "type": "text/html" }]);
        }
        email["bodyValues"] = body_values;

        Mock::given(wm("GET"))
            .and(wp("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "apiUrl": format!("{}/jmap/", server.uri()),
                "downloadUrl": "d", "uploadUrl": "u",
                "username": "lucy@lindner.earth",
                "primaryAccounts": { "urn:ietf:params:jmap:mail": "acct-1" }
            })))
            .mount(&server)
            .await;
        Mock::given(wm("POST"))
            .and(wp("/jmap/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "methodResponses": [
                    ["Mailbox/get", { "list": [
                        { "id": "mb-drafts", "role": "drafts", "name": "Drafts" },
                        { "id": "mb-sent", "role": "sent", "name": "Sent" }
                    ] }, "m"],
                    ["Identity/get", { "list": [
                        { "id": "id-1", "email": "lucy@lindner.earth", "name": "Lucy" }
                    ] }, "i"],
                    ["Email/get", { "list": [email] }, "g"],
                    ["Email/set", { "created": { "d": { "id": "email-new" } } }, "s"],
                    ["EmailSubmission/set", { "created": { "sub": { "id": "sub-1" } } }, "e"]
                ]
            })))
            .mount(&server)
            .await;
        server
    }

    fn harness_config(stalwart_uri: &str) -> Config {
        let mut cfg = Config::new(
            "https://jmap-mcp.example.test",
            "https://login.example.test/oidc",
            stalwart_uri,
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap();
        cfg.allow_app_password = true;
        cfg
    }

    fn mcp_request(basic: &str, session: Option<&str>, body: String) -> Request<Body> {
        let mut rb = Request::builder()
            .method("POST")
            .uri("/mcp")
            // `Request::builder()` sets no Host on a relative URI, and without
            // one every call is `400 Bad Request: missing Host header`.
            .header(header::HOST, "jmap-mcp.example.test")
            .header(header::AUTHORIZATION, basic)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(sid) = session {
            rb = rb.header("mcp-session-id", sid);
        }
        rb.body(Body::from(body)).unwrap()
    }

    #[allow(clippy::panic)] // a harness fault, and the frame is the diagnosis
    fn panic_on_empty(text: &str) -> &'static str {
        panic!("no JSON-RPC payload in the SSE frame: {text}")
    }

    /// The JSON-RPC payload out of the `text/event-stream` frame.
    async fn sse_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 512 * 1024)
            .await
            .expect("body");
        let text = String::from_utf8_lossy(&bytes);
        let data = text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .find(|d| !d.trim().is_empty())
            .unwrap_or_else(|| {
                // An empty SSE frame here means the tool never answered, which
                // is a harness fault rather than a result worth asserting on.
                panic_on_empty(&text)
            });
        serde_json::from_str(data).expect("JSON-RPC in the SSE frame")
    }

    /// `initialize`, then one `tools/call`, returning the JSON-RPC response.
    ///
    /// **The router is cloned, never rebuilt.** A fresh `router(cfg)` is
    /// identical in construction and shares no session manager, so the id
    /// `initialize` returns is meaningless to it and the second call answers
    /// `404 Session not found` — which reads as a session bug rather than as
    /// two routers. `Router` being `Clone` is what makes the wrong version look
    /// correct, because rebuilding is what a careful person does to avoid
    /// shared state.
    async fn call_tool(cfg: Config, tool: &str, args: serde_json::Value) -> serde_json::Value {
        let basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("lucy@lindner.earth:app-password")
        );
        let app = router(cfg);

        let init = app
            .clone()
            .oneshot(mcp_request(
                &basic,
                None,
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"harness","version":"1"}}}"#.to_owned(),
            ))
            .await
            .unwrap();
        assert_eq!(init.status(), StatusCode::OK, "initialize must succeed");
        let sid = init
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .expect("initialize returns a session id")
            .to_owned();

        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": tool, "arguments": args }
        })
        .to_string();
        let resp = app
            .clone()
            .oneshot(mcp_request(&basic, Some(&sid), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "tools/call transport");
        sse_json(resp).await
    }

    /// #31: the handler must not discard `build_email_object`'s error.
    ///
    /// Unit tests on `build_email_object` and on the guard both passed while
    /// the handler's `?` was replaced with `unwrap_or_else`, because neither
    /// reaches the call site. This asserts on what the caller receives.
    #[tokio::test]
    async fn send_email_with_html_and_empty_text_is_an_error_to_the_caller() {
        let stalwart = mock_jmap(None).await;
        let out = call_tool(
            harness_config(&stalwart.uri()),
            "send_email",
            serde_json::json!({
                "from": "lucy@lindner.earth",
                "to": ["julian@lindner.earth"],
                "subject": "Briefing",
                "body_text": "   ",
                "body_html": "<h1>Briefing</h1>"
            }),
        )
        .await;

        let is_error = out["result"]["isError"].as_bool();
        let rpc_error = out.get("error").is_some();
        assert!(
            is_error == Some(true) || rpc_error,
            "the caller must be told this was refused, got: {out}"
        );
        let rendered = out.to_string();
        assert!(
            rendered.contains("body_html requires a non-empty body_text"),
            "and told why, got: {rendered}"
        );
    }

    /// #33's reds-nothing: `body_html: None` in the handler's result.
    ///
    /// Three tests on `extract_html_body` and `read_email_html_body` passed
    /// with the handler hard-coding `body_html: None`, because none of them
    /// reached the assembly of `ReadEmailResult`.
    #[tokio::test]
    async fn read_email_returns_the_html_the_backend_served() {
        let html = "<div style=\"color:#0a0\">briefing</div>";
        let stalwart = mock_jmap(Some(html)).await;
        let out = call_tool(
            harness_config(&stalwart.uri()),
            "read_email",
            serde_json::json!({ "email_id": "email-1" }),
        )
        .await;

        assert_eq!(
            out["result"]["isError"].as_bool(),
            Some(false),
            "got: {out}"
        );
        assert_eq!(
            out["result"]["structuredContent"]["body_html"].as_str(),
            Some(html),
            "the html the backend served must reach the caller, got: {out}"
        );
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
