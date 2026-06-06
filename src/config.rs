//! Process-level configuration.
//!
//! Config construction is split into a pure constructor (`Config::new`)
//! and an env-var wrapper (`Config::from_env`). Tests build Config directly
//! and never touch process-global env state — Rust 2024 makes `set_var`
//! unsafe (correctly: it's racy under multi-threaded test harnesses), and
//! we forbid `unsafe_code` at the crate root, so this split is the clean
//! way to keep both invariants.

use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::{Context, Result};

/// Public URL of this MCP server, used as the OAuth `resource` identifier
/// (RFC 8707) and as the `resource` field in the protected-resource metadata
/// document (RFC 9728). Also the audience jmap-mcp requires on inbound
/// Logto access tokens.
const ENV_RESOURCE_URL: &str = "JMAP_MCP_RESOURCE_URL";
/// Issuer URL of the authorization server (Logto) that mints tokens for this
/// resource, e.g. `https://login.kampong.social/oidc`.
const ENV_AUTH_SERVER_URL: &str = "JMAP_MCP_AUTHORIZATION_SERVER";
/// Base URL of the Stalwart server we discover the JMAP session from
/// (`{base}/.well-known/jmap`), e.g. `https://mail.kampong.social`.
const ENV_STALWART_JMAP_BASE_URL: &str = "JMAP_MCP_STALWART_JMAP_BASE_URL";
/// Bind address, defaults to `0.0.0.0:3000` for container deployment.
const ENV_BIND_ADDR: &str = "JMAP_MCP_BIND_ADDR";
/// Separate bind for the cluster-internal `/metrics` endpoint. Never binds
/// `0.0.0.0` unless an operator explicitly sets this var. See
/// [`resolve_metrics_bind_addr`].
const ENV_METRICS_BIND_ADDR: &str = "JMAP_MCP_METRICS_BIND_ADDR";
/// Kubernetes downward-API pod IP. Injected via `fieldRef: status.podIP`.
/// Used to derive the metrics bind address.
const ENV_POD_IP: &str = "POD_IP";
/// Optional OAuth client id, only used for the opaque-token introspection
/// fallback path (when Logto is configured to issue non-JWT access tokens).
const ENV_INTROSPECTION_CLIENT_ID: &str = "JMAP_MCP_LOGTO_CLIENT_ID";
/// Optional client secret paired with the id above.
const ENV_INTROSPECTION_CLIENT_SECRET: &str = "JMAP_MCP_LOGTO_CLIENT_SECRET";

/// Pre-provisioned Logto `client_id` handed back by the RFC 7591 dynamic client
/// registration shim. Logto has no DCR endpoint, so claude.ai (which only
/// onboards via DCR) gets this static public-SPA client. When unset, the
/// `/register` endpoint and `registration_endpoint` advertisement are disabled.
const ENV_DCR_CLIENT_ID: &str = "JMAP_MCP_DCR_CLIENT_ID";
/// Per-identity read quota (per minute).
const ENV_RATE_LIMIT_READS: &str = "JMAP_MCP_RATE_LIMIT_READS_PER_MIN";
/// Per-identity write quota (per minute).
const ENV_RATE_LIMIT_WRITES: &str = "JMAP_MCP_RATE_LIMIT_WRITES_PER_MIN";
/// Maximum bytes a single `download_attachment` fetch may pull. Default 5 MiB.
const ENV_DOWNLOAD_MAX_BYTES: &str = "JMAP_MCP_DOWNLOAD_MAX_BYTES";
/// Maximum bytes `upload_blob_from_url` will fetch before uploading to
/// Stalwart's blob store. Default 10 MiB.
pub const ENV_UPLOAD_MAX_BYTES: &str = "JMAP_MCP_UPLOAD_MAX_BYTES";
/// Number of trusted proxies in front of jmap-mcp. Default 1 (Traefik).
const ENV_TRUSTED_PROXY_HOPS: &str = "JMAP_MCP_TRUSTED_PROXY_HOPS";
/// Optional IP to connect to when reaching the Stalwart host, overriding DNS.
/// Used in-cluster to avoid hairpin NAT on the public `LoadBalancer`: we keep
/// `Host` = the public hostname (so TLS + JMAP session URLs stay valid) but
/// dial the in-cluster Service `ClusterIP` on port 443.
const ENV_STALWART_CONNECT_IP: &str = "JMAP_MCP_STALWART_CONNECT_IP";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
const DEFAULT_RATE_LIMIT_WRITES: u32 = 30;
const DEFAULT_DOWNLOAD_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_UPLOAD_MAX_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXY_HOPS: usize = 1;

#[derive(Debug, Clone)]
pub struct Config {
    /// Our own public URL (e.g. `https://jmap-mcp.kampong.social`). Never
    /// trailing-slashed — RFC 8707 resource indicators are compared as
    /// strings.
    pub resource_url: String,
    /// Authorization server (Logto OIDC issuer). No trailing slash.
    pub authorization_server: String,
    /// Stalwart base URL for JMAP session discovery. No trailing slash.
    pub stalwart_jmap_base_url: String,
    /// TCP bind address for the public API (rmcp + health + .well-known).
    pub bind_addr: SocketAddr,
    /// TCP bind for the cluster-internal metrics endpoint.
    pub metrics_bind_addr: SocketAddr,
    /// Optional introspection credentials — only for the opaque-token
    /// fallback. The default JWKS path needs none.
    pub introspection: Option<IntrospectionCredentials>,
    /// Per-minute read quota. 0 is rejected at parse time.
    pub rate_limit_reads_per_min: u32,
    /// Per-minute write quota. 0 is rejected at parse time.
    pub rate_limit_writes_per_min: u32,
    /// Maximum attachment download size (bytes).
    pub download_max_bytes: u64,
    /// Maximum outbound URL-fetch size (bytes) for blob uploads.
    pub upload_max_bytes: usize,
    /// Number of trusted proxies in front of jmap-mcp (X-Forwarded-For).
    pub trusted_proxy_hops: usize,
    /// Optional IP to dial for the Stalwart host (DNS override). `None` = use
    /// normal DNS resolution.
    pub stalwart_connect_ip: Option<String>,
    /// Optional static Logto `client_id` returned by the DCR shim (`/register`).
    /// `None` disables dynamic client registration advertisement.
    pub dcr_client_id: Option<String>,
}

#[derive(Clone)]
#[allow(dead_code)] // `client_secret` is a reserved fallback field.
pub struct IntrospectionCredentials {
    pub client_id: String,
    pub client_secret: String,
}

impl std::fmt::Debug for IntrospectionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntrospectionCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

impl Config {
    /// Pure constructor. Validates URLs are absolute http(s) and strips
    /// trailing slashes. Used directly by tests; `from_env` wraps it.
    pub fn new(
        resource_url: impl Into<String>,
        authorization_server: impl Into<String>,
        stalwart_jmap_base_url: impl Into<String>,
        bind_addr: SocketAddr,
    ) -> Result<Self> {
        let resource_url = strip_trailing_slash(resource_url.into());
        let authorization_server = strip_trailing_slash(authorization_server.into());
        let stalwart_jmap_base_url = strip_trailing_slash(stalwart_jmap_base_url.into());
        validate_url(&resource_url, ENV_RESOURCE_URL)?;
        validate_url(&authorization_server, ENV_AUTH_SERVER_URL)?;
        validate_url(&stalwart_jmap_base_url, ENV_STALWART_JMAP_BASE_URL)?;
        Ok(Self {
            resource_url,
            authorization_server,
            stalwart_jmap_base_url,
            bind_addr,
            metrics_bind_addr: SocketAddr::from(([127, 0, 0, 1], 9090)),
            introspection: None,
            rate_limit_reads_per_min: DEFAULT_RATE_LIMIT_READS,
            rate_limit_writes_per_min: DEFAULT_RATE_LIMIT_WRITES,
            download_max_bytes: DEFAULT_DOWNLOAD_MAX_BYTES,
            upload_max_bytes: DEFAULT_UPLOAD_MAX_BYTES,
            trusted_proxy_hops: DEFAULT_TRUSTED_PROXY_HOPS,
            stalwart_connect_ip: None,
            dcr_client_id: None,
        })
    }

    /// Builder-style: attach optional introspection credentials.
    #[must_use]
    pub fn with_introspection(mut self, creds: IntrospectionCredentials) -> Self {
        self.introspection = Some(creds);
        self
    }

    /// Load from environment variables. Missing required vars are fatal at
    /// startup — we refuse to boot rather than silently fall back to a
    /// development default in production.
    pub fn from_env() -> Result<Self> {
        let resource_url = require_env(ENV_RESOURCE_URL)?;
        let authorization_server = require_env(ENV_AUTH_SERVER_URL)?;
        let stalwart_jmap_base_url = require_env(ENV_STALWART_JMAP_BASE_URL)?;
        let bind_addr_str = std::env::var(ENV_BIND_ADDR).unwrap_or_else(|_| "0.0.0.0:3000".into());
        let bind_addr = SocketAddr::from_str(&bind_addr_str)
            .with_context(|| format!("invalid {ENV_BIND_ADDR}: {bind_addr_str}"))?;
        let explicit_addr = std::env::var(ENV_METRICS_BIND_ADDR).ok();
        let pod_ip = std::env::var(ENV_POD_IP).ok();
        let metrics_bind_addr =
            resolve_metrics_bind_addr(explicit_addr.as_deref(), pod_ip.as_deref())?;

        let mut cfg = Self::new(
            resource_url,
            authorization_server,
            stalwart_jmap_base_url,
            bind_addr,
        )?;
        cfg.metrics_bind_addr = metrics_bind_addr;
        cfg.rate_limit_reads_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_READS, DEFAULT_RATE_LIMIT_READS)?;
        cfg.rate_limit_writes_per_min =
            parse_rate_limit(ENV_RATE_LIMIT_WRITES, DEFAULT_RATE_LIMIT_WRITES)?;
        cfg.download_max_bytes = parse_u64_env(ENV_DOWNLOAD_MAX_BYTES, DEFAULT_DOWNLOAD_MAX_BYTES)?;
        cfg.upload_max_bytes = usize::try_from(parse_u64_env(
            ENV_UPLOAD_MAX_BYTES,
            DEFAULT_UPLOAD_MAX_BYTES as u64,
        )?)
        .unwrap_or(DEFAULT_UPLOAD_MAX_BYTES);
        cfg.trusted_proxy_hops = parse_trusted_proxy_hops()?;
        cfg.stalwart_connect_ip = std::env::var(ENV_STALWART_CONNECT_IP)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.dcr_client_id = std::env::var(ENV_DCR_CLIENT_ID)
            .ok()
            .filter(|s| !s.trim().is_empty());

        // Optional opaque-token introspection fallback credentials.
        if let (Ok(client_id), Ok(client_secret)) = (
            std::env::var(ENV_INTROSPECTION_CLIENT_ID),
            std::env::var(ENV_INTROSPECTION_CLIENT_SECRET),
        ) {
            cfg = cfg.with_introspection(IntrospectionCredentials {
                client_id,
                client_secret,
            });
        }
        Ok(cfg)
    }
}

/// Resolve the metrics listener bind address. Priority: explicit env →
/// `{POD_IP}:9090` → `127.0.0.1:9090`. Never returns `0.0.0.0` by default.
fn resolve_metrics_bind_addr(
    explicit_addr: Option<&str>,
    pod_ip: Option<&str>,
) -> Result<SocketAddr> {
    let addr_str: String = explicit_addr.map_or_else(
        || pod_ip.map_or_else(|| "127.0.0.1:9090".to_owned(), |ip| format!("{ip}:9090")),
        str::to_owned,
    );
    SocketAddr::from_str(&addr_str)
        .with_context(|| format!("invalid {ENV_METRICS_BIND_ADDR}: {addr_str}"))
}

fn require_env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("required env var {key} is not set"))
}

fn validate_url(url: &str, key: &str) -> Result<()> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        anyhow::bail!("{key} must be an absolute http(s) URL, got: {url}");
    }
    Ok(())
}

fn parse_rate_limit(key: &str, default: u32) -> Result<u32> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => {
            let v: u32 = raw
                .trim()
                .parse()
                .with_context(|| format!("{key} must be a positive integer, got: {raw}"))?;
            if v == 0 {
                anyhow::bail!("{key} must be > 0");
            }
            Ok(v)
        }
    }
}

fn parse_u64_env(key: &str, default: u64) -> Result<u64> {
    std::env::var(key).map_or_else(
        |_| Ok(default),
        |raw| {
            raw.trim()
                .parse()
                .with_context(|| format!("{key} must be a non-negative integer, got: {raw}"))
        },
    )
}

fn parse_trusted_proxy_hops() -> Result<usize> {
    std::env::var(ENV_TRUSTED_PROXY_HOPS).map_or_else(
        |_| Ok(DEFAULT_TRUSTED_PROXY_HOPS),
        |raw| {
            raw.trim().parse().with_context(|| {
                format!("{ENV_TRUSTED_PROXY_HOPS} must be a non-negative integer, got: {raw}")
            })
        },
    )
}

fn strip_trailing_slash(mut s: String) -> String {
    while s.ends_with('/') {
        s.pop();
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config::new(
            "https://jmap-mcp.example.test/",
            "https://login.example.test/oidc",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    #[test]
    fn strips_trailing_slash_on_resource_url() {
        assert_eq!(cfg().resource_url, "https://jmap-mcp.example.test");
    }

    #[test]
    fn rejects_non_http_url() {
        let err = Config::new(
            "jmap-mcp.example.test",
            "https://login.example.test",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        );
        assert!(err.is_err());
    }

    #[test]
    fn metrics_bind_prefers_explicit_then_pod_ip_then_localhost() {
        assert_eq!(
            resolve_metrics_bind_addr(Some("0.0.0.0:1234"), Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "0.0.0.0:1234"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, Some("10.0.0.5"))
                .unwrap()
                .to_string(),
            "10.0.0.5:9090"
        );
        assert_eq!(
            resolve_metrics_bind_addr(None, None).unwrap().to_string(),
            "127.0.0.1:9090"
        );
    }
}
