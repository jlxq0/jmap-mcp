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

use crate::oauth_redirect;

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
/// Number of trusted proxies in front of jmap-mcp.
///
/// Default 2, which is this fleet's topology and not a universal:
/// client -> Caddy edge -> Cilium gateway -> pod. The edge sets no
/// `trusted_proxies`, so it **replaces** `X-Forwarded-For` with its peer
/// (entry 1, the client); Cilium runs `gateway-api-xff-num-trusted-hops: 0`,
/// so Envoy **appends** the downstream address (entry 2, the edge). Measured
/// at the pod 2026-08-27 as `xff_entries=2`, and derived independently from
/// `oddie-apps/edge-config`, which is why the number is written down here
/// with the systems that produce it named beside it.
///
/// **A deployment not behind that edge must override this.** A backend behind
/// the LAN-only `home` gateway (`10.0.10.240`) sees **one** entry, and moving
/// between the two gateways changes the correct value with nothing reporting
/// it.
///
/// **2 is safe here only because the edge replaces rather than appends**, and
/// that is a property of the edge rather than of the number. `parse_client_ip`
/// counts in from the right, so:
///
/// - too low records a proxy's address as the client's, confidently;
/// - too high blanks the field **only** when the chain is genuinely shorter
///   *and* nothing preserved a client-supplied entry. Behind a front-most
///   proxy that **appends**, a client sending `X-Forwarded-For: 1.2.3.4`
///   produces `1.2.3.4, <client>`; `len` is then 2, the `len < hops` guard
///   never fires, and a hop count of 2 selects the **attacker's** value.
///
/// So raising this number is not a free safety margin. Behind an appending
/// proxy it turns a wrong address into a chosen one, which is worse. Check
/// what the front-most proxy does before changing it.
///
/// # The residual this value carries, and the one line that would open it
///
/// A caller that reaches the Cilium gateway **directly**, bypassing the edge,
/// has a real chain depth of 1. It sends its own `X-Forwarded-For`, Envoy
/// appends, `len` becomes 2, the `len < hops` guard never fires, and this
/// value selects `parts[0]`: **the caller's own string, written into the audit
/// record as the client address.** Forged provenance rather than access, which
/// is the failure that reads as settled rather than as unknown.
///
/// **The asymmetry matters and is why "use the edge-inclusive depth" is not a
/// complete instruction**: on that bypass path `2` is *worse* than `1`, since
/// `1` selects an infrastructure address and `2` selects whatever the caller
/// typed. The same setting that fixes the ordinary path turns a wrong-but-inert
/// value into a caller-controlled one on the other.
///
/// **The mitigation is a cluster fact and nothing in this process asserts it.**
/// Measured 2026-08-27: the gateway is unreachable from the public internet
/// *and from the LAN*, and answers only to code running inside the cluster.
/// From one external host, with a same-moment control proving the path works:
///
///     203.24.209.8:443   edge (Caddy)         OPEN
///     203.24.209.5:443   cilium-gateway-web   timeout, 6s
///     203.24.209.5:80    cilium-gateway-web   timeout, 6s
///
/// `fondue` holds `203.24.209.5/32` as a `MetalLB` `BGPAdvertisement` peered across
/// `sgp`, `lax` and `zrh`; the L2 pool is `home-lan` on `10.0.10.240`. Nothing
/// on the wifi has a route to it.
///
/// **What would open it is one line in the deployment manifest.** This
/// service's `HTTPRoute` has exactly one `parentRef`, `gateway/web`
/// (`sectionName: http`), as do all 89 routes on the cluster. Adding
/// `gateway/home` as a second makes the service LAN-reachable with nothing
/// else changing: no alert, no failing test, no visible difference in this pod.
/// The assertion therefore lives in `oddie-apps/platform`, not here.
const ENV_TRUSTED_PROXY_HOPS: &str = "JMAP_MCP_TRUSTED_PROXY_HOPS";
/// Optional IP to connect to when reaching the Stalwart host, overriding DNS.
/// Used in-cluster to avoid hairpin NAT on the public `LoadBalancer`: we keep
/// `Host` = the public hostname (so TLS + JMAP session URLs stay valid) but
/// dial the in-cluster Service `ClusterIP` on port 443.
const ENV_STALWART_CONNECT_IP: &str = "JMAP_MCP_STALWART_CONNECT_IP";
/// Opt in to accepting a Stalwart app password over HTTP Basic, in addition to
/// the Logto JWT over Bearer.
///
/// **Off by default, and the default is the point.** Until this exists the
/// server has only ever held a credential Logto validated. A Stalwart app
/// password is long-lived and validated by the mail server instead, so turning
/// it on is a deployment decision about that mailbox rather than a code one.
///
/// It does not make any bearer acceptable. `Bearer` remains Logto-JWT-only, so
/// a garbage bearer takes exactly the path it took before this flag existed;
/// `Basic` is a separate path that Stalwart itself accepts or refuses. The two
/// never merge into "forwarded to Stalwart either way", which is how a
/// validated credential and an unvalidated one become the same thing to the
/// next reader.
const ENV_ALLOW_APP_PASSWORD: &str = "JMAP_MCP_ALLOW_STALWART_APP_PASSWORD";

/// Additional addresses this mailbox may send as, declared by the operator.
///
/// Stalwart exposes a principal's aliases only through `x:Account/get` /
/// `x:Account/query`, which require the `sysAccountGet` / `sysAccountQuery`
/// permissions. An ordinary mail user's OAuth token carries neither, so alias
/// discovery is unavailable in the normal deployment and the mailbox's own
/// aliases are invisible. This lets the operator name them explicitly instead
/// of granting the server admin rights over the mail server.
pub const ENV_EXTRA_FROM_ADDRESSES: &str = "JMAP_MCP_EXTRA_FROM_ADDRESSES";

const DEFAULT_RATE_LIMIT_READS: u32 = 60;
const DEFAULT_RATE_LIMIT_WRITES: u32 = 30;
const DEFAULT_DOWNLOAD_MAX_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_UPLOAD_MAX_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_TRUSTED_PROXY_HOPS: usize = 2;

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
    /// Accept a Stalwart app password over HTTP Basic. See
    /// [`ENV_ALLOW_APP_PASSWORD`]. Default `false`.
    pub allow_app_password: bool,
    /// Optional IP to dial for the Stalwart host (DNS override). `None` = use
    /// normal DNS resolution.
    pub stalwart_connect_ip: Option<String>,
    /// Optional static Logto `client_id` returned by the DCR shim (`/register`).
    /// `None` disables dynamic client registration advertisement.
    pub dcr_client_id: Option<String>,
    /// Exact OAuth redirect URIs accepted by the proxy and DCR shim.
    pub oauth_redirect_uris: Vec<String>,
    /// Operator-declared addresses this mailbox may send as, in addition to
    /// the JMAP identities. Lower-cased, de-duplicated, and guaranteed free of
    /// role addresses by [`parse_extra_from_addresses`].
    pub extra_from_addresses: Vec<OwnedFromAddress>,
    /// Declared addresses that name no owner. Granted to nobody; startup warns.
    pub unowned_from_addresses: Vec<String>,
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
        let resource_url = canonical_resource_origin(resource_url.into());
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
            allow_app_password: false,
            stalwart_connect_ip: None,
            dcr_client_id: None,
            oauth_redirect_uris: Vec::new(),
            extra_from_addresses: Vec::new(),
            unowned_from_addresses: Vec::new(),
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
        cfg.allow_app_password = parse_bool_env(ENV_ALLOW_APP_PASSWORD)?;
        cfg.stalwart_connect_ip = std::env::var(ENV_STALWART_CONNECT_IP)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.dcr_client_id = std::env::var(ENV_DCR_CLIENT_ID)
            .ok()
            .filter(|s| !s.trim().is_empty());
        cfg.oauth_redirect_uris = parse_redirect_uris_env()?;
        let parsed = parse_extra_from_addresses_env()?;
        cfg.extra_from_addresses = parsed.owned;
        cfg.unowned_from_addresses = parsed.unowned;

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

/// Canonicalise `JMAP_MCP_RESOURCE_URL` to the bare **origin**, accepting
/// either `https://host` or `https://host/mcp`.
///
/// Both spellings are natural to write — the public MCP endpoint really is
/// `<origin>/mcp`, so operators reasonably set that — but `resource_url` is
/// the base every other URL hangs off, and only the origin works for all of
/// them:
///
/// * RFC 9728 `resource` is derived as `<origin>/mcp`
///   ([`crate::oauth_metadata::mcp_resource`]) — an origin that already ended
///   in `/mcp` would advertise `/mcp/mcp`.
/// * The `WWW-Authenticate` challenge appends
///   `/.well-known/oauth-protected-resource/mcp`.
/// * RFC 8414 `issuer` must equal the origin the metadata is served from, and
///   `authorization_endpoint`/`token_endpoint` are `<origin>/authorize` and
///   `<origin>/token` — routes mounted at the origin, not under `/mcp`.
/// * `/oauth/callback` is registered with Logto at the origin.
/// * It is the JWT `aud` we validate, which Logto mints as the origin and
///   which Stalwart's directory `requireAudience` must match byte-for-byte
///   (a mismatch here is exactly the 2026-08 `InvalidAudience` outage).
///
/// So normalising here lets the env var carry either form while every derived
/// URL stays correct, instead of silently doubling the path segment.
fn canonical_resource_origin(raw: String) -> String {
    let trimmed = strip_trailing_slash(raw);
    match trimmed.strip_suffix("/mcp") {
        // Guard against eating the whole value for a pathological input like
        // `https:///mcp`; only strip when an origin remains.
        Some(origin) if origin.contains("://") && !origin.ends_with('/') => origin.to_owned(),
        _ => trimmed,
    }
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

fn parse_redirect_uris_env() -> Result<Vec<String>> {
    match std::env::var(oauth_redirect::ENV_OAUTH_REDIRECT_URIS) {
        Ok(raw) => oauth_redirect::parse_allowlist(&raw, oauth_redirect::ENV_OAUTH_REDIRECT_URIS),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(e) => {
            Err(e).with_context(|| format!("invalid {}", oauth_redirect::ENV_OAUTH_REDIRECT_URIS))
        }
    }
}

fn parse_extra_from_addresses_env() -> Result<ParsedFromAddresses> {
    match std::env::var(ENV_EXTRA_FROM_ADDRESSES) {
        Ok(raw) => parse_extra_from_addresses(&raw),
        Err(std::env::VarError::NotPresent) => Ok(ParsedFromAddresses {
            owned: Vec::new(),
            unowned: Vec::new(),
        }),
        Err(e) => Err(e).with_context(|| format!("invalid {ENV_EXTRA_FROM_ADDRESSES}")),
    }
}

/// Parse a comma- or whitespace-separated address allowlist.
///
/// Rejects the whole configuration rather than dropping a bad entry: a typo
/// that silently disappears is how an operator ends up believing an address is
/// sendable when it is not. Role addresses are refused here as well as at send
/// time, so a shared inbox cannot be turned into a personal `From` by config.
/// An operator-declared From address and the account it belongs to.
///
/// The owner is not decoration. Before it existed these addresses were a flat
/// list appended to **every** authenticated caller, so declaring one of
/// Julian's aliases granted it to anybody who authenticated, including a
/// second identity added later. The list could not express *she may send as
/// herself and not as him*, which is the distinction the deployment actually
/// needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedFromAddress {
    /// The mail account this address belongs to, matched case-insensitively
    /// against the JMAP session's `username`.
    pub owner: String,
    /// The address that account may put in `From`.
    pub email: String,
}

/// Outcome of parsing `JMAP_MCP_EXTRA_FROM_ADDRESSES`.
#[derive(Debug)]
pub struct ParsedFromAddresses {
    /// Entries of the form `owner@domain=address@domain`.
    pub owned: Vec<OwnedFromAddress>,
    /// Bare `address@domain` entries, which name no owner.
    ///
    /// **Granted to nobody**, and kept only so startup can say so. Honouring
    /// them would restore the flat list this replaced; refusing to start would
    /// take a live mail server down over a config line. Fail closed, stay up,
    /// and name the fix.
    pub unowned: Vec<String>,
}

fn parse_one_address(entry: &str, raw_entry: &str) -> Result<String> {
    let addr = entry.trim().to_ascii_lowercase();
    let mut parts = addr.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        anyhow::bail!(
            "{ENV_EXTRA_FROM_ADDRESSES}: {raw_entry} is not a single user@domain address"
        );
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        anyhow::bail!("{ENV_EXTRA_FROM_ADDRESSES}: {raw_entry} is not a valid user@domain address");
    }
    // Checked here rather than on the granted address alone, so an unowned
    // entry is still refused loudly. Setting a role address aside quietly
    // would keep it out of every caller's From and lose the error that says
    // the operator asked for something forbidden.
    if crate::mcp::is_role_address(&addr) {
        anyhow::bail!(
            "{ENV_EXTRA_FROM_ADDRESSES}: {raw_entry} is a shared role address and must never be \
             configured as a personal From"
        );
    }
    Ok(addr)
}

pub fn parse_extra_from_addresses(raw: &str) -> Result<ParsedFromAddresses> {
    let mut owned: Vec<OwnedFromAddress> = Vec::new();
    let mut unowned: Vec<String> = Vec::new();
    for entry in raw.split([',', '\n', '\r', '\t', ' ']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((owner_raw, email_raw)) = entry.split_once('=') else {
            // No owner. Parsed for its shape so a typo is still an error, then
            // set aside ungranted.
            let addr = parse_one_address(entry, entry)?;
            if !unowned.contains(&addr) {
                unowned.push(addr);
            }
            continue;
        };
        let account = parse_one_address(owner_raw, entry)?;
        let email = parse_one_address(email_raw, entry)?;
        let candidate = OwnedFromAddress {
            owner: account,
            email,
        };
        if !owned.contains(&candidate) {
            owned.push(candidate);
        }
    }
    Ok(ParsedFromAddresses { owned, unowned })
}

/// Parse a boolean env var. Absent is `false`; only the exact strings below are
/// accepted, so a typo is an error rather than a silent `false` on a flag that
/// widens the auth surface.
fn parse_bool_env(name: &str) -> Result<bool> {
    match std::env::var(name) {
        Err(_) => Ok(false),
        Ok(raw) => match raw.trim() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" | "" => Ok(false),
            other => anyhow::bail!("{name} must be one of 1/true/yes/0/false/no, got: {other}"),
        },
    }
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
mod extra_from_address_tests {
    use super::{OwnedFromAddress, parse_extra_from_addresses};

    fn owned(owner: &str, email: &str) -> OwnedFromAddress {
        OwnedFromAddress {
            owner: owner.into(),
            email: email.into(),
        }
    }

    #[test]
    fn parses_separated_and_normalises() {
        let out = parse_extra_from_addresses(
            "Julian@Kampong.Social=Julian@Lindner.Earth, julian@kampong.social=jl@lindner.sg\n \
             julian@kampong.social=jl@lindner.sg",
        )
        .expect("valid list");
        assert_eq!(
            out.owned,
            vec![
                owned("julian@kampong.social", "julian@lindner.earth"),
                owned("julian@kampong.social", "jl@lindner.sg"),
            ]
        );
        assert!(out.unowned.is_empty());
    }

    #[test]
    fn empty_is_empty() {
        let out = parse_extra_from_addresses("   ,,\n ").unwrap();
        assert!(out.owned.is_empty() && out.unowned.is_empty());
    }

    /// A bare address names no owner, so it is granted to nobody rather than
    /// to everybody. Granting it to everybody is what this change removes.
    #[test]
    fn an_entry_without_an_owner_is_granted_to_nobody() {
        let out = parse_extra_from_addresses("julian@lindner.earth").expect("still valid syntax");
        assert!(
            out.owned.is_empty(),
            "an unowned entry must not become a grant"
        );
        assert_eq!(out.unowned, vec!["julian@lindner.earth"]);
    }

    /// The whole point of the allowlist is that it cannot be used to turn a
    /// shared inbox into a personal From, and that holds for an entry with no
    /// owner too, where it would otherwise be set aside silently.
    #[test]
    fn role_addresses_are_refused() {
        for role in [
            "team@kampong.social",
            "TEAM@kampong.social",
            "postmaster@lindner.earth",
            "julian@lindner.earth, team@kampong.social",
            "julian@kampong.social=team@kampong.social",
            "team@kampong.social=julian@lindner.earth",
        ] {
            let err = parse_extra_from_addresses(role).expect_err("role address must be refused");
            assert!(
                err.to_string().contains("role address"),
                "unexpected error for {role}: {err}"
            );
        }
    }

    /// A malformed entry fails the whole configuration rather than vanishing:
    /// a silently dropped typo leaves the operator believing an address is
    /// sendable when it is not. Both halves of an owned entry are checked.
    #[test]
    fn malformed_entries_fail_loudly() {
        for bad in [
            "notanemail",
            "two@at@signs.com",
            "@lindner.earth",
            "julian@",
            "julian@local",
            "julian@kampong.social=notanemail",
            "notanemail=julian@lindner.earth",
            "=julian@lindner.earth",
            "julian@kampong.social=",
        ] {
            assert!(
                parse_extra_from_addresses(bad).is_err(),
                "{bad} should be rejected"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The default is a measurement of this fleet's ingress, not a guess.
    ///
    /// client -> Caddy edge -> Cilium gateway -> pod is two appended entries,
    /// observed at the pod as `xff_entries=2` on 2026-08-27 and derived
    /// separately from the edge config. `parse_client_ip` counts in from the
    /// right, so 1 against a two-entry header selects the edge's own address
    /// and writes it into the audit trail as the client's.
    ///
    /// If this assertion fails, the topology changed or someone reverted the
    /// constant. Re-measure with the `ingress chain length` log line before
    /// changing the number.
    /// Why the default is only correct behind a *replacing* front proxy.
    ///
    /// Found by Codex in review of the 1 -> 2 change, and it contradicts the
    /// tidy claim that a higher hop count always fails safe. Behind a proxy
    /// that appends instead of replacing, a client pads the header and the
    /// `len < hops` guard never fires, so the selected entry is the client's
    /// own. Our edge replaces, which is what makes 2 correct here; this test
    /// exists so the next person raising the number meets the reason.
    #[test]
    fn a_padded_chain_defeats_a_higher_hop_count() {
        // Appending proxy: client sent "1.2.3.4", proxy appended what it saw.
        let padded = "1.2.3.4, 198.51.100.9";
        assert_eq!(
            crate::last_used::parse_client_ip(Some(padded), 2),
            Some("1.2.3.4".parse().unwrap()),
            "hops=2 on a padded 2-entry chain selects the attacker's entry"
        );
        assert_eq!(
            crate::last_used::parse_client_ip(Some(padded), 1),
            Some("198.51.100.9".parse().unwrap()),
            "hops=1 there selects what the proxy actually saw"
        );
        // Replacing edge, which is our path: the client's value is gone before
        // the gateway appends, so no padding survives to be selected.
        let replaced = "203.0.113.5, 10.0.0.1";
        assert_eq!(
            crate::last_used::parse_client_ip(Some(replaced), 2),
            Some("203.0.113.5".parse().unwrap()),
            "hops=2 behind a replacing edge selects the real client"
        );
    }

    #[test]
    fn default_trusted_proxy_hops_matches_the_measured_chain_length() {
        assert_eq!(
            DEFAULT_TRUSTED_PROXY_HOPS, 2,
            "measured xff_entries=2 at the pod; 1 records the edge as the client"
        );
        // And the pairing that makes it matter, on a two-entry header.
        let xff = "203.0.113.5, 10.0.0.1";
        assert_eq!(
            crate::last_used::parse_client_ip(Some(xff), DEFAULT_TRUSTED_PROXY_HOPS),
            Some("203.0.113.5".parse().unwrap()),
            "the default must select the client, not the edge"
        );
    }

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

    fn cfg_with(resource_url: &str) -> Config {
        Config::new(
            resource_url,
            "https://login.example.test/oidc",
            "https://mail.example.test",
            SocketAddr::from(([0, 0, 0, 0], 3000)),
        )
        .unwrap()
    }

    /// `JMAP_MCP_RESOURCE_URL` may be written with or without the `/mcp`
    /// suffix — the public endpoint really is `<origin>/mcp`, so operators
    /// reasonably set that. Both must canonicalise to the origin.
    #[test]
    fn resource_url_accepts_mcp_suffix() {
        for raw in [
            "https://jmap-mcp.kampong.social",
            "https://jmap-mcp.kampong.social/",
            "https://jmap-mcp.kampong.social/mcp",
            "https://jmap-mcp.kampong.social/mcp/",
        ] {
            assert_eq!(
                cfg_with(raw).resource_url,
                "https://jmap-mcp.kampong.social",
                "{raw} should canonicalise to the origin"
            );
        }
    }

    /// The whole point of normalising: every derived URL must come out
    /// byte-identical whichever spelling the operator used. These are the
    /// exact strings the contract pins.
    #[test]
    fn both_spellings_derive_identical_urls() {
        let plain = cfg_with("https://jmap-mcp.kampong.social");
        let suffixed = cfg_with("https://jmap-mcp.kampong.social/mcp");

        // RFC 9728 resource — must be the origin + /mcp exactly once.
        let resource = crate::oauth_metadata::mcp_resource(&suffixed.resource_url);
        assert_eq!(resource, "https://jmap-mcp.kampong.social/mcp");
        assert_eq!(
            resource,
            crate::oauth_metadata::mcp_resource(&plain.resource_url)
        );

        // WWW-Authenticate resource_metadata path.
        let challenge = crate::oauth_metadata::www_authenticate_header(&suffixed.resource_url);
        assert!(challenge.contains(
            r#"resource_metadata="https://jmap-mcp.kampong.social/.well-known/oauth-protected-resource/mcp""#
        ));
        assert_eq!(
            challenge,
            crate::oauth_metadata::www_authenticate_header(&plain.resource_url)
        );

        // RFC 8414 issuer / authorize / token must stay on the origin, where
        // the routes are actually mounted.
        let meta = crate::oauth_metadata::AuthorizationServerMetadata::from_config(&suffixed);
        assert_eq!(meta.issuer, "https://jmap-mcp.kampong.social");
        assert_eq!(
            meta.authorization_endpoint,
            "https://jmap-mcp.kampong.social/authorize"
        );
        assert_eq!(meta.token_endpoint, "https://jmap-mcp.kampong.social/token");

        // The JWT audience we validate — must match Logto's minted `aud` and
        // Stalwart's `requireAudience` byte-for-byte.
        assert_eq!(suffixed.resource_url, "https://jmap-mcp.kampong.social");
    }

    /// Only a whole trailing `/mcp` path segment is stripped.
    #[test]
    fn resource_url_keeps_other_paths_and_lookalikes() {
        assert_eq!(
            cfg_with("https://jmap-mcp.kampong.social/mcpx").resource_url,
            "https://jmap-mcp.kampong.social/mcpx"
        );
        // The host itself contains "mcp" — must survive untouched.
        assert_eq!(
            cfg_with("https://jmap-mcp.kampong.social/mcp/mcp").resource_url,
            "https://jmap-mcp.kampong.social/mcp"
        );
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
