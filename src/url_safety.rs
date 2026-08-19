//! Public-only URL fetch validation (SSRF defence).
//!
//! The URL attachment tools fetch caller-supplied URLs from the jmap-mcp
//! pod's network position. Without validation, an
//! authenticated MCP caller could ask jmap-mcp to issue GETs against
//! anything the pod can reach — RFC1918 / loopback / link-local / cloud
//! metadata endpoints — and either exfiltrate the body (when the
//! response matches the expected Content-Type prefix) or trigger
//! side-effects on internal GET endpoints.
//!
//! Defence: before issuing the request,
//!
//! 1. Resolve the URL's host via standard `tokio::net::lookup_host`.
//! 2. Reject if **any** resolved IP is non-publicly-routable.
//! 3. Pin the validated addresses into the one-off reqwest client so DNS is
//!    not resolved again between validation and connection.
//! 4. Disable reqwest's automatic redirect handling. Callers currently reject
//!    redirects rather than following them.
//!
//! Address pinning closes DNS rebinding, while rejecting redirects prevents a
//! public server from redirecting the fetch to a private or metadata address.
//!
use std::net::{IpAddr, SocketAddr};

use anyhow::Result;
use tokio::net::lookup_host;

/// True iff `ip` falls in any address range we refuse to fetch from.
///
/// This is the canonical IETF "non-globally-reachable" set, expanded a
/// little (CGNAT, ULA, link-local, etc.). It deliberately does NOT
/// distinguish IPv4 vs IPv6 — both families have analogous private
/// ranges, both must be denied for the cloud-metadata / internal-API
/// classes of SSRF.
#[must_use]
pub fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // CGNAT (100.64.0.0/10) — used by Tailscale and similar.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
                // 0.0.0.0/8 (current network), 198.18.0.0/15 (benchmarking),
                // and 240.0.0.0/4 (reserved) are not globally reachable.
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
                || v4.octets()[0] >= 240
                // Deprecated 6to4 relay anycast range.
                || (v4.octets()[0..3] == [192, 88, 99])
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Stable APIs only — `is_unique_local`, `is_unicast_link_local`,
                // and `is_documentation` are still nightly in current MSRV.
                // The segment checks below cover those ranges manually.
                || {
                    let s = v6.segments()[0];
                    // fc00::/7 (ULA) — segment starts 1111 110x
                    (s & 0xfe00) == 0xfc00
                        // fe80::/10 (link-local) — segment starts 1111 1110 10
                        || (s & 0xffc0) == 0xfe80
                        // 2001:db8::/32 (documentation)
                        || s == 0x2001 && v6.segments()[1] == 0x0db8
                }
                // IPv4-mapped (::ffff:0:0/96): pull out the v4 and recurse.
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_private_or_local_ip(IpAddr::V4(v4)))
        }
    }
}

/// Resolve `host:port` and return `Ok(())` iff every resolved address
/// is globally routable. Returns `Err(reason)` when any resolved IP is
/// private/loopback/link-local/etc., or when the lookup fails / yields
/// zero addresses.
///
/// We reject the whole URL when *any* resolved IP is private, not just
/// one — DNS rebinding could otherwise let an attacker swap a public
/// IP for a private one between checks.
pub async fn resolve_public_host(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = lookup_host((host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup for {host}:{port} failed: {e}"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("DNS lookup for {host}:{port} returned no addresses");
    }
    for sa in &addrs {
        if is_private_or_local_ip(sa.ip()) {
            anyhow::bail!(
                "refusing to fetch from {host} (resolves to non-public IP {})",
                sa.ip()
            );
        }
    }
    Ok(addrs)
}

/// An HTTPS URL paired with the exact public socket addresses that passed the
/// SSRF check. Fetchers must use both together to avoid DNS rebinding.
#[derive(Debug, Clone)]
pub struct ValidatedHttpsUrl {
    url: reqwest::Url,
    host: String,
    resolved_addrs: Vec<SocketAddr>,
    host_is_domain: bool,
}

impl std::fmt::Display for ValidatedHttpsUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ValidatedHttpsUrl {
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn resolved_addrs(&self) -> &[SocketAddr] {
        &self.resolved_addrs
    }

    #[must_use]
    pub const fn host_is_domain(&self) -> bool {
        self.host_is_domain
    }
}

/// Parse an absolute HTTPS URL and assert its host resolves to a public
/// IP and retain those exact addresses for the subsequent fetch.
pub async fn validate_https_url(url: &str) -> Result<ValidatedHttpsUrl> {
    if !url.starts_with("https://") {
        anyhow::bail!(
            "url must be HTTPS (http:// is rejected to prevent credential exposure over cleartext)"
        );
    }
    // reqwest::Url is the only correct way to extract host+port across
    // all RFC 3986 cases (userinfo, IPv6 literal, default port, etc.).
    // It's already in the dep tree via reqwest.
    let parsed =
        reqwest::Url::parse(url).map_err(|e| anyhow::anyhow!("failed to parse URL {url}: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL {url} has no host"))?
        .to_owned();
    let host_is_domain = matches!(parsed.host(), Some(url::Host::Domain(_)));
    let port = parsed.port_or_known_default().unwrap_or(443);
    let resolved_addrs = resolve_public_host(&host, port).await?;
    Ok(ValidatedHttpsUrl {
        url: parsed,
        host,
        resolved_addrs,
        host_is_domain,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn ipv4_loopback_is_private() {
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn ipv4_rfc1918_is_private() {
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        ))));
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
    }

    #[test]
    fn ipv4_link_local_is_private() {
        // 169.254.0.0/16 — includes AWS/GCP cloud metadata endpoints.
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
    }

    #[test]
    fn ipv4_cgnat_is_private() {
        // 100.64.0.0/10 — Tailscale and similar.
        assert!(is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            100, 100, 1, 1
        ))));
        // Edge: 100.63.x.x is NOT CGNAT (still public-ish range).
        assert!(!is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            100, 63, 0, 1
        ))));
    }

    #[test]
    fn ipv4_benchmark_and_reserved_ranges_are_blocked() {
        for ip in [
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 19, 255, 254),
            Ipv4Addr::new(240, 0, 0, 1),
        ] {
            assert!(is_private_or_local_ip(IpAddr::V4(ip)), "{ip}");
        }
    }

    #[test]
    fn ipv4_public_addresses_pass() {
        // 1.1.1.1, 8.8.8.8, GitHub, etc.
        assert!(!is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        ))));
        assert!(!is_private_or_local_ip(IpAddr::V4(Ipv4Addr::new(
            140, 82, 114, 4
        ))));
    }

    #[test]
    fn ipv6_loopback_and_ula_blocked() {
        assert!(is_private_or_local_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // fc00::/7 (ULA)
        assert!(is_private_or_local_ip(IpAddr::V6(
            "fc00::1".parse().unwrap()
        )));
        assert!(is_private_or_local_ip(IpAddr::V6(
            "fd12:3456::1".parse().unwrap()
        )));
        // fe80::/10 (link-local)
        assert!(is_private_or_local_ip(IpAddr::V6(
            "fe80::1".parse().unwrap()
        )));
    }

    #[test]
    fn ipv6_ipv4_mapped_falls_through() {
        // ::ffff:10.0.0.1 should be blocked because 10.0.0.1 is private.
        let mapped: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private_or_local_ip(IpAddr::V6(mapped)));
    }

    #[test]
    fn ipv6_public_passes() {
        // Cloudflare 1.1.1.1 v6 equivalent.
        assert!(!is_private_or_local_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[tokio::test]
    async fn validate_rejects_non_https() {
        let err = validate_https_url("http://example.com/foo")
            .await
            .unwrap_err();
        assert!(err.to_string().to_lowercase().contains("https"));
    }

    #[tokio::test]
    async fn validate_rejects_loopback_literal() {
        let err = validate_https_url("https://127.0.0.1/x").await.unwrap_err();
        assert!(err.to_string().contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn validate_rejects_cloud_metadata() {
        let err = validate_https_url("https://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("169.254.169.254"));
    }

    #[tokio::test]
    async fn validate_rejects_rfc1918_literal() {
        let err = validate_https_url("https://10.0.0.1/x").await.unwrap_err();
        assert!(err.to_string().contains("10.0.0.1"));
    }

    #[tokio::test]
    async fn validated_url_carries_the_checked_socket_address() {
        let validated = validate_https_url("https://1.1.1.1/resource")
            .await
            .unwrap();
        assert_eq!(validated.as_str(), "https://1.1.1.1/resource");
        assert!(!validated.host_is_domain());
        assert_eq!(validated.resolved_addrs().len(), 1);
        assert_eq!(validated.resolved_addrs()[0].ip().to_string(), "1.1.1.1");
    }
}
