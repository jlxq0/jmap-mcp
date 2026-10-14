//! Logto access-token validation via JWKS and allowlisted asymmetric algorithms.
//!
//! Unlike matrix-mcp (which introspected every bearer against MAS over the
//! network), jmap-mcp validates Logto access tokens *locally*: fetch the
//! issuer's JWKS once, cache the decoding keys, and verify the JWT's
//! signature + `aud` + `exp` per request. This is a self-contained check
//! with no per-request round-trip.
//!
//! Pass-through model: the same validated JWT is then forwarded verbatim to
//! Stalwart as the JMAP `Authorization: Bearer`. Stalwart validates it
//! against the same Logto issuer via its OIDC directory.
//!
//! Token must be a JWT issued for *our* resource indicator (the audience
//! check enforces RFC 8707 binding). Opaque tokens (no JWT header) are
//! rejected — Logto issues JWT access tokens for registered API resources,
//! which is how jmap-mcp's protected-resource metadata steers claude.ai.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

/// Maximum age of a cached positive validation. Bounded so a token
/// revocation (Logto session end) propagates in at most this window even
/// though local JWT verification can't see revocations directly.
#[allow(unknown_lints, clippy::duration_suboptimal_units)]
const MAX_CACHE_TTL: Duration = Duration::from_secs(60);

/// Hard cap on the validation cache size.
const CACHE_CAP: usize = 256;

/// JWKS cache lifetime. Refetched on unknown `kid` regardless (key rotation).
/// `from_secs` not `from_hours`: the unit constructors are unstable on 1.93.
#[allow(unknown_lints, clippy::duration_suboptimal_units)]
const JWKS_TTL: Duration = Duration::from_secs(3600);
/// Bound refresh amplification from attacker-chosen unknown key ids. A real
/// key rotation is accepted after at most this short interval.
const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Claims we read off a Logto access token. Logto always emits `sub`, `aud`,
/// `iss`, `exp`, `iat`. `email`/`name`/`username` are present only when the
/// resource/app is configured to include user claims in the access token;
/// they're best-effort here and enriched from the JMAP session elsewhere.
#[derive(Debug, Deserialize, Clone)]
struct LogtoAccessTokenClaims {
    sub: String,
    aud: AudField,
    exp: i64,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// `aud` can be a single string or an array. We check membership, not
/// equality.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum AudField {
    Single(String),
    Multi(Vec<String>),
}

impl AudField {
    fn matches(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multi(xs) => xs.iter().any(|s| s == expected),
        }
    }
}

/// What the auth layer hands to the rest of the application after a
/// successful validation.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Stable Logto user id (`sub`). Ownership/cache key.
    pub user_id: String,
    /// User's email, when the token carries it. Enriched from the JMAP
    /// session's `username` for display when absent.
    pub email: Option<String>,
    /// Display name, when present.
    pub name: Option<String>,
    /// Token expiry (Unix epoch seconds). Surfaced via `/token/introspect`.
    pub exp: Option<i64>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("JWKS fetch/transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JWKS endpoint returned non-2xx: {status}")]
    JwksUpstream { status: u16 },
}

#[derive(Clone)]
pub struct LogtoValidationClient {
    http: reqwest::Client,
    jwks_url: String,
    expected_audience: String,
    expected_issuer: String,
    jwks: Arc<RwLock<JwksCache>>,
    jwks_refresh: Arc<AsyncMutex<()>>,
    cache: Arc<RwLock<HashMap<[u8; 32], CacheEntry>>>,
}

#[allow(clippy::missing_fields_in_debug)] // intentionally redacts cached token/JWKS state
impl std::fmt::Debug for LogtoValidationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogtoValidationClient")
            .field("jwks_url", &self.jwks_url)
            .field("expected_audience", &self.expected_audience)
            .finish()
    }
}

#[derive(Default)]
struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
    refresh_attempted_at: Option<Instant>,
}

#[derive(Clone)]
struct CacheEntry {
    identity: AuthenticatedIdentity,
    expires_at: Instant,
}

enum CachedKeyStatus {
    Key(DecodingKey),
    Cooldown,
    Refresh,
}

impl LogtoValidationClient {
    /// Build the request validator from the same configuration as the router.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Self> {
        let client = Self::new(&cfg.authorization_server, cfg.resource_url.clone())?;
        if let Some(validation) = &cfg.oidc_validation {
            client.with_oidc_validation(
                validation.issuer.clone(),
                validation.audience.clone(),
                validation.jwks_url.clone(),
            )
        } else {
            Ok(client)
        }
    }

    /// Build a validation client. `authorization_server` is the Logto OIDC
    /// issuer base (`https://login.kampong.social/oidc`); the JWKS lives at
    /// `{issuer}/jwks` and the `iss` claim equals the issuer base exactly.
    pub fn new(authorization_server: &str, expected_audience: String) -> Result<Self> {
        let issuer = authorization_server.trim_end_matches('/').to_owned();
        let jwks_url = format!("{issuer}/jwks");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent(concat!("jmap-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            jwks_url,
            expected_audience,
            expected_issuer: issuer,
            jwks: Arc::new(RwLock::new(JwksCache::default())),
            jwks_refresh: Arc::new(AsyncMutex::new(())),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Configure an explicit OIDC issuer, audience, and JWKS endpoint.
    /// Values are trusted deployment configuration, never request data.
    pub fn with_oidc_validation(
        mut self,
        issuer: String,
        audience: String,
        jwks_url: String,
    ) -> Result<Self> {
        crate::config::OidcValidation::parse(
            Some(issuer.clone()),
            Some(audience.clone()),
            Some(jwks_url.clone()),
        )?;
        self.expected_issuer = issuer;
        self.expected_audience = audience;
        self.jwks_url = jwks_url;
        Ok(self)
    }

    /// Validate a bearer token. `Ok(Some(identity))` on a valid JWT for our
    /// audience; `Ok(None)` if the token is expired, malformed, opaque, has
    /// the wrong audience/issuer, or fails signature verification. `Err`
    /// only for JWKS-fetch transport failures.
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<Option<AuthenticatedIdentity>, ValidationError> {
        let key = hash_token(token);
        if let Some(hit) = self.cache_lookup(&key) {
            debug!("token validation cache hit");
            return Ok(Some(hit));
        }

        let Ok(header) = decode_header(token) else {
            warn!("bearer is not a JWT (opaque token?); rejecting");
            return Ok(None);
        };
        let Some(kid) = header.kid.clone() else {
            warn!("JWT missing `kid`; rejecting");
            return Ok(None);
        };

        let Some(decoding_key) = self.decoding_key_for(&kid).await? else {
            warn!(%kid, "no JWKS key matched token kid; rejecting");
            return Ok(None);
        };

        // jsonwebtoken requires every entry in `validation.algorithms` to
        // share the key's family (mixing EC + RSA errors out), so we can't
        // hardcode a cross-family list. Use the token header's declared `alg`
        // — but only after allow-listing it to the asymmetric algorithms we
        // accept (rejects `none`/HMAC and blocks alg-confusion). The key is
        // already pinned by `kid` from the trusted JWKS and the signature is
        // verified against it below, and jsonwebtoken enforces key.family ==
        // alg.family, so a forged cross-family `alg` cannot validate.
        if !matches!(
            header.alg,
            Algorithm::ES384
                | Algorithm::ES256
                | Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::EdDSA
        ) {
            warn!(alg = ?header.alg, "unsupported token signing algorithm; rejecting");
            return Ok(None);
        }
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[&self.expected_audience]);
        validation.set_issuer(&[&self.expected_issuer]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);

        let claims = match decode::<LogtoAccessTokenClaims>(token, &decoding_key, &validation) {
            Ok(data) => data.claims,
            Err(e) => {
                debug!(error = %e, "JWT validation failed; rejecting");
                return Ok(None);
            }
        };

        // Defence in depth: jsonwebtoken already enforced aud via Validation,
        // but re-check membership explicitly to be robust against future
        // Validation default changes.
        if !claims.aud.matches(&self.expected_audience) {
            warn!("token audience does not include resource url; rejecting");
            return Ok(None);
        }

        let identity = AuthenticatedIdentity {
            user_id: claims.sub.clone(),
            email: claims.email.clone().or_else(|| claims.username.clone()),
            name: claims.name.clone(),
            exp: Some(claims.exp),
        };
        let _ = claims.scope; // currently unused; reserved for scope gating.

        self.cache_insert(key, &identity, Some(claims.exp));
        Ok(Some(identity))
    }

    /// Drop a cached positive validation, forcing re-verification on the
    /// next presentation of this token (used when Stalwart reports the
    /// token is no longer good).
    pub fn drop_token(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut g) = self.cache.write() {
            g.remove(&key);
        }
    }

    async fn decoding_key_for(&self, kid: &str) -> Result<Option<DecodingKey>, ValidationError> {
        match self.cached_key_status(kid) {
            CachedKeyStatus::Key(key) => return Ok(Some(key)),
            CachedKeyStatus::Cooldown => return Ok(None),
            CachedKeyStatus::Refresh => {}
        }

        // Only one request may refresh at a time. Re-check after acquiring the
        // lock because another request may have populated the cache meanwhile.
        let _refresh_guard = self.jwks_refresh.lock().await;
        match self.cached_key_status(kid) {
            CachedKeyStatus::Key(key) => return Ok(Some(key)),
            CachedKeyStatus::Cooldown => return Ok(None),
            CachedKeyStatus::Refresh => {}
        }
        if let Ok(mut g) = self.jwks.write() {
            g.refresh_attempted_at = Some(Instant::now());
        }
        self.refresh_jwks().await?;
        Ok(self.jwks.read().ok().and_then(|g| g.keys.get(kid).cloned()))
    }

    fn cached_key_status(&self, kid: &str) -> CachedKeyStatus {
        let Ok(g) = self.jwks.read() else {
            return CachedKeyStatus::Refresh;
        };
        let fresh = g.fetched_at.is_some_and(|t| t.elapsed() < JWKS_TTL);
        if fresh && let Some(key) = g.keys.get(kid) {
            return CachedKeyStatus::Key(key.clone());
        }
        let cooling_down = g
            .refresh_attempted_at
            .is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH_INTERVAL);
        drop(g);
        if cooling_down {
            CachedKeyStatus::Cooldown
        } else {
            CachedKeyStatus::Refresh
        }
    }

    async fn refresh_jwks(&self) -> Result<(), ValidationError> {
        let resp = self.http.get(&self.jwks_url).send().await?;
        if !resp.status().is_success() {
            return Err(ValidationError::JwksUpstream {
                status: resp.status().as_u16(),
            });
        }
        let set: JwkSet = resp.json().await?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if let Some(kid) = jwk.common.key_id.clone()
                && let Ok(key) = DecodingKey::from_jwk(jwk)
            {
                keys.insert(kid, key);
            }
        }
        if let Ok(mut g) = self.jwks.write() {
            g.keys = keys;
            g.fetched_at = Some(Instant::now());
        }
        Ok(())
    }

    fn cache_lookup(&self, key: &[u8; 32]) -> Option<AuthenticatedIdentity> {
        let guard = self.cache.read().ok()?;
        let result = guard
            .get(key)
            .and_then(|e| (e.expires_at > Instant::now()).then(|| e.identity.clone()));
        drop(guard);
        result
    }

    fn cache_insert(&self, key: [u8; 32], identity: &AuthenticatedIdentity, exp: Option<i64>) {
        let ttl = exp.map_or(MAX_CACHE_TTL, |exp| {
            let now = now_unix();
            let remaining = u64::try_from((exp - now).max(0)).unwrap_or(0);
            Duration::from_secs(remaining).min(MAX_CACHE_TTL)
        });
        let entry = CacheEntry {
            identity: identity.clone(),
            expires_at: Instant::now() + ttl,
        };
        let Ok(mut guard) = self.cache.write() else {
            return;
        };
        if guard.len() >= CACHE_CAP {
            let now = Instant::now();
            guard.retain(|_, e| e.expires_at > now);
        }
        if guard.len() >= CACHE_CAP
            && !guard.contains_key(&key)
            && let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| *key)
        {
            guard.remove(&oldest);
        }
        guard.insert(key, entry);
    }
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

fn now_unix() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(i64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn aud_single_and_multi_membership() {
        assert!(AudField::Single("https://x".into()).matches("https://x"));
        assert!(!AudField::Single("https://x".into()).matches("https://y"));
        let m = AudField::Multi(vec!["https://x".into(), "https://y".into()]);
        assert!(m.matches("https://y"));
        assert!(!m.matches("https://z"));
    }

    #[test]
    fn jwks_url_derived_from_issuer() {
        let c =
            LogtoValidationClient::new("https://login.example.test/oidc/", "https://res".into())
                .unwrap();
        assert_eq!(c.jwks_url, "https://login.example.test/oidc/jwks");
        assert_eq!(c.expected_issuer, "https://login.example.test/oidc");
    }

    #[tokio::test]
    async fn opaque_token_rejected() {
        let c = LogtoValidationClient::new("https://login.example.test/oidc", "https://res".into())
            .unwrap();
        // Not a JWT — decode_header fails, no network touched.
        assert!(c.validate_token("opaque-abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unknown_kids_share_one_jwks_refresh_during_cooldown() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oidc/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = LogtoValidationClient::new(
            &format!("{}/oidc", server.uri()),
            "https://resource.test".to_owned(),
        )
        .unwrap();

        assert!(
            client
                .decoding_key_for("attacker-kid-1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            client
                .decoding_key_for("attacker-kid-2")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn validation_cache_is_hard_capped() {
        let client =
            LogtoValidationClient::new("https://login.test/oidc", "https://res".to_owned())
                .unwrap();
        let identity = AuthenticatedIdentity {
            user_id: "user".to_owned(),
            email: None,
            name: None,
            exp: None,
        };
        for i in 0..=CACHE_CAP {
            let mut key = [0_u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            client.cache_insert(key, &identity, None);
        }
        assert_eq!(client.cache.read().unwrap().len(), CACHE_CAP);
    }
    #[test]
    fn configured_validator_uses_independent_jwks_endpoint_and_exact_issuer() {
        let mut cfg = crate::config::Config::new(
            "https://mcp.example.test",
            "https://login.example.test/oidc",
            "https://mail.example.test",
            "127.0.0.1:3000".parse().unwrap(),
        )
        .unwrap();
        let default = LogtoValidationClient::from_config(&cfg).unwrap();
        assert_eq!(default.expected_issuer, "https://login.example.test/oidc");
        assert_eq!(default.expected_audience, "https://mcp.example.test");
        assert_eq!(default.jwks_url, "https://login.example.test/oidc/jwks");
        cfg.oidc_validation = crate::config::OidcValidation::parse(
            Some("https://issuer.example.test/tenant/".into()),
            Some("backend-api".into()),
            Some("https://keys.example.test/signing.json?version=2".into()),
        )
        .unwrap();
        let configured = LogtoValidationClient::from_config(&cfg).unwrap();
        assert_eq!(
            configured.expected_issuer,
            "https://issuer.example.test/tenant/"
        );
        assert_eq!(configured.expected_audience, "backend-api");
        assert_eq!(
            configured.jwks_url,
            "https://keys.example.test/signing.json?version=2"
        );
    }

    // Public test fixture only; never used by production configuration.
    const TEST_KEY: &str = "MIIEpQIBAAKCAQEAmbXeWS/CESvDJqGc+yRyPIWA5dO5jKTuKjaugzrOKxMwbquuGA2ClzX+rAIts/X2ix96LU3LVIeoB5/g351vyvMeOzUmiMDVWhOI8WnvOBhUqZJRwFGvNZi/1eQ03H7v5G0j2wzxu1wrA0qnoo/i9SdOmD4mNBjQxU8JlJ5Z6k59IE2EOoPo5rOqRWpE+dHH09ZKoH+rVyC9qogMEVY4RMWf/VsBPQpAlomQ82YDPWZSmdiDQyVhay7HLAIeiT8kzisaEPlh7RwHUaSMy7ubK4nI9SylxsZFW6uYmuiUy/pRzyCx1FzO6OC2DjrKEfRKJrZQf1dYkgeRN+wEHJspzQIDAQABAoIBAAH7DnjuvRz0h+i9B2VTFGfEPqN3hXoS/ACuQLRvMw3qCuM6Mh2cOvUQ3I3B323kuv8S8kOYL4kQ0HD8teybvj+Kv3Z62lrDxVwKSWb2+v6pjZm7yXLlepEBvWMXtDitKBE0+NPPSGQmLWW29g8JtJ59Ga2ri1l7gmEwggqYucbjo+qs7wWjN9tfqx3zFVSsQpR+nd1MV7G/DOkZW2xLHZgOeBrMNfkRGHfgsl0lhla3gpReb+0+b8KtpkhZYSr6GddKd9HRE52Yo7FazvBFQJKIKdbOlDFCQjsi5GYxZXkTU2fo9Q/iH45EwTwTkRd9/Kodx++D5TlhIkujzKzhZuECgYEAzOowBKUU37zwPlc18LVBiX9Tr3YSvzt5lxFmHp989llQI3UUT83bmphbh706y70qk8x1BfhwGYbHn0ZAVmJDdEJwCzB3Wf/gARiDEEtxTc1/5bg8z2DgsHyFQkXDIW8NNRY2ABBkZ5518omK/SWgk927zOIt0Hh/snEDiIDglxECgYEAwAfHzVEnpgJZBeOIqwoHwTVhACLvk7dkQuVxMP+0nKhLc/asnfMGxm/OeWuOC1Izxh1CqTEiaL9yiQ241Yip5ceBu0ayZuh1YZ78HIi4Y4/VVRNHv2ijzb3rNu6Yl7+BzpfDv+jloJ3WYHF/ZiQ7adztKQmV1LXXZBMeWIqT/v0CgYEAjFLGxTeC/uA0qIwyPP7yvUS7OwmhNuF0l1Xr14aiHVT2AwH3AdtXyhsRevfDnqeQ05uMe6UwptpcMx75ie5KgP/KGG99G92UOUve3La9BWl3bwlmYyDVXSY4XzTEtk2E/tiR7CNNjoO+A3PbARXWS8vpAhnVA9CwqbKol76hjfECgYEAkFuI/TUb/DVZnQ6up/2zVLB/Ci45Mi+0ZIG9dNtVeEsf5b4zh82xcy2L50VOk/4ow68tdKlmN55sSNGS+JtzNTSktxdvd+MakteEqSKyks4Gzpze2+qa8UjrcPEury0dNSRr2HIJZZQiG4BXCH8GVw/pDWeSRkSo9idVMbSDizUCgYEApkv53v/HhDQUuBPdapaDGSVPKdhh4mLAX5s6NYaGaRQ84n2fkek96tNg/Qx8pDJPZrghSNDxMqS0m9Uc4svb0mNQxPXJeSxdZDlOaYA+VxjhbKuauN/0BIpaB71Do3j0IqmjnGAbaqlaPd97tCK4VsA4NnzOH7cvr8FH9CYYR2U=";
    const TEST_PUBLIC_KEY: &str = "MIIBCgKCAQEAmbXeWS/CESvDJqGc+yRyPIWA5dO5jKTuKjaugzrOKxMwbquuGA2ClzX+rAIts/X2ix96LU3LVIeoB5/g351vyvMeOzUmiMDVWhOI8WnvOBhUqZJRwFGvNZi/1eQ03H7v5G0j2wzxu1wrA0qnoo/i9SdOmD4mNBjQxU8JlJ5Z6k59IE2EOoPo5rOqRWpE+dHH09ZKoH+rVyC9qogMEVY4RMWf/VsBPQpAlomQ82YDPWZSmdiDQyVhay7HLAIeiT8kzisaEPlh7RwHUaSMy7ubK4nI9SylxsZFW6uYmuiUy/pRzyCx1FzO6OC2DjrKEfRKJrZQf1dYkgeRN+wEHJspzQIDAQAB";
    pub const TEST_ISSUER: &str = "https://auth.example.test/tenant/";

    pub fn security_test_client() -> LogtoValidationClient {
        let client = LogtoValidationClient::new("https://unused.test", "old".into())
            .unwrap()
            .with_oidc_validation(
                TEST_ISSUER.into(),
                "stalwart".into(),
                format!("{TEST_ISSUER}jwks/"),
            )
            .unwrap();
        {
            let mut keys = client.jwks.write().unwrap();
            keys.keys.insert(
                "test-key".into(),
                DecodingKey::from_rsa_der(
                    &base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        TEST_PUBLIC_KEY,
                    )
                    .unwrap(),
                ),
            );
            keys.fetched_at = Some(Instant::now());
        }
        client
    }

    pub fn security_test_token(subject: &str, issuer: &str, audience: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        signed_test_claims(&serde_json::json!({
            "iss": issuer, "aud": audience, "sub": subject, "exp": now + 300
        }))
    }

    fn signed_test_claims(claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("test-key".into());
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_rsa_der(
                &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, TEST_KEY)
                    .unwrap(),
            ),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn oidc_override_requires_expiry_and_subject_and_accepts_audience_membership() {
        let client = security_test_client();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({
            "iss": TEST_ISSUER, "aud": ["another-api", "stalwart"],
            "sub": "alice", "exp": now + 300
        });
        assert!(
            client
                .validate_token(&signed_test_claims(&claims))
                .await
                .unwrap()
                .is_some()
        );
        for missing in ["sub", "exp", "iss", "aud"] {
            let mut invalid = claims.clone();
            invalid.as_object_mut().unwrap().remove(missing);
            assert!(
                client
                    .validate_token(&signed_test_claims(&invalid))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let mut expired = claims;
        expired["exp"] = serde_json::json!(now - 300);
        assert!(
            client
                .validate_token(&signed_test_claims(&expired))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn security_oidc_overrides_preserve_issuer_and_enforce_audience_and_signature() {
        let client = security_test_client();
        let valid = security_test_token("alice", TEST_ISSUER, "stalwart");
        assert_eq!(
            client
                .validate_token(&valid)
                .await
                .unwrap()
                .unwrap()
                .user_id,
            "alice"
        );
        for token in [
            security_test_token("alice", TEST_ISSUER.trim_end_matches('/'), "stalwart"),
            security_test_token("alice", TEST_ISSUER, "mcp-mail"),
        ] {
            assert!(client.validate_token(&token).await.unwrap().is_none());
        }
        let mut parts: Vec<String> = valid.split('.').map(str::to_owned).collect();
        let first = if parts[2].starts_with('A') { "B" } else { "A" };
        parts[2].replace_range(..1, first);
        assert!(
            client
                .validate_token(&parts.join("."))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn security_oidc_overrides_reject_insecure_endpoints_and_empty_audience() {
        for (issuer, audience, jwks) in [
            ("http://auth.test/", "stalwart", "https://auth.test/jwks"),
            (
                "https://auth.test/?tenant=one",
                "stalwart",
                "https://auth.test/jwks",
            ),
            (
                "https://auth.test/#fragment",
                "stalwart",
                "https://auth.test/jwks",
            ),
            (
                "https://auth.test/",
                "stalwart",
                "https://auth.test/jwks#fragment",
            ),
            ("https://auth.test/", "stalwart", "http://auth.test/jwks"),
            (
                "https://user:password@auth.test/",
                "stalwart",
                "https://auth.test/jwks",
            ),
            ("https://auth.test/", " ", "https://auth.test/jwks"),
        ] {
            assert!(
                LogtoValidationClient::new("https://unused.test", "old".into())
                    .unwrap()
                    .with_oidc_validation(issuer.into(), audience.into(), jwks.into())
                    .is_err()
            );
        }
    }
}
