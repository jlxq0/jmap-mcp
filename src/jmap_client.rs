//! Minimal JMAP (RFC 8620/8621) client over `reqwest`, talking to Stalwart.
//!
//! Replaces matrix-mcp's `matrix_client.rs`. There is no per-user crypto
//! store, no device, no sync loop — JMAP is a request/response JSON API and
//! the user's Logto bearer is the only credential, forwarded verbatim on
//! every call (pass-through model).
//!
//! Per-token we cache only the discovered Session resource (apiUrl,
//! account id, blob URL templates). Everything else is stateless.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

/// JMAP Mail capability URN — used to resolve the primary mail account id.
pub const CAP_CORE: &str = "urn:ietf:params:jmap:core";
pub const CAP_MAIL: &str = "urn:ietf:params:jmap:mail";
pub const CAP_SUBMISSION: &str = "urn:ietf:params:jmap:submission";

/// How long a discovered Session is cached before re-fetching.
/// `from_secs(3600)` not `from_hours(1)`: the unit constructors are unstable
/// on our pinned Rust 1.93 toolchain.
#[allow(unknown_lints, clippy::duration_suboptimal_units)]
const SESSION_TTL: Duration = Duration::from_secs(3600);
const SESSION_CAP: usize = 256;

#[derive(Debug, Error)]
pub enum JmapError {
    #[error("not authenticated to Stalwart (token expired or rejected)")]
    Unauthorized,
    #[error("JMAP transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JMAP endpoint returned non-2xx: {status}")]
    Upstream { status: u16 },
    #[error("JMAP method error: {error_type}{}", .description.as_deref().map(|d| format!(" — {d}")).unwrap_or_default())]
    Method {
        error_type: String,
        description: Option<String>,
    },
    #[error("unexpected JMAP response shape: {0}")]
    Parse(String),
    #[error("attachment exceeds the configured size cap")]
    TooLarge,
}

/// The JMAP Session resource (subset we use).
#[derive(Clone, Debug, Deserialize)]
pub struct JmapSession {
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "downloadUrl")]
    pub download_url: String,
    #[serde(rename = "uploadUrl")]
    pub upload_url: String,
    #[serde(rename = "primaryAccounts")]
    pub primary_accounts: HashMap<String, String>,
    #[serde(default)]
    pub username: Option<String>,
}

impl JmapSession {
    /// Primary mail account id, if the session advertises the mail capability.
    pub fn mail_account_id(&self) -> Option<&str> {
        self.primary_accounts.get(CAP_MAIL).map(String::as_str)
    }

    /// Whether this session belongs to somebody.
    ///
    /// Stalwart returns **200** with a capabilities-only document when no
    /// `Authorization` header is sent at all, and that document parses into
    /// this struct without error: `primary_accounts` `{}` and `username` `""`.
    /// So "the fetch succeeded" cannot distinguish a valid credential from a
    /// forgotten one, and this is the predicate that can. Measured against
    /// `jmap.kampong.social` 2026-08-28.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        !self.primary_accounts.is_empty()
            || self
                .username
                .as_deref()
                .is_some_and(|u| !u.trim().is_empty())
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlobUploadResponse {
    #[serde(rename = "blobId")]
    pub blob_id: String,
    #[serde(rename = "type")]
    pub content_type: String,
    pub size: u64,
}

#[derive(Clone)]
pub struct JmapClient {
    http: reqwest::Client,
    discovery_url: String,
    sessions: Arc<RwLock<HashMap<[u8; 32], CachedSession>>>,
}

#[allow(clippy::missing_fields_in_debug)] // intentionally redacts session/token state
impl std::fmt::Debug for JmapClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmapClient")
            .field("discovery_url", &self.discovery_url)
            .finish()
    }
}

#[derive(Clone)]
struct CachedSession {
    session: JmapSession,
    cached_at: Instant,
}

impl JmapClient {
    /// `stalwart_base` is the Stalwart host base; the JMAP session resource
    /// is discovered at `{base}/.well-known/jmap`. When `connect_ip` is set,
    /// DNS for the base host is overridden to that IP on port 443 — keeping
    /// `Host`/SNI = the public hostname (TLS + session URLs stay valid) while
    /// dialling the in-cluster Service IP to avoid `LoadBalancer` hairpin NAT.
    pub fn new(stalwart_base: &str, connect_ip: Option<&str>) -> Result<Self> {
        let base = stalwart_base.trim_end_matches('/');
        let discovery_url = format!("{base}/.well-known/jmap");
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("jmap-mcp/", env!("CARGO_PKG_VERSION")));
        if let Some(ip) = connect_ip {
            let host = url::Url::parse(base)
                .ok()
                .and_then(|u| u.host_str().map(ToOwned::to_owned))
                .context("cannot parse host from Stalwart base URL for connect-IP override")?;
            let addr: std::net::IpAddr = ip
                .parse()
                .context("JMAP_MCP_STALWART_CONNECT_IP is not a valid IP")?;
            builder = builder.resolve(&host, std::net::SocketAddr::new(addr, 443));
        }
        let http = builder.build().context("build reqwest client")?;
        Ok(Self {
            http,
            discovery_url,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Fetch (and cache) the JMAP Session for this credential.
    ///
    /// `token` is the **complete `Authorization` header value**, scheme
    /// included, as produced by `AccessToken::header_value`. Every method here
    /// takes it in that form so that no call site chooses a scheme and a
    /// Stalwart app password can never go out as `Bearer`.
    ///
    /// **A success here is not proof of authentication.** Stalwart answers an
    /// *absent* `Authorization` header with **200** and a capabilities-only
    /// document that deserialises cleanly into [`JmapSession`], with empty
    /// `primary_accounts` and an empty `username`. Only a *bad* credential
    /// gives 401. Use [`JmapSession::is_authenticated`] before treating a
    /// session as evidence that a credential is good.
    pub async fn session_for(&self, token: &str) -> Result<JmapSession, JmapError> {
        let key = hash_token(token);
        if let Some(s) = self.session_lookup(&key) {
            return Ok(s);
        }
        let resp = self
            .http
            .get(&self.discovery_url)
            .header(reqwest::header::AUTHORIZATION, token)
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.evict(token);
            return Err(JmapError::Unauthorized);
        }
        if !status.is_success() {
            return Err(JmapError::Upstream {
                status: status.as_u16(),
            });
        }
        let session: JmapSession = resp
            .json()
            .await
            .map_err(|e| JmapError::Parse(format!("session resource: {e}")))?;
        self.session_insert(key, &session);
        Ok(session)
    }

    /// Primary mail account id for this token (from the cached session).
    pub async fn account_id(&self, token: &str) -> Result<String, JmapError> {
        let session = self.session_for(token).await?;
        session
            .mail_account_id()
            .map(ToOwned::to_owned)
            .ok_or_else(|| JmapError::Parse("session has no primary mail account".into()))
    }

    /// Issue a JMAP method batch. `method_calls` is a list of
    /// `(method_name, args, call_id)`; `accountId` must already be present in
    /// each method's args (use [`Self::account_id`]). Returns the
    /// `methodResponses` as `(name, payload, call_id)` tuples.
    ///
    /// A method-level `error` response surfaces as `JmapError::Method`.
    pub async fn call(
        &self,
        token: &str,
        using: &[&str],
        method_calls: Vec<(&str, Value, &str)>,
    ) -> Result<Vec<(String, Value, String)>, JmapError> {
        let session = self.session_for(token).await?;
        let calls: Vec<Value> = method_calls
            .into_iter()
            .map(|(name, args, id)| json!([name, args, id]))
            .collect();
        let body = json!({ "using": using, "methodCalls": calls });

        let resp = self
            .http
            .post(&session.api_url)
            .header(reqwest::header::AUTHORIZATION, token)
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.evict(token);
            return Err(JmapError::Unauthorized);
        }
        if !status.is_success() {
            return Err(JmapError::Upstream {
                status: status.as_u16(),
            });
        }
        let envelope: Value = resp
            .json()
            .await
            .map_err(|e| JmapError::Parse(format!("method response envelope: {e}")))?;
        let responses = envelope
            .get("methodResponses")
            .and_then(Value::as_array)
            .ok_or_else(|| JmapError::Parse("missing methodResponses array".into()))?;

        let mut out = Vec::with_capacity(responses.len());
        for r in responses {
            let arr = r
                .as_array()
                .ok_or_else(|| JmapError::Parse("methodResponse is not an array".into()))?;
            let name = arr
                .first()
                .and_then(Value::as_str)
                .ok_or_else(|| JmapError::Parse("methodResponse[0] not a string".into()))?;
            let payload = arr.get(1).cloned().unwrap_or(Value::Null);
            let call_id = arr.get(2).and_then(Value::as_str).unwrap_or("").to_owned();
            if name == "error" {
                let error_type = payload
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknownError")
                    .to_owned();
                let description = payload
                    .get("description")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                return Err(JmapError::Method {
                    error_type,
                    description,
                });
            }
            out.push((name.to_owned(), payload, call_id));
        }
        Ok(out)
    }

    /// Download a blob (attachment) via the session's `downloadUrl` template.
    /// Honors `max_bytes` against the `Content-Length` and the streamed body.
    pub async fn download_blob(
        &self,
        token: &str,
        blob_id: &str,
        content_type: &str,
        name: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, JmapError> {
        let session = self.session_for(token).await?;
        let account_id = session
            .mail_account_id()
            .ok_or_else(|| JmapError::Parse("session has no primary mail account".into()))?;
        let url = expand_download_url(
            &session.download_url,
            account_id,
            blob_id,
            content_type,
            name,
        );
        let resp = self
            .http
            .get(&url)
            .header(reqwest::header::AUTHORIZATION, token)
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.evict(token);
            return Err(JmapError::Unauthorized);
        }
        if !status.is_success() {
            return Err(JmapError::Upstream {
                status: status.as_u16(),
            });
        }
        if let Some(len) = resp.content_length()
            && len > max_bytes
        {
            return Err(JmapError::TooLarge);
        }
        let bytes = resp.bytes().await?;
        if bytes.len() as u64 > max_bytes {
            return Err(JmapError::TooLarge);
        }
        Ok(bytes.to_vec())
    }

    /// Upload raw bytes to the session's `uploadUrl` template, returning the
    /// blob id Stalwart assigned.
    pub async fn upload_blob(
        &self,
        token: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<BlobUploadResponse, JmapError> {
        let session = self.session_for(token).await?;
        let account_id = session
            .mail_account_id()
            .ok_or_else(|| JmapError::Parse("session has no primary mail account".into()))?;
        let url = session.upload_url.replace("{accountId}", account_id);
        let resp = self
            .http
            .post(&url)
            .header(reqwest::header::AUTHORIZATION, token)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(bytes)
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            self.evict(token);
            return Err(JmapError::Unauthorized);
        }
        if !status.is_success() {
            return Err(JmapError::Upstream {
                status: status.as_u16(),
            });
        }
        resp.json()
            .await
            .map_err(|e| JmapError::Parse(format!("blob upload response: {e}")))
    }

    /// Drop the cached session for a token (after a 401 from Stalwart).
    pub fn evict(&self, token: &str) {
        let key = hash_token(token);
        if let Ok(mut g) = self.sessions.write()
            && g.remove(&key).is_some()
        {
            debug!("evicted JMAP session cache entry");
        }
    }

    fn session_lookup(&self, key: &[u8; 32]) -> Option<JmapSession> {
        let g = self.sessions.read().ok()?;
        let r = g
            .get(key)
            .and_then(|c| (c.cached_at.elapsed() < SESSION_TTL).then(|| c.session.clone()));
        drop(g);
        r
    }

    fn session_insert(&self, key: [u8; 32], session: &JmapSession) {
        let Ok(mut g) = self.sessions.write() else {
            return;
        };
        if g.len() >= SESSION_CAP {
            g.retain(|_, c| c.cached_at.elapsed() < SESSION_TTL);
        }
        if g.len() >= SESSION_CAP
            && !g.contains_key(&key)
            && let Some(oldest) = g
                .iter()
                .max_by_key(|(_, cached)| cached.cached_at.elapsed())
                .map(|(key, _)| *key)
        {
            g.remove(&oldest);
        }
        g.insert(
            key,
            CachedSession {
                session: session.clone(),
                cached_at: Instant::now(),
            },
        );
    }
}

/// Expand a JMAP `downloadUrl` URI template. Stalwart uses
/// `{accountId}`, `{blobId}`, `{type}`, `{name}` placeholders.
#[allow(clippy::literal_string_with_formatting_args)] // these are URI-template placeholders, not format args
fn expand_download_url(
    template: &str,
    account_id: &str,
    blob_id: &str,
    content_type: &str,
    name: &str,
) -> String {
    template
        .replace("{accountId}", &url_escape(account_id))
        .replace("{blobId}", &url_escape(blob_id))
        .replace("{type}", &url_escape(content_type))
        .replace("{name}", &url_escape(name))
}

/// Percent-encode a path/query component (RFC 3986 unreserved kept as-is).
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn hash_token(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Warn-log a JMAP method's record-level partial failures (notCreated etc.).
pub fn log_set_failures(method: &str, payload: &Value) {
    for k in ["notCreated", "notUpdated", "notDestroyed"] {
        if let Some(obj) = payload.get(k).and_then(Value::as_object)
            && !obj.is_empty()
        {
            warn!(
                method,
                kind = k,
                count = obj.len(),
                "JMAP set partial failure"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Stalwart answers a request carrying **no** `Authorization` header with
    /// 200 and this body. It deserialises without error, so `session_for`
    /// returns `Ok` and a validator built on "the fetch succeeded" would
    /// authenticate a request whose credential was never attached.
    ///
    /// Captured from `https://jmap.kampong.social/jmap/session` on 2026-08-28.
    const UNAUTHENTICATED_SESSION: &str = r#"{
        "apiUrl": "https://jmap.kampong.social/jmap/",
        "downloadUrl": "https://jmap.kampong.social/jmap/download/{accountId}/{blobId}/{name}",
        "uploadUrl": "https://jmap.kampong.social/jmap/upload/{accountId}/",
        "primaryAccounts": {},
        "username": ""
    }"#;

    #[test]
    fn the_unauthenticated_session_parses_but_is_not_authenticated() {
        let s: JmapSession = serde_json::from_str(UNAUTHENTICATED_SESSION)
            .expect("Stalwart's no-credential 200 body must still parse; that is the trap");
        assert!(
            !s.is_authenticated(),
            "a session with no account and no username belongs to nobody"
        );
        assert_eq!(s.mail_account_id(), None);
    }

    #[test]
    fn a_real_session_is_authenticated() {
        let raw = r#"{
            "apiUrl": "https://example.test/jmap/",
            "downloadUrl": "d",
            "uploadUrl": "u",
            "primaryAccounts": {"urn:ietf:params:jmap:mail": "acct-1"},
            "username": "lucy@example.test"
        }"#;
        let s: JmapSession = serde_json::from_str(raw).unwrap();
        assert!(s.is_authenticated());
    }

    /// Either signal alone is enough, so a backend that reports only one of
    /// them still authenticates.
    #[test]
    fn either_account_or_username_is_enough() {
        let account_only = r#"{"apiUrl":"a","downloadUrl":"d","uploadUrl":"u",
            "primaryAccounts":{"urn:ietf:params:jmap:mail":"x"},"username":""}"#;
        let username_only = r#"{"apiUrl":"a","downloadUrl":"d","uploadUrl":"u",
            "primaryAccounts":{},"username":"someone@example.test"}"#;
        let blank_username = r#"{"apiUrl":"a","downloadUrl":"d","uploadUrl":"u",
            "primaryAccounts":{},"username":"   "}"#;
        assert!(
            serde_json::from_str::<JmapSession>(account_only)
                .unwrap()
                .is_authenticated()
        );
        assert!(
            serde_json::from_str::<JmapSession>(username_only)
                .unwrap()
                .is_authenticated()
        );
        assert!(
            !serde_json::from_str::<JmapSession>(blank_username)
                .unwrap()
                .is_authenticated(),
            "whitespace is not a username"
        );
    }

    #[test]
    fn download_url_template_expands() {
        let u = expand_download_url(
            "https://mail.example/jmap/download/{accountId}/{blobId}/{name}?type={type}",
            "acct1",
            "blob9",
            "image/png",
            "photo.png",
        );
        assert!(u.contains("/acct1/blob9/photo.png"));
        assert!(u.contains("type=image%2Fpng"));
    }

    #[test]
    fn url_escape_leaves_unreserved() {
        assert_eq!(url_escape("abc-1.2_3~"), "abc-1.2_3~");
        assert_eq!(url_escape("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn session_cache_is_hard_capped() {
        let client = JmapClient::new("https://mail.example.test", None).unwrap();
        let session: JmapSession = serde_json::from_value(session_body()).unwrap();
        for i in 0..=SESSION_CAP {
            let mut key = [0_u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_be_bytes());
            client.session_insert(key, &session);
        }
        assert_eq!(client.sessions.read().unwrap().len(), SESSION_CAP);
    }

    // ----- session discovery against a mock Stalwart -----

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn session_body() -> Value {
        json!({
            "apiUrl": "https://mail.example.test/jmap/",
            "downloadUrl": "https://mail.example.test/jmap/download/{accountId}/{blobId}/{name}?type={type}",
            "uploadUrl": "https://mail.example.test/jmap/upload/{accountId}/",
            "username": "julian@kampong.social",
            "primaryAccounts": { CAP_MAIL: "acct-1" }
        })
    }

    /// The data `whoami` reports comes straight off the discovered session:
    /// the account id, and the username it falls back to when the Logto
    /// token carried no `email` claim. This is the path that answered
    /// `InvalidAudience` in the 2026-08 incident.
    #[tokio::test]
    async fn session_discovery_yields_username_and_account_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .and(header("authorization", "Bearer live-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(session_body()))
            .mount(&server)
            .await;

        // The credential is now the COMPLETE header value, scheme included,
        // so the scheme cannot be chosen at a call site. The mock asserts the
        // exact bytes that go on the wire.
        let client = JmapClient::new(&server.uri(), None).unwrap();
        let session = client.session_for("Bearer live-token").await.unwrap();

        assert!(session.is_authenticated());
        assert_eq!(session.username.as_deref(), Some("julian@kampong.social"));
        assert_eq!(session.mail_account_id(), Some("acct-1"));
        assert_eq!(
            client.account_id("Bearer live-token").await.unwrap(),
            "acct-1".to_owned()
        );
    }

    /// Second call is served from cache — one upstream request only.
    #[tokio::test]
    async fn session_is_cached_per_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(session_body()))
            .expect(1)
            .mount(&server)
            .await;

        let client = JmapClient::new(&server.uri(), None).unwrap();
        client.session_for("live-token").await.unwrap();
        client.session_for("live-token").await.unwrap();
        // `expect(1)` is asserted on drop.
    }

    /// Stalwart refusing the bearer (what `requireAudience` produced) must
    /// surface as `Unauthorized`, which is what the MCP layer keys on.
    #[tokio::test]
    async fn stalwart_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = JmapClient::new(&server.uri(), None).unwrap();
        assert!(matches!(
            client.session_for("rejected-token").await,
            Err(JmapError::Unauthorized)
        ));
    }

    /// A rejection must not leave a poisoned cache entry behind.
    #[tokio::test]
    async fn unauthorized_evicts_cached_session() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(200).set_body_json(session_body()))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let client = JmapClient::new(&server.uri(), None).unwrap();
        client.session_for("tok").await.unwrap();
        assert!(client.session_lookup(&hash_token("tok")).is_some());

        // Backend now rejects: the cached session must be dropped.
        Mock::given(method("GET"))
            .and(path("/.well-known/jmap"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        client.evict("tok");
        assert!(matches!(
            client.session_for("tok").await,
            Err(JmapError::Unauthorized)
        ));
        assert!(client.session_lookup(&hash_token("tok")).is_none());
    }
}
