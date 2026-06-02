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
#[allow(clippy::duration_suboptimal_units)]
const SESSION_TTL: Duration = Duration::from_secs(3600);
const SESSION_SOFT_CAP: usize = 256;

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
    /// is discovered at `{base}/.well-known/jmap`.
    pub fn new(stalwart_base: &str) -> Result<Self> {
        let base = stalwart_base.trim_end_matches('/');
        let discovery_url = format!("{base}/.well-known/jmap");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("jmap-mcp/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            http,
            discovery_url,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Fetch (and cache) the JMAP Session for this token.
    pub async fn session_for(&self, token: &str) -> Result<JmapSession, JmapError> {
        let key = hash_token(token);
        if let Some(s) = self.session_lookup(&key) {
            return Ok(s);
        }
        let resp = self
            .http
            .get(&self.discovery_url)
            .bearer_auth(token)
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
            .bearer_auth(token)
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
        let resp = self.http.get(&url).bearer_auth(token).send().await?;
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
            .bearer_auth(token)
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
        if g.len() >= SESSION_SOFT_CAP {
            g.retain(|_, c| c.cached_at.elapsed() < SESSION_TTL);
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
}
