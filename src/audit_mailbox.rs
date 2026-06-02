//! Self-audit to a designated JMAP mailbox.
//!
//! matrix-mcp posted an `m.notice` to a Matrix "audit room" for every write
//! it made on the user's behalf. The JMAP analogue: append an envelope-only
//! audit email (via `Email/set create`) to a mailbox the user designates with
//! the `set_audit_mailbox` tool. Fire-and-forget — a failure to write the
//! audit note must never fail the underlying tool call.
//!
//! Body is envelope-only: `jmap-mcp: {method} → {resource} outcome={outcome}`.
//! No email contents, recipients, or subjects of the audited action leak in.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde_json::json;
use tracing::{debug, warn};

use crate::jmap_client::{CAP_CORE, CAP_MAIL, JmapClient};

/// Per-user designated audit mailbox, keyed by stable Logto `user_id`.
/// In-memory only: a designation is lost on pod roll, which is acceptable —
/// the user re-runs `set_audit_mailbox` (the same posture matrix-mcp had,
/// where the audit room lived in volatile account data).
#[derive(Clone, Default)]
pub struct AuditMailboxRegistry {
    map: Arc<RwLock<HashMap<String, String>>>,
}

impl AuditMailboxRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, user_id: &str, mailbox_id: &str) {
        if let Ok(mut g) = self.map.write() {
            g.insert(user_id.to_owned(), mailbox_id.to_owned());
        }
    }

    #[must_use]
    pub fn get(&self, user_id: &str) -> Option<String> {
        self.map.read().ok().and_then(|g| g.get(user_id).cloned())
    }
}

/// Append an envelope-only audit email to `mailbox_id`. Fire-and-forget:
/// spawn this with `tokio::spawn`; it logs on failure and never returns an
/// error to the caller.
pub async fn emit_audit_message(
    jmap: JmapClient,
    token: String,
    mailbox_id: String,
    from_addr: String,
    method: &'static str,
    resource: Option<String>,
    outcome: &'static str,
) {
    let account_id = match jmap.account_id(&token).await {
        Ok(a) => a,
        Err(e) => {
            warn!(error = %e, "audit: could not resolve account id; skipping note");
            return;
        }
    };
    let resource_str = resource.as_deref().unwrap_or("-");
    let subject = format!("jmap-mcp audit: {method}");
    let body = format!("jmap-mcp: {method} → {resource_str} outcome={outcome}");

    let create = json!({
        "accountId": account_id,
        "create": {
            "note": {
                "mailboxIds": { mailbox_id: true },
                "keywords": { "$seen": true },
                "from": [ { "email": from_addr } ],
                "to": [ { "email": from_addr } ],
                "subject": subject,
                "bodyValues": { "b": { "value": body, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ]
            }
        }
    });

    match jmap
        .call(
            &token,
            &[CAP_CORE, CAP_MAIL],
            vec![("Email/set", create, "a")],
        )
        .await
    {
        Ok(_) => debug!(method, "audit note appended"),
        Err(e) => warn!(error = %e, method, "audit: Email/set failed; note dropped"),
    }
}
