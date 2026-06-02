//! Spam classification tools: move emails into the Junk mailbox or back out to
//! the Inbox. Both are non-destructive `Email/set` updates that replace the
//! `mailboxIds` membership of a batch of email ids in a single round-trip.

use super::*;

// ----- mark_as_spam -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkAsSpamParams {
    /// JMAP Email ids to move into the Junk mailbox.
    pub email_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MarkAsSpamResult {
    pub email_ids: Vec<String>,
    pub moved_to_spam: u32,
}

// ----- mark_as_not_spam -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkAsNotSpamParams {
    /// JMAP Email ids to move back into the Inbox.
    pub email_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MarkAsNotSpamResult {
    pub email_ids: Vec<String>,
    pub moved_from_spam: u32,
}

#[tool_router(router = spam_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Move emails into the Junk (spam) mailbox, replacing all memberships.
    #[tool(
        description = "Mark emails as spam by moving them into the Junk mailbox, \
                       replacing all existing mailbox memberships.",
        annotations(
            title = "Mark as spam",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn mark_as_spam(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MarkAsSpamParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("mark_as_spam", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.email_ids.is_empty() {
                return Err(ErrorData::invalid_params(
                    "email_ids: must not be empty",
                    None,
                ));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let junk = Self::role_mailbox(&mailboxes, "junk")
                .ok_or_else(|| ErrorData::invalid_params("no Junk mailbox found", None))?;
            let patch = json!({ "mailboxIds": { junk: true } });
            let moved_to_spam = self
                .replace_mailboxes(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&MarkAsSpamResult {
                email_ids: params.email_ids.clone(),
                moved_to_spam,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "mark_as_spam", None, &result);
        emit_tool_audit("mark_as_spam", &user, None, started, None, &span, &result);
        result
    }

    /// Move emails out of Junk and back into the Inbox, replacing memberships.
    #[tool(
        description = "Mark emails as not spam by moving them back into the Inbox, \
                       replacing all existing mailbox memberships.",
        annotations(
            title = "Mark as not spam",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn mark_as_not_spam(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MarkAsNotSpamParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("mark_as_not_spam", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.email_ids.is_empty() {
                return Err(ErrorData::invalid_params(
                    "email_ids: must not be empty",
                    None,
                ));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let inbox = Self::role_mailbox(&mailboxes, "inbox")
                .ok_or_else(|| ErrorData::invalid_params("no Inbox mailbox found", None))?;
            let patch = json!({ "mailboxIds": { inbox: true } });
            let moved_from_spam = self
                .replace_mailboxes(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&MarkAsNotSpamResult {
                email_ids: params.email_ids.clone(),
                moved_from_spam,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "mark_as_not_spam", None, &result);
        emit_tool_audit(
            "mark_as_not_spam",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

impl JmapMcpService {
    /// Apply the same `Email/set` `mailboxIds`-replacing `patch` to every id in
    /// a single round-trip, log record-level failures, and return the count of
    /// successfully-updated records.
    async fn replace_mailboxes(
        &self,
        token: &str,
        account_id: &str,
        email_ids: &[String],
        patch: &Value,
    ) -> Result<u32, ErrorData> {
        let mut update = serde_json::Map::new();
        for id in email_ids {
            update.insert(id.clone(), patch.clone());
        }
        let resps = self
            .jmap
            .call(
                token,
                &[CAP_CORE, CAP_MAIL],
                vec![(
                    "Email/set",
                    json!({ "accountId": account_id, "update": Value::Object(update) }),
                    "e",
                )],
            )
            .await
            .map_err(map_jmap_err)?;
        let payload = resps
            .into_iter()
            .find(|(n, _, _)| n == "Email/set")
            .map_or(Value::Null, |(_, p, _)| p);
        crate::jmap_client::log_set_failures("Email/set", &payload);
        let count = payload
            .get("updated")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len);
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }
}
