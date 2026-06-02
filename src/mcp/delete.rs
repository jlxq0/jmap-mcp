//! Destructive email tools: move-to-trash, permanent destroy, and emptying
//! the Trash / Spam folders. Every tool is a write: it rate-limits on the
//! Write category, spawns a fire-and-forget audit note, and emits a tool
//! audit record.

use super::*;

// ----- delete_email -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteEmailParams {
    /// JMAP Email ids to move to the Trash mailbox.
    pub email_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeleteEmailResult {
    pub email_ids: Vec<String>,
    pub moved_to_trash: u32,
}

// ----- permanently_delete_email -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PermanentlyDeleteEmailParams {
    /// JMAP Email ids to destroy permanently (cannot be undone).
    pub email_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct PermanentlyDeleteEmailResult {
    pub email_ids: Vec<String>,
    pub destroyed: u32,
}

// ----- empty_trash / empty_spam -----

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct EmptyMailboxResult {
    pub destroyed_count: u32,
}

#[tool_router(router = delete_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Move one or more emails to the Trash mailbox.
    #[tool(
        description = "Move emails to the Trash mailbox by id. Reversible until the trash is \
                       emptied. Errors if the account has no Trash mailbox.",
        annotations(
            title = "Delete email (move to trash)",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn delete_email(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DeleteEmailParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("delete_email", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.email_ids.is_empty() {
                return Err(ErrorData::invalid_params(
                    "`email_ids` must not be empty",
                    None,
                ));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let trash = Self::role_mailbox(&mailboxes, "trash")
                .ok_or_else(|| ErrorData::internal_error("no Trash mailbox found", None))?;

            let mut update = serde_json::Map::new();
            for id in &params.email_ids {
                update.insert(id.clone(), json!({ "mailboxIds": { trash.clone(): true } }));
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Email/set",
                        json!({ "accountId": account_id, "update": Value::Object(update) }),
                        "e",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;

            let moved_to_trash = resps
                .iter()
                .find(|(n, _, _)| n == "Email/set")
                .and_then(|(_, p, _)| p.get("updated").and_then(Value::as_object))
                .map_or(0, serde_json::Map::len);

            structured_result(&DeleteEmailResult {
                email_ids: params.email_ids.clone(),
                moved_to_trash: u32::try_from(moved_to_trash).unwrap_or(u32::MAX),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "delete_email", None, &result);
        emit_tool_audit("delete_email", &user, None, started, None, &span, &result);
        result
    }

    /// Permanently destroy one or more emails (irreversible).
    #[tool(
        description = "Permanently delete emails by id. This is irreversible — the messages are \
                       destroyed outright, not moved to Trash.",
        annotations(
            title = "Permanently delete email",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn permanently_delete_email(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<PermanentlyDeleteEmailParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("permanently_delete_email", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.email_ids.is_empty() {
                return Err(ErrorData::invalid_params(
                    "`email_ids` must not be empty",
                    None,
                ));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Email/set",
                        json!({ "accountId": account_id, "destroy": params.email_ids }),
                        "e",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;

            let destroyed = resps
                .iter()
                .find(|(n, _, _)| n == "Email/set")
                .and_then(|(_, p, _)| p.get("destroyed").and_then(Value::as_array))
                .map_or(0, Vec::len);

            structured_result(&PermanentlyDeleteEmailResult {
                email_ids: params.email_ids.clone(),
                destroyed: u32::try_from(destroyed).unwrap_or(u32::MAX),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "permanently_delete_email", None, &result);
        emit_tool_audit(
            "permanently_delete_email",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Permanently destroy every email in the Trash mailbox.
    #[tool(
        description = "Empty the Trash mailbox: permanently destroy every message it contains. \
                       Irreversible. Errors if the account has no Trash mailbox.",
        annotations(
            title = "Empty trash",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn empty_trash(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("empty_trash", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let trash = Self::role_mailbox(&mailboxes, "trash")
                .ok_or_else(|| ErrorData::internal_error("no Trash mailbox found", None))?;
            let destroyed = self.empty_mailbox(&token.0, &account_id, &trash).await?;
            structured_result(&EmptyMailboxResult {
                destroyed_count: destroyed,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "empty_trash", None, &result);
        emit_tool_audit("empty_trash", &user, None, started, None, &span, &result);
        result
    }

    /// Permanently destroy every email in the Spam (junk) mailbox.
    #[tool(
        description = "Empty the Spam mailbox: permanently destroy every message it contains. \
                       Irreversible. Errors if the account has no Spam mailbox.",
        annotations(
            title = "Empty spam",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn empty_spam(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("empty_spam", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let junk = Self::role_mailbox(&mailboxes, "junk")
                .ok_or_else(|| ErrorData::internal_error("no Spam mailbox found", None))?;
            let destroyed = self.empty_mailbox(&token.0, &account_id, &junk).await?;
            structured_result(&EmptyMailboxResult {
                destroyed_count: destroyed,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "empty_spam", None, &result);
        emit_tool_audit("empty_spam", &user, None, started, None, &span, &result);
        result
    }
}

impl JmapMcpService {
    /// Permanently destroy every email in `mailbox_id` in one round-trip:
    /// `Email/query` (filtered to the mailbox) feeds `Email/set`'s `#destroy`
    /// back-reference. Returns the count of destroyed ids.
    async fn empty_mailbox(
        &self,
        token: &str,
        account_id: &str,
        mailbox_id: &str,
    ) -> Result<u32, ErrorData> {
        let resps = self
            .jmap
            .call(
                token,
                &[CAP_CORE, CAP_MAIL],
                vec![
                    (
                        "Email/query",
                        json!({
                            "accountId": account_id,
                            "filter": { "inMailbox": mailbox_id },
                            "limit": 1000
                        }),
                        "q",
                    ),
                    (
                        "Email/set",
                        json!({
                            "accountId": account_id,
                            "#destroy": {
                                "resultOf": "q",
                                "name": "Email/query",
                                "path": "/ids"
                            }
                        }),
                        "e",
                    ),
                ],
            )
            .await
            .map_err(map_jmap_err)?;
        let destroyed = resps
            .iter()
            .find(|(n, _, _)| n == "Email/set")
            .and_then(|(_, p, _)| p.get("destroyed").and_then(Value::as_array))
            .map_or(0, Vec::len);
        Ok(u32::try_from(destroyed).unwrap_or(u32::MAX))
    }
}
