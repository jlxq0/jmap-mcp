//! Mailbox (folder) management tools: create, rename, delete, and
//! subscribe/unsubscribe. All are `Mailbox/set` writes against the caller's
//! primary mail account, audited fire-and-forget like every other write.

use super::*;

// ----- create_mailbox -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateMailboxParams {
    /// Display name for the new mailbox (folder).
    pub name: String,
    /// Optional parent mailbox id to nest under. Omit for a top-level folder.
    #[serde(default)]
    pub parent_id: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CreateMailboxResult {
    pub mailbox_id: String,
    pub name: String,
}

// ----- rename_mailbox -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RenameMailboxParams {
    /// JMAP Mailbox id to rename (from `list_mailboxes`).
    pub mailbox_id: String,
    /// New display name for the mailbox.
    pub new_name: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct RenameMailboxResult {
    pub mailbox_id: String,
    pub name: String,
}

// ----- delete_mailbox -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DeleteMailboxParams {
    /// JMAP Mailbox id to delete (from `list_mailboxes`).
    pub mailbox_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DeleteMailboxResult {
    pub mailbox_id: String,
}

// ----- subscribe_mailbox / unsubscribe_mailbox -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SubscribeMailboxParams {
    /// JMAP Mailbox id to (un)subscribe (from `list_mailboxes`).
    pub mailbox_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SubscribeMailboxResult {
    pub mailbox_id: String,
    pub is_subscribed: bool,
}

#[tool_router(router = mailbox_mgmt_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Create a new mailbox (folder), optionally nested under a parent.
    #[tool(
        description = "Create a new mailbox (folder), optionally nested under a parent mailbox id.",
        annotations(
            title = "Create mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn create_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<CreateMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("create_mailbox", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let mut create = json!({ "name": params.name });
            if let Some(parent) = &params.parent_id {
                create["parentId"] = Value::String(parent.clone());
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Mailbox/set",
                        json!({ "accountId": account_id, "create": { "m": create } }),
                        "m",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let payload = resps
                .iter()
                .find(|(n, _, _)| n == "Mailbox/set")
                .map(|(_, p, _)| p)
                .ok_or_else(|| ErrorData::internal_error("Mailbox/set: no response", None))?;
            let mailbox_id = payload
                .get("created")
                .and_then(|c| c.get("m"))
                .and_then(|m| m.get("id"))
                .and_then(Value::as_str)
                .ok_or_else(|| mailbox_create_failure(payload))?
                .to_owned();
            structured_result(&CreateMailboxResult {
                mailbox_id,
                name: params.name.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "create_mailbox", None, &result);
        emit_tool_audit("create_mailbox", &user, None, started, None, &span, &result);
        result
    }

    /// Rename an existing mailbox (folder).
    #[tool(
        description = "Rename an existing mailbox (folder) by id.",
        annotations(
            title = "Rename mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn rename_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<RenameMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let mbox = params.mailbox_id.clone();
        let span = make_tool_span("rename_mailbox", &user, Some(&mbox));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Mailbox/set",
                        json!({
                            "accountId": account_id,
                            "update": { params.mailbox_id.clone(): { "name": params.new_name } }
                        }),
                        "m",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let payload = resps
                .iter()
                .find(|(n, _, _)| n == "Mailbox/set")
                .map(|(_, p, _)| p)
                .ok_or_else(|| ErrorData::internal_error("Mailbox/set: no response", None))?;
            if !set_updated(payload, &params.mailbox_id) {
                return Err(mailbox_update_failure(payload, &params.mailbox_id));
            }
            structured_result(&RenameMailboxResult {
                mailbox_id: params.mailbox_id.clone(),
                name: params.new_name.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "rename_mailbox", Some(mbox.clone()), &result);
        emit_tool_audit(
            "rename_mailbox",
            &user,
            Some(&mbox),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Permanently delete a mailbox (folder).
    #[tool(
        description = "Permanently delete a mailbox (folder) by id. Destructive: removes the \
                       folder and is rejected by the server if it still contains messages or \
                       child folders.",
        annotations(
            title = "Delete mailbox",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false
        )
    )]
    async fn delete_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DeleteMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let mbox = params.mailbox_id.clone();
        let span = make_tool_span("delete_mailbox", &user, Some(&mbox));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Mailbox/set",
                        json!({
                            "accountId": account_id,
                            "destroy": [params.mailbox_id.clone()]
                        }),
                        "m",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let payload = resps
                .iter()
                .find(|(n, _, _)| n == "Mailbox/set")
                .map(|(_, p, _)| p)
                .ok_or_else(|| ErrorData::internal_error("Mailbox/set: no response", None))?;
            let destroyed = payload
                .get("destroyed")
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.iter()
                        .any(|v| v.as_str() == Some(params.mailbox_id.as_str()))
                });
            if !destroyed {
                return Err(mailbox_destroy_failure(payload, &params.mailbox_id));
            }
            structured_result(&DeleteMailboxResult {
                mailbox_id: params.mailbox_id.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "delete_mailbox", Some(mbox.clone()), &result);
        emit_tool_audit(
            "delete_mailbox",
            &user,
            Some(&mbox),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Subscribe to a mailbox (folder).
    #[tool(
        description = "Subscribe to a mailbox (folder) so it appears in subscribed-folder listings.",
        annotations(
            title = "Subscribe mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn subscribe_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SubscribeMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        self.set_subscription(ctx, params.mailbox_id, true, "subscribe_mailbox")
            .await
    }

    /// Unsubscribe from a mailbox (folder).
    #[tool(
        description = "Unsubscribe from a mailbox (folder) so it no longer appears in \
                       subscribed-folder listings.",
        annotations(
            title = "Unsubscribe mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn unsubscribe_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SubscribeMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        self.set_subscription(ctx, params.mailbox_id, false, "unsubscribe_mailbox")
            .await
    }
}

impl JmapMcpService {
    /// Shared body for subscribe/unsubscribe: a `Mailbox/set` update of
    /// `isSubscribed`.
    async fn set_subscription(
        &self,
        ctx: RequestContext<RoleServer>,
        mailbox_id: String,
        subscribe: bool,
        tool: &'static str,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span(tool, &user, Some(&mailbox_id));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Mailbox/set",
                        json!({
                            "accountId": account_id,
                            "update": { mailbox_id.clone(): { "isSubscribed": subscribe } }
                        }),
                        "m",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let payload = resps
                .iter()
                .find(|(n, _, _)| n == "Mailbox/set")
                .map(|(_, p, _)| p)
                .ok_or_else(|| ErrorData::internal_error("Mailbox/set: no response", None))?;
            if !set_updated(payload, &mailbox_id) {
                return Err(mailbox_update_failure(payload, &mailbox_id));
            }
            structured_result(&SubscribeMailboxResult {
                mailbox_id: mailbox_id.clone(),
                is_subscribed: subscribe,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, tool, Some(mailbox_id.clone()), &result);
        emit_tool_audit(
            tool,
            &user,
            Some(&mailbox_id),
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

/// Whether a `Mailbox/set` response's `updated` map acknowledges `id`.
/// Stalwart lists updated ids as keys of the `updated` object (values may be
/// null), so presence of the key is the success signal.
fn set_updated(payload: &Value, id: &str) -> bool {
    payload
        .get("updated")
        .and_then(Value::as_object)
        .is_some_and(|o| o.contains_key(id))
}

/// Build an error from a `Mailbox/set` that created nothing (surfacing the
/// `notCreated` reason when present).
fn mailbox_create_failure(payload: &Value) -> ErrorData {
    let reason = payload.get("notCreated").map_or_else(
        || "Mailbox/set created no mailbox".to_owned(),
        std::string::ToString::to_string,
    );
    ErrorData::internal_error(format!("create mailbox failed: {reason}"), None)
}

/// Build an error from a `Mailbox/set` that failed to update `id` (surfacing
/// the per-id `notUpdated` reason when present).
fn mailbox_update_failure(payload: &Value, id: &str) -> ErrorData {
    let reason = payload
        .get("notUpdated")
        .and_then(|n| n.get(id))
        .map(std::string::ToString::to_string)
        .or_else(|| {
            payload
                .get("notUpdated")
                .map(std::string::ToString::to_string)
        })
        .unwrap_or_else(|| "Mailbox/set updated nothing".to_owned());
    ErrorData::internal_error(format!("update mailbox failed: {reason}"), None)
}

/// Build an error from a `Mailbox/set` that failed to destroy `id` (surfacing
/// the per-id `notDestroyed` reason when present).
fn mailbox_destroy_failure(payload: &Value, id: &str) -> ErrorData {
    let reason = payload
        .get("notDestroyed")
        .and_then(|n| n.get(id))
        .map(std::string::ToString::to_string)
        .or_else(|| {
            payload
                .get("notDestroyed")
                .map(std::string::ToString::to_string)
        })
        .unwrap_or_else(|| "Mailbox/set destroyed nothing".to_owned());
    ErrorData::internal_error(format!("delete mailbox failed: {reason}"), None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn set_updated_detects_key() {
        let p = json!({ "updated": { "mb1": null } });
        assert!(set_updated(&p, "mb1"));
        assert!(!set_updated(&p, "mb2"));
        assert!(!set_updated(&json!({}), "mb1"));
    }

    #[test]
    fn destroy_failure_surfaces_reason() {
        let p = json!({ "notDestroyed": { "mb1": { "type": "mailboxHasChild" } } });
        let e = mailbox_destroy_failure(&p, "mb1");
        assert!(e.message.contains("mailboxHasChild"));
    }

    #[test]
    fn create_failure_surfaces_reason() {
        let p = json!({ "notCreated": { "m": { "type": "invalidProperties" } } });
        let e = mailbox_create_failure(&p);
        assert!(e.message.contains("invalidProperties"));
    }
}
