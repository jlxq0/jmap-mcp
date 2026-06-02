//! Email flag, keyword, and placement tools: mark read/unread, set/unset
//! flags and keywords, and move/copy messages between mailboxes. All are
//! non-destructive `Email/set` updates applied to a batch of email ids in a
//! single round-trip; the `mark_*`/keyword/flag variants are idempotent.

use super::*;

// ----- mark_read / mark_unread -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MarkSeenParams {
    /// JMAP Email ids to update.
    pub email_ids: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MarkSeenResult {
    pub email_ids: Vec<String>,
    pub updated: u32,
}

// ----- set_flag / unset_flag -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FlagParams {
    /// JMAP Email ids to update.
    pub email_ids: Vec<String>,
    /// Flag name: `flagged`, `answered`, `forwarded`, or a raw IMAP keyword.
    pub flag: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct FlagResult {
    pub email_ids: Vec<String>,
    pub flag: String,
    pub updated: u32,
}

// ----- set_keyword / unset_keyword -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KeywordParams {
    /// JMAP Email ids to update.
    pub email_ids: Vec<String>,
    /// Raw JMAP keyword to set or clear (e.g. `$flagged`, `$seen`, `custom`).
    pub keyword: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct KeywordResult {
    pub email_ids: Vec<String>,
    pub keyword: String,
    pub updated: u32,
}

// ----- move_to_mailbox -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MoveParams {
    /// JMAP Email ids to relocate.
    pub email_ids: Vec<String>,
    /// JMAP Mailbox id the emails should belong to (sole membership).
    pub target_mailbox_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct MoveResult {
    pub email_ids: Vec<String>,
    pub target_mailbox_id: String,
    pub moved: u32,
}

// ----- copy_to_mailbox -----

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct CopyResult {
    pub email_ids: Vec<String>,
    pub target_mailbox_id: String,
    pub copied: u32,
}

#[tool_router(router = flags_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Mark emails as read (`$seen`).
    #[tool(
        description = "Mark emails as read by adding the $seen keyword. Idempotent.",
        annotations(
            title = "Mark read",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn mark_read(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MarkSeenParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("mark_read", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let updated = self
                .email_set_update(
                    &token.0,
                    &account_id,
                    &params.email_ids,
                    &json!({ "keywords/$seen": true }),
                )
                .await?;
            structured_result(&MarkSeenResult {
                email_ids: params.email_ids.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "mark_read", None, &result);
        emit_tool_audit("mark_read", &user, None, started, None, &span, &result);
        result
    }

    /// Mark emails as unread (clear `$seen`).
    #[tool(
        description = "Mark emails as unread by clearing the $seen keyword. Idempotent.",
        annotations(
            title = "Mark unread",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn mark_unread(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MarkSeenParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("mark_unread", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let updated = self
                .email_set_update(
                    &token.0,
                    &account_id,
                    &params.email_ids,
                    &json!({ "keywords/$seen": Value::Null }),
                )
                .await?;
            structured_result(&MarkSeenResult {
                email_ids: params.email_ids.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "mark_unread", None, &result);
        emit_tool_audit("mark_unread", &user, None, started, None, &span, &result);
        result
    }

    /// Set a flag (mapped to a keyword) on emails.
    #[tool(
        description = "Set a flag on emails. Known flags map to keywords: \
                       flagged→$flagged, answered→$answered, forwarded→$forwarded; \
                       any other value is used verbatim as the keyword. Idempotent.",
        annotations(
            title = "Set flag",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn set_flag(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<FlagParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("set_flag", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let kw = flag_keyword(&params.flag);
            let patch = json!({ format!("keywords/{kw}"): true });
            let updated = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&FlagResult {
                email_ids: params.email_ids.clone(),
                flag: params.flag.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "set_flag", None, &result);
        emit_tool_audit("set_flag", &user, None, started, None, &span, &result);
        result
    }

    /// Clear a flag (mapped to a keyword) from emails.
    #[tool(
        description = "Clear a flag from emails. Known flags map to keywords: \
                       flagged→$flagged, answered→$answered, forwarded→$forwarded; \
                       any other value is used verbatim as the keyword. Idempotent.",
        annotations(
            title = "Unset flag",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn unset_flag(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<FlagParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("unset_flag", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let kw = flag_keyword(&params.flag);
            let patch = json!({ format!("keywords/{kw}"): Value::Null });
            let updated = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&FlagResult {
                email_ids: params.email_ids.clone(),
                flag: params.flag.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "unset_flag", None, &result);
        emit_tool_audit("unset_flag", &user, None, started, None, &span, &result);
        result
    }

    /// Set an arbitrary keyword on emails.
    #[tool(
        description = "Set a raw JMAP keyword (e.g. $flagged, $seen, or a custom label) \
                       on emails. Idempotent.",
        annotations(
            title = "Set keyword",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn set_keyword(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<KeywordParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("set_keyword", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let kw = &params.keyword;
            let patch = json!({ format!("keywords/{kw}"): true });
            let updated = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&KeywordResult {
                email_ids: params.email_ids.clone(),
                keyword: params.keyword.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "set_keyword", None, &result);
        emit_tool_audit("set_keyword", &user, None, started, None, &span, &result);
        result
    }

    /// Clear an arbitrary keyword from emails.
    #[tool(
        description = "Clear a raw JMAP keyword (e.g. $flagged, $seen, or a custom label) \
                       from emails. Idempotent.",
        annotations(
            title = "Unset keyword",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn unset_keyword(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<KeywordParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("unset_keyword", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let kw = &params.keyword;
            let patch = json!({ format!("keywords/{kw}"): Value::Null });
            let updated = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&KeywordResult {
                email_ids: params.email_ids.clone(),
                keyword: params.keyword.clone(),
                updated,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "unset_keyword", None, &result);
        emit_tool_audit("unset_keyword", &user, None, started, None, &span, &result);
        result
    }

    /// Move emails to a single target mailbox (replacing all memberships).
    #[tool(
        description = "Move emails into one mailbox, replacing all existing mailbox \
                       memberships with the target. Not idempotent across overlapping \
                       calls because prior memberships are discarded.",
        annotations(
            title = "Move to mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn move_to_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MoveParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let target = params.target_mailbox_id.clone();
        let span = make_tool_span("move_to_mailbox", &user, Some(&target));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let patch = json!({ "mailboxIds": { params.target_mailbox_id.clone(): true } });
            let moved = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&MoveResult {
                email_ids: params.email_ids.clone(),
                target_mailbox_id: params.target_mailbox_id.clone(),
                moved,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "move_to_mailbox", Some(target.clone()), &result);
        emit_tool_audit(
            "move_to_mailbox",
            &user,
            Some(&target),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Add emails to a target mailbox (keeping existing memberships).
    #[tool(
        description = "Copy emails into a mailbox by adding it to their mailbox \
                       memberships, leaving existing memberships intact. Idempotent.",
        annotations(
            title = "Copy to mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn copy_to_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<MoveParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let target = params.target_mailbox_id.clone();
        let span = make_tool_span("copy_to_mailbox", &user, Some(&target));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let tgt = &params.target_mailbox_id;
            let patch = json!({ format!("mailboxIds/{tgt}"): true });
            let copied = self
                .email_set_update(&token.0, &account_id, &params.email_ids, &patch)
                .await?;
            structured_result(&CopyResult {
                email_ids: params.email_ids.clone(),
                target_mailbox_id: params.target_mailbox_id.clone(),
                copied,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "copy_to_mailbox", Some(target.clone()), &result);
        emit_tool_audit(
            "copy_to_mailbox",
            &user,
            Some(&target),
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

impl JmapMcpService {
    /// Apply the same `Email/set` update `patch` to every id in `email_ids` in
    /// a single round-trip, log any record-level failures, and return the count
    /// of successfully-updated records.
    async fn email_set_update(
        &self,
        token: &str,
        account_id: &str,
        email_ids: &[String],
        patch: &Value,
    ) -> Result<u32, ErrorData> {
        if email_ids.is_empty() {
            return Err(ErrorData::invalid_params(
                "email_ids: must not be empty",
                None,
            ));
        }
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

/// Map a friendly flag name to its JMAP keyword. Known aliases expand to their
/// `$`-prefixed IMAP system keyword; anything else is treated as a raw keyword.
fn flag_keyword(flag: &str) -> String {
    match flag {
        "flagged" => "$flagged".to_owned(),
        "answered" => "$answered".to_owned(),
        "forwarded" => "$forwarded".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn flag_keyword_maps_known_aliases() {
        assert_eq!(flag_keyword("flagged"), "$flagged");
        assert_eq!(flag_keyword("answered"), "$answered");
        assert_eq!(flag_keyword("forwarded"), "$forwarded");
    }

    #[test]
    fn flag_keyword_passes_through_unknown() {
        assert_eq!(flag_keyword("$custom"), "$custom");
        assert_eq!(flag_keyword("Important"), "Important");
    }
}
