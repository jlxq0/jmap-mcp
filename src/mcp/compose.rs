//! Compose-group tools: send with attachments, reply, forward, save/update
//! drafts. All are writes (not idempotent, not destructive). They mirror the
//! `send_email` pattern from the parent module: resolve Drafts/Sent via
//! `all_mailboxes` + `role_mailbox`, resolve the sending identity, create a
//! draft with `Email/set`, then submit with `EmailSubmission/set` chaining the
//! `emailId` back-reference `#draft` and an `onSuccessUpdateEmail` patch that
//! moves the copy into Sent.

use super::*;

use base64::Engine as _;

// ----- parameter + result types -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AttachmentInput {
    /// File name to present to the recipient (e.g. `invoice.pdf`).
    pub filename: String,
    /// MIME type of the attachment (e.g. `application/pdf`).
    pub mime_type: String,
    /// Attachment bytes, standard base64-encoded.
    pub body_base64: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendWithAttachmentsParams {
    /// From address (must be one of the caller's identities).
    pub from: String,
    /// Recipient email addresses.
    pub to: Vec<String>,
    /// Optional CC recipients.
    #[serde(default)]
    pub cc: Vec<String>,
    /// Email subject line.
    pub subject: String,
    /// Plain-text body.
    pub body_text: String,
    /// Files to attach. Each is base64-decoded and uploaded as a JMAP blob.
    pub attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SendWithAttachmentsResult {
    pub email_id: String,
    pub submission_id: String,
    pub attachment_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReplyEmailParams {
    /// JMAP Email id of the message being replied to.
    pub email_id: String,
    /// Reply to all original recipients (To + CC), not just the sender.
    pub reply_to_all: bool,
    /// Plain-text reply body.
    pub body: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ReplyEmailResult {
    pub reply_email_id: String,
    pub submission_id: String,
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ForwardEmailParams {
    /// JMAP Email id of the message being forwarded.
    pub email_id: String,
    /// Recipient email addresses for the forward.
    pub to: Vec<String>,
    /// Optional note to prepend above the quoted original.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct ForwardEmailResult {
    pub forward_email_id: String,
    pub submission_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SaveDraftParams {
    /// From address (must be one of the caller's identities).
    pub from: String,
    /// Recipient email addresses.
    pub to: Vec<String>,
    /// Email subject line.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// Optional Message-ID this draft is in reply to (sets In-Reply-To).
    #[serde(default)]
    pub in_reply_to: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SaveDraftResult {
    pub email_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UpdateDraftParams {
    /// JMAP Email id of the draft to update.
    pub email_id: String,
    /// New from address (must be one of the caller's identities).
    #[serde(default)]
    pub from: Option<String>,
    /// New recipient email addresses (replaces the existing list).
    #[serde(default)]
    pub to: Option<Vec<String>>,
    /// New subject line.
    #[serde(default)]
    pub subject: Option<String>,
    /// New plain-text body.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UpdateDraftResult {
    pub email_id: String,
}

#[tool_router(router = compose_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Send a plain-text email with one or more attachments.
    #[tool(
        description = "Send a plain-text email with attachments. Each attachment is base64-decoded, \
                       uploaded as a blob, attached to a draft, submitted, and the copy moved to Sent.",
        annotations(
            title = "Send email with attachments",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn send_email_with_attachments(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendWithAttachmentsParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("send_email_with_attachments", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.to.is_empty() {
                return Err(ErrorData::invalid_params("`to` must not be empty", None));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let drafts = Self::role_mailbox(&mailboxes, "drafts")
                .ok_or_else(|| ErrorData::internal_error("no Drafts mailbox found", None))?;
            let sent = Self::role_mailbox(&mailboxes, "sent");
            let identity_id = self.identity_id_for(&token.0, &account_id, &params.from).await?;

            // Decode + upload each attachment, collecting blob ids.
            let mut attachment_ids = Vec::with_capacity(params.attachments.len());
            let mut attachment_objs = Vec::with_capacity(params.attachments.len());
            for att in &params.attachments {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(att.body_base64.as_bytes())
                    .map_err(|e| {
                        ErrorData::invalid_params(
                            format!("attachment {}: invalid base64: {e}", att.filename),
                            None,
                        )
                    })?;
                let blob = self
                    .jmap
                    .upload_blob(&token.0, bytes, &att.mime_type)
                    .await
                    .map_err(map_jmap_err)?;
                attachment_objs.push(json!({
                    "blobId": blob.blob_id,
                    "name": att.filename,
                    "type": att.mime_type,
                    "disposition": "attachment"
                }));
                attachment_ids.push(blob.blob_id);
            }

            let to_addrs: Vec<Value> = params.to.iter().map(|e| json!({ "email": e })).collect();
            let cc_addrs: Vec<Value> = params.cc.iter().map(|e| json!({ "email": e })).collect();

            let mut email_obj = json!({
                "mailboxIds": { drafts.clone(): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [ { "email": params.from } ],
                "to": to_addrs,
                "subject": params.subject,
                "bodyValues": { "b": { "value": params.body_text, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ],
                "attachments": attachment_objs
            });
            if !cc_addrs.is_empty() {
                email_obj["cc"] = Value::Array(cc_addrs);
            }

            let mut patch = json!({ "keywords/$draft": null, "keywords/$seen": true });
            if let Some(sent_id) = &sent {
                patch[format!("mailboxIds/{sent_id}")] = Value::Bool(true);
                patch[format!("mailboxIds/{drafts}")] = Value::Null;
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL, CAP_SUBMISSION],
                    vec![
                        (
                            "Email/set",
                            json!({ "accountId": account_id, "create": { "draft": email_obj } }),
                            "e",
                        ),
                        (
                            "EmailSubmission/set",
                            json!({
                                "accountId": account_id,
                                "create": { "sub": { "identityId": identity_id, "emailId": "#draft" } },
                                "onSuccessUpdateEmail": { "#sub": patch }
                            }),
                            "s",
                        ),
                    ],
                )
                .await
                .map_err(map_jmap_err)?;

            let email_id = created_id(&resps, "Email/set", "draft")
                .ok_or_else(|| email_set_failure(&resps))?;
            let submission_id = created_id(&resps, "EmailSubmission/set", "sub")
                .ok_or_else(|| submission_failure(&resps))?;

            structured_result(&SendWithAttachmentsResult {
                email_id,
                submission_id,
                attachment_ids,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "send_email_with_attachments", None, &result);
        emit_tool_audit(
            "send_email_with_attachments",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Reply to an email, auto-populating recipients, subject, and threading.
    #[tool(
        description = "Reply to an email by id. Auto-fills To (the original sender, plus all \
                       recipients when reply_to_all), subject (`Re: ...`), and threading headers, \
                       then sends and files the copy in Sent.",
        annotations(
            title = "Reply to email",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn reply_email(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ReplyEmailParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let eid = params.email_id.clone();
        let span = make_tool_span("reply_email", &user, Some(&eid));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let drafts = Self::role_mailbox(&mailboxes, "drafts")
                .ok_or_else(|| ErrorData::internal_error("no Drafts mailbox found", None))?;
            let sent = Self::role_mailbox(&mailboxes, "sent");

            // Fetch the parent's envelope + threading headers.
            let parent = self
                .get_email(
                    &token.0,
                    &account_id,
                    &params.email_id,
                    &["from", "to", "cc", "subject", "messageId", "references"],
                )
                .await?;

            // Recipients: original sender, plus original to+cc when reply_to_all.
            let mut to_objs = raw_addr_objs(&parent, "from");
            if params.reply_to_all {
                to_objs.extend(raw_addr_objs(&parent, "to"));
                to_objs.extend(raw_addr_objs(&parent, "cc"));
            }
            if to_objs.is_empty() {
                return Err(ErrorData::invalid_params(
                    "parent email has no resolvable reply recipient",
                    None,
                ));
            }

            // From-address: the caller identity that was an original recipient,
            // else the default (first) identity.
            let identities = self.list_identities(&token.0, &account_id).await?;
            let recipient_addrs = recipient_addr_set(&parent, params.reply_to_all);
            let (from_addr, identity_id) = pick_reply_identity(&identities, &recipient_addrs)
                .ok_or_else(|| {
                    ErrorData::invalid_params("no usable sending identity for reply", None)
                })?;

            let parent_subject = str_field(&parent, "subject").unwrap_or_default();
            let subject = if parent_subject.to_ascii_lowercase().starts_with("re:") {
                parent_subject
            } else {
                format!("Re: {parent_subject}")
            };

            let parent_message_id = parent
                .get("messageId")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);

            let mut email_obj = json!({
                "mailboxIds": { drafts.clone(): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [ { "email": from_addr } ],
                "to": to_objs,
                "subject": subject,
                "bodyValues": { "b": { "value": params.body, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ]
            });
            if let Some(mid) = &parent_message_id {
                email_obj["inReplyTo"] = json!([mid]);
                // references = parent references + parent messageId.
                let mut references: Vec<Value> = parent
                    .get("references")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                references.push(Value::String(mid.clone()));
                email_obj["references"] = Value::Array(references);
            }

            let mut patch = json!({ "keywords/$draft": null, "keywords/$seen": true });
            if let Some(sent_id) = &sent {
                patch[format!("mailboxIds/{sent_id}")] = Value::Bool(true);
                patch[format!("mailboxIds/{drafts}")] = Value::Null;
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL, CAP_SUBMISSION],
                    vec![
                        (
                            "Email/set",
                            json!({ "accountId": account_id, "create": { "draft": email_obj } }),
                            "e",
                        ),
                        (
                            "EmailSubmission/set",
                            json!({
                                "accountId": account_id,
                                "create": { "sub": { "identityId": identity_id, "emailId": "#draft" } },
                                "onSuccessUpdateEmail": { "#sub": patch }
                            }),
                            "s",
                        ),
                    ],
                )
                .await
                .map_err(map_jmap_err)?;

            let reply_email_id = created_id(&resps, "Email/set", "draft")
                .ok_or_else(|| email_set_failure(&resps))?;
            let submission_id = created_id(&resps, "EmailSubmission/set", "sub")
                .ok_or_else(|| submission_failure(&resps))?;

            structured_result(&ReplyEmailResult {
                reply_email_id,
                submission_id,
                in_reply_to: parent_message_id,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "reply_email", Some(eid.clone()), &result);
        emit_tool_audit(
            "reply_email",
            &user,
            Some(&eid),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Forward an email, quoting the original plain-text body.
    #[tool(
        description = "Forward an email by id to new recipients. Prepends an optional note above \
                       the quoted original plain-text body, sends, and files the copy in Sent.",
        annotations(
            title = "Forward email",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn forward_email(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<ForwardEmailParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let eid = params.email_id.clone();
        let span = make_tool_span("forward_email", &user, Some(&eid));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.to.is_empty() {
                return Err(ErrorData::invalid_params("`to` must not be empty", None));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let drafts = Self::role_mailbox(&mailboxes, "drafts")
                .ok_or_else(|| ErrorData::internal_error("no Drafts mailbox found", None))?;
            let sent = Self::role_mailbox(&mailboxes, "sent");

            // Fetch the parent (envelope + text body for the quote).
            let parent = self
                .get_email(
                    &token.0,
                    &account_id,
                    &params.email_id,
                    &["from", "to", "subject", "textBody", "bodyValues"],
                )
                .await?;

            // From-address: the default (first) identity.
            let identities = self.list_identities(&token.0, &account_id).await?;
            let (from_addr, identity_id) = first_identity(&identities)
                .ok_or_else(|| ErrorData::invalid_params("no sending identity available", None))?;

            let parent_subject = str_field(&parent, "subject").unwrap_or_default();
            let subject = if parent_subject.to_ascii_lowercase().starts_with("fwd:") {
                parent_subject.clone()
            } else {
                format!("Fwd: {parent_subject}")
            };

            let original_body = extract_text_body(&parent);
            let mut body = String::new();
            if let Some(note) = &params.message
                && !note.is_empty()
            {
                body.push_str(note);
                body.push_str("\n\n");
            }
            body.push_str("---------- Forwarded message ----------\n");
            let orig_from = addrs(&parent, "from").join(", ");
            let orig_to = addrs(&parent, "to").join(", ");
            {
                use std::fmt::Write as _;
                let _ = writeln!(body, "From: {orig_from}");
                let _ = writeln!(body, "To: {orig_to}");
                let _ = writeln!(body, "Subject: {parent_subject}\n");
            }
            body.push_str(&original_body);

            let to_addrs: Vec<Value> = params.to.iter().map(|e| json!({ "email": e })).collect();

            let email_obj = json!({
                "mailboxIds": { drafts.clone(): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [ { "email": from_addr } ],
                "to": to_addrs,
                "subject": subject,
                "bodyValues": { "b": { "value": body, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ]
            });

            let mut patch = json!({ "keywords/$draft": null, "keywords/$seen": true });
            if let Some(sent_id) = &sent {
                patch[format!("mailboxIds/{sent_id}")] = Value::Bool(true);
                patch[format!("mailboxIds/{drafts}")] = Value::Null;
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL, CAP_SUBMISSION],
                    vec![
                        (
                            "Email/set",
                            json!({ "accountId": account_id, "create": { "draft": email_obj } }),
                            "e",
                        ),
                        (
                            "EmailSubmission/set",
                            json!({
                                "accountId": account_id,
                                "create": { "sub": { "identityId": identity_id, "emailId": "#draft" } },
                                "onSuccessUpdateEmail": { "#sub": patch }
                            }),
                            "s",
                        ),
                    ],
                )
                .await
                .map_err(map_jmap_err)?;

            let forward_email_id = created_id(&resps, "Email/set", "draft")
                .ok_or_else(|| email_set_failure(&resps))?;
            let submission_id = created_id(&resps, "EmailSubmission/set", "sub")
                .ok_or_else(|| submission_failure(&resps))?;

            structured_result(&ForwardEmailResult {
                forward_email_id,
                submission_id,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "forward_email", Some(eid.clone()), &result);
        emit_tool_audit(
            "forward_email",
            &user,
            Some(&eid),
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Save a plain-text email as a draft (no submission).
    #[tool(
        description = "Save a plain-text email as a draft in the Drafts mailbox. Does not send.",
        annotations(
            title = "Save draft",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn save_draft(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SaveDraftParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("save_draft", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let drafts = Self::role_mailbox(&mailboxes, "drafts")
                .ok_or_else(|| ErrorData::internal_error("no Drafts mailbox found", None))?;

            let to_addrs: Vec<Value> = params.to.iter().map(|e| json!({ "email": e })).collect();

            let mut email_obj = json!({
                "mailboxIds": { drafts: true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [ { "email": params.from } ],
                "to": to_addrs,
                "subject": params.subject,
                "bodyValues": { "b": { "value": params.body, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ]
            });
            if let Some(irt) = &params.in_reply_to {
                email_obj["inReplyTo"] = json!([irt]);
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Email/set",
                        json!({ "accountId": account_id, "create": { "draft": email_obj } }),
                        "e",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;

            let email_id = created_id(&resps, "Email/set", "draft")
                .ok_or_else(|| email_set_failure(&resps))?;

            structured_result(&SaveDraftResult { email_id })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "save_draft", None, &result);
        emit_tool_audit("save_draft", &user, None, started, None, &span, &result);
        result
    }

    /// Update selected fields of an existing draft.
    #[tool(
        description = "Update an existing draft by id, changing only the provided fields \
                       (from, to, subject, body).",
        annotations(
            title = "Update draft",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn update_draft(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<UpdateDraftParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let eid = params.email_id.clone();
        let span = make_tool_span("update_draft", &user, Some(&eid));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let mut patch = serde_json::Map::new();
            if let Some(from) = &params.from {
                patch.insert("from".to_owned(), json!([ { "email": from } ]));
            }
            if let Some(to) = &params.to {
                let to_addrs: Vec<Value> = to.iter().map(|e| json!({ "email": e })).collect();
                patch.insert("to".to_owned(), Value::Array(to_addrs));
            }
            if let Some(subject) = &params.subject {
                patch.insert("subject".to_owned(), Value::String(subject.clone()));
            }
            if let Some(body) = &params.body {
                patch.insert(
                    "bodyValues".to_owned(),
                    json!({ "b": { "value": body, "isTruncated": false } }),
                );
                patch.insert(
                    "textBody".to_owned(),
                    json!([ { "partId": "b", "type": "text/plain" } ]),
                );
            }
            if patch.is_empty() {
                return Err(ErrorData::invalid_params(
                    "no fields to update; provide at least one of from/to/subject/body",
                    None,
                ));
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Email/set",
                        json!({
                            "accountId": account_id,
                            "update": { params.email_id.clone(): Value::Object(patch) }
                        }),
                        "e",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;

            let updated = resps
                .iter()
                .find(|(n, _, _)| n == "Email/set")
                .and_then(|(_, p, _)| {
                    p.get("updated")
                        .and_then(Value::as_object)
                        .map(|o| o.contains_key(&params.email_id))
                })
                .unwrap_or(false);
            if !updated {
                let reason = resps
                    .iter()
                    .find(|(n, _, _)| n == "Email/set")
                    .and_then(|(_, p, _)| p.get("notUpdated"))
                    .map_or_else(
                        || "Email/set updated no draft".to_owned(),
                        std::string::ToString::to_string,
                    );
                return Err(ErrorData::invalid_params(
                    format!("update_draft failed: {reason}"),
                    None,
                ));
            }

            structured_result(&UpdateDraftResult {
                email_id: params.email_id.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "update_draft", Some(eid.clone()), &result);
        emit_tool_audit(
            "update_draft",
            &user,
            Some(&eid),
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

impl JmapMcpService {
    /// Fetch a single email by id with the requested properties.
    async fn get_email(
        &self,
        token: &str,
        account_id: &str,
        email_id: &str,
        properties: &[&str],
    ) -> Result<Value, ErrorData> {
        let resps = self
            .jmap
            .call(
                token,
                &[CAP_CORE, CAP_MAIL],
                vec![(
                    "Email/get",
                    json!({
                        "accountId": account_id,
                        "ids": [email_id],
                        "properties": properties,
                        "fetchTextBodyValues": true,
                        "maxBodyValueBytes": super::MAX_BODY_VALUE_BYTES
                    }),
                    "g",
                )],
            )
            .await
            .map_err(map_jmap_err)?;
        resps
            .into_iter()
            .find(|(n, _, _)| n == "Email/get")
            .and_then(|(_, p, _)| {
                p.get("list")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first().cloned())
            })
            .ok_or_else(|| ErrorData::invalid_params("email_id: not found", None))
    }

    /// Fetch the caller's sendable identities as raw JMAP objects.
    async fn list_identities(
        &self,
        token: &str,
        account_id: &str,
    ) -> Result<Vec<Value>, ErrorData> {
        let resps = self
            .jmap
            .call(
                token,
                &[CAP_CORE, CAP_SUBMISSION],
                vec![(
                    "Identity/get",
                    json!({ "accountId": account_id, "ids": Value::Null }),
                    "i",
                )],
            )
            .await
            .map_err(map_jmap_err)?;
        Ok(resps
            .into_iter()
            .find(|(n, _, _)| n == "Identity/get")
            .and_then(|(_, p, _)| p.get("list").and_then(Value::as_array).cloned())
            .unwrap_or_default())
    }
}

// ----- module-level helpers -----

/// Pull the created object's id out of a `Foo/set` response by creation key.
fn created_id(resps: &[(String, Value, String)], method: &str, key: &str) -> Option<String> {
    resps
        .iter()
        .find(|(n, _, _)| n == method)
        .and_then(|(_, p, _)| {
            p.get("created")
                .and_then(|c| c.get(key))
                .and_then(|o| o.get("id"))
                .and_then(Value::as_str)
        })
        .map(ToOwned::to_owned)
}

/// Extract a JMAP address list (`[{name,email}]`) as raw `{name,email}`
/// objects suitable for re-use in an outgoing email.
fn raw_addr_objs(email: &Value, field: &str) -> Vec<Value> {
    email
        .get(field)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    let addr = p.get("email").and_then(Value::as_str)?;
                    let mut obj = json!({ "email": addr });
                    if let Some(name) = p
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                    {
                        obj["name"] = Value::String(name.to_owned());
                    }
                    Some(obj)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Collect the set of recipient email addresses (lower-cased) on a parent
/// email: From always; To+CC when replying to all.
fn recipient_addr_set(parent: &Value, reply_to_all: bool) -> Vec<String> {
    let mut fields: Vec<&str> = vec!["from"];
    if reply_to_all {
        fields.push("to");
        fields.push("cc");
    }
    let mut out = Vec::new();
    for f in fields {
        if let Some(arr) = parent.get(f).and_then(Value::as_array) {
            for p in arr {
                if let Some(addr) = p.get("email").and_then(Value::as_str) {
                    out.push(addr.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

/// Pick the caller identity whose email is among `recipient_addrs`; returns
/// `(email, identity_id)`. Falls back to the first identity if none matched.
fn pick_reply_identity(
    identities: &[Value],
    recipient_addrs: &[String],
) -> Option<(String, String)> {
    let matched = identities.iter().find(|i| {
        i.get("email")
            .and_then(Value::as_str)
            .is_some_and(|e| recipient_addrs.contains(&e.to_ascii_lowercase()))
    });
    matched
        .or_else(|| identities.first())
        .and_then(identity_pair)
}

/// The default (first) identity as `(email, identity_id)`.
fn first_identity(identities: &[Value]) -> Option<(String, String)> {
    identities.first().and_then(identity_pair)
}

fn identity_pair(i: &Value) -> Option<(String, String)> {
    let email = i.get("email").and_then(Value::as_str)?.to_owned();
    let id = i.get("id").and_then(Value::as_str)?.to_owned();
    Some((email, id))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn created_id_extracts() {
        let resps = vec![(
            "Email/set".to_owned(),
            json!({ "created": { "draft": { "id": "E99" } } }),
            "e".to_owned(),
        )];
        assert_eq!(
            created_id(&resps, "Email/set", "draft"),
            Some("E99".to_owned())
        );
        assert_eq!(created_id(&resps, "Email/set", "other"), None);
    }

    #[test]
    fn raw_addr_objs_keeps_name() {
        let e = json!({ "from": [ { "name": "Alice", "email": "a@x.test" }, { "email": "b@x.test" } ] });
        let objs = raw_addr_objs(&e, "from");
        assert_eq!(objs[0], json!({ "email": "a@x.test", "name": "Alice" }));
        assert_eq!(objs[1], json!({ "email": "b@x.test" }));
    }

    #[test]
    fn pick_reply_identity_prefers_recipient_match() {
        let identities = vec![
            json!({ "id": "I1", "email": "default@x.test" }),
            json!({ "id": "I2", "email": "me@x.test" }),
        ];
        let recips = vec!["me@x.test".to_owned()];
        assert_eq!(
            pick_reply_identity(&identities, &recips),
            Some(("me@x.test".to_owned(), "I2".to_owned()))
        );
        // No match → falls back to first.
        assert_eq!(
            pick_reply_identity(&identities, &[]),
            Some(("default@x.test".to_owned(), "I1".to_owned()))
        );
    }
}
