//! Attachment & media tools: download an email attachment, upload a blob
//! fetched from a public URL, and send an email with a URL-sourced
//! attachment. Mirrors the structure of the core tools in `super`
//! (`read_email`, `send_email`): span → `rate_limit_check` → identity/token →
//! `account_id` → `jmap.call` → `map_jmap_err` → `structured_result` →
//! `react_to_auth_expiry` → `emit_tool_audit`; writes also call `spawn_audit`.

use super::*;

use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;

/// Build a one-off rustls reqwest client used for fetching public URLs.
/// Automatic redirect handling is disabled because each redirect target
/// must be re-validated against the SSRF denylist before following — and
/// for the attachment tools we conservatively refuse to follow redirects
/// at all, requiring the caller to pass the final URL.
fn fetch_client() -> Result<reqwest::Client, ErrorData> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("jmap-mcp/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| ErrorData::internal_error(format!("build http client: {e}"), None))
}

/// Fetch `url` (already SSRF-validated) and return its bytes + content-type,
/// capping the streamed body at `max_bytes`.
async fn fetch_capped(url: &str, max_bytes: usize) -> Result<(Vec<u8>, String), ErrorData> {
    let client = fetch_client()?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ErrorData::invalid_params(format!("failed to fetch {url}: {e}"), None))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ErrorData::invalid_params(
            format!("fetch of {url} returned HTTP {}", status.as_u16()),
            None,
        ));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or(s).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_owned());

    // Reject early if the server advertises an over-cap Content-Length.
    if let Some(len) = resp.content_length()
        && len > max_bytes as u64
    {
        return Err(ErrorData::invalid_params(
            format!("remote resource is {len} bytes, exceeds cap of {max_bytes}"),
            None,
        ));
    }

    let mut bytes: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| ErrorData::invalid_params(format!("error streaming {url}: {e}"), None))?;
        if bytes.len() + chunk.len() > max_bytes {
            return Err(ErrorData::invalid_params(
                format!("remote resource exceeds cap of {max_bytes} bytes"),
                None,
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, content_type))
}

// ----- parameter + result types -----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DownloadAttachmentParams {
    /// JMAP Email id that owns the attachment.
    pub email_id: String,
    /// The attachment's JMAP `blobId` (from `read_email` / `list_attachments`).
    pub attachment_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct DownloadAttachmentResult {
    /// Attachment filename as declared in the email part (may be empty).
    pub filename: String,
    /// MIME content type of the attachment.
    pub content_type: String,
    /// Decoded attachment size in bytes.
    pub size_bytes: u64,
    /// Standard base64-encoded attachment bytes.
    pub body_base64: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct UploadBlobFromUrlParams {
    /// Public HTTPS URL to fetch and upload as a JMAP blob (SSRF-guarded).
    pub url: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct UploadBlobFromUrlResult {
    /// The JMAP blob id Stalwart assigned to the uploaded content.
    pub blob_id: String,
    /// Size of the uploaded blob in bytes.
    pub size_bytes: u64,
    /// Content type recorded for the uploaded blob.
    pub content_type: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendEmailWithUrlAttachmentParams {
    /// From address (must be one of the caller's identities).
    pub from: String,
    /// Recipient email addresses.
    pub to: Vec<String>,
    /// Email subject line.
    pub subject: String,
    /// Plain-text body.
    pub body: String,
    /// Public HTTPS URL of the file to attach (SSRF-guarded).
    pub attachment_url: String,
    /// Filename to present the attachment under.
    pub attachment_filename: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[allow(clippy::struct_field_names)] // domain ids: email_id / submission_id / blob_id
pub struct SendEmailWithUrlAttachmentResult {
    /// The created (sent) email's JMAP id.
    pub email_id: String,
    /// The `EmailSubmission` id for the send.
    pub submission_id: String,
    /// The JMAP blob id of the uploaded attachment.
    pub blob_id: String,
}

#[tool_router(router = attachments_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// Download a single attachment from an email, returned base64-encoded.
    #[tool(
        description = "Download an email attachment by its blobId and return the bytes \
                       base64-encoded. Rejects attachments larger than the configured \
                       download cap.",
        annotations(
            title = "Download attachment",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn download_attachment(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<DownloadAttachmentParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let eid = params.email_id.clone();
        let span = make_tool_span("download_attachment", &user, Some(&eid));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Email/get",
                        json!({
                            "accountId": account_id,
                            "ids": [params.email_id],
                            "properties": ["attachments"]
                        }),
                        "g",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let email = resps
                .into_iter()
                .find(|(n, _, _)| n == "Email/get")
                .and_then(|(_, p, _)| {
                    p.get("list")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first().cloned())
                })
                .ok_or_else(|| ErrorData::invalid_params("email_id: not found", None))?;

            let attachment = email
                .get("attachments")
                .and_then(Value::as_array)
                .and_then(|a| {
                    a.iter().find(|att| {
                        att.get("blobId").and_then(Value::as_str) == Some(&params.attachment_id)
                    })
                })
                .ok_or_else(|| {
                    ErrorData::invalid_params(
                        "attachment_id: no attachment with that blobId on this email",
                        None,
                    )
                })?;

            let content_type = str_field(attachment, "type")
                .unwrap_or_else(|| "application/octet-stream".to_owned());
            let filename = str_field(attachment, "name").unwrap_or_default();
            let declared_size = attachment.get("size").and_then(Value::as_u64);

            // Reject up front if the declared size already exceeds the cap.
            if let Some(size) = declared_size
                && size > self.download_max_bytes
            {
                return Err(ErrorData::invalid_params(
                    format!(
                        "attachment is {size} bytes, exceeds download cap of {}",
                        self.download_max_bytes
                    ),
                    None,
                ));
            }

            let bytes = self
                .jmap
                .download_blob(
                    &token.0,
                    &params.attachment_id,
                    &content_type,
                    &filename,
                    self.download_max_bytes,
                )
                .await
                .map_err(map_jmap_err)?;
            let size_bytes = bytes.len() as u64;
            let body_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

            structured_result(&DownloadAttachmentResult {
                filename,
                content_type,
                size_bytes,
                body_base64,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "download_attachment",
            &user,
            Some(&eid),
            started,
            Some(1),
            &span,
            &result,
        );
        result
    }

    /// Fetch a public URL and upload its contents as a JMAP blob.
    #[tool(
        description = "Fetch a public HTTPS URL (SSRF-guarded) and upload its bytes as a \
                       JMAP blob, returning the new blob id. Rejects non-public hosts and \
                       content larger than the upload cap.",
        annotations(
            title = "Upload blob from URL",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn upload_blob_from_url(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<UploadBlobFromUrlParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("upload_blob_from_url", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            crate::url_safety::validate_https_url(&params.url)
                .await
                .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

            let (bytes, content_type) = fetch_capped(&params.url, self.upload_max_bytes).await?;
            let uploaded = self
                .jmap
                .upload_blob(&token.0, bytes, &content_type)
                .await
                .map_err(map_jmap_err)?;

            structured_result(&UploadBlobFromUrlResult {
                blob_id: uploaded.blob_id,
                size_bytes: uploaded.size,
                content_type: uploaded.content_type,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "upload_blob_from_url", None, &result);
        emit_tool_audit(
            "upload_blob_from_url",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Send a plain-text email with a single attachment fetched from a URL.
    #[tool(
        description = "Send a plain-text email with one attachment fetched from a public \
                       HTTPS URL (SSRF-guarded). Creates a draft with the uploaded blob, \
                       submits it, and moves the copy to Sent.",
        annotations(
            title = "Send email with URL attachment",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false
        )
    )]
    async fn send_email_with_url_attachment(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SendEmailWithUrlAttachmentParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("send_email_with_url_attachment", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            if params.to.is_empty() {
                return Err(ErrorData::invalid_params("`to` must not be empty", None));
            }
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            crate::url_safety::validate_https_url(&params.attachment_url)
                .await
                .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let mailboxes = self.all_mailboxes(&token.0, &account_id).await?;
            let drafts = Self::role_mailbox(&mailboxes, "drafts")
                .ok_or_else(|| ErrorData::internal_error("no Drafts mailbox found", None))?;
            let sent = Self::role_mailbox(&mailboxes, "sent");

            let identity_id = self
                .identity_id_for(&token.0, &account_id, &params.from)
                .await?;

            // Fetch + upload the attachment before composing the draft.
            let (bytes, content_type) =
                fetch_capped(&params.attachment_url, self.upload_max_bytes).await?;
            let uploaded = self
                .jmap
                .upload_blob(&token.0, bytes, &content_type)
                .await
                .map_err(map_jmap_err)?;
            let blob_id = uploaded.blob_id.clone();

            let to_addrs: Vec<Value> = params.to.iter().map(|e| json!({ "email": e })).collect();

            let email_obj = json!({
                "mailboxIds": { drafts.clone(): true },
                "keywords": { "$draft": true, "$seen": true },
                "from": [ { "email": params.from } ],
                "to": to_addrs,
                "subject": params.subject,
                "bodyValues": { "b": { "value": params.body, "isTruncated": false } },
                "textBody": [ { "partId": "b", "type": "text/plain" } ],
                "attachments": [ {
                    "blobId": uploaded.blob_id,
                    "type": uploaded.content_type,
                    "name": params.attachment_filename,
                    "disposition": "attachment"
                } ]
            });

            // onSuccessUpdateEmail: clear $draft, mark $seen, move to Sent.
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
                                "create": {
                                    "sub": {
                                        "identityId": identity_id,
                                        "emailId": "#draft"
                                    }
                                },
                                "onSuccessUpdateEmail": { "#sub": patch }
                            }),
                            "s",
                        ),
                    ],
                )
                .await
                .map_err(map_jmap_err)?;

            let email_id = resps
                .iter()
                .find(|(n, _, _)| n == "Email/set")
                .and_then(|(_, p, _)| {
                    p.get("created")
                        .and_then(|c| c.get("draft"))
                        .and_then(|d| d.get("id"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| super::email_set_failure(&resps))?
                .to_owned();
            let submission_id = resps
                .iter()
                .find(|(n, _, _)| n == "EmailSubmission/set")
                .and_then(|(_, p, _)| {
                    p.get("created")
                        .and_then(|c| c.get("sub"))
                        .and_then(|s| s.get("id"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| super::submission_failure(&resps))?
                .to_owned();

            structured_result(&SendEmailWithUrlAttachmentResult {
                email_id,
                submission_id,
                blob_id,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "send_email_with_url_attachment", None, &result);
        emit_tool_audit(
            "send_email_with_url_attachment",
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
