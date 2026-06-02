//! Profile, settings, account/session, and audit-mailbox tools.
//!
//! Ported from matrix-mcp's profile/account surface onto JMAP: identity-based
//! profile, server vacation-response (`urn:ietf:params:jmap:vacationresponse`),
//! session-derived account info, a lightweight session liveness check, and the
//! `set_audit_mailbox` designation that drives fire-and-forget write auditing.

use super::*;

/// JMAP vacation-response capability URN (RFC 8621 §8).
const CAP_VACATION: &str = "urn:ietf:params:jmap:vacationresponse";

// ----- result + parameter types -----

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct GetProfileResult {
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VacationResponseResult {
    pub enabled: bool,
    pub message: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    /// Whether the server advertises the vacation-response capability.
    pub supported: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetVacationResponseParams {
    /// Whether the auto-reply is active.
    pub enabled: bool,
    /// Plain-text body of the auto-reply.
    pub message: String,
    /// Optional ISO-8601 start date/time the auto-reply becomes active.
    #[serde(default)]
    pub start_date: Option<String>,
    /// Optional ISO-8601 end date/time the auto-reply stops.
    #[serde(default)]
    pub end_date: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SetVacationResponseResult {
    pub enabled: bool,
    pub message: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct AccountInfoResult {
    pub email: Option<String>,
    pub account_id: String,
    pub server: Option<String>,
    pub quota_used_bytes: Option<u64>,
    pub quota_max_bytes: Option<u64>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct VerifySessionResult {
    pub authenticated: bool,
    pub email: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SetAuditMailboxParams {
    /// JMAP Mailbox id that should receive envelope-only audit notes.
    pub mailbox_id: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub struct SetAuditMailboxResult {
    pub mailbox_id: String,
}

#[tool_router(router = profile_router, vis = "pub(crate)")]
impl JmapMcpService {
    /// The caller's default sending identity as a profile.
    #[tool(
        description = "Return the user's profile (email + display name) from their default sending identity.",
        annotations(title = "Get profile", read_only_hint = true, idempotent_hint = true)
    )]
    async fn get_profile(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("get_profile", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_SUBMISSION],
                    vec![(
                        "Identity/get",
                        json!({ "accountId": account_id, "ids": Value::Null }),
                        "i",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let identity = resps
                .into_iter()
                .find(|(n, _, _)| n == "Identity/get")
                .and_then(|(_, p, _)| {
                    p.get("list")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first().cloned())
                });
            structured_result(&GetProfileResult {
                email: identity.as_ref().and_then(|i| str_field(i, "email")),
                name: identity.as_ref().and_then(|i| str_field(i, "name")),
                avatar_url: None,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit("get_profile", &user, None, started, None, &span, &result);
        result
    }

    /// Read the server-side vacation auto-reply, if supported.
    #[tool(
        description = "Get the current vacation auto-reply (out-of-office) setting. \
                       Returns supported=false when the server lacks the capability.",
        annotations(
            title = "Get vacation response",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn get_vacation_response(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("get_vacation_response", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;
            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_VACATION],
                    vec![(
                        "VacationResponse/get",
                        json!({ "accountId": account_id, "ids": Value::Null }),
                        "v",
                    )],
                )
                .await;
            // Capability absent (or any method error) → report unsupported
            // rather than failing the call.
            let Ok(resps) = resps else {
                return structured_result(&VacationResponseResult {
                    enabled: false,
                    message: None,
                    from_date: None,
                    to_date: None,
                    supported: false,
                });
            };
            let vacation = resps
                .into_iter()
                .find(|(n, _, _)| n == "VacationResponse/get")
                .and_then(|(_, p, _)| {
                    p.get("list")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first().cloned())
                });
            structured_result(&VacationResponseResult {
                enabled: vacation
                    .as_ref()
                    .and_then(|v| v.get("isEnabled").and_then(Value::as_bool))
                    .unwrap_or(false),
                message: vacation.as_ref().and_then(|v| str_field(v, "textBody")),
                from_date: vacation.as_ref().and_then(|v| str_field(v, "fromDate")),
                to_date: vacation.as_ref().and_then(|v| str_field(v, "toDate")),
                supported: true,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "get_vacation_response",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Set (or clear) the server-side vacation auto-reply.
    #[tool(
        description = "Set the vacation auto-reply (out-of-office). Errors with \
                       invalid_params when the server lacks the capability.",
        annotations(
            title = "Set vacation response",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn set_vacation_response(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetVacationResponseParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("set_vacation_response", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            let mut singleton = json!({
                "isEnabled": params.enabled,
                "textBody": params.message,
            });
            if let Some(from) = &params.start_date {
                singleton["fromDate"] = json!(from);
            }
            if let Some(to) = &params.end_date {
                singleton["toDate"] = json!(to);
            }

            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_VACATION],
                    vec![(
                        "VacationResponse/set",
                        json!({
                            "accountId": account_id,
                            "update": { "singleton": singleton }
                        }),
                        "v",
                    )],
                )
                .await
                .map_err(|_| ErrorData::invalid_params("vacation response not supported", None))?;
            let updated = resps
                .iter()
                .find(|(n, _, _)| n == "VacationResponse/set")
                .and_then(|(_, p, _)| p.get("updated"))
                .and_then(Value::as_object)
                .is_some_and(|o| o.contains_key("singleton"));
            if !updated {
                return Err(ErrorData::invalid_params(
                    "vacation response not supported",
                    None,
                ));
            }
            structured_result(&SetVacationResponseResult {
                enabled: params.enabled,
                message: params.message.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "set_vacation_response", None, &result);
        emit_tool_audit(
            "set_vacation_response",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Account summary derived from the cached JMAP session.
    #[tool(
        description = "Return account info from the JMAP session: login email, account id, and server host.",
        annotations(
            title = "Get account info",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn get_account_info(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("get_account_info", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let session = self
                .jmap
                .session_for(&token.0)
                .await
                .map_err(map_jmap_err)?;
            let account_id = session
                .mail_account_id()
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    ErrorData::internal_error("session has no primary mail account", None)
                })?;
            // Derive the server host from the session apiUrl, when parseable.
            let server = host_of(&session.api_url);
            structured_result(&AccountInfoResult {
                email: session.username,
                account_id,
                server,
                quota_used_bytes: None,
                quota_max_bytes: None,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit(
            "get_account_info",
            &user,
            None,
            started,
            None,
            &span,
            &result,
        );
        result
    }

    /// Confirm the caller's token still authenticates to Stalwart.
    #[tool(
        description = "Verify the session is still authenticated by re-fetching the JMAP session resource.",
        annotations(
            title = "Verify session",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    async fn verify_session(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let user = identity_from_ctx(&ctx)
            .and_then(|i| i.email)
            .unwrap_or_default();
        let span = make_tool_span("verify_session", &user, None);
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Read)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let session = self
                .jmap
                .session_for(&token.0)
                .await
                .map_err(map_jmap_err)?;
            structured_result(&VerifySessionResult {
                authenticated: true,
                email: session.username,
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        emit_tool_audit("verify_session", &user, None, started, None, &span, &result);
        result
    }

    /// Designate the mailbox that receives envelope-only audit notes.
    #[tool(
        description = "Designate a mailbox to receive envelope-only audit notes for every write this server makes.",
        annotations(
            title = "Set audit mailbox",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true
        )
    )]
    async fn set_audit_mailbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(params): Parameters<SetAuditMailboxParams>,
    ) -> Result<rmcp::model::CallToolResult, ErrorData> {
        let started = Instant::now();
        let identity = identity_from_ctx(&ctx);
        let user = identity
            .as_ref()
            .and_then(|i| i.email.clone())
            .unwrap_or_default();
        let mbox = params.mailbox_id.clone();
        let span = make_tool_span("set_audit_mailbox", &user, Some(&mbox));
        let mut result = async {
            self.rate_limit_check(&ctx, Category::Write)?;
            let identity = identity.clone().ok_or_else(missing_identity_err)?;
            let token = token_from_ctx(&ctx).ok_or_else(missing_token_err)?;
            let account_id = self.jmap.account_id(&token.0).await.map_err(map_jmap_err)?;

            // Validate the mailbox exists before registering it.
            let resps = self
                .jmap
                .call(
                    &token.0,
                    &[CAP_CORE, CAP_MAIL],
                    vec![(
                        "Mailbox/get",
                        json!({
                            "accountId": account_id,
                            "ids": [params.mailbox_id],
                            "properties": ["id"]
                        }),
                        "m",
                    )],
                )
                .await
                .map_err(map_jmap_err)?;
            let found = resps
                .iter()
                .find(|(n, _, _)| n == "Mailbox/get")
                .and_then(|(_, p, _)| p.get("list").and_then(Value::as_array))
                .is_some_and(|a| !a.is_empty());
            if !found {
                return Err(ErrorData::invalid_params("mailbox_id: not found", None));
            }

            self.audit_registry
                .set(&identity.user_id, &params.mailbox_id);
            structured_result(&SetAuditMailboxResult {
                mailbox_id: params.mailbox_id.clone(),
            })
        }
        .instrument(span.clone())
        .await;
        self.react_to_auth_expiry(&ctx, &mut result).await;
        self.spawn_audit(&ctx, "set_audit_mailbox", Some(mbox.clone()), &result);
        emit_tool_audit(
            "set_audit_mailbox",
            &user,
            Some(&mbox),
            started,
            None,
            &span,
            &result,
        );
        result
    }
}

/// Extract the `scheme://host[:port]` origin from an absolute URL, dropping the
/// path/query. Returns `None` if the input isn't shaped like an absolute URL.
fn host_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn host_of_strips_path() {
        assert_eq!(
            host_of("https://mail.example.com/jmap/api"),
            Some("https://mail.example.com".to_owned())
        );
        assert_eq!(
            host_of("https://mail.example.com:8443/jmap?x=1"),
            Some("https://mail.example.com:8443".to_owned())
        );
    }

    #[test]
    fn host_of_rejects_non_url() {
        assert_eq!(host_of("not-a-url"), None);
        assert_eq!(host_of("https://"), None);
    }
}
