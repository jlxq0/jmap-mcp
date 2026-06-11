# jmap-mcp

A remote MCP server that lets [claude.ai](https://claude.ai) (or any other
MCP client) read, search, send, and organise email in your
[JMAP](https://jmap.io) mailbox — here, a [Stalwart](https://stalw.art)
server — using your existing single-sign-on identity.

It speaks [OAuth 2.1 / MCP / RFC 9728](https://modelcontextprotocol.io) on
one side and the [JMAP](https://datatracker.ietf.org/doc/html/rfc8620)
Mail API (RFC 8620/8621) on the other. Inbound bearer tokens are validated
against [Logto](https://logto.io) (JWKS + RS256), then forwarded verbatim to
Stalwart as the JMAP credential — a pure pass-through, no stored mailbox
passwords.

Ported from [`matrix-mcp`](https://forge.oddie.app/julian/matrix-mcp): same
Rust + `axum` + `rmcp` stack, same distroless image, same Gruyere/ArgoCD
hosting — with Matrix's E2EE/cross-signing machinery replaced by a stateless
JMAP client (there is no per-user store, no PVC).

## What you get

46 tools, all carrying MCP annotations (`read_only_hint`,
`destructive_hint`, `idempotent_hint`) so client UIs can auto-approve reads
and warn before writes.

- **Identity**: `whoami`, `get_identities`
- **Reads**: `list_mailboxes`, `get_mailbox_info`, `list_recent_emails`,
  `read_email`, `search_emails`, `read_thread`, `get_unread_summary`,
  `list_recent_activity`, `get_email_headers`, `list_attachments`
- **State & flags**: `mark_read`, `mark_unread`, `set_flag`, `unset_flag`,
  `set_keyword`, `unset_keyword`, `move_to_mailbox`, `copy_to_mailbox`
- **Compose & send**: `send_email`, `send_email_with_attachments`,
  `reply_email`, `forward_email`, `save_draft`, `update_draft`
- **Deletion**: `delete_email`, `permanently_delete_email`, `empty_trash`,
  `empty_spam`
- **Attachments**: `download_attachment`, `upload_blob_from_url`,
  `send_email_with_url_attachment`
- **Mailbox management**: `create_mailbox`, `rename_mailbox`,
  `delete_mailbox`, `subscribe_mailbox`, `unsubscribe_mailbox`
- **Spam**: `mark_as_spam`, `mark_as_not_spam`
- **Profile / settings**: `get_profile`, `get_vacation_response`,
  `set_vacation_response`, `get_account_info`, `verify_session`
- **Self-audit**: `set_audit_mailbox` — designate a mailbox where jmap-mcp
  appends an envelope-only note for every write it makes on your behalf.

Read tools that return message bodies wrap them in
`<email:message trust="external">` delimiters with prompt-injection markers
escaped, and flag suspicious bodies — the same content-sandbox defence
matrix-mcp applies to Matrix messages.

## Prerequisites

- A Stalwart server with JMAP enabled and an OIDC directory trusting your
  Logto issuer (so Stalwart accepts the same Logto JWT jmap-mcp validates).
- A Logto API resource whose indicator equals this server's public URL, so
  claude.ai's tokens carry the right `aud`.
- An MCP client speaking the streamable-HTTP transport (claude.ai Custom
  Connectors, etc.).

## Quick start

```bash
docker run --rm -p 3000:3000 \
  -e JMAP_MCP_RESOURCE_URL=https://jmap-mcp.your-domain.example \
  -e JMAP_MCP_AUTHORIZATION_SERVER=https://login.your-domain.example/oidc \
  -e JMAP_MCP_STALWART_JMAP_BASE_URL=https://mail.your-domain.example \
  -e JMAP_MCP_OAUTH_REDIRECT_URIS=https://client.example/oauth/callback \
  forge.oddie.app/jlxq0/jmap-mcp:latest
```

Then point a public HTTPS hostname at it (claude.ai requires `https://`).
Set `JMAP_MCP_OAUTH_REDIRECT_URIS` to the exact comma-separated redirect URI
allowlist configured on the pre-provisioned Logto public client; the OAuth proxy
rejects authorization and DCR requests for any other redirect URI.

## Security

jmap-mcp gives claude.ai access to your email — that's the point. You extend
trust to claude.ai (and Anthropic), and to whoever runs the instance. Run
your own. The validated Logto JWT is forwarded to Stalwart and never stored;
no mailbox password lives in jmap-mcp.

## Development

Rust 1.93+ with `edition = "2024"`.

```sh
cargo run
curl http://127.0.0.1:3000/health
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
```

## Licence

[MIT](LICENSE).
