# Security policy

## Supported versions

Only the latest published release receives security fixes. Operators should
deploy an immutable image digest and upgrade when a new release is published.

| Version | Supported |
|---|---:|
| 0.2.12 | yes |
| 0.2.11 and earlier | no |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting for
[`jlxq0/jmap-mcp`](https://github.com/jlxq0/jmap-mcp/security/advisories/new).
If that channel is unavailable, email `security@oddie.app` with:

- the affected version or commit;
- the attack preconditions and impact;
- reproduction steps or a minimal proof of concept;
- any suggested remediation or disclosure constraints.

Do not include real access tokens, mailbox content, customer addresses, or
other personal data. Use synthetic accounts and messages.

Receipt should be acknowledged within three business days. Fix and disclosure
timing depends on severity, exploitability, and coordinated-release needs.

## Security boundaries

jmap-mcp is a bearer-token bridge. Anyone who obtains a valid token can act
with that token's mailbox permissions. Deployments must protect TLS keys,
identity-provider configuration, container-registry credentials, cluster
access, telemetry, and logs.

The supported production model assumes:

- HTTPS terminates at a trusted proxy;
- Logto signs tokens with an allowlisted asymmetric algorithm;
- the token audience contains the configured jmap-mcp origin;
- Stalwart independently validates the same token and maps it to one account;
- `/metrics` is reachable only from internal monitoring;
- `JMAP_MCP_OAUTH_REDIRECT_URIS` contains only exact trusted client callbacks;
- operators understand the audit metadata described in `README.md`.

Security reports about unsupported identity providers or JMAP servers are still
useful when they demonstrate a defect in jmap-mcp's validation or isolation.
