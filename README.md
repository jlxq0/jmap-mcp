# jmap-mcp

A remote [Model Context Protocol](https://modelcontextprotocol.io) server that
lets Claude and other streamable-HTTP MCP clients read, search, compose, and
organise mail in a [Stalwart](https://stalw.art) JMAP mailbox using the user's
existing [Logto](https://logto.io) identity.

jmap-mcp validates each inbound OAuth access token against Logto's JWKS and
forwards the same token to Stalwart. It stores no mailbox passwords and has no
per-user database or persistent volume.

> [!IMPORTANT]
> The current authentication bridge is specifically tested with Logto and
> Stalwart. Other JMAP or OIDC implementations may work only when their issuer,
> token, audience, claim, and dynamic-registration behaviour matches this
> deployment model.

## Features

The server exposes 47 tools with MCP read-only, destructive, and idempotency
annotations:

- **Identity:** `whoami`, `get_identities`, `create_identity`
- **Read:** mailbox listing and metadata, recent mail and activity, search,
  message and thread reading, unread summaries, headers, and attachments
- **State:** read/unread, flags, keywords, move, and copy
- **Compose:** send, reply, forward, save/update drafts, and attachments
- **Delete:** trash, permanent deletion, empty trash, and empty spam
- **Mailbox management:** create, rename, delete, subscribe, and unsubscribe
- **Profile:** profile, account information, vacation response, and session
  verification
- **Self-audit:** append envelope-only audit notes to a designated mailbox

Sender-controlled bodies, subjects, snippets, addresses, structured headers,
and attachment filenames are treated as untrusted. Returned bodies are wrapped
in `<email:message trust="external">` delimiters, prompt-injection markers are
escaped, and suspicious content is flagged.

## Requirements

- A public HTTPS hostname for jmap-mcp
- A Logto tenant with a public application and API resource
- A Stalwart server with JMAP enabled and an OIDC directory that trusts Logto
- An MCP client supporting streamable HTTP and OAuth 2.1

## Quick start

Copy the environment template, fill in your deployment-specific values, and
start the published Linux/amd64 image:

```sh
cp .env.example .env
docker compose up -d
curl http://127.0.0.1:3000/health
```

The image is published to:

```text
ghcr.io/jlxq0/jmap-mcp:0.2.13
forge.oddie.app/jlxq0/jmap-mcp:v0.2.13
```

For a direct container invocation:

```sh
docker run --rm -p 3000:3000 --env-file .env \
  ghcr.io/jlxq0/jmap-mcp:0.2.13
```

Expose port 3000 through HTTPS and configure the MCP client with:

```text
https://jmap-mcp.your-domain.example/mcp
```

`GET /health` is public and returns the running package version:

```json
{"status":"healthy","version":"0.2.13"}
```

## Logto and Stalwart setup

The following identifiers must remain aligned:

1. Create a Logto API resource whose indicator is the bare jmap-mcp origin,
   such as `https://jmap-mcp.your-domain.example`.
2. Create a public SPA/native Logto application. Put its client ID in
   `JMAP_MCP_DCR_CLIENT_ID`; no client secret is used by the DCR flow.
3. Register `https://jmap-mcp.your-domain.example/oauth/callback` as the Logto
   application's redirect URI.
4. Put every MCP client's callback URI in `JMAP_MCP_OAUTH_REDIRECT_URIS`.
   HTTPS and native private-use callbacks match exactly. Loopback HTTP
   callbacks match the configured host, path, and query while allowing the
   client to choose an ephemeral local port, as required by RFC 8252.
5. Configure Stalwart's OIDC directory to trust the same Logto issuer, accept
   the jmap-mcp origin as the token audience, and map the token's `username`,
   `email`, or `sub` claim to the mailbox principal.
6. Confirm that a Logto access token for the resource can discover a JMAP
   session directly:

   ```sh
   curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     https://mail.your-domain.example/.well-known/jmap
   ```

The JWT `aud` value accepted by jmap-mcp and Stalwart must contain the exact
bare origin. `JMAP_MCP_RESOURCE_URL` accepts either the origin or an origin
ending in `/mcp`; jmap-mcp canonicalises it to the bare origin and advertises
`<origin>/mcp` through RFC 9728 metadata.

## Configuration

| Variable | Required | Default | Purpose |
|---|---:|---|---|
| `JMAP_MCP_RESOURCE_URL` | yes | — | Public origin and required JWT audience; a trailing `/mcp` is accepted and removed |
| `JMAP_MCP_AUTHORIZATION_SERVER` | yes | — | Logto OIDC issuer, normally ending in `/oidc` |
| `JMAP_MCP_STALWART_JMAP_BASE_URL` | yes | — | Stalwart base used for `/.well-known/jmap` discovery |
| `JMAP_MCP_DCR_CLIENT_ID` | for DCR clients | disabled | Pre-provisioned public Logto client returned by `/register` |
| `JMAP_MCP_OAUTH_REDIRECT_URIS` | for OAuth proxy | empty | Comma-separated MCP client callback allowlist; only loopback HTTP ports may vary |
| `JMAP_MCP_BIND_ADDR` | no | `0.0.0.0:3000` | Public HTTP listener |
| `JMAP_MCP_METRICS_BIND_ADDR` | no | `127.0.0.1:9090` | Internal Prometheus listener; never publish it directly |
| `POD_IP` | no | — | Derives the metrics listener as `<pod-ip>:9090` in Kubernetes |
| `JMAP_MCP_RATE_LIMIT_READS_PER_MIN` | no | `60` | Per-identity read quota |
| `JMAP_MCP_RATE_LIMIT_WRITES_PER_MIN` | no | `30` | Per-identity write quota |
| `JMAP_MCP_DOWNLOAD_MAX_BYTES` | no | `5242880` | Maximum attachment download response |
| `JMAP_MCP_UPLOAD_MAX_BYTES` | no | `10485760` | Maximum remote URL attachment fetch |
| `JMAP_MCP_TRUSTED_PROXY_HOPS` | no | `1` | Trusted rightmost `X-Forwarded-For` proxy count; use `0` when directly exposed |
| `JMAP_MCP_EXTRA_FROM_ADDRESSES` | for mailbox aliases | empty | Extra sendable addresses, comma- or whitespace-separated. Stalwart exposes principal aliases only through `x:Account/*`, which need `sysAccountGet`/`sysAccountQuery` permissions an ordinary user token lacks, so aliases must be named here. Role addresses are refused |
| `JMAP_MCP_STALWART_CONNECT_IP` | no | DNS | Optional fixed Stalwart socket address for private routing while preserving TLS host validation |
| `JMAP_MCP_LOGTO_CLIENT_ID` | no | — | Opaque-token introspection client ID; must be paired with the secret |
| `JMAP_MCP_LOGTO_CLIENT_SECRET` | no | — | Opaque-token introspection client secret |
| `JMAP_MCP_LOG_FORMAT` | no | compact | Set to `json` for structured logs |
| `RUST_LOG` | no | application defaults | Standard tracing filter |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | disabled | Enables OTLP trace export |
| `OTEL_SERVICE_NAME` | no | `jmap-mcp` | OpenTelemetry service name |

The app fails startup when required values are missing or malformed. When DCR
is configured, an empty redirect allowlist fails authorization closed.

## Security and privacy

jmap-mcp grants an MCP client access to a user's mailbox. Operators and users
must trust the MCP client, model provider, Logto, Stalwart, and the jmap-mcp
operator.

- Access tokens are held in memory and forwarded to Stalwart; raw tokens are
  not logged or persisted.
- Audit logs include the account identity, MCP method, mailbox/message resource
  identifiers, outcome, latency, result count, error class, and the first 16
  hexadecimal characters of a SHA-256 token hash. They exclude message bodies,
  subjects, recipients, attachment contents, and free-form tool arguments.
- Remote attachment fetches require HTTPS, reject private/reserved addresses,
  pin the validated socket address, bypass environment proxies, and enforce
  byte limits.
- In-memory caches, pending OAuth state, rate-limit key maps, MCP sessions, and
  request bodies have hard bounds.
- Release CI runs formatting, Clippy, tests, independent RustSec and OSV
  dependency audits, cargo-deny, container vulnerability scanning, SBOM
  generation, provenance attestation, and keyless image signing.

See [SECURITY.md](SECURITY.md) for reporting and supported-version policy.

## Building and testing

Rust 1.93 is pinned in `rust-toolchain.toml`.

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
docker build --platform linux/amd64 -t jmap-mcp:local .
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release history is maintained in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
