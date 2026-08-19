# jmap-mcp — project notes

Remote MCP server bridging claude.ai to a Stalwart JMAP mailbox. Rust + axum +
rmcp. Logto validates inbound bearer tokens (JWKS); the token is passed through
to Stalwart. Stateless. See `memory/` notes for deploy/auth wiring.

## Known Pitfalls

- **Never `String::truncate(n)` at a byte offset on untrusted or multibyte
  text.** `String::truncate` asserts `n` is a UTF-8 char boundary and panics
  otherwise. Release builds set `panic = "abort"` (Cargo.toml), so such a panic
  **aborts the whole process** — a one-message DoS when an email body's byte cap
  lands inside a multi-byte char (e.g. `CAP-1` ASCII bytes + `é`). Fixed by
  `truncate_text_body` in `src/mcp.rs`, which backs the index down to the
  nearest char boundary; use it for any body/text capping. (`Vec::truncate` is
  fine — it has no boundary requirement.) Found 2026-06: read_email/read_thread.

- **claude.ai connector needs DCR, Logto has none.** We front Logto: the
  protected-resource metadata advertises *jmap-mcp itself* as the auth server,
  we serve RFC 8414 metadata (authorize/token/jwks delegate to Logto) +
  an RFC 7591 `/register` shim returning a pre-provisioned Logto public-SPA
  client (`JMAP_MCP_DCR_CLIENT_ID`). See `src/oauth_metadata.rs`.

- **OAuth proxy must enforce client redirect URIs itself.** Logto only sees
  jmap-mcp's `/oauth/callback`, not the real client callback, so `/authorize`,
  `/token`, and `/register` must reject any `redirect_uri` outside the exact
  `JMAP_MCP_OAUTH_REDIRECT_URIS` allowlist. Do not rely on Logto's registered
  redirect URI policy once the transparent proxy rewrites `redirect_uri`.
  Found 2026-06: authorization-code theft via attacker-controlled callback.

## CI / deploy

- Forgejo Actions (`.forgejo/workflows/ci.yml`) build and scan the
  `linux/amd64` image, attach SBOM/provenance attestations, and publish
  `forge.oddie.app/jlxq0/jmap-mcp:vX.Y.Z` for a matching version tag.
- GitHub Actions (`.github/workflows/`) run equivalent public CI and publish a
  keylessly signed `ghcr.io/jlxq0/jmap-mcp:X.Y.Z` image plus an SPDX SBOM.
- Live deployment is GitOps-managed by ArgoCD on **Fondue**, namespace
  `jmap-mcp`. The manifest is
  `/Users/jl/Code/oddie-apps/platform/clusters/fondue/jmap-mcp/deployment.yaml`
  and images are pinned by tag **and digest**. Never use `kubectl set image`;
  update the platform repository and wait for the `jmap-mcp` Argo application
  to report `Synced` and `Healthy`.
