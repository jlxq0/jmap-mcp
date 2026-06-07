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

## CI / deploy

- Forgejo Actions (`.forgejo/workflows/ci.yml`). The docker job derives
  `BUILDKIT_HOST` from the container's own default gateway at runtime — never
  hardcode the runner IP. Release path: push tag `vX.Y.Z` → CI builds + pushes
  `forge.oddie.app/jlxq0/jmap-mcp:vX.Y.Z`.
- Live deploy is **kubectl-applied** (namespace `jmap-mcp-www`), not yet argocd.
  Roll a new version: `kubectl -n jmap-mcp-www set image deploy/jmap-mcp-www
  app=forge.oddie.app/jlxq0/jmap-mcp:vX.Y.Z`.
