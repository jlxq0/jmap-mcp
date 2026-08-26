# Project Guidance

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

- **A JSON shape asserted only against a hand-written fixture is not tested.**
  `aliases_of` read Stalwart's `aliases` as an object map; the real schema is a
  **list**, so `as_object()` returned `None` and the mailbox's aliases silently
  vanished — while the unit test passed, because the fixture was a map too. The
  tool reported `outcome=ok` with a plausible count throughout. When a fixture
  encodes an external API's shape, cite the vendor schema in the test, and
  accept both shapes when the cost is a two-arm match.

- **Optional-capability fallbacks must be logged at least at `warn`.**
  Principal alias discovery degraded to identities-only at `debug`, and prod
  runs at `info`, so the permanent failure was invisible for two releases.
  `x:Account/query` and `x:Account/get` need `sysAccountQuery`/`sysAccountGet`,
  which an ordinary user token never has, so that path always degrades — the
  addresses users send as come from `JMAP_MCP_EXTRA_FROM_ADDRESSES` instead. A
  fallback that is expected to fire still has to say so. Found 2026-08.

- **Editing `.github/workflows/` can silently break the forge→GitHub mirror.**
  When the push mirror's GitHub PAT lacks the `workflow` scope, GitHub rejects
  any push containing a commit that touches a workflow file — and it rejects the
  *whole* push, `main` and every tag with it. The forge, CI and the cluster all
  stay green while the public repo, GHCR and the SBOM silently fall behind; the
  only evidence is `last_error` on
  `GET /api/v1/repos/jlxq0/jmap-mcp/push_mirrors`. Found 2026-08: v0.2.12 edited
  `ci.yml` and three tags went missing from the public repo. **Observed clear on
  2026-08-26**, by three checks that can disagree: GitHub carries v0.2.12,
  v0.2.13 and v0.2.14 at shas matching the forge; GitHub `main` equals forge
  `main` at 71c0268; and 2023000, the commit that touches `.github/workflows/`,
  returns 200 from GitHub's API. A push carrying a workflow file therefore
  succeeded, so the scope was granted rather than the block merely being dodged.
  Nothing says that grant is permanent: read `last_error` after the next
  workflow edit instead of assuming.

- A cache is not capped merely because expired entries are swept at a threshold. If every entry is still live, insertion can exceed the threshold; enforce a hard bound and test it with more than the configured capacity.
- Never refresh JWKS independently for every attacker-controlled unknown `kid`. Serialize refreshes and apply a short global cooldown while preserving normal key rotation.
- Validating a URL's DNS result and then resolving it again during the request leaves a DNS-rebinding gap. Pin the validated socket addresses into the fetch client.
- Treat every sender-controlled email field as untrusted, including subjects, display names, snippets, headers, and attachment filenames—not only the message body.
- JMAP queries are paginated. Operations described as affecting an entire mailbox must loop until a confirming empty query and must surface partial `Email/set` failures.
- Preserve the distinction between unsupported JMAP capabilities and authentication, transport, or backend failures; never collapse every method error into “unsupported.”
- Best-effort optional JMAP methods may ignore only explicit unsupported-method/capability errors. Never swallow authentication, transport, or upstream failures as an empty optional result.
- Sender-controlled structured headers such as Message-ID, In-Reply-To, and References need the same recursive sanitization and suspicious-content checks as subjects and display names.
- DNS pinning is ineffective when an environment-configured proxy resolves the target hostname; SSRF-guarded one-off fetch clients must bypass proxies.
- A clean RustSec audit does not cover the runtime base image. Scan the final container, keep the distroless digest current, and block releases on fixed HIGH/CRITICAL OS-package vulnerabilities.
- A shell-level `RUSTUP_TOOLCHAIN` overrides `rust-toolchain.toml`. Verify the exact MSRV in CI, and pair version-new Clippy allowances with `unknown_lints` so the pinned compiler can still build.
- RustSec and GitHub's advisory database are not identical. Check both before tagging a public release; a passing `cargo audit` alone can miss GitHub-reviewed Rust advisories.
- Docker Buildx and raw `buildctl` use different attestation flags. Buildx accepts `--attest`; `buildctl build` requires frontend options such as `--opt attest:sbom=` and `--opt attest:provenance=mode=max`.
- Native OAuth clients can select an ephemeral loopback listener port even when given a preferred port. Match allowlisted loopback HTTP callbacks on the exact host, path, and query while permitting only the port to vary; keep HTTPS and private-use callbacks exact.
- A hand-written loopback host check compares parsed hosts, not the text the client sent. The WHATWG URL parser canonicalizes `127.1` and `0177.0.0.1` to `127.0.0.1` and normalizes `/x/../cb` to `/cb`, so those match a `127.0.0.1` entry; `[::ffff:127.0.0.1]` and `/%63b` do not normalize and are rejected. Enumerate loopback hosts against `Url::host_str()` output, and assert the accepted and rejected spellings rather than reasoning about them.
- Relaxing the redirect port must key off the allowlist *entry's* scheme, not only the request's. Checking only the request lets an allowlisted `https://localhost:8443/cb` be satisfied by `http://localhost:*/cb`, putting the authorization code on the wire in cleartext.
- A defence-in-depth guard that no mutation can turn red is not dead code, but nothing will tell you it broke. Say so in a comment where it lives, or a later reader deletes it as redundant.

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
