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

- **Stalwart answers a request with *no* `Authorization` header with `200`,
  not `401`, and the body parses cleanly into `JmapSession`.** Only a *bad*
  credential gives 401. Measured on `jmap.kampong.social` 2026-08-28:

      no Authorization header   200, 1297-byte capabilities document
      garbage Basic             401
      garbage Bearer            401

  The 200 body carries `apiUrl`, `downloadUrl`, `uploadUrl`, `primaryAccounts`
  `{}` and `username` `""`, so a session fetch that forgets to attach the
  credential returns **`Ok`**, the authentication step succeeds, and the failure
  surfaces somewhere else entirely as a missing account. **"The session fetch
  returned 200" is therefore not proof of authentication**, and it is the first
  predicate anyone writing credential validation against this backend reaches
  for. Use `JmapSession::is_authenticated`: 200 **and** a non-empty `username`
  or a real entry in `primaryAccounts`.

- **A mutation set that only edits function bodies cannot see whether the
  function is called.** `send_email` gained a `validate_send_bodies` guard with
  a test that exercised it and four mutations that each redded exactly one
  test. Deleting the guard's **single call site** in the handler left all 187
  green while HTML-with-empty-text sent in production. Every mutation targeted
  a function body; none targeted reachability, so the set looked thorough and
  had one whole class outside it. Found 2026-08-29 in review, not by the suite.

  The repair is structural rather than a second test to remember: the check
  moved **inside** `build_email_object`, which returns `Result`, so there is no
  call to omit and the existing test reaches it through the one path the
  handler uses. **An object builder that cannot construct an invalid object
  beats a guard somebody has to call.**

  What that still does not cover, stated because it is easy to believe
  otherwise: the handler can call the builder and **discard** the error.
  Replacing `?` with `unwrap_or_else(|_| json!({}))` reds nothing. Closing that
  needs a test that drives the handler itself, and no unit test on either
  function reaches it. Mutate the call site as well as the callee, and when a
  mutation reds nothing say so rather than dropping it.

- **A stale tool description cannot be found by anyone who has used the
  tool.** `send_email`'s read *"Send a plain-text email"* for a day after it
  gained `body_html`, so the parameter's own tool advertised that its purpose
  was impossible. It was found by the one person who could not be misled by it:
  she had already called it successfully with `body_html`, so she flagged the
  description of the tool she was **reading** and not the one she was **using**.

  A description only misleads somebody who has not already done the thing, and
  that is exactly the person who is not reviewing it. The cost is measured
  rather than argued: the same reader had, two days earlier, read `read_email`'s
  summary rather than its properties, told two people `body_html` did not
  exist, and retracted. **A description that denies a capability is worse than
  a missing feature, because a caller acts on it and stops looking.**

  So when a tool gains a parameter, re-read the description of **that** tool,
  and treat "I know it works" as the reason you are the wrong reader. Fixed in
  v0.2.21; `#33`'s own release shipped with both descriptions stale.

- **A fixture contains only what its author thought to put in it**, so a test
  on your own output confirms the cases you predicted and cannot assert the
  absence of damage you did not predict. The escaping in `read_email` was
  tested against a fixture carrying a `style` attribute and an `&` in a query
  string, both of which I had thought of. What established it was safe on real
  mail was a reader checking her own composed briefing for **"no entity
  anywhere I did not put there"** — an assertion no fixture can make.

  Worth the distinction when a change touches sender-controlled content:
  *"the styles came back"* is a predicted case, *"nothing came back that I did
  not write"* is a different claim and the stronger one.

- **A JSON shape asserted only against a hand-written fixture is not tested.**
  `aliases_of` read Stalwart's `aliases` as an object map; the real schema is a
  **list**, so `as_object()` returned `None` and the mailbox's aliases silently
  vanished — while the unit test passed, because the fixture was a map too. The
  tool reported `outcome=ok` with a plausible count throughout. When a fixture
  encodes an external API's shape, cite the vendor schema in the test, and
  accept both shapes when the cost is a two-arm match.

- **`JMAP_MCP_EXTRA_FROM_ADDRESSES` entries carry an owner, and an entry
  without one is granted to nobody.** Write `owner@domain=address@domain`. The
  owner is matched case-insensitively against the JMAP session's own
  `username`, so a caller receives only the addresses declared for the account
  it authenticated as.

  Before the owner existed the list was a flat `Arc<Vec<String>>` appended to
  **every** authenticated caller, while the other two sources of a sendable
  `From` (`Identity/get` and `principal_aliases`) were caller-scoped. So one
  account's declared alias was a sendable `From` for anybody who
  authenticated, and the config could not express *she may send as herself and
  not as him*. Found 2026-08-29 while adding a second identity, before that
  identity had a working mount.

  A bare entry is **not** an error and **not** a grant: the server starts,
  warns once per entry naming the required form, and grants it to nobody.
  Refusing to start would take a live mail server down over a config line;
  honouring it would restore the flat list. It fails closed and stays up, and
  the consequence is that the address stops being sendable until the manifest
  names its owner.

- **Optional-capability fallbacks must be logged at least at `warn`.**
  Principal alias discovery degraded to identities-only at `debug`, and prod
  runs at `info`, so the permanent failure was invisible for two releases.
  `x:Account/query` and `x:Account/get` need `sysAccountQuery`/`sysAccountGet`,
  which an ordinary user token never has, so that path always degrades — the
  addresses users send as come from `JMAP_MCP_EXTRA_FROM_ADDRESSES` instead. A
  fallback that is expected to fire still has to say so. Found 2026-08.

- **Editing `.github/workflows/` silently breaks the forge→GitHub mirror, and
  it is broken right now.** The push mirror's GitHub PAT lacks the `workflow`
  scope, so GitHub rejects any push containing a commit that touches a workflow
  file, and it rejects the *whole* push, `main` and every tag with it. The
  forge, CI and the cluster all stay green while the public repo, GHCR and the
  SBOM fall behind; the only evidence is `last_error` on
  `GET /api/v1/repos/jlxq0/jmap-mcp/push_mirrors`.

  Live as of 2026-08-27T03:00:34Z, from `859399b` editing
  `.github/workflows/release.yml`:

      ! [remote rejected] main -> main (refusing to allow a Personal Access
      Token to create or update workflow `.github/workflows/release.yml`
      without `workflow` scope)

  Forge `main` is `236f9a6`, GitHub `main` is `0e73d2f1`, four commits behind,
  and GitHub carries 14 tags against the forge's 22.

  **The 2026-08-26 note in this file said the block was cleared, and that
  inference was wrong.** It rested on `2023000` modifying
  `.github/workflows/ci.yml` and returning 200 from GitHub's API, read as
  proof that a workflow-carrying push had succeeded and therefore that the
  scope was granted. A commit reaching GitHub says nothing about *which*
  credential put it there or what scope that credential holds today. Three
  checks that agree can all be answering a question other than the one asked.
  **Only `last_error` after your own workflow-touching push answers it**, and
  it must be read every time rather than concluded once.

- **An image can reach the registry without CI, and the ancestry gate cannot
  see it.** `v0.2.5` and `v0.2.6` are in the forge registry with no git tag
  anywhere and no Actions run that could have built them. Measured 2026-08-27:
  on 2026-08-16 the repository ran **six** Actions tasks, **all `cargo`, all
  `failure`, no `docker` job at all**, and the first `docker` job to succeed
  after 2026-08-14 was 2026-08-18T01:29:29Z, two days later. Yet the `v0.2.5`
  image was created **129 seconds** after commit `09b5f5b` and `v0.2.6` **931
  seconds** after `c0a9353`. That cadence, with CI red, is a local
  `docker build && push`.

  So the tag-ancestry gate closes tags cut off unmerged branches and closes
  nothing here: **it runs in CI, and this path never enters CI.** Anything
  holding registry push credentials can publish, and the result is
  indistinguishable in the registry from a released image. Corroborating: both
  carry **no OCI labels**, consistent with predating `0ebc967` which added the
  `LABEL` block, so there is no `org.opencontainers.image.revision` to recover.
  The only remaining route to their source is rebuilding a candidate commit and
  comparing layer digests. Tracked on issue #14.

- **Every release from `v0.1.0` to `v0.2.9` shipped a binary reporting version
  `0.0.1`.** `Cargo.toml` carried `version = "0.0.1"` from the initial commit
  until `0ebc967`, so `CARGO_PKG_VERSION` was `0.0.1` in the `User-Agent` sent
  to Logto and Stalwart, in the OTLP `service.version`, and in the `version`
  field `main.rs` serves. Verified by reading the literal out of the shipped
  binaries:

      v0.2.4  jmap-mcp/0.0.1     v0.2.7   jmap-mcp/0.0.1
      v0.2.5  jmap-mcp/0.0.1     v0.2.14  jmap-mcp/0.2.14
      v0.2.6  jmap-mcp/0.0.1     v0.2.16  jmap-mcp/0.2.16

  Fixed at `0ebc967`, which set the real version **and** added
  `test "${V#v}" = "$VERSION"` to the tag build in the same commit. **That
  check is the only thing preventing recurrence**, and it looks like ceremony
  next to a tag you just typed. Do not remove it.

- **`main` requires `CI / cargo*`, and excludes `CI / docker` on purpose.** The
  `docker` job carries `needs: cargo` (`.forgejo/workflows/ci.yml:74`), and a
  Forgejo job skipped because the job it needs failed still posts **`success`**
  to the commit status, with no docker task created for that sha at all.
  Measured here on six commits spanning 2026-08-16 to 2026-08-25 and across both
  event types: every one had `cargo=failure` beside `docker=success`, among them
  `83396b91` on `main` and `53bd20a5` on PR #10. Requiring `CI / docker` would
  therefore build a gate that a commit where nothing was built satisfies. The
  required context is a glob because the event suffix differs: a branch push
  posts `CI / cargo (push)` and a pull-request head posts
  `CI / cargo (pull_request)`. Do not tidy this up by adding `docker` to the
  required contexts; the rule shows what is required and cannot show why.

- **A pull request's `mergeable` field is not the merge gate, and it reads
  `true` when the merge is refused.** Measured 2026-08-27 on PR #13 while
  `CI / cargo` was still pending: the merge API returned **405** with
  `not allowed to merge [reason: Not all required status checks successful]`,
  and `GET /pulls/13` reported `mergeable=true` at that same moment.
  `mergeable` answers whether the branches merge without conflict, which is a
  different question from whether branch protection permits it, and it is the
  field a session naturally reads before merging. Attempt the merge and read
  the HTTP status; do not pre-check `mergeable` and conclude the way is clear.

- **`git rev-parse <annotated-tag>` returns the tag object, not the commit.**
  Every release tag here is annotated, so `git rev-parse v0.2.14` is
  `22b4507c` while the commit is `41d6c8f0`. Comparing that against a commit
  sha reports **NO MATCH for a tag that does point at it**, which is a
  confident wrong answer in the place a script decides whether a release is on
  `main`. Measured 2026-08-27. `git merge-base --is-ancestor` and
  `git log -1 --format=%H` peel on their own and are safe; `git rev-parse` and
  any string comparison built on it are not. Peel with `^{commit}` whenever the
  sha is printed, compared, or handed to another tool. Same class as the
  `mergeable` note above: a field that answers a different question than the
  one asked, in the place everyone looks.

- **A queued Actions run is invisible in the tasks API, so a pending required
  context is not evidence that no run was scheduled.** `created_at` on a task
  is when it *starts*, not when it is queued. PR #16 opened
  2026-08-27T02:27:23Z; the task list's newest entry stayed at 02:25:35 for
  eleven minutes, and its run was created at **02:38:53**, 11m30s later. The
  `macos-27`/shared runner is capacity 1 across every repository on this forge,
  so that wait is ordinary rather than a fault.

  Read as "no run exists", it produces exactly the wrong action: a second push
  to re-trigger **cancels the queued run under ref-scoped concurrency and
  requeues from the back**. That is what happened here, and the replacement did
  not start until 02:46:26. The push cost nine minutes rather than saving them.
  Before concluding a context is stuck, check `on:` for the trigger and wait
  past the queue; a run that has not started reports nothing anywhere.

- **Three further ways a gate's state stops being about the code**, all
  answered by the workflow's `on:` block and none of them by the statuses on
  past commits: a job skipped because its `needs:` failed posts `success`
  without doing the work; a workflow with no `pull_request` trigger posts
  nothing at all on a PR head; a repository with no PR history has never
  produced its PR contexts, so their absence says nothing about whether it
  would. Reading a `(push)`-only status history as evidence that a job is
  push-only is the mistake this prevents. Read `on:`.

- A cache is not capped merely because expired entries are swept at a threshold. If every entry is still live, insertion can exceed the threshold; enforce a hard bound and test it with more than the configured capacity.
- Never refresh JWKS independently for every attacker-controlled unknown `kid`. Serialize refreshes and apply a short global cooldown while preserving normal key rotation.
- Validating a URL's DNS result and then resolving it again during the request leaves a DNS-rebinding gap. Pin the validated socket addresses into the fetch client.
- Treat every sender-controlled email field as untrusted, including subjects, display names, snippets, headers, and attachment filenames—not only the message body.
- **`token_hash` in the audit log identifies a credential, not a client, and in
  this deployment it is a constant.** Every session that mounts jmap-mcp
  presents the same bearer: `honoka`, `lucy`, `mantis` and `penny` all mount it
  from `~/Smithy/<name>_agent/wt/main/src/mcp.json` (`vryan` mounts `hevy` and
  no jmap, so the check can return a negative). Measured 2026-08-27 across ten
  audit lines from three separate occasions and at least two sessions:
  **1 distinct `token_hash`, and `user` `julian@kampong.social` on all of
  them.**

  That is not wrong data; it is non-discriminating data in the shape of
  discriminating data, which is worse than an absent field. During an incident
  a reader pairs `token_hash` with `user`, sees two identical hashes, and
  concludes they have separated or joined two callers. **The field can say
  which credential was used and cannot say who used it.** Per-session
  attribution would be a bearer-per-agent decision and is not this repository's
  to make.

  **And do not repair this by pairing on `token_hash`.** The `ingress chain
  length` line carries no `token_hash`; the `audit` line does, about 24 µs
  earlier, so correlating them is an inference from adjacency rather than a
  field read, and under concurrency another request's audit line lands between
  a request's own two. Pairing on the hash looks like the fix and is not one:
  every mounting session presents the same bearer, so two concurrent requests
  carry **identical** hashes and the pairing is exactly as ambiguous as
  adjacency with the appearance of attribution added. It would pass review.
  A real fix needs a per-request correlation id, or the count folded into the
  audit event. The line is left alone on purpose: what it answers is a property
  of the deployment rather than of a request, so it needs no subject.

- **A request count in this log is not a call count.** One
  `mcp__jmap__whoami` produced **seven** authenticated requests, at
  2026-08-27T04:12:08.290281Z through .347111Z, 57 ms apart end to end. The
  `ingress chain length` line fires once per authenticated HTTP request, and
  streamable-http turns one MCP tool call into a whole exchange. Reading nine
  requests as nine actions is out by most of an order of magnitude, and the
  same applies to any rate or volume conclusion drawn from these lines.

- **The logs are JSON, so a `key=value` grep matches nothing while the pod is
  logging normally.** `JMAP_MCP_LOG_FORMAT=json` in the Deployment, and fields
  land as `"trusted_proxy_hops":2`, never `trusted_proxy_hops=2`. Measured on a
  pod mid-flight:

      grep 'trusted_proxy_hops=[0-9]'   0 matches
      grep '"trusted_proxy_hops":'      9 matches

  A zero here reads as "the feature is not running" rather than "my pattern is
  wrong", which is how it cost a fleet sweep three pods. Quote a line as it
  lands rather than as a tool rendered it: `jq -r '"a=\(.x)"'` output is a
  rendering, and pasting it into a grep is how the wrong pattern gets built.
- JMAP queries are paginated. Operations described as affecting an entire mailbox must loop until a confirming empty query and must surface partial `Email/set` failures.
- Preserve the distinction between unsupported JMAP capabilities and authentication, transport, or backend failures; never collapse every method error into “unsupported.”
- Best-effort optional JMAP methods may ignore only explicit unsupported-method/capability errors. Never swallow authentication, transport, or upstream failures as an empty optional result.
- Sender-controlled structured headers such as Message-ID, In-Reply-To, and References need the same recursive sanitization and suspicious-content checks as subjects and display names.
- DNS pinning is ineffective when an environment-configured proxy resolves the target hostname; SSRF-guarded one-off fetch clients must bypass proxies.
- A clean RustSec audit does not cover the runtime base image. Scan the final container, keep the distroless digest current, and block releases on fixed HIGH/CRITICAL OS-package vulnerabilities.
- **`docker manifest inspect -v` on an image *index* returns an array of
  per-platform manifests, and `[0].Descriptor.digest` is not what a pod's
  `imageID` carries.** The fleet rule says to use `-v` and read
  `Descriptor.digest`, which is right for a single-manifest image and wrong
  here: every `jmap-mcp` tag is an
  `application/vnd.oci.image.index.v1+json`. Calibrated 2026-08-27 against
  `v0.2.14`, whose deployed `imageID` is known:

      pod imageID                         sha256:316e64a8…
      registry HEAD Docker-Content-Digest sha256:316e64a8…   <- match, the index
      manifest inspect -v [0].Descriptor  sha256:50831874…   <- linux/amd64 manifest

  The array holds `[linux/amd64]` and an `[unknown/unknown]` attestation entry;
  neither is the index. So the check is a registry `HEAD` on
  `/v2/jlxq0/jmap-mcp/manifests/<tag>` with the index media types in `Accept`,
  reading `Docker-Content-Digest`. That needs a **registry** token from
  `/v2/token`, not the Forgejo API token.

  This fails in the direction that looks like a rollback: comparing a platform
  manifest against a correctly deployed `imageID` reports a mismatch on a
  healthy image. It was caught only by running both methods against a tag whose
  answer was already known, which is the point of dry-running a check against
  a known state before the moment it matters.

  Why the fleet rule reads as it does: measured across the five deployed MCP
  servers, `caldav-mcp`, `hevy-mcp`, `matrix-mcp` and `typst-mcp` all publish a
  **single** manifest, where `-v` returns an object and the rule is correct.
  `jmap-mcp` is the only index among them, so the precondition had never been
  visible. Do not "simplify" this entry back to the fleet form.
- A shell-level `RUSTUP_TOOLCHAIN` overrides `rust-toolchain.toml`. Verify the exact MSRV in CI, and pair version-new Clippy allowances with `unknown_lints` so the pinned compiler can still build.
- **`RUSTUP_TOOLCHAIN` unset is not enough: mise's `rustc` shim resolves
  `stable` and ignores `rust-toolchain.toml`.** Measured 2026-08-27 with
  `RUSTUP_TOOLCHAIN` unset, `rust-toolchain.toml` pinning `1.93.0` and
  `.forgejo/workflows/ci.yml:35` pinning `1.93.0`: `rustc --version` reported
  **1.98.0**, resolved through `~/.local/share/mise/shims/rustc`. So a local
  green can be on the wrong compiler with every visible signal agreeing, which
  is the opposite direction from the env-var route above and needs no
  misconfiguration to happen. Run `cargo +1.93.0 …`, and read the pin out of
  `git show origin/main:.forgejo/workflows/ci.yml` rather than assuming it.
  The specimen: `clippy::naive_bytecount` rejected the first spelling of
  `xff_entry_count`. That lint fires on 1.93.0 and the 1.98.0 shim would have
  passed it straight to CI.
- RustSec and GitHub's advisory database are not identical. Check both before tagging a public release; a passing `cargo audit` alone can miss GitHub-reviewed Rust advisories.
- Docker Buildx and raw `buildctl` use different attestation flags. Buildx accepts `--attest`; `buildctl build` requires frontend options such as `--opt attest:sbom=` and `--opt attest:provenance=mode=max`.
- Native OAuth clients can select an ephemeral loopback listener port even when given a preferred port. Match allowlisted loopback HTTP callbacks on the exact host, path, and query while permitting only the port to vary; keep HTTPS and private-use callbacks exact.
- A hand-written loopback host check compares parsed hosts, not the text the client sent. The WHATWG URL parser canonicalizes `127.1` and `0177.0.0.1` to `127.0.0.1` and normalizes `/x/../cb` to `/cb`, so those match a `127.0.0.1` entry; `[::ffff:127.0.0.1]` and `/%63b` do not normalize and are rejected. Enumerate loopback hosts against `Url::host_str()` output, and assert the accepted and rejected spellings rather than reasoning about them.
- Relaxing the redirect port must key off the allowlist *entry's* scheme, not only the request's. Checking only the request lets an allowlisted `https://localhost:8443/cb` be satisfied by `http://localhost:*/cb`, putting the authorization code on the wire in cleartext.
- A defence-in-depth guard that no mutation can turn red is not dead code, but nothing will tell you it broke. Say so in a comment where it lives, or a later reader deletes it as redundant.

## Where fleet facts live

- **Which sessions mount this server is answered by
  `~/Smithy/<name>_agent/wt/main/src/mcp.json`**, moved there under
  `jlxq0/mantis#122`. They are in neither `~/.claude.json` nor any project
  `.mcp.json`. On 2026-08-27 three sweeps of those two locations returned
  nothing while four sessions (`honoka`, `lucy`, `mantis`, `penny`) mounted
  jmap-mcp and `vryan` did not, which makes `vryan` a usable negative control.
  **A sweep returning zero is the expected result of looking in the wrong
  place, not evidence that nothing mounts the server**, and the two are
  indistinguishable from the output. Read the `mcpServers` keys, never the
  `headers` values.

## CI / deploy

- Forgejo Actions (`.forgejo/workflows/ci.yml`) build and scan the
  `linux/amd64` image, attach SBOM/provenance attestations, and publish
  `forge.oddie.app/jlxq0/jmap-mcp:vX.Y.Z` for a matching version tag.
- GitHub Actions (`.github/workflows/`) run equivalent public CI and publish a
  keylessly signed `ghcr.io/jlxq0/jmap-mcp:X.Y.Z` image plus an SPDX SBOM.
- Live deployment is GitOps-managed by ArgoCD on **Fondue**, namespace
  `jmap-mcp`. The manifest is `clusters/fondue/jmap-mcp/deployment.yaml` in the
  `oddie-apps/platform` repository, and images are pinned by tag **and digest**. Never use `kubectl set image`;
  update the platform repository and wait for the `jmap-mcp` Argo application
  to report `Synced` and `Healthy`.
