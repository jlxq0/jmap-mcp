# Project Guidance

## Known Pitfalls

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
