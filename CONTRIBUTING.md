# Contributing

The [GitHub repository](https://github.com/jlxq0/jmap-mcp) is the public project
home for issues, pull requests, releases, and GHCR images. The
[Forge repository](https://forge.oddie.app/jlxq0/jmap-mcp) is the deployment
source and is mirrored to GitHub.

## Development

Rust 1.93 is pinned by `rust-toolchain.toml`.

```sh
git clone https://github.com/jlxq0/jmap-mcp.git
cd jmap-mcp
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny check bans licenses sources
```

Before submitting a change:

1. Add regression tests for behaviour changes and bug fixes.
2. Keep environment-specific values in configuration, never source code.
3. Never commit access tokens, mailbox content, real customer addresses, or
   captured OAuth/browser state.
4. Run the complete command set above.
5. Use a conventional commit such as `fix(auth): reject an invalid audience`.

Use synthetic addresses on domains you control in integration tests. Existing
tests use reserved `.test` names and must never contact external services.

## Pull requests

Describe the security boundary affected, user-visible behaviour, tests added,
and any deployment/configuration change. Keep changes narrowly scoped and do
not weaken validation to make a test pass.

Report security problems privately as described in [SECURITY.md](SECURITY.md).
