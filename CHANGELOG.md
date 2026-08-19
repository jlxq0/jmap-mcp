# Changelog

All notable changes are recorded here. The project uses semantic version tags.

## 0.2.14 — 2026-08-20

### Fixed

- Every compose path resolved the sending identity's display name and then
  discarded it, so recipients saw a bare address: `julian@lindner.earth`
  rather than `Julian Lindner <julian@lindner.earth>`. `send_email`,
  `reply_email`, `forward_email`, `save_draft`, `update_draft`,
  `send_email_with_attachments`, and `send_email_with_url_attachment` now set
  the JMAP `EmailAddress` `name` field when the address has one on file.

  The name is only ever the one the mailbox already publishes — an
  `Identity`'s `name`, or an alias's description. It is never synthesised, and
  resolving it never changes the address. Blank and whitespace-only names are
  dropped rather than emitted. JMAP carries the display name in its own field
  and performs the RFC 5322 quoting and RFC 2047 encoding itself, so the name
  is passed through verbatim rather than pre-quoted here.

## 0.2.13 — 2026-08-19

### Fixed

- `save_draft` wrote its `from` parameter into the draft unchecked. It was the
  only compose path that skipped `resolve_submission_identity`, so a draft
  could be composed from a shared role address, or from an address the mailbox
  does not own — one click from being sent by a human in a mail client. It now
  validates identically to `update_draft`, `reply_email`, and `send_email`.

## 0.2.12 — 2026-08-19

### Fixed

- Expose the mailbox's own aliases as sendable From-addresses. `get_identities`
  returned only the 11 JMAP identities — 9 of them role addresses — and omitted
  personal aliases such as `julian@lindner.earth`, which made them unusable in
  `send_email` and `reply_email`. Two independent causes:
  - `aliases` was parsed as an object map; Stalwart's schema declares it a
    list, so alias expansion silently produced nothing.
  - `x:Account/query` and `x:Account/get` require the `sysAccountQuery` and
    `sysAccountGet` permissions, which an ordinary user's token does not carry,
    so discovery always degraded to identities-only.
- Add `JMAP_MCP_EXTRA_FROM_ADDRESSES` so an operator can declare the mailbox's
  sendable aliases without granting jmap-mcp administrative rights over the
  mail server. Creates no mailbox and no identity; submission borrows the
  personal identity while `From` carries the alias.
- Refuse role addresses (`team@`, `postmaster@`, …) as a personal `From` at
  configuration-parse time as well as at send time.
- Log the optional-capability fallback at `warn` instead of `debug`; at `info`
  log level the permanent degradation was invisible.

### Changed

- Stop hardcoding `APP_VERSION` in the Dockerfile and public CI; the scan image
  now takes its version from `Cargo.toml`, and the Dockerfile default is an
  explicit `0.0.0-dev` placeholder.
- Update README, `compose.yaml`, and the SECURITY supported-version table,
  which still instructed users to deploy 0.2.10.

## 0.2.11 — 2026-08-19

### Fixed

- Accept an OAuth native client's ephemeral loopback listener port while still
  requiring the configured loopback host, path, and query to match. This makes
  Claude Code registration interoperable without weakening HTTPS or
  private-use callback matching.

## 0.2.10 — 2026-08-19

### Security

- Hard-cap JMAP sessions, token-validation results, pending OAuth state,
  rate-limiter keys, MCP sessions, and request bodies.
- Serialize JWKS refresh and apply a global cooldown for unknown key IDs.
- Upgrade `jsonwebtoken` to fix CVE-2026-25537 claim type confusion and the
  OpenTelemetry stack to fix CVE-2026-48504 baggage allocation denial of
  service.
- Pin validated socket addresses for remote attachment fetches, reject
  reserved address space, and bypass environment proxies.
- Refresh the distroless runtime base to include Debian's fix for
  CVE-2026-45447 in `libssl3`.
- Sanitize sender-controlled bodies, metadata, structured headers, snippets,
  and filenames before returning them to an MCP client.
- Paginate whole-mailbox operations and surface partial JMAP failures.

### Changed

- Distinguish upstream JMAP authentication rejection from local token expiry.
- Resolve send identities from explicit or signed-in addresses, never server
  list order, and refuse implicit role-address sending.
- Preserve authentication, transport, and backend errors from optional JMAP
  methods instead of reporting them as unsupported.
- Return structured health status with the package version.
- Add public deployment, security, contribution, and release documentation.
- Add GitHub CI and signed GHCR releases with vulnerability scanning, SBOMs,
  and provenance attestations.

## 0.2.9 — 2026-08-18

- Update `quinn-proto` to address RUSTSEC-2026-0185.
- Add identity creation and deterministic sender selection.
- Correct resource URL and audience handling.

## 0.2.4 — 2026-06-03

- Enforce an exact OAuth redirect URI allowlist.

## 0.2.0 — 2026-06-02

- Add OAuth proxying, RFC 7591 registration shim, and RFC 9728 metadata.

## 0.1.0 — 2026-06-02

- Initial public release.
