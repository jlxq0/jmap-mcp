# Changelog

All notable changes are recorded here. The project uses semantic version tags.

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
