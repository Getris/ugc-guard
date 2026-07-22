# Changelog

All notable changes are documented here. The project follows semantic versioning while acknowledging that pre-`1.0` minor releases may contain documented breaking changes.

## [0.2.0] - 2026-07-22

### Added

- `allow` / `review` / `block` decision model and risk levels.
- Per-rule timeouts, abort signals, and configurable error handling.
- UTF-8 input-size limit before normalization and inspection.
- Runtime validation and score clamping for custom findings.
- `SecretRule` and `RateLimitRule`.
- Private-network, local-host, URL credential, protocol, Punycode, and link-count checks.
- Grapheme-aware length counting.
- Mixed-script, bidi, zero-width, control-character, and malformed-surrogate checks.
- SHA-256 duplicate keys and pluggable duplicate storage.
- Community preset, architecture docs, threat model, and maintainer security review.
- Express and Fastify adapters that hide internal findings by default.
- 34 automated tests, CodeQL, issue templates, CODEOWNERS, and package-lock verification.

### Changed

- Minimum supported Node.js version is now 22.
- CI tests Node.js 22 and 24.
- Package links and badges point to `Getris/ugc-guard`.
- Package name is `@getris/ugc-guard` pending npm publication.

### Security

- Bounded input and state reduce denial-of-service risk.
- Custom rule failures no longer disclose raw internal error messages in findings.
- Duplicate detection no longer stores raw normalized content as map keys.
- HTTP adapters no longer expose scores and policy findings unless explicitly configured.

## [0.1.0] - 2026-07-22

- Initial open-source prototype with configurable content rules and Express/Fastify-compatible adapters.
