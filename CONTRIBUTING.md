# Contributing

Thank you for helping improve Zooplio UGC Guard.

## Before opening a pull request

1. Create a focused branch from `main`.
2. Add or update tests for behavioral changes.
3. Run `npm ci`, `npm test`, and `npm run typecheck`.
4. Document public API changes in the README or configuration reference.
5. Keep runtime dependencies at zero unless there is a strong, documented reason to change that constraint.

## Design expectations

- Detection rules must describe signals, not claim to prove that content is safe or malicious.
- Avoid network requests in built-in rules.
- Bound memory, iteration counts, and user-configurable values.
- Do not echo suspected secrets or full blocked content in findings.
- Preserve useful false-positive controls.
- New stateful rules need a strategy for multi-process deployments.

## Bug reports

Include the package version, Node.js version, minimal safe reproduction, expected behavior, and actual behavior. Never submit real credentials, personal data, private URLs, malware, or active exploit payloads.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
