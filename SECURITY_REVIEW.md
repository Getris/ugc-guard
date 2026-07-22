# Maintainer security review

**Review date:** 2026-07-22  
**Scope:** version `0.2.0` source, tests, package metadata, and GitHub workflows  
**Status:** internal maintainer review, not an independent security audit

## Findings addressed in 0.2.0

### High: unbounded or stalled custom-rule execution

**Previous behavior:** a custom asynchronous rule could stall the entire inspection pipeline indefinitely.

**Mitigation:** configurable per-rule timeouts, an `AbortSignal`, and explicit `throw` / `finding` / `ignore` failure modes.

**Residual risk:** synchronous JavaScript cannot be preempted, and asynchronous code must cooperate with the abort signal to stop its underlying work.

### High: private-network and credential-bearing URLs were not distinguished

**Previous behavior:** raw IP addresses were detected with a loose pattern, but private ranges, local hosts, embedded credentials, and dangerous schemes were not handled consistently.

**Mitigation:** validated IPv4 parsing, private/loopback detection, local hostname checks, protocol policy, URL credential detection, inspection limits, and deduplicated findings.

### Medium: duplicate detection retained raw normalized content

**Previous behavior:** the in-memory map key contained the user scope and full normalized content.

**Mitigation:** keys now use SHA-256. Anonymous duplicate matching is disabled by default, storage is pluggable, and the default store is bounded.

### Medium: custom findings could return invalid scores

**Previous behavior:** `NaN`, infinity, or malformed fields from custom rules could produce unpredictable scoring.

**Mitigation:** every finding is validated, normalized, and clamped before scoring.

### Medium: middleware disclosed complete policy findings

**Previous behavior:** rejected responses included the complete guard result, which could reveal internal rules and tuning.

**Mitigation:** public responses now hide scores and findings by default. The full result remains available server-side as `request.ugcGuard`.

### Medium: input size was not bounded by the core

**Previous behavior:** very large strings reached normalization and every rule.

**Mitigation:** a configurable UTF-8 byte limit is enforced before normalization and rule execution.

### Medium: option validation was incomplete

**Previous behavior:** invalid repeated-character thresholds, score ranges, length bounds, and ratios could create incorrect behavior or invalid regular expressions.

**Mitigation:** constructors validate bounds and relationships.

### Low: Unicode normalization reporting was ambiguous

**Previous behavior:** whitespace normalization could prevent accurate detection of NFKC changes.

**Mitigation:** normalization is now a first-class pipeline that records individual change types.

### Low: Node.js 20 remained in CI after end of support

**Mitigation:** package support and CI were moved to maintained Node.js release lines. GitHub Actions use Node 24-compatible major versions.

## Additional hardening

- added secret-shape detection without echoing suspected credentials;
- added mixed-script, bidi, malformed surrogate, and control-character checks;
- added CodeQL workflow and stricter workflow permissions;
- added a lockfile and `npm ci --ignore-scripts` in CI;
- added security-focused tests and package dry-run checks;
- documented trust boundaries and explicit non-goals.

## Known limitations

- detection remains heuristic and bypasses are possible;
- link checks do not establish destination reputation;
- in-memory state is process-local;
- SHA-256 keys do not prevent offline guessing of low-entropy content if storage is exposed and no `hashSalt` is configured;
- a malicious synchronous custom rule can still block the JavaScript event loop;
- regular expressions are intentionally bounded where practical, but this review is not a formal ReDoS proof.

## Recommended next work

1. Add Redis and generic async key-value adapters outside the core package.
2. Add fuzz/property tests for URL extraction, Unicode, and markup detection.
3. Pin GitHub Actions to audited full commit SHAs.
4. Add release provenance and npm trusted publishing when the package is published.
5. Request an independent review before advertising the package as production-grade security software.
