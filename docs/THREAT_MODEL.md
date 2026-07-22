# Threat model

This document defines what UGC Guard attempts to mitigate and what remains outside its scope.

## Protected assets

- application availability;
- moderation policy consistency;
- users who may view attacker-controlled text;
- credentials accidentally pasted into content;
- internal moderation signals and policy details;
- memory used by process-local stateful rules.

## Expected attackers

- unauthenticated or authenticated users submitting crafted text;
- spam accounts repeating content at high frequency;
- users attempting to disguise links or text with Unicode controls;
- users pasting script-like markup into fields expected to contain plain text;
- accidental credential disclosure.

## Mitigated classes

| Threat | Mitigation |
|---|---|
| Oversized input causing unnecessary processing | UTF-8 byte limit before rules run |
| Slow or broken custom rule | Per-rule timeout, abort signal, configurable error policy |
| Invalid custom finding corrupting score | Runtime finding validation and score clamping |
| HTML/script-like input in plain-text fields | Heuristic active-markup detection |
| Private-network and local URL references | Structural URL checks without fetching |
| Embedded URL credentials | Dedicated finding |
| Unicode bidi/zero-width obfuscation | Unicode rule and normalization report |
| Cross-user duplicate false positives | Anonymous detection disabled by default; per-user scope |
| Raw user text retained for duplicate detection | SHA-256 key derivation |
| Unbounded state growth | Maximum store sizes and eviction |
| Internal policy disclosure through middleware | Findings hidden from clients by default |

## Out of scope

UGC Guard does not provide:

- HTML sanitization or context-aware output encoding;
- browser XSS protection by itself;
- malware scanning of files or URLs;
- URL reputation, DNS resolution, or redirect inspection;
- authentication, authorization, CSRF protection, or session security;
- distributed denial-of-service protection;
- reliable identity or IP attribution;
- comprehensive secret scanning;
- legal or policy-complete content moderation;
- model-based classification of meaning or intent.

## Trust boundaries

Custom rules are application code and therefore trusted to the same degree as the host application. Timeouts reduce impact but cannot forcibly terminate synchronous JavaScript or cancel a promise that ignores the supplied signal.

Process-local duplicate and rate-limit stores are suitable for development, low-volume single-process services, and defense in depth. Multi-instance deployments should use shared infrastructure or enforce limits at the edge.

## Safe deployment checklist

1. Enforce request-body limits at the reverse proxy and framework level.
2. Store and render content using context-aware escaping.
3. Keep `exposeFindings` disabled for public clients.
4. Use stable authenticated user or tenant identifiers for stateful rules.
5. Replace process-local stores for horizontally scaled deployments.
6. Log decisions without logging secrets or full rejected content.
7. Measure false positives before enabling blocking policies.
8. Keep moderation appeal and human-review paths available.
