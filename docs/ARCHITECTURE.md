# Architecture

UGC Guard is intentionally small and dependency-free at runtime. The package is divided into four layers.

## 1. Core engine

`ContentGuard` owns normalization, rule execution, timeouts, error handling, finding sanitization, scoring, and the final decision.

The engine runs rules sequentially by default. This preserves deterministic behavior for stateful rules such as duplicate detection and rate limiting. A rule receives a read-only context with the original text, normalized text, normalization events, current time, and an `AbortSignal`.

## 2. Rules

Rules are independent policy units. They do not mutate the input and should not perform network requests unless an application author deliberately implements such a custom rule.

A rule may return:

- one finding;
- multiple findings;
- `null` or `undefined`;
- a promise of any of the above.

The core sanitizes findings from custom rules before scoring them. Invalid or infinite scores cannot poison the final result.

## 3. Presets

Presets compose existing rules into an opinionated baseline. `createCommunityGuard()` is intended for comments, posts, profiles, and chat. It is not a hidden policy layer: every included rule is exported and can be configured independently.

## 4. Adapters

Framework adapters translate HTTP request shapes into `GuardInput`. They attach the full result to the server-side request object and return a minimal error response by default.

## Data flow

```text
raw text
  │
  ├─ input byte limit
  │
  ├─ line-ending normalization
  ├─ Unicode NFKC normalization
  ├─ horizontal whitespace collapse
  └─ trimming
       │
       ▼
sequential rule execution
       │
       ├─ timeout / abort signal
       ├─ error isolation
       └─ finding sanitization
             │
             ▼
       score + severity policy
             │
             ▼
      allow / review / block
```

## Extension points

- `GuardRule` for custom policy logic.
- `DuplicateStore` for Redis, SQL, key-value, or distributed storage.
- `keyResolver` callbacks for user, tenant, session, device, or IP scoping.
- framework adapters can be copied or implemented for any request lifecycle.

## Design constraints

- No outbound network requests.
- No runtime dependencies.
- No raw-content storage in duplicate detection.
- Bounded default in-memory state.
- Safe defaults must remain explicit and overrideable.
- Detection rules must not claim to sanitize or prove safety.
