# Configuration reference

## Core guard

| Option | Default | Description |
|---|---:|---|
| `blockThreshold` | `60` | Score at or above which content is blocked |
| `maxRiskScore` | — | Backwards-compatible alias for `blockThreshold` |
| `reviewThreshold` | `30` | Score at or above which content is marked for review |
| `blockOnSeverities` | `["critical"]` | Severities that force a block regardless of score |
| `maxInputBytes` | `65536` | Maximum UTF-8 input size before rules run |
| `ruleTimeoutMs` | `1000` | Time limit per rule; `0` disables the timeout |
| `onRuleError` | `"finding"` | `throw`, `finding`, or `ignore` |
| `stopOnBlock` | `false` | Stop once the result is definitely blocked |
| `normalizeUnicode` | `true` | Apply Unicode NFKC normalization |
| `trimWhitespace` | `true` | Remove leading and trailing whitespace |
| `collapseWhitespace` | `true` | Collapse repeated horizontal whitespace |
| `normalizeLineEndings` | `true` | Convert CRLF and CR to LF |

## Stateful rules

`DuplicateRule` and `RateLimitRule` skip anonymous input by default. Provide `userId`, `ip`, or a custom `keyResolver`.

```ts
new DuplicateRule({
  windowMs: 60_000,
  keyResolver: (input) => {
    const tenant = input.metadata?.tenantId;
    return typeof tenant === "string" && input.userId
      ? `${tenant}:${input.userId}`
      : undefined;
  }
});
```

## Review handling

The core considers `review` allowed so applications can enqueue the content rather than reject it. HTTP adapters expose `rejectOnReview` for stricter endpoints.

```ts
createExpressMiddleware(guard, {
  rejectOnReview: true,
  exposeFindings: false
});
```

## Rule failures

- `finding`: adds a non-sensitive system finding and continues;
- `ignore`: continues without a finding;
- `throw`: propagates the original error.

For public request paths, `finding` is the recommended default. For offline batch processing and tests, `throw` can make failures more visible.
