# Zooplio UGC Guard

[![CI](https://github.com/Getris/ugc-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Getris/ugc-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight, dependency-free runtime toolkit for inspecting user-generated content in TypeScript and Node.js applications.

> This project provides defensive signals, not a complete moderation or security system. Always combine it with output encoding, rate limiting, authentication, authorization, platform abuse controls, and human review where appropriate.

## Features

- Unicode NFKC normalization and suspicious control-character detection
- Basic HTML and script-like payload detection
- URL allowlists, blocklists, shortened-link detection, and raw-IP detection
- Length limits, repeated-character checks, uppercase checks, and repeated-token checks
- Configurable phrase matching
- In-memory duplicate-content detection scoped by user
- Small Express-compatible and Fastify-compatible adapters
- Zero runtime dependencies
- Strict TypeScript types and automated tests

## Install

```bash
npm install @getris/ugc-guard
```

Until the package is published to npm, install directly from GitHub:

```bash
npm install github:Getris/ugc-guard
```

## Basic usage

```ts
import {
  createGuard,
  DuplicateRule,
  HtmlRule,
  LengthRule,
  LinkRule,
  PhraseRule,
  SpamRule,
  UnicodeRule
} from "@getris/ugc-guard";

const guard = createGuard({
  maxRiskScore: 60,
  rules: [
    new LengthRule({ maxLength: 500 }),
    new HtmlRule(),
    new LinkRule({
      blockedHosts: ["example-malware.test"],
      blockIpHosts: true,
      blockShorteners: true
    }),
    new PhraseRule({ phrases: ["configured blocked phrase"] }),
    new SpamRule(),
    new DuplicateRule({ windowMs: 60_000 }),
    new UnicodeRule()
  ]
});

const result = await guard.inspect({
  text: userComment,
  userId: currentUser.id
});

if (!result.allowed) {
  console.log(result.findings);
}
```

## Result shape

```ts
{
  allowed: false,
  score: 80,
  normalizedText: "...",
  findings: [
    {
      rule: "html",
      code: "DANGEROUS_HTML",
      message: "Potentially dangerous HTML or script-like content was detected.",
      severity: "high",
      score: 80
    }
  ]
}
```

A result is rejected when its total score is greater than or equal to `maxRiskScore`. Scores are capped at 100.

## Express-compatible middleware

The adapter uses structural types, so Express is not required as a package dependency.

```ts
import express from "express";
import { createGuard, HtmlRule, SpamRule } from "@getris/ugc-guard";
import { createExpressMiddleware } from "@getris/ugc-guard/express";

const app = express();
const guard = createGuard({ rules: [new HtmlRule(), new SpamRule()] });

app.use(express.json());
app.post("/comments", createExpressMiddleware(guard, { field: "text" }), (req, res) => {
  res.status(201).json({ text: req.body.text });
});
```

## Custom rules

```ts
import type { GuardRule } from "@getris/ugc-guard";

const noEmptyContent: GuardRule = {
  name: "no-empty-content",
  inspect(_input, context) {
    if (context.normalizedText.length > 0) return null;
    return {
      rule: this.name,
      code: "EMPTY_CONTENT",
      message: "Content must not be empty.",
      severity: "medium",
      score: 60
    };
  }
};
```

## Development

```bash
npm install
npm test
```

## Security and limitations

Regex-based inspection can produce false positives and false negatives. This library does not sanitize HTML and does not guarantee that a URL is safe. For browser rendering, use context-aware escaping or a dedicated sanitizer. For production abuse prevention, use persistent rate limits and shared storage rather than the in-memory duplicate rule.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License and trademark

The source code is available under the [MIT License](LICENSE).

“Zooplio” and associated branding may be trademarks of their respective owner. The MIT License covers the source code and does not grant permission to use Zooplio names, logos, or branding to imply endorsement.
