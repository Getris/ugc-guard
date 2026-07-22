# Testing

The project uses the built-in Node.js test runner. Tests operate on compiled ESM output so the package surface exercised in CI matches what consumers import.

## Commands

```bash
npm test
npm run typecheck
npm run test:coverage
npm pack --dry-run
```

## Current local validation snapshot

Validation performed on 2026-07-22 with Node.js 22:

- 34 tests passed;
- 0 tests failed;
- 85.87% line coverage;
- 77.23% branch coverage;
- 94.05% function coverage;
- TypeScript strict compilation passed;
- package dry-run completed successfully.

Coverage is a diagnostic signal, not proof of security. New behavior should include regression tests focused on boundary conditions and false-positive controls.

## Test categories

- core normalization and decision thresholds;
- oversized input rejection;
- custom-rule failure isolation and timeouts;
- HTML and encoded-markup detection;
- URL, private-network, credential, and protocol policy;
- Unicode controls and mixed-script detection;
- accidental credential patterns;
- duplicate and rate-limit state behavior;
- Express and Fastify adapter disclosure defaults.
