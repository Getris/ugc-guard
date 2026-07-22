import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface SecretRuleOptions {
  detectJwt?: boolean;
}

interface SecretPattern {
  type: string;
  pattern: RegExp;
  score: number;
}

const BASE_PATTERNS: readonly SecretPattern[] = [
  { type: "private-key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/u, score: 100 },
  { type: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/u, score: 100 },
  { type: "aws-access-key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/u, score: 95 },
  { type: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/u, score: 95 },
  { type: "stripe-live-key", pattern: /\bsk_live_[A-Za-z0-9]{16,}\b/u, score: 100 }
];

const JWT_PATTERN: SecretPattern = {
  type: "jwt",
  pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  score: 80
};

export class SecretRule implements GuardRule {
  readonly name = "secret";
  readonly #patterns: readonly SecretPattern[];

  constructor(options: SecretRuleOptions = {}) {
    this.#patterns = options.detectJwt === false ? BASE_PATTERNS : [...BASE_PATTERNS, JWT_PATTERN];
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];

    for (const candidate of this.#patterns) {
      if (!candidate.pattern.test(context.originalText)) continue;
      findings.push({
        rule: this.name,
        code: "POSSIBLE_SECRET",
        message: "Content appears to contain a credential or private key.",
        severity: candidate.score >= 90 ? "critical" : "high",
        score: candidate.score,
        category: "secret",
        details: { type: candidate.type }
      });
    }

    return findings.length > 0 ? findings : null;
  }
}
