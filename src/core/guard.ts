import { normalizeText } from "./normalize.js";
import type { GuardInput, GuardOptions, GuardResult, GuardRule } from "./types.js";

export class ContentGuard {
  readonly #options: Required<Omit<GuardOptions, "rules">>;
  readonly #rules: GuardRule[];

  constructor(options: GuardOptions = {}) {
    this.#options = {
      maxRiskScore: options.maxRiskScore ?? 60,
      normalizeUnicode: options.normalizeUnicode ?? true,
      trimWhitespace: options.trimWhitespace ?? true,
      collapseWhitespace: options.collapseWhitespace ?? true
    };
    this.#rules = [...(options.rules ?? [])];
  }

  use(rule: GuardRule): this {
    this.#rules.push(rule);
    return this;
  }

  async inspect(input: GuardInput): Promise<GuardResult> {
    if (typeof input.text !== "string") {
      throw new TypeError("Guard input text must be a string.");
    }

    const normalizedText = normalizeText(input.text, {
      unicode: this.#options.normalizeUnicode,
      trim: this.#options.trimWhitespace,
      collapseWhitespace: this.#options.collapseWhitespace
    });

    const context = { now: Date.now(), normalizedText };
    const findings = [];

    for (const rule of this.#rules) {
      const result = await rule.inspect(input, context);
      if (Array.isArray(result)) findings.push(...result);
      else if (result) findings.push(result);
    }

    const score = Math.min(100, findings.reduce((sum, finding) => sum + Math.max(0, finding.score), 0));

    return {
      allowed: score < this.#options.maxRiskScore,
      score,
      normalizedText,
      findings
    };
  }
}

export function createGuard(options: GuardOptions = {}): ContentGuard {
  return new ContentGuard(options);
}
