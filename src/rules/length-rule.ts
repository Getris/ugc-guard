import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface LengthRuleOptions {
  maxLength: number;
  minLength?: number;
}

export class LengthRule implements GuardRule {
  readonly name = "length";
  readonly #maxLength: number;
  readonly #minLength: number;

  constructor(options: LengthRuleOptions) {
    if (!Number.isInteger(options.maxLength) || options.maxLength < 1) {
      throw new RangeError("maxLength must be a positive integer.");
    }
    this.#maxLength = options.maxLength;
    this.#minLength = options.minLength ?? 0;
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding | null {
    const length = [...context.normalizedText].length;
    if (length > this.#maxLength) {
      return {
        rule: this.name,
        code: "TEXT_TOO_LONG",
        message: `Text exceeds the maximum length of ${this.#maxLength} characters.`,
        severity: "medium",
        score: 35,
        details: { length, maxLength: this.#maxLength }
      };
    }
    if (length < this.#minLength) {
      return {
        rule: this.name,
        code: "TEXT_TOO_SHORT",
        message: `Text is shorter than the minimum length of ${this.#minLength} characters.`,
        severity: "low",
        score: 10,
        details: { length, minLength: this.#minLength }
      };
    }
    return null;
  }
}
