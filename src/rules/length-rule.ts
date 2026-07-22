import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";
import { assertIntegerInRange } from "../core/utils.js";

export type LengthCountMode = "grapheme" | "code-point" | "code-unit";

export interface LengthRuleOptions {
  maxLength: number;
  minLength?: number;
  countMode?: LengthCountMode;
}

export class LengthRule implements GuardRule {
  readonly name = "length";
  readonly #maxLength: number;
  readonly #minLength: number;
  readonly #countMode: LengthCountMode;

  constructor(options: LengthRuleOptions) {
    this.#minLength = options.minLength ?? 0;
    this.#maxLength = options.maxLength;
    this.#countMode = options.countMode ?? "grapheme";

    assertIntegerInRange("minLength", this.#minLength, 0, 10_000_000);
    assertIntegerInRange("maxLength", this.#maxLength, 1, 10_000_000);
    if (this.#minLength > this.#maxLength) {
      throw new RangeError("minLength cannot be greater than maxLength.");
    }
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding | null {
    const length = countLength(context.normalizedText, this.#countMode);

    if (length > this.#maxLength) {
      return {
        rule: this.name,
        code: "TEXT_TOO_LONG",
        message: `Text exceeds the maximum length of ${this.#maxLength} characters.`,
        severity: "medium",
        score: 35,
        category: "content",
        details: { length, maxLength: this.#maxLength, countMode: this.#countMode }
      };
    }

    if (length < this.#minLength) {
      return {
        rule: this.name,
        code: "TEXT_TOO_SHORT",
        message: `Text is shorter than the minimum length of ${this.#minLength} characters.`,
        severity: "low",
        score: 10,
        category: "content",
        details: { length, minLength: this.#minLength, countMode: this.#countMode }
      };
    }

    return null;
  }
}

function countLength(text: string, mode: LengthCountMode): number {
  if (mode === "code-unit") return text.length;
  if (mode === "code-point") return [...text].length;

  const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
  let count = 0;
  for (const _segment of segmenter.segment(text)) count += 1;
  return count;
}
