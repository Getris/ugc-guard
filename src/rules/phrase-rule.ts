import type { GuardFinding, GuardInput, GuardRule, RuleContext, Severity } from "../core/types.js";
import { assertIntegerInRange } from "../core/utils.js";

export type PhraseMatchMode = "substring" | "word";

export interface PhraseRuleOptions {
  phrases: string[];
  caseSensitive?: boolean;
  matchMode?: PhraseMatchMode;
  severity?: Severity;
  score?: number;
  revealMatches?: boolean;
  maxMatches?: number;
}

export class PhraseRule implements GuardRule {
  readonly name = "phrase";
  readonly #phrases: string[];
  readonly #caseSensitive: boolean;
  readonly #matchMode: PhraseMatchMode;
  readonly #severity: Severity;
  readonly #score: number;
  readonly #revealMatches: boolean;
  readonly #maxMatches: number;

  constructor(options: PhraseRuleOptions) {
    if (!Array.isArray(options.phrases)) throw new TypeError("phrases must be an array.");

    this.#caseSensitive = options.caseSensitive ?? false;
    this.#matchMode = options.matchMode ?? "substring";
    this.#severity = options.severity ?? "medium";
    this.#score = options.score ?? 40;
    this.#revealMatches = options.revealMatches ?? false;
    this.#maxMatches = options.maxMatches ?? 10;

    assertIntegerInRange("score", this.#score, 0, 100);
    assertIntegerInRange("maxMatches", this.#maxMatches, 1, 1_000);

    const normalized = options.phrases
      .map((value) => value.trim())
      .filter(Boolean)
      .map((value) => this.#caseSensitive ? value : value.toLocaleLowerCase());

    this.#phrases = [...new Set(normalized)].slice(0, 10_000);
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const haystack = this.#caseSensitive ? context.normalizedText : context.normalizedText.toLocaleLowerCase();
    const matches: string[] = [];

    for (const phrase of this.#phrases) {
      if (matches.length >= this.#maxMatches) break;
      const matched = this.#matchMode === "substring"
        ? haystack.includes(phrase)
        : new RegExp(`(?<![\\p{L}\\p{N}_])${escapeRegExp(phrase)}(?![\\p{L}\\p{N}_])`, "u").test(haystack);
      if (matched) matches.push(phrase);
    }

    if (matches.length === 0) return null;

    return matches.map((phrase) => ({
      rule: this.name,
      code: "CONFIGURED_PHRASE_MATCH",
      message: "Content matched a configured phrase policy.",
      severity: this.#severity,
      score: this.#score,
      category: "content",
      details: this.#revealMatches ? { phrase } : { matchLength: [...phrase].length }
    }));
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
