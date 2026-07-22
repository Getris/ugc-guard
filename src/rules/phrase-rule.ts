import type { GuardFinding, GuardInput, GuardRule, RuleContext, Severity } from "../core/types.js";

export interface PhraseRuleOptions {
  phrases: string[];
  caseSensitive?: boolean;
  severity?: Severity;
  score?: number;
}

export class PhraseRule implements GuardRule {
  readonly name = "phrase";
  readonly #phrases: string[];
  readonly #caseSensitive: boolean;
  readonly #severity: Severity;
  readonly #score: number;

  constructor(options: PhraseRuleOptions) {
    this.#caseSensitive = options.caseSensitive ?? false;
    this.#phrases = options.phrases.filter(Boolean).map((value) => this.#caseSensitive ? value : value.toLocaleLowerCase());
    this.#severity = options.severity ?? "medium";
    this.#score = options.score ?? 40;
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const haystack = this.#caseSensitive ? context.normalizedText : context.normalizedText.toLocaleLowerCase();
    const matches = this.#phrases.filter((phrase) => haystack.includes(phrase));
    if (matches.length === 0) return null;

    return matches.map((phrase) => ({
      rule: this.name,
      code: "BLOCKED_PHRASE",
      message: "A configured blocked phrase was detected.",
      severity: this.#severity,
      score: this.#score,
      details: { phrase }
    }));
  }
}
