import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface DuplicateRuleOptions {
  windowMs?: number;
  maxEntries?: number;
}

export class DuplicateRule implements GuardRule {
  readonly name = "duplicate";
  readonly #windowMs: number;
  readonly #maxEntries: number;
  readonly #seen = new Map<string, number>();

  constructor(options: DuplicateRuleOptions = {}) {
    this.#windowMs = options.windowMs ?? 60_000;
    this.#maxEntries = options.maxEntries ?? 10_000;
  }

  inspect(input: GuardInput, context: RuleContext): GuardFinding | null {
    this.#prune(context.now);
    const scope = input.userId ?? "anonymous";
    const digest = `${scope}\0${context.normalizedText}`;
    const previous = this.#seen.get(digest);
    this.#seen.set(digest, context.now);

    if (previous !== undefined && context.now - previous <= this.#windowMs) {
      return {
        rule: this.name,
        code: "DUPLICATE_CONTENT",
        message: "Duplicate content was submitted within the configured time window.",
        severity: "medium",
        score: 45,
        details: { windowMs: this.#windowMs }
      };
    }
    return null;
  }

  #prune(now: number): void {
    for (const [key, timestamp] of this.#seen) {
      if (now - timestamp > this.#windowMs) this.#seen.delete(key);
    }
    while (this.#seen.size > this.#maxEntries) {
      const first = this.#seen.keys().next().value as string | undefined;
      if (first === undefined) break;
      this.#seen.delete(first);
    }
  }
}
