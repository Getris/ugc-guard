import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface SpamRuleOptions {
  maxRepeatedCharacter?: number;
  maxRepeatedToken?: number;
  maxUppercaseRatio?: number;
}

export class SpamRule implements GuardRule {
  readonly name = "spam";
  readonly #maxRepeatedCharacter: number;
  readonly #maxRepeatedToken: number;
  readonly #maxUppercaseRatio: number;

  constructor(options: SpamRuleOptions = {}) {
    this.#maxRepeatedCharacter = options.maxRepeatedCharacter ?? 6;
    this.#maxRepeatedToken = options.maxRepeatedToken ?? 4;
    this.#maxUppercaseRatio = options.maxUppercaseRatio ?? 0.75;
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];
    const text = context.normalizedText;

    const repeatedCharacter = new RegExp(`(.)\\1{${this.#maxRepeatedCharacter},}`, "iu");
    if (repeatedCharacter.test(text)) {
      findings.push({ rule: this.name, code: "REPEATED_CHARACTERS", message: "Excessive repeated characters were detected.", severity: "medium", score: 30 });
    }

    const tokens = text.toLocaleLowerCase().split(/\s+/u).filter(Boolean);
    let streak = 1;
    for (let i = 1; i < tokens.length; i += 1) {
      streak = tokens[i] === tokens[i - 1] ? streak + 1 : 1;
      if (streak > this.#maxRepeatedToken) {
        findings.push({ rule: this.name, code: "REPEATED_TOKENS", message: "A token was repeated too many times.", severity: "medium", score: 35 });
        break;
      }
    }

    const letters = [...text].filter((char) => /\p{L}/u.test(char));
    const uppercase = letters.filter((char) => char === char.toLocaleUpperCase() && char !== char.toLocaleLowerCase());
    if (letters.length >= 12 && uppercase.length / letters.length >= this.#maxUppercaseRatio) {
      findings.push({ rule: this.name, code: "EXCESSIVE_UPPERCASE", message: "Excessive uppercase text was detected.", severity: "low", score: 20 });
    }

    return findings.length > 0 ? findings : null;
  }
}
