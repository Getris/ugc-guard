import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";
import { assertIntegerInRange, assertNumberInRange } from "../core/utils.js";

export interface SpamRuleOptions {
  maxRepeatedCharacter?: number;
  maxRepeatedToken?: number;
  maxUppercaseRatio?: number;
  maxSymbolRatio?: number;
  minLettersForUppercaseCheck?: number;
  minCharactersForSymbolCheck?: number;
}

export class SpamRule implements GuardRule {
  readonly name = "spam";
  readonly #maxRepeatedCharacter: number;
  readonly #maxRepeatedToken: number;
  readonly #maxUppercaseRatio: number;
  readonly #maxSymbolRatio: number;
  readonly #minLettersForUppercaseCheck: number;
  readonly #minCharactersForSymbolCheck: number;

  constructor(options: SpamRuleOptions = {}) {
    this.#maxRepeatedCharacter = options.maxRepeatedCharacter ?? 6;
    this.#maxRepeatedToken = options.maxRepeatedToken ?? 4;
    this.#maxUppercaseRatio = options.maxUppercaseRatio ?? 0.75;
    this.#maxSymbolRatio = options.maxSymbolRatio ?? 0.65;
    this.#minLettersForUppercaseCheck = options.minLettersForUppercaseCheck ?? 12;
    this.#minCharactersForSymbolCheck = options.minCharactersForSymbolCheck ?? 20;

    assertIntegerInRange("maxRepeatedCharacter", this.#maxRepeatedCharacter, 1, 100);
    assertIntegerInRange("maxRepeatedToken", this.#maxRepeatedToken, 1, 100);
    assertNumberInRange("maxUppercaseRatio", this.#maxUppercaseRatio, 0, 1);
    assertNumberInRange("maxSymbolRatio", this.#maxSymbolRatio, 0, 1);
    assertIntegerInRange("minLettersForUppercaseCheck", this.#minLettersForUppercaseCheck, 1, 10_000);
    assertIntegerInRange("minCharactersForSymbolCheck", this.#minCharactersForSymbolCheck, 1, 10_000);
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];
    const text = context.normalizedText;

    if (hasRepeatedCharacter(text, this.#maxRepeatedCharacter)) {
      findings.push({
        rule: this.name,
        code: "REPEATED_CHARACTERS",
        message: "Excessive repeated characters were detected.",
        severity: "medium",
        score: 30,
        category: "spam"
      });
    }

    const tokens = text.toLocaleLowerCase().split(/\s+/u).filter(Boolean);
    let streak = 1;
    for (let index = 1; index < tokens.length; index += 1) {
      streak = tokens[index] === tokens[index - 1] ? streak + 1 : 1;
      if (streak > this.#maxRepeatedToken) {
        findings.push({
          rule: this.name,
          code: "REPEATED_TOKENS",
          message: "A token was repeated too many times in sequence.",
          severity: "medium",
          score: 35,
          category: "spam"
        });
        break;
      }
    }

    const characters = [...text];
    const letters = characters.filter((character) => /\p{L}/u.test(character));
    const uppercase = letters.filter((character) => character === character.toLocaleUpperCase() && character !== character.toLocaleLowerCase());
    if (letters.length >= this.#minLettersForUppercaseCheck && uppercase.length / letters.length >= this.#maxUppercaseRatio) {
      findings.push({
        rule: this.name,
        code: "EXCESSIVE_UPPERCASE",
        message: "Excessive uppercase text was detected.",
        severity: "low",
        score: 20,
        category: "spam",
        details: { ratio: Number((uppercase.length / letters.length).toFixed(3)) }
      });
    }

    const visible = characters.filter((character) => !/\s/u.test(character));
    const symbols = visible.filter((character) => /[\p{S}\p{P}]/u.test(character));
    if (visible.length >= this.#minCharactersForSymbolCheck && symbols.length / visible.length >= this.#maxSymbolRatio) {
      findings.push({
        rule: this.name,
        code: "EXCESSIVE_SYMBOLS",
        message: "An unusually high ratio of symbols or punctuation was detected.",
        severity: "medium",
        score: 25,
        category: "spam",
        details: { ratio: Number((symbols.length / visible.length).toFixed(3)) }
      });
    }

    return findings.length > 0 ? findings : null;
  }
}

function hasRepeatedCharacter(text: string, maximum: number): boolean {
  let previous = "";
  let streak = 0;

  for (const character of text) {
    if (character === previous) streak += 1;
    else {
      previous = character;
      streak = 1;
    }
    if (streak > maximum) return true;
  }

  return false;
}
