import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export class UnicodeRule implements GuardRule {
  readonly name = "unicode";

  inspect(input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];
    const invisible = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/u;

    if (invisible.test(input.text)) {
      findings.push({
        rule: this.name,
        code: "INVISIBLE_CHARACTERS",
        message: "Invisible or bidirectional control characters were detected.",
        severity: "high",
        score: 65
      });
    }

    if (input.text !== context.normalizedText && input.text.normalize("NFKC") === context.normalizedText) {
      findings.push({
        rule: this.name,
        code: "UNICODE_NORMALIZED",
        message: "Compatibility Unicode characters were normalized.",
        severity: "low",
        score: 5
      });
    }

    return findings.length > 0 ? findings : null;
  }
}
