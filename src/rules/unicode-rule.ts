import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

const ZERO_WIDTH = /[\u200B-\u200D\u2060\uFEFF]/u;
const BIDI_CONTROL = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;
const UNEXPECTED_CONTROL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/u;

export interface UnicodeRuleOptions {
  detectMixedScripts?: boolean;
}

export class UnicodeRule implements GuardRule {
  readonly name = "unicode";
  readonly #detectMixedScripts: boolean;

  constructor(options: UnicodeRuleOptions = {}) {
    this.#detectMixedScripts = options.detectMixedScripts ?? true;
  }

  inspect(input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];

    if (ZERO_WIDTH.test(input.text)) {
      findings.push(makeFinding("ZERO_WIDTH_CHARACTERS", "Zero-width characters were detected.", 55));
    }
    if (BIDI_CONTROL.test(input.text)) {
      findings.push(makeFinding("BIDI_CONTROL_CHARACTERS", "Bidirectional text control characters were detected.", 75));
    }
    if (UNEXPECTED_CONTROL.test(input.text)) {
      findings.push(makeFinding("CONTROL_CHARACTERS", "Unexpected control characters were detected.", 60));
    }
    if (input.text.includes("\uFFFD")) {
      findings.push(makeFinding("REPLACEMENT_CHARACTER", "Unicode replacement characters were detected.", 25));
    }
    if (hasUnpairedSurrogate(input.text)) {
      findings.push(makeFinding("UNPAIRED_SURROGATE", "Malformed UTF-16 surrogate data was detected.", 65));
    }
    if (context.normalizations.some((change) => change.type === "unicode")) {
      findings.push(makeFinding("UNICODE_NORMALIZED", "Compatibility Unicode characters were normalized.", 5));
    }
    if (this.#detectMixedScripts && hasSuspiciousMixedScriptToken(context.normalizedText)) {
      findings.push(makeFinding("MIXED_SCRIPT_TOKEN", "A token mixes scripts commonly used in look-alike text.", 35));
    }

    return findings.length > 0 ? findings : null;
  }
}

function makeFinding(code: string, message: string, score: number): GuardFinding {
  return {
    rule: "unicode",
    code,
    message,
    severity: score >= 60 ? "high" : score >= 30 ? "medium" : "low",
    score,
    category: "unicode"
  };
}

function hasUnpairedSurrogate(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xD800 && code <= 0xDBFF) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xDC00 && next <= 0xDFFF)) return true;
      index += 1;
    } else if (code >= 0xDC00 && code <= 0xDFFF) {
      return true;
    }
  }
  return false;
}

function hasSuspiciousMixedScriptToken(text: string): boolean {
  for (const token of text.split(/[\s\p{P}\p{S}]+/u)) {
    if (token.length < 3) continue;
    const latin = /\p{Script=Latin}/u.test(token);
    const cyrillic = /\p{Script=Cyrillic}/u.test(token);
    const greek = /\p{Script=Greek}/u.test(token);
    if ((latin && cyrillic) || (latin && greek)) return true;
  }
  return false;
}
