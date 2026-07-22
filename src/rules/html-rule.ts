import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export class HtmlRule implements GuardRule {
  readonly name = "html";

  inspect(_input: GuardInput, context: RuleContext): GuardFinding | null {
    const dangerousPattern = /<\s*(script|iframe|object|embed|style|link|meta)\b|on\w+\s*=|javascript\s*:/iu;
    const genericTagPattern = /<\/?[a-z][^>]*>/iu;

    if (dangerousPattern.test(context.normalizedText)) {
      return {
        rule: this.name,
        code: "DANGEROUS_HTML",
        message: "Potentially dangerous HTML or script-like content was detected.",
        severity: "high",
        score: 80
      };
    }

    if (genericTagPattern.test(context.normalizedText)) {
      return {
        rule: this.name,
        code: "HTML_DETECTED",
        message: "HTML markup was detected.",
        severity: "medium",
        score: 30
      };
    }

    return null;
  }
}
