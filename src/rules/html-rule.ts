import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface HtmlRuleOptions {
  allowBasicMarkup?: boolean;
}

const DANGEROUS_TAG = /<\s*\/?\s*(?:script|iframe|object|embed|style|link|meta|base|form|input|button|svg|math)\b/iu;
const EVENT_HANDLER = /\bon[a-z][a-z0-9_-]*\s*=/iu;
const ACTIVE_SCHEME = /(?:javascript|vbscript)\s*:/iu;
const HTML_DATA_URL = /data\s*:\s*text\/(?:html|xml)|data\s*:\s*image\/svg\+xml/iu;
const CSS_EXECUTION = /(?:expression\s*\(|url\s*\(\s*["']?\s*javascript\s*:)/iu;
const GENERIC_TAG = /<\/?[a-z][^>]{0,2000}>/iu;

export class HtmlRule implements GuardRule {
  readonly name = "html";
  readonly #allowBasicMarkup: boolean;

  constructor(options: HtmlRuleOptions = {}) {
    this.#allowBasicMarkup = options.allowBasicMarkup ?? false;
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const findings: GuardFinding[] = [];
    const decoded = decodeSecurityRelevantEntities(context.normalizedText);

    if (
      DANGEROUS_TAG.test(decoded)
      || EVENT_HANDLER.test(decoded)
      || ACTIVE_SCHEME.test(decoded)
      || HTML_DATA_URL.test(decoded)
      || CSS_EXECUTION.test(decoded)
    ) {
      findings.push({
        rule: this.name,
        code: "ACTIVE_MARKUP_DETECTED",
        message: "Potentially executable HTML, SVG, CSS, or script-like content was detected.",
        severity: "critical",
        score: 90,
        category: "content"
      });
    } else if (!this.#allowBasicMarkup && GENERIC_TAG.test(decoded)) {
      findings.push({
        rule: this.name,
        code: "HTML_MARKUP_DETECTED",
        message: "HTML-like markup was detected.",
        severity: "medium",
        score: 30,
        category: "content"
      });
    }

    if (decoded !== context.normalizedText && GENERIC_TAG.test(decoded)) {
      findings.push({
        rule: this.name,
        code: "ENCODED_MARKUP_DETECTED",
        message: "HTML-like markup was hidden with character references.",
        severity: "high",
        score: 55,
        category: "content"
      });
    }

    return findings.length > 0 ? findings : null;
  }
}

function decodeSecurityRelevantEntities(text: string): string {
  return text
    .replace(/&lt;?/giu, "<")
    .replace(/&gt;?/giu, ">")
    .replace(/&#0*60;?/giu, "<")
    .replace(/&#x0*3c;?/giu, "<")
    .replace(/&#0*62;?/giu, ">")
    .replace(/&#x0*3e;?/giu, ">");
}
