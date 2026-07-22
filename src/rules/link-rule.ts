import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";

export interface LinkRuleOptions {
  allowedHosts?: string[];
  blockedHosts?: string[];
  blockIpHosts?: boolean;
  blockShorteners?: boolean;
}

const DEFAULT_SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly"]);

export class LinkRule implements GuardRule {
  readonly name = "link";
  readonly #allowedHosts: Set<string>;
  readonly #blockedHosts: Set<string>;
  readonly #blockIpHosts: boolean;
  readonly #blockShorteners: boolean;

  constructor(options: LinkRuleOptions = {}) {
    this.#allowedHosts = new Set((options.allowedHosts ?? []).map(normalizeHost));
    this.#blockedHosts = new Set((options.blockedHosts ?? []).map(normalizeHost));
    this.#blockIpHosts = options.blockIpHosts ?? true;
    this.#blockShorteners = options.blockShorteners ?? true;
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const urls = extractUrls(context.normalizedText);
    const findings: GuardFinding[] = [];

    for (const raw of urls) {
      const value = /^https?:\/\//iu.test(raw) ? raw : `https://${raw}`;
      try {
        const url = new URL(value);
        const host = normalizeHost(url.hostname);

        if (this.#allowedHosts.size > 0 && !matchesHostSet(host, this.#allowedHosts)) {
          findings.push(makeFinding("UNAPPROVED_HOST", "A link points to a host that is not on the allowlist.", 45, host));
        }
        if (matchesHostSet(host, this.#blockedHosts)) {
          findings.push(makeFinding("BLOCKED_HOST", "A link points to a blocked host.", 80, host));
        }
        if (this.#blockIpHosts && isIpAddress(host)) {
          findings.push(makeFinding("IP_HOST", "A link uses a raw IP address.", 55, host));
        }
        if (this.#blockShorteners && DEFAULT_SHORTENERS.has(host)) {
          findings.push(makeFinding("URL_SHORTENER", "A shortened URL was detected.", 35, host));
        }
      } catch {
        findings.push(makeFinding("MALFORMED_URL", "A malformed URL-like value was detected.", 25, raw));
      }
    }

    return findings.length > 0 ? findings : null;
  }
}

function extractUrls(text: string): string[] {
  return text.match(/(?:https?:\/\/|www\.)[^\s<>()]+|\b[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s<>()]*)?/giu) ?? [];
}

function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/^www\./u, "").replace(/\.$/u, "");
}

function matchesHostSet(host: string, set: Set<string>): boolean {
  for (const candidate of set) {
    if (host === candidate || host.endsWith(`.${candidate}`)) return true;
  }
  return false;
}

function isIpAddress(host: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host) || host.includes(":");
}

function makeFinding(code: string, message: string, score: number, host: string): GuardFinding {
  return {
    rule: "link",
    code,
    message,
    severity: score >= 60 ? "high" : "medium",
    score,
    details: { host }
  };
}
