import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";
import { assertIntegerInRange } from "../core/utils.js";

export interface LinkRuleOptions {
  allowedHosts?: string[];
  blockedHosts?: string[];
  allowedProtocols?: string[];
  blockIpHosts?: boolean;
  blockPrivateNetworks?: boolean;
  blockLocalHosts?: boolean;
  blockShorteners?: boolean;
  flagPunycode?: boolean;
  blockCredentials?: boolean;
  maxLinks?: number;
  maxUrlsToInspect?: number;
}

const DEFAULT_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
  "cutt.ly", "shorturl.at", "rebrand.ly", "tiny.cc", "rb.gy"
]);

export class LinkRule implements GuardRule {
  readonly name = "link";
  readonly #allowedHosts: Set<string>;
  readonly #blockedHosts: Set<string>;
  readonly #allowedProtocols: Set<string>;
  readonly #blockIpHosts: boolean;
  readonly #blockPrivateNetworks: boolean;
  readonly #blockLocalHosts: boolean;
  readonly #blockShorteners: boolean;
  readonly #flagPunycode: boolean;
  readonly #blockCredentials: boolean;
  readonly #maxLinks: number;
  readonly #maxUrlsToInspect: number;

  constructor(options: LinkRuleOptions = {}) {
    this.#allowedHosts = new Set((options.allowedHosts ?? []).map(normalizeHost).filter(Boolean));
    this.#blockedHosts = new Set((options.blockedHosts ?? []).map(normalizeHost).filter(Boolean));
    this.#allowedProtocols = new Set((options.allowedProtocols ?? ["http:", "https:"]).map(normalizeProtocol));
    this.#blockIpHosts = options.blockIpHosts ?? true;
    this.#blockPrivateNetworks = options.blockPrivateNetworks ?? true;
    this.#blockLocalHosts = options.blockLocalHosts ?? true;
    this.#blockShorteners = options.blockShorteners ?? true;
    this.#flagPunycode = options.flagPunycode ?? true;
    this.#blockCredentials = options.blockCredentials ?? true;
    this.#maxLinks = options.maxLinks ?? 8;
    this.#maxUrlsToInspect = options.maxUrlsToInspect ?? 25;

    assertIntegerInRange("maxLinks", this.#maxLinks, 0, 10_000);
    assertIntegerInRange("maxUrlsToInspect", this.#maxUrlsToInspect, 1, 10_000);
  }

  inspect(_input: GuardInput, context: RuleContext): GuardFinding[] | null {
    const candidates = [...new Set(extractUrlCandidates(context.normalizedText))];
    const findings: GuardFinding[] = [];

    if (candidates.length > this.#maxLinks) {
      findings.push({
        rule: this.name,
        code: "TOO_MANY_LINKS",
        message: `Content contains more than ${this.#maxLinks} links.`,
        severity: "medium",
        score: 35,
        category: "link",
        details: { count: candidates.length, maxLinks: this.#maxLinks }
      });
    }

    for (const raw of candidates.slice(0, this.#maxUrlsToInspect)) {
      if (/^(?:javascript|vbscript|data|file):/iu.test(raw)) {
        findings.push(makeFinding("DANGEROUS_URL_SCHEME", "A dangerous or unsupported URL scheme was detected.", 90, { scheme: raw.split(":", 1)[0]?.toLowerCase() }));
        continue;
      }

      const value = /^[a-z][a-z0-9+.-]*:\/\//iu.test(raw)
        ? raw
        : `https://${raw.replace(/^www\./iu, "")}`;

      try {
        const url = new URL(value);
        const host = normalizeHost(url.hostname);
        const protocol = normalizeProtocol(url.protocol);

        if (!this.#allowedProtocols.has(protocol)) {
          findings.push(makeFinding("UNAPPROVED_PROTOCOL", "A link uses a protocol that is not allowed.", 70, { protocol }));
        }
        if (this.#allowedHosts.size > 0 && !matchesHostSet(host, this.#allowedHosts)) {
          findings.push(makeFinding("UNAPPROVED_HOST", "A link points to a host that is not on the allowlist.", 45, { host }));
        }
        if (matchesHostSet(host, this.#blockedHosts)) {
          findings.push(makeFinding("BLOCKED_HOST", "A link points to a blocked host.", 85, { host }));
        }
        if (this.#blockCredentials && (url.username || url.password)) {
          findings.push(makeFinding("URL_CREDENTIALS", "Credentials embedded in a URL were detected.", 75, { host }));
        }
        if (this.#blockLocalHosts && isLocalHost(host)) {
          findings.push(makeFinding("LOCAL_HOST", "A link points to a local-only hostname.", 65, { host }));
        }

        const ipVersion = getIpVersion(host);
        if (this.#blockIpHosts && ipVersion > 0) {
          findings.push(makeFinding("IP_HOST", "A link uses a raw IP address.", 55, { host, ipVersion }));
        }
        if (this.#blockPrivateNetworks && ipVersion > 0 && isPrivateIp(host)) {
          findings.push(makeFinding("PRIVATE_NETWORK_HOST", "A link points to a private or loopback network address.", 80, { host }));
        }
        if (this.#blockShorteners && DEFAULT_SHORTENERS.has(host)) {
          findings.push(makeFinding("URL_SHORTENER", "A shortened URL was detected.", 35, { host }));
        }
        if (this.#flagPunycode && host.split(".").some((label) => label.startsWith("xn--"))) {
          findings.push(makeFinding("PUNYCODE_HOST", "An internationalized hostname encoded with Punycode was detected.", 35, { host }));
        }
      } catch {
        findings.push(makeFinding("MALFORMED_URL", "A malformed URL-like value was detected.", 25, {}));
      }
    }

    if (candidates.length > this.#maxUrlsToInspect) {
      findings.push(makeFinding(
        "URL_INSPECTION_LIMIT_REACHED",
        "Not every detected URL was inspected because the configured safety limit was reached.",
        20,
        { count: candidates.length, inspected: this.#maxUrlsToInspect }
      ));
    }

    return deduplicateFindings(findings);
  }
}

export function extractUrlCandidates(text: string): string[] {
  const matches = text.match(
    /(?:javascript|vbscript|data|file):[^\s<>"'`]+|(?:[a-z][a-z0-9+.-]*:\/\/|www\.)[^\s<>"'`]+|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:\/[^\s<>"'`]*)?/giu
  ) ?? [];

  return matches.map((value) => value.replace(/[),.;!?\]}]+$/u, ""));
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/^www\./u, "").replace(/\.$/u, "");
}

function normalizeProtocol(protocol: string): string {
  const value = protocol.trim().toLowerCase();
  return value.endsWith(":") ? value : `${value}:`;
}

function matchesHostSet(host: string, set: Set<string>): boolean {
  for (const candidate of set) {
    if (host === candidate || host.endsWith(`.${candidate}`)) return true;
  }
  return false;
}

function getIpVersion(host: string): 0 | 4 | 6 {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(host)) {
    const parts = host.split(".").map(Number);
    return parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) ? 4 : 0;
  }
  if (host.includes(":") && /^[0-9a-f:.]+$/iu.test(host)) return 6;
  return 0;
}

function isLocalHost(host: string): boolean {
  return host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal");
}

function isPrivateIp(host: string): boolean {
  if (getIpVersion(host) === 4) {
    const parts = host.split(".").map(Number);
    const first = parts[0] ?? -1;
    const second = parts[1] ?? -1;
    return first === 10
      || first === 127
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || first === 0;
  }

  const normalized = host.toLowerCase();
  return normalized === "::1"
    || normalized === "::"
    || normalized.startsWith("fc")
    || normalized.startsWith("fd")
    || normalized.startsWith("fe8")
    || normalized.startsWith("fe9")
    || normalized.startsWith("fea")
    || normalized.startsWith("feb");
}

function makeFinding(code: string, message: string, score: number, details: Record<string, unknown>): GuardFinding {
  return {
    rule: "link",
    code,
    message,
    severity: score >= 90 ? "critical" : score >= 60 ? "high" : score >= 30 ? "medium" : "low",
    score,
    category: "link",
    details
  };
}

function deduplicateFindings(findings: GuardFinding[]): GuardFinding[] | null {
  const seen = new Set<string>();
  const unique = findings.filter((finding) => {
    const key = `${finding.code}:${JSON.stringify(finding.details ?? {})}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return unique.length > 0 ? unique : null;
}
