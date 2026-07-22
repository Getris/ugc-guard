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
      if (hasDangerousScheme(raw)) {
        findings.push(makeFinding("DANGEROUS_URL_SCHEME", "A dangerous or unsupported URL scheme was detected.", 90, { scheme: raw.split(":", 1)[0]?.toLowerCase() }));
        continue;
      }

      const value = hasHierarchicalScheme(raw)
        ? raw
        : `https://${removeWwwPrefix(raw)}`;

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

const MAX_URL_CANDIDATE_LENGTH = 2_048;
const DANGEROUS_SCHEMES = ["javascript:", "vbscript:", "data:", "file:"] as const;

export function extractUrlCandidates(text: string): string[] {
  const candidates: string[] = [];
  let tokenStart = -1;

  for (let index = 0; index <= text.length; index += 1) {
    const character = index < text.length ? text[index] : undefined;

    if (character !== undefined && !isUrlTokenDelimiter(character)) {
      if (tokenStart < 0) tokenStart = index;
      continue;
    }

    if (tokenStart < 0) continue;

    const rawToken = text.slice(tokenStart, Math.min(index, tokenStart + MAX_URL_CANDIDATE_LENGTH));
    tokenStart = -1;

    const candidate = trimUrlPunctuation(rawToken);
    if (candidate.length > 0 && isUrlLikeCandidate(candidate)) {
      candidates.push(candidate);
    }
  }

  return candidates;
}

function isUrlTokenDelimiter(character: string): boolean {
  return character === "<"
    || character === ">"
    || character === '"'
    || character === "'"
    || character === "`"
    || character.trim().length === 0;
}

function trimUrlPunctuation(value: string): string {
  let start = 0;
  let end = value.length;

  while (start < end && isLeadingUrlPunctuation(value[start] ?? "")) start += 1;
  while (end > start && isTrailingUrlPunctuation(value[end - 1] ?? "")) end -= 1;

  return value.slice(start, end);
}

function isLeadingUrlPunctuation(character: string): boolean {
  return character === "(" || character === "[" || character === "{";
}

function isTrailingUrlPunctuation(character: string): boolean {
  return character === ")"
    || character === "]"
    || character === "}"
    || character === ","
    || character === "."
    || character === ";"
    || character === "!"
    || character === "?";
}

function isUrlLikeCandidate(value: string): boolean {
  if (hasDangerousScheme(value) || hasHierarchicalScheme(value) || startsWithIgnoreCase(value, "www.")) {
    return true;
  }

  return isBareDomainCandidate(value);
}

function hasDangerousScheme(value: string): boolean {
  return DANGEROUS_SCHEMES.some((scheme) => startsWithIgnoreCase(value, scheme));
}

function hasHierarchicalScheme(value: string): boolean {
  const separatorIndex = value.indexOf("://");
  if (separatorIndex < 1 || !isAsciiLetter(value.charCodeAt(0))) return false;

  for (let index = 1; index < separatorIndex; index += 1) {
    const code = value.charCodeAt(index);
    if (!isAsciiLetter(code) && !isAsciiDigit(code) && code !== 43 && code !== 45 && code !== 46) {
      return false;
    }
  }

  return true;
}

function isBareDomainCandidate(value: string): boolean {
  if (value.includes("@")) return false;

  const authorityEnd = findFirstIndex(value, "/?#");
  const authority = authorityEnd < 0 ? value : value.slice(0, authorityEnd);
  if (authority.length === 0) return false;

  const portSeparator = authority.lastIndexOf(":");
  const host = portSeparator >= 0 ? authority.slice(0, portSeparator) : authority;
  const port = portSeparator >= 0 ? authority.slice(portSeparator + 1) : "";

  if (portSeparator >= 0 && !isValidPort(port)) return false;
  if (!host.includes(".") || host.length > 253) return false;

  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !isValidHostLabel(label))) return false;

  const topLevelDomain = labels.at(-1) ?? "";
  return isValidTopLevelDomain(topLevelDomain);
}

function isValidTopLevelDomain(value: string): boolean {
  if (value.length < 2 || value.length > 63) return false;
  return everyAsciiLetter(value)
    || (startsWithIgnoreCase(value, "xn--") && isValidHostLabel(value));
}

function isValidHostLabel(label: string): boolean {
  if (label.length < 1 || label.length > 63) return false;
  if (!isAsciiAlphaNumeric(label.charCodeAt(0)) || !isAsciiAlphaNumeric(label.charCodeAt(label.length - 1))) return false;

  for (let index = 1; index < label.length - 1; index += 1) {
    const code = label.charCodeAt(index);
    if (!isAsciiAlphaNumeric(code) && code !== 45) return false;
  }

  return true;
}

function isValidPort(port: string): boolean {
  if (port.length < 1 || port.length > 5) return false;
  for (let index = 0; index < port.length; index += 1) {
    if (!isAsciiDigit(port.charCodeAt(index))) return false;
  }
  const numericPort = Number(port);
  return numericPort >= 1 && numericPort <= 65_535;
}

function everyAsciiLetter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    if (!isAsciiLetter(value.charCodeAt(index))) return false;
  }
  return true;
}

function isAsciiAlphaNumeric(code: number): boolean {
  return isAsciiLetter(code) || isAsciiDigit(code);
}

function isAsciiLetter(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

function isAsciiDigit(code: number): boolean {
  return code >= 48 && code <= 57;
}

function startsWithIgnoreCase(value: string, prefix: string): boolean {
  if (value.length < prefix.length) return false;
  return value.slice(0, prefix.length).toLowerCase() === prefix;
}

function removeWwwPrefix(value: string): string {
  return startsWithIgnoreCase(value, "www.") ? value.slice(4) : value;
}

function findFirstIndex(value: string, characters: string): number {
  for (let index = 0; index < value.length; index += 1) {
    if (characters.includes(value[index] ?? "")) return index;
  }
  return -1;
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
