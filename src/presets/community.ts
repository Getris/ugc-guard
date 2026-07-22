import { createGuard, type ContentGuard } from "../core/guard.js";
import type { GuardOptions, GuardRule, Severity } from "../core/types.js";
import { DuplicateRule } from "../rules/duplicate-rule.js";
import { HtmlRule } from "../rules/html-rule.js";
import { LengthRule } from "../rules/length-rule.js";
import { LinkRule } from "../rules/link-rule.js";
import { PhraseRule } from "../rules/phrase-rule.js";
import { RateLimitRule } from "../rules/rate-limit-rule.js";
import { SecretRule } from "../rules/secret-rule.js";
import { SpamRule } from "../rules/spam-rule.js";
import { UnicodeRule } from "../rules/unicode-rule.js";

export interface CommunityGuardOptions {
  maxLength?: number;
  blockedHosts?: string[];
  allowedHosts?: string[];
  blockedPhrases?: string[];
  blockedPhraseSeverity?: Severity;
  enableDuplicateDetection?: boolean;
  duplicateWindowMs?: number;
  enableRateLimit?: boolean;
  maxSubmissionsPerMinute?: number;
  guard?: Omit<GuardOptions, "rules">;
}

/**
 * Opinionated baseline for comments, posts, profiles, and chat messages.
 * Every rule can still be composed manually for a different policy.
 */
export function createCommunityGuard(options: CommunityGuardOptions = {}): ContentGuard {
  const rules: GuardRule[] = [
    new LengthRule({ maxLength: options.maxLength ?? 5_000 }),
    new HtmlRule(),
    new LinkRule({
      ...(options.allowedHosts ? { allowedHosts: options.allowedHosts } : {}),
      ...(options.blockedHosts ? { blockedHosts: options.blockedHosts } : {}),
      blockIpHosts: true,
      blockPrivateNetworks: true,
      blockLocalHosts: true,
      blockShorteners: true,
      blockCredentials: true,
      flagPunycode: true,
      maxLinks: 8
    }),
    new SecretRule(),
    new SpamRule(),
    new UnicodeRule()
  ];

  if ((options.blockedPhrases?.length ?? 0) > 0) {
    rules.push(new PhraseRule({
      phrases: options.blockedPhrases ?? [],
      severity: options.blockedPhraseSeverity ?? "medium",
      score: 40,
      revealMatches: false
    }));
  }

  if (options.enableDuplicateDetection ?? true) {
    rules.push(new DuplicateRule({ windowMs: options.duplicateWindowMs ?? 60_000 }));
  }

  if (options.enableRateLimit ?? false) {
    rules.push(new RateLimitRule({
      maxAttempts: options.maxSubmissionsPerMinute ?? 20,
      windowMs: 60_000
    }));
  }

  return createGuard({
    blockThreshold: 60,
    reviewThreshold: 30,
    ruleTimeoutMs: 1_000,
    onRuleError: "finding",
    ...options.guard,
    rules
  });
}
