export { ContentGuard, createGuard } from "./core/guard.js";
export type {
  GuardDecision,
  GuardFinding,
  GuardInput,
  GuardOptions,
  GuardResult,
  GuardRule,
  GuardRuleResult,
  NormalizationChange,
  RiskLevel,
  RuleContext,
  RuleFailureMode,
  Severity
} from "./core/types.js";

export { LengthRule } from "./rules/length-rule.js";
export type { LengthCountMode, LengthRuleOptions } from "./rules/length-rule.js";
export { HtmlRule } from "./rules/html-rule.js";
export type { HtmlRuleOptions } from "./rules/html-rule.js";
export { LinkRule, extractUrlCandidates } from "./rules/link-rule.js";
export type { LinkRuleOptions } from "./rules/link-rule.js";
export { PhraseRule } from "./rules/phrase-rule.js";
export type { PhraseMatchMode, PhraseRuleOptions } from "./rules/phrase-rule.js";
export { SpamRule } from "./rules/spam-rule.js";
export type { SpamRuleOptions } from "./rules/spam-rule.js";
export { DuplicateRule, MemoryDuplicateStore } from "./rules/duplicate-rule.js";
export type { DuplicateRuleOptions, DuplicateStore } from "./rules/duplicate-rule.js";
export { RateLimitRule } from "./rules/rate-limit-rule.js";
export type { RateLimitRuleOptions } from "./rules/rate-limit-rule.js";
export { SecretRule } from "./rules/secret-rule.js";
export type { SecretRuleOptions } from "./rules/secret-rule.js";
export { UnicodeRule } from "./rules/unicode-rule.js";
export type { UnicodeRuleOptions } from "./rules/unicode-rule.js";
export { createCommunityGuard } from "./presets/community.js";
export type { CommunityGuardOptions } from "./presets/community.js";
