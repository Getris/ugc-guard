export type Severity = "low" | "medium" | "high" | "critical";
export type GuardDecision = "allow" | "review" | "block";
export type RuleFailureMode = "throw" | "finding" | "ignore";
export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export interface GuardInput {
  text: string;
  userId?: string;
  contentId?: string;
  ip?: string;
  metadata?: Readonly<Record<string, unknown>>;
}

export interface NormalizationChange {
  type: "unicode" | "trim" | "whitespace" | "line-endings";
  description: string;
}

export interface GuardFinding {
  rule: string;
  code: string;
  message: string;
  severity: Severity;
  score: number;
  category?: "content" | "spam" | "link" | "secret" | "unicode" | "system";
  details?: Readonly<Record<string, unknown>>;
}

export interface GuardResult {
  allowed: boolean;
  decision: GuardDecision;
  score: number;
  riskLevel: RiskLevel;
  normalizedText: string;
  findings: GuardFinding[];
  normalizations: NormalizationChange[];
  rulesEvaluated: number;
  durationMs: number;
}

export interface RuleContext {
  now: number;
  originalText: string;
  normalizedText: string;
  normalizations: readonly NormalizationChange[];
  signal: AbortSignal;
}

export type GuardRuleResult = GuardFinding | GuardFinding[] | null | undefined;

export interface GuardRule {
  readonly name: string;
  inspect(
    input: GuardInput,
    context: RuleContext
  ): GuardRuleResult | Promise<GuardRuleResult>;
}

export interface GuardOptions {
  /** Score at or above which content is blocked. */
  blockThreshold?: number;
  /** Backwards-compatible alias for blockThreshold. */
  maxRiskScore?: number;
  /** Score at or above which content is marked for review. */
  reviewThreshold?: number;
  /** A finding with one of these severities blocks regardless of score. */
  blockOnSeverities?: Severity[];
  /** Maximum UTF-8 size accepted before rule execution. */
  maxInputBytes?: number;
  /** Per-rule timeout. Set to 0 to disable. */
  ruleTimeoutMs?: number;
  /** What happens when a custom rule throws or times out. */
  onRuleError?: RuleFailureMode;
  /** Stop evaluating after the content is definitely blocked. */
  stopOnBlock?: boolean;
  normalizeUnicode?: boolean;
  trimWhitespace?: boolean;
  collapseWhitespace?: boolean;
  normalizeLineEndings?: boolean;
  rules?: GuardRule[];
}
