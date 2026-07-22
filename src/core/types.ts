export type Severity = "low" | "medium" | "high";

export interface GuardInput {
  text: string;
  userId?: string;
  contentId?: string;
  metadata?: Readonly<Record<string, unknown>>;
}

export interface GuardFinding {
  rule: string;
  code: string;
  message: string;
  severity: Severity;
  score: number;
  details?: Readonly<Record<string, unknown>>;
}

export interface GuardResult {
  allowed: boolean;
  score: number;
  normalizedText: string;
  findings: GuardFinding[];
}

export interface RuleContext {
  now: number;
  normalizedText: string;
}

export interface GuardRule {
  readonly name: string;
  inspect(input: GuardInput, context: RuleContext): GuardFinding | GuardFinding[] | null | Promise<GuardFinding | GuardFinding[] | null>;
}

export interface GuardOptions {
  maxRiskScore?: number;
  normalizeUnicode?: boolean;
  trimWhitespace?: boolean;
  collapseWhitespace?: boolean;
  rules?: GuardRule[];
}
