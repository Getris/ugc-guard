import { normalizeText } from "./normalize.js";
import type {
  GuardDecision,
  GuardFinding,
  GuardInput,
  GuardOptions,
  GuardResult,
  GuardRule,
  GuardRuleResult,
  RiskLevel,
  Severity
} from "./types.js";
import { assertIntegerInRange, sanitizeFinding } from "./utils.js";

interface ResolvedGuardOptions {
  blockThreshold: number;
  reviewThreshold: number;
  blockOnSeverities: Set<Severity>;
  maxInputBytes: number;
  ruleTimeoutMs: number;
  onRuleError: "throw" | "finding" | "ignore";
  stopOnBlock: boolean;
  normalizeUnicode: boolean;
  trimWhitespace: boolean;
  collapseWhitespace: boolean;
  normalizeLineEndings: boolean;
}

export class ContentGuard {
  readonly #options: ResolvedGuardOptions;
  readonly #rules: GuardRule[];

  constructor(options: GuardOptions = {}) {
    const blockThreshold = options.blockThreshold ?? options.maxRiskScore ?? 60;
    const reviewThreshold = options.reviewThreshold ?? Math.min(30, blockThreshold);

    assertIntegerInRange("blockThreshold", blockThreshold, 1, 100);
    assertIntegerInRange("reviewThreshold", reviewThreshold, 0, blockThreshold);

    const maxInputBytes = options.maxInputBytes ?? 64 * 1024;
    assertIntegerInRange("maxInputBytes", maxInputBytes, 1, 10 * 1024 * 1024);

    const ruleTimeoutMs = options.ruleTimeoutMs ?? 1_000;
    assertIntegerInRange("ruleTimeoutMs", ruleTimeoutMs, 0, 60_000);

    this.#options = {
      blockThreshold,
      reviewThreshold,
      blockOnSeverities: new Set(options.blockOnSeverities ?? ["critical"]),
      maxInputBytes,
      ruleTimeoutMs,
      onRuleError: options.onRuleError ?? "finding",
      stopOnBlock: options.stopOnBlock ?? false,
      normalizeUnicode: options.normalizeUnicode ?? true,
      trimWhitespace: options.trimWhitespace ?? true,
      collapseWhitespace: options.collapseWhitespace ?? true,
      normalizeLineEndings: options.normalizeLineEndings ?? true
    };

    this.#rules = [...(options.rules ?? [])];
  }

  use(rule: GuardRule): this {
    if (!rule || typeof rule.name !== "string" || typeof rule.inspect !== "function") {
      throw new TypeError("A guard rule must expose a name and an inspect() function.");
    }
    this.#rules.push(rule);
    return this;
  }

  async inspect(input: GuardInput): Promise<GuardResult> {
    const startedAt = performance.now();

    if (!input || typeof input.text !== "string") {
      throw new TypeError("Guard input text must be a string.");
    }

    const inputBytes = new TextEncoder().encode(input.text).byteLength;
    if (inputBytes > this.#options.maxInputBytes) {
      const finding: GuardFinding = {
        rule: "core",
        code: "INPUT_TOO_LARGE",
        message: `Input exceeds the configured ${this.#options.maxInputBytes}-byte limit.`,
        severity: "critical",
        score: 100,
        category: "system",
        details: { inputBytes, maxInputBytes: this.#options.maxInputBytes }
      };
      return this.#buildResult(input.text, [], [finding], 0, startedAt);
    }

    const normalized = normalizeText(input.text, {
      unicode: this.#options.normalizeUnicode,
      trim: this.#options.trimWhitespace,
      collapseWhitespace: this.#options.collapseWhitespace,
      lineEndings: this.#options.normalizeLineEndings
    });

    const findings: GuardFinding[] = [];
    let rulesEvaluated = 0;

    for (const rule of this.#rules) {
      rulesEvaluated += 1;
      const controller = new AbortController();

      try {
        const rawResult = await this.#runRule(rule, input, {
          now: Date.now(),
          originalText: input.text,
          normalizedText: normalized.text,
          normalizations: normalized.changes,
          signal: controller.signal
        }, controller);

        const values = Array.isArray(rawResult) ? rawResult : rawResult ? [rawResult] : [];
        for (const value of values) {
          const finding = sanitizeFinding(value, rule.name);
          if (finding) findings.push(finding);
        }
      } catch (error) {
        if (this.#options.onRuleError === "throw") throw error;
        if (this.#options.onRuleError === "finding") {
          findings.push({
            rule: rule.name,
            code: error instanceof RuleTimeoutError ? "RULE_TIMEOUT" : "RULE_EXECUTION_FAILED",
            message: error instanceof RuleTimeoutError
              ? "A guard rule exceeded its execution time limit."
              : "A guard rule failed during inspection.",
            severity: "high",
            score: error instanceof RuleTimeoutError ? 50 : 40,
            category: "system",
            details: { rule: rule.name }
          });
        }
      }

      if (this.#options.stopOnBlock && this.#isDefinitelyBlocked(findings)) break;
    }

    return this.#buildResult(normalized.text, normalized.changes, findings, rulesEvaluated, startedAt);
  }

  async #runRule(
    rule: GuardRule,
    input: GuardInput,
    context: Parameters<GuardRule["inspect"]>[1],
    controller: AbortController
  ): Promise<GuardRuleResult> {
    const execution = Promise.resolve().then(() => rule.inspect(input, context));
    if (this.#options.ruleTimeoutMs === 0) return execution;

    let timeout: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new RuleTimeoutError(rule.name, this.#options.ruleTimeoutMs));
      }, this.#options.ruleTimeoutMs);
    });

    try {
      return await Promise.race([execution, timeoutPromise]);
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  #isDefinitelyBlocked(findings: GuardFinding[]): boolean {
    const score = calculateScore(findings);
    return score >= this.#options.blockThreshold
      || findings.some((finding) => this.#options.blockOnSeverities.has(finding.severity));
  }

  #buildResult(
    normalizedText: string,
    normalizations: GuardResult["normalizations"],
    findings: GuardFinding[],
    rulesEvaluated: number,
    startedAt: number
  ): GuardResult {
    const score = calculateScore(findings);
    const decision = this.#decision(score, findings);

    return {
      allowed: decision !== "block",
      decision,
      score,
      riskLevel: riskLevelFromScore(score),
      normalizedText,
      findings,
      normalizations: [...normalizations],
      rulesEvaluated,
      durationMs: Number((performance.now() - startedAt).toFixed(3))
    };
  }

  #decision(score: number, findings: GuardFinding[]): GuardDecision {
    if (
      score >= this.#options.blockThreshold
      || findings.some((finding) => this.#options.blockOnSeverities.has(finding.severity))
    ) return "block";
    if (score >= this.#options.reviewThreshold) return "review";
    return "allow";
  }
}

class RuleTimeoutError extends Error {
  constructor(ruleName: string, timeoutMs: number) {
    super(`Rule ${ruleName} exceeded ${timeoutMs}ms.`);
    this.name = "RuleTimeoutError";
  }
}

function calculateScore(findings: GuardFinding[]): number {
  const score = findings.reduce((sum, finding) => sum + finding.score, 0);
  return Math.min(100, Math.max(0, Number.isFinite(score) ? score : 100));
}

function riskLevelFromScore(score: number): RiskLevel {
  if (score === 0) return "none";
  if (score < 30) return "low";
  if (score < 60) return "medium";
  if (score < 90) return "high";
  return "critical";
}

export function createGuard(options: GuardOptions = {}): ContentGuard {
  return new ContentGuard(options);
}
