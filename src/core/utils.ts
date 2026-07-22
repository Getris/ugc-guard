import type { GuardFinding, Severity } from "./types.js";

export function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(maximum, Math.max(minimum, value));
}

export function assertIntegerInRange(name: string, value: number, minimum: number, maximum: number): void {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer between ${minimum} and ${maximum}.`);
  }
}

export function assertNumberInRange(name: string, value: number, minimum: number, maximum: number): void {
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be a finite number between ${minimum} and ${maximum}.`);
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function sanitizeFinding(value: unknown, fallbackRule: string): GuardFinding | null {
  if (!isRecord(value)) return null;

  const rule = typeof value.rule === "string" && value.rule.trim() ? value.rule.trim() : fallbackRule;
  const code = typeof value.code === "string" && value.code.trim() ? value.code.trim() : "UNSPECIFIED_FINDING";
  const message = typeof value.message === "string" && value.message.trim()
    ? value.message.trim()
    : "A guard rule reported a finding.";
  const scoreValue = typeof value.score === "number" && Number.isFinite(value.score) ? value.score : 0;
  const score = clamp(scoreValue, 0, 100);
  const severity = isSeverity(value.severity) ? value.severity : severityFromScore(score);
  const category = isCategory(value.category) ? value.category : undefined;
  const details = isRecord(value.details) ? value.details : undefined;

  return {
    rule,
    code,
    message,
    severity,
    score,
    ...(category ? { category } : {}),
    ...(details ? { details } : {})
  };
}

export function severityFromScore(score: number): Severity {
  if (score >= 90) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function isSeverity(value: unknown): value is Severity {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

function isCategory(value: unknown): value is NonNullable<GuardFinding["category"]> {
  return value === "content" || value === "spam" || value === "link" || value === "secret" || value === "unicode" || value === "system";
}
