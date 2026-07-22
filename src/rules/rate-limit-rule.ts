import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";
import { assertIntegerInRange } from "../core/utils.js";

export interface RateLimitRuleOptions {
  maxAttempts?: number;
  windowMs?: number;
  maxKeys?: number;
  includeAnonymous?: boolean;
  keyResolver?: (input: GuardInput) => string | undefined;
}

interface Bucket {
  timestamps: number[];
  touchedAt: number;
}

/**
 * Single-process sliding-window limiter. For horizontally scaled production
 * deployments, implement rate limiting at the edge or with shared storage.
 */
export class RateLimitRule implements GuardRule {
  readonly name = "rate-limit";
  readonly #maxAttempts: number;
  readonly #windowMs: number;
  readonly #maxKeys: number;
  readonly #includeAnonymous: boolean;
  readonly #keyResolver: (input: GuardInput) => string | undefined;
  readonly #buckets = new Map<string, Bucket>();

  constructor(options: RateLimitRuleOptions = {}) {
    this.#maxAttempts = options.maxAttempts ?? 10;
    this.#windowMs = options.windowMs ?? 60_000;
    this.#maxKeys = options.maxKeys ?? 10_000;
    this.#includeAnonymous = options.includeAnonymous ?? false;
    this.#keyResolver = options.keyResolver ?? ((input) => input.userId ?? input.ip);

    assertIntegerInRange("maxAttempts", this.#maxAttempts, 1, 100_000);
    assertIntegerInRange("windowMs", this.#windowMs, 1, 86_400_000);
    assertIntegerInRange("maxKeys", this.#maxKeys, 1, 1_000_000);
  }

  inspect(input: GuardInput, context: RuleContext): GuardFinding | null {
    const key = this.#keyResolver(input);
    if (!key && !this.#includeAnonymous) return null;

    const resolvedKey = key ?? "anonymous";
    const cutoff = context.now - this.#windowMs;
    const existing = this.#buckets.get(resolvedKey);
    const timestamps = (existing?.timestamps ?? []).filter((timestamp) => timestamp > cutoff);
    timestamps.push(context.now);

    this.#buckets.delete(resolvedKey);
    this.#buckets.set(resolvedKey, { timestamps, touchedAt: context.now });
    this.#evictOldestKeys();

    if (timestamps.length > this.#maxAttempts) {
      const oldest = timestamps[0] ?? context.now;
      return {
        rule: this.name,
        code: "RATE_LIMIT_EXCEEDED",
        message: "Too many submissions were made in the configured time window.",
        severity: "high",
        score: 70,
        category: "spam",
        details: {
          attempts: timestamps.length,
          maxAttempts: this.#maxAttempts,
          windowMs: this.#windowMs,
          retryAfterMs: Math.max(0, oldest + this.#windowMs - context.now)
        }
      };
    }

    return null;
  }

  #evictOldestKeys(): void {
    while (this.#buckets.size > this.#maxKeys) {
      const oldest = this.#buckets.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#buckets.delete(oldest);
    }
  }
}
