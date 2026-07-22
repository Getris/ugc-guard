import type { GuardFinding, GuardInput, GuardRule, RuleContext } from "../core/types.js";
import { assertIntegerInRange } from "../core/utils.js";

export interface DuplicateStore {
  get(key: string): number | undefined | Promise<number | undefined>;
  set(key: string, timestamp: number): void | Promise<void>;
  prune?(olderThan: number): void | Promise<void>;
}

export interface DuplicateRuleOptions {
  windowMs?: number;
  maxEntries?: number;
  includeAnonymous?: boolean;
  hashSalt?: string;
  store?: DuplicateStore;
  keyResolver?: (input: GuardInput) => string | undefined;
}

export class MemoryDuplicateStore implements DuplicateStore {
  readonly #entries = new Map<string, number>();
  readonly #maxEntries: number;

  constructor(maxEntries = 10_000) {
    assertIntegerInRange("maxEntries", maxEntries, 1, 1_000_000);
    this.#maxEntries = maxEntries;
  }

  get(key: string): number | undefined {
    const value = this.#entries.get(key);
    if (value !== undefined) {
      this.#entries.delete(key);
      this.#entries.set(key, value);
    }
    return value;
  }

  set(key: string, timestamp: number): void {
    this.#entries.delete(key);
    this.#entries.set(key, timestamp);
    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }

  prune(olderThan: number): void {
    for (const [key, timestamp] of this.#entries) {
      if (timestamp < olderThan) this.#entries.delete(key);
    }
  }
}

export class DuplicateRule implements GuardRule {
  readonly name = "duplicate";
  readonly #windowMs: number;
  readonly #includeAnonymous: boolean;
  readonly #hashSalt: string;
  readonly #store: DuplicateStore;
  readonly #keyResolver: (input: GuardInput) => string | undefined;
  #lastPrune = 0;

  constructor(options: DuplicateRuleOptions = {}) {
    this.#windowMs = options.windowMs ?? 60_000;
    this.#includeAnonymous = options.includeAnonymous ?? false;
    this.#hashSalt = options.hashSalt ?? "";
    this.#store = options.store ?? new MemoryDuplicateStore(options.maxEntries ?? 10_000);
    this.#keyResolver = options.keyResolver ?? ((input) => input.userId);

    assertIntegerInRange("windowMs", this.#windowMs, 1, 86_400_000);
  }

  async inspect(input: GuardInput, context: RuleContext): Promise<GuardFinding | null> {
    const scope = this.#keyResolver(input);
    if (!scope && !this.#includeAnonymous) return null;

    if (this.#store.prune && context.now - this.#lastPrune >= Math.min(this.#windowMs, 30_000)) {
      this.#lastPrune = context.now;
      await this.#store.prune(context.now - this.#windowMs);
    }

    const key = await sha256(`${this.#hashSalt}\0${scope ?? "anonymous"}\0${context.normalizedText}`);

    const previous = await this.#store.get(key);
    await this.#store.set(key, context.now);

    if (previous !== undefined && context.now - previous <= this.#windowMs) {
      return {
        rule: this.name,
        code: "DUPLICATE_CONTENT",
        message: "Duplicate content was submitted within the configured time window.",
        severity: "medium",
        score: 45,
        category: "spam",
        details: { windowMs: this.#windowMs }
      };
    }

    return null;
  }
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
