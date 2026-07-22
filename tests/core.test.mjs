import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, LengthRule } from "../dist/index.js";

test("normalizes line endings, Unicode, whitespace, and trim", async () => {
  const guard = createGuard({ rules: [new LengthRule({ maxLength: 100 })] });
  const result = await guard.inspect({ text: "  Ｈello\r\n\tworld  " });
  assert.equal(result.normalizedText, "Hello\n world");
  assert.equal(result.decision, "allow");
  assert.equal(result.normalizations.length >= 3, true);
});

test("returns review between review and block thresholds", async () => {
  const guard = createGuard({
    reviewThreshold: 20,
    blockThreshold: 60,
    rules: [{ name: "review", inspect: () => ({ rule: "review", code: "REVIEW", message: "Review", severity: "low", score: 25 }) }]
  });
  const result = await guard.inspect({ text: "hello" });
  assert.equal(result.allowed, true);
  assert.equal(result.decision, "review");
});

test("blocks critical findings regardless of score", async () => {
  const guard = createGuard({
    rules: [{ name: "critical", inspect: () => ({ rule: "critical", code: "X", message: "X", severity: "critical", score: 1 }) }]
  });
  const result = await guard.inspect({ text: "hello" });
  assert.equal(result.allowed, false);
  assert.equal(result.decision, "block");
});

test("sanitizes invalid custom-rule scores", async () => {
  const guard = createGuard({
    rules: [{ name: "unsafe-custom", inspect: () => ({ rule: "unsafe-custom", code: "BAD", message: "Bad", severity: "high", score: Number.POSITIVE_INFINITY }) }]
  });
  const result = await guard.inspect({ text: "hello" });
  assert.equal(result.score, 0);
});

test("turns rule errors into findings by default", async () => {
  const guard = createGuard({ rules: [{ name: "broken", inspect: () => { throw new Error("secret internal message"); } }] });
  const result = await guard.inspect({ text: "hello" });
  assert.equal(result.findings[0]?.code, "RULE_EXECUTION_FAILED");
  assert.equal(JSON.stringify(result).includes("secret internal message"), false);
});

test("can throw rule errors when configured", async () => {
  const guard = createGuard({ onRuleError: "throw", rules: [{ name: "broken", inspect: () => { throw new Error("boom"); } }] });
  await assert.rejects(() => guard.inspect({ text: "hello" }), /boom/u);
});

test("times out slow rules", async () => {
  const guard = createGuard({
    ruleTimeoutMs: 5,
    rules: [{ name: "slow", inspect: async () => new Promise((resolve) => setTimeout(() => resolve(null), 50)) }]
  });
  const result = await guard.inspect({ text: "hello" });
  assert.equal(result.findings.some((finding) => finding.code === "RULE_TIMEOUT"), true);
});

test("blocks oversized input before running rules", async () => {
  let ran = false;
  const guard = createGuard({ maxInputBytes: 4, rules: [{ name: "probe", inspect: () => { ran = true; return null; } }] });
  const result = await guard.inspect({ text: "12345" });
  assert.equal(result.findings[0]?.code, "INPUT_TOO_LARGE");
  assert.equal(ran, false);
});

test("validates guard options", () => {
  assert.throws(() => createGuard({ reviewThreshold: 70, blockThreshold: 60 }), RangeError);
  assert.throws(() => createGuard({ maxInputBytes: 0 }), RangeError);
});
