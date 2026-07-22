import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, DuplicateRule, HtmlRule, LengthRule, LinkRule, SpamRule, UnicodeRule } from "../dist/index.js";

test("allows ordinary text and normalizes whitespace", async () => {
  const guard = createGuard({ rules: [new LengthRule({ maxLength: 100 })] });
  const result = await guard.inspect({ text: "  Hello   world  " });
  assert.equal(result.allowed, true);
  assert.equal(result.normalizedText, "Hello world");
  assert.equal(result.score, 0);
});

test("rejects dangerous HTML", async () => {
  const guard = createGuard({ rules: [new HtmlRule()] });
  const result = await guard.inspect({ text: '<img src=x onerror="alert(1)">' });
  assert.equal(result.allowed, false);
  assert.equal(result.findings[0]?.code, "DANGEROUS_HTML");
});

test("detects raw IP links", async () => {
  const guard = createGuard({ rules: [new LinkRule()] });
  const result = await guard.inspect({ text: "Visit http://192.168.1.20/login" });
  assert.equal(result.allowed, true);
  assert.equal(result.findings.some((finding) => finding.code === "IP_HOST"), true);
});

test("detects repeated submissions per user", async () => {
  const guard = createGuard({ rules: [new DuplicateRule({ windowMs: 10_000 })] });
  const first = await guard.inspect({ text: "same", userId: "u1" });
  const second = await guard.inspect({ text: "same", userId: "u1" });
  assert.equal(first.score, 0);
  assert.equal(second.findings[0]?.code, "DUPLICATE_CONTENT");
});

test("detects spam patterns", async () => {
  const guard = createGuard({ rules: [new SpamRule()] });
  const result = await guard.inspect({ text: "BUY NOWWWWWWWWW" });
  assert.equal(result.findings.some((finding) => finding.code === "REPEATED_CHARACTERS"), true);
});

test("detects invisible unicode controls", async () => {
  const guard = createGuard({ rules: [new UnicodeRule()] });
  const result = await guard.inspect({ text: "safe\u202Etxt" });
  assert.equal(result.allowed, false);
  assert.equal(result.findings.some((finding) => finding.code === "INVISIBLE_CHARACTERS"), true);
});
