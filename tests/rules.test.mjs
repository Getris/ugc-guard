import assert from "node:assert/strict";
import test from "node:test";
import {
  createGuard,
  DuplicateRule,
  extractUrlCandidates,
  HtmlRule,
  LengthRule,
  LinkRule,
  PhraseRule,
  RateLimitRule,
  SecretRule,
  SpamRule,
  UnicodeRule
} from "../dist/index.js";

async function inspect(rule, text, extra = {}) {
  return createGuard({ rules: [rule] }).inspect({ text, ...extra });
}

test("LengthRule counts emoji grapheme clusters", async () => {
  const result = await inspect(new LengthRule({ maxLength: 1 }), "👨‍👩‍👧‍👦");
  assert.equal(result.findings.length, 0);
});

test("LengthRule validates min and max", () => {
  assert.throws(() => new LengthRule({ minLength: 10, maxLength: 5 }), RangeError);
});

test("HtmlRule detects event handlers", async () => {
  const result = await inspect(new HtmlRule(), '<img src="x" onerror="alert(1)">');
  assert.equal(result.findings.some((finding) => finding.code === "ACTIVE_MARKUP_DETECTED"), true);
});

test("HtmlRule detects encoded markup", async () => {
  const result = await inspect(new HtmlRule(), "&lt;script&gt;alert(1)&lt;/script&gt;");
  assert.equal(result.findings.some((finding) => finding.code === "ENCODED_MARKUP_DETECTED"), true);
});

test("LinkRule detects URL credentials", async () => {
  const result = await inspect(new LinkRule(), "https://user:password@example.com/path");
  assert.equal(result.findings.some((finding) => finding.code === "URL_CREDENTIALS"), true);
});

test("LinkRule detects private IPv4", async () => {
  const result = await inspect(new LinkRule(), "http://192.168.1.20/admin");
  assert.equal(result.findings.some((finding) => finding.code === "PRIVATE_NETWORK_HOST"), true);
});

test("LinkRule detects dangerous schemes", async () => {
  const result = await inspect(new LinkRule(), "javascript:alert(1)");
  assert.equal(result.findings.some((finding) => finding.code === "DANGEROUS_URL_SCHEME"), true);
});

test("LinkRule respects subdomain allowlists", async () => {
  const result = await inspect(new LinkRule({ allowedHosts: ["example.com"] }), "https://docs.example.com/start");
  assert.equal(result.findings.some((finding) => finding.code === "UNAPPROVED_HOST"), false);
});

test("LinkRule reports excessive links", async () => {
  const result = await inspect(new LinkRule({ maxLinks: 1 }), "https://a.example https://b.example");
  assert.equal(result.findings.some((finding) => finding.code === "TOO_MANY_LINKS"), true);
});

test("extractUrlCandidates handles adversarial punctuation in linear time", () => {
  const hostile = `https://example.com/${"!".repeat(100_000)}`;
  assert.deepEqual(extractUrlCandidates(hostile), ["https://example.com/"]);
});

test("extractUrlCandidates finds explicit and bare URLs without matching email addresses", () => {
  const values = extractUrlCandidates("See (https://example.com/path), www.example.org! and docs.example.net/start; not user@example.com");
  assert.deepEqual(values, ["https://example.com/path", "www.example.org", "docs.example.net/start"]);
});

test("PhraseRule hides matched phrase by default", async () => {
  const result = await inspect(new PhraseRule({ phrases: ["internal blocked phrase"] }), "Contains internal blocked phrase here");
  assert.equal(JSON.stringify(result.findings).includes("internal blocked phrase"), false);
});

test("PhraseRule supports whole-word matching", async () => {
  const rule = new PhraseRule({ phrases: ["cat"], matchMode: "word" });
  const noMatch = await inspect(rule, "educate");
  const match = await inspect(rule, "a cat here");
  assert.equal(noMatch.findings.length, 0);
  assert.equal(match.findings.length, 1);
});

test("SpamRule detects repeated characters", async () => {
  const result = await inspect(new SpamRule(), "BUY NOWWWWWWWWW");
  assert.equal(result.findings.some((finding) => finding.code === "REPEATED_CHARACTERS"), true);
});

test("SpamRule validates ratios", () => {
  assert.throws(() => new SpamRule({ maxUppercaseRatio: 1.5 }), RangeError);
});

test("UnicodeRule detects bidirectional controls", async () => {
  const result = await inspect(new UnicodeRule(), "safe\u202Etxt");
  assert.equal(result.findings.some((finding) => finding.code === "BIDI_CONTROL_CHARACTERS"), true);
});

test("UnicodeRule detects Latin/Cyrillic look-alike tokens", async () => {
  const result = await inspect(new UnicodeRule(), "pаypal");
  assert.equal(result.findings.some((finding) => finding.code === "MIXED_SCRIPT_TOKEN"), true);
});

test("SecretRule detects private keys without echoing them", async () => {
  const text = "-----BEGIN PRIVATE KEY-----\nexample";
  const result = await inspect(new SecretRule(), text);
  assert.equal(result.findings[0]?.code, "POSSIBLE_SECRET");
  assert.equal(JSON.stringify(result.findings).includes("BEGIN PRIVATE KEY"), false);
});

test("SecretRule detects GitHub token shapes", async () => {
  const result = await inspect(new SecretRule(), `ghp_${"a".repeat(36)}`);
  assert.equal(result.findings.some((finding) => finding.details?.type === "github-token"), true);
});

test("DuplicateRule skips anonymous content by default", async () => {
  const rule = new DuplicateRule();
  const guard = createGuard({ rules: [rule] });
  await guard.inspect({ text: "same" });
  const second = await guard.inspect({ text: "same" });
  assert.equal(second.findings.length, 0);
});

test("DuplicateRule detects repeated content per user", async () => {
  const rule = new DuplicateRule({ windowMs: 10_000 });
  const guard = createGuard({ rules: [rule] });
  await guard.inspect({ text: "same", userId: "u1" });
  const second = await guard.inspect({ text: "same", userId: "u1" });
  assert.equal(second.findings[0]?.code, "DUPLICATE_CONTENT");
});

test("DuplicateRule isolates users", async () => {
  const rule = new DuplicateRule();
  const guard = createGuard({ rules: [rule] });
  await guard.inspect({ text: "same", userId: "u1" });
  const second = await guard.inspect({ text: "same", userId: "u2" });
  assert.equal(second.findings.length, 0);
});

test("RateLimitRule blocks after configured attempts", async () => {
  const rule = new RateLimitRule({ maxAttempts: 2, windowMs: 10_000 });
  const guard = createGuard({ rules: [rule] });
  await guard.inspect({ text: "one", userId: "u1" });
  await guard.inspect({ text: "two", userId: "u1" });
  const third = await guard.inspect({ text: "three", userId: "u1" });
  assert.equal(third.findings[0]?.code, "RATE_LIMIT_EXCEEDED");
});
