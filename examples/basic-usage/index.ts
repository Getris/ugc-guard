import {
  createGuard,
  DuplicateRule,
  HtmlRule,
  LengthRule,
  LinkRule,
  PhraseRule,
  SpamRule,
  UnicodeRule
} from "@getris/ugc-guard";

const guard = createGuard({
  maxRiskScore: 60,
  rules: [
    new LengthRule({ maxLength: 500 }),
    new HtmlRule(),
    new LinkRule({ blockedHosts: ["example-malware.test"] }),
    new PhraseRule({ phrases: ["configured blocked phrase"] }),
    new SpamRule(),
    new DuplicateRule(),
    new UnicodeRule()
  ]
});

const result = await guard.inspect({
  text: "Hello from Zooplio!",
  userId: "demo-user"
});

console.log(result);
