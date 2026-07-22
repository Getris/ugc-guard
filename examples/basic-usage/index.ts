import {
  createCommunityGuard,
  type GuardResult
} from "@getris/ugc-guard";

const guard = createCommunityGuard({
  maxLength: 1_000,
  blockedHosts: ["known-abuse.example"],
  enableDuplicateDetection: true
});

const result: GuardResult = await guard.inspect({
  text: "  Hello from the community!  ",
  userId: "example-user"
});

console.log({
  decision: result.decision,
  score: result.score,
  normalizedText: result.normalizedText,
  findingCodes: result.findings.map((finding) => finding.code)
});
