# Roadmap

The roadmap describes intended direction, not guaranteed delivery dates.

## Near term

- fuzz and property tests for URL and Unicode handling;
- Redis-backed duplicate and rate-limit adapters in a separate integration package;
- more framework examples;
- npm release automation with provenance;
- benchmark suite with published methodology;
- rule-level documentation and migration notes.

## Before 1.0

- stabilize scoring and decision semantics;
- document compatibility guarantees;
- independent security review;
- structured observability hooks without raw-content logging;
- configurable finding aggregation and policy profiles;
- test corpus for false-positive and false-negative regression tracking.

## Non-goals

- becoming a full HTML sanitizer;
- fetching or crawling submitted URLs;
- replacing dedicated edge rate limiting;
- claiming automatic moderation is sufficient without human policy oversight.
