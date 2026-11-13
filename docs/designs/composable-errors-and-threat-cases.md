# Composable errors and threat/fault cases

Date: 2026-09-06
Status: CP0.3 draft; proposed verification obligations, no executed security scan.
Parent: CP0.
Related: [scope map](composable-scope-and-manifest-map.md),
[transitions](composable-lifecycle-transitions.md).

## Preserve protocol-owned errors

[API_ERROR_SHAPE](../standards/API_ERROR_SHAPE.md) and the owning OpenAPI Problem
schema remain the app-JSON error authority. Existing OAuth, DAV, SMTP/IMAP/LDAP
and other documented protocol exceptions retain their contracts. Do not convert
every protocol into an extension-specific JSON envelope.

The current Office handler maps BZ321–BZ327 to named Office problem slugs; this is
a current module mapping, not a reserved public extension error registry. New
capabilities must allocate exact names/statuses through their owning schema review.
Never expose raw SQL messages, tokens, credentials, internal paths or another
organization’s resource existence to explain a failure.

### Inspected Office JSON projection

The current [shared classifier](../../shared/reducererr/reducererr.go),
[HTTP projection](../../shared/reducererr/projection.go) and
[contract cases](../../shared/reducererr/contract_test.go) establish this bounded
mapping. Tests were read, not run in this documentation task.

| SQLSTATE | Office slug | Current JSON HTTP status |
|---|---|---:|
| BZ321 | not-found | 404 |
| BZ322 | invalid-arguments | 400 |
| BZ323 | forbidden | 403 |
| BZ324 | session-stale | 409 |
| BZ325 | lock-conflict | 409 |
| BZ326 | replay-conflict | 409 |
| BZ327 | provider-unavailable | 409 |

Do not relabel BZ327 as a generic retryable 503 just because the word unavailable
appears in its name. Inspect the actual blocker and owning recovery contract.
Protocol-specific WOPI lock headers and non-JSON paths still need their own tests.

## Proposed caller recovery classes

These are semantics, not wire enum allocations.

| Class | Safe caller action | Authority / test condition |
|---|---|---|
| Invalid input / unsupported contract | Correct input or negotiate a supported contract; no automatic retry | Decoder rejects before privileged effect; unknown operation cannot execute |
| Not found / not discoverable | Safe unavailable message | Avoid distinguishing foreign resource from nonexistent resource |
| Permission revoked | Stop privileged action, remove protected view and refresh current capability projection | Fresh reducer-owned fence, not cached consent or UI visibility |
| State/preview mismatch | Re-read, recompute consequences and obtain new confirmation where required | Never silently substitute a new target/base/deletion set |
| Lock conflict | Show current allowed conflict resolution; no forced overwrite | Domain lock and fence checks remain authoritative |
| Idempotency mismatch | Fail without effect; investigate changed input | Same key with different accepted intent/content must not produce another action |
| Busy / unavailable | Explain known blocker; bounded retry only where owner declares safe | Health cannot override grants; no retry storm or fail-open fallback |
| Response lost / outcome unknown | Query authorized durable receipt before retry | Do not claim failure implies no mutation; external send needs delivery-specific reconciliation |
| Dependency / policy block | Preview authorized affected items and safe resolution | No silent cascade, retention bypass or disclosure of hidden dependents |
| Partial / recovery required | Itemized confirmed facts and resumable operation | Never turn uncertain cleanup or missing backup bytes into green success |

Retry budgets, receipt retention, observation permissions and exact transport
status/body/header mappings remain EP-P1. A retry-after hint is not authorization.
Safe error detail and administrator diagnostics are separate projections of the
same receipt; diagnostics still redact secrets and respect current permissions.

## Threat and fault matrix

| ID | Stimulus | Required independent oracle | Owner / existing case link |
|---|---|---|---|
| ET01 | Caller spoofs actor/mailbox/organization | No read/mutation/audit attribution crosses authenticated scope | Domain reducers; CP-T02 |
| ET02 | Group membership or grant changes mid-operation | Current authority rejects new privileged effect | Broker/domain; SC-P3 |
| ET03 | Callback has revoked/mismatched security fence, invalid operation ownership or no authorized accepted-session binding | Reject without route/grant resurrection or save; paired positive case permits an older pinned runtime's accepted save while current token/fence/ACL/lock checks pass | Office/E1; CP-T03/05/06 |
| ET04 | Planned drain raced with new launch | New launch denied; only accepted currently permitted saves may complete | Office; CP-T05 |
| ET05 | Revocation raced with drain/final save | Revoked token immediately loses authority; separately authorized maintenance cannot revive it | Office; CP-T06 |
| ET06 | Same request key reused with altered bytes/scope | Reject altered intent; original receipt unchanged | Command owner; CP-T08 |
| ET07 | Commit succeeds but response is lost | One durable result; observation authorized under current policy | Domain/WOPI; CP-T08 |
| ET08 | Provider input uploaded, ACL then revoked | No unauthorized output promotion; only owned temporary cleanup | Drive; reference Provider packet |
| ET09 | Shared/foreign Docker resource appears during cleanup | Zero foreign/shared deletion, including after reinspection race | D5; CP-T07 |
| ET10 | Hold/ownership changes after deletion preview | New confirmation before changed authorization; per-item eligibility rechecked during execution | App data/Drive; AB-T05/06 |
| ET11 | Referenced Drive chunk omitted, corrupt or GC'd during backup | Recovery set remains incomplete; independent restore cannot pass | Backup; AB-T02/10 |
| ET12 | Restore collisions, stale secrets or external job state | Inactive isolated result or safe refusal; no automatic outbound effects | Backup/domain; AB-T07 |
| ET13 | Candidate needs broader grant or changes publisher/egress | No new authority until explicit approval; old valid grants unchanged | E0/E1; CP-T04 |
| ET14 | Dependency graph cycle or concurrent overlapping activation | Deterministic refusal/reservation; no partial route activation | Resolver/E1; CP-T09 |
| ET15 | Forged frame origin, stale view or oversized UI message | No host capability invocation; safe teardown and bounded rejection | UI/E5; UI-T05/09 |
| ET16 | WASI unavailable or resource budget exceeded | Clear unavailable/limited result, no host/native/network escape | E5; paper UI/WASI fixture |
| ET17 | Slow/replayed/reordered event consumer | Stable-ID dedup, declared per-key ordering, bounded retries; no WAL retention or reducer stall | Domain outbox/E3 |
| ET18 | Catalog signature valid but digest/platform/capability invalid | Refuse before executable admission; badge grants nothing | Catalog/runtime; SC-P1/4 |
| ET19 | Updater and app manager both claim CODE | One exclusive durable owner; stale executor observations rejected | D5/Manifest v2; SC-P5 |
| ET20 | Public error or diagnostics contains secret/foreign identifier | Schema and redaction oracle rejects leakage, including nested causes | Gateway/domain; EP-P1 |

Test observations must be outside the code under test where practical: compare
database versions/receipts, absence of external sends, runtime ownership inventories
and restored content hashes rather than merely asserting the same UI status string.
Every denial verifies absence of unintended effects, not only HTTP status.

## Evidence and closure

Existing Office tests and reducer files are source-inspected anchors, not proof of
these proposed combinations. ET cases bind to CP/AB/UI owners rather than adding a
new competing acceptance suite. Retain exact source/fixture/model/runner hashes;
missing, skipped, ambiguous or flaky-after-retry evidence is not a pass.

EP-P1: freeze exact domain transport errors, safe remedy wording, timing and receipt
retention. EP-P2: map all ET rows to concrete existing/new test selectors and output
oracles. EP-P3: complete fresh architecture/security review after scope and lifecycle
schemas settle. EP-P4: reconcile legacy security-document posture against current
source before citing a universal RLS state; this draft relies on authenticated
ownership checks and required table-specific isolation, not blanket RLS claims.

These are threat hypotheses and contract tests, not newly validated vulnerabilities.
No scanner result, current exploitability verdict or 10/10 score is claimed.
