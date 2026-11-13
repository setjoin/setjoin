# Chat policy transaction and caller closure

Date: 2026-09-07. Documentation-only continuation of the
[hold/writer plan](composable-chat-hold-writer-serialization.md). Source observations
below identify implementation work; no race, privilege exploit or fix has been
executed. Chat compliance remains the policy owner; Go remains a translator, not
the new authority for plugin-accessible mutations.

## Concrete classification atomicity gap

[SetClassification](../../mailserver/internal/admin/admin_chat_compliance.go:605)
validates request fields and permission, then makes two separate pool calls:

1. Worker-pool UPDATE saves `retention_days` and `worm_mode`.
2. App-pool SELECT invokes `chat_channel_set_classification`.

There is no encompassing transaction in this handler. The
[reducer](../../mailserver/sql/reducers/chat_channel_set_classification.sql:40)
can subsequently reject a missing/invalid transition, federated room (`BZ210`),
disabled compliance or other failure. The first successful UPDATE is not rolled
back by a second-call error. This is a source-established partial-write path, not
an observed customer incident. On a regular channel, the changed retention value
is a purge ceiling, not yet a WORM keep-floor; [V126](../../mailserver/sql/dbschema/V126__chat_compliance.sql:10)
explicitly distinguishes those meanings. A rejection can therefore leave meaningful
retention changes, not merely harmless setup values.

**First repair unit, before lock redesign:** extend or replace the owning reducer
to accept the requested classification, retention and WORM mode together. Bind
authenticated authority, lock/re-read the channel, validate all fields and the
federation exclusion, then update settings/classification, append the domain audit
and extend the required chunk retention in one transaction. Remove the raw handler
UPDATE; wrapping the two current calls in Go alone would leave the business boundary
split. Freeze the replacement signature, error mapping, caller inventory and
schema/reducer loading order in implementation review; do not leave an executable
old overload as an authorization or partial-write bypass.

Preserve regular→GxP only, required positive days/allowed WORM modes and existing
no-downgrade constraints. A repeat request against GxP must retain the chosen
existing rejection behavior without partially changing settings. Do not silently
add new idempotency semantics. Confirmed abort leaves settings, audit and retention
high-water marks unchanged; lost response/commit uncertainty follows HW's
authoritative reconciliation rule, not presumed rollback.

## Retention, audit and permission implications

| Boundary | Observed source | Required plan obligation |
|---|---|---|
| Per-channel retention | [Reducer](../../mailserver/sql/reducers/chat_channel_set_retention.sql:34) reads the old value, then UPDATEs and audits; its old-value SELECT has no row lock. | Capture the before-image under the qualified mutation boundary. Two competing edits must produce accurate before/after audit facts. Preserve immediate channel override/null-clear semantics, distinct from org-policy grace. |
| GxP monotonicity | [No-downgrade trigger](../../mailserver/sql/dbschema/V126__chat_compliance.sql:52) rejects class downgrade, null/lower GxP retention and compliance→governance. | Keep database backstops. Do not turn a failed classification attempt into a settings-edit operation, and do not equate a larger keep-floor with a more aggressive purge ceiling. |
| Chunk protection | Classification UPDATE → Chat audit → [global-scope chunk retention extension](../../mailserver/sql/reducers/chat_channel_set_classification.sql:83); [helper](../../mailserver/sql/dbschema/V114__drive_core.sql:239) updates high-water values. | Include channel, `chat_audit_` advisory and chunk rows in the lock graph, including shared global chunks across channels. SQL high-water stamps are not verified backend Object Lock or snapshot pins. Concurrent attachment publication must be included in qualification. |
| HTTP authority | [Handler permission check](../../mailserver/internal/admin/admin_chat_compliance.go:79), route permission middleware, and custodian [reach check](../../mailserver/internal/admin/admin_chat_ediscovery.go:144) precede mutations. | Preserve these gates, but do not expose the underlying functions as public app APIs on the assumption that a supplied admin ID proves authority. Current reach check is a separate query; authority freshness belongs in the mutation contract too. |
| Database execution | [V118 applicator](../../mailserver/sql/dbschema/V118__worker_ownership_applicator.sql:12) changes owner to worker, revokes PUBLIC execution and explicitly grants execution to `setjoin_app`, owner and worker when those roles exist. The sampled compliance reducers call it. | Worker-owned is not worker-only. Freeze effective grants from a fully loaded database, including inherited/default privileges, alongside each reducer's in-body checks. Do not globally change the applicator to repair these paths: unrelated reducers depend on its current grants. |

The database repair must use the project's established authenticated principal and
scope contract, reject forged/missing context and recheck current permission/reach
in the owning transaction. Inventory legitimate admin, CLI and worker consumers
before choosing a restricted wrapper or revised reducer. Plugin code receives
neither worker credentials nor arbitrary SQL execution. This paper does not claim
an end user currently possesses an app-pool credential or a working SQL exploit.

## Exact proposed repair checks

PC-T IDs are future obligations, not executed selectors. Retain existing tests;
the sampled `TestChatComplianceSetClassification_UpgradesToGxp` checks success and
resulting settings, not second-call rollback or concurrent policy changes.

| ID | Injection and independent oracle |
|---|---|
| PC-T01 Rejected classification | Federated regular channel, already-GxP repeat with different valid settings, disabled compliance and nonexistent channel. Preserve mapped error; compare pre/post settings, chunk high-water values and domain audit. No hidden first-call commit or partial settings edit. |
| PC-T02 Mid-operation failure | Fail after settings mutation, after audit and during retention extension; confirmed transaction abort leaves every effect unchanged. Commit followed by lost response reconciles committed facts, not a retry that applies a second mutation. |
| PC-T03 Competing policy operations | Retention edits, classification and federation binding race with purge and attachment sends using explicit barriers. Verify both commit orders, fresh eligibility and accurate audit before-images. No successful GxP/federated-room combination, lost committed attachment or stale-policy deletion. |
| PC-T04 Execution authority | Invoke old/new signatures as app role with absent/forged/insufficient/revoked authority, out-of-scope custodian and legitimate admin/worker callers. Check SQL denial and zero mutation separately from HTTP denial; full grant-loading evidence binds the source version. Never invent a passing denial from function ownership. |

## Read scope and admission

Root full reads: classification reducer1–93; retention reducer1–48; V1181–45.
Sampled: admin compliance1–150 and590–699; admin Chat eDiscovery120–174;
V1261–34,50–170; V114226–265; Chat audit writer1–65;
admin compliance test685–738; worker ownership test15–28. Route registration and
later ownership/revoke definitions were bounded searches, not full runtime tracing.
Line bounds are verified separately; hashes are retained in the continuation ledger.

Before implementation: integrate the case/membership caller map, reconcile the
repair with the security program's source-keyed findings, approve the exact SQL
authority/signature and finish the actual lock graph. Deduplicate overlapping
findings instead of creating parallel fixes or declaring old scans closed. This
addition does not authorize code, live SQL, deployment, release claims or a new
portfolio score.
