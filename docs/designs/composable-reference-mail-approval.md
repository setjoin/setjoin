# PAPER reference — Outbound Mail Approval

Date: 2026-09-06

Status: CP0.4 paper fixture; not an implementation, frozen schema, or public API.

## Purpose and authority

This fixture exercises an outbound-mail approval app against the proposed
protected Mail system-app boundary. It does not authorize a generic workflow
engine, replace the existing approval app, or add an endpoint. It supplies the
Mail reference required by the CP0 contract-freeze plan.

The [extension control-plane design](extension-control-plane-public-system-apps.md)
owns the trust classes, scoped broker and future contracts. Its first-party
Outbound Mail Approval vertical owns policy UX, approver chains, assigned
worklists, reminders and isolated UI contributions. Mail reducers retain message
bytes, pending state, authorization, final release/rejection, timeout/failure
policy and audit. Authority-affecting Mail contributions are not general community
grants. This fixture uses the already-selected first-party dogfood class.

The app-data lifecycle amendment
owns retention, backup, inactive-copy restore and removal. The [lifecycle packet](composable-lifecycle-transitions.md)
owns shared transition work. This document supplies examples, not exceptions.

## Current source facts, not extension promises

| Inspected boundary | Current behavior | Consequence for this fixture |
|---|---|---|
| [send.sql](../../mailserver/sql/reducers/send.sql), `send`, lines 54–151 and 154–238 | Checks mailbox/send-as authority and quota; a matching enabled external-send approval policy captures replay arguments and returns before Sent-copy creation, quota consumption and outbound queuing. | Mail already owns the hold. The app must not receive SQL access, the replay payload, or the internal `p_skip_approval` escape hatch. |
| [approval/handler.go](../../mailserver/internal/approval/handler.go), `ListMyApprovals` and `scanApprovalItem`, lines 124–237 | User-scoped visibility; empty lists are arrays; Mail payload is removed from the response. `Decide` is an existing user surface, not an installation-scoped extension API. | A proposed work-item projection must be deliberately scoped and redacted; existing routes are not silently reclassified as public contracts. |
| [approval_decide.sql](../../mailserver/sql/reducers/approval_decide.sql), lines 15–75 | Locks a pending request; checks separation of duties and assigned-user/current role-group authority; records decision, audit and notification. A second decision raises `BZ108`, rather than returning a durable success receipt. | Version-bound, installation-fenced, exact-retry receipts require additional contract work. The signature has no message/workflow version. |
| [mail_external_approval_decide.sql](../../mailserver/sql/reducers/mail_external_approval_decide.sql), lines 26–90 | Calls the shared decision reducer, replays `send` internally on approval, marks applied, audits, and invokes the sender NDR path on denial. Eligible submission replay publishes the committed Mail fact. | An app supplies a decision intent; it does not deliver mail or declare it delivered. Reducer failure rolls back the transaction. |
| [approval_expire_due.sql](../../mailserver/sql/reducers/approval_expire_due.sql), lines 14–37 | A separate locked sweep expires overdue pending requests and invokes the Mail NDR path. The inspected `approval_decide` pending-row predicate does not check the request's `expires_at`. | Atomic deadline enforcement in the proposed public command is an explicit gap to close, not established current behavior. |
| [approval/handler.go](../../mailserver/internal/approval/handler.go), lines 15–28; [routing_test.go](../../mailserver/internal/approval/routing_test.go), `TestDecideRoutesMailReplayToWorkerPool`, line 174 | Mail decision replay has a worker-pool cross-mailbox leg, while visibility remains user-scoped and the reducer reauthorizes the actor. | Neither the worker credential nor this internal dispatch becomes an extension capability. |

The older approval-engine design
section 7.2 describes an outbound-queue hold. The inspected implementation instead
stores replay arguments in the approval request before creating the send effects.
Use the source facts above for the current baseline; this fixture does not resolve
that older document's drift by inventing an implementation.

## Illustrative manifest and capability matrix

Every `paper.*` name, reference, field layout and value below is illustrative.
There is no installable manifest, signed artifact, registered capability ID,
route, SDK, or normative error enum here. E0 must freeze the schema and registry.
The managed-OCI runtime is an example placement, not approval to provision one.

```json
{
  "paperOnly": true,
  "schemaVersion": "<E0 manifest schema to freeze>",
  "app": "paper.setjoin.outbound-mail-approval",
  "publisher": "<first-party publisher identity>",
  "release": "0.0.0-paper",
  "artifactDigest": "<signed immutable artifact digest>",
  "compatibility": {
    "apiLevel": "<supported range>",
    "domainContracts": {"Mail": "<approval contract major>"}
  },
  "dependency": "protected Mail system app",
  "runtime": {"kind": "managed OCI", "placement": "server"},
  "contributions": ["isolated approval worklist", "outbound approval provider"],
  "requestedCapabilities": ["read assigned work", "submit version-bound decision"],
  "data": {"mail": "Mail-owned", "appState": "Setjoin-managed namespaced state"},
  "egress": "broker only; no arbitrary destination",
  "lifecycle": {"removeDataDefault": "retain", "pendingMail": "Mail-owned disposition"},
  "resources": "<bounded CPU, memory, queue, payload and time profiles>",
  "supportAndLicense": "<first-party support and license metadata>"
}
```

| Requested interaction | Scope and current-authority check | Explicit exclusion |
|---|---|---|
| Read an assigned worklist/item | Approved installation generation ∩ authenticated actor's current approver assignment ∩ approved organization/group/mailbox scope; projection allowlist and opaque pagination. | Unassigned work, another user's item, unrestricted mailbox search, replay arguments, BCC/body by default. Additional fields need explicit data-class approval. |
| Submit approve/deny intent | Same live grant plus exact Mail work, message snapshot and workflow versions; current SoD, assignment, deadline and pending-state check in the committing reducer. | Caller-selected actor/organization, policy bypass, arbitrary sender/recipients, direct queue or SMTP control. |
| Receive committed work/disposition facts | Installation subscription audience and current scope; minimal opaque references; delivery rechecks the active grant. | Raw `NOTIFY`, WAL, tables, all-organization event feeds, or event receipt as authorization. |
| Maintain app policy UX and reminders | Namespaced app metadata and separately admitted bounded jobs; a policy change is an intent accepted under Mail's authority. | Silent alteration of an already-held message's accepted policy snapshot; the app's chain completion does not itself release Mail. |

Installation scope maps to existing deployment/account authority. A mail domain is
not a new tenant or installation. The broker derives actor, installation, approved
generation, scope, audience, grant expiry and fence from authenticated context;
none is trusted merely because a request body names it. A group-scoped installation
does not confer every member's read or approval rights on its runtime.

## Four-path data flow

```text
isolated app view -> broker -> Mail scoped work projection
  valid item --------> review exact snapshots -> decision intent
                       -> Mail reducer commit -> durable receipt/outbox fact
  missing/hidden ----> indistinguishable unavailable item; no existence detail
  empty worklist ----> successful items=[]; no decision and no fabricated hold
  upstream failure --> unavailable/retryable observation; not an empty success
                       -> pending disposition stays with Mail, independently of app
```

An empty worklist is not an empty decision. Missing work reference, missing expected
version, or an empty/unknown decision is invalid input and creates no effect.
An unavailable app while work is pending cannot default to approval. Mail applies
its accepted timeout/failure policy; transport failure itself neither releases nor
rejects a message. Before a new policy can activate, its failure behavior must be
explicitly accepted by Mail's owner rather than chosen by the app or this paper.

## Illustrative query, command, receipt and event

These are separate typed contract sketches, not a proposed universal JSON action
endpoint. Identifiers are fictional opaque references. Versions are server-issued;
the app cannot mint or advance them. Mail binds the reviewed message snapshot,
accepted policy/workflow snapshot and pending work together.

```json
{
  "paperQuery": "paper.mail.approval.item",
  "input": {"workRef": "paper-work-A"},
  "result": {
    "workRef": "paper-work-A",
    "workVersion": "paper-work-version-4",
    "messageVersion": "paper-message-snapshot-2",
    "workflowVersion": "paper-workflow-snapshot-3",
    "display": {"summary": "External submission awaiting review"},
    "allowedDecisions": ["approve", "deny"],
    "deadline": "<Mail-owned absolute deadline>"
  }
}
```

```json
{
  "paperCommand": "paper.mail.approval.decide",
  "requestId": "paper-request-A1",
  "input": {
    "idempotencyKey": "paper-decision-A",
    "workRef": "paper-work-A",
    "expectedWorkVersion": "paper-work-version-4",
    "expectedMessageVersion": "paper-message-snapshot-2",
    "expectedWorkflowVersion": "paper-workflow-snapshot-3",
    "decision": "approve",
    "comment": "Reviewed the authorized submission snapshot"
  },
  "receipt": {
    "idempotencyKey": "paper-decision-A",
    "operationRef": "paper-operation-A",
    "outcome": "committed",
    "workVersion": "paper-work-version-5",
    "mailDisposition": "released-for-delivery",
    "externalDeliveryOutcome": "not-reported",
    "eventRef": "paper-event-A"
  }
}
```

```json
{
  "specversion": "1.0",
  "id": "paper-event-A",
  "source": "paper:protected-mail",
  "type": "paper.mail.approval.disposition-committed",
  "subject": "paper-work-A",
  "data": {
    "workVersion": "paper-work-version-5",
    "disposition": "released-for-delivery",
    "operationRef": "paper-operation-A"
  }
}
```

The proposed receipt and event are one reducer-committed fact, not an executor's
claim of success. Release-for-delivery is not external delivery confirmation.
Events publish after commit through the future domain outbox; a rolled-back
decision has neither a success receipt nor a committed event. Current
`approval_decided` notifications are not that public durable outbox.

`requestId` correlates one transport attempt and may change on retry; it is not
the durable retry identity. The illustrative idempotency scope is installation,
authenticated actor, command kind and work reference plus `idempotencyKey`. Its
receipt binds one logical operation and the accepted generation/fence, snapshot
versions and canonical intent digest. E0 must freeze the exact scope and encoding.

Proposed retry rules: the same authorized idempotency key in that scope and the
same canonical intent returns the original receipt without another send. Reusing
that key with changed intent is a conflict. Two distinct decisions race on the
authoritative pending work/version;
only the winning transition can apply. A changed draft, workflow or assignment
invalidates the old decision basis; Mail rejects stale intent without approving
the replacement. Current exact identity/digest, receipt retention and response
schemas remain freeze work. Receipt lookup itself requires current read authority.

Events are at least once. The consumer deduplicates by stable event ID and never
uses arrival order as workflow authority. Aggregate ordering, if offered, is
explicitly scoped to this work item. Bounded retry/dead-letter/replay state belongs
to the broker, not a Mail transaction; reasoned replay rechecks current audience
and cannot resurrect a revoked generation. An event can trigger a fresh query,
not an automatic decision under an old token.

## Lifecycle, ownership and paper receipts

The following rows illustrate separate lifecycle dimensions; they are not one
overloaded status enum. Each receipt binds immutable release/config digest,
installation, operation, approved generation and the domain work it concerns.

| Paper receipt | Committed authority / observation | Resume or cleanup obligation |
|---|---|---|
| `paper-install-1`: candidate awaiting expanded grant | Existing approved generation stays within its old grants; candidate has no active Mail route. | No candidate work or subscriptions before approval; rejection removes only candidate-owned disposable resources. |
| `paper-withdraw-1`: new admission closed, pending work unresolved | Mail records the remaining work references and required disposition/migration; app process exit is not completion. | Removal cannot claim success while obligations are unresolved. Any permitted drain is narrowly bound to the accepted work and deadline. |
| `paper-revoke-1`: security fence committed | Old generation loses read/decide/event delivery immediately. | Revoke handles/subscriptions/jobs; separately authorized Mail maintenance settles or migrates obligations. Never revive the old app token to drain. |
| `paper-stop-1`: runtime stopped, disposable cleanup incomplete | Mail disposition/drain obligations and authoritative admission/route fencing are confirmed before runtime stop; an already-inert listener/subscription disposal acknowledgement is still missing. | Retry exact owned disposal; record failure honestly until acknowledged. An unreconciled authoritative route cannot be deferred past stop under this receipt. No broad mailbox deletion. |
| `paper-restore-1`: isolated inactive copy | Mail/app data provenance is retained; restored app routes, reminders and external sends remain disabled. | Explicit current-authority validation and activation are separate operations; historical decisions are not replayed into new sends. |

Own each request timer, event subscription, UI listener, route, runtime lease and
temporary review handle. Record acquisition, cancellation, cleanup acknowledgement,
deadline and retry owner. Numeric grant, command, drain, retry, receipt-retention and
cleanup deadlines must be set by the owning implementation packet; this fixture
does not adopt a universal timeout or treat cancellation as cleanup proof.

Mail messages, pending work and audit remain Setjoin-owned. App policy/worklist
metadata is namespaced and retained by default. Installer departure transfers no
Mail ownership. Disable/removal does not erase messages, audit, shared files,
backups or pending obligations. Persistent app attachments, if introduced, use an
organization-owned app-managed Drive space, not the installer's personal folder.
Selected/full backup must include the declared dependency closure; configuration
backup alone is not recovery of pending Mail or app state. Restored copies suppress
outbound effects until separately authorized activation.

## Proposed tests and remaining freeze work

These cases are specifications to implement later, not tests run in CP0.

| Proposed case | Required observation |
|---|---|
| MA-P01 — valid, missing, empty, unavailable | Exact permitted projection; opaque missing/hidden response; empty array success; upstream failure never masquerades as empty or approves mail. |
| MA-P02 — scope and SoD | Another user's work, actor spoofing, out-of-scope mailbox, requester-as-approver and expired/revoked grant produce no Mail mutation or information leak. |
| MA-P03 — stale snapshots and deadlines | Draft/workflow/assignment change and an expiry race reject old decisions atomically; the expiry sweep is not the only command-time guard. |
| MA-P04 — duplicate/reordered/concurrent decisions | A new correlation request ID with the same scoped idempotency key/intent returns one receipt; changed-intent key reuse conflicts; reordered events and conflicting decisions produce one disposition and no duplicate send. |
| MA-P05 — transaction and delivery uncertainty | Reducer failure publishes no committed event; lost command response is resolved by authorized receipt lookup. Ambiguous external SMTP delivery is not blindly replayed by the app. |
| MA-P06 — lifecycle and resource failure | App unavailable while pending; planned withdrawal; immediate security revocation; crash after commit; missing cleanup acknowledgement. Pending work remains visible to Mail and resource completion is honest. |
| MA-P07 — retention and inactive restore | Admin departure, uninstall retain-default, dependency blockers, configuration-only limits and isolated restore cannot delete or resend Mail. |
| MA-P08 — public-boundary conformance | No DB/worker credential, private replay flag, raw event feed, or hidden first-party endpoint is required; unknown schemas/capabilities fail closed. |

Existing source-level anchors, not fresh verification: [approval_decide.pg](../../mailserver/sql/tests/approval_decide.pg)
lines 20–28 cover SoD, actor denial and second-decision rejection;
[mail_external_approval.pg](../../mailserver/sql/tests/mail_external_approval.pg)
lines 38–119 cover held-send effects, replay and committed facts;
[approval_expire.pg](../../mailserver/sql/tests/approval_expire.pg) lines 77–118
cover expiry effects. The routing test cited above covers the worker dispatch seam.
None establishes the proposed installation broker, public versioned command,
durable receipt, or lifecycle protocol.

Freeze gaps: precise field/data-class allowlists; mapping installation scope onto
existing authority; immutable message/workflow identity and update semantics;
atomic deadline/grant fences; public outbox/receipt schemas and bounded retention;
pending-work migration/disposition receipts; exact numeric resource deadlines; and
backup dependency/restore evidence. They need owning engineering/security review.
No new product decision is asserted here. An unresolved pending-Mail failure or
migration policy must be surfaced to its owner, not silently selected by this app.
