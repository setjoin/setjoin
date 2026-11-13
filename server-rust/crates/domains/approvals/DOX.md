# Approvals (F10, #269)

`setjoin-approvals` depends only on foundation crates. The gateway owns HTTP
translation; canonical PL/pgSQL reducers own business mutations. Actor IDs come
from shared authz or the verified approval-email capability. User and mailbox
IDs are distinct. Request-owned IDs identify targets, never authority.

## Scope and admission

Tenant reads use `ScopedExecutor::read_scoped` and same-statement ownership
predicates. The executor installs both mailbox and user GUCs from its verified
context; `app.current_user_id` is required by approvals' FORCE RLS policies.
The global policy collection requires live governed approvals permissions.
Signed permission or domain claims alone never grant policy authority.
Unsupported credentials and unmirrored security gates forward the whole request
before consuming its body or attempting a write, per ARCH-027.

## Verification

The `approvals` gateway integration target observes the real HTTP front door.
Recording uses the assigned disposable full-schema DB, the app credential for
HTTP tenant requests, and a frozen-Go coverage binary. Containers use the
caller-supplied APPR1 prefix; ordinary replay starts no Go. Recordings use
exclusive create and retain the frozen commit. Generated fixture IDs are
validated before normalization. All twelve bundled registrations are ON after
their recorded response/effect
replays and deliberate adapter/reducer mutants pass. The route catalog binds
exact no-Go replay selectors to immutable frozen-Go observations.

## Cancellation and commit observations

Cancellation calls frozen Go's `approval_request_cancel` with the sealed actor.
Its same-WHERE requester/pending guard, core audit and approval_decided publish
commit together. `run_receipted_command` adds only the foundation's opaque F10
receipt; business-effect comparisons exclude that system metadata. Unknown
returns 503 and X-Operation-ID, never success or forwarding after an attempt.
BZ125 stays Go's opaque notFound response for foreign and repeated cancellation.

The lifecycle oracle captures complete changed request/mailbox rows, core audit
rows and commit-ordered approval_decided. It verifies response bytes and headers
before replacing generated fixture identifiers and timestamps. The initial
cancel-success files retain an unnormalized audit occurred_at and are immutable
historical recordings; the qualified success pair is the replay source. Test
cleanup removes exact fixture requests, audits, accounts and new F10 receipts.

Authenticated decisions use an explicit requester/active approver/governed
viewer visibility predicate under user RLS, then call the consumer reducer.
The reducer rechecks decision authority atomically. HR calls the existing
hr_approval_decide, with receipts and Unknown handling as for cancellation.
Go's BZ106/BZ108 conflict and BZ107 forbidden detail projection is allowlisted;
BZ125 stays opaque. JSON decoding retains Go's case folding, null and duplicate
field rules while rejecting unknown fields and trailing values. The gateway
wires guest.invite through Guests #272's atomic preparation/delivery helper;
domain crates have no dependency on each other.

## Global policies

Admin admission resolves current governed permissions and the narrowest live
domain scope. Signed permission/scope claims supply no grants. Policy listing
retains Go's manage-only table RLS even for callers admitted by approvals.view.
The seven-type HTTP filter whitelist intentionally omits SQL-only protected
identity/system-upgrade consumers. Permission denials reproduce the system
console.denied audit with NULL actor and verified display email in before_state.

The four `rust_approval_policy_*` commands are installed through the canonical reducer loader.
Update/delete use their own guarded data reducers; reorder retains Go's two
negative/positive passes and accepts missing IDs and empty lists as Go does.

`rust_approval_policy_create` reproduces Go's priority read and insert; a separate best-effort audit then
records the committed policy with trusted actor/IP. This is frozen Go's two
transaction contract, preserved under #269's explicit parity rule. Each Rust
transaction has its own opaque receipt/operation ID; the secondary ID is a
bijective bit flip of the request's random ID. Data Unknown returns 503 with the
original operation ID and never runs an audit or forwards the request.
## Email capability and notification worker

Email GET/POST use the server JWT secret as Go's padded-base64url HMAC-SHA256
key; the verified tuple binds request, approver, decision and expiry. GET only
reads and renders Go's confirmation HTML. POST retains Go's narrower consumer
switch (HR, Drive access and Guests links render inactive). Session policy does
not replace this independent capability. Visibility uses the verified approver;
reducers recheck approver authority and pending status atomically.

`RUST_WORKERS_ON=approval-notify` starts the direct `approval_created` listener;
configure `GO_WORKERS_OFF=approval-notify` on Go at the same transfer. The Rust
worker uses `DB_WORKER_DSN` (fallback `DB_DSN`), never the direct listener DSN
for data. Shutdown closes LISTEN and cancels in-flight work; lost connections
reconnect. `JWT_SECRET`/`HOSTNAME` construct the same signed links as Go. Missing
secret/base URL skips delivery. Only rbac.jit_activation is skipped by Go's
consumer switch: other consumers, including HR, receive notification emails.
The seed/one-event oracle verifies HMAC-bound links, full message columns,
mailbox counters, unread/tag changes and changes-journal rows. Generated global
IMAP modseq must advance exactly once before normalization.

## Qualification and rollback

The route catalog binds success, ownership/permission, malformed input and every
mutator's repeat to immutable Go observations, including full response headers,
request rows, core/Drive audits and commit-ordered notifications. Per-route
changed-status adapters run real requests; family faults shadow only the
canonical cancellation function in an owned disposable schema (missing audit,
missing publish, removed requester predicate on the pre-flip owner credential,
and an erroneous double mailbox bump). Observations are never edited to simulate
faults. The executable suite checks all twelve registrations with bundled ON,
`GATEWAY_ENABLED=false`, and a custom inventory demoting F10 to Go. F10 rollback
keeps `/api` classification and its family proxy counter.

Parity notes: HR requester fields are ignored and the token's user owns each
new request, including repeated submissions; policy matching is a worker-owned
function, so ordinary requesters can match policies. Unknown list/pagination
query fields retain Go's ignored/default behavior. No accepted divergence is
introduced. Guest decisions retain atomic apply/mint and best-effort delivery
through the gateway-owned Guests integration (#272).

Historical unqualified observations remain immutable for provenance: the first
cancel success retained audit occurred_at, the first reorder success retained a
generated orderedIds ID, the first update permission denial retained a path ID,
the first HR success retained policy_id, and the first notifier tick retained a
global modseq. Only the corrected `*-qualified` recordings enter the catalog or
worker replay. Each replacement was re-recorded from the frozen binary.

Additional edge recordings pin priority-collision 409, Go base64 signature CR/LF
and pad-bit decoding, fractional expiry rounded down by Unix(), case-folded
worker events, and mail/Drive error projection (including typed quota HINT and
retryable infrastructure failure). Raw SQL messages/HINTs remain private except
Go's explicit approval-message allowlist and classified remediation. The scoped
executor's optional HINT field is transported without changing log summaries.
Replay worker executors receive the same trusted audit keys as the executable
and frozen Go pools. This remains required after earlier shared checks enable
core audit-key enforcement; fixture setup must not depend on a permissive DB
baseline. Serialize database test processes and reconcile abandoned owned
fixtures before the full lane's empty-database bootstrap cases.
