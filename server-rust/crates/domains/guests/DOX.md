# Guests (F11, #272)

`setjoin-guests` depends only on foundation crates. The gateway translates HTTP;
canonical PL/pgSQL reducers retain business authority. User and mailbox IDs are
distinct and come from the sealed auth context. Target IDs never grant authority.

Profile list/detail/domain reads run through the worker credential, matching frozen Go's explicit
BYPASSRLS carve-out. Its reducer couples live guest permission and domain reach
on one assignment; signed scope claims supply no grants. The feature gate runs
before permission admission. Unmirrored credential/security checks forward the
untouched request before reading a body or attempting a command.

The gateway `guests` integration target records frozen Go through the front door
and replays immutable observations with no Go upstream. Record mode uses
`GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`; normal replay leaves them unset.
All twenty F11 routes are native in the bundled inventory. Its catalog binds
success, cross-tenant, invalid-input and write-repeat Go recordings to executable
replay and status mutants; family effect mutants exercise real SQL/HTTP faults.

Profile saves call `rust_guest_profile_save`, reproducing Go's profile set then
get before one commit. The strict HTTP decoder preserves Go's field folding,
pointer presence and duplicate/null semantics. `run_receipted_command` adds the
foundation's opaque F11 recovery receipt; Unknown returns 503 and X-Operation-ID,
never success or forwarding after an attempted write. Business-effect recordings
exclude only that foundation metadata. Audit keys come from trusted configuration.

Guest list/detail and sponsor reads retain frozen Go's worker-pool SQL, with
same-statement live guest permission, immutable host-domain and scoped target
predicates. `src/{guest_list,guest_get,sponsors}.sql` are request SELECTs, not
installed reducers. Domain/OU/set reach stays coupled to the permission-bearing
assignment. An inaccessible detail is Go's plain `guest not found` 404; an
inaccessible collection/sponsor selection is empty.

Lifecycle status commands call `rust_guest_status`: Go's authority fence,
permission-bearing guest prelock and canonical lifecycle call are one transaction.
A prelock miss is decoded as a rollback and plain 404, with no receipt. The HTTP
oracle captures complete guest/auth rows, core audit, commit-ordered session
revocation events and unchanged actor/foreign mailbox states.

Disable/enable/extend preserve the existing status reducer, full revocation
boundary and audit/publish effects. Disable repeats revoke again; enabling an
already active account is BZ162/422. Extend validates its body before target ID,
as Go does. Timestamp decoding tests pin timezone conversion and pgx's truncation
to microseconds; Go's zero-time check precedes that truncation. The wrapper's
seven pgTAP assertions cover coupled state, same-domain scope, revocation and audit.

Profile assignment and sponsor transfer each issue one canonical reducer command.
The global invite allowlist preserves Go's actor metadata lookup and one-statement
mutation. Its attribution is authenticated, even though the list is global.
Revoke combines Go's UX reach preflight with the canonical rechecked mutation in
one wrapper reducer; an unreachable target rolls back with the plain Go 403.
Member submissions require both toggles and call guest_invite_request_create;
policy selection owns the approver and host, and no credential is minted here.
Console middleware denials retain Go's best-effort system audit.

Direct invitation, reinvitation and approved invitation preparation are single
wrapper reducer calls. Rust generates a 256-bit base64url token in memory; SQL
receives only SHA-256. Sender/public URL validation happens in the command's
precommit decoder. S3 MIME storage precedes Go's separate queue insert; failed
or unknown delivery returns the committed-pending 503 shape, without logging
transport errors or exposing a token in JSON. Retryable storage failures retain
Go's ten-attempt bound. The oracle verifies SigV4, object checksum, MIME token
width/digest binding, recipient, committed expiry, queue rows and notifications.
SQL invite composition has nine rollback-only pgTAP assertions. Existing unqualified recordings retained for
provenance are not catalog inputs; qualified replacements correct fixture ID or
timestamp normalization without changing frozen Go responses/effects.


The gateway wires the F10 authenticated `guest.invite` decision to the same
atomic prepare helper, with approval authority rechecked by the canonical
reducer. Denial mints nothing. Postcommit delivery failure is best effort for
approval decisions (200/applied), whereas direct/reinvite callers receive 503.
Go's email-button switch excludes this consumer and stays unchanged. Invite
acceptance/identity remains F21 Go, pending #331–#333; no F11 credential is
accepted by this crate.

`guest_worker` invokes canonical expiry at startup/hourly and drains exact
durable SFU intents at startup/every five seconds, regardless of admission
flags. Claims lease for 30 seconds with SKIP LOCKED; batches stop at 100.
Authenticated LiveKit protobuf removal preserves Go's room-admin-only grant,
retry horizon, success/absence cadence, exponential failure cap and 60-attempt
dead-letter. Disable/reinvite perform a bounded five-second postcommit drain;
reinvite drains before token-bearing mail. Named transfer is
`RUST_WORKERS_ON=guest-lifecycle` plus `GO_WORKERS_OFF=guest-lifecycle` (startup
refuses shared effects without the Go-off declaration); request
adapters retain immediate drain independently of the scheduled-worker switch.
Shutdown cancels and joins the worker. Six frozen one-tick Go recordings cover
expiry with admission OFF and SFU success/absence/failure/horizon/dead-letter.

The executable test `guests_startup` checks every bundled ON route, zero F11
forwards, route-OFF and global kill-switch forwarding, and worker shutdown.
S3 uses existing `S3_*` deployment settings; LiveKit uses `LIVEKIT_URL`,
`LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`. No new production configuration is added.

The [coverage receipt](../../../tests/conformance/guests/COVERAGE.md) records
the frozen Go baseline, branch reachability limits and replay evidence.

Approval delivery replays deliberately share the numeric approval/invite ID.
Audit normalization validates each target against its recorded `target_type`
and exact fixture ID, so independent ID sequences cannot alias their meanings.
