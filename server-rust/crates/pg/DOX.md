# PostgreSQL infrastructure

`workers::DirectListener::listen`/`unlisten` (#318) add/remove validated channels
on one direct-DSN connection for the shared push dispatcher. Drop aborts its
owned driver, including when a socket/hub is cancelled; `close` joins it.

`ScopedExecutor::read_user_scoped` (#318) serves mailbox-less user domains:
`BEGIN READ ONLY`, transaction-local `app.current_user_id` from a verified
`ActorId`, one admitted SELECT, COMMIT. It never invents a mailbox, sets a role
or pools a failed transaction. Family SQL retains its authenticated user WHERE.
`audit_app_blocked` mirrors Go's independent best-effort app-denial audit through
one `audit_write` statement; the actor comes only from verified authentication.

The request executor's contract remains in `src/lib.rs`. `operator` (#354)
provides standalone local CLI connections whose authority is the configured
operator credential. It never impersonates an HTTP user or changes role.
Statements bind parameters over the unnamed protocol, including on DB_DSN.
Schema/bootstrap choose direct-owner → owner → legacy direct → pooled DSN;
SCIM/S/MIME/push/sources use only DB_DSN, following frozen Go.

This operator adapter is for trusted local operators only; request handlers use
authenticated scoped executors. The explicitly authorized compliance snapshot
below uses the separate worker adapter. Push device resolution sets its encryption key transaction-locally, filters the
selected user and revoked rows in the SELECT, and commits before outbound I/O.
SCIM/bootstrap invoke existing reducers; S/MIME retains Go's separate one-statement
autocommit writes (a later default failure does not roll back the upsert).
No session GUC persists beyond
an operator command. Driver tasks are aborted when a connection is dropped.

## Existing executor and worker contract

  - `crates/pg` (`setjoin-pg`, #213) — scoped PostgreSQL executor
    (`tokio-postgres` 0.7.18 + `deadpool-postgres` 0.14.2): one transaction
    per command; `set_config('app.current_mailbox_id', $1, true)` from
    `MailboxAuthContext` only (mirrors Go `dbscope.RunScoped`); unnamed
    statements (`query_typed_raw`) and simple-protocol BEGIN/COMMIT/ROLLBACK;
    refuses `SET`/`set_config`/transaction control; outcome is the
    `setjoin-db` lifecycle observation, `Unknown` never success and its
    connection discarded. `read_scoped` (#216): one admitted SELECT in a
    `BEGIN READ ONLY` transaction with the same scope GUC, for reads; any
    failure is `Err` and discards the connection. `Timeouts` (pool wait,
    create, statement; `SET LOCAL statement_timeout` sent by the executor)
    bound every wait on a stalled database (`from_dsn`/`new` use
    `Timeouts::resolved()`: the defaults, widened only when
    `SETJOIN_PG_DEADLINE_MS` 1..=120000 is set, as the DB-backed conformance
    harness does with 30 s so a starved host cannot forward an oracle request
    to Go, #421); a read dropped mid-flight is
    discarded, never pooled. Crate docs (`src/lib.rs`) are the contract. The
    only runtime crate that links a database driver. `run_command` binds the
    authenticated mailbox, actor and operation ID as `$1`–`$3` and executes
    one statement; the family supplies atomic audit/notify effects in that
    statement or its reducer. `lookup_operation` reads the family receipt
    under current scope; the receipt must commit with the command. Lookup waits
    for the operation lock, then reads at READ COMMITTED; timeout is an error.
    Operation IDs must be unique per command attempt.
    `workers::WorkerDatabase` opens worker-credential connections and holds
    Go's `cron:scheduler-single-flight` advisory lock on a dedicated backend
    until the lease is released or the backend dies. Session-affine connections
    are required for this lock; it must not use the request transaction pool.
    `try_cron_task_lock(name)` takes the separate `cron-task:<name>` lock for
    per-task cron handover (#365); `run_cron_statement(&'static str)` runs one
    fixed reducer statement like Go's cron executor (audit keys when set).
    Worker connections use `DB_WORKER_DSN` when set, otherwise `DB_DSN`;
    `workers::DirectListener` takes a separate explicit direct DSN for LISTEN.

## Disaster recovery (#355)

The operator restore connection accepts the already separated password in driver
configuration. Its schema reset holds an ACCESS EXCLUSIVE lock on users, rechecks
zero users and replaces public in one transaction, as frozen Go does. This DDL
surface is local-owner-only; HTTP callers cannot invoke it. No user authority is
inferred from a request or from the archive. Archive ownership/grants are retained
by external pg_restore against the provisioned standard roles.

`workers::WorkerConnection` exposes the same unnamed query protocol through a
WorkerDatabase-selected credential. Backup uses it for explicitly global live-blob
and config inventories and operator run bookkeeping; no tenant HTTP adapter can
obtain this connection from request fields.

Operator recovery snapshots use a dedicated owner connection and a read-only
repeatable-read transaction. The exported snapshot remains alive until external
pg_dump completes and its restore list is durable. This global inventory is an
explicit local operator operation; it never uses a request/authenticated pool.

Standalone operator connections also honor PGPASSWORD and the selected
PGPASSFILE (default HOME/.pgpass) when conninfo has no password. Passfile lookup
retains pgx's first-match, wildcard and escaped-field rules; the selected DSN
still supplies user, host, port and database. Worker configurations enter through
from_config and do not inherit unrelated operator credential defaults. The CLI's
`pgpass-auth` process oracle verifies the PostgreSQL authentication exchange
against an owned loopback peer that denies the connection before any SQL.

## Rust operation receipts (#257/#265)

`run_receipted_command` takes a static `ReceiptCommand { family, command }` and
otherwise uses `run_command`'s trusted mailbox/actor/operation bindings. After
successful reducer execution and decoding it inserts `rust_operation_receipts`
before COMMIT, in that same transaction. Receipt failure rolls back all effects.
Unique operation IDs are mandatory; no upsert or silent replay is allowed.
`lookup_command` waits on the same operation lock, then reads the receipt at
READ COMMITTED. Unknown never reports success; lookup returns committed/absent,
never the command result or user data. Retain IDs under the authenticated context.
The legacy JMAP pilot keeps `run_command`, its same-transaction audit operation
ID and `lookup_operation`'s actor/mailbox-scoped SELECT unchanged.

V276 creates the receipt through the canonical forward schema path; provisioning
ensures `setjoin_owner` owns it even on a fresh cluster. App and worker credentials
can SELECT/INSERT. It is RLS-exempt system metadata: opaque UUID, static family
and command names, commit timestamp; no actor, mailbox, payload or resource data.
Golden row-effect normalization rule: exclude `public.rust_operation_receipts`
from Go/Rust business-effect comparisons. It is Rust-only recovery bookkeeping;
all business rows, audits, state and notifications still compare unchanged.

DB proofs: `foundation_receipt_*` in `tests/db_scope.rs` cover commit/decoder
rollback, owner/ACL posture, in-flight lookup and actual PostgreSQL wire loss
before COMMIT and after its acknowledgement. The latter resolves to absent /
committed without replaying a command.

## Protected audit GUCs

`ScopedExecutor::with_audit_keys` accepts only trusted deployment configuration.
The gateway binds `DB_ENCRYPTION_KEY` and `AUDIT_HMAC_KEY`, the same values Go's
`pgxutil.OpenPool` uses. The executor privately attaches these secrets to the
verified `MailboxAuthContext`; neither request fields nor JWT claims can provide
a GUC name or value. Secret Debug output is redacted. For every scoped write or
read it sets exactly `app.encryption_key` and `app.audit_hmac_key` with bound
`set_config(..., true)`, before command SQL. This transaction-local named
allowlist works with PgBouncer and dies on commit/rollback/cancellation. Empty
keys retain Go's unkeyed fallback. The mailbox GUC remains auth-derived.
Caller SQL still refuses ALL SET/set_config, including these two names; no
arbitrary-GUC or SET ROLE capability is exposed. The request and F16 worker
executors use the same deployment settings. `protected_audit_*` DB tests prove
V3 audit hashing, pool isolation and refusal of caller-supplied GUC mutation.

DB fixture teardown keeps FK cascades active; only append-only audit deletion
uses transaction-local replica mode. Message partition locks are released before
atomic mailbox/user deletion. This also removes membership UID-ledger children,
so subsequent standalone CLI dump/restore sees a valid schema and dataset.
Provisioning's receipt ownership footer tolerates the loader's pre-baseline pass.

`WorkerDatabase::with_audit_keys` uses that same named allowlist for recovery
expiration's core audit. Keys are trusted worker deployment configuration;
expiration commits before selecting/deleting cleanup objects, matching Go's
separate transactions. No request role or mailbox is fabricated for a worker.
The executable test `executable_cleanup_keeps_configured_core_audits_protected`
compares the same one-tick Go recording and additionally requires a V3 checksum.

`command::run_receipted_effect` (#270) keeps the operation lock and receipt
contract while allowing a peripheral effect between transaction-scoped
preflight/locking and the family's reducer. Office uses it for Go's canonical
chunk copy: authorization and advisory lock precede S3 copy; chunk registration
and the receipt commit together. Canonical content is never compensated after
Unknown. This adds no credential, arbitrary-GUC or pooled-role capability.

The restore's locked user-count recheck uses the operator adapter's unnamed
query protocol before schema DDL. Keep named prepared reads out of this teardown;
the full-schema roundtrip-rust process oracle covers this path.

## Authenticated user scope

Scoped request reads and writes also install `app.current_user_id` from the
verified context's actor (#269/#270). Office Drive chunks and approval
policies/requests require this independent user currency under FORCE RLS. It is transaction-local, bound by infrastructure
before caller SQL, and cannot be set by caller statements. Mailbox scope and
credentials retain their existing contracts. The populated approval-list HTTP
oracle and Office `put_file_acl_mode` exercise this through the constrained app
credential with distinct actor and mailbox IDs.

## Business error projection (#269)

`StatementFailure.message` retains the untrusted PostgreSQL server message;
`hint` retains its untrusted optional HINT,
needed to reproduce frozen Go's explicitly allowlisted BZ details. An adapter
must classify the SQLSTATE before exposing any message; unknown SQL text stays
private. Logging still uses `Rejection::log_summary`, which omits row values and
messages and hints. The approval HTTP repeat and authority-denial recordings exercise the
projection; no arbitrary SQL detail becomes a public error.

F10 also classifies canonical mail/Drive errors without exposing diagnostics.
BZ001 uses the structured HINT type to distinguish over_quota from its unrelated
calendar meanings, as Go does. Only a known classified code may use a structured
remediation. Synthetic failures set `hint: None`; existing Blobs/JMAP literals
only receive that mechanical field addition and keep their behavior/contracts.

`WorkerDatabase::guest_expire_due` (#272) invokes only the canonical bounded
expiry reducer, using trusted transaction-local audit keys and the worker DSN.
The recorded guest-worker expiry tick compares its full committed effects with
Go while admission is OFF. No request/mailbox identity is fabricated.

## Frozen Go row-iteration reads (#273)

`ScopedExecutor::read_iterated` is an explicit compatibility seam for list
handlers that ignore pgx Rows.Err. It uses the same admitted SELECT, unnamed
protocol, credential, lease and timeout bounds as `read`. A failure before
RowDescription is an error; a later stream failure retains only rows already
delivered. Failed or cancelled connections retain the existing discard rules.
It must not authorize a request, resolve ownership or execute a command. F14
uses per-row JSON projections, preserving both Go's ordering and partial-list
behavior. `drive_recorded` query-fault HTTP cases record the frozen-Go oracle.
The ordinary `read` and scoped/command APIs keep their fail-closed contract.

## Authorized compliance export snapshots (#291)

`WorkerConnection::rows` streams one unnamed statement with backpressure on a
dedicated worker connection. Drain or drop its `WorkerRows` before the next
query. F04 first commits its token-bound, live-grant-gated export-begin reducer,
then uses the deployment worker credential for one organization-wide REPEATABLE
READ READ ONLY snapshot, matching frozen Go. All content, counts, chain pins and
federation/attachment metadata use that snapshot. No request chooses a credential
or installs a role/GUC. Dropping the snapshot aborts the dedicated driver and
rolls back server-side; connections are never returned dirty to a request pool.

## Legacy protocol password self-heal (#342)

`ScopedExecutor::upgrade_legacy_protocol_password` is the authentication-time,
best-effort single-statement CAS from frozen `pwhash.CheckPassword`. Only call it
after verifying the exact old hash; user ID/email come from that authentication
lookup. User ID, email and old hash share the UPDATE predicate, so credential
rotation or email changes win. It uses the request credential and unnamed
protocol with the executor's usual bounded wait/discard behavior. It claims no
upgrade success after an unknown result; the independently verified login stays
valid, matching Go. No new transaction, audit or notify is added.

Dirty read-lease drop sends a bounded PostgreSQL CancelRequest before discarding
the client (#342). Dropping the client alone can queue Terminate behind an active
query, leaving a disconnected protocol client holding locks until the SQL
finishes. Clean answers return the lease without cancellation. The LDAP socket
regression holds a real relation lock, drops the TLS client, and observes that the
blocked backend disappears before its statement deadline.

## Protocol authentication writes (#343)

`ScopedExecutor::record_protocol_auth_event` and `touch_app_password` are the only
pre-authentication writes: one autocommit statement each on the pool credential,
no tenant scope, fixed SQL (`auth_event_log` insert with the IP cast through text
to INET as Go's text parameter behaves; `app_passwords.last_used_at` and
`users.last_login_at` guarded by the verified user and token hash). Callers
ignore failures, as `pwhash.LogAuthEvent` does. Used by `setjoin-imap`; new
protocol listeners (SMTP submission, DAV basic auth) reuse them.

`ScopedExecutor::record_mailbox_audit` (#344) is the post-authentication twin: one
autocommit `mailbox_audit_log` insert (mailbox and actor from the authenticated
session, never request fields) for IMAP's `auditLog`; callers ignore failures.

## Typed worker query failures (#348)

`WorkerConnection::query_detailed` uses the same explicit worker credential,
parameters and unnamed query protocol as `query`, while retaining
`StatementFailure`'s SQLSTATE and HINT. The existing string-error API is
unchanged. Diagnostics remain untrusted and private; consumers must project
only an allowlisted Go reply class. SMTP needs HINT to distinguish BZ001 storage
quota from its unrelated meanings and to preserve BZ081/BZ099's dual-use rules.
The real-socket `setjoin-smtp --test session reducer_error_projection_matches_frozen_go`
oracle exercises these errors from PostgreSQL, including private diagnostics
that must never appear on the SMTP wire.

## Authentication-time user transactions (#112)

`ScopedExecutor::run_user_command` accepts an ActorId from a proved credential,
an operation ID, one admitted SQL statement/reducer, and a pre-commit decoder.
It sets that user's transaction-local GUC and takes a per-user/operation
advisory lock. It invents no mailbox, uses DB_DSN and unnamed statements, and
waits for explicit COMMIT acknowledgement. A returned row from an autocommit
SELECT alone is insufficient evidence of a committed authentication mint.
Known statement/commit failures roll back; transport loss or timeout at COMMIT
returns Unknown with the operation ID and discards the connection. A current-
authority lookup takes the same operation lock before its fresh SELECT snapshot.
The F21 HTTP wire-fault tests cut before/after COMMIT and verify no credentials
escape, zero/one anchors, and correct current-password lookup.

#333: auth user commands also apply configured encryption/audit keys through the
executor's existing named infrastructure statement. Keys remain deployment-only
and transaction-local, with the same scope/role statement admission. The public
`db_scope::auth_crypto_context_is_local_on_commit_and_rollback` case observes
configured keys inside the command and no key in the next pooled transaction,
after both COMMIT and rollback. WebPush's single INSERT uses this context.
Authentication-time independent tails (#332): `run_user_command_with_tail` runs
a bounded best-effort callback after the one reducer result and before COMMIT.
Frozen refresh logs its auth event through another pool lease at this point,
so that log survives both COMMIT-loss cuts. The callback must never release
credentials; a tail failure does not change the main transaction outcome. The
ordinary `run_user_command` uses an empty tail. Pool capacity must allow the
independent lease. Auth `session_faults` tests both actual wire cuts.

User-command infrastructure also sets transaction-local `app.rust_operation_id`
from the server's opaque operation ID. F21 refresh writes the existing system-
metadata receipt in its publishing transaction; no user/resource payload is
stored there. `Session::lookup_refresh` takes the same lock under a newly
verified refresh proof, rechecks its enabled principal and durable anchor, then
reads only that operation's commit marker. Lost authority is an error rather
than an absence result.

Credential proof callbacks (#334): `run_user_proof_command` keeps the same
explicit user/operation transaction open across a fenced read, synchronous
cryptographic verification, and one `ProvenStatement` reducer write. Both
statements use unnamed typed parameters and the same deployment-only crypto
GUCs. Business writes remain in the reducer; the callback neither borrows a
connection nor releases credentials. Timeout/cancellation discards the lease;
statement admission also checks the selected reducer. Existing one-statement
commands and independent tails use the same lifecycle with no proof step.
`db_scope::credential_proof_and_reducer_share_transaction_scope_and_snapshot`
observes the same database transaction and local crypto/user scope across both
steps, followed by an empty scope on the next pooled lease.
The async form `run_user_async_proof_command_with_tail` keeps the same bounded
lease while a completion callback awaits independent read-only admission and
signing work, then runs its one reducer. Its independent tail has the existing
before-COMMIT best-effort semantics. No connection is exposed and no response is
published by either callback. `db_scope::async_credential_proof_keeps_the_user_fence_until_reducer_commit`
tries a concurrent user mutation during the awaited callback and observes55P03,
then verifies the final statement still uses the original transaction.

User-command commit receipts (#334): `with_user_receipt(ReceiptCommand)` attaches
code-owned family/command metadata to a cloned executor. It inserts the receipt
after successful decode and before the independent tail/COMMIT, in the same
transaction. The key is PostgreSQL pgcrypto SHA-256 of the opaque operation ID
and authenticated actor, truncated to the UUID column. Lookup derives the same
key under fresh current authority and the original operation lock; another
actor cannot recover a receipt from the operation UUID. No user payload is
stored. Ordinary executors retain their prior behavior. TOTP HTTP COMMIT cuts
exercise absent/committed results, foreign-user isolation and disabled authority.

## Mailbox-less user transactions (#188)

The compatibility-named `MailboxAuthContext` can also carry a verified user with
`mailbox_optional() == None` and `ResourceScope::User(actor)`. Only the auth boundary
constructs it. Such transactions clear the mailbox GUC and set the real authenticated
user GUC; they never invent a MailboxId, change credential or SET ROLE. Mailstore
callers still require `mailbox()` and real mailbox authority. User-domain reducers
keep authenticated-user ownership/membership predicates.

Receipted user commands retain the legacy positional binding layout: `$1` is zero
for an absent mailbox, `$2` is the verified actor, `$3` the opaque operation. Zero is
only an unused compatibility binding, never a mailbox GUC or ownership key. User
command guards assert `$2 > 0`; receipts, authority checks, rollback and Unknown
COMMIT behavior remain in the same executor/lifecycle. HTTP guest Chat/Meet/Drive
recordings exercise reads and reducer-refused writes without mailbox rows.

`audit_console_denied` (#188) executes one canonical `audit_write` statement with
trusted before-state JSON and a verified ActorId. As in Go's WriteSystem callback,
user_id/IP/target_id remain NULL; actor email, target and missing permission are
before_state, target type is console, notes is the Go path, tier is core. Audit
failure remains best effort and never grants access or changes the denial.

`protocol_query` (#202) is the returned-row form of the existing best-effort
`protocol_statement` authentication seam. Fixed SQL only, same request pool,
unnamed statement, deadline/cancellation behavior; callers supply verified
principal IDs. Threat rate counters and the scoped device reducer consume its
result. It grants no request-derived identity or success after query loss.

Revocation snapshot cancellation (#202): `active_session_revocations` owns its
PostgreSQL driver with a drop guard. A cancelled/timed-out snapshot sends a
bounded CancelRequest and aborts the driver, including during IMAP cold-start
retry/shutdown. Successful reads disarm cancellation before graceful close.
The gateway `imap_activation` held-lock test checks retry and shutdown leave no
blocked backends; worker credentials and cross-tenant read scope are unchanged.

Anonymous protocol publication (#339): `run_protocol_command` runs one fixed
statement with empty user/mailbox GUCs, a code-owned credential scope, operation
lock, opaque scoped receipt and explicit COMMIT acknowledgement. It grants no
user authority. Cancellation/unknown COMMIT discards the lease and withholds the
result. `lookup_protocol_operation` waits on that same lock before its fresh
receipt read; callers must re-prove the current protocol credential. OP uses
this for an unbound authorization request, never for an authenticated user write.
