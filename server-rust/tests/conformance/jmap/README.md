# JMAP recorded parity cases

`bins/gateway/tests/jmap_recorded.rs` runs the real front door and sends one
signed request per case. It creates and removes a fresh isolated mailbox in the
provided disposable database. The Rust replay installs the native JMAP route,
unsets the Go upstream, and compares the checked-in Go response, request,
mailbox snapshots, complete mailbox audit rows, and direct `LISTEN` events.
The cross-tenant cases also observe the foreign mailbox, its complete row
changes, audit rows and notifications. Mark-read names a foreign message and
Go returns `notFound`; inbox-list names a foreign tag and Go returns an empty
page.
The invalid mark-read case sends an empty-string `$seen` and records Go's
per-item `invalidArguments`; the Rust adapter passes that value to the same
scoped reducer and retains its audit and unknown-commit behavior.
The inbox invalid-input case supplies a negative limit; Go clamps it to 50 and
the replay verifies the returned page and absence of effects.
The mark-read repeat case sends the same request twice on one connection and
records both responses, the combined row changes, two audit rows and the single
notification emitted by the first change.

The family self-tests plant no-audit, no-notify, double-state-bump and
no-tenant-filter mutants in random, disposable schemas on the application
connection's search path. Public schema definitions are not replaced. The
tenant mutant uses an owner-backed messages view only in its test schema, so
the application predicate is exercised independently of the RLS backstop;
the ordinary replay still runs as `DB_APP_DSN`. Each case drops its schema.
Companion `*-row-effects.json` goldens compare all columns in the declared
mailbox-scoped tables before and after the request. Volatile substitutions are
listed in each file; state counters and the existence of a changed timestamp
remain observable. The test key and JWKS are public fixtures, never production
credentials. This fixture uses fresh per-case rows in the assigned database;
it does not create or clone a separate template database.

Run the ordinary replay with the database environment required by
`server-rust/AGENTS.md`:

```sh
cargo test --locked -p setjoin-gateway --test jmap_recorded
```

To record a new case, run the frozen Go mailserver with JMAP coverage behind a
loopback listener, configured to use the disposable database and to fetch
`test-jwks.json` from a local HTTP server. Set `GOFREE_RECORD_UPSTREAM` to that
Go listener and `GOFREE_GO_SOURCE` to the exact Go source commit, then run the
single named case with `cargo test ... --test jmap_recorded CASE_NAME`.
Recording installs a proxy-only route table so every request reaches Go;
turning the retired Rust pilot flags OFF does not select Go. A second run with
`GOFREE_RECORD_EFFECTS=1` records that case's companion row changes. Each file uses exclusive creation and cannot overwrite an existing
golden; use a new case name for a new recording. Never record with real tokens
or tenant data. Go builds for recording should instrument both its main package
and JMAP handler, for example `go build -cover -coverpkg=setjoin.com/mailserver/cmd/mailserverd,setjoin.com/mailserver/internal/jmap ./mailserver/cmd/mailserverd`.
With Go 1.26.6, selecting only the handler produces no coverage profiles.

`divergences.json` applies only to an exact route, case, JSON Pointer and
before/after pair. Every entry needs a reason, reviewer and `reviewed: true`;
the existing audit
entry references the owner decision that explicitly approved the operation ID.
The library rejects incomplete or duplicate records even when they target a
different case. The HTTP-status and unexpected-row mutation cases demonstrate
that the oracle reports changed behavior.

The workspace `route-catalog.json` associates every recorded case with its
exact Rust test and handler files. Multiplexed commands are also named in the
gateway inventory. The adequacy guard executes each listed replay, requires a
case-specific receipt after comparison, and executes the per-route status and
applicable family effect mutants ([gate contract](../../../DOX.md#oracle-adequacy)). An ON command needs success, cross-tenant and invalid
cases; a mutator also needs row-effect goldens and a repeated request. OFF
commands with recorded cases still run and report coverage. Use
`python3 scripts/check-gofree-oracle-adequacy.py --execute --coverage` with
the disposable DB environment, `DB_APP_DSN`, and Rust `llvm-tools`; pass
`--coverage-output PATH` to retain the JSON report. The standard Rust lane
runs this check when a DB is available.

JMAP2 HTTP cases share `jmap_email_oracle`: request `path` is the inventory
route template, while `uri` retains the concrete fixture-normalized request.
Each HTTP Go recording starts its own frozen binary with the assigned database
and a stateful, independently SigV4-verifying S3 seam. Replay has no Go upstream
and asserts total/F18 proxy counters are zero. Session cases capture native
registration row effects under both app-role and pre-flip owner credentials.
Upload effects include complete blob, charge, aggregate usage and cleanup rows;
its fixture removes the canonical hash between recordings so inserts cannot
silently degrade into dedup updates. All dynamic containers use the resource
prefix/ledger supported by `common::go_oracle` and are reaped by its guard.

Recovery HTTP effects also include the server-global continuity row; the
fixture saves/restores its clock/boot fields and normalizes generated boot UUIDs.
The attachment-token replay independently verifies HS256 using Go's captured
KDF output for the public fixture secret, verifies the current SQL policy digest,
origin session/device/actor binding, 300-second TTL and fresh UUIDv4, then masks
only generated identity/time/signature and the validated policy digest. Raw JWT
claim key order remains covered. The parent expires in 60 seconds to preserve
Go's intentional five-minute mint lifetime beyond parent expiry.

Identity fixtures fix users.updated_at for stable state tokens and name
prefixed identity IDs independently of their numeric actor/alias IDs. Alias
rows are included in complete effects. Database cancellation cases inject
SQLSTATE 57014 into one existing reducer and restore its exact definition after
the request. The final-phase Identity/set fault proves alias/user rollback.
EmailSubmission (#317) uses `bins/gateway/tests/jmap_submission.rs` and the shared
`jmap_email_oracle` runner. Its requests declare the submission capability.
The scheduled-send fixture uses a fixed future send time; replay still requires
`REQUIRE_DB=1`, all assigned DSNs and `--test-threads=1`. Record with this exact
worktree's covered Go executable and keep its source commit in `GOFREE_GO_SOURCE`.

The #317 corpus also covers the mounted REST undo/recall actions: the recorded
`path` is Go's registration pattern, with `path_values` binding its ID, while
the request is sent to `/api/messages/...`. Native replays assert total and F18
proxy counters stay zero. The explicit helper-forward tests use a local
#328 owner fake and asserts one forward, unchanged mixed-map bytes and zero
native effects (ASCII and Unicode-folded S/MIME flags, attachments and malformed helper load IDs).

Submission effects add complete scheduled-action, hot/deferred queue and recall
audit rows, including affected recipient mailboxes. Generated action IDs/default
dedup keys are named together. `imap_modseq_seq` is seeded to 1 before each
serialized disposable fixture; its protocol-visible values remain compared.
Go's recorder uses the owner request DSN (the latent-RLS baseline); native reads,
cancel and undo use `DB_APP_DSN`, with `DB_WORKER_DSN` for set/recall fan-out.
Always select a recording test with `--exact` and use immutable exclusive files.

#317 qualification uses six changed-status mutants, four private-schema
`app_notify` mutants and a private recall reducer with its audit insert removed.
The public schema is unchanged; each exact random schema is dropped before
fixture cleanup. The F18 family audit/tenant/double-bump mutants remain in
`jmap_recorded`. The COMMIT seam is `common/commit.rs`: both actual wire cuts
require Unknown, scope-bound receipt resolution and no effects or exactly one
recorded Go request's effects. No timing sleep substitutes for the COMMIT or
LISTEN barriers. All #317 entries are bundled ON; the native test fixture does
not override inventory decisions.

Go error-branch coverage (#317, ARCH-030) uses the covered frozen executable
(main + JMAP + user packages); the retained `JMAP3-go-coverage-closeout.log` is the
function report. The recorded error branches are:

- Set: typed argument decode (`submission-set-invalid-argument-type`), account
  parse/denial, create-map decode and reducer error (`submission-set-db-error`).
- Get: typed arguments/elements, missing/foreign account and malformed scheduled
  payload (`submission-get-db-error`). Query: typed limit, foreign account and
  database argument overflow. Cancel: typed arguments, account denial, missing/
  invalid emailId and foreign source reducer failure.
- Undo: invalid ID, missing/foreign source (BZ021), repeat/not-sent (BZ022).
  Recall: invalid ID, owner-filtered metadata miss, sender denial, owned alias,
  expired window and disabled reducer verdict, plus normal/repeated fan-out.

Unreached branches have these request-boundary exclusions: Go's auth middleware
prevents either REST handler's nil-user branch, and the route pattern cannot
supply an empty undo path ID. Primary-mailbox admission failures remain #112.
Set's sign/encrypt and attachment assembly pass remains the #328 MIME/S/MIME
helper, so an entire map needing it forwards before writes; no crypto/blob
preprocessing branch is claimed here. Its JSON marshal-error arms cannot fail
for validated RawMessage/string/bool maps (no cycles or non-finite numbers).
Undo's generic reducer-error arm has no other business error in the frozen
reducer; recall's top-level reducer/alias-query errors require database failure
(the per-recipient reducer failures are caught). Recall decode/unknown-verdict
arms cannot follow the frozen reducer's four typed JSON verdicts. Its notFound/
alreadyRecalled verdicts after a successful source lookup require concurrent
source deletion between lookup and reducer, absent from serialized fixtures;
ordinary absence is covered at the same owner-filtered metadata gate.
