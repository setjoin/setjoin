# Guests HTTP oracle (#272)

Goldens are immutable recordings from frozen Go source
`1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`; source equality and binary SHA
are retained under `test-results/gofree-guests1`. Record one new test by exact
selector with `GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`. Existing files
are exclusive-create; recording a whole target again intentionally fails.

Replay: `cargo test -p setjoin-gateway --test guests`, with assigned owner/app
DSNs, `REQUIRE_DB=1`, recording variables unset and serial DB execution.
The actual HTTP front door has no Go upstream during replay. User/mailbox IDs
are distinct. Domain-scoped governed grants prove collection non-enumeration
and detail anti-oracles; list query fields are ignored by frozen Go.

All twenty F11 registrations are ON by default. The catalog selects Go floors
and mutator repeats, changed-status per route, and four family mutants. HTTP
replay asserts a zero F11 forwarding counter. `guests_startup` runs the executable
with bundled defaults and both rollback switches; all twenty routes are checked.

Mutants change execution: profile audit suppression, a two-step mailbox bump,
worker-pool collection SQL without its tenant predicate, and isolated clones of
the status/revocation reducer chain with publishing removed. Observations are
never edited to simulate a failure. Each temporary trigger/schema is removed
before fixture teardown. Row effects retain complete owned user/guest/auth
records and unchanged foreign mailbox states.

Invitation capture verifies S3 signatures/chunks and object digest, MIME
recipient, 256-bit token and committed SHA-256 binding, queued reference, and
wire/database expiry before normalizing generated identities and timestamps.
Reinvite, profile defaults, config rollback, delivery failure and duplicate
request/invite behavior have additional recordings. Approval decisions retain
Go's best-effort delivery; email-button guest dispatch remains inactive.

`worker-*` are one-tick recordings from the tagged frozen-Go hook. Replay invokes
Rust SQL plus a real fake-SFU HTTP endpoint which verifies JWT signature/grant,
protobuf target and retry delay. Natural expiry is tested with admission OFF.

Historical unqualified assignment/invite/revoke recordings remain immutable;
the catalog selects qualified replacements where fixture IDs, timestamps or
route wildcard spelling needed normalization fixes. No response/effect divergence
is accepted. Date, generated IDs and digests are validated before normalization.

The measured Go baseline and unreached-branch inventory are in
[COVERAGE.md](COVERAGE.md). Historical folded-profile and sponsor-query files
also retain their original fixture normalization; qualified catalog entries
are the executable comparisons.
