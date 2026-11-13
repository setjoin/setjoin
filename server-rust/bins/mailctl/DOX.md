# Rust mailctl — process-boundary ports (#352–#355)

Standalone `mailctl` binary; `main.rs` only dispatches to the library. Rust replaces the shipped CLI in #355; frozen Go
`mailctl/` remains an oracle source. No runtime
fallback invokes Go. Database access uses setjoin-pg; no server-family dependencies belong here.

## Fixed command split

The issue is read-only for this implementer; this is the fixed scope handoff for
#352/#353 (27 Go REST groups, with backup assigned separately):

- Part A (#352), 13 groups, all actions: `user`, `domain`, `health`, `webhook`,
  `config`, `migration`, `auto-update`, `system`, `tls`, `spam`, `storage`, `ad`,
  `ldap`. Also the argv/help/version shell and shared REST/config reader.
- Part B (#353), 13 groups, all actions: `mailbox`, `upgrade`, `ca`, `eap`,
  `device`, `policy`, `quarantine`, `identity`, `feature`, `office`, `audit`,
  `approval`, `role`; also `login` and `logout` (credential configuration).
- #354: direct DB (`schema`, `bootstrap-admin`, `scim`, `smime`, `push`, `sources`).
- #355: `backup`, `backup-db`, `restore`, backup worker and release replacement.
- #355 also owns all offline tools: `dane`, `entitlement`, `exchange-a0`, `exchange`.

Full top-level and subcommand help deliberately retain Go's surface (including
its obsolete argv-password examples). Production builds and releases use this
whole binary; they never invoke the frozen Go CLI.

## Process oracle

`cargo test -p setjoin-mailctl --test oracle` launches `tests/oracle.py replay`
against the compiled Rust binary. No Go toolchain or database is needed. Each
case runs against a loopback fake HTTP server and compares
argv-to-request (method, path, end-to-end headers, exact body), stdout, stderr
and exit status with frozen-Go recordings under `tests/goldens/`.
Transport headers (Host/port, User-Agent, Accept, Accept-Encoding, Connection,
Content-Length) are excluded; auth and Content-Type remain compared. Only the
private home path, assigned loopback port and explicitly selected random private
artifact basename are normalized in diagnostics.
Nondeterministic multi-column Go map-table order is compared by column identity;
JSON bytes and all deterministic text remain exact.

`MAILCTL_CASE=<name>` selects one tracer slice. Record only with:
`python3 tests/oracle.py record /absolute/go-mailctl --output /new/empty/dir`.
The recorder refuses a populated directory; replay cannot change recordings.
Build the unmodified Go source with `CGO_ENABLED=0` (as cross-builds do).
Go resolves the OS account home through `/etc/passwd` before falling back to
`HOME`. The original config-home cases record that it ignores an overridden
HOME for an existing account. Actual private-config cases use UID 65532 with no
passwd entry, so both binaries use the disposable HOME. These cases require
Linux/root (the verification image's normal user); absence fails rather than
skipping. Temp directories explicitly use `/tmp`, since inherited TMPDIR may be
under `/root`. Fixtures contain synthetic credentials only. No test writes an
operator config; the original-account cases require no pre-existing config.
Keep receipt hashes of the Go source/binary and corpus.

## Contracts

REST uses `/api` except Go's pinned prefixes, bearer precedence
`MAILCTL_TOKEN` > `MAILCTL_API_KEY` > config token > config API key, JSON bodies
and Go's bounded RFC7807 errors. Request credentials never come from argv.
The CLI reads `~/.mailctl/config.yaml`. Login reads the password from a terminal
with echo disabled and writes the Go-compatible YAML at mode 0600; logout clears
its auth fields. Both use the OS account home before the HOME fallback.
The config decoder is `serde-saphyr` (safe Rust; `serde_yaml`/`unsafe-libyaml`
removed, #388). It decodes as Go's yaml.v3 does, YAML nulls included, except
three pinned edge cases (multiple documents, a tab before a block key,
`%YAML 1.2`). `client::tests` holds the Go-recorded table.
Global flags parse only leading post-action arguments, including Go's partial
parse before an unknown subcommand flag. Command-local flagsets stop at the
first positional except `user password`, whose flags may follow the email.
Confirmation prompts and per-command quiet/JSON quirks follow frozen Go.

## Verification and provenance

The corpus covers every Part A and Part B action, global JSON/quiet variants, top-level
and command-local help, incomplete/invalid arguments, HTTP denials, confirmation
and cancellation, partial CSV failure, password-file permissions/symlinks and
stdin bounds, credential precedence, JSON escaping, typed zero fields and Go's
human numeric formatting. `process_oracle_rejects_request_stdout_and_exit_mutants`
executes request, stdout, exit-status and file-permission mutants against real
recordings to prove discrimination.

Frozen source: commit `9ea7da184425b52ca7ab2555493028ba17b0cb84`, unmodified
`mailctl/` and `shared/`. Build: `CGO_ENABLED=0 go build -o <oracle> .` in
`mailctl/`, using `setjoin-ci-linux-tc:local-amd64` (Go 1.26.6).
Exact recording inputs and corpus hashes: [tests/recording.json](tests/recording.json).
Rust replays never need that Go binary; it is an ignored recording-time artifact.

Verification: the workspace includes this crate automatically in
`bash scripts/check-server-rust.sh`. Also run `cargo fmt --check` and
`cargo clippy -p setjoin-mailctl --all-targets -- -D warnings` in the workspace,
and `bash scripts/check-agent-context-budget.sh` at the repository root.

## Direct database commands (#354)

The process-boundary oracle in `tests/direct_db.py` replays frozen Go against an
explicit disposable TEST_DB_DSN. `MAILCTL_DB_CASE` selects a tracer case.
The shared setjoin-schema crate embeds migrations from the canonical Go SQL directory;
the standalone binary needs no source checkout. Local operator credentials,
selected with frozen Go's per-command precedence, supply administrative authority;
these commands are never exposed as authenticated HTTP request adapters.

SCIM calls `scim_token_create`/`scim_token_list` under the operator's DB_DSN.
Bearer tokens are random 32-byte lowercase hex, bcrypt cost 10 (`$2a$`) plus
an indexed SHA-256 lookup hash. Only stdout receives plaintext. The oracle
checks both the stored bcrypt verifier and lookup against the printed token
before replacing the random value; expiry is checked against argv before
normalizing its timestamp. These writes have no audit/notify in frozen Go.

Bootstrap calls `ensure_default_admin` under owner-first credentials, retaining
its advisory lock and governed Super Admin grant. Password policy and reserved
names match Go. Interactive input is hidden; noninteractive stdin is one bounded
line. The oracle snapshots every public root table, comparing added/removed rows
with bijective row-content-based generated-ID placeholders (including every FK)
and verified-password/time placeholders. The initial quota date is checked
against database CURRENT_DATE before normalization; certificate dates stay exact.
Its only creation fixture requires an empty disposable database. It saves a full
snapshot, then restores that same database's public schema after the case (plain
pg_restore --clean cannot remove inherited partition constraints). No other
database, role, container or operator configuration is modified.

`sources status|doctor` is read-only: connectivity-profile resolution, fixed-path
Ubuntu/APT/Docker inventory and credential-presence-only external provider
posture. `get_system_config` uses only DB_DSN; unavailable assist posture remains
Go's warning. Repository resolution never chooses a public accelerator. Host
files are size bounded and leaf symlinks are reported without following them.
Cleanup defers SIGINT/SIGTERM until fixture restoration finishes. Run database
lanes serially on the assigned database. Tests compare exact human/JSON output and verify fixture files are unchanged.

S/MIME imports keep Go's independent autocommit upsert and optional per-user
set-default UPDATE. A failed default update warns after the cert has committed;
there is no new transaction spanning those writes. Private keys use
`pgp_sym_encrypt` with DB_ENCRYPTION_KEY as a bind parameter, never a session GUC.
The oracle decrypts stored fixture keys byte-for-byte, preserves certificate
validity dates and checks that another user's default/cert is untouched. Dry-run
validates files without opening the database or resolving users, as Go actually
does. All PEM/key material under `tests/fixtures` is synthetic test data.

Push uses the shared setjoin-push transports. Device resolution runs in a single
transaction with transaction-local `app.encryption_key`; only the selected user's
unrevoked devices are decrypted. The transaction commits before outbound I/O.
Unreadable devices are counted and logged without exposing tokens; sends have no
DB write effects. Provider absence, OAuth diagnostics, partial send failures and
zero-delivery exit status follow Go. No background worker changes belong here.

The direct oracle requires Python 3, PostgreSQL client tools (`psql`, `pg_dump`,
`pg_restore`), OpenSSL and system libcrypto/libnghttp2. It serializes by disposable
DSN and restores its owned fixtures. Run `cargo test -p setjoin-mailctl --test
direct_db` with REQUIRE_DB=1 and the assigned TEST_DB_DSN. Missing prerequisites,
unavailable DB or unmatched selectors fail. Its `self-test` mode checks a matching
baseline then proves DB-effect, stdout and exit-status mutants are rejected.
Record only to a new directory; provenance is `tests/direct-recording.json`.

Push peers are local, never forwarding proxies: OAuth JWT signatures are verified,
APNs uses HTTP/2 with verified client-certificate authentication, and Web Push is
authenticated/decrypted under RFC 8291 and its VAPID signature verified. A Go
build overlay (`tests/record_overlay.py`) changes only APNs dial destination and
the injected Web Push HTTP transport. Rust's matching `oracle-loopback` feature
is enabled by a dev dependency only; ordinary builds ignore both fixture env vars.
Go's production Web Push SSRF rejection is also recorded without the injection.
Frozen Go advertises an empty VAPID public key and prepends `mailto:` even to its
default `mailto:` subject; preserve these observed quirks until a separately
approved behavior change. All fixture credentials, certificates and keys are
synthetic; no real push endpoints receive test traffic.
HTTP peers buffer complete replies for status-only FCM clients and join all
request handlers before checking captured I/O and peer errors. Recorded requests,
database effects and process outputs stay exact.

## Part B process clients (#353)

`src/part_b.rs` implements all Part B groups; `src/identity.rs` owns the identity
subcommands. Part B remains an API client: it adds no database queries, gateway
adapters, worker transfers or binary replacement. All API commands in the fixed
split execute locally in Rust. Direct DB work belongs to #354; offline/backup
work keeps its later-ticket owner.

Identity clients preserve Go's validation, generation CAS, idempotency headers,
step-up challenges, polling, structured problem exits and bounded downloads.
`identity_checks.rs` and `identity_source_doc.rs` mirror Go's wire/document
validators. Exported reports and diagnostics verify the documented checksums,
refuse symlink/non-regular destinations, honor replacement confirmation and use
same-directory private temporary files, explicit chmod 0600, fsync, atomic publish
and cleanup. Upgrade diagnostics preserve Go's create-only publication behavior.

`wire_b.rs` translates frozen Go's typed wire shapes. Field declaration order,
null defaults, nil slices, omitempty, raw JSON and float formatting are observable.
Generic JSON numbers use Go's float64 conversion; typed IDs remain int64. Embedded
RawMessage values retain their lexical key order. `flags_b.json` records 96 local
flagsets, their help, flag types and Go's individual parse/error modes. Global
flags parse only the initial argument prefix; a local unknown flag preserves
Go's partially applied globals. Use `--yes -- <local flags>` where Go requires it.
`ca_schema.rs` mirrors offline CA validation; `ca_errors.json` retains Go's literal
operator dictionary. The HTTP client keeps structured status/problem fields for
command-specific exit mapping and preserves streaming versus bounded JSON reads.

`tests/cases-b.json` adds 1,030 cases without changing Part A's 270 goldens. Cases
cover every action, all 96 help/unknown-flag seams, JSON/quiet variants, HTTP
denials, confirmations, invalid arguments, polling, exports and credential writes.
The oracle can compare exact file bytes/modes and binary requests/downloads,
exercise login over a PTY and run private config cases as UID 65532. Generated
mutation keys must be canonical UUIDv4 with equal body/header values before
replacement by `$UUID`. Artifact cases assert temporary-file cleanup.

Part B provenance: [tests/recording-b.json](tests/recording-b.json). Go is needed
only when deliberately recording new cases or deriving metadata. Derive into new
files, compare, then review before replacing checked-in declarations:

```
python3 tests/derive_models.py --output /tmp/new-mailctl-wire.rs
rustfmt --edition 2021 /tmp/new-mailctl-wire.rs
python3 tests/derive_flags.py --go-binary /absolute/go-mailctl --output /tmp/new-mailctl-flags.json
```

Run from this crate; generators resolve source paths relative to themselves.
They refuse existing output files. Models derive from Go's declarations; the flag
recipe combines Go's flag definitions with actual process help recordings.
Replays and CI need neither generator nor Go. Keep old recordings immutable and
record each new slice against frozen Go before changing Rust.

## Offline tools (#355)

Offline dispatch constructs no API client or database connection. DANE retains
Go's uint8 flag conversion, certificate/SPKI selectors, matching algorithms and
DNS zone-name grammar. Entitlement verification retains canonical Go JSON,
Ed25519 purpose-separated production roots, installation/channel/time checks and
private atomic publication. Exchange A0 stays non-importable; V1 binds registry,
catalog, support cell, collector, artifact digests and probe denominator before
explicit import constructs an authenticated client. Reports and receipts retain
Go's bytes, HTML escaping, checksums, modes and create-only publication.
`tests/cases-c.json` and `tests/recording-c.json` extend the process oracle with
unmodified Go recordings. Generated import keys are validated UUIDv4 headers;
Exchange uses a header-only idempotency key rather than duplicating it in JSON.

## Database backups and restore (#355)

`backup-db` preserves Go's owner-first DSN precedence, refuses argv secrets,
separates URL/keyword conninfo passwords and sets only the child's PGPASSWORD.
It validates a complete custom-format dump, uploads canonical and archival copies
with individually bound HMAC sidecars, and removes private temporary files on
all exits. `restore` uses only the local Unix control socket: preview is read-only;
execution requires --yes or typed RESTORE. Full restore first requests blob
recovery, atomically rechecks empty users under an exclusive lock and replaces
public, verifies the published dump binding, then runs external pg_restore with
ownership and grants retained. Authenticated dump verification precedes replay.
Transport, worker and harness contracts: [backup crate](../../crates/backup/DOX.md).
The round-trip oracle's separate disposable DSN and PostgreSQL lock-capacity
preflight are documented there; other CLI DB suites retain `TEST_DB_DSN`.

`backup create/verify --pre-upgrade` binds authenticated installation/timeline,
immutable gateway blob/config backup, a repeatable-read exported owner snapshot,
restore list, counts, feature-toggle digest and external protected-key evidence.
Every artifact and inventory blob is read and hashed before the HMAC manifest is
published last. Verification enforces identity and 24-hour freshness before
registering evidence through the authenticated API. No PostgreSQL tools or DSN
are needed to verify. `tests/recovery_oracle.py` records the complete Go process
boundary and independently restores the exported dump; denial cases cover bad
HMAC, stale timeline/freshness, corrupted components and mismatched protected keys.
The ticket's env-only-password rule also applies to the pre-upgrade pg_dump;
frozen Go passes an env-sourced raw DSN here, unlike its ordinary backup command.

Offline raw JSON facts retain lexical key order and accept explicit null where
Go's RawMessage does; generic V1 facts retain Go's float64 conversion before
origin digests. Private artifact creation shares the existing CLI publisher.
Entitlement replacement swaps and checks the displaced inode before deletion,
restoring an intervening target on a race; a failed rollback preserves that
entry. Process cases check artifact bytes, 0600 modes and temporary-file cleanup.

The owner schema-reset/exported-snapshot connection honors PGPASSFILE and the
operator's default .pgpass, matching external PostgreSQL tools. The credential
file stays in the environment; no password is added to argv. A protocol peer
checks this fallback without querying or mutating a database.

Schema-oracle parameterization: the immutable #354 recordings use V275 and its
predecessor. `direct_db.py` now retargets expected schema-version and migration-name
tokens from the canonical source catalog, and the behind fixture removes that
catalog's latest version. Actual stdout/stderr, pending names, exit and committed
version deltas remain exact. Adding V276 therefore preserves the recorded CLI
contract without editing goldens or hiding a wrong reported version.

Bootstrap-oracle teardown reuses backup_oracle.py's bounded fixture reset before
restoring every saved table, sequence and grant. Each generated drop runs in its
own psql autocommit, releasing locks before the remaining schema is recreated
(#266). Keep the strict full-dump restore and disposable-DSN/empty-user guards;
do not replace it with pg_restore --clean or change shared cluster settings.
The product restore keeps its exclusive-lock atomic schema reset. On cleanup
failure the direct-DB harness retains its private bootstrap dump and reports
MCTL3_RETAINED_SNAPSHOT instead of deleting the only original copy.
