# SMTP listener (#348–#351)

`setjoin-smtp` owns the inbound TCP session: command sequencing, Go-compatible
framing, recipient admission, DATA intake, TLS and connection bookkeeping. The enabled inbound pipeline is native (#526); fresh installs and upgrades
transfer SMTP sockets by default. There is no TCP proxy.

Use `smtp-proto` for standard commands with a compatibility adapter for the
nonstandard commands accepted by frozen Go. The oracle is production Go's socket
output, recorded by `mailserver/internal/smtp/listener_oracle_record_test.go`
(`gofree_record`) and replayed without Go. Add a separate corpus for new groups;
never edit recorded replies. `oracle/recording.json` records frozen-Go source,
corpus counts and SHA-256 digests of stimuli, observations, fixtures and recorder. Record with `SMTP_ORACLE_DIR` pointing at `oracle/`,
`REQUIRE_DB=1`, and the disposable SMTP1 owner/worker DSN.

Run `cargo test --locked -p setjoin-smtp -- --test-threads=1` with the assigned
disposable DSNs. The interop lane uses the existing `test-smtp` Postfix image;
all current owned Docker names and artifacts start with `gofree-smtp6-`.

Mail authentication/signing is #349 (`mail-auth`), documented below; outbound queue is #350;
DANE/MTA-STS on hickory and activation are #351. The shared threat interceptor
is #420 and is consumed by submission AUTH, not inbound MTA: frozen Go's inbound
session never calls it. No production activation is allowed without those
components. Shared gateway webhook dispatch must receive delivery events.

## Session and recipient admission

`oracle/commands-go.json` pins the bounded command reader and Go's sequence
checks; `recipients-go.json` pins mailbox, alias, catch-all and remote-relay
admission and the 1000-recipient cap. These queries deliberately run on
`WorkerDatabase`: inbound SMTP has no authenticated mailbox, and Go's
`mailbox_lifecycle_delivery_mode` authorizes each locally addressed destination.
A connection uses one unnamed-query worker session, discarded on a query error;
the next recipient retries a fresh connection. No role or tenant GUC is invented.

Parity: `MAIL FROM:<>` stores an empty sender and subsequent RCPT returns 503;
command splitting uses a literal space, so a tab after NOOP is an unknown
command. RSET preserves EHLO, and an overlong physical line is fully drained.

## DATA and storage seam

`data-go.json` pins CRLF dot termination, Go's line-length errors, half-close,
and transaction recovery. The intake retains at most 150 MiB plus the sentinel
byte; four permits bound messages at/above 1 MiB through their delivery lifetime.
The Rust intake uses bounded memory rather than Go's disk spill/rematerialization.
`delivery-go.json` compares real `smtp_inbound_deliver` effects (including repeat):
message fields, raw-reference hash, tag counters, mailbox state, journal and audit.
Shared MIME parsing uses the `setjoin-mime` foundation byte parser, moved
unchanged from F05. F05 preserves its `mimeutil` compatibility re-export.

The storage qualification records Go with its mail features disabled; it does
not qualify the enabled security pipeline. `DeliveryFeatures` passes Go's seven
reducer feature GUCs transaction-locally. Storage uses the worker credential,
stores the raw object before its reducer transaction, and sends no success for
an unsuccessful/unknown COMMIT. `RawBlobs` and `DeliveryEvents` are injected by
the gateway at activation; `None` mirrors Go's nil fixture configuration only.
The event subject is returned by the committed reducer, never by the envelope.

Mirrored Go bugs: `MAIL FROM:<>` cannot proceed to RCPT; the dot reader's begin-line
state does not return to begin-line on a bare LF. Fixed (SECURITY.md, #488): DATA
after zero accepted recipients is 554 and DATA cut before its terminator is 451;
`secfix-data.json` replays the framing cases with an accepted recipient.

Enabled security adapters, per-recipient trust, link protection and post-commit
iMIP (#526): [inbound contract](src/inbound/DOX.md). Production receives the same
configuration through gateway `smtp_runtime`; installer sockets default ON.

## TLS, limits and monitoring

`with_tls` mirrors Go `SetTLS`: an implicit-TLS listener which still advertises
STARTTLS and permits a nested upgrade. Go's TLS-enforce state ignores implicit
TLS, and its reset after STARTTLS preserves an existing EHLO. The immutable
`tls-go.json` records these quirks; #351 owns production certificate loading,
socket activation and the complete TLS lifecycle.

`admission-go.json` pins the default 100 simultaneous sessions (explicit zero
rejects all), per-IP 20/minute budget, and counting a connection even when the
global cap refuses it. Go's expired-window upsert retains the old count; mirror
that bug. Checks fail open on DB errors. Monitoring uses only the worker pool
and the generated owned session ID; `monitor-go.json` pins Go's always-greeting,
zero-byte session rows. Closed and cancelled sessions remove owned rows; listener
shutdown aborts/joins its sessions and sweeps only the IDs it registered.

## Container interop and shared webhooks

`tests/interop.rs` runs the pinned `setjoin-interop-smtp:local` image (the existing `test-smtp`
image plus a Python client layer, `scripts/build-interop-images.sh`, `.github/ci/images.lock`; never
built or removed by the test, #141). CPython smtplib sends real messages over plaintext and implicit TLS
(CA verified), checks capabilities, refuses remote relay, and exercises dot
stuffing. A real Postfix queue from that image also delivers through the native
listener (all inet services removed, so the fixture binds no other host port).
All deliveries must be visible in the disposable database; #349 adds the fourth
signed-message case below. Owned PID-specific `gofree-smtp6-*` client containers
and images are removed.

The gateway supplies `smtp_events::DeliveryEvents(Dispatcher)`; no separate
executor or Go dispatch path exists. `bins/gateway/tests/smtp_events_recorded.rs`
compares the frozen-Go `mail.received` requests, signatures and delivery rows:
organization and recipient-self subscriptions receive both messages; a foreign
self owner, inactive subscription and unrelated event type receive none.
Record via the existing drain harness and `smtp_received_tick_test.go.txt`, with
`GOFREE_RECORD_DRAIN=all`, `GOFREE_GO_SOURCE=<full frozen Go sha>`, an owned
`GOFREE_ORACLE_CONTAINER_PREFIX=gofree-smtp1-*` and `GOFREE_RESOURCE_LEDGER`.
Native replay: `cargo test --locked -p setjoin-gateway --test smtp_events_recorded
-- --test-threads=1`. Durable-enrolled delivery is owned by the shared publication
worker; the compatibility sink only dispatches when the committed reducer says
publication was not enrolled.

## Effect adequacy and transaction faults

`effects-go.json` records committed `tag:<mailbox>` notifications and row/state
changes with the Go gateway audit flag enabled. **Parity: Go inbound delivery
still writes no mailbox audit row** (`deliver` never calls that writer), so the
missing-audit mutant is not applicable to this seam. The oracle plants and
rejects missing NOTIFY, double state bump, and wrong-recipient delivery by
replacing the actual database function, then restores its exact catalog
statement. A broken baseline or a transport error cannot count as a rejection.

`size-go.json` uses compact repeated-input stimuli: spilled truncation at 1 MiB
returns 451, and 150 MiB + 1 decoded byte returns 552. Smaller unexpected EOF is
accepted, as recorded separately. `tests/faults.rs` multiplexes the foundation
PostgreSQL wire-cut seam through real SMTP connections: cutting before COMMIT
leaves no delivery; cutting its acknowledgement leaves one delivery and state
bump. Both return SMTP 451, never a false success. The fault tests are native
wire-fault qualification, not additional Go recordings.

## Byte strings, greylisting and reducer replies

`bytes-go.json` preserves raw SMTP envelope bytes through the database boundary:
invalid UTF-8 senders tempfail after DATA, whereas MIME fields inside Go's JSON
parameters receive replacement runes. NUL JSON fields fail as Go does.
`greylist-go.json` compares fresh/matured triplets, repeated calls and whitelist
exemption through `greylist_check`, including its database rows. The runtime
supplies Go's feature setting through `with_greylisting` (the staged corpus
explicitly selects its fixture configuration).

`resolution-go.json` proves delivery ownership comes from envelope resolution,
rejecting lifecycle state and independent per-recipient transactions (a quota
failure does not cancel another recipient's successful commit). Go's per-user
sender lists are consulted only when the exact recipient has an alias; direct
mailbox and catch-all resolution skip them. This bug is mirrored.

`errors-go.json` drives actual PostgreSQL failures through SMTP for Go's full
SMTP-actionable code catalog, dual-use HINT slugs, and unknown errors. The shared
worker adapter retains typed SQLSTATE/HINT; `reducer_reply.rs` emits only Go's
fixed public lines. Neither diagnostic text nor a string pretending to contain
an SQLSTATE can become an SMTP business error. The fixture restores the
canonical reducer after every case, including a failed replay.

## Bounded recipient fanout

`fanout-go.json` records both recipient orders with fast/slow quota and
infrastructure failures. Delivery runs at most eight independent transactions
concurrently, waits for every recipient and preserves the first completed
failure for the single DATA reply, as Go does. A failure never cancels siblings.

## Mail authentication (#349)

`mail_auth::MailAuth` is injected with independent SPF/DKIM/DMARC/ARC feature
settings and a `Dns` resolver. `SystemDns` uses hickory with a five-second
lookup deadline. The staged server has no auth configuration until its owner
supplies it; #351 wires production toggles at the whole-listener swap.
`mail-auth` 0.9 is pinned to its ring backend (0.10/0.11 force a platform trust
store with CDLA-Permissive-2.0 outside this repository's allowlist, and later
releases removed ring),
with no RustCrypto RSA or AWS-LC dependency. Security-severity Go bugs are fixed
here, not mirrored: see [SECURITY.md](SECURITY.md) (divergences, mutants). The compiled-in `psl` list must be bumped periodically (SECURITY.md).

SPF runs on each accepted MAIL command, before its 250 reply. Its result follows
the transaction to every recipient. `spf-pass` and `spf-mechanisms` socket/effect
corpora cover qualifiers, CIDR, A/MX/PTR, includes/redirects, macros, negative DNS,
unknown mechanisms and the lookup budget (RFC 7208 semantics after the security
fixes; superseded Go verdicts are in `oracle/divergences.json`). Fixtures are injected through
resolver operations only; SMTP replies and effects come from real Go/Rust code.
The tagged recorder accepts `mail_auth` flags and typed `dns` fixture answers.

`dkim` socket/effect sessions and `dkim-vectors-go.json` additionally pin the
verified signing domain, authenticated canonical body length, and canonicalization
mode used by downstream iMIP. Verification is mail-auth's (all signatures, `x=` expiry, standard Ed25519).
Public `verify_dkim` returns parsed metadata on failure too; consumers MUST require
`result == "pass"` before treating the domain/length as authenticated. Fixed
fixture private keys are public test inputs only.

`dmarc` records reject/quarantine/monitor decisions, exact/organizational DNS
walk, relaxed-default alignment, deterministic pct sampling,
repetition and per-recipient report accounting. Aggregate report writes retain
Go's independent single-statement, best-effort upsert before delivery; rejection
or later storage failure does not roll that write back. The worker credential
owns this cross-recipient transport work. Quarantine raises the reducer spam
score to at least ten. A DMARC reject dominates generic sibling errors in the
single DATA reply.

`auth-observe.sql` observes only SMTP2 report domains, with generated day/id fields
excluded; `auth-cleanup.sql` removes only those fixture reports. The shared TCP
replay treats an omitted Go `omitempty` notification list as the empty list,
while continuing to reject every unexpected notification. Mailbox rows, tags,
state bumps and audit remain checked by the original full delivery snapshot.

ARC sealing verifies the incoming chain first (SECURITY.md); `arc*-go.json` stay as
recorded Go history, superseded cases listed in `oracle/divergences.json`.
`sign_outbound` and `outbound_data_frame` are the signing and DATA seams for #350
(queue claiming, outcomes and retries stay there).

The `test-smtp` container interop lane enables all four auth features: smtplib
plaintext/TLS and Postfix deliveries require SPF/DMARC pass; a fourth, freshly signed
message must pass DKIM-aligned DMARC despite SPF failure. Container/image names use
`gofree-smtp6-*`; tests remove them on failure/success.

The real UDP DNS adapter test additionally checks TXT chunk/record boundaries,
NXDOMAIN/NODATA vs SERVFAIL, and ascending MX preference (Go `net.LookupMX`).
`SystemDns::from_resolver` accepts a caller-owned hickory configuration for that
network seam and for later listener DNS wiring.

`oracle/auth-recording.json` binds 98 additional TCP sessions, 28 DKIM metadata
vectors and 8 signing vectors (5 fake-MTA receipts) to frozen Go runtime hashes
and the tagged recorder/fixtures. It supplements the unchanged SMTP1 receipt.

`arc-bounds` records Go's signed 64-bit instance wrap, ignored out-of-range
scanf values and accepted numeric prefixes, through SMTP and exact raw blobs.
The adapter retains those behaviors on every shipped 64-bit target.

## Outbound queue (#350)

Worker, transport, recording and handover contract: [outbound](src/outbound/DOX.md).

## Transport security and swap status (#351)

Outgoing DANE, MTA-STS and TLS-RPT session recording are native; see the
[outbound contract](src/outbound/DOX.md#transport-security-351) for resolver,
HTTPS/cache, feature reload, recordings and preserved Go defects.

## Submission and the listener swap (#501)

`submission.rs` ports Go's MSA: STARTTLS (files re-read per upgrade; AUTH is
advertised only on an active TLS session), AUTH PLAIN/LOGIN, the shared threat gate
(`setjoin-threat`, protocol `smtp`), the two `rate_limit_check` counters, app password then
bcrypt/SM3, conditional-access post-auth, per-user slots, the revocation registry
(moved to `setjoin-threat`, shared with IMAP), envelope-from ownership, and
`smtp_submission_send` in one worker transaction (a lost COMMIT is never acknowledged).
Everything runs on the worker credential like Go's `workerPool`. `oracle/submission-*`
holds 42 immutable frozen-Go sessions (recorder `submission_oracle_record_test.go`,
`gofree_record`; seed/cleanup/observe SQL beside it); `tests/submission.rs` replays
replies and DB effects, including the real Rust threat gate over feed/IP/lockout/rate/
policy/device cases. `reducer_reply::submission` keeps Go's split: a recognized class
keeps its reply, an unmapped error is `554 5.3.0 Failed to send message`.

Inbound `Server` gained `with_tls_files` (Go cipher/curve policy, files re-read per
handshake) and `with_flags` (greylisting, SPF/DKIM/DMARC/ARC and the delivery GUCs follow
live `feature_toggles` per session). Plain :25 has no STARTTLS, as in Go.

Gateway activation, GO_LISTENERS_OFF names (`smtp` covers :25 and the implicit-TLS
socket, `submission` covers :587) and the installer/upgrade/rollback contract live in
the gateway and mailserver DOX. STILL NOT QUALIFIED for default-ON: the enabled
inbound pipeline's remaining link-protect and iMIP qualification is tracked
in the inbound contract below. The original SMTP1 corpora retain their disabled
security-feature configuration.

Security fix (#501): an unknown, disabled or hash-less account at AUTH costs one verify of the
crypto profile's dummy hash (`with_dummy_hash`, from `setjoin_identity::login::dummy_hash`), where frozen
Go returned before any hash. Test `unknown_and_disabled_accounts_spend_a_password_hash`; mutant
`smtp-no-dummy-hash` (feature `oracle-mutants`) makes it fail. The gateway honours
`feature.smtp_inbound`/`feature.smtp_submission` at startup (disabled sockets accept and close) and an SMTP
configuration error is logged without stopping HTTPS; `smtp.env` is empty unless `SMTP_FRONT_ENABLED`.

Enabled inbound security port (#526): [stage and oracle contract](src/inbound/DOX.md).

## Recorded DKIM validity (#472)

Go signed its vectors with a 24 h/7 d `x=`. `oracle/refresh-dkim-validity.py` moves every real instant to 2100
(re-signing with `oracle/auth-fixture/rsa.pem` when it reproduces the recorded signature, so tampered ones stay
invalid) and updates the stored-blob keys; `tests/fixture_expiry.rs` fails when a recorded `x=` is within ten years.
In `dkim-go.json` only `x=` moved: every `b=` and `bh=` is Go's original, and `x=` is a signed tag, so those
signatures no longer verify and only the permerror (expired/invalid-signature) cases may rely on them; do not
treat them as a signature oracle (re-sign with the script to get one). `oracle/auth-recording.json` pins
(`sha256`, hand-pinned) were refreshed for this move (`dkim-go.json`, `dkim-requests.json`, and the `x=`-only
`dmarc-*` files) and for the later #526 edit of `listener_oracle_record_test.go` (checked: it only adds iMIP
notify capture behind `ImipNotify` and the `security-imip*`/`security-joint*` corpora, which no pinned
auth corpus uses, so what the auth recording captures is unchanged and re-pinning is correct); re-pin by hand after any
such change, checking every entry against the files.
Test files that share the fixed fixtures take a per-file `SERIAL` lock (do not re-enter it).
