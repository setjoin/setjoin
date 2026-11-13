# Mailserver-only F21 oracle (#494)

`setjoin-gateway --test identity_self_service` records actual covered frozen
mailserver handlers through the front door, then replays the same requests with
Go upstreams unset and asserts zero F21 Go hops. The domain/transaction map is
[SELF_SERVICE.md](../../../crates/domains/identity/SELF_SERVICE.md).

Run with the assigned disposable database, `REQUIRE_DB=1`, and
`--test-threads=1`. Recording additionally requires `GOFREE_RECORD_GO_BINARY`,
`GOFREE_GO_SOURCE` and optionally `GOFREE_GO_COVERAGE_DIR`. The existing Go
process helper names and registers every owned container/key through
`GOFREE_RESOURCE_PREFIX` and `GOFREE_RESOURCE_LEDGER`. Recording exclusively
creates files; never rerun an already recorded case in recording mode.

Each case creates two accounts with different user/mailbox IDs. The observation
contains the actual request, byte-preserving response, owned database rows,
audit rows and delivered `config_changed`, `state_change`, and `critical_events`
notifications. Generated IDs are placeholders. Fixed seed timestamps remain
literal. Raw Content-Length is checked against the received body before its
numeric value is canonicalized for comparison (generated IDs change width);
recorded headers are retained unchanged. Problem bodies use the shared encoder.

Read-only handlers may ignore invalid unused input and caller-supplied identity
fields: the Go recordings retain that 200 result and demonstrate that only the
authenticated owner's rows are visible. A status mutant is served on the wire
and must fail specifically at `/response/status`.

`catalog.py` appends only this ticket's qualified suites and updates their
existing registrations, preserving other routes and supplemental oracles.

`goldens/` retains the complete original Go capture. `qualified/` is its
exclusive-create metadata projection: `request.path` is the registration pattern
required by the adequacy schema, and `request.wire_path` retains the original
normalized URI (including query). Response/effect/audit/notify data is unchanged.
Replay verifies every projection against its immutable source before comparing
Rust. `catalog.py` refuses an existing projection that differs from its source.
The qualification schema represents notifications as a list of channel/payload
pairs; projections flatten the original per-channel observations in sorted
channel order, retaining delivery order within each channel.

App-password creation verifies every returned credential's prefix/entropy shape,
owned SHA-256 row and request-bounded creation time before masking. Repeated POSTs
really run twice and must commit two credentials. Actor-bound infrastructure
receipts are observed separately from frozen business effects. The two wire
cuts intercept actual PostgreSQL COMMIT before execution and after its server
acknowledgement: both withhold the token and return503/operation ID; row state
and the same actor's receipt prove absent versus committed, and the other actor
cannot match that receipt. The database-error case temporarily revokes only the
app role's INSERT or UPDATE grant (create or revoke) on the assigned database's app_passwords table and
restores its verified baseline grant on every normal/error path.

DLP records clean/violating drafts, a foreign-domain policy, reducer failure and
feature OFF before decode. Every advisory separately compares the authenticated
accounts' violation rows before/after, in addition to HTTP/audit/notify goldens.

Read-receipt snapshots include owned message flags, mailbox state, notification
policy, logical read receipts and complete queued MDNs. Operational surrogate
receipt/queue IDs are omitted; logical message/recipient keys and row counts
remain. The returned MDN ID must name the owned message and contain a canonical,
request-bounded PostgreSQL epoch. Queue and receipt timestamps must match it;
sender, recipients, original ID and MIME date must match the acknowledged MDN.
Only then are that ID's clock and corresponding RFC date replaced. Repeat
really sends twice and compares the already-sent response and unchanged queue.

Webhook creation checks the64-hex one-time secret by opening secret_enc using
the configured Go-compatible column codec. The persisted owner, v1 key id, NULL
legacy plaintext cell and request-bounded created/updated clock must match before
the ciphertext/secret placeholders are introduced. The full owned subscription
rows remain in the effect snapshots. Missing/nil codec is unreachable through
Go's shipped constructor plus BaseConfig.Validate (nonempty JWT secret); the
seal failure branch otherwise needs unavailable system entropy. The shared
user-command COMMIT wire-cut cases cover this one-statement transaction shape.

S/MIME fixture certificates live in fixtures/: a pre-existing repository RSA
oracle key plus a test-only P-256 key, signed with cryptography. Validity dates
are fixed and remain literal in snapshots. generate.py refuses replacement;
existing HTTP captures depend on these exact bytes. The private EC fixture is
never deployment material.

Own-key uploads validate pgp_sym_decrypt against the exact submitted test key
before replacing the ciphertext. They check actor ownership, first/default
selection, request-bounded creation and preserved upsert clocks. Re-upload must
refresh its PGP envelope without duplicating the label. Oversized multipart
requests are sent in full; their request body is represented by byte count and
SHA-256 to keep the immutable corpus small. The returned HTTP/effect observation
is unchanged. Query decoding uses the pinned percent-encoding crate; cargo-deny
checks the complete workspace dependency graph.

Own-delete replay includes both SQL privileges (DELETE and survivor UPDATE),
foreign/missing/repeated identifiers, no-survivor and non-default deletion.
Actual before/after COMMIT cuts compare Go's absent/committed row effects and
the actor-bound receipt; both return an uncertain503, never deleted success.
The additional invalid-UTF8 upload sends raw bytes (size/SHA256 descriptor) and
retains Go's store500 without adding a row.

The [closing census](CLOSING-AUDIT.md) distinguishes this ticket's 25 assigned
registrations from seven other F21 owners. All 25 assigned registrations are qualified native/ON with zero assigned gaps.

Default selection and recipient import/deletion validate owned row effects,
foreign preservation, fixed phase errors and acknowledgement receipts. Recipient
upsert checks exact PEM/fingerprint/source/label, preserved first_seen and a
request-bounded last_seen before masking clocks. Go's certificate/key mismatch
acceptance and ignored deferred list errors remain frozen behavior.

Migration start uses the existing actual worker, waits for terminal state and
native task exit, validates actor/source/strategy/request-bounded creation and
opens any retained envelope before masking it. Repeated admission waits for the
first job to finish and commits two actor-bound receipts. No-primary mutation
is unrepresentable under BZ014; that case asserts rejection and retains the
original primary, recording this setup constraint explicitly. No-mailbox setup
detaches ownership and clears is_primary atomically. A native-only revoked
mailbox-less HTTP denial protects the narrow identity-admission exception.

The first history-delete capture includes Go's startup recovery of a pre-seeded
paused job. Native replay invokes the existing migration_recover_stuck seam and
asserts only that known fixture was recovered. New preservation cases seed paused
state after startup. Original Go captures are never rewritten to adjust setup.

Resume fixtures seed paused actor/foreign jobs after Go startup recovery; native
replay waits for the existing worker task to exit before comparing rows. A second
resume after completion is404. Invalid unused bodies are accepted202 (Go parity).
The handler500 requires a concurrent start between its process-local state lookup
and StartJob; that race is outside this serial HTTP fixture. Runner duplicate-start
checks remain authoritative; no serial client input reaches that branch.

Cancel fixtures hold a real ICS worker at S3 GET, then compare its cancelled row
and foreign preservation after task exit. The stale capture includes Go startup
recovery of B between the two seed inserts; native setup invokes the existing
recovery reducer before A is inserted and asserts only B was recovered. Captures
remain immutable. Probe status mutation targets the concrete request path so
helper migration-start requests keep their real status.

New migration captures fence startup recovery with one paused sentinel belonging
to the fixture, wait for its failed state, and delete it before seeding active
jobs. A health response alone does not establish that recovery has finished.
Native replay needs no sentinel. Pause preserves Go's ignored ICS pause token
and eventual completion, plus real foreign/stale/fault/retry projections.

Upload observations add signed PUT attempts and committed object maps to the
before/after effects. The fake S3 boundary independently verifies SigV4 (including
Go streaming chunks) before canonicalizing client-specific headers and clocks.
Keys, lengths and SHA256 remain exact. HTTP403 on ICS stops before VCF;403 on VCF
retains only ICS. Go200 sizes are mirrored. Empty files are accepted without PUT.
The actual64 MiB+ multipart body is represented by byte count/SHA256 to avoid
normalizing or checking in the huge request; rejection must leave storage empty.

IMAP testing records a real LOGIN/LIST/LOGOUT against an owned internal Docker
bridge with a public-shaped address. Replay injects the existing DNS-policy dialer
and maps the identical public input to a loopback server; it needs no Go or bridge.
Private inputs would reach the scripted server if policy were bypassed, so their
recorded false result discriminates an unsafe dial. The connector regression also
rejects mixed public/private DNS answers before the first TCP attempt. All private
exceptions are administrator-owned; caller hosts/CIDRs are rejected at ingress.

The exact migration registrations opt into the existing mailbox-less user proof;
Go status/history/control/upload/connection cases and native revoked denial pin
user currency without inventing a mailbox or weakening other surfaces.

## Security divergences (#547)

`divergences.json` pins the Go baselines whose behaviour changed by an owner-approved
security fix (2026-11-05): an IMAP test-connection or IMAP migration start with `tls_mode`
`none` is refused (400, no dial, no job). The reviewed expectations are under `security/`;
the replay compares a pinned baseline with its expectation and the sha256 pin fails if the Go
capture changes. `SECFIX3_WRITE_SECURITY=1` regenerates them and always fails the run.

Because the plaintext cases above no longer reach the dial, `migration-test-imap-tls-*`
(loopback, link-local, ipv6-loopback, no-host, cross-tenant, no-mailbox) were recorded from the
frozen Go binary with `tls_mode` `tls`: the SSRF guard and ingress/identity cases stay covered
(Go fails them before or at the TLS handshake, `success:false`). Success and bad-password with TLS
would need a TLS fake IMAP the frozen Go container trusts; not recorded.
