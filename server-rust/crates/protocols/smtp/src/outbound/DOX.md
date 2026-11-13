# Outbound queue (#350)

The protocol crate owns the `outbound-mail` task: every ten seconds select the
oldest ten due pending/deferred rows, with twenty concurrent deliveries across
batches. This is a cross-tenant transport on `WorkerDatabase`, with subjects and
raw references derived only from trusted queue rows. No request credential,
request-selected mailbox, `SET ROLE`, SQL transaction emulation or second writer.
Go's worker has no singleton lock or atomic claim; preserve its selection and
separate autocommit statements. The gateway requires both
`RUST_WORKERS_ON=outbound-mail` and `GO_WORKERS_OFF=outbound-mail` before starting.

Each recipient resolves MX records and tries them in order. Successful sessions
remain open, keyed by MX host, and start reuse with RSET. A failed reuse falls
through to a fresh connection. Idle expiry is sixty seconds, maximum five idle
sessions per host. Command phases share a five-minute deadline, DATA has ten
minutes, connect has thirty seconds; shutdown cancels owned I/O and closes pools.

Raw references containing CR/LF are inline messages; other references are object
keys. Mark sending and read the current raw reference in one UPDATE RETURNING.
Use SMTP2's `mail_auth::sign_outbound` (fixed: active-schema key, complete
`DKIM-Signature:` field, see SECURITY.md) and `outbound_data_frame`. Submission already performs S/MIME work; queue
transport relays its bytes. Submission also owns `mail.sent` publication; the
frozen outbound worker emits no webhook, audit, mailbox state bump or tag notify.
No duplicate sent event belongs here. Inbound events keep using the gateway's
shared Dispatcher adapter.

A nullable message surrogate/received_at/mailbox link suppresses only the
best-effort per-recipient delivery-attempt log. Accepted/deferred/rejected/error
outcomes follow Go's SMTP-code mapping. Any accepted recipient marks the whole
queue item delivered, increments attempt_count once and writes one message-level
trace naming the first accepted recipient. All failures defer until attempt 20,
then bounce; even 5xx responses retry. Backoff is 1 minute, 15 from attempt 2,
240 from attempt 5, 1440 from attempt 10. Only the bounce writes a bounced trace.
These independent best-effort statements deliberately retain Go's failure cuts.

DANE/MTA-STS policy (#351) participates before pooled reuse and envelope I/O;
final inbound/submission listener activation remains staged for #351, and
there is no TCP proxy or back-to-Go execution path. Link-protect preparation must
run before DKIM and retain the original message on rewrite error, as Go does.

## Oracle

`outbound_oracle_record_test.go` (`gofree_record`) calls frozen `processBatch`,
waits for its real delivery goroutines, and records TCP fake-MTA commands/DATA
and database effects. It refuses an existing golden. `SMTP_OUTBOUND_CORPUS`
selects a fresh `<name>-requests.json` / `<name>-go.json` pair in `SMTP_ORACLE_DIR`.
`outbound-observe.sql` excludes generated IDs/timestamps, retains backoff minutes,
recipient rows, queue outcomes, traces and unchanged mailbox/audit state. Each
recording cleans only SMTP fixture identities and message IDs. Existing SMTP1/2
recordings remain immutable. Replay uses no Go runtime.

Run the `setjoin-smtp --test outbound` target serially with REQUIRE_DB=1 and the
assigned disposable DSNs. The complete protocol suite also runs the existing
`test-smtp` container clients. Record and replay only on the ticket's own database.

Fatal database-session faults retain Go's independent statement behavior:
`Statements` drops a failed session without retrying its statement, then opens a
new worker session for the next independent write. A failed sending transition
can therefore defer on a new connection; failed attempt logging does not prevent
a delivered update/trace; a failed delivered update can leave `sending` while
its independently committed trace exists. `outbound-db-fault` records all four
cuts by terminating only the fixture worker's own backend in temporary triggers.

The gateway `smtp_outbound::BlobSource` uses the native S3 client. It preserves
MinIO's missing-object XML message and requires a valid Last-Modified header on
successful object responses. `outbound-blobs` keeps the original malformed-200
and 404 recordings; `outbound-blobs-valid` proves opaque S/MIME bytes are relayed.
The fixture's explicit us-east-1 region bypasses bucket discovery; production
keeps the existing lazy discovery unless an explicit region is supplied.

Production wiring is `smtp_outbound::from_environment`: named handover, worker
DSN (request fallback), S3 and system DNS. It waits ten seconds before the first
pass and cancels/joins owned tasks on gateway shutdown. Native DANE/MTA-STS and
TLS-RPT services replace the retired unported-shape guard. Startup requires a
valid authoritative feature snapshot and preloads the persistent MTA-STS cache.
Each tick reloads the four transport features before any pooled delivery.
The listener itself remains staged for #351; no Go or TCP fallback is added.

`ForwardTransform` runs only for the trusted queue's forward_unwrap_links flag,
after blob loading and before signing. The gateway supplies its existing
current/retiring `TokenKeys` verifier, the shared strict MIME walk, scraper's
HTML5 parser, and context-specific escaping. Calendar/binary leaves and literal
HTML contexts keep redirects as Go does; decode/frame errors retain the original.
`outbound-preparation` checks real TCP DATA receipts for plain/HTML/CSS/srcset,
base64/QP, nested MIME, expiry/foreign/control refusals and retiring keys.

The backlog count includes future-due pending/deferred rows. Above 1000 it logs
`outbound queue backlog` and depth. Parity: Go's ignored polymorphic
`json_build_object(...,$1)` statement fails PostgreSQL type inference (42P18),
so it emits no admin:alert. `outbound-backlog` records that absence and warning;
the real gateway process test verifies the warning and normal ten-second tick.

`outbound-preparation-edge` retains invalid UTF-8 outside rewritten plain links,
unknown MIME contexts and malformed encodings. The replay reads DATA as bytes.
The worker observer rejects planted missing attempts, wrong recipient attribution,
double attempt increments and missing traces, with a green baseline for each.
Audit/notify/state mutants are inapplicable: this Go worker emits none of those
mailbox effects. Only committed-effect assertion failures qualify a mutant.
`outbound-recording.json` pins immutable corpora, frozen runtime and current test
fixtures/recorder hashes; historical input hashes retain their original commits.

## Transport security (#351)

`transport::TransportSecurity` consumes resolver answers with their AD/RCODE
metadata. `transport-dane-failure` records the real Go queue tick: lookup failure
defers before any socket opens, including before pooled reuse. The recorder's
optional `transport`, `tlsa` and `dns` inputs select static feature flags and raw
resolver answers; all delivery decisions still run frozen Go. `transport-dane` adds 30 recorded certificate/STARTTLS/pool cases: all usage
modes, certificate/SPKI selectors, exact/SHA-256/SHA-512 associations, rollover,
unsupported/empty associations, AD precedence, two-lookup answer changes and
admin-skip precedence. Security fix 2026-11-05 (#500, [SECURITY.md](../../SECURITY.md)):
`dane.rs` decides inside the handshake (DANE-EE skips PKIX; CA usages need the matching
CA in the verified chain) and a session is DANE-validated only after a record matched;
superseded recorded cases (`usage-0`, `second-lookup-failure`) are in
`oracle/divergences.json`, new ones in `oracle/secfix-transport.json`.
The outgoing transport is wired natively; listener activation remains staged.
Existing observations remain immutable. Owned interop resources use `gofree-smtp4-*`.

`SystemTlsa` uses hickory-net's UDP client to preserve AD/RCODE and every TLSA
record, including unsupported values and empty associations. Go uses the first
`/etc/resolv.conf` nameserver (fallback 1.1.1.1:53), one five-second UDP exchange,
RD and EDNS DO with a 1232-byte payload; no new DNSSEC validation or TCP retry is
invented. `transport_dns` verifies the actual UDP request and returned answers.
Hickory owns random IDs/ports and response-source/question validation.

`transport-mta-cache` records twelve queue ticks with persisted policies. Cache
load tolerates malformed rows and preserves Go's duration overflow behavior,
case-sensitive domain keys, case-insensitive exact MX comparison (including
its lack of wildcard matching), unknown-mode handling and expired-policy miss.
Enforce policy participates before connecting/reusing and combines with the
admin policy; cached version strings are not revalidated by Go. This cache
uses the worker credential against global transport metadata, with no invented
mailbox/auth context. `transport-mta-cache-edge` adds four cases for Go JSON
case aliases, null scalar/slice handling and typed decoding errors.

MTA-STS HTTPS inputs: `transport-mta-fetch` and `transport-mta-errors` record 22
queue ticks, comparing policy GET targets, SMTP wire, policy persistence and
all original queue/effect observers. Only non-`none` valid fetched policies are
cached; failed persistence still leaves the in-process entry. Go accepts any
TXT containing a final nonempty `id=`, unknown modes, partial max_age integers
and empty MX entries; those behaviors and the 64 KiB body limit are preserved.
`PolicyFetch` is an HTTP I/O seam, not a policy verdict. The gateway supplies
the shared SSRF-guarded client; direct fixtures return the recorded raw body.

Record HTTP cases in the CI image with `SMTP_OUTBOUND_CORPUS=<fresh-name>` and
`python3 server-rust/crates/protocols/smtp/oracle/record-transport.py` (from any
cwd). It uses Go's overlay mechanism to substitute only the HTTP client factory
with a build-tagged recording hook, retaining the frozen runtime source hashes.
The TLS fake changes only dial/trust configuration; Go still constructs the URL,
fetches, checks status, limits the body, parses, caches and persists. Existing
goldens refuse overwrite. Custom teardown statements must be idempotent: the
recorder invokes both explicit per-case teardown and a final cleanup trap.

`transport-mta-gzip` records Go's transparent HTTP gzip decoding before policy
parsing. The gateway `HttpPolicyFetch` uses the shared public-address-only HTTPS
client, disables proxy/redirects, sets a ten-second deadline and bounds decoded
output to 65536 bytes, including compression bombs. Its real TLS peer test
compares plaintext/gzip bodies, truncation, malformed gzip, HTTP failures and
production private-target/scheme rejection.

`transport-report` and `transport-report-matrix` record fourteen TLS-RPT cases: URI
discovery, repeated aggregation, every delivered MX attempt, failures, disabled
reporting and skipped MTA-STS MXes. Writes remain independent best-effort worker
statements; existing rows retain their first failure/URI on conflict. Go's error
substring classification is preserved, including certificate mismatch reported
as expired. The active schema lacks `tls_rpt_sessions`, so normal inserts still
fail silently as in Go. Tests create/drop an archived-shape compatibility table
only on their disposable DB; the no-table case retains active-schema behavior.
Report submission/scheduling already belongs to #323; no second worker is added.

`with_live_features` reloads the four flags from the authoritative registry state
and rows. Invalid/missing registry state rejects production worker startup. A
later reload error retains Go's conservative polarity: DNSSEC/DANE ON, MTA-STS
and TLS-RPT OFF. `transport-live` uses Go's real `toggle.New/Reload`, two ticks
and a new queue item to prove a feature enable cannot reuse an idle plaintext
connection. `between_ticks_sql` runs only after its matching tick. Static
`transport` flags are replaced by DB flags when `transport_from_db` is true.

## Listener activation status

The whole SMTP socket swap is incomplete. #420 owns the unavailable shared
protocol threat interceptor. SMTP submission and the enabled inbound security
pipeline still need their Rust adapters and socket/effect qualification. This
slice does not turn Go's listener off or claim the missing default-ON swap.
The already-qualified inbound/auth and outgoing transport tests remain runnable
without Go; no new proxy, fallback or return-to-Go flag is introduced.
