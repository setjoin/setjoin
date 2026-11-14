# LDAP listener (#342)

`setjoin-ldap` owns the inbound read-only GAL protocol, separate from the F02
outbound LDAP sync client. `ldap3_proto` 0.9 is an unmodified MPL-2.0 codec;
transport, authentication, STARTTLS, admission and directory authorization live
in this crate. Protocols run inside the gateway process, never behind a TCP proxy.

The listener is under construction. Production listener authority remains in Go
until the recorded listener oracle, interop and shared threat interceptor (#420)
are qualified. The shared provider is `setjoin-threat` (#420); production authentication must
use it rather than an allow-all provider.

## Oracle

`oracle/requests.json` contains authored wire requests. The build-tagged recorder
`mailserver/internal/ldap/listener_oracle_record_test.go` starts the frozen Go
listener and records actual TCP/TLS BER responses into `oracle/go-sessions.json`.
Only this adapter is new Go; production Go remains frozen. Record against a fresh
schema in the task's own disposable DB with `REQUIRE_DB=1`,
`LDAP_ORACLE_DIR=<absolute oracle path>` and `go test -tags gofree_record
./internal/ldap -run '^TestRecordLDAPListener$' -count=1` inside the CI image.
The fixed fixture IDs are deliberately divergent. The corpus uses only disposable
credentials. Goldens are immutable after their first successful recording.

Rust tests replay at the listener socket, byte for byte. Use the assigned DSNs,
`REQUIRE_DB=1`, `cargo test --locked -p setjoin-ldap -- --test-threads=1`.
No Go upstream participates in replay.

## Qualified initial slices

Implicit TLS uses rustls/ring with a bounded handshake; plaintext credentials are
rejected. The staged database authenticator verifies bcrypt and rejects guest
principals. It is not production admission until its activation owner wires the now-available shared threat/password path. People search/Compare resolve the bound user to its
primary mailbox before calling `directory_visible_users`; address matching uses
that function's canonical aliases and UPNs. Root/unknown-base handling, attribute
order, type-only searches and size caps match recorded Go bytes. Failed rebind clears the old principal (#420 owner-approved security divergence).

The generic Extended response is a universal BER SEQUENCE in frozen Go. A small
encoder adapter changes only that serialization tag using `ldap3_lber`; it does
not modify the MPL dependency. Go registers no extended-operation OID, so its
STARTTLS handler is unreachable and a STARTTLS request gets this generic rejection.

The extended corpus adds nonempty Groups/Resources/Contacts, private-contact
exclusion, department paths, filters, attribute selection, DN bind and configured
STARTTLS. Record with `LDAP_ORACLE_VARIANT=extended-`; `oracle/cases.py` authors
only requests and never generates responses. The recorder uses `seed-extra.sql`
and reuses the original password hash. Standard paged-results cookies are ignored
by Go's context-tagged ASN.1 cookie field; the size is honored, no response control
is emitted. Mixed-case `Cn=` extraction also preserves the Go failure.

The third corpus (`LDAP_ORACLE_VARIANT=edges-`) records unsupported filters,
read-only writes, empty extended requests, SM3 and legacy password upgrades.
These cases also compare normalized hash-upgrade effects and auth-event counts.
Go passes `RemoteAddr.String()` (host:port) to the INET auth-log column, so normal
LDAP success/failure events are silently dropped; the corpus records zero rows.
The staged authenticator uses the shared authz format verifier and pg's bounded,
identity-and-old-hash CAS. It currently supports the standard upgrade profile;
production profile selection remains with the shared admission provider.

`tests/interop.rs` uses the existing `mailserver/deploy/docker/test-ldap` image
pinned as `setjoin-interop-ldap:local` (`scripts/build-interop-images.sh`, `.github/ci/images.lock`),
running OpenLDAP `ldapsearch` clients with CA verification. The test never builds or removes images
(#141). Run it with the assigned DSNs and `REQUIRE_DB=1`. Every client
container has a task prefix, a 15-second deadline and `--rm`. It covers canonical
alias lookup, hidden-user exclusion and failed bind.

Go's LDAP package tests leak five fixture users because their cleanup ignores
primary-mailbox FK failures. Run the Go suite before reloading the disposable
schema, then run Rust replays. Never run Go and Rust GAL suites simultaneously.

## Session admission and cancellation

The server accepts an already-bound listener. Connection cap defaults to 100
(0 means unlimited); operations default to 16 per connection and 128 globally.
Reader, writer and bounded in-flight futures are separate; a single extra frame
may wait before dispatch. Admission permits survive through bounded response
writes, so nonreading peers cannot free their budget by queueing responses.
Oversized BER declarations are refused before payload reads; writes expire after
30 seconds. Listener shutdown joins/aborts only its own connection tasks.
Disconnect drops outstanding read futures and pg explicitly cancels their SQL.

The no-op Abandon route and its grant leak are frozen Go bugs: primitive 0x50
consumes a grant, while Go mistakenly exempts 0x70, and the registered no-op
bypasses the dependency's cancellation fallback. The immutable
`go-abandon-admission.json` records the stall after sixteen requests. This is
corrected under the owner-approved #420 security divergence. RFC 3909 Cancel uses Go's built-in extended-operation
fallback instead: malformed/no-target results have their own recorded corpus;
active operations are tracked per connection and Cancel drops their query future.

The gateway does not instantiate this listener yet. Shared threat admission
is qualified in #420; production crypto-profile wiring, socket activation/Go
listener disable and TLS handover remain with the LDAP activation owner.


## Current qualification and remaining handover

The four immutable corpora contain 73 sessions / 130 request frames; the separate
Abandon observation records sixteen no-response requests and a stalled final
bind. The crate's socket tests cover all cases, plus real blocked-query
cancellation, pool-wide admission and OpenLDAP clients. Standard password formats
also replay the shared Go vectors. The owning pg bounds/scoped transaction tests
cover the dirty-lease cancellation change.

This is a staged listener implementation, not a completed authority transfer.
The #420 shared provider is now consumed and replayed through LDAP. The
standalone LDAP production listener remains Go-owned until its activation owner
qualifies socket and TLS handover; this task changes no LDAP deployment default.


## Shared threat admission and security divergences (#420)

`Server::with_threat_gate` consumes the shared `setjoin-threat` protocol seam.
The socket supplies its canonical peer IP; Bind normalizes the DN, applies feed,
IP, country, lockout/rate and CA admission, then records the verified result.
`threat-go-sessions.json` and the `threat-policy-` supplement are frozen Go TCP/TLS
observations (recorder variant inputs in the oracle directory). LDAP has no
production socket swap here; its activation remains with the LDAP listener owner.

Four security fixes are covered (owner decision 2026-11-05, review 2026-11-06):
clear the previous principal before every Bind; perform user-scoped post-auth CA
before binding; release Abandon's no-op admission permit; serialize Bind as a
connection-wide barrier. Original Go goldens are
unchanged; `oracle/divergences.json` names the exact secure wire observations and
owner decision. `oracle-mutants` is an explicit test-only build feature restoring
these bugs. `scripts/test-authrt-ldap-mutants.py` requires all four socket tests
to reject that build, then reruns the ordinary secure build and cleans fixtures.
Run the listener target with strict DSNs, one test thread; no test is skipped.

Review hardening (2026-11-06): `ThreatPolicy::Disabled` is the default unwired
state; `serve` refuses it before accepting any connection. Use
`with_threat_gate` or explicit `ThreatPolicy::Enforced` for activation. Legacy
oracle fixtures explicitly inject a test-only gate; production has no allow-all
provider. Bind clears the previous principal as soon as decoded, drains prior
operations and completes before dispatching later operations. The reader remains
active for disconnect/Unbind cancellation. This also clears identity
when global admission returns Busy. The pipelined valid/failed Bind socket test
and concurrent-dispatch mutant cover delayed credential completion.
