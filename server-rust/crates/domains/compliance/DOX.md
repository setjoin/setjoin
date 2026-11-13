# Compliance (F04, #289–#291)

`setjoin-compliance` depends only on foundation crates. Gateway adapters are
`bins/gateway/src/compliance.rs` (mail), `retention_audit.rs` (retention/audit)
and `chat_compliance.rs` (chat). Frozen Go is authoritative (ARCH-029/030).

## Slice ownership

All 39 F04 registrations have exactly one slice, checked through the public
inventory by `python3 server-rust/tests/conformance/compliance/slice_map.py`:

- `ediscovery` (#289): 12 `/admin/ediscovery*` routes (case CRUD/close/associate,
  search start/read, litigation hold/release, case-bound MBOX/PST export).
- `retention-audit` (#290): 14 audit, retention and content-search routes.
- `chat-compliance` (#291): 13 `/admin/chat-*` routes.

All 39 F04 routes (12 eDiscovery, 14 retention/audit and 13 chat compliance)
are ON by default after HTTP/effect, mutant and commit-loss qualification. Slices append
modules to this crate and disjoint adapter registrations; never add family
crate dependencies.

## Authorization

eDiscovery is an organization-wide admin surface. Go rejects every domain-scoped
principal with an audited 403 before handler execution. Case reads use the Mail
console permission set, content reads/export use `mail.export`, writes use
`compliance.write`. The verified actor supplies ownership/audit identity. Message
operations explicitly use the worker credential, as frozen Go does, never a
request-selected credential or SET ROLE. Cases use the request credential.

## eDiscovery case reads

List and detail preserve Go struct field order, HTML escaping, RFC3339 seconds,
optional closed/description fields and search counts. A NULL description makes
ListCases return 500 (pgx retains the scan error in Rows.Err); GetCase returns
404. Detail's child-search query is best-effort. These are parity behaviors,
not accepted divergences. Case listing ignores query input.

## eDiscovery case writes and message holds

CreateCase, UpdateCase, DeleteCase and AssociateSearch are each Go's single
statement, with no audit/state/notify. Rust binds the verified actor in its
statement and uses the foundation receipt transaction. CloseCase calls
`rust_compliance_case_close`; hold/release call `rust_compliance_message_hold`
on the explicit worker credential. Those reducers combine the data and audit
that Go commits separately, preserving Go's best-effort audit behavior. Hold
also preserves Go's swallowed UPDATE errors and unconditional audit of empty or
repeated requests. No JMAP state, journal entry or notification is added.
Unknown commit outcomes return 503 with `X-Operation-ID`, per the foundation rail.

Body decoding uses the gateway's Go-compatible first-value/field-occurrence
helpers: folded keys, trailing input ignored, string null as a no-op, pointer
null as a reset, null integer-slice elements as zero. Case edits may target a
closed case; search association may target a closed case. Go permits both.

## Search results

`GET /admin/ediscovery/{id}` uses `mail.export` and the worker pool. It renders
Go's search struct and its nullable results list; content comes only from the
persisted result binding of a case-bound completed search, capped at 500 rows.
Absent optional query keys make Go's Scan fail (404), even when the search row
exists. Stored mailbox IDs follow Go's float64-to-int64 conversion. Child row
iteration/scan failures retain or skip rows exactly as frozen Go does.

## Search jobs and KQL

SearchStart commits its one INSERT before launching a process-local, bounded
2-hour worker job. The request's routing decision chooses its writer; there is
no shared cron/singleton to disable through GO_WORKERS_OFF. Running/failed
transitions are individual Go statements with creator predicates. Completion
calls `rust_compliance_search_complete` for count, persisted result replacement
and complete status atomically. Terms use bound text-array parameters; only
allowlisted parser operators/columns enter SQL. Go's 4096-character, 32-depth,
128-term limits and parser/SQL quirks are retained. Error quoting uses generated
Go 1.26.6 Unicode 15 printable ranges (see the independent Go probe in the corpus).
Quoted NUL made frozen Go's parser loop without progress; `kql::parse` refuses any NUL
("query contains a NUL character", a 400 on both routes): owner-approved security fix 2026-11-05, #436.

## Export

Export requires `mail.export`, an active case and completed persisted coverage
for every deduplicated positive numeric ID. `rust_compliance_export_authorize`
commits its mandatory audit before any custody or object byte; audit failure
returns 500 with no outbound object request. Organization-wide worker reads
then stream message metadata and signed S3 bytes through a bounded channel.
Client disconnect cancels pending reads; Go's 2 KiB HTTP buffering boundary and
successfully copied prefixes on object errors are preserved. HEAD drains object
reads even though Hyper discards its body. Large JSON/HEAD responses hide the
known buffer length to preserve Go's framing. Original query bytes survive into
the custody hash and ID header; audit JSON uses Go's per-byte UTF-8 replacement,
and malformed/semicolon query pairs are dropped as Go does. Custody hashes use
the audited SHA-256 crate over the original comma-separated IDs. Invalid numeric
IDs are ignored by Go, including the empty numeric set; duplicate custody counts
retain the original request count. PST remains an audited 501 as frozen Go does.

## Oracle

`cargo test --locked -p setjoin-gateway --test compliance_recorded -- --test-threads=1`
needs the disposable schema and documented owner/app/direct DSNs with
`REQUIRE_DB=1`. There are 167 immutable frozen-Go HTTP/effect cases across all
12 routes plus seven HEAD recordings, 12 route-status mutants, three family mutants (audit, state and domain
scope), eight before/after COMMIT wire faults, both kill switches and deferred
request forwarding. Every native replay has no Go upstream, uses bundled ON
entries, and asserts zero F04 proxy attempts. Recordings retain response bytes,
all headers, persisted rows, mailbox state, audit, notifications and signed S3
calls. No recorded notification exists, so no-notify is inapplicable.

SQL seam: `mailserver/sql/tests/rust_compliance.pg` (27 checks). WORM hold/release
remains owned by F04 Compliance #289 and forwards to Go pending its separate
S3 SetLegalHold adapter and eDiscovery effect oracle. Platform #301 and Blobs
#419 qualify F16 PutObjectRetention; they do not complete this legal-hold path. Full corpus and recording instructions: `tests/conformance/compliance/CASES.md`.

## Chat compliance (#291)

`src/chat.rs` and gateway `src/chat_compliance.rs` own this slice without a
family dependency. The HTTP/effect oracle is
[chat-compliance/CASES.md](../../../tests/conformance/chat-compliance/CASES.md).
These are organization-wide consoles: view/manage grants admit metadata reads;
content access requires the separate `chat.ediscovery` permission. Resolve live
admin grants before the feature gate, preserving the audited middleware denial.
The slice's inventory is ON after the qualification below.
Per-channel F12 administration stays in the Chat crate.

Policy/case reads use the request pool; hold, preview and overview reads use the
explicit worker pool, matching Go's RLS authority. Hold browsing adds a separate
best-effort core audit. Preview calls the existing purge reducer with dry-run
true and never destroys content. JSON keeps Go struct/map order, HTML escaping,
raw JSONB order and timestamp shapes.

Policy create/update/delete call `rust_compliance_chat_policy` on the request
credential. The worker-owned DEFINER function performs Go's organization-wide
exposure read, fences the authenticated manage grant in each mutation, and
contains core audit failures in a savepoint. Preserve the seven-day re-arm,
`confirm=DESTROY` and Go's no-op pending-policy re-arm quirk. No state bump or
notification is added. SQL seam: `mailserver/sql/tests/rust_compliance_chat.pg`.
Grace cases preserve deadline change bits and remaining grace hours before
normalizing timestamps, so an omitted or unnecessary re-arm remains observable.

Case-bound holds call `rust_compliance_chat_command`, which invokes the canonical
set/release reducer with the authenticated manage-grant predicate and then attempts
Go's best-effort global audit. Mandatory channel-chain errors roll everything back.
Custodian placement checks `admin_can_reach`; channel placement remains org-wide.
Release keeps Go's empty-reason and closed-case allowances, repeat refusal, and
last-coverage audit rule. The 14 placement and 12 release HTTP/effect recordings
observe all hold/coverage rows and independently verify the chain before masking
its digests. SQL seam: `mailserver/sql/tests/rust_compliance_chat_holds.pg`.

Chat search and channel read require the separate `chat.ediscovery` grant, never
manage alone. The oversight wrapper calls canonical `chat_ediscovery_search/read`
and best-effort core audit in one request-owned transaction on the explicit worker
credential. Persisted search/read actors come only from auth; DTOs build an
allowlisted query. Go's Han property comes from `setjoin_contracts::han`. Raw JSONB
field order and arbitrarily large numeric tokens survive response compaction.
Date validation retains Go's hour24/minute60 offset acceptance while sending the
unchanged bound to PostgreSQL (including its subsequent generic500).
The matcher decodes resource segments and preserves Go StripPrefix's encoded-API
mount404. The HTTP corpus covers cursors/limits, nonmembers, SOD, decoded paths,
canonical/optional audit faults and the1001-digit stored-payload regression.

Chat ZIP export first commits the live `chat.ediscovery`-gated canonical
`chat_ediscovery_export_begin` and best-effort core audit through the oversight
reducer. `chat_export::Snapshot` then owns one worker-credential REPEATABLE READ
READ ONLY connection; counts, content and manifest provenance share that
snapshot. Row streams are bounded and cancellation drops the connection. ZIP
peripheral output starts only after a known committed command outcome; Unknown
returns the operation handle without object reads or success bytes.

Qualification is173 ordinary Go recordings plus13 per-route status mutants,
16 real COMMIT cuts with authenticated receipt resolution, both switches and
shared-auth deferral byte preservation. All13 chat inventory routes are ON;
the retention/audit slice (#290) is also ON in the integrated family.
ZIP records independently verify CRC/content SHA and committed chain pins;
normalization and HEAD alias coverage are specified in the corpus CASES.md.
SQL seams cover policy9 and oversight24 assertions, including content grant
revocation and zero actors. No worker ownership changes in this slice.

## Retention and audit (#290)

`retention.rs` and gateway `retention_audit.rs` own the second slice, including
`/admin/content-search/*`. Qualification lives in
`tests/conformance/retention-audit/CASES.md` and `tests/retention_audit_recorded.rs`.
Policy reads preserve Go's nullable-description scan failure and omit empty
strings. Creation only accepts delete/hold; updates additionally accept the
schema's archive action. A null patch field is ignored, including retainDays.
Verified live authority supplies the domain predicate; global admins may target
any domain, and domain admins see global policies but cannot mutate them.
The three `rust_compliance_retention_*` reducers commit Go's returning-row audit
and policy change together. Update locks the scoped pre-image; mutation repeats
the ownership predicate. Audit failure rolls the change back. Scoped creation
uses the authenticated domain, never the requested identity. No extra JMAP state,
journal or notification is added.

Log retention get/set/prune uses the Mail console and compliance.write gates.
Frozen Go allows authorized domain-scoped principals on this global surface;
permission-denial and authorized domain-scope recordings distinguish those cases.
Missing, non-integer or non-positive settings read as null. Setting replaces all
four values, treating omitted/null/non-positive values as zero. The four ordered
upserts run in `rust_compliance_log_retention_set`; table triggers publish four
`config_changed` events in that transaction. Prune calls Go's existing
`prune_log_tables`, preserving the WORM audit-table exclusion and returned counts.
`rust_compliance_log_prune` wraps the existing prune reducer: Go ignores
Rows.Err, so an execution failure rolls back all pruning yet returns 200 with an
empty array. This bug is recorded in `log_prune-query-failure.json`, not fixed.

### Global audit console

`audit.rs` owns list, CSV, chain verification and audit policy. Reads require
`audit.read`; CSV and policy writes require `audit.export`. Domain-scoped principals are refused by Go’s central global-only permission
guard, with a distinct audited reason before handler execution. Policy PUT applies the live header reason
gate before decoding, always requires its body reason, records the verified actor,
and preserves Go's best-effort audit in `rust_compliance_audit_policy_set`.
Missing header denials commit their own best-effort sensitive-action audit.

List preserves Go struct order, omitted fields, raw JSON image key order and
nullable empty lists. CSV uses the foundation Go format, ignores filters and stops
at the first Scan error: pgx closes its iterator even though Go writes continue.
A newest NULL target_type therefore produces a header-only CSV (a recorded Go
bug); the rows case also proves formula escaping and multiline output. Chain
verification calls the existing verifier through a scoped read so trusted audit
keys apply; the gateway parses optional ID bounds exactly as Go does.

### Content search and purge

`content.rs` uses the explicit worker credential after compliance.write and an
org-wide-only gate. Legacy FTS/from/date/mailbox filters and the existing KQL
compiler retain Go behavior; KQL replaces the legacy filters. Arguments remain
bound text-array values, including integer-exact mailbox IDs. The 64 KiB body cap,
first JSON value, folded keys and null slice elements match Go. A NUL-bearing KQL
request is a local 400 (#436), as for eDiscovery; no golden claims that shape.
Go ignores Rows.Err, including date/data binding errors after pgx's statement
description, and returns empty successful results. Rust preserves that behavior
for data errors even when its unnamed array plan fails before RowDescription.

Purge calls the same `content_purge_messages` reducer as Go, through the foundation
receipt transaction. Actor ID/email come from the verified token. It preserves
held messages/mailboxes, duplicate/missing counts, audit and rollback on any
non-hold error, including failures after earlier deletes. Reason length counts
UTF-8 bytes as Go does. Message/tag rows and counters, both mailboxes' JMAP states,
journal and mailbox audit are recorded. Go changes tag counters but adds no JMAP
state bump, journal or notification; Rust adds none. Case/ownership IDs supplied
in the body never select actor authority.

### Retention/audit qualification

All 14 second-slice entries are bundled ON. Native replay requires those exact
bundled decisions and no Go upstream; every local case checks F04 proxy count zero.
The corpus is 150 immutable Go observations (149 catalog cases plus a redundant
empty-GET smoke case), with row projections derived only from those observations.
Qualification has 14 route status mutants, four database/authority effect mutants,
14 before/after COMMIT cuts, both 14-route kill switches and original-byte NUL
forwarding. No behavior divergence is accepted. SQL ownership/rollback seam:
`mailserver/sql/tests/rust_retention_audit.pg` (20 checks).

Security (#437, owner-approved 2026-11-05): `rust_compliance_audit_policy_set` writes its audit row in the same transaction; an audit failure aborts the policy change (Go swallowed it). Mutant `sql:audit-policy-swallows-failure`.
