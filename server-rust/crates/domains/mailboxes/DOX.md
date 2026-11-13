# Mailboxes and migration (F05, #292)

`setjoin-mailboxes` depends only on foundation crates (`authz`, `contracts`, `db`, `pg`).
The gateway translates HTTP (`bins/gateway/src/mailboxes.rs`); PL/pgSQL reducers keep
business authority. The actor and mailbox come from the sealed auth context; path ids name
targets and never grant authority.

## Slice map

F05 has four slices; the inventory assigns every route to exactly one:
`mailboxes` (19 routes, this crate), `migration` (16 routes), `exchange-replacement` (13) and
`mailwork` (the worker, no routes). Later slices add their own modules here.

## Slice mailboxes (#292)

- Gates mirror Go's chain from the live governed grants (`authority`): reads
  `requireMailPerm` (any of `domains.read|queue.read|reports.read|mail.pipeline|mail.security`),
  mailbox and folder writes and import `users.create`, lifecycle/purge `users.delete`,
  export `mail.export`. A refusal writes Go's durable `console.denied` audit row and answers
  the bare 403. The domain scope is the live minimum over active assignments.
- Reads run on the request pool with Go's SQL (`mailbox_effective_type`, tag-sourced folder
  counts). Go skips rows it cannot scan: a folder with NULL `role` never lists, and
  `GET /admin/mailboxes/{id}` of a row it cannot scan is a 500.
- Writes: create and update are one receipted statement each (the user's domain and the
  admin's scope ride in the same WHERE). Delete (worker credential) and the folder
  writes call `rust_admin_mailbox_delete` / `rust_admin_folder_*`, which reproduce Go's
  multi-statement handlers; the paired tag statement's failure is swallowed as Go only logs it.
- Create validates the address with a conservative `net/mail` model (dot-atom local part,
  ASCII domain). An address outside that model forwards the untouched request to Go.
- Go quirks kept: create without a positive `quotaBytes` binds NULL and hits the column's
  NOT NULL (500); update NULLs both purge-day columns when absent; folder update/delete of a
  missing folder answer 204; delete of a missing mailbox (global admin) answers 204;
  `deletedPurgeDays` outside int4 is a 500 before any SQL (pgx range check).

- Lifecycle console (8 routes, `users.delete`): each is one reducer call on the worker
  credential (`mailbox_lifecycle_*`, `mailbox_retained_list`, `mailbox_purge_*`). Reads return
  the reducer's `jsonb` text verbatim (no trailing newline), as Go writes
  the raw bytes. Writes use one receipted command, so a BZ business error rolls back with no
  receipt. BZ300-BZ313 and the approval codes BZ106-BZ110 project like `reducererr`
  (`lifecycle::classify`); any other error is Go's fixed per-route 500 text.
  Bodies decode strictly (`DisallowUnknownFields`, one value, 64 KiB); the request digest
  is SHA-256 of Go's `json.Marshal` of the decoded struct (unit-tested against Go output);
  UUIDs parse like `github.com/google/uuid`. `auth_time` comes from the signed claim.
- Go quirk kept: `mailbox_purge_execute` has no reach check, so any `users.delete` admin can
  execute another domain's approved purge (reported as a security bug, not fixed here).
- Import and export (#425) are native; see the next section.

## Import and export (#425)

`POST /admin/mailboxes/{id}/import` and `GET /admin/mailboxes/{id}/export` (gateway
`mailbox_io.rs`, db seam `import_export.rs`) run on the worker credential; the gates are
`users.create` (import) and `mail.export` (export) with Go's durable `console.denied` row.
Every refusal is Go's bare problem (empty `instance`, no language), not the folder-style one.

- Order as Go: id (`ParseInt`, positive) -> `reach` (Go's `canReachMailbox`: owner arm
  `admin_can_reach`, owner-less arms `admin_effective_authority`, 403/404/500) -> body.
  The reducer `import_message` carries the actor and live domain scope (`p_actor_id`,
  `p_domain_scope`) so its INSERT predicate decides at execution time; the export SELECT uses
  `admin_can_reach_mailbox`; the export re-checks reach every 50 messages and stops the stream.
  Each reducer call is one receipted transaction; `Committed(None)` is Go's "authority revoked".
- Upload: multipart, 50 MiB, first `file` part, `folder_id` from the query first then the form;
  a bad query string is "invalid multipart form" (Go's `ParseMultipartForm` returns the
  `ParseForm` error). Filename = `filepath.Base`, kind by lower-cased suffix. MBOX splits on
  `From ` lines longer than five bytes (the message index counts skipped blank ones), EML is
  one message (an empty file imports), ZIP follows Go's limits (10000 entries, 128 MiB per
  entry, 2 GiB, ratio 100) and skips non-`.eml` names. Raw bytes go to the object store under
  their SHA-256 (`message/rfc822`) before the reducer call; the audit row `mailbox.import`
  (tier core) is a separate best-effort statement. Response `{"failed":null|[...],"imported":N}`.
- `mimeutil` (compatibility re-export of foundation `setjoin-mime`) ports Go's `mimeutil` for reuse by the migration runner
  (`importMailItem` calls the same ten functions; `ImportFields::parse` is that block). It works
  on bytes like Go strings: `net/mail` address parser, `mime.ParseMediaType` incl. RFC 2231,
  RFC 2047 `WordDecoder.Decode` (utf-8, iso-8859-1, us-ascii only; the whole header value must be
  one word), `http.ParseTime` (three layouts, zone abbreviations read as UTC), the fail-closed
  multipart walk and `htmlindex` charsets through `encoding_rs`. `tests/vectors/` holds 274
  corpus cases recorded from frozen Go (`corpus.py`, `dump_go.txt`, `vectors.json`); extend
  the corpus, rerun the dumper and keep `mimeutil_vectors` green.
- Go quirks mirrored: the stored `from_addr` is the display name and `from_name` the address
  (`importRawMessage` swaps `ParseFrom`'s results); text with invalid UTF-8 or NUL fails the
  message after the object upload; an RFC 2822 date (`-0700`) is not an HTTP date so `now()` is
  used; the body is not transfer-decoded (QP/base64 kept as is); an unknown charset keeps the
  bytes; `export` skips an mbox message whose object name is invalid, answers an empty entry for
  a missing object, and decides Content-Length vs chunked at 2048 bytes as net/http does.
- Export ZIP: written by `ziparchive::ZipStream` with Go's header fields (deflate, data
  descriptor, DOS time and date zero, version 2.0, flags 8 or 8|0x800, zip64 past 65535
  entries); the deflate stream is `flate2`'s. **Reviewed divergence (ARCH-029):** Go's
  `compress/flate` bytes cannot be reproduced, so the archive length and SHA-256 differ for every
  ZIP golden (`tests/conformance/mailboxes/divergences.json`, one record each); everything else
  is compared entry by entry in the golden (name, order, header fields, CRC-32, sizes, contents).
  The mbox separator date is the export time in UTC (Go formats in its local zone).

## Slice migration (#293)

All 16 migration shapes have native adapters (`migration.rs`, `private_policy.rs`,
gateway `src/migration.rs`), including EWS, Microsoft 365 and the callback (#446).
Start/control/test require the configured runner; missing dependencies fail locally.
The provider, checkpoint, callback and uploaded-phase contracts are in
[MICROSOFT.md](MICROSOFT.md); lifecycle and worker transfer are below.
The [provider oracle](../../../tests/conformance/migration/README.md) documents isolated HTTPS/DNS recording and replay.

- Gates mirror Go's chain from the live grants: reads `requireMailPerm` (any of the
  `MAIL_CONSOLE` grants), writes and the consent start `requireMailPipeline` (`mail.pipeline`),
  then `requireOrgWideSurface`: a domain-scoped admin is refused with Go's
  `org-wide-only surface (domain-scoped principal; domain=N)` `console.denied` row. `migration_jobs`
  and `system_config` have no RLS and no owner column; they are installation-wide admin
  resources, so R1-R4 reduce to that gate plus the verified actor on every receipted write.
- Writes are one receipted statement each (job delete, profile upsert/delete) or the existing
  `m365_consent_state_mint` reducer for the actor (consent start). The callback uses
  `m365_consent_state_consume` before verification and `m365_consent_complete` afterwards;
  source-identity auxiliary projection uses the atomic wrapper documented in `MICROSOFT.md`.
- Sealed profiles (`ews.global`, `m365.app`): `{"_enc": base64(nonce || AES-256-GCM)}` with the
  key HKDF-SHA256(raw `DB_ENCRYPTION_KEY`, no salt, info `system`), exactly Go's
  `migration.EncryptConfigAny`. The oracle seeds with the Rust codec, so frozen Go opening it and
  the Rust replay opening Go-written rows prove both directions.
- Go quirks kept: job get is a Go `map` (sorted keys); progress/error_log are compacted jsonb;
  the list's `user_id` filter is bound as text (a non-number is a 500 `query failed`); `GET
  source/imap` returns the stored jsonb text verbatim and ignores `encrypted`; a sealed profile
  that cannot be opened is `404 config not found`; `PUT` profile validation uses ports of
  `ssrf.CompilePrivatePolicy`, `validateEWSServerURL` and Go's `url.Parse`/`net.ParseCIDR`
  (unit-tested); `tests/migration_startup.rs` proves all migration shapes native; the consent redirect writes Go's `http.Redirect` body and
  `m365_oauth_state` cookie (`Secure` follows the client-facing scheme).

## Oracle

`bins/gateway/tests/mailboxes{.rs,_oracle/}` (and `mailbox_io{.rs,_oracle/}` for import/export, with the stateful fake S3 of `drive_workers_oracle/fake_s3.rs`) records frozen Go through the front door
(`GOFREE_RECORD_GO_BINARY`, `GOFREE_GO_SOURCE`) and replays with no Go upstream. Goldens live in
`tests/conformance/mailboxes/goldens`; the route catalog binds them with status mutants and
family fault mutants.

## Worker slice (#295)

The worker-only `mailwork` slice has no HTTP registrations. Its adapter and
seed-plus-one-tick oracle are `bins/gateway/src/mail_workers.rs` and
`bins/gateway/tests/mail_workers_recorded.rs`; frozen Go recording overlays live in
`tests/conformance/drain/`. Qualified ticks cover SLA scans, due digests, local push/digest/metric dispatch and
Task/Chat/Drive actions (including authorization failures and repeated ticks), using
the existing reducers on the worker credential.
Lifecycle purge ticks replay successful/reclaimed deletion and tombstones, retention
blockers, stale-generation retries, future eligibility and active/exhausted leases.
Lifecycle local effects now replay revocations, delegate removal, notifications, empty
media completion, expired leases and missing peripherals. LiveKit eviction uses the
shared signed transport, treats NotFound as success per attempt, repeats through the
committed horizon (at most 5 s between attempts), and acknowledges each target before
completing the effect. A completion error leaves the claim leased, as Go does.
The nil-dispatcher retry path and the configured dispatcher with no matching active
organization subscribers both have Go recordings. Self subscriptions are ignored by
this durable organization dispatcher, as in Go. `with_dispatcher` hands each
mail-work and lifecycle event to the shared webhook `Dispatcher::enqueue_durable` (#457):
mail-work events carry Go's five-key payload (numbers as float64), the outbox event id
as CloudEvent id and source `urn:setjoin:mailwork`; lifecycle events carry the outbox id,
`mailserver/lifecycle`, the row's RFC 3339 nano time and the jsonb data as raw text.
Without a dispatcher both fail as in Go (nil dispatcher).
Executable transfer: `RUST_WORKERS_ON=mail-work,mailbox-lifecycle` requires the same
names in `GO_WORKERS_OFF` (exact, case-sensitive, comma/whitespace trimmed). Each is
an independent task: immediate drain, then every 5 s, interrupting in-flight work
on shutdown. Both use `DB_WORKER_DSN` (fallback `DB_DSN`) and the deployment audit
keys, never a pooled role switch. Lifecycle takes `LIVEKIT_URL`, `LIVEKIT_API_KEY`
and `LIVEKIT_API_SECRET`; missing media records Go's retryable failure.

Subscribed deployments no longer stay on Go: delivery is the shared dispatcher's
(`tests/mail_workers_recorded.rs::mail_workers_webhook_delivery_tick`, Go-recorded fake
receiver). To return a worker to Go, omit its Rust name and restore Go's name on restart.
`GATEWAY_ENABLED` controls HTTP dispatch and does not stop workers.
`tests/mail_workers_startup.rs` verifies credentials, immediate/recurring effects,
delivery of subscribed events through the executable, disabled queues and cancellation through a media
horizon. No HTTP entry belongs to this slice; F05 closure still depends on the
sibling migration/exchange/import-export slices.

The shared LiveKit transport preserves Go's persisted Twirp error for refused numeric
endpoints; the media oracle covers it and the six Guest worker replays guard reuse.
The empty protobuf reply is validated with pinned `prost` before acknowledgment:
a malformed 200 response fails the effect, matching the Go-recorded diagnostic.
Both worker oracles reject an omitted-tick mutant on actual effects; the lifecycle
check additionally requires missing audit and notification differences.

## Security fix: Exchange group domain scope (#434, #511)

Owner-approved security fix 2026-11-05 (ARCH-029 exception): `exchange_assessment_domain_authorized`
now honours the role group's `domain_scope` when the assignment override is NULL (frozen Go ignored
it, so a group-scoped admin could create projects for any domain). Only a grant with neither is
organization-wide. Every Exchange reducer shares that function. Reviewed record:
`tests/conformance/exchange/divergences.json`; test `bins/gateway/tests/secfix5.rs`.

Security (#424/#430, owner-approved 2026-11-05): `mailbox_purge_execute` needs the cancel reach (requester, `users.delete` over the requester, or the superadmin role; a foreign request answers like a missing one, BZ311); the M365 consent URL (`migration::consent_url`) escapes the client id and builds `redirect_uri` from the configured `HOSTNAME`, never the Host header. Mutants `sql:purge-execute-no-reach`, `m365-consent-untrusted`.

Security (#531 F2, owner-approved 2026-11-06): `GET /admin/migration/m365/connect` answers 503 `public hostname is not configured` when `HOSTNAME` is unset, empty or `localhost` (`migration::public_host_usable`), before any config read; `main.rs` no longer defaults it to `localhost`. Mutant `m365-connect-localhost`.

Job runner (#431) and Exchange replacement (#294): [RUNNER_EXCHANGE.md](RUNNER_EXCHANGE.md).

Microsoft migration providers and callback (#446): [contract](MICROSOFT.md).
