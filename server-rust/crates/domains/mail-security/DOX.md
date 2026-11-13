# Mail security (F06, #320..#328)

`setjoin-mail-security` depends only on foundation crates (`authz`, `contracts`, `db`, `pg`, `mime`, `spam`, `certificates`)
and no other family crate. The gateway adapter `bins/gateway/src/mail_security.rs`
translates HTTP (one `Intercept`, a method/pattern `action()` table, a `gate()` per route);
business authority stays in reducers. The actor and mailbox come from the sealed auth
context; path ids, query strings and bodies name targets and never grant authority. Later
slices add modules here and arms to the adapter's table; they reuse `authority`,
`console_denied`, `scope`, `envelope`, `command`, `done`, `nano` and the permission sets in
`lib.rs`. Frozen Go is authoritative (ARCH-029/030).

## Slice map (all 56 F06 inventory entries, exactly one slice each)

Guard: `inventory_guard::mail_security_slice_ownership_is_exhaustive_and_disjoint`.

| Slice | Routes | State |
| --- | --- | --- |
| `quarantine` (#320, `src/quarantine.rs`) | 9: `/quarantine`, `/quarantine/count`, `/quarantine/{id}/release|reject`, `/admin/quarantine`, `/admin/quarantine/stats`, `/admin/quarantine/{id}/preview|release|reject` | ON |
| `queue` (#321, `src/queue.rs`) | 4: `/admin/queue`, `/admin/queue/summary`, `/admin/queue/{id}/retry|bounce` | ON |
| `spam` (#322, `src/spam.rs`) | 15: `/admin/spam*`, `/settings/senders*`, `/settings/trusted-senders*`, `/settings/sender-control*`, `/settings/external-sender`, `POST /report` | ON (routes; trainer worker #451) |
| `tls` (#323, `src/tls.rs`) | 6: `/admin/tls/*`, `/admin/outbound-tls-policy` | ON |
| `dmarc` (#324, `src/dmarc.rs`) | 4: `/admin/dmarc/*`, `/admin/auth-log` | ON (plus the `dmarc-report` worker, gateway `src/dmarc_report.rs`) |
| `dlp` (#325, `src/dlp.rs`) | 6: `/admin/dlp/patterns`, `/admin/anti-phish`, `/admin/link-protect/audit`, `GET /link-protect` | ON |
| `threat` (#326, `src/threat.rs`) | 4: `/admin/threat/{view}`, `/admin/threat/ip-rules` (GET, POST), `DELETE /admin/threat/ip-rules/{id}` | ON |
| `trace` (#327, `src/trace.rs`, `src/received.rs`) | 4: `/admin/trace`, `/admin/trace/export`, `/admin/trace/{messageId}`, `GET /messages/{emailId}/trace` | ON |
| `smime` (#328, `src/smime.rs`) | 4: `/admin/smime/trust-anchors*`, `GET /user/cert-status` | ON (plus the `smime-trust-listener` worker) |

Every route mounts at `/api` except the unauthenticated `GET /link-protect`, which Go pins at
the root (`inventory.rs` lists family 6). The oracle is shared: `tests/mailsec_oracle/mod.rs`
owns persona, masking, observation, goldens, planted mutants and cleanup; each slice adds a
module with `route`, `granted`, `seed`, `request`, `wanted` and `snapshot`, a test target
`mailsec_<slice>.rs` and goldens under `tests/conformance/mail-security/`
(`goldens/<slice>-<action>-<label>.json`, `divergences.json`).

## Authorization

Admin gates mirror Go: `requireMailPerm` is any of `domains.read|queue.read|reports.read|
mail.pipeline|mail.security`, `requireMailExport` is `mail.export`, `requireSecurityWrite`
is `security.write`. A refusal writes Go's durable `console.denied` row and answers the bare
403. None of these is org-wide-only (`audit.read`/`audit.export` are), so a domain-scoped
admin is served, and Go has no handler-level domain filter on quarantine: a scoped admin sees
and acts on every mailbox (mirrored, recorded as the `scoped` cases). User routes need only
a verified token; ownership is the token's user in the same WHERE as each write.

## Slice `quarantine`

- Both list handlers scan `timestamptz` into Go strings, which pgx cannot do in binary
  format, so every row fails its `Scan` and is skipped: Go always answers `{"items":null}`
  when the query runs. Rust still runs the query (`read_iterated`, Go's `Rows.Err`
  blindness) so a database error keeps its 500; the response is the constant document.
- `GET /quarantine/count` and `/admin/quarantine/stats` ignore scan errors (a failed read
  counts 0); stats renders sorted keys. Preview renders `fromAddr,html,quarantinedAt,subject`
  (UTC, seconds) and answers 404 for no row or any read error.
- Release and reject call `rust_mailsec_quarantine_release|reject` (worker credential,
  receipted, ownership in the reducer's UPDATE WHERE): one transaction where Go commits the
  UPDATE and its follow-up separately (reviewed divergence record, fault-only). User release
  and admin release are identical in effect (`release_quarantine_tags`, one `tag:{mailbox}`
  push). User reject soft-deletes; admin reject hard-deletes with the error swallowed, and
  the quarantine row stays. Reject of an already-rejected row succeeds again (Go's WHERE only
  excludes released rows). Statuses: user 403 "not found or already released|processed",
  admin 404 "not found or already processed", bad id 400 "invalid id".
- The planted `no-tenant-filter` family mutant is observational, as Platform's: it seeds an
  extra foreign row that an unfiltered query would surface and requires the golden to fail.

## Slice `queue`

- Reads need `requireMailPerm` (any of the five console permissions); retry and bounce need
  `queue.write` (`requireQueueWrite`, audited denial, not org-wide-only so a domain-scoped admin is
  served). `outbound_queue` has no tenant column and Go has no handler-level filter: the queue is
  global. Responses use `WriteProblem` (instance = stripped path, `Content-Language`), unlike
  quarantine's bare problems; a denial stays bare.
- List: `status` maps `failed|held|all` to fixed clauses, any other value binds as the status
  (so unknown values answer `[]`); `limit` 1..200 else 50, `offset` clamped to 0..1,000,000. Always
  a JSON array (`[]`, never null), sorted-key items, `lastError` `""` for NULL, `mailboxId` null.
  Summary: `oldestMinutes` is `"%.0f min"`.
- Retry and bounce call `rust_mailsec_queue_retry|bounce` (worker credential, receipted): Go's
  single UPDATE, with the DSN trigger and the immutable-status guard (bounce of a delivered item is
  BZ012, Go's 500) inside the same statement. Success is a bare 204; no match is 404 ("item not
  found or not retriable" / "item not found"); a non-integer id is 400 "invalid queue id". Go writes
  no audit row and no notification here (recorded). Bounce has no status filter, so repeating it
  is 204 again. No reviewed divergence.
- Oracle: `tests/mailsec_oracle/queue.rs` moves foreign `outbound_queue` rows aside (global table)
  and restores them in `teardown`; the `sending` row is flipped after Go boots because startup
  recovery resets `sending` to `pending`.

## Slice `spam`

- HTTP side: `bins/gateway/src/mail_security_spam.rs` (handlers) and `mail_security_input.rs`
  (Go `encoding/json` decoding: folded keys, per-type `null` rules, strict 64 KiB one-object
  decoder for the sender-control action, `normalize_sender` for trusted senders).
  Reads (`dashboard`, `senders_legacy`, `trusted_list`, `external_get`) tolerate scan errors
  as Go does; every write is receipted. The sender-control center flag
  (`feature.sender_control_center`, default OFF) is read per request from `feature_toggles`
  and picks Go's two branches; a failed flag read forwards to Go.
- Writes: trusted senders, the external-sender toggle and the three admin model switches are
  one statement each (the switches fold `admin_can_reach($actor,$target)` into a CTE, so the
  check and the write cannot diverge: 403 when false, 500 on any error). Legacy list replace,
  never-block and report call `rust_mailsec_sender_list_replace|never_block|report`. Center-ON
  replace, control read and action call Go's own `sender_list_replace`,
  `sender_control_read`, `sender_control_action` with Go's exact digest bytes
  (`json.Marshal` of the request struct / of the all-strings digest struct) and map
  BZ006/300/301/302/303/304 through the reducer problem projection (`WriteProblem`
  instance, `Content-Language`); reducer jsonb is written verbatim (no newline) with
  `ETag: "<generation>"`.
- Go quirks mirrored: `WriteHeader(200)` before `Encode` leaves the type sniffed
  (`text/plain; charset=utf-8`) for senders PUT, never-block and external PUT; the dashboard
  scans several aggregates with ignored errors; `warn_color` NULL fails the whole domain
  scan; `user_spam_model` disable of a missing user is Go's 500 (FK).
- Divergences (`divergences.json`): a spam report emits `spam_train` where Go
  enqueues in process (the oracle asserts the notification and removes it from the golden);
  never-block and the report audit+lookup are atomic.
- Oracle: `tests/mailsec_oracle/spam.rs`; `POST /report` is recorded with the pre-RLS owner
  pool (`start_named_unscoped`) because Go resolves the message through the request pool
  without a tenant GUC and answers 404 for every message under `setjoin_app`.

## Slice `tls`

- HTTP side: `bins/gateway/src/mail_security_tls.rs`. Reads (`status`, `config-get`, `policy-get`)
  need `requireMailPerm`, writes (`config-put`, `import-cert`, `policy-put`) need
  `security.write`; none is org-wide-only. Every error is Go's bare `WriteError`. `system_config`
  is global (no tenant filter).
- `GET /admin/tls/config` is `GetByPrefix("tls_")` (the `_` is a LIKE wildcard, so `tlsx...` keys
  show), value text per `configStringForResponse` (`[ENCRYPTED]` for the `encrypted` column or an
  `_enc` key, JSON string unquoted, `null` is "", anything else raw jsonb text). `PUT` keeps only
  `tls_*` keys, renders each value as `json.Marshal` of the decoded `interface{}` (floats via
  `go_float`, sorted keys, HTML escapes), refuses `_enc` keys (Go's TLS `ConfigStore` is built
  without a secrets codec, so any secret value answers 500; the console's `[ENCRYPTED]` echo
  preserves a stored secret, 500 when absent) and calls
  `rust_mailsec_tls_config_set`, which upserts and writes the `tls_config_set` core audit row in
  one transaction (Go audits after the commit; reviewed divergence, fault-only). A `null` body is an
  empty write that still audits.
- `GET /admin/tls/status` reads five keys with `#>> '{}'` (any error is ""), `domains` is `null`
  when empty, and the certificate is the first PEM block of `<cache_dir>/<sha256(first domain)>`
  parsed through `certificate.rs`'s Go profile over audited DER/X.509/curve decoders
  (last CN, RFC 3339 UTC, `days_left` truncated). The same admission profile serves
  S/MIME imports and gateway operator CA bundles; parsing does not verify a signature,
  establish trust, or enforce validity. [Certificate oracle](../../../../tests/conformance/mail-security/divfix/README.md)
  records rejected shapes and accepted controls from frozen Go.
- `POST /admin/tls/import-cert` mirrors `ParseMultipartForm(10 MiB)` + `FormFile` (a part without a
  filename is a value), `MkdirAll(0700)`, `os.Create` + `Chmod(0600)` of `custom.cert.pem` and
  `custom.key.pem`, then the `tls_cert_import` audit row (a failed audit is ignored as in Go).
  The directory is `<TLS_AUTOCERT_CACHE_DIR or /var/cache/mailserver/autocert>/imported`; when the
  variable is unset and `SETJOIN_CONFIG` is set the route forwards to Go (Rust cannot read the file).
  Go never parses the uploaded certificate/key; arbitrary bytes succeed. #468 preserves
  that storage contract and fixes strict parsing in the status reader instead.
- `PUT /admin/outbound-tls-policy` decodes with `DecodeJSON` semantics (1 MiB, one value, nothing
  after it), validates in Go's order and calls `rust_mailsec_tls_policy_set` (three upserts and the
  `config_changed` notification in one transaction; Go commits them separately). `GET` degrades
  per key to the defaults and decodes each list like `json.Unmarshal` with the error ignored.
- Oracle: `tests/mailsec_oracle/tls.rs`; each case stashes the `tls%`/`outbound_tls%` rows and a
  per-case host directory is mounted at the same path into Go's container
  (`go_oracle` `--volume` pseudo-variable). A seeded sealed value is compared by what it opens to.

## Slice `trace`

Detail: [slices/trace.md](slices/trace.md) (moved verbatim from this file; #327).

## Slice `smime`

Detail: [slices/smime.md](slices/smime.md) (moved verbatim from this file; #328).

## Slice `dlp`

Detail: [slices/dlp.md](slices/dlp.md) (moved verbatim from this file; #325).

## Slice `threat`

Detail: [slices/threat.md](slices/threat.md) (moved verbatim from this file; #326).

## Slice `dmarc`

- Four reads, no reducer. `/admin/dmarc/*` need `requireMailPerm`; `/admin/auth-log` needs
  `requireLogsPerm` (`audit.read`, org-wide only, so a domain-scoped admin is refused with the
  audited `console.denied`). Failed reads mirror Go's ignored errors: live counts zero, a missing
  scoped domain answers the empty document, empty lists are `null` (`byDomain`, `failures`, `days`)
  except the auth log (`[]`) and trend for a vanished scoped domain (`{"days":[]}`).
- `live` counts rows whose `end_time` equals today's UTC midnight, but Go's recorder writes
  `end_time` = tomorrow's midnight, so only rows that closed at midnight are seen (frozen-Go bug,
  mirrored). Per-domain `policy` is `domains.dmarc_policy`, `""` for an unknown domain.
- `failures`: `ParseLimitOffset(100,200)`; a scoped admin adds `mb.domain_id`; any read or scan
  error is `WriteProblemStatus` 500 "database error". `trend`: 30 days, scoped by domain name.
- `auth-log`: filters bind as Go's (provider/event `all` = none, `since` is an interval text, email
  `ILIKE`); `limit` and `since` bind as text, so a bad value fails at Bind; pgx surfaces that through
  `Rows.Err`, which Go ignores, so the answer is `[]` 200 (a pool failure is Go's 500 "query
  failed"). A NULL email fails Go's `Scan` into a string; pgx then closes the rows, so the list ends before that row.
- Oracle dates are run-relative: `mailsec_oracle::dmarc::mask_days` renders `"<today-N>"`.

## Security fix: quarantine domain scope (#448, #511)

Owner-approved security fix 2026-11-05 (ARCH-029 exception): frozen Go's admin list, stats,
preview, release and reject had no per-domain filter. They now require `admin_can_reach_perm` over
the route's permission (list/stats `MAIL_CONSOLE`, preview `mail.export`, release/reject
`security.write`) for the owner of the mailbox stored on the quarantine row. Preview, release and
reject of a foreign row answer exactly like a missing one (404); stats count only reachable rows;
release/reject repeat the rule in the UPDATE's own WHERE inside `rust_mailsec_quarantine_*` (R3).
An organization-wide grant keeps Go's behaviour. Reviewed record: `divergences.json` (entries with
`baseline`); test `bins/gateway/tests/secfix5.rs`; mutants `scripts/test-secfix5-mutants.py`.

## Spam trainer (#451)

Native per-user SPM1/FTR2 model, collector, save fence and named-worker handover:
[model and worker contract](slices/spam-trainer.md). The immutable oracle compares
whole model bytes, rows and signed S3 requests without a weight tolerance.

## Delivery batch gauges (#468)

The exact live source while delivery remains in Go (#526, the remaining #351 pipeline) is the `spamStore`
`*spam.PGModelStore` created in `mailserver/cmd/mailserverd/main.go`, passed to the
inbound SMTP server and wired by `adminSpamH.SetBatchLoadStats(spamStore.BatchLoadStats)`.
`mailserver/internal/spam/batchload.go::PGModelStore.BatchLoadStats` reads that store's
`batchResidentModels`, `batchResidentBytes`, `batchLoadsTotal` and `batchHitsTotal` atomics
(`store.go`). `recordBatchLoad` increments loads and residency on a successful first load;
`recordBatchRelease` subtracts residency at reset. Preserve Go's counter defects:
`BatchScorer.Score` increments only its local hit count (the store's dashboard hits
stay zero), and resetting several models decrements the store model gauge only once.
They are not `user_spam_model` aggregates or the Rust trainer's counters.

Rust inbound scoring (#526) now consumes the shared `setjoin-spam` model store.
The gateway shares `process_stats` between its inbound listeners and the authenticated
spam dashboard. `smtp_inbound_dashboard` compares live loads/residency, repeated
cache-hit behavior and release on QUIT against the frozen-Go SMTP batch recording;
Go's zero reported hits and one-decrement-per-batch gauge defect remain mirrored.
The standalone F06 dashboard adapter defaults to idle counters for callers without
a delivery store. [Scorer contract](../../spam/DOX.md).

## Certificate profile and client transport (#468)

`certificate::accepts_der` exposes parse-only admission to gateway startup; it grants
no trust. The private profile uses RustCrypto `der` for canonical tag/length/primitive
reads and RustCrypto NIST curves for public point validity, then `x509-parser` for
certificate fields. P-224 is pinned to 0.14.0-rc.15: the stable 0.13 line brings
advisory-affected crypto-bigint; the release candidate shares the patched workspace
arithmetic graph. No private-key arithmetic or certificate-signature check is added. Field OIDs use Go's
signed31bit component bound; policy OIDs retain arbitrary-width canonical components
(validated with the existing audited byte-regex engine after DER field decoding).
HTTP status, import responses and row/notification effects replay archived Go bytes;
see the linked certificate oracle for fixtures, recording and transport tests.

`smime::first_certificate_dates` (#494) composes the same parsing profile for
the mailserver's owned-certificate date hints. It decodes the first PEM block
without checking its label or trailing bytes, matching Go's ParseCert; it
returns validity seconds only and grants no trust or signature authority.

`smime::first_pem_bytes` (#494) exposes the same first-block decoding for the
independent private-key parser composed by the gateway. It performs no key
arithmetic or trust decision; private-key validation and storage stay in F21.

`smime::first_certificate_encrypt_capable` (#494) composes the same strict first
certificate parser for RSA/keyEncipherment eligibility. It grants no trust and
leaves time/email admission to the recipient-import adapter.

`smime::first_certificate_email` (#494) returns the first nonblank SAN rfc822Name,
trimmed and lowercased, under that same parsing profile. It grants no trust.
SMTP6 (#526) extracts the same certificate/PEM profile and `smime::trust` cache to
the [certificates foundation](../../certificates/DOX.md). Existing public names
remain compatibility re-exports; F06's import and cache oracles still apply.
