# Calendar and DAV over HTTP (F17, #296)

`setjoin-calendar` depends only on foundation crates, and no other family crate
depends on it. Slice 1 (`calendar-booking`, #296) holds the booking pages, the
batch free/busy query and the webcal subscription list/delete/create; slice 2
(`contacts`, #297) is the contacts CSV/vCard import and export; CalDAV/CardDAV
(`dav`, #426/#427) is the third slice of the inventory. CalDAV and CardDAV are ON (#426/#427), completing all F17 HTTP slices. The booking adapter is `bins/gateway/src/calendar.rs`.

## Contract

- Authenticated routes act for the verified token's user and primary mailbox only;
  request fields name targets (`id`, calendar ids) and never grant authority.
  Ownership sits in the same statement as every write (R3).
- Reducers keep the logic. Owner page writes call Go's own `booking_page_upsert` /
  `booking_page_delete` in one receipted statement (Go's whole transaction is that
  one call). The public routes call `booking_page_public_get`, `booking_slots`,
  `booking_create`, `booking_confirm` and `booking_cancel` as one autocommit
  statement on the worker credential, like Go's pool: the reducers self-scope by
  slug and token hash (`feature.booking_pages` OFF, an unknown slug and a disabled
  page all answer the same bare 404).
- Subscribe is two inserts in one transaction, so it is the one new reducer,
  `rust_calendar_subscribe` (`mailserver/sql/reducers/`), mirroring Go. Follow-up:
  fold it into a canonical calendar reducer. Unsubscribe is Go's single `DELETE`.
- Free/busy calls `calendar_free_busy_multi` on the request credential without a
  tenant GUC (as Go) with the caller's primary mailbox. Go mounts it only while
  `feature.caldav` is on and behind the calendar entitlement; both refusals (and
  the entitlement audit) stay with Go (the request is forwarded).
- Mail: the verification link, owner heads-up and the confirm iMIP invite are
  built byte-for-byte like Go (`booking_mail.rs`), stored as content-addressed
  objects and queued with one plain `INSERT` on the worker credential. Confirm
  sends them detached from the request. Invalid addresses store an empty message,
  as Go does.
- `POST /calendar/subscriptions` (#298) is ON: the detached first fetch is the
  calendar-subscription-sync worker's `SyncKick` (`subscription_sync.rs`), which the
  gateway installs only when that worker runs in Rust; without it the route keeps
  forwarding to Go.
- The `calendar-subscription-sync` worker (`subscription_sync.rs`, parser in
  `ics.rs`) ports Go's `calendarsync.Worker`: 15 min + up to 3 min jitter, claim 20
  due rows (`FOR UPDATE SKIP LOCKED`, stamped in the claim), conditional GET, 5
  redirects each re-validated, 5 MiB cap, reducer plus bookkeeping in one
  transaction. The fetch is SSRF-safe: a resolver that returns public addresses
  only, a literal-address check per hop, no proxy, every failure the one text
  `couldn't reach that URL`. Starts only with `RUST_WORKERS_ON=calendar-subscription-sync`
  and `GO_WORKERS_OFF=calendar-subscription-sync`. Zones come from the host
  zoneinfo through `tz-rs`, like Go without embedded tzdata. Divergence: no
  `Accept-Encoding: gzip` is sent.
- The `booking-expiry` worker (`booking_worker.rs`) runs Go's one statement
  `SELECT booking_expire_due()` every ten minutes on the worker credential; it
  starts only with `RUST_WORKERS_ON=booking-expiry` and `GO_WORKERS_OFF=booking-expiry`.

## Contacts slice (`contacts`, #297)

- Routes: `/api/contacts/import/*` and `/api/contacts/export/*` (two `*` inventory
  entries, five commands: `csv-preview`, `csv-import`, `vcf-import`, `csv-export`,
  `vcf-export`). Go dispatches on the path suffix; anything else under the subtree
  is the bare 404 after auth. Adapter `bins/gateway/src/contacts.rs`; Go's
  `encoding/csv` reader/writer, column mapping and row-to-vCard projection are in
  `contacts_csv.rs`, vCard parse/split/serialize in `contacts_vcard.rs`; statements
  in `src/contacts.rs` of this crate.
- Authentication and the `contacts` entitlement stay with Go (refusal and its audit
  are forwarded). The address-book gate (`mailboxes.user_id` = verified user) is a
  separate read as in Go; the verified owner mailbox is then in every write's WHERE.
- Every row is one autocommit reducer call (`rust_contacts_import_write`/`_remove`)
  on the request credential with no tenant GUC and no receipt, like Go's pool:
  partial imports and per-row error text (`row N: ERROR: ... (SQLSTATE ...)`) are
  Go's. The change journal's best-effort write is therefore skipped under forced
  RLS exactly as in Go (imported rows never reach `Contact/changes`; recorded).
- `notify_contact_state` runs once after an import that wrote a row, errors ignored.
- Limits: cells/files with invalid UTF-8 are converted lossily (Go would hand the
  bytes to PostgreSQL, which rejects them); multipart parsing is `multer`'s.

## Oracle

`cargo test -p setjoin-gateway --test calendar` replays frozen-Go recordings
(`tests/conformance/calendar/goldens`) with real HTTP, SQL, object-store and NOTIFY
observations and no Go upstream; record with `GOFREE_RECORD_GO_BINARY` and
`GOFREE_GO_SOURCE`. The workers have `--test booking_expiry` (seed plus one tick of
Go's real `Sweeper.Run` through an overlay) and `--test subscription_sync` (real
`calendarsync.Worker` ticks against a feed fixture, `GOFREE_RECORD_SYNC=1` to
record), each with a `_startup` test.
Case list and Go quirks: [CASES.md](../../../tests/conformance/calendar/CASES.md).
The contacts slice is `--test contacts` (55 cases + 5 status mutants), goldens in
`tests/conformance/contacts/goldens`, cases in [CASES.md](../../../tests/conformance/contacts/CASES.md).

Calendar oracle fixture-day normalization (#446 validation): requests use a future
Monday; request metadata applies the same `<D>` normalization as responses, rows
and mail. Replay and Go verification normalize the historical request-metadata anchor
`2026-11-16` in memory; immutable recordings and every other byte stay checked.

## CalDAV HTTP slice (#426)

The native adapter is `bins/gateway/src/caldav.rs`, using dav-server's method
model and frozen-Go wire semantics. The whole `/caldav/` dav inventory entry is
ON; all methods have native dispatch. Qualification lives in `--test caldav`;
[recording contract](../../../tests/conformance/caldav/README.md). DAV roots stay pinned
outside `/api` even for ON entries; the original generic LocalRust fallback
incorrectly overrode that exception. Basic/Negotiate proof remains with #420/#339.

CAL4 preserves Go's timezone catalog keyed solely by TZID, including foreign
stored definitions (Go `caldav.go:75–94,254–269`). The isolated-calendar fix is
assigned separately by the orchestrator; the immutable recording stays unchanged.

GET's first qualified resource case selects the owned master row (detached
occurrences never own a URI). The iCalendar serializer lives in
`bins/gateway/src/caldav/ical.rs`; generated DTSTAMP is normalized, while all
other bytes and the wire Content-Length are checked. The GET corpus additionally records VEVENT/VTODO/VJOURNAL, all-day values,
IANA timezone output, UTF-8 line folding, and detached-occurrence resources.
Calendar-owned overrides are selected with the same verified user predicate.
Go omits organizer/attendees and VTODO priority/completion/due fields; Rust
retains that projection.

REPORT uses `caldav/report.rs`: strict namespace/root decoding follows Go's
substring dispatch. Calendar-query filters owned masters; sync-collection calls
`caldav_changes` with its verified collection-owner mailbox GUC. Free/busy calls
`calendar_free_busy` with the caller's primary mailbox and owned target. Go's
ambiguous email projection then suppresses all free/busy principals, so Rust
preserves the empty multistatus. Standard calendar-multiget is rejected with
400 because Go decodes it into the calendar-query root type. Both behaviors
are immutable recorded parity, not accepted divergences.

PROPFIND on a calendar lists up to 500 master resources unless Depth is exactly
`0`; a resource path returns that master alone, with detached overrides in its
calendar-data. Event properties retain Go's empty successful property block for
zero content length and missing resourcetype. Malformed PROPFIND XML uses allprop;
foreign collections/resources produce an empty multistatus. OPTIONS ignores its
body and target ownership, as recorded from Go.

PUT-create calls `jmap_calendar_event_set_create` with the verified user/email
and a collection ownership predicate in the same publishing statement. It uses
the user transaction executor with a F17 receipt, retaining Go's absent mailbox
GUC (and missing CalendarEvent journal rows); an uncertain COMMIT returns 503
with X-Operation-ID. Infrastructure receipts are excluded from domain-effect
snapshots. The basic create oracle binds generated IDs and ETags to the owned
rows, using a high event sequence floor to avoid literal-digit collisions.
PUT updates and occurrence reconciliation use Go's canonical reducers and
independent user-scoped transactions; normal reducer refusals in occurrence
reconciliation remain best effort. Unknown commits always return uncertainty.
Go's update ETag is empty and a recurring create's ETag predates reconciliation;
both wire quirks are recorded. Shared `ics.rs` adds attendee/occurrence fields
without adding them to subscription JSON. DELETE uses `jmap_calendar_event_set_destroy` with the same actor-bound
transaction/receipt and ownership check. MKCALENDAR preserves Go's unconditional
403 caused by its invalid LIMIT-before-UNION SQL, so it writes no calendar.
Unsupported scheduling POST and HEAD return Go's bare 405; all advertised
methods have recorded floors. No HTTP CalDAV path in Go enqueues iMIP mail;
Rust preserves the empty queue and the unsupported scheduling POST response.

Input qualification retains Go's 1 MiB XML / 10 MiB calendar limits, stripped
DAV paths and negotiated language on problem replies. Generated oversize inputs
are represented in recordings by length plus SHA-256, while the full bodies
are sent. Encoded route-prefix rejection mirrors Go's raw-path StripPrefix
behavior. Recurrence parsing rejects comma RECURRENCE-ID and takes the first
VALUE/TZID parameter; date-only VTODO input keeps Go's all-day projection.

CalDAV opts into shared terminal session admission and uses the verified user
proof so active mailbox-less guests do not acquire invented mailbox authority.
`check_user_app_entitlement(user,'calendar')` fails closed before every method;
a denial mirrors Go's 403 and independent best-effort `audit_write` routine row.
The denial oracle forces full audit policy, checks actor/IP/action, validates the
checksum format, and masks its generated digest and timestamp.

`CalDavRoute::new` warms the process-local TZID catalog before serving. Its
optional `DB_DIRECT_DSN` listener reloads on `timezone_changed`; request-pool
reads fetch definitions, while the direct connection only LISTENs. Shutdown or
last-owner drop stops the owned task. Reload merges keys without clearing,
matching Go. This local cache runs in both processes until Go deletion; it has
no worker handover flag. The owned lifecycle recording checks stale reads before
NOTIFY and refreshed bytes afterward. The foreign-TZID disclosure stays mirrored.

`dav::lookup_operation` accepts a fresh verified user context and a code-owned
Create/Update/Occurrence/Delete category. It takes the publisher's actor/operation
lock and checks the actor-hashed F17 receipt under current enabled identity.
`recovery_before_commit` / `recovery_after_commit` cut the real transport at the
COMMIT boundary, require a 503 with operation ID, distinguish absent/committed
under fresh authority, deny another actor, and compare committed effects with
the single-create Go recording. Neither path replays the write.

`real_client_sessions` captures two actual python-caldav 3.7.0 sessions: principal
discovery and configured-calendar CRUD. Permanent replay sends the recorded
requests through the front door, binds owned resource IDs/versioned ETags, checks
each HTTP observation plus final effects/NOTIFY, and requires total Go proxies
zero. Python is needed only for recording; see the CalDAV conformance README.

Production startup snapshots `feature.caldav` to install the route, warms its
cache before accepting connections, and starts its direct timezone listener.
`executable_client_sessions` replays the same immutable client transcript against
the actual gateway executable with shared admission, bundled ON inventory and
no Go mail upstream; all bytes, effects and zero total proxies must match.
The catalog covers each method/REPORT command, standalone row-effect artifacts
extracted from the immutable write observations, twelve status mutants and F17's
CalDAV audit/notification mutants. The disabled entitlement floors deliberately
record successful enforcement (403), including foreign and malformed requests.

## CardDAV HTTP slice (#427)

Child DOX: [CardDAV contract](carddav.DOX.md) — native HTTP methods, personal
contacts and GAL authority, serialization, journal effects and qualification.

## Security fixes (#512, owner-approved 2026-11-05)
- Subscription cap (#423): `subscription_count(exec, actor)` counts in the caller's user scope, so it sees its rows under the RLS-bound credential (Go counted on the unscoped pool, saw 0). Mutant `subscription-cap-unscoped`.
- CalDAV timezone cache (#426/#512): keyed by (calendar, TZID); `timezone_catalog` returns the calendar id. Mutant `caldav-tz-global-key` (golden `propfind-timezone-foreign` re-baselined).
- GAL (#427/#512): `gal_users` shows a manager's name only when the manager is itself in `directory_visible_users` for the caller. Mutant `gal-manager-disclosed`.
- Tests: `bins/gateway/tests/secfix6.rs`, `scripts/test-secfix6-mutants.py`.
