# CardDAV HTTP contract (#427)

Parent: [Calendar DOX](DOX.md).

## CardDAV HTTP slice (#427)

`bins/gateway/src/carddav.rs` implements the CardDAV compatibility layer using
`dav-server`'s method model. It shares CalDAV's HTTP reply encoder and uses the
verified user proof and contacts entitlement; denied access emits Go's independent
best-effort routine audit. Data access belongs in `src/carddav.rs` of this crate.
Oracle: `setjoin-gateway --test carddav`, with assigned owner/app DSNs and
`REQUIRE_DB=1 --test-threads=1`. The bundled `/carddav/` entry is ON; startup
snapshots `feature.carddav` as Go does. A disabled bridge uses the native root
mux (including website/SPA behavior); it never becomes a Go rollback.
GAL visibility is a live flag.
Shared Basic/Negotiate proof remains with #420/#339, as in CalDAV.

Personal CardDAV reads use verified-user predicates through the owning mailbox.
GET and PROPFIND reuse the CAL2 vCard serializer, retaining Go's projection and
empty/missing property semantics. REPORT uses strict roots after Go's substring
selection: query filters owned contacts, multiget selects requested UIDs across
owned books (href book ids are not an extra selector in Go), and sync-collection
calls `caldav_changes` under the verified collection-owner mailbox GUC.

PUT-create/update and DELETE each publish through one canonical
`jmap_contact_set_*` call in an actor-bound user transaction with an F17 receipt.
A contact disappearing after the ownership read still reaches canonical per-item
notFound accounting; the reducer scopes the contact inside its mutation.
The publishing statement resolves the current owned book, and takes its mailbox
from that verified ownership join; it retains Go's absent mailbox GUC and
associated journal behavior. Uncertain COMMIT yields 503 plus X-Operation-ID.
Per-item reducer accounting gates 201/204, and conditional headers and stored
ETags follow Go. CardDAV fills ROLE/PHOTO/CATEGORIES in the shared parser without
adding those fields to CAL2's import projection. The oracle checks both owners'
rows and state, contact notifications, and ETags bound to the stored contact.


The GAL is read-only and org-wide (ARCH-004), resolved through the verified
user's primary mailbox and `directory_visible_users`. Cross-domain colleagues
are visible; hidden, disabled and guest directory entries are filtered by that
canonical seam. GET, member PROPFIND, query and multiget call
`gal_visibility_record` best effort before disclosure, as Go does. This journal
is not an acknowledged business write of a read response. GAL sync calls the
canonical `gal_changes` reducer in an actor-bound receipted transaction and
returns the opaque micros/count token. Contact sync uses the mailbox counter.
No CardDAV background worker exists.

GAL rendering retains Go's property catalog, byte folding, vCard 3.0 projection,
manager join and read-only XML errors. The enabled-only manager join preserves
Go gal.go:98; its hidden-manager disclosure is reported separately for a
security-fix ticket. This ticket changes neither frozen Go nor that behavior.

The immutable oracle includes real HTTP, both owners' committed effects, audit,
contact notifications and a visibility journal snapshot. Generated contact IDs
and stored ETags are bound to their owned rows; fixture domains normalize to
same-length stable names, including across physical vCard folds. Wire body
lengths are validated before normalizing Content-Length. Invalid first captures
are retained in ignored task evidence, never rewritten in place.

`OutcomeKind` admits only the three contact commands and GAL sync. Recovery
requires a fresh verified user, the publisher's actor/operation lock, the
actor-hashed F17 receipt and current enabled identity admission. A receipt proves
transaction commitment, not per-item acknowledgment or continuing resource access.
The before/after-COMMIT transport cuts cover all four commands, refuse another
actor and another command, compare committed effects with Go and never retry.
The HTTP oracle also plants real missing-audit/notify, ownership and state mutants;
each command has a status mutant and all native cases require zero Go proxies.
Malformed stored contact JSON is refused before PUT/DELETE, matching Go's row
scan rather than silently repairing or deleting a row the Go handler cannot load.

Real vdirsyncer 0.20.0 discovery, vCard 3/4 CRUD and GAL sessions are immutable
HTTP transcripts; normal replay needs neither Python nor Go. The executable
replay boots the production admission/route table without a Go mail upstream.
Discovery and returned-href failures remain observable Go parity, not a claim
that broken Go discovery succeeds. Scoped reducer exceptions and absent/malformed
per-item accounting refuse successful write acknowledgments and preserve effects.
Row-effect goldens are exact immutable HTTP observation extracts, checked in normal
replay; `tests/conformance/carddav/catalog.py` reconciles only this route's catalog.

F17 closure: all 16 inventory rows across calendar-booking, contacts and dav are
ON. `inventory_guard::calendar_dav_slice_ownership_is_exhaustive_and_disjoint`
checks that no family route remains with Go. The inherited `booking_expiry` and
`subscription_sync` oracle targets and their `*_startup` executable tests qualify
both shared-effect workers, with matching `RUST_WORKERS_ON`/`GO_WORKERS_OFF` names.
The CalDAV timezone cache remains process-local in both runtimes until Go deletion.
CardDAV introduces no worker. F17 no longer occupies an in-flight family slot.
