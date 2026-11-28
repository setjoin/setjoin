# F17 slice `calendar-booking` oracle (#296)

Frozen Go: the covered production source `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8`.
The Go mailserver binary runs per case behind the Rust front door against the
assigned disposable database (its worker pool, object store and JWKS are fakes;
every Go worker is switched off); replay removes Go entirely
(`setjoin_gateway_proxied_to_go_by_family_total{family="F17"} 0`). Record with
`GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`, skipping mutants and faults
(`-- --skip mutant`); goldens are exclusive-create, so a normalization fix means
deleting the affected files and re-recording. `GOFREE_VERIFY_GO=1` compares
without writing. Run serially. `route-catalog.json` binds goldens, replay
selectors and mutants.

Fixture: an owner and an other account (separate domains), fixed ids (pages
951001-951004, calendars 952001-952003, subscription rows 954001-954002; new rows
draw from sequences moved to 960000). The owner's page accepts Mondays 09:00-12:00
UTC in hour slots, with one required question; the test day is the first Monday
at least ten days ahead and is masked as `<D>`. Cross-tenant meaning: authenticated
routes act on another account's id (404/empty, the foreign row untouched); a
public route cannot see tenants, so its denial is the disabled page or unknown
token, which must answer exactly like an unknown slug.

| Route | Cases |
| --- | --- |
| GET booking/pages | success, other account lists only its own, ignored junk query, feature off 404 |
| PUT booking/pages | create, update, repeat (duplicate slug 500), foreign id 404, bad JSON/empty/oversize 400, bad slug/bad id/scalar/null 500, trailing data accepted, feature off |
| DELETE booking/pages | success, repeat 404, missing/bad id 400, foreign id 404 (row kept), feature off |
| GET public/booking/{slug} | success, folded slug, unknown, disabled, feature off, `/slots` suffix quirk |
| GET .../slots | success, missing params 400, bad date 500, range and reversed 400, unknown, disabled, feature off |
| POST .../book | success (mail queued), repeat 409, honeypot, missing required answer, no/null answers, bad JSON, oversize 413, bad start 500, type error, unparseable address, unicode title, unknown, disabled, feature off |
| POST public/booking/confirm | success (event, invite and owner mail), repeat 409, unicode title, bad body, unknown token 409, feature off |
| POST public/booking/cancel | success (event cancelled, NOTIFY), repeat 409, bad body, unknown token, feature off |
| POST calendar/free-busy | own calendar, other account with `sharing.defaults` ON (empty), open by default, rooms, unknown ids, every validation message |
| GET calendar/subscriptions | success, other account, ignored junk query |
| DELETE calendar/subscriptions/{id} | success, repeat 404, bad id 400, foreign id 404 (row kept), missing 404 |
| POST calendar/subscriptions | recorded for the first-fetch worker (stays OFF in the inventory): create, validation, webcal rewrite, name cut, cap |

Go quirks mirrored (ARCH-029): the public dispatch tests the path suffix, so
`GET /public/booking/slots` is the slots handler; `answers` absent is stored as JSON
`null`; an address that does not parse produces an empty stored message and a queue
row with an empty message id; free/busy compares a calendar id with `mailboxes.id`
when it looks up the e-mail; an unparseable or oversized body is always 400 on the owner
routes, 413 only on the public ones.

Known limits: every recorded page is UTC, so the iMIP `DTSTART;TZID` branch (zone
known only through the host zoneinfo, as Go without an embedded database) and a page
timezone other than UTC are unit-level only. Go's per-user subscription cap counts
without a user scope, so under the RLS-constrained `setjoin_app` credential it never
trips (it works only with the owner credential); Rust mirrors the same query, so the
cap is not recorded.
