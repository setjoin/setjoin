# Meet and RTC (F13, #285–#288)

One family crate (`setjoin-meet`); only foundation dependencies. Frozen Go is the
oracle (ARCH-029/030). LiveKit, Egress, Valkey and the ASR bot are peripherals:
never authority stores, and recorded only against fake endpoints. HTTP lives in
gateway `src/meet.rs`; external paths are mounted at `/api`.

## Disjoint inventory slices (all 51 F13 registrations)

- `golden-routes` (#285): `GET|POST /meet`, `GET /meet/{id}`, `GET /meet/by-slug/{slug}`,
  `POST /meet/{id}/lock|settings|role` (7).
- `sub-router-a` (#286): `join`, `kick`, `end`; lobby `knock`, `requests/{reqId}`,
  public `join-request` POST/GET; the four `breakouts` routes; `POST /meet/webhook` (12).
- `sub-router-b` (#287): recording and captions (POST/DELETE each), the eleven
  presentation routes (start/source/page/presenter/ready/degrade/recover/revoke/end,
  checkpoint GET, create) and annotation GET/POST (17).
- `sub-router-c` (#288): local-capture, semantic package/replay, `GET /admin/meet/recordings`,
  the four asrbot-listener routes (their Rust binary is #356), and the `/meet`,
  `/meet/`, `/rtc`, `/rtc/` catch-alls (15; the seven real routes are ON, the rest stay Go).

`inventory_guard::meet_slice_ownership_is_exhaustive_and_disjoint` pins 7/12/17/15
and the exact golden keys. The `/rtc` SFU signal proxy stays at its registration
path; every other gateway-listener F13 entry mounts at `/api`.

## Golden routes (#285)

Gate order matches Go: shared authz (native terminal errors, #406), `feature.meet` (OFF is 404
without Content-Language), `check_user_app_entitlement` (native denial plus Go's independent app_blocked
audit), then LiveKit configured (`LIVEKIT_API_KEY`, `_SECRET`, `_URL`;
else the 503 service-unavailable problem), then the handler. The verified user is the
only identity; `p_user_id` and the transaction-local user GUC come from it, never from
the body, path or query. Reads use READ ONLY scoped transactions; the four mutators
call the existing `meeting_*` reducers through `run_receipted_command` with family
`F13` (`$1` mailbox, `$2` actor, `$3` operation). An unacknowledged COMMIT returns 503
plus `X-Operation-ID`. No reducer is added or changed.

Body decoding mirrors `httputil.DecodeJSON`: one JSON value, 1 MiB cap, every failure
including the cap is 400 `invalid JSON` (case-insensitive keys, last duplicate wins,
null leaves a zero value, timestamps strict RFC 3339).

Tests: `setjoin-gateway --test meet_recorded` (HTTP, committed rows, audits and
notifications against Go recordings in `tests/conformance/meet`), `--test meet_dispatch`
(executable mount, global and inventory kill switches).

## Qualification (#285)

The seven routes default ON/local-rust. `meet_recorded` replays 43 frozen-Go cases
(HTTP, committed rows, chat and core audits with independent chain verification,
`meet:`/`chat:` notifications) plus per-route changed-status mutants, planted SQL
mutants (no audit on create; no notify, double `change_seq` bump and no tenant filter
on lock) and both COMMIT-loss cuts. Native replay requires zero total and F13 Go proxy
counters. `meet_dispatch` runs the real executable: native, global kill, inventory
rollback (external `/api` mount and F13 counter retained), LiveKit unconfigured and
entitlement denial with Go absent (#406). Configured HS256/SM2 keys are shared
with identity (#331/#333); guest admission uses the shared program/route belt
and mailbox-less user proof (#406).

Recording: set `GOFREE_RECORD_GO_BINARY` and `GOFREE_GO_SOURCE`; the Go oracle gets
`LIVEKIT_*` through `go_oracle::start_named_with_env`. Cases and branch map:
[CASES](../../../tests/conformance/meet/CASES.md), [COVERAGE](../../../tests/conformance/meet/COVERAGE.md).
No accepted divergences. No workers move; Go's meet worker keeps running.

## Sub-router-a (#286)

The twelve `sub-router-a` routes default ON (kill switches unchanged). Gateway
`src/meet_livekit.rs` holds the peripherals: HS256 join tokens (the sole grant
builder; `u:` identities capped at 60 s, `canUpdateOwnMetadata` pinned false),
JSON twirp calls to RoomService/Egress (`CreateRoom`, `RemoveParticipant`,
`DeleteRoom`, `StopEgress`) and webhook verification. A peripheral call only
follows a committed reducer result and its failure is reported (502), never
rolled back. Authenticated routes keep the gate order above; `join`, `kick`,
`end`, `knock`, `requests/{reqId}` and the four `breakouts` routes call the
existing reducers through `run_receipted_command` (family `F13`); `join` runs
`meeting_join` then `meeting_get` as two statements of one receipted transaction
(`run_receipted_effect`: `meeting_get` is STABLE and would not see the join in one
statement), `end` and `knock` read their
follow-up rows in separate scoped reads exactly as Go does.

Unauthenticated: the guest lobby (`public/meet/{slug}/join-request` POST/GET) and
`POST /meet/webhook` have no caller identity; the SECURITY DEFINER reducers
self-scope by slug/secret and run as one autocommit statement (`exec.read`, no
receipt, no mailbox). Lobby gates: `feature.meet`, then `meet.guest_access` (create
only); no LiveKit gate. Poll strips `grant`, mints inside a per-process 15 minute
window (second layer; the reducer fence is the first) and sorts keys as Go's map
encoder does. Webhook: 1 MiB cap (413), bad/absent/expired token or digest (401,
also Go's answer for a body protojson refuses), unknown events and non-UUID rooms
(200). Egress info is projected to the fields the reducer reads (status, error,
file size/duration), omitting protojson defaults.

Tests: `--test meet_a_recorded` (frozen-Go goldens with fake LiveKit/Egress: every
SFU call is part of the observation; changed-status, silent-SFU and no-tenant-filter
mutants; COMMIT-loss for kick), `--test meet_a_dispatch` (executable, both kill
switches). Accepted gap, not golden-observable: protojson validates every field of
`WebhookEvent`; Rust validates only the consumed ones (a signed body with a
malformed sibling field is 200, Go answers 401).

## Sub-router-b (#287)

The seventeen `sub-router-b` routes default ON: recording and captions start/stop,
the eleven presentation routes (prepare to revoke plus the checkpoint read) and annotation commit/read.
Gateway `src/meet_b.rs` holds them (a child module of `meet.rs`); the crate only adds
reducer calls (no new reducer). Flag gates run before the path parses: recording
`feature.meet_recording` + `feature.drive`, captions `feature.meet_captions`, new-intent
presentation verbs and annotation commit `feature.meet_document_presentation` +
`feature.drive` (all default OFF, a miss is a plain 404). Drain routes (recording
stop, captions stop, presentation end/revoke, checkpoint and annotation reads) are never
flag-gated. A missing egress runtime or ASR URL is the 503 problem (`DELETE captions`
answers 204 instead, after clearing the flag).

Every write is one receipted reducer call (`run_receipted_command`, family `F13`); a
peripheral (Egress start/stop, ASR start/stop) only follows the committed fact.
Recording start is reducer, room lookup, Egress `StartRoomCompositeEgress`, then
`meeting_recording_bind_egress` (a failed or busy start binds `p_ok=false`, so the banner
rolls back); captions start rolls the flag back the same way. The staging key
`meet-egress/<id>-<room>.mp4` and the S3 sink (`S3_*`, scheme prepended exactly as Go
does) are server-composed. Presentation responses are the committed fact plus the
versioned `t:"presentation"` frame, omitted when Go's encoder would refuse it (14000
bytes, page range, annotation reference shape). The checkpoint read keeps Go's
per-process 5/s burst-2 budget (429 with a 1-30 s `Retry-After`).

Tests: `--test meet_b_recorded` (frozen-Go goldens with fake LiveKit/Egress and a fake
ASR bot; changed-status, silent-peripheral and no-tenant-filter mutants; COMMIT-loss for
the four start/stop reducers and prepare), `--test meet_b_dispatch` (executable, both
kill switches). Recorded Go facts: host/cohost bypass the generation fence on degrade,
recover, end and presenter; a non-participant sees `404` (anti-oracle), a plain member
`403`; the S3 endpoint is `http://` + `S3_ENDPOINT` even when it already names a scheme.

## Sub-router-c (#288)

Seven of the fifteen `sub-router-c` entries default ON: the four local-capture POSTs
(`local/lease`, `{rid}/heartbeat|stop|register`), the semantic `package` and `replay`
reads and `GET /admin/meet/recordings`. The four asrbot-listener routes belong to the
separate asrbot binary (#356, upstream `go-asrbot`, never promoted here) and the four
catch-alls (`/meet`, `/meet/`, `/rtc`, `/rtc/`) stay OFF like every other family's
catch-all: Go's mux answers anything unmatched, and `/rtc` is the SFU signal proxy.

Gateway `src/meet_c.rs` (a child of `meet.rs`). Local capture: all four are new intent
behind `feature.meet_local_recording` (OFF is a plain 404 before the path parses); the
two reads are never flag-gated. Lease, heartbeat and stop are one receipted reducer call
each (`meeting_local_capture_lease_*`, family `F13`); register validates the descriptor
exactly as Go does before the reducer (typed decode with folded keys and merged nested
objects, `MediaSegment.Validate` messages, recomputed coverage, then the canonical-JSON
sha256 seal: keys sorted, number literals verbatim, `integrityDigest` cleared to null)
and hands the reducer the received bytes. Descriptor refusals are the 403
`local-package-not-admitted` problem; a >1 MiB body is Go's 413. No peripheral is called.

Registry: it sits behind adminLimit and `drive.view` only (no `feature.meet`, entitlement
or LiveKit gate). A denial writes the `console.denied` audit row and answers the bare 403;
otherwise the worker credential (`MeetRoute::with_worker`, `DB_WORKER_DSN`, defaulting to
the request executor) reads at most 200 rows newest first (BYPASSRLS: the admin sees every
tenant by design), and `meet_recordings_list` is audited best effort after the read (a
failed audit never changes the 200). Timestamps are UTC `Z` (frozen Go formats in its
process zone; every deployment runs UTC). Query pairs follow `url.Values.Get`.

Tests: `--test meet_c_recorded` (frozen-Go goldens, changed-status mutants for all seven
routes, no-tenant-filter shadow-schema mutants for the six user routes, a no-audit mutant
for the registry, COMMIT-loss for the four reducers), `--test meet_c_dispatch`
(executable, both kill switches). Go quirks mirrored: a plain member's lease is 404 (row
security), heartbeat/stop/package for an unknown or foreign lease or recording are 409
(class conflict on BZ282/BZ278), and a double quote or backslash in a chat/meeting title
makes the audit hash cast to bytea fail (22P02, 500) in `meeting_create`.

## Mailbox-less guest admission (#406)

The HTTP adapter accepts live guest user proof after the shared program/route belt.
Its database scope carries the verified user without inventing a mailbox; reducer
membership and guest profile flags still decide reads/writes. Member scope is
unchanged. The shared guest-domain corpus records list success and guest-create
refusal through the executable with Go absent.

Meet entitlement-denial parity (#406): the adapter returns Go's typed Forbidden
problem and calls the existing one-statement `audit_app_blocked` helper. Full
audit policy writes one row per refusal; lean suppresses routine rows, as Go does.
The twelve-case shared corpus includes list/create/get and repeated requests.
An entitlement read failure denies, and audit failure remains best effort.

## Security fix (#378, owner-approved 2026-11-05)
`meeting_get`/`meeting_get_by_slug` (`reducers/meeting_read.sql`) return `roomName` and `ownerUserId` only to a caller related to the meeting (owner, participant, bound-channel member or knocker; `meeting_guest_read_allowed`), and `slug` only when related or resolved by that slug. Join stays org-open by id (ratified); an unrelated caller still gets the pre-join facts. Goldens `get-foreign` and `by_slug-foreign` re-baselined; mutant `sql:meeting-read-org-wide`.

## Security fix (#531 F1, owner-approved 2026-11-06)
`meeting_get_projection` also returns `chatChannelId` and `calendarEventId` only to a related caller (same rule as `roomName`/`ownerUserId`); `chatChannelMember` is unchanged. Meeting ids are sequential, so join-by-id stays enumerable: accepted risk, bounded by the gateway rate limit. Test `bins/gateway/tests/secfix8.rs`, mutant `sql:meet-ids-unrelated`.
