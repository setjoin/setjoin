# F13 golden-routes recordings (#285)

Every golden was recorded once from frozen Go (`GOFREE_GO_SOURCE`, production Go
unchanged since) behind the real front door by `setjoin-gateway --test meet_recorded`.
Go ran as an isolated process against the assigned disposable database with
`LIVEKIT_*` set to an unreachable address: none of these seven routes calls the
SFU. Replay unsets Go and serves the bundled ON inventory natively.

Fixtures: two accounts (owner, foreign), each seeded with one meeting through the
canonical `meeting_create` reducer. The role cases add the foreign account as a plain
participant of the owner's meeting. Observations: response, meeting/participant/chat
rows, chat and core audit rows (chains verified independently), and the four
`meet:`/`chat:` notification channels. Generated ids, slugs, room names and
timestamps are replaced by stable labels; user, meeting and channel ids are
replaced only under keys that carry that identity.

| Route | Cases (floor kinds in bold) |
| --- | --- |
| `GET /meet` | **success**, **foreign** (other member's list), **invalid** (ignored query), disabled, unconfigured |
| `GET /meet/{id}` | **success**, **foreign** (org-open read), **invalid** (non-numeric id), missing |
| `GET /meet/by-slug/{slug}` | **success**, **foreign**, **invalid** (unknown slug) |
| `POST /meet` | **success**, **foreign** (another member's chat channel), **invalid** (malformed JSON), **repeat**, empty title, window, time, type, trailing/duplicate/case-folded JSON, unowned calendar event, disabled |
| `POST /meet/{id}/lock` / `settings` / `role` | **success**, **foreign** (not host or cohost), **invalid** (bad id and body), **repeat**, bad body, missing meeting; role also bad role |

Planted mutants (private schema on the request connection, never the canonical
definitions): changed status for each route, no audit (`POST /meet`), no notify,
double state bump (an extra channel `change_seq` write) and no tenant filter
(every actor reads as host) on `POST /meet/{id}/lock`. The Go-free replay rejects
each at the named JSON pointer.

No accepted divergences: `divergences.json` is empty.

# F13 sub-router-a recordings (#286)

Recorded from the same frozen Go build by `setjoin-gateway --test meet_a_recorded`.
Go runs with `LIVEKIT_*` and `MEET_EGRESS_ENABLED` pointing at a fake twirp endpoint
(`tests/common/meet_peripherals.rs`) that records every `CreateRoom`,
`RemoveParticipant`, `DeleteRoom` and `StopEgress` call (Go speaks protobuf, Rust
JSON; both reduce to the same canonical fields plus the verified grant). Join tokens
are replaced by their HS256-verified claims (time claims reduced to a TTL), so a
mutant that widens a grant or skips the 60 s `u:` cap fails the golden.

Fixtures: two accounts, a seeded meeting each; cases add participants, a locked,
banned or ended meeting, open breakouts, pending/admitted/denied join requests and
`active`/`stopping` recordings through the canonical reducers or plain rows.
Observations add breakouts, join requests, lobby mint fences and recordings.

| Route | Cases |
| --- | --- |
| `POST /meet/{id}/join` | **success**, **foreign** (member of another's meeting), **invalid**, **repeat**, missing, locked, banned, ended, redirect (assigned breakout: 24 h child room), livekit_fail (502), no_asr, disabled, unconfigured |
| `POST /meet/{id}/kick` | **success**, **foreign**, **invalid**, **repeat**, bad_body, missing, breakout (evicts from the child room), livekit_fail, commit_before/after (replay only) |
| `POST /meet/{id}/end` | **success**, **foreign**, **invalid**, **repeat** (409), recording (StopEgress first), breakouts (child rooms then parent), livekit_fail |
| `POST /meet/{id}/knock` | **success**, **foreign**, **invalid**, **repeat**, missing |
| `POST /meet/{id}/requests/{reqId}` | **success** (admit), **foreign**, **invalid**, **repeat**, deny, bad_action, bad_request, missing |
| `POST /meet/{id}/breakouts` | **success**, **foreign**, **invalid**, **repeat**, zero, disabled |
| `POST /meet/{id}/breakouts/assign` | **success**, **foreign**, **invalid**, **repeat**, unknown, main, livekit_fail |
| `POST /meet/{id}/breakouts/close` | **success**, **foreign**, **invalid**, **repeat**, livekit_fail |
| `POST /meet/{id}/breakouts/join` | **success**, **foreign**, **invalid**, **repeat**, livekit_fail |
| `POST /public/meet/{slug}/join-request` | **success**, **foreign** (unknown slug), **invalid**, **repeat**, trailing, oversize, not_allowed, guest_off, disabled |
| `GET /public/meet/{slug}/join-request/{id}` | **success** (admitted, token), **foreign** (wrong secret), **invalid**, pending, denied, repeat, disabled |
| `POST /meet/webhook` | **success**, **foreign** (wrong secret), **invalid** (duplicate field), **repeat**, no_auth, bad_digest, expired, unknown_event, non_uuid, oversize, left, egress_ended, egress_failed, egress_no_info |

Planted mutants: changed status for every route; silent SFU (reducer runs, no
peripheral call) for the seven routes that call it; no tenant filter (every actor
reads as host) on `kick` and `requests/{reqId}` (the latter also drops the row-level filter on the request row with an unfiltered view).

No accepted golden divergences. Known gap: see the crate DOX (webhook sibling-field
validation).

# F13 sub-router-b recordings (#287)

Recorded from the same frozen Go build by `setjoin-gateway --test meet_b_recorded`.
Go runs with `LIVEKIT_*`, `MEET_EGRESS_ENABLED`, `S3_ENDPOINT=http://127.0.0.1:9` and an
`ASR_URL` pointing at fakes (`tests/common/meet_peripherals.rs`): the twirp fake records
`StartRoomCompositeEgress` (decoded from Go's protobuf, or Rust's JSON, to one canonical
request with the S3 sink) plus the other room and egress calls with their verified grants;
the ASR fake records `/start` (bot token replaced by its verified claims) and `/stop`
with the bearer. Fixtures: a live meeting (`meeting_join` then the SFU's `room_started`
fact), a plain member (joined), a Drive file with two versions for the host and one for
the member, and presentations driven to PREPARING/READY/ACTIVE/DEGRADED/ENDED (and with an
annotation, or the member presenting) through the canonical reducers. Observations add
recordings, presentations, their events and annotation snapshots, plus captions settings.

| Route | Cases |
| --- | --- |
| `POST /meet/{id}/recording` | busy, disabled, drive_off, egress_fail, guest, invalid_id, member, missing, no_egress, not_live, repeat, stranger, success |
| `DELETE /meet/{id}/recording` | egress_fail, flag_off, invalid_id, member, no_egress, none, repeat, stranger, success |
| `POST /meet/{id}/captions` | already_on, asr_fail, busy, disabled, invalid_id, member, missing, no_asr, repeat, stranger, success |
| `DELETE /meet/{id}/captions` | already_off, asr_fail, flag_off, invalid_id, member, no_asr, repeat, stranger, success |
| `POST /meet/{id}/presentation` | bad_digest, bad_json, bad_type, disabled, drive_off, duplicate, ended, gone, invalid_id, member, missing, no_rights, not_live, repeat, stranger, success |
| `POST .../presentation/{pid}/ready` | bad_digest, bad_json, disabled, drive_off, invalid_id, invalid_pid, member, missing_pres, null_digest, repeat, stranger, success, wrong_state |
| `POST .../presentation/{pid}/start` | bad_json, disabled, invalid_id, member, missing_pres, repeat, stale, stranger, success, wrong_state |
| `POST .../presentation/{pid}/page` | as_presenter, bad_json, disabled, huge, invalid_pid, member, missing_field, out_of_range, repeat, stale_gen, stale_seq, stranger, success, wrong_state |
| `POST .../presentation/{pid}/presenter` | bad_json, bad_target, disabled, grant, member, repeat, stale_gen, stranger, takeover, wrong_state |
| `POST .../presentation/{pid}/source` | bad_digest, bad_json, disabled, gone, member, no_rights, repeat, same_version, stale_gen, stale_seq, stranger, success |
| `POST .../presentation/{pid}/degrade` | bad_json, disabled, member, no_reason, repeat, stale_gen, stale_presenter, stranger, success, wrong_state |
| `POST .../presentation/{pid}/recover` | bad_json, disabled, member, repeat, stale_gen, stranger, success, wrong_state |
| `POST .../presentation/{pid}/end` | already_ended, bad_json, cancel, degraded, flag_off, invalid_id, member, missing_pres, repeat, stale_gen, stale_presenter, stranger, success |
| `POST .../presentation/{pid}/revoke` | already_ended, bad_json, flag_off, invalid_id, member, no_reason, repeat, stranger, success |
| `GET .../presentation/{pid}/checkpoint` | annotated, ended, flag_off, invalid_id, invalid_pid, member, missing_pres, stranger, success, throttled |
| `POST .../presentation/{pid}/annotation` | bad_json, both, clear, disabled, empty, member, missing_field, neither, oversize, repeat, snapshot, stale_gen, stale_seq, stranger, unicode, wrong_state |
| `GET .../presentation/{pid}/annotation` | flag_off, invalid_id, member, missing_pres, none, snapshot, stranger |

Replay-only (no Go recording; COMMIT lost on the wire): `rec_start`, `rec_stop`,
`cap_start`, `cap_stop` and `prepare` each with `commit_before` (nothing written) and
`commit_after` (the receipt resolves the committed fact; a start never reaches its
peripheral). Mutants per route: changed status, silent peripheral (the four start/stop
routes) and no tenant filter (a private schema shadows `meeting_member_role` and
`meeting_attendee_role`, plus unfiltered views for the two reads).

Findings mirrored from Go: host and cohost bypass the generation fence on degrade,
recover, end and presenter (`stale_gen` answers 200; only a presenter is fenced, see
`stale_presenter`); a plain member cannot lock the meeting row for `prepare` or
recording start (404, not 403); a non-participant gets 404 on every presentation route;
`pageIndex` beyond int4 is a 500 before the reducer; the S3 endpoint handed to Egress is
`http://` + `S3_ENDPOINT` even when it already names a scheme.

No accepted divergences: `divergences.json` is empty.

## Sub-router-c (#288)

| Route | Recorded cases |
|---|---|
| `POST /meet/{id}/local/lease` | bad_json, bad_surface, bad_type, both_surfaces, cohost, dup_surface, ended, flag_off, guest, high_seconds, invalid_id, long_device, low_seconds, max_seconds, member, min_seconds, missing, no_api, no_device, no_producer, no_surfaces, not_live, null_seconds, other_device, repeat, stranger, success, unicode_device |
| `POST .../local/{rid}/heartbeat` | after_stop, bad_json, bad_state, bad_type, default_state, disk, ended, expired, flag_off, invalid_id, invalid_rid, member, missing_rec, regress, repeat, stale_gen, stopped_frame, stopping, stranger, success, zero_seq |
| `POST .../local/{rid}/stop` | already, bad_json, bad_reason, bad_type, cohost, flag_off, gen_match, invalid_id, invalid_rid, member, missing_rec, repeat, revoked, stale_gen, stranger, success |
| `POST .../local/{rid}/register` | array_body, bad_json, bad_observed_sha, bad_surface, bad_type, capturing_segment, digest_absent, digest_null, digest_wrong, dup_surface, ends_early, fabricated_coverage, failed_segment, flag_off, flat_interval, gap_drift, interrupted, invalid_id, invalid_rid, meeting_mismatch, member, missing_rec, mode, no_end, no_mime, no_platform, no_reason, no_recording_id, no_segments, no_size, no_start, no_surfaces, nonhex_sha, not_stopped, null_body, number_literal, overlap, oversize, policy, recording_mismatch, registered_no_time, registered_state, repeat, reregister, schema, seq_zero, short_sha, state_bad, stranger, success, unicode_text, unknown_segment_state, uploaded, uploaded_absent, wall_backwards |
| `GET .../semantic/{rid}/package` | active, flag_off, invalid_id, invalid_rid, member, missing_rec, registered, stopped, stranger |
| `GET .../semantic/{rid}/replay` | active, flag_off, invalid_id, invalid_rid, member, missing_rec, registered, stopped, stranger |
| `GET /admin/meet/recordings` | bad_meeting, both, denied, empty_params, encoded, features_off, meeting, no_match, non_admin, repeat, scoped, semicolon, state, success, unknown_meeting |

Replay-only (no Go recording; COMMIT lost on the wire): `lease`, `heartbeat`, `lstop` and
`register` each with `commit_before` (nothing written) and `commit_after` (the receipt resolves
the committed fact). The registry's audit is best effort in Go, so it has no COMMIT-loss lane.
Mutants per route: changed status (all seven), no tenant filter (a private schema shadows
`meeting_member_role`, `meeting_attendee_role`, `meeting_require_authority`, the lease lock and the
owner-or-host check) and, for the registry, a no-op `audit_write`.

Findings mirrored from Go: a plain member's lease acquire is 404 (row security); heartbeat, stop,
register, package and replay for an unknown or foreign lease/recording are 409 (class conflict on
BZ282/BZ278, never 404); the descriptor is validated (403 `local-package-not-admitted`) before the
reducer sees it, and the seal is sha256 over key-sorted canonical JSON with number literals verbatim;
the registry has no `feature.meet`, entitlement or LiveKit gate and is not audited when denied
(a `console.denied` row is written instead); a double quote or backslash in a meeting title makes
`meeting_create` fail in the audit hash (bytea cast, 22P02).

