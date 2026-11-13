package reducererr

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// contract_test.go — the GOLDEN WIRE MATRIX for the BZ error contract (arch c6).
//
// One row per BZ code (× HINT slug for the dual-use codes): the HTTP status,
// JMAP method-error type, and detail policy the code projects to on the wire.
// This is the consumed contract every gateway handler routes through — a change
// to any row is a wire-behavior change and must be deliberate.
//
// detail column legend:
//
//	"message"  — pgErr.Message passes through as the wire detail (allowlisted)
//	"hint"     — pgErr.Hint (else Message) passes through (the CA family)
//	"fixed:…"  — a fixed per-code string (the former jmap hand-rolled wording)
//	"class"    — the per-class fallback string (never the raw SQLERRM)
//
// Reconciliation record (c6): before this contract, the statuses/types for
// BZ043/064/085/088/090/091/092/095/099(last_global)/100/104/106/108/109 lived
// as hand-rolled pgErr.Code switches in the owning handlers, DIVERGENT from
// reducererr's classification. The handler semantics won (each handler was the
// only live wire path for its code); every reconciled row carries a comment
// naming the handler that owned it and the classification it replaced.
type contractRow struct {
	code     string
	hint     string // optional HINT (dual-use slug disambiguation)
	status   int    // Classify(err).HTTPStatus()
	jmapType string // Classify(err).JMAPError(); "" = serverFail fallback
	detail   string // Detail(err) policy (see legend)
}

var contractMatrix = []contractRow{
	// ── storage / send quota ──────────────────────────────────────────────
	{"BZ001", `{"type":"over_quota"}`, 507, "overQuota", "fixed:over quota"},
	// BZ001 calendar slugs are ClassUnknown here BY DESIGN; the calendar JMAP
	// handlers own that meaning (jmap/calendar_a3.go maps it to forbidden via
	// IsCode — a call-site-contextual dual-use, not a projection).
	{"BZ001", `{"type":"acl_forbidden"}`, 500, "", "class"},
	{"BZ009", "", 507, "overQuota", "fixed:over quota"},
	{"BZ004", "", 507, "overQuota", "fixed:sending quota exceeded"},
	// BZ148 — drive: space quota / chunk upload-limit exceeded. Class fallback
	// here; mailserver/internal/drive/problem.go overrides the WIRE status to
	// 413 (Request Entity Too Large) for the drive REST surface — this row pins
	// the underlying reducererr projection (507), not the drive override.
	{"BZ148", "", 507, "overQuota", "class"},

	// ── forbidden / policy / ownership / SoD ──────────────────────────────
	{"BZ002", "", 403, "forbidden", "fixed:access denied"},
	{"BZ003", "", 403, "forbidden", "fixed:not authorized to send from this address"},
	{"BZ005", "", 403, "forbidden", "fixed:message blocked by policy"},
	// BZ015 is dual-purpose (litigation-hold delete trigger / app-password cap).
	// user/app_passwords.go keeps its bespoke 409 body via IsCode — reconciling
	// the class to Conflict would flip the litigation-hold JMAP meaning.
	{"BZ015", "", 403, "forbidden", "class"},
	{"BZ045", "", 403, "forbidden", "fixed:contact group not owned by caller"},
	{"BZ052", "", 403, "forbidden", "class"},
	{"BZ061", "", 403, "forbidden", "message"},
	{"BZ065", "", 403, "forbidden", "message"},
	{"BZ066", "", 403, "forbidden", "message"},
	{"BZ069", "", 403, "forbidden", "message"},
	{"BZ071", "", 403, "forbidden", "class"},
	{"BZ107", "", 403, "forbidden", "message"},
	// BZ116 — sharing default auth ladder (lacks sharing.manage / not the owner).
	{"BZ116", "", 403, "forbidden", "message"},
	// BZ140 — drive: insufficient role / space-creation gate. Class fallback.
	{"BZ140", "", 403, "forbidden", "class"},
	// BZ161/163/164/166/167 — chat: not owner/admin, not a member, announcement
	// post by a non-admin, broadcast by a non-owner/admin, not the author.
	// Class fallback only — no reducer text passthrough (A1 Task 8).
	{"BZ161", "", 403, "forbidden", "class"},
	{"BZ163", "", 403, "forbidden", "class"},
	{"BZ164", "", 403, "forbidden", "class"},
	{"BZ166", "", 403, "forbidden", "class"},
	{"BZ167", "", 403, "forbidden", "class"},

	// ── not found ─────────────────────────────────────────────────────────
	{"BZ006", "", 404, "accountNotFound", "fixed:accountId does not match an existing account"},
	{"BZ007", "", 404, "notFound", "fixed:recipient not found"},
	{"BZ019", "", 404, "notFound", "class"},
	{"BZ020", "", 404, "notFound", "class"},
	// BZ021/BZ022: user/undo_send.go keeps a bespoke string-match map
	// (BZ021→404, BZ022→410 Gone) — see the guard allowlist; user/recall.go
	// routes BZ022 through this class (409). Ambiguous pair, left as-is.
	{"BZ021", "", 404, "notFound", "class"},
	{"BZ030", "", 404, "notFound", "class"},
	{"BZ033", "", 404, "notFound", "class"},
	{"BZ038", "", 404, "notFound", "fixed:reminder not found"},
	{"BZ042", "", 404, "notFound", "fixed:quick step not found"},
	{"BZ049", "", 404, "notFound", "class"},
	{"BZ051", "", 404, "notFound", "class"},
	// BZ053 — mdm_device_wipe_arm: wipe target not found / out of scope. Class
	// fallback ON PURPOSE: 404-indistinguishable, no existence oracle; the
	// engine maps it to the same "device not found" ValidationError pair.
	{"BZ053", "", 404, "notFound", "class"},
	{"BZ060", "", 404, "notFound", "message"},
	{"BZ074", "", 404, "notFound", "class"},
	{"BZ084", "", 404, "notFound", "class"},
	{"BZ086", "", 404, "notFound", "hint"},
	// BZ091 — RECONCILED: 404 per admin_ca_import_export.go caImportErrorStatus
	// (was ClassInvalidArguments/400 in the old reducererr table).
	{"BZ091", "", 404, "notFound", "hint"},
	{"BZ099", `{"type":"not_found","id":7}`, 404, "notFound", "fixed:policy not found"},
	// BZ101: user/devices.go treats it as idempotent success (200) via IsCode;
	// the class below is what any other consumer would project.
	{"BZ101", "", 404, "notFound", "class"},
	{"BZ103", "", 404, "notFound", "class"},
	{"BZ112", "", 404, "notFound", "class"},
	{"BZ113", "", 404, "notFound", "class"},
	// BZ114 — sharing: mailbox not owned / grantee or default row not found.
	// Class fallback ON PURPOSE: 404-indistinguishable (no ownership oracle).
	{"BZ114", "", 404, "notFound", "class"},
	// BZ118 — calendar_subscription_refresh: subscription not found / the given
	// calendar_id is not the one it owns. Class fallback ON PURPOSE, same
	// no-ownership-oracle posture as BZ113/BZ114.
	{"BZ118", "", 404, "notFound", "class"},
	// BZ121 — rules_apply_retroactive: rule not found / not owned / transport.
	{"BZ121", "", 404, "notFound", "class"},
	// BZ125 — approval_request_cancel: not found / not requester / not pending.
	// Class fallback ON PURPOSE: 404-indistinguishable, no ownership oracle.
	{"BZ125", "", 404, "notFound", "class"},
	// BZ130 — task_lists.sql: list not owned / not a member. Class fallback ON
	// PURPOSE: 404-indistinguishable (no membership oracle), shared task lists Phase 1.
	{"BZ130", "", 404, "notFound", "class"},
	// BZ132 — task_list_tasks.sql / tasks_assigned.sql: not a list member / task
	// not assigned to caller. Same no-oracle posture as BZ130.
	{"BZ132", "", 404, "notFound", "class"},
	// BZ134 — self-service booking pages (feature #6): page not found / disabled
	// / not owned. Class fallback only — no reducer text passthrough (public
	// unauth surface, minimize disclosure).
	{"BZ134", "", 404, "notFound", "class"},
	// BZ139 — drive: object not found / not a member. Class fallback ON
	// PURPOSE: 404-indistinguishable, no membership oracle (BZ130 posture).
	{"BZ139", "", 404, "notFound", "class"},
	// BZ169 — chat: reaction target message not found / soft-deleted (distinct
	// from BZ163 membership). BZ170 — chat: chat_channel_join on a private or
	// nonexistent channel, deliberately 404-indistinguishable (anti-oracle,
	// same posture as BZ139). Class fallback only (A1 Task 8).
	{"BZ169", "", 404, "notFound", "class"},
	{"BZ170", "", 404, "notFound", "class"},
	// BZ171 — chat: chat_message_send/edit/delete against an archived
	// (read-only) channel. Class fallback, same posture as the rest of the
	// A1 forbidden band (BZ161/163/164/166/167).
	{"BZ171", "", 403, "forbidden", "class"},
	// BZ173 — chat A2: chat_message_send's reducer-defense when attachments
	// are present but feature.drive is off (route gate is primary). BZ175 —
	// drive_member_grant/drive_node_trash|move|rename/drive_file_put_version:
	// chat-bound space rejects ad-hoc member grants / chat-attached node is
	// immutable via Drive. Class fallback only, same posture as the rest of
	// the chat forbidden band.
	{"BZ173", "", 403, "forbidden", "class"},
	{"BZ175", "", 403, "forbidden", "class"},
	// BZ176 — chat A3 QoL: chat_pin_toggle pin/unpin permission (a plain
	// channel member, not owner/admin, may not pin/unpin in a CHANNEL; DMs/
	// group-DMs are all-member so this never fires there). Class fallback
	// only (Task 3).
	{"BZ176", "", 403, "forbidden", "class"},
	{"BZ081", "", 404, "notFound", "hint"},
	{"BZ081", `{"type":"bad_outcome","outcome":"x"}`, 400, "invalidArguments", "class"},

	// ── invalid arguments ─────────────────────────────────────────────────
	{"BZ040", "", 400, "invalidArguments", "message"},
	{"BZ041", "", 400, "invalidArguments", "message"},
	{"BZ031", "", 400, "invalidArguments", "class"},
	{"BZ036", "", 400, "invalidArguments", "class"},
	{"BZ037", "", 400, "invalidArguments", "class"},
	{"BZ039", "", 400, "invalidArguments", "fixed:snooze time must be in the future"},
	// BZ043 — RECONCILED: invalidArguments per jmap/quicksteps.go quickStepError
	// (was ClassForbidden/403/forbidden in the old reducererr table).
	{"BZ043", "", 400, "invalidArguments", "message"},
	{"BZ044", "", 400, "invalidArguments", "class"},
	// BZ046/BZ047: user/auto_reply.go writes its own fixed 400 body via IsCode
	// (status matches this class).
	{"BZ046", "", 400, "invalidArguments", "class"},
	{"BZ047", "", 400, "invalidArguments", "class"},
	// BZ119 — approval delegation: invalid window / invalid delegate. user/
	// approval_delegation.go writes its own fixed 400 body via IsCode (status matches
	// this class).
	{"BZ119", "", 400, "invalidArguments", "class"},
	{"BZ050", "", 400, "invalidArguments", "class"},
	{"BZ055", "", 400, "invalidArguments", "class"},
	{"BZ056", "", 400, "invalidArguments", "class"},
	// BZ057 — mdm_device_wipe_arm: wipe level outside the account/device
	// vocabulary (defense in depth; the gateway validates before calling).
	{"BZ057", "", 400, "invalidArguments", "class"},
	{"BZ070", "", 400, "invalidArguments", "class"},
	{"BZ072", "", 400, "invalidArguments", "class"},
	{"BZ076", "", 400, "invalidArguments", "class"},
	{"BZ078", "", 400, "invalidArguments", "class"},
	{"BZ082", "", 400, "invalidArguments", "hint"},
	// BZ085 — RECONCILED: 400 per admin_conditional_access.go caErrorStatus
	// ("unknown template slug" = a bad argument; was ClassNotFound/404 here).
	{"BZ085", "", 400, "invalidArguments", "hint"},
	{"BZ094", "", 400, "invalidArguments", "hint"},
	{"BZ097", "", 400, "invalidArguments", "hint"},
	{"BZ098", "", 400, "invalidArguments", "hint"},
	// BZ104 — RECONCILED: 400 per admin_jit.go mapJITErr (kept TODAY's handler
	// status; was ClassForbidden/403 in the old reducererr table).
	{"BZ104", "", 400, "invalidArguments", "message"},
	{"BZ105", "", 400, "invalidArguments", "message"},
	// BZ115/BZ117 — sharing: invalid delegate permission level / invalid
	// scope-audience-level combination (messages authored for the dialogs).
	{"BZ115", "", 400, "invalidArguments", "message"},
	{"BZ117", "", 400, "invalidArguments", "message"},
	// BZ120 — rules_apply_retroactive: invalid window / missing mailbox.
	{"BZ120", "", 400, "invalidArguments", "class"},
	// BZ122 — vip_sender_set: empty sender email (QoL #10a).
	{"BZ122", "", 400, "invalidArguments", "message"},
	// BZ123 — jmap_calendar_event_set_occurrence: recurrenceId is not a real
	// occurrence of the series (typo/timezone-shift guard).
	{"BZ123", "", 400, "invalidArguments", "message"},
	// BZ124 — hr_request_create: leave/expense form validation.
	{"BZ124", "", 400, "invalidArguments", "message"},
	// BZ126 — hr_request_create: receipt_sha256 not found in blobs.
	{"BZ126", "", 400, "invalidArguments", "message"},
	// BZ131 — task_lists.sql: invalid name / unresolvable member email / roster
	// cap / cannot remove the owner (shared task lists Phase 1).
	{"BZ131", "", 400, "invalidArguments", "message"},
	// BZ133 — task_list_tasks.sql / tasks_assigned.sql: assignee not a list
	// member / bad status value / no primary mailbox.
	{"BZ133", "", 400, "invalidArguments", "message"},
	// BZ135 — self-service booking pages (feature #6): invalid date range /
	// missing required answer / event-creation failure.
	{"BZ135", "", 400, "invalidArguments", "class"},
	// BZ160 — chat: notify_chat_state's internal-seam NULL-channel guard
	// (never a real user request path; class fallback only, A1 Task 8).
	{"BZ160", "", 400, "invalidArguments", "class"},
	// BZ172 — chat A2: chat_message_send's attachment-payload guard (>8 per
	// message / bad name-size-manifest shape). Class fallback only.
	{"BZ172", "", 400, "invalidArguments", "class"},

	// ── state conflicts ───────────────────────────────────────────────────
	{"BZ022", "", 409, "", "class"},
	{"BZ048", "", 409, "", "class"},
	// BZ054 — mdm_device_wipe_arm: wipe already executed / armed at another
	// level. Class fallback; the engine maps it to the fielded 409 contract.
	{"BZ054", "", 409, "", "class"},
	{"BZ062", "", 409, "", "message"},
	{"BZ063", "", 409, "", "message"},
	// BZ064 — RECONCILED: 409 per admin/admin_protection.go mapProtectionErr
	// (self-lock / last-Super-Admin; was ClassForbidden/403 here).
	{"BZ064", "", 409, "", "message"},
	{"BZ075", "", 409, "", "class"},
	{"BZ077", "", 409, "", "class"},
	{"BZ080", "", 409, "", "hint"},
	{"BZ087", "", 409, "", "hint"},
	{"BZ093", "", 409, "", "hint"},
	// BZ095 — RECONCILED: 409 per admin/admin_device_lockdown.go dlErrorStatus
	// ("device state changed — refresh and retry"; was ClassNotFound/404 here).
	// The SYNTHETIC 403+BZ095 body from middleware/device_trust_gate.go is a
	// separate non-pgErr surface (the SPA deviceBlock contract) — untouched.
	{"BZ095", "", 409, "", "hint"},
	// BZ099/last_global — RECONCILED: 409 per admin/admin_offline.go
	// DeletePolicy (was flat ClassNotFound/404 here; slug-disambiguated now).
	{"BZ099", `{"type":"last_global"}`, 409, "", "message"},
	// BZ100 — RECONCILED: 409 per admin/admin_offline.go deviceAction
	// (was ClassNotFound/404 here).
	{"BZ100", "", 409, "", "message"},
	{"BZ102", "", 409, "", "hint"},
	// BZ106 — RECONCILED: 409 per approval/handler.go mapApprovalErr
	// (SoD self-decide; was ClassForbidden/403 here).
	{"BZ106", "", 409, "", "message"},
	// BZ108 — RECONCILED: 409 per approval/handler.go mapApprovalErr
	// (was ClassNotFound/404 here).
	{"BZ108", "", 409, "", "message"},
	{"BZ110", "", 409, "", "message"},
	{"BZ111", "", 409, "", "class"},
	// BZ136/BZ137 — self-service booking pages (feature #6): requested slot no
	// longer open (double-booking / confirm-time re-check) and verify/cancel
	// token invalid, expired, or already used. Class fallback only.
	{"BZ136", "", 409, "", "class"},
	{"BZ137", "", 409, "", "class"},
	// BZ142/BZ143/BZ145/BZ147 — drive: classification/compliance downgrade,
	// cross-space move, immutable (WORM/audit append-only), and duplicate live
	// name in a folder. Class fallback only — no reducer text passthrough.
	{"BZ142", "", 409, "", "class"},
	{"BZ143", "", 409, "", "class"},
	{"BZ145", "", 409, "", "class"},
	// BZ146 — drive: export grant invalid (opaque) / WORM lock pending
	// (transient). Class fallback only, same tier as BZ145/BZ147/BZ149.
	{"BZ146", "", 409, "", "class"},
	{"BZ147", "", 409, "", "class"},
	// BZ149/BZ150 — drive P4 versioning/locks. This row pins the underlying
	// reducererr projection (409, like every drive conflict code); drive/problem.go
	// overrides the WIRE status for BZ149 to 423 Locked (the BZ148/413 precedent).
	{"BZ149", "", 409, "", "class"},
	{"BZ150", "", 409, "", "class"},

	// ── unprocessable (422) ───────────────────────────────────────────────
	// BZ088/BZ090/BZ092 — RECONCILED: 422 per admin_ca_import_export.go
	// caImportErrorStatus (semantically-bad import doc ≠ malformed request;
	// were ClassInvalidArguments/400 in the old reducererr table).
	{"BZ088", "", 422, "", "hint"},
	{"BZ090", "", 422, "", "hint"},
	{"BZ092", "", 422, "", "hint"},
	// BZ109 — RECONCILED: 422 per approval/handler.go mapApprovalErr
	// (spec-reserved "no approver resolved"; was unclassified→500 here).
	{"BZ109", "", 422, "", "message"},
	// BZ141/BZ144 — drive: invalid argument / manifest shape / gxp knobs, and
	// manifest chunk not proven (anti-oracle). Class fallback only.
	{"BZ141", "", 422, "", "class"},
	{"BZ144", "", 422, "", "class"},
	// BZ162/165/168 — chat: bad channel-create/DM/member-add args, a missing/
	// cross-channel/soft-deleted reply parent, and an empty or >64KiB message
	// body. Class fallback only — no reducer text passthrough (A1 Task 8).
	{"BZ162", "", 422, "", "class"},
	{"BZ165", "", 422, "", "class"},
	{"BZ168", "", 422, "", "class"},
	// BZ178 — chat A3 QoL: chat_message_send voice durationMs over the
	// 300000ms cap. Class fallback only (Task 6).
	{"BZ178", "", 422, "", "class"},
	// BZ179 — chat A3 QoL: chat_schedule_message/chat_scheduled_cancel
	// scheduled-send invalid (bad fireAt / not-pending-or-not-yours cancel).
	// Class fallback only (Task 2).
	{"BZ179", "", 422, "", "class"},
	// BZ177 — chat A3 QoL: chat_poll_vote/chat_poll_close/chat_poll_results
	// "poll invalid" (poll/option not found, anchor message soft-deleted, or
	// already closed). Class fallback only (Task 9). The wrong-actor close
	// case reuses BZ161 (forbidden), not this code — see reducererr.go.
	{"BZ177", "", 422, "", "class"},
	// BZ185-BZ190 — Meet B1 (meeting_*.sql, notify_meet_state.sql). Class
	// fallback only (Task 2) — no reducer-text passthrough.
	{"BZ185", "", 404, "notFound", "class"},
	{"BZ186", "", 403, "forbidden", "class"},
	{"BZ187", "", 403, "forbidden", "class"},
	{"BZ188", "", 422, "", "class"},
	{"BZ189", "", 422, "", "class"},
	{"BZ190", "", 409, "", "class"},
	// BZ191 — Chat A4a Task 2: chat_access_audit unknown action (closed
	// catalog, drive BZ141 genre). Class fallback only.
	{"BZ191", "", 422, "", "class"},
	// BZ192/BZ193 — Chat A4a (V126 triggers): compliance no-downgrade and WORM
	// message/revision immutability. Class fallback only.
	{"BZ192", "", 409, "", "class"},
	{"BZ193", "", 409, "", "class"},
	// BZ194 — Chat A4a: legal hold blocks destruction (trg_chat_message_hold_fn,
	// same 403/forbidden genre as BZ015). Class fallback only.
	{"BZ194", "", 403, "forbidden", "class"},
	// BZ195 — Chat A4a: invalid compliance arguments (bad retention days, hold
	// conflict/no-op, invalid classification transition). Class fallback only.
	{"BZ195", "", 422, "", "class"},
	// BZ196 — Chat A4a Task 10: per-user chat send rate exceeded
	// (chat_message_send's per-minute counter). Same ClassSendQuota genre as
	// BZ004 (507/overQuota); class fallback only — no detailPass/detailFixed
	// entry, so the retryAfterSeconds HINT stays a raw pgErr fact, not a wire
	// field (Task 10 registers no Problem-struct extension for it).
	{"BZ196", "", 507, "overQuota", "class"},
	// BZ197/BZ198 — Chat A4b oversight: invalid oversight arguments (bad hold
	// scope/query/target, hold not found/already released) and eDiscovery
	// case not open (mutation/read against a closed ediscovery_cases row).
	// Class fallback only (Task 1's sole registration; Tasks 2/3/4 only RAISE).
	{"BZ197", "", 422, "", "class"},
	{"BZ198", "", 409, "", "class"},
	// BZ199/BZ200 — Meet B2 recording: guest⇄recording exclusion (both
	// arms) and recording state conflict. Class fallback only (Task 1's
	// sole registration; Tasks 2/3/4 only RAISE).
	{"BZ199", "", 403, "forbidden", "class"},
	{"BZ200", "", 409, "", "class"},
	// BZ201 — Meet B3 QoL: breakout invalid, the anti-oracle lump (not found
	// / not open / foreign to the meeting / target unassignable / an open
	// set already exists). Class fallback only (Task 1's sole registration;
	// Task 2 only RAISEs, Task 4 owns the meet bzSlug row).
	{"BZ201", "", 422, "", "class"},
	// BZ202 — Pillar C0 federation spike (E2 crux): federation_apply_inbound
	// sequence-gap guard (p_peer_seq > last_applied_seq+1) — the receiver
	// pauses the stream and sends a replay_req frame instead of skipping
	// ahead. Class fallback only (this reducer's sole registration site;
	// spike code, mailserver/sql/reducers/federation_apply_inbound.sql).
	{"BZ202", "", 409, "", "class"},
	// BZ203 — Pillar C0 federation spike (E4): federation_peer_authorize's
	// local refusal gate (not allow-listed/enabled, or scope mismatch). Class
	// fallback only (this reducer's sole registration site; spike code,
	// mailserver/sql/reducers/federation_peer_authorize.sql).
	{"BZ203", "", 403, "forbidden", "class"},
	// BZ204 — Pillar C1 Task 2: federation_dm_ensure's local refusal gate
	// (DM-ensure target peer domain not allow-listed/enabled) — a distinct
	// code from BZ203's wire-handshake refusal, same underlying check
	// (federation_peer_authorize), different caller. Class fallback only
	// (this reducer's sole registration site; mailserver/sql/reducers/
	// federation_dm_ensure.sql). BZ205 is reserved for Task 7's backpressure
	// cap — not registered here.
	{"BZ204", "", 403, "forbidden", "class"},
	// BZ206 — Pillar C1 Task 2: chat_message_send's federated-branch refuse
	// — feature.federation OFF (the BZ173 toggle-refuse pattern) or a body
	// over the 64KiB poison cap mirrored from the inbound applier. Class
	// fallback only (this reducer's sole registration site;
	// mailserver/sql/reducers/chat_message.sql).
	{"BZ206", "", 422, "", "class"},
	// BZ205 — Pillar C1 Task 7: federation_enqueue's user-initiated
	// backpressure/dead-peer cap (unacked outbox depth over
	// federation.outbox_cap, or the peer hasn't acked anything in over
	// federation.peer_stale_minutes). Class fallback only (this reducer's
	// sole registration site; mailserver/sql/reducers/federation_enqueue.sql).
	{"BZ205", "", 409, "", "class"},
	// BZ207/BZ208 — Pillar C1 Task 8: federation_peer_set's admin-argument
	// backstop (empty domain / bad scope / anchor not PEM-shaped) and
	// federation_peer_delete's disable-before-delete conflict. Class
	// fallback only (this reducer pair's sole registration site;
	// mailserver/sql/reducers/federation_peer_set.sql,
	// federation_peer_delete.sql).
	{"BZ207", "", 400, "invalidArguments", "class"},
	{"BZ208", "", 409, "", "class"},
	// BZ209/BZ210/BZ211 — Pillar C2 Task 2: room lifecycle reducers.
	// BZ209 is the room-bind/archive/org-default refusal family (channel
	// shape/state ineligible to bind, or — Q13 — archiving a room-bound
	// channel while the hub has active members / a live spoke mirror).
	// BZ210 is the gxp x federated-room-binding refusal, both arms (Q7).
	// BZ211 is the room membership-authority refusal family (Q3 — owner/
	// admin, hub-shape, hub-domain-as-target, contactAddr mismatch, peer
	// not room-scope allow-listed, unknown/already-left member, archived
	// channel). Class fallback only (this task's sole registration site;
	// raised in mailserver/sql/reducers/federation_room_create.sql,
	// federation_room_invite.sql, federation_room_remove.sql,
	// federation_room_fanout.sql (internal-invariant unknown-room guard),
	// chat_channel.sql, chat_channel_set_classification.sql,
	// chat_org_defaults.sql).
	{"BZ209", "", 422, "", "class"},
	{"BZ210", "", 422, "", "class"},
	{"BZ211", "", 403, "forbidden", "class"},
	// BZ212/BZ213 — Pillar C2 Task 3: the outbound room arm in
	// chat_message_send. BZ212 is the Q11 content-scope refusal (an
	// attachment or a non-'text' msg_type cannot propagate to a federated
	// room — refused rather than silently desyncing every member org's
	// copy). BZ213 is the kicked/closed-mirror send refusal (Q3/Q9 — a
	// spoke mirror with federated_room_removed_at set is archive-read-only;
	// Task 5's 'remove'/'room_revoked' op arms are what SET that field).
	// Class fallback only (this task's sole registration site;
	// mailserver/sql/reducers/chat_message.sql).
	{"BZ212", "", 422, "", "class"},
	{"BZ213", "", 403, "forbidden", "class"},
	// BZ215/BZ216/BZ219/BZ221 — Guest Accounts G0 (registered by Task 1,
	// the V143 migration commit; raisers land in the door/provision tasks).
	{"BZ215", "", 403, "forbidden", "class"},
	{"BZ216", "", 403, "forbidden", "class"},
	{"BZ219", "", 403, "forbidden", "class"},
	{"BZ221", "", 409, "", "class"},
	// BZ217/BZ218/BZ222/BZ223 — Guest Accounts G1 invite flow.
	{"BZ217", "", 403, "forbidden", "class"},
	{"BZ218", "", 403, "forbidden", "class"},
	{"BZ222", "", 400, "invalidArguments", "class"},
	{"BZ223", "", 403, "forbidden", "class"},
	// BZ220/BZ224/BZ225/BZ226 — Guest Accounts G2 profile/chat contract.
	{"BZ220", "", 403, "forbidden", "class"},
	{"BZ224", "", 422, "", "class"},
	{"BZ225", "", 409, "", "class"},
	{"BZ226", "", 409, "", "class"},
	// BZ227 — Identity Model Modernization I0 stable-pair safety.
	{"BZ227", "", 409, "", "class"},
	// BZ228-BZ241 — Identity Model Modernization normalized source/link and
	// transition contract.
	{"BZ228", "", 400, "invalidArguments", "class"},
	{"BZ229", "", 409, "", "class"},
	{"BZ230", "", 409, "", "class"},
	{"BZ231", "", 422, "", "class"},
	{"BZ232", "", 409, "", "class"},
	{"BZ233", "", 409, "", "class"},
	{"BZ234", "", 409, "", "class"},
	{"BZ235", "", 409, "", "class"},
	{"BZ236", "", 403, "forbidden", "class"},
	{"BZ237", "", 409, "", "class"},
	{"BZ238", "", 409, "", "class"},
	{"BZ239", "", 403, "forbidden", "class"},
	{"BZ240", "", 409, "", "class"},
	{"BZ241", "", 400, "invalidArguments", "class"},
	// BZ242-BZ251 — transactional updater authority and recovery boundaries.
	{"BZ242", "", 409, "", "class"},
	{"BZ243", "", 409, "", "class"},
	{"BZ244", "", 403, "forbidden", "class"},
	{"BZ245", "", 422, "", "class"},
	{"BZ246", "", 409, "", "class"},
	{"BZ247", "", 409, "", "class"},
	{"BZ248", "", 409, "", "class"},
	{"BZ249", "", 409, "", "class"},
	{"BZ250", "", 403, "forbidden", "class"},
	{"BZ251", "", 400, "invalidArguments", "class"},
	// BZ252-BZ259 — Drive ACL and normalized directory-group authority.
	{"BZ252", "", 400, "invalidArguments", "class"},
	{"BZ253", "", 403, "forbidden", "class"},
	{"BZ254", "", 409, "", "class"},
	{"BZ255", "", 409, "", "class"},
	{"BZ256", "", 409, "", "class"},
	{"BZ257", "", 400, "invalidArguments", "class"},
	{"BZ258", "", 403, "forbidden", "class"},
	{"BZ259", "", 409, "", "class"},
	{"BZ260", "", 409, "", "class"},
	// BZ261-BZ263 — feature registry authority.
	{"BZ261", "", 400, "invalidArguments", "class"},
	{"BZ262", "", 409, "", "class"},
	{"BZ263", "", 409, "", "class"},
	// BZ264-BZ271 — migration source identity + IMAP UID correctness.
	{"BZ264", "", 409, "", "class"},
	{"BZ265", "", 400, "invalidArguments", "class"},
	{"BZ266", "", 409, "", "class"},
	{"BZ267", "", 409, "", "class"},
	{"BZ268", "", 404, "notFound", "class"},
	{"BZ269", "", 400, "invalidArguments", "class"},
	{"BZ270", "", 404, "notFound", "class"},
	{"BZ271", "", 400, "invalidArguments", "class"},
	// BZ272-BZ277 — MEET plan M2 presentation session (V265).
	{"BZ272", "", 404, "notFound", "class"},
	{"BZ273", "", 403, "forbidden", "class"},
	{"BZ274", "", 409, "", "class"},
	{"BZ275", "", 409, "", "class"},
	{"BZ276", "", 422, "", "class"},
	{"BZ277", "", 403, "forbidden", "class"},
	// BZ278-BZ281 — MEET plan M4 semantic recording (V266).
	{"BZ278", "", 409, "", "class"},
	{"BZ279", "", 409, "", "class"},
	{"BZ280", "", 409, "", "class"},
	{"BZ281", "", 422, "", "class"},
	// BZ282-BZ284 — MEET plan M5 local capture (V268).
	{"BZ282", "", 409, "", "class"},
	{"BZ283", "", 422, "", "class"},
	{"BZ284", "", 403, "forbidden", "class"},
	{"BZ285", "", 400, "invalidArguments", "class"},
	// BZ300-BZ309 — mailbox lifecycle + webmail productivity.
	{"BZ300", "", 404, "notFound", "class"},
	{"BZ301", "", 400, "invalidArguments", "class"},
	{"BZ302", "", 404, "notFound", "class"},
	{"BZ303", "", 409, "stateMismatch", "class"},
	{"BZ304", "", 409, "stateMismatch", "class"},
	{"BZ305", "", 409, "", "class"},
	{"BZ306", "", 409, "", "class"},
	{"BZ307", "", 403, "forbidden", "class"},
	{"BZ308", "", 403, "forbidden", "class"},
	{"BZ309", "", 409, "stateMismatch", "class"},
	{"BZ310", "", 404, "notFound", "class"},
	{"BZ311", "", 403, "forbidden", "class"},
	{"BZ312", "", 409, "", "class"},
	{"BZ313", "", 409, "", "class"},
	{"BZ314", "", 403, "forbidden", "class"},
	{"BZ315", "", 409, "", "class"},
	{"BZ316", "", 400, "invalidArguments", "class"},
	{"BZ317", "", 404, "notFound", "class"},
	{"BZ318", "", 409, "", "class"},
	{"BZ319", "", 409, "", "class"},
	{"BZ320", "", 422, "", "class"},
	{"BZ321", "", 404, "notFound", "class"},
	{"BZ322", "", 400, "invalidArguments", "class"},
	{"BZ323", "", 403, "forbidden", "class"},
	{"BZ324", "", 409, "stateMismatch", "class"},
	{"BZ325", "", 409, "", "class"},
	{"BZ326", "", 409, "stateMismatch", "class"},
	{"BZ327", "", 409, "", "class"},
	{"BZ328", "", 409, "", "class"},
	{"BZ329", "", 409, "stateMismatch", "class"},

	// ── JMAP state ────────────────────────────────────────────────────────
	{"BZ011", "", 409, "cannotCalculateChanges", "fixed:client must resync (sinceState too old)"},

	// ── transient infra (must not leak; SMTP 451) ─────────────────────────
	{"BZ008", "", 500, "", "class"},

	// ── deliberate 500s (internal invariants — intentional500) ───────────
	{"BZ010", "", 500, "", "class"},
	{"BZ012", "", 500, "", "class"},
	{"BZ013", "", 500, "", "class"},
	{"BZ014", "", 500, "", "class"},
	{"BZ016", "", 500, "", "class"},
	{"BZ017", "", 500, "", "class"},
	{"BZ018", "", 500, "", "class"},
	{"BZ034", "", 500, "", "class"},
	{"BZ035", "", 500, "", "class"},
	{"BZ067", "", 500, "", "class"},
	{"BZ073", "", 500, "", "class"},
	{"BZ079", "", 500, "", "class"},
	{"BZ083", "", 500, "", "class"},
}

// classFallbackGolden pins the tier-3 per-class fallback strings independently
// of the implementation (do NOT call detailFallback here — this is the golden
// copy a regression must diff against).
var classFallbackGolden = map[int]string{
	507: "overQuota",
	403: "forbidden",
	404: "notFound",
	400: "invalidArguments",
	409: "conflict",
	422: "unprocessable",
	500: "request failed",
}

// TestContractMatrix_StatusJMAPTypeDetail asserts every row's HTTP status,
// JMAP type, and Detail projection against the live classification — the
// single seam all handlers consume.
func TestContractMatrix_StatusJMAPTypeDetail(t *testing.T) {
	for _, row := range contractMatrix {
		name := row.code
		if row.hint != "" {
			name += "/" + row.hint
		}
		t.Run(name, func(t *testing.T) {
			hint := row.hint
			if hint == "" && row.detail == "hint" {
				hint = "actionable hint text"
			}
			err := &pgconn.PgError{Code: row.code, Message: "reducer message text", Hint: hint}
			class := Classify(err)
			if got := class.HTTPStatus(); got != row.status {
				t.Errorf("HTTPStatus(%s) = %d, want %d", row.code, got, row.status)
			}
			if got := class.JMAPError(); got != row.jmapType {
				t.Errorf("JMAPError(%s) = %q, want %q", row.code, got, row.jmapType)
			}

			var wantDetail string
			switch {
			case row.detail == "message":
				wantDetail = "reducer message text"
			case row.detail == "hint":
				wantDetail = hint
			case len(row.detail) > 6 && row.detail[:6] == "fixed:":
				wantDetail = row.detail[6:]
			case row.detail == "class":
				wantDetail = classFallbackGolden[row.status]
				// accountNotFound / cannotCalculateChanges share a status with
				// another class; no "class"-mode row uses them today.
				if row.jmapType == "accountNotFound" || row.jmapType == "cannotCalculateChanges" || row.jmapType == "stateMismatch" {
					wantDetail = row.jmapType
				}
			default:
				t.Fatalf("bad detail legend %q", row.detail)
			}
			if got := Detail(err); got != wantDetail {
				t.Errorf("Detail(%s) = %q, want %q", row.code, got, wantDetail)
			}
		})
	}
}

// TestDetail_HintFallsBackToMessage pins the passHint tier's fallback: an
// allowlisted CA-family code with an empty HINT surfaces the message instead
// (caErrorDetail's historical behavior).
func TestDetail_HintFallsBackToMessage(t *testing.T) {
	err := &pgconn.PgError{Code: "BZ080", Message: "would lock out all admins"}
	if got := Detail(err); got != "would lock out all admins" {
		t.Errorf("Detail(BZ080, no hint) = %q, want the message", got)
	}
}

// TestDetail_NeverLeaksUnlistedText pins the security property: a code outside
// the passthrough allowlist NEVER surfaces raw SQLERRM/HINT, and a non-pg
// error yields the generic fallback.
func TestDetail_NeverLeaksUnlistedText(t *testing.T) {
	err := &pgconn.PgError{Code: "BZ019", Message: "SECRET internal text", Hint: "SECRET hint"}
	if got := Detail(err); got != "notFound" {
		t.Errorf("Detail(BZ019) = %q, want class fallback %q", got, "notFound")
	}
	unknown := &pgconn.PgError{Code: "XX000", Message: "SECRET", Hint: "SECRET"}
	if got := Detail(unknown); got != "request failed" {
		t.Errorf("Detail(XX000) = %q, want %q", got, "request failed")
	}
}

// TestContractMatrix_CoversEveryClassifiedCode asserts the matrix enumerates
// every code reducererr classifies (codeClass + intentional500) — a new code
// cannot enter the vocabulary without a golden row.
func TestContractMatrix_CoversEveryClassifiedCode(t *testing.T) {
	inMatrix := map[string]bool{}
	for _, row := range contractMatrix {
		inMatrix[row.code] = true
	}
	for code := range codeClass {
		if !inMatrix[code] {
			t.Errorf("codeClass entry %s has no row in the golden contract matrix", code)
		}
	}
	for code := range intentional500 {
		if !inMatrix[code] {
			t.Errorf("intentional500 entry %s has no row in the golden contract matrix", code)
		}
	}
}

// TestSPAContracts pins the wire values the webmail SPA hard-branches on:
//   - offline/sync.ts:230 branches on jmapType === 'cannotCalculateChanges'
//   - admin conditional-access state-helpers.ts maps 409→lockout copy and
//     400→invalid copy (statuses must not move)
//
// (The third SPA contract — jmap/client.ts branching on 403 + body code
// 'BZ095' — is emitted SYNTHETICALLY by middleware/device_trust_gate.go, not
// by this projection; it is pinned in middleware's device_lockdown_gate_test.)
func TestSPAContracts(t *testing.T) {
	if got := Classify(&pgconn.PgError{Code: "BZ011"}).JMAPError(); got != "cannotCalculateChanges" {
		t.Errorf("BZ011 JMAP type = %q, want cannotCalculateChanges (offline/sync.ts resync branch)", got)
	}
	if got := Classify(&pgconn.PgError{Code: "BZ080"}).HTTPStatus(); got != 409 {
		t.Errorf("BZ080 status = %d, want 409 (state-helpers.ts lockout copy)", got)
	}
	if got := Classify(&pgconn.PgError{Code: "BZ082"}).HTTPStatus(); got != 400 {
		t.Errorf("BZ082 status = %d, want 400 (state-helpers.ts invalid copy)", got)
	}
	if got := Classify(&pgconn.PgError{Code: "BZ087"}).HTTPStatus(); got != 409 {
		t.Errorf("BZ087 status = %d, want 409 (restore-conflict copy)", got)
	}
}
