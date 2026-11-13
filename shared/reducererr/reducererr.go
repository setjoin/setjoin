// Package reducererr owns the BZ business-error vocabulary raised by the
// PL/pgSQL reducers (see docs/reducer-error-codes.md), the decoder that turns
// a pgx error into a typed ReducerError, and (wire.go, arch #3) the shared
// reducer->HTTP translator kit (WriteProblem) chat/meet/drive route
// their RFC 7807 projection through.
//
// Its only non-stdlib dependencies are pgx (the error/row types it decodes)
// and shared/httputil (the RFC 7807 Problem type) — both leaves outside this
// module's own package graph — so every gateway protocol layer can route on
// the stable BZ code without an import cycle: jmap, smtp, admin, and every
// other consumer depend on this package directly (the former admin.*
// re-export shim — admin.Err*, admin.ParseReducerError, admin.ReducerError —
// was a zero-non-test-consumer dead alias, deleted arch review #A5).
package reducererr

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
)

// ReducerError represents a structured business error from a PL/pgSQL reducer.
// Reducers raise exceptions with ERRCODE and HINT (JSON) — the Go gateway
// parses these into typed errors instead of relying on string matching.
type ReducerError struct {
	Type        string `json:"type"`
	MailboxID   int    `json:"mailbox_id,omitempty"`
	UserID      int    `json:"user_id,omitempty"`
	DomainID    int    `json:"domain_id,omitempty"`
	FromAddr    string `json:"from_addr,omitempty"`
	PolicyID    int    `json:"policy_id,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// Business error codes (BZ prefix = Business Logic, per PostgreSQL convention).
// These are stable identifiers — the human-readable message in RAISE EXCEPTION
// can change without breaking Go code.
const (
	ErrOverQuota            = "BZ001" // mailbox or domain storage quota exceeded
	ErrForbidden            = "BZ002" // access denied (mailbox not found, not owner)
	ErrSendAsUnauthorized   = "BZ003" // sending from unauthorized From: address
	ErrSendingQuotaExceeded = "BZ004" // daily sending quota reached
	ErrDLPBlocked           = "BZ005" // DLP policy blocked outbound message
	ErrAccountNotFound      = "BZ006" // invalid account ID in JMAP request
	ErrNoMailbox            = "BZ007" // recipient has no mailbox
	ErrMissingInbox         = "BZ008" // mailbox has no Inbox tag
	ErrDomainOverQuota      = "BZ009" // domain-level storage quota exceeded
	ErrInvalidSide          = "BZ010" // invalid rule evaluation side
	ErrCannotCalcChanges    = "BZ011" // JMAP state unavailable for change calculation
	ErrInvalidArguments     = "BZ040" // request arguments invalid (e.g. empty required filter)
	ErrInvalidArguments2    = "BZ041" // request arguments invalid (second invalidArguments code)
	// Self-service booking pages (feature #6; booking_pages.sql).
	ErrBookingPageNotFound = "BZ134" // booking page not found / disabled / not owned
	ErrBookingInvalidSlot  = "BZ135" // invalid date range / missing required answer / event creation failed
	ErrBookingSlotTaken    = "BZ136" // requested slot no longer open (double-booking / re-check at confirm)
	ErrBookingBadToken     = "BZ137" // verify/cancel token invalid, expired, or already used
)

// codeClass is THE single source of truth mapping every client-actionable BZ
// code to its protocol-agnostic ReplyClass (see projection.go). It replaced the
// old two-source split (a `validErrorCodes` set PLUS a separate `Classify`
// switch that between them recognized only 13 of ~90 codes — the other ~70 fell
// through to an opaque serverFail/500). Now Classify is a lookup here, CodeIsKnown
// is membership here, and the machine guard in guard_test.go asserts EVERY code a
// reducer RAISEs is a key here (or a deliberate intentional500), so no reducer
// error can silently 500 again without a build failure.
//
// BZ001 and BZ081 are dual-use on one SQLSTATE (disambiguated by HINT in
// Classify); their entry here is the primary meaning, for CodeIsKnown.
var codeClass = map[string]ReplyClass{
	// storage / send quota
	ErrOverQuota:            ClassOverQuota, // BZ001 over_quota (dual-use; Classify checks HINT)
	ErrDomainOverQuota:      ClassOverQuota, // BZ009
	ErrSendingQuotaExceeded: ClassSendQuota, // BZ004
	// forbidden / policy / ownership / SoD
	ErrForbidden:          ClassForbidden, // BZ002
	ErrSendAsUnauthorized: ClassForbidden, // BZ003
	ErrDLPBlocked:         ClassForbidden, // BZ005
	"BZ015":               ClassForbidden, // litigation-hold delete / app-password cap
	"BZ045":               ClassForbidden, // contact group not owned
	"BZ052":               ClassForbidden, // MDM device owned by another user
	"BZ061":               ClassForbidden, // access review out of scope
	"BZ065":               ClassForbidden, // target holds privileges beyond yours
	"BZ066":               ClassForbidden, // cannot act on your own account
	"BZ069":               ClassForbidden, // cannot review your own access (SoD)
	"BZ071":               ClassForbidden, // signature not owned
	"BZ107":               ClassForbidden, // actor not authorized to decide
	"BZ116":               ClassForbidden, // sharing default: actor lacks sharing.manage / not the owner (auth ladder)
	// not found
	ErrAccountNotFound:     ClassAccountNotFound, // BZ006 (JMAP accountNotFound)
	ErrNoMailbox:           ClassNotFound,        // BZ007
	"BZ019":                ClassNotFound,        // tag not found in mailbox
	"BZ020":                ClassNotFound,        // message not found (undo lookup)
	"BZ021":                ClassNotFound,        // message not found (undo cancel)
	"BZ030":                ClassNotFound,        // message not found / snooze tag missing
	"BZ033":                ClassNotFound,        // entitlement target user not found
	"BZ038":                ClassNotFound,        // reminder not found
	"BZ042":                ClassNotFound,        // quick-step / target message not found
	"BZ049":                ClassNotFound,        // migration job not found
	"BZ051":                ClassNotFound,        // unknown queue
	"BZ053":                ClassNotFound,        // mdm_device_wipe_arm wipe target not found / out of scope (404-indistinguishable, no existence oracle)
	"BZ060":                ClassNotFound,        // access-review campaign / item not found
	"BZ074":                ClassNotFound,        // quarantine tag / message not found
	"BZ084":                ClassNotFound,        // secure_account user not found
	"BZ086":                ClassNotFound,        // CA restore audit not found
	"BZ091":                ClassNotFound,        // CA import unknown slug — 404 semantics owned by admin_ca_import_export.go caImportErrorStatus (was ClassInvalidArguments here; the import route is the only wire path)
	"BZ099":                ClassNotFound,        // offline policy not found / invalid (dual: HINT slug last_global → ClassConflict in Classify; 409 owned by admin_offline.go DeletePolicy)
	"BZ101":                ClassNotFound,        // wipe-ack mailbox / pending not found (user/devices.go treats it as idempotent success via IsCode)
	"BZ103":                ClassNotFound,        // compute_user_risk user not found
	"BZ112":                ClassNotFound,        // contact_merge contact not found / not owned
	"BZ113":                ClassNotFound,        // calendar_import_ics target calendar not found / not owned
	"BZ114":                ClassNotFound,        // sharing: mailbox not owned / grantee or default row not found (404-indistinguishable)
	"BZ118":                ClassNotFound,        // calendar_subscription_refresh: subscription not found / calendar_id foreign to it (404-indistinguishable, no ownership oracle — mirrors BZ113/BZ114)
	"BZ121":                ClassNotFound,        // rules_apply_retroactive: rule not found / not owned by this mailbox / transport rule (self-service retro apply)
	"BZ081":                ClassNotFound,        // CA entity not found (dual with queue bad_outcome; Classify checks HINT)
	"BZ125":                ClassNotFound,        // approval_request_cancel: not found / not the requester / not pending (404-indistinguishable, no ownership oracle — mirrors BZ113/BZ114/BZ118)
	"BZ130":                ClassNotFound,        // task_lists.sql: list not owned / not a member (404-indistinguishable, no membership oracle — shared task lists Phase 1)
	"BZ132":                ClassNotFound,        // task_list_tasks.sql / tasks_assigned.sql: not a list member / task not assigned to caller (404-indistinguishable, no oracle)
	ErrBookingPageNotFound: ClassNotFound,        // BZ134 (self-service booking pages, feature #6)
	// invalid arguments (bad request input)
	ErrInvalidArguments:   ClassInvalidArguments, // BZ040
	ErrInvalidArguments2:  ClassInvalidArguments, // BZ041
	"BZ043":               ClassInvalidArguments, // quick-step action not in allowlist — invalidArguments semantics owned by jmap/quicksteps.go quickStepError (was ClassForbidden here; the JMAP quick-step path is the only wire path)
	"BZ085":               ClassInvalidArguments, // CA template unknown slug — 400 semantics owned by admin_conditional_access.go caErrorStatus (was ClassNotFound here; the admin CA routes are the only wire path)
	"BZ104":               ClassInvalidArguments, // JIT not enabled / no eligible assignment — 400 semantics owned by admin_jit.go mapJITErr (was ClassForbidden here; the self-service JIT route is the only wire path)
	"BZ031":               ClassInvalidArguments, // snooze time in the past
	"BZ036":               ClassInvalidArguments, // unknown action_kind
	"BZ037":               ClassInvalidArguments, // fire_at required
	"BZ039":               ClassInvalidArguments, // reminder snooze time in the past
	"BZ044":               ClassInvalidArguments, // contact-group name required / duplicate
	"BZ046":               ClassInvalidArguments, // invalid out-of-office external_audience
	"BZ047":               ClassInvalidArguments, // out-of-office start after end
	"BZ119":               ClassInvalidArguments, // approval delegation: invalid window / invalid delegate (self / missing / cross-domain)
	"BZ050":               ClassInvalidArguments, // unknown migration phase
	"BZ055":               ClassInvalidArguments, // invalid link-protect verdict
	"BZ056":               ClassInvalidArguments, // provision into a non-local domain
	"BZ057":               ClassInvalidArguments, // mdm_device_wipe_arm wipe level outside the account/device vocabulary
	"BZ070":               ClassInvalidArguments, // invalid signature default role
	"BZ072":               ClassInvalidArguments, // invalid provision email
	"BZ076":               ClassInvalidArguments, // EAP rendered an empty local-part
	"BZ078":               ClassInvalidArguments, // EAP rendered a non-local domain
	"BZ082":               ClassInvalidArguments, // CA break-glass set empty
	"BZ094":               ClassInvalidArguments, // CA built-in auth-strength guard
	"BZ097":               ClassInvalidArguments, // illegal revocation scope
	"BZ098":               ClassInvalidArguments, // session-control bad args
	"BZ105":               ClassInvalidArguments, // JIT justification required
	"BZ115":               ClassInvalidArguments, // sharing: invalid delegate permission level
	"BZ117":               ClassInvalidArguments, // sharing: invalid scope/audience/level combination or unknown ref
	"BZ120":               ClassInvalidArguments, // rules_apply_retroactive: invalid window / missing mailbox
	"BZ122":               ClassInvalidArguments, // vip_sender_set: empty sender email
	"BZ123":               ClassInvalidArguments, // set_occurrence: recurrenceId is not an occurrence of the series
	"BZ124":               ClassInvalidArguments, // hr_request_create: leave/expense form validation (bad type/dates/amounts/currency/line-items)
	"BZ126":               ClassInvalidArguments, // hr_request_create: receipt_sha256 does not exist in blobs
	"BZ131":               ClassInvalidArguments, // task_lists.sql: invalid name / unresolvable member email / roster cap / cannot remove the owner (shared task lists Phase 1)
	"BZ133":               ClassInvalidArguments, // task_list_tasks.sql / tasks_assigned.sql: assignee not a list member / bad status value / no primary mailbox
	ErrBookingInvalidSlot: ClassInvalidArguments, // BZ135 (self-service booking pages, feature #6)
	// state conflicts (409)
	"BZ022":             ClassConflict, // message not sent (cannot undo/recall)
	"BZ048":             ClassConflict, // illegal migration phase transition
	"BZ054":             ClassConflict, // mdm_device_wipe_arm state conflict: wipe already executed / armed at another level
	"BZ062":             ClassConflict, // access-review campaign closed
	"BZ063":             ClassConflict, // access-review revoke already won
	"BZ064":             ClassConflict, // cannot remove the last Super Admin — 409 semantics owned by admin/admin_protection.go mapProtectionErr (was ClassForbidden here; the admin protection routes are the only wire path)
	"BZ075":             ClassConflict, // EAP collision-resolution exhausted
	"BZ077":             ClassConflict, // EAP rendered address conflicts with an existing alias
	"BZ080":             ClassConflict, // CA policy would lock out all admins
	"BZ087":             ClassConflict, // CA restore priority clash
	"BZ093":             ClassConflict, // CA named-location restore name clash
	"BZ095":             ClassConflict, // device enroll not-found / illegal transition — 409 "state moved, refresh and retry" semantics owned by admin/admin_device_lockdown.go (was ClassNotFound here). NOTE: the SYNTHETIC 403+BZ095 body written by middleware/device_trust_gate.go is a different, non-pgErr surface — the SPA's deviceBlock contract — and is untouched by this classification.
	"BZ100":             ClassConflict, // offline device not found / illegal transition — 409 semantics owned by admin/admin_offline.go deviceAction (was ClassNotFound here)
	"BZ102":             ClassConflict, // Terms-of-Use not found / disabled / stale
	"BZ106":             ClassConflict, // requester cannot decide own request (SoD) — 409 semantics owned by approval/handler.go mapApprovalErr (was ClassForbidden here)
	"BZ108":             ClassConflict, // approval request not found / not pending / bad decision — 409 semantics owned by approval/handler.go mapApprovalErr (was ClassNotFound here)
	"BZ110":             ClassConflict, // RBAC assignment no longer eligible
	"BZ111":             ClassConflict, // group has no moderator / approver
	ErrBookingSlotTaken: ClassConflict, // BZ136 (self-service booking pages, feature #6 — slot no longer open)
	ErrBookingBadToken:  ClassConflict, // BZ137 (self-service booking pages, feature #6 — token invalid/expired/already used)
	// unprocessable (422 — semantically bad content, not bad request syntax)
	"BZ088": ClassUnprocessable, // CA import schemaVersion too new — 422 owned by admin_ca_import_export.go caImportErrorStatus (was ClassInvalidArguments here)
	"BZ090": ClassUnprocessable, // CA import invalid shape — 422 owned by admin_ca_import_export.go (was ClassInvalidArguments here)
	"BZ092": ClassUnprocessable, // CA import invalid mode — 422 owned by admin_ca_import_export.go (was ClassInvalidArguments here)
	"BZ109": ClassUnprocessable, // approval: no approver resolved (spec-reserved, currently unreachable) — 422 owned by approval/handler.go mapApprovalErr (was unclassified→500 here)
	// setjoin Drive (P1; drive_*.sql, spec §7 BZ→status map). BZ148 is dual-owned:
	// ClassOverQuota's HTTPStatus() is 507, but drive/problem.go overrides to 413
	// (Request Entity Too Large) for the drive REST surface via reducererr.IsCode.
	"BZ139": ClassNotFound,      // drive: object not found / not a member (no membership oracle — BZ130 posture)
	"BZ140": ClassForbidden,     // drive: insufficient role / space-creation gate
	"BZ141": ClassUnprocessable, // drive: invalid argument / manifest shape / gxp knobs (422 per drive §7 map)
	"BZ142": ClassConflict,      // drive: classification/compliance downgrade forbidden
	"BZ143": ClassConflict,      // drive: cross-space move forbidden
	"BZ144": ClassUnprocessable, // drive: manifest chunk not proven (anti-oracle)
	"BZ145": ClassConflict,      // drive: immutable record (WORM / audit append-only)
	"BZ146": ClassConflict,      // drive: export grant invalid (unknown/expired/consumed/wrong-grantee, opaque) or WORM lock pending (transient, retryable)
	"BZ147": ClassConflict,      // drive: duplicate live name in folder
	"BZ148": ClassOverQuota,     // drive: quota/upload limit — 413 owned by drive/problem.go (507 elsewhere)
	// BZ149/BZ150 — P4 versioning/locks (drive_file_lock.sql, drive_file_put_version.sql,
	// drive_branch_create/rename/set_status/resolve.sql). Class fallback is 409 for both
	// (like every other drive state-conflict code); drive/problem.go overrides BZ149's
	// WIRE status to 423 Locked (dual-owned, same pattern as BZ148's 413 override) — BZ150
	// already wants 409, so no override is needed for it.
	"BZ149": ClassConflict, // drive: file hard-locked by another user (checkout rejection, I-12)
	"BZ150": ClassConflict, // drive: branch error (unknown/not-open branch, name collision, ineligible transition, resolve-authorization failure)
	// setjoin Chat A1 (Pillar A1; chat_*.sql, notify_chat_state.sql — see
	// retired-docs:superpowers/plans/archive/2026-07-11-chat-A1-core-messaging.md Task 8's
	// locked §BZ160-170 map). Chat's Go wire projection lives in
	// mailserver/internal/chat/errors.go (bzSlug + writeChatProblem) — a
	// thin reducererr.Classify consumer, no per-code status override (unlike
	// drive's BZ148/BZ149).
	"BZ160": ClassInvalidArguments, // notify_chat_state: NULL channel (internal-seam guard, never a real user request)
	"BZ161": ClassForbidden,        // chat_channel_update/chat_member_add/chat_member_remove: not owner/admin
	"BZ162": ClassUnprocessable,    // chat_channel_create/chat_dm_open/chat_member_add: empty name, bad visibility, <2 DM members, member-add on a dm/group_dm
	"BZ163": ClassForbidden,        // chat_message_send/chat_mark_read/chat_typing_signal: caller not a channel member; ALSO federation_room_create.sql (Pillar C2 Task 2): caller is not a member of the channel being bound to a federated room at all
	"BZ164": ClassForbidden,        // chat_message_send: announcement post by a non-admin
	"BZ165": ClassUnprocessable,    // chat_message_send: parent message missing / in another channel / soft-deleted
	"BZ166": ClassForbidden,        // chat_message_send: broadcast (@channel/@all) by a non-owner/admin
	"BZ167": ClassForbidden,        // chat_message_edit/chat_message_delete: not the author (delete also allows owner/admin)
	"BZ168": ClassUnprocessable,    // chat_message_send: body empty or >64KiB
	"BZ169": ClassNotFound,         // chat_reaction_toggle: message not found / soft-deleted (distinct from BZ163 membership)
	"BZ170": ClassNotFound,         // chat_channel_join: private or nonexistent channel — anti-oracle, joining must not reveal private channels exist (drive BZ139 posture)
	"BZ171": ClassForbidden,        // chat_message_send/edit/delete: mutation attempted against an archived (read-only) channel
	// Chat A2 (chat_message.sql, drive_file_put_version.sql / drive_node_*.sql
	// — DES-009). BZ172/BZ173 HINT.type is literal "invalidArguments"/"forbidden";
	// BZ175 HINT.type is literal "forbidden" at every raise site (drive_member_grant,
	// drive_node_trash/move/rename, drive_file_put_version) so it classifies the same
	// even though it also guards an immutability conflict.
	"BZ172": ClassInvalidArguments, // chat_message_send: >8 attachments per message / bad attachment shape
	"BZ173": ClassForbidden,        // chat_message_send: attachments present while feature.drive is disabled (reducer defense)
	"BZ175": ClassForbidden,        // drive_member_grant/drive_node_trash|move|rename/drive_file_put_version: chat-bound space rejects ad-hoc member grants / chat-attached node is immutable via Drive
	// Chat A3 QoL (chat_message.sql — 2026-07-12-chat-A3-qol.md Task 6).
	"BZ178": ClassUnprocessable, // chat_message_send: voice message durationMs over the 300000ms (5 min) cap
	// Chat A3 QoL Task 3 (chat_pin.sql): pin/unpin permission — a plain
	// channel member (not owner/admin) may not pin/unpin in a CHANNEL; DMs/
	// group-DMs are all-member (every row is 'member', so this never fires
	// there). Unpin is collective — this code never distinguishes "not the
	// pinner" from "not authorized to curate", there is no such distinction.
	"BZ176": ClassForbidden,
	// Chat A3 QoL Task 9 (chat_poll.sql): "poll invalid" — one code, no
	// oracle on which of: poll/option not found, the poll's anchor message
	// soft-deleted, or the poll already closed. The manual-close wrong-actor
	// case (not creator, not owner/admin) deliberately does NOT share this
	// code — that's a ClassForbidden concern and reuses the EXISTING BZ161
	// instead, keeping this lumped code's HTTP class pure (all BZ177 raises
	// are ClassUnprocessable).
	"BZ177": ClassUnprocessable,
	// Chat A3 QoL Task 2 (chat_schedule.sql): scheduled-send invalid — a
	// missing/past fireAt at enqueue, or a cancel attempt against a row that
	// is not pending/failed/not-yours/nonexistent (one code, all shapes, no
	// oracle on which — same posture as BZ162/165/168's class fallback).
	"BZ179": ClassUnprocessable,
	// Meet B1 (Pillar B1; meeting_*.sql, notify_meet_state.sql — see
	// retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md Global Constraints'
	// locked BZ185-190 map). BZ180-BZ184 are an unallocated gap, never
	// backfilled.
	"BZ185": ClassNotFound,      // meeting/slug not found — anti-oracle (nonexistent/ended/guest-disallowed/guest_access-off read identically on the public surface)
	"BZ186": ClassForbidden,     // host-or-cohost-required action, or a banned (kicked) participant rejoining before host re-admit
	"BZ187": ClassForbidden,     // meeting locked — join refused (client falls back to a knock)
	"BZ188": ClassUnprocessable, // invalid meeting arguments (title/window/role/flood cap/foreign calendar event)
	"BZ189": ClassUnprocessable, // join-request not decidable (not pending/expired/nonexistent/wrong meeting — no oracle on which)
	"BZ190": ClassConflict,      // meeting already ended — mutation against a dead meeting
	// Chat A4a (Pillar A4a; V126__chat_compliance.sql + chat_*.sql — see
	// retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md Global
	// Constraints' locked BZ191-196 map). BZ191/BZ196 are classified in Tasks
	// 2/10 (each raises its own code); THIS entry set (BZ192-195) is Task 1's
	// SOLE registration — the V126 triggers (BZ192/193/194) and later
	// reducers (BZ195, raised in Tasks 4/5/8) all classify here so a
	// duplicate codeClass map key never ships (verify C1). Do not re-add
	// these keys elsewhere.
	"BZ191": ClassUnprocessable, // chat: unknown audit action — chat_access_audit's closed catalog (chat_audit_actions()), the drive BZ141 genre (Task 2's own registration)
	"BZ192": ClassConflict,      // chat: compliance no-downgrade (classification/retention/worm_mode may never relax on a gxp channel) — trg_chat_channel_no_downgrade_fn
	"BZ193": ClassConflict,      // chat: WORM message/revision immutable inside gxp retention — trg_chat_message_worm_fn / trg_chat_revision_worm_fn
	"BZ194": ClassForbidden,     // chat: legal hold blocks destruction — trg_chat_message_hold_fn (litigation_hold HINT slug, BZ015's own)
	"BZ195": ClassUnprocessable, // chat: invalid compliance arguments (bad retention days, hold conflict/no-op, invalid classification transition — Tasks 4/5/8)
	"BZ196": ClassSendQuota,     // chat: per-user chat send rate exceeded — chat_message_send's per-minute counter (send.sql BZ004 genre, Task 10's own registration)
	// Chat A4b oversight (2026-07-15-chat-A4b-oversight.md Task 1 — this is
	// the SOLE registration site for BZ197/BZ198; Tasks 2/3/4 only RAISE).
	"BZ197": ClassUnprocessable, // chat: invalid oversight arguments (bad hold scope/query/target, hold not found or already released) — chat_case_hold_set/release, chat_ediscovery_* reducers
	"BZ198": ClassConflict,      // chat: eDiscovery case not open — mutation/read against a closed ediscovery_cases row
	// Meet B2 recording (2026-07-15-meet-B2-recording.md Task 1 — this is
	// the SOLE registration site for BZ199/BZ200; Tasks 2/3/4 only RAISE,
	// Task 5 owns the meet bzSlug rows).
	"BZ199": ClassForbidden, // meet: guest⇄recording exclusion, both arms — recording start blocked by a guest ADMISSION; guest admit blocked while a recording is requested|active|stopping (meeting_recording_start / meeting_admit)
	"BZ200": ClassConflict,  // meet: recording state conflict — not live, already recording, none active to stop, bind/ingest against a wrong state (meeting_recording_* reducers)
	// Meet B3 QoL (2026-07-15-meet-B3-qol.md Task 1 — this is the SOLE
	// registration site for BZ201; Task 2 only RAISEs, Task 4 owns the meet
	// bzSlug row). F13: every BZ201 raise carries the byte-identical
	// message+HINT — the anti-oracle lump discloses THAT a breakout arg was
	// invalid, never WHICH condition failed.
	"BZ201": ClassUnprocessable, // meet: breakout invalid — not found / not open / foreign to the meeting / target unassignable (guest, banned, non-participant) / open set already exists (meeting_breakout_* reducers)
	// Pillar C0 federation spike (E2 crux — retired-docs:superpowers/plans/archive/2026-07-16-pillar-C0-federation-spike.md
	// Task 2). Sole registration site for BZ202.
	"BZ202": ClassConflict, // federation: sequence gap on inbound apply — receiver must pause + replay_req, never skip ahead (federation_apply_inbound.sql)
	// Pillar C0 federation spike (E4 — same plan, Task 3). Sole registration
	// site for BZ203.
	"BZ203": ClassForbidden, // federation: peer not locally allow-listed/enabled, or allow-list scope does not cover the requested scope (federation_peer_authorize.sql)
	// Pillar C1 DM federation (2026-07-17-pillar-C1-dm-federation.md Task
	// 2). Sole registration site for BZ204/BZ206 (BZ205 is reserved for
	// Task 7's backpressure cap — not raised by this task).
	"BZ204": ClassForbidden,     // federation: DM-ensure target peer domain not locally allow-listed/enabled (federation_dm_ensure.sql; a distinct code from BZ203's wire-handshake refusal)
	"BZ206": ClassUnprocessable, // federation: outbound chat send to a federated DM refused — feature.federation is OFF, or body exceeds the 64KiB poison cap mirrored from the inbound applier (chat_message_send's federated branch)
	// Pillar C1 DM federation (same plan, Task 7 — backpressure/dead-peer
	// cap). Sole registration site for BZ205. A user-initiated
	// federation_enqueue refuses when a peer's unacked outbox depth exceeds
	// federation.outbox_cap, or the oldest unacked frame is older than
	// federation.peer_stale_minutes — both a "try again once the peer
	// catches up / comes back" condition, the same genre as BZ200's
	// recording-state conflict, not a permissions failure.
	"BZ205": ClassConflict, // federation: user-initiated enqueue refused — peer unacked outbox depth over cap, or peer appears unreachable (stale) (federation_enqueue.sql)
	// Pillar C1 DM federation (2026-07-17-pillar-C1-dm-federation.md Task
	// 8). Sole registration site for BZ207/BZ208 (admin allow-list console).
	"BZ207": ClassInvalidArguments, // federation: peer admin arguments invalid — empty domain, bad scope, or anchor not PEM-shaped (federation_peer_set.sql; a shallow backstop, the real x509 parse + self-domain refusal are Go-side)
	"BZ208": ClassConflict,         // federation: peer must be disabled before delete — disable-before-delete lifecycle so the Service reconcile drops the live stream first (federation_peer_delete.sql)
	// Pillar C2 rooms + federated typing (2026-07-17-pillar-C2-rooms-presence-
	// federation.md Task 2 — room lifecycle reducers). Sole registration site
	// for BZ209/BZ210/BZ211 (Task 3 raises BZ212/BZ213 separately, its own
	// registration site — see the plan's Global Constraints BZ allocation).
	"BZ209": ClassUnprocessable, // federation: room-bind/archive/org-default refusal family — channel not kind='channel' / already room-bound / archived / federated-DM-shaped / an org-default channel (Q14), OR (Q13) archiving a room-bound channel while the hub still has active member orgs / a live spoke mirror (federation_room_create.sql, chat_channel.sql's chat_channel_update archive arm, chat_org_defaults.sql's chat_org_default_set)
	"BZ210": ClassUnprocessable, // federation: gxp classification × federated room binding refusal, both arms (Q7) — federation_room_create.sql refuses binding a gxp channel; chat_channel_set_classification.sql refuses gxp-classifying a room-bound channel
	"BZ211": ClassForbidden,     // federation: room membership-authority refusal family (Q3) — owner/admin required, channel not hub-shaped, target is the room's own hub domain, contactAddr domain mismatch, peer not allow-listed/enabled at scope 'room', an unknown/already-left member, an archived hub channel (federation_room_invite.sql, federation_room_remove.sql), or an unknown roomId reaching federation_room_fanout.sql (internal invariant)
	// Pillar C2 rooms + federated typing (same plan, Task 3 — the outbound
	// room arm in chat_message_send). Sole registration site for
	// BZ212/BZ213.
	"BZ212": ClassUnprocessable, // federation: outbound room-content-scope refusal (Q11) — an attachment or a non-'text' msg_type cannot propagate to a federated room, so it is refused rather than silently desyncing every member org's copy (chat_message.sql's chat_message_send)
	"BZ213": ClassForbidden,     // federation: outbound send refused because the target room mirror was closed (kicked or scope-revoked) — federated_room_removed_at is set, archive-read-only (Q3/Q9; chat_message.sql's chat_message_send; the field is written by federation_apply_room's 'remove'/'room_revoked' op arms, Task 5)
	// Guest Accounts G0 (2026-07-18-guest-G0-substrate.md Task 1 — SOLE
	// registration site for BZ215/BZ216/BZ219/BZ221; door/provision tasks
	// only RAISE):
	"BZ215": ClassForbidden, // guest door deny — org-open chat/meet surface refused for a guest account (P2/P6)
	"BZ216": ClassForbidden, // federated⇄guest exclusion, both arms (P12, BZ199 genre): guest into a federation-bound channel; guest member blocks a federation bind
	"BZ219": ClassForbidden, // guest account not active (disabled/expired) — guest_require_active belt behind the auth-chain gate
	"BZ221": ClassConflict,  // guest⇄non-guest provisioning collision, both directions, at the provision_account choke (P1)
	// Guest Accounts G1 (2026-07-19-guest-G1-invite.md Task 2).
	"BZ217": ClassForbidden,        // invite token expired/invalid/used; accept handler collapses these to uniform 401
	"BZ218": ClassForbidden,        // invited domain is not in the org allowlist
	"BZ222": ClassInvalidArguments, // invite request has a malformed/missing email
	"BZ223": ClassForbidden,        // feature disabled between approval submit and decide
	// Guest Accounts G2 profile/admin contract.
	"BZ220": ClassForbidden,     // chat membership is explicitly read-only (can_post=false)
	"BZ224": ClassUnprocessable, // invalid profile field, app list, or expiry default
	"BZ225": ClassConflict,      // assigned profile cannot be deleted
	"BZ226": ClassConflict,      // guest entitlement is profile-derived/read-only
	// Identity Model Modernization I0. Pair updates are atomic: a stable
	// subject without its provider (or provider without subject) is never a
	// usable identity and must be repaired or cleared explicitly.
	"BZ227": ClassConflict, // incomplete OIDC/SAML stable identity pair
	// Identity Model Modernization I1-I7. BZ227 was already claimed by I0,
	// so the reviewed plan's contiguous allocation shifts by one.
	"BZ228": ClassInvalidArguments, // invalid source/capability/input document
	"BZ229": ClassConflict,         // stale person/source/link generation
	"BZ230": ClassConflict,         // immutable source subject already reserved
	"BZ231": ClassUnprocessable,    // soft evidence cannot authorize a link
	"BZ232": ClassConflict,         // active authentication-link limit
	"BZ233": ClassConflict,         // lifecycle authority/link conflict
	"BZ234": ClassConflict,         // transition preflight failed
	"BZ235": ClassConflict,         // preview/generation drift
	"BZ236": ClassForbidden,        // approval/elevation invalid
	"BZ237": ClassConflict,         // last recovery route would be removed
	"BZ238": ClassConflict,         // illegal transition state
	"BZ239": ClassForbidden,        // account class excluded
	"BZ240": ClassConflict,         // idempotency-key digest conflict
	"BZ241": ClassInvalidArguments, // malformed normalized-identity reducer arguments
	// Transactional updater U0-U4. The reducer HINT carries the stable semantic
	// type while the code owns the shared HTTP/JMAP classification.
	"BZ242": ClassConflict,         // illegal/stale intent state or idempotency conflict
	"BZ243": ClassConflict,         // preview/readiness/policy generation is stale
	"BZ244": ClassForbidden,        // Enterprise entitlement does not authorize the release
	"BZ245": ClassUnprocessable,    // manifest/trust evidence is invalid or unavailable
	"BZ246": ClassConflict,         // local journal checksum/version mismatch
	"BZ247": ClassConflict,         // required application recovery set is missing or stale
	"BZ248": ClassConflict,         // executable rollback is unavailable
	"BZ249": ClassConflict,         // automated recovery stopped; operator recovery required
	"BZ250": ClassForbidden,        // system.upgrade authority/fresh elevation invalid
	"BZ251": ClassInvalidArguments, // malformed or out-of-range updater input
	// Drive node ACL and normalized directory-group authority.
	"BZ252": ClassInvalidArguments, // malformed capability, closure, or exact-check input
	"BZ253": ClassForbidden,        // Drive ACL actor lacks exact authority
	"BZ254": ClassConflict,         // Drive ACL generation/idempotency conflict
	"BZ255": ClassConflict,         // client must perform a bounded full reconcile
	"BZ256": ClassConflict,         // bound-space/node governance rejects ACL mutation
	"BZ257": ClassInvalidArguments, // malformed/cross-domain normalized group input
	"BZ258": ClassForbidden,        // normalized group actor is outside admin reach
	"BZ259": ClassConflict,         // normalized group/source generation conflict
	"BZ260": ClassConflict,         // Drive opaque live-name collision
	// Feature registry authority.
	"BZ261": ClassInvalidArguments, // malformed key, reason, or registry mode
	"BZ262": ClassConflict,         // unknown row under enforcement or digest/row cutover conflict
	"BZ263": ClassConflict,         // protected mutation or known-row deletion
	// Mail interoperability, mailbox lifecycle, sender control and shared-mail
	// productivity use one contiguous post-V194 wire family.
	"BZ264": ClassConflict,         // migration source identity/type conflict
	"BZ265": ClassInvalidArguments, // malformed migration source envelope / missing binding
	"BZ266": ClassConflict,         // migration operation replay conflict
	"BZ267": ClassConflict,         // migration source object drift
	"BZ268": ClassNotFound,         // IMAP membership tag not found
	"BZ269": ClassInvalidArguments, // IMAP UID backfill bound invalid
	"BZ285": ClassInvalidArguments, // IMAP batch location move: misaligned batch arrays
	"BZ270": ClassNotFound,         // migration target/job not found
	"BZ271": ClassInvalidArguments, // migration reconcile bound invalid
	// MEET plan M2 — reducer-owned presentation session (V265,
	// meeting_presentation.sql): the meet BZ block continues at BZ272.
	// BZ274 is the plan registry's stalePresenterGeneration /
	// presentationSequenceGap wire landing (rescue: refresh checkpoint).
	// BZ277 was the M4 annotation reservation failing closed; since the M4
	// admission (V267) it carries ADMITTED-PATH semantics — an admitted
	// snapshot commit/clear passes, every un-admitted annotation shape
	// still refuses BZ277. Same class, no renumbering.
	"BZ272": ClassNotFound,      // presentation not found / foreign to the meeting (anti-oracle; also sourceVersionGone on prepare/switch)
	"BZ273": ClassForbidden,     // presentation authority refused — not the current presenter, no Drive source right, target not a live participant
	"BZ274": ClassConflict,      // stale presenter generation or checkpoint sequence — refresh the checkpoint, never retry blind
	"BZ275": ClassConflict,      // presentation lifecycle conflict — illegal state-machine transition (terminal states never resurrect)
	"BZ276": ClassUnprocessable, // presentation invalid arguments — page index outside [0,500), same-version switch, malformed manifest digest
	"BZ277": ClassForbidden,     // annotation not admitted — since the M4 admission (V267), an un-admitted annotation shape (admitted-path semantics, not an always-refusal)
	// MEET plan M4 — semantic event capture and replay (V266,
	// meeting_semantic_recording.sql): the semantic recording slice.
	"BZ278": ClassConflict,      // semantic recording conflict — one primary recording mode per meeting (B2⇄M4), lifecycle illegal, stale stop
	"BZ279": ClassConflict,      // semantic segment ingest conflict — duplicate media interval, untruthful state promotion, unknown/stale segment re-entry
	"BZ280": ClassConflict,      // .sjrec package delete/hold conflict — child release outside DELETE_PENDING or stale generation, delete outside ACTIVE, restore of non-HELD_COMPLETE, export against a deletion fence
	"BZ281": ClassUnprocessable, // semantic export invalid — no verified audio interval, coverage drift from the confirmed receipt bounds
	// MEET plan M5 — Electron local-first capture (V268,
	// meeting_local_capture.sql): the capture lease + truthful
	// local-package registration.
	"BZ282": ClassConflict,         // local capture lease conflict — unknown/foreign lease, stale lease generation, an expired lease used as if live (captureLeaseExpired)
	"BZ283": ClassUnprocessable,    // local capture invalid — malformed acquire/heartbeat/stop shapes, a heartbeat seq regression, register against a capture that has not stopped
	"BZ284": ClassForbidden,        // local package registration not admitted — an untruthful sjrec-local-v1 descriptor (the BZ277 admitted-path genre): schema drift, fabricated completeness, coverage/identity drift, conflicting re-registration
	"BZ300": ClassNotFound,         // OFF-gated lifecycle/productivity surface
	"BZ301": ClassInvalidArguments, // malformed lifecycle/productivity input
	"BZ302": ClassNotFound,         // lifecycle target not found
	"BZ303": ClassStateMismatch,    // idempotency UUID digest conflict
	"BZ304": ClassStateMismatch,    // stale generation / already-won mutation
	"BZ305": ClassConflict,         // illegal mailbox lifecycle state
	"BZ306": ClassConflict,         // reconnect target already has a mailbox
	"BZ307": ClassForbidden,        // reconnect evidence/identity is not authorized
	"BZ308": ClassForbidden,        // independent purge approval required
	"BZ309": ClassStateMismatch,    // purge preview digest is stale
	"BZ310": ClassNotFound,         // purge request/approval not found
	"BZ311": ClassForbidden,        // purge is not independently approved
	"BZ312": ClassConflict,         // retention authority blocks purge
	"BZ313": ClassConflict,         // purge is no longer cancellable / retained delete guard
	// Exchange replacement assessment control plane.
	"BZ314": ClassForbidden,        // retained address mutation/release is forbidden
	"BZ315": ClassConflict,         // address is reserved by another retained mailbox
	"BZ316": ClassInvalidArguments, // malformed bounded assessment argument
	"BZ317": ClassNotFound,         // unauthorized or unavailable project/run (anti-oracle)
	"BZ318": ClassConflict,         // stale run generation, lease, or fencing token
	"BZ319": ClassConflict,         // illegal lifecycle transition or conflicting replay
	"BZ320": ClassUnprocessable,    // evidence-derived publication requirements are incomplete
	// Office broker and WOPI authority.
	"BZ321": ClassNotFound,         // unavailable/unauthorized Office target or session (anti-oracle)
	"BZ322": ClassInvalidArguments, // malformed Office launch, lock, save, or policy argument
	"BZ323": ClassForbidden,        // Office policy, classification, platform, or entitlement denies action
	"BZ324": ClassStateMismatch,    // stale Office fence, expired launch, or terminal cohort
	"BZ325": ClassConflict,         // WOPI opaque lock mismatch
	"BZ326": ClassStateMismatch,    // Office operation-key replay disagrees with its durable receipt
	"BZ327": ClassConflict,         // Office provider is disabled, draining, or unavailable
	"BZ328": ClassConflict,         // identity address admission: the address would gain a second enabled claimant
	"BZ329": ClassStateMismatch,    // meet lobby admitted re-mint fence: the join request's 15-minute mint window (meeting_lobby_mint_fences, V270) is closed — the poll maps this to its own expired shape, so it surfaces only on direct fence misuse
	// JMAP state
	ErrCannotCalcChanges: ClassCannotCalc, // BZ011
	// transient infra/config (retry)
	ErrMissingInbox: ClassTransient, // BZ008
}

// intentional500 lists BZ codes that DELIBERATELY project to 500 — internal
// invariants and append-only guards that fire only on a bug, never on a
// client-actionable condition, so leaking a 4xx would be misleading. They behave
// exactly like an unclassified code at runtime (Classify → ClassUnknown → 500);
// this set exists so the machine guard (guard_test.go) can tell "deliberately
// 500" apart from "forgot to classify" (which is a build failure).
var intentional500 = map[string]bool{
	ErrInvalidSide: true, // BZ010 invalid rule evaluation side (corrupt rule)
	"BZ012":        true, // immutable/terminal queue status transition
	"BZ013":        true, // user must keep at least one primary mailbox
	"BZ014":        true, // user has no primary mailbox
	"BZ016":        true, // crash_events append-only
	"BZ017":        true, // audit records append-only
	"BZ018":        true, // greylist delay must be positive
	"BZ034":        true, // notify_* called with a NULL mailbox
	"BZ035":        true, // message carries >1 location tag (corrupt state)
	"BZ067":        true, // audit_write bad tier
	"BZ073":        true, // read-receipt policy=never guard
	"BZ079":        true, // ca_notify called with a blank reason (defensive)
	"BZ083":        true, // ca_signin_log append-only
}

// CodeIsKnown reports whether a raw SQLSTATE/BZ code is a recognized business
// error code (classified in codeClass, or a deliberate intentional500). Exposed
// for callers that route on the stable code directly (the JMAP map, the SMTP
// permanent/transient classifier) without unmarshalling the HINT.
func CodeIsKnown(code string) bool {
	if _, ok := codeClass[code]; ok {
		return true
	}
	return intentional500[code]
}

// IsCode reports whether err is a pg error carrying one of the given BZ
// SQLSTATEs. It is the sanctioned seam for SEMANTIC control-flow branches on a
// specific business condition — an idempotent-success (BZ101 wipe-ack), a
// bespoke render path (approval email pages), a call-site-contextual dual-use
// meaning (calendar BZ001, litigation-hold/app-password BZ015). Wire status /
// JMAP type / detail projections must NOT route through IsCode — that is what
// Classify + HTTPStatus/JMAPError + Detail are for, and the
// check-reducererr-contract.sh guard bans hand-rolled pgErr.Code switching on
// BZ literals outside this package.
func IsCode(err error, codes ...string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	for _, c := range codes {
		if pgErr.Code == c {
			return true
		}
	}
	return false
}

// WriteHTTPError classifies a reducer error through Classify and writes the
// matching status to w, logging at the class's LogLevel() — a client-actionable
// business failure (403/404/409/507/…) logs at Info since it's expected and
// recoverable, while a genuinely-internal error (the 500 fallback) logs at
// Error. Shared by the CalDAV and CardDAV handlers so both surfaces project
// reducer errors identically instead of each keeping its own copy.
func WriteHTTPError(ctx context.Context, w http.ResponseWriter, logger *slog.Logger, logMsg string, err error) {
	class := Classify(err)
	status := class.WebDAVStatus()
	logger.Log(ctx, class.LogLevel(), logMsg, "error", err, "status", status)
	w.WriteHeader(status)
}

// ParseReducerError extracts a business error from a pgx database error.
// Returns (nil, err) if the error is not a recognized business error —
// callers should treat the original error as a generic server failure.
func ParseReducerError(err error) (*ReducerError, error) {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return nil, err
	}
	if !CodeIsKnown(pgErr.Code) {
		return nil, err
	}
	var rerr ReducerError
	if pgErr.Hint != "" {
		// A malformed HINT must not partially populate classification-relevant
		// fields (D-SHARED-REDUCERERR-001): json.Unmarshal into a struct can
		// succeed on a prefix-valid payload while leaving fields at zero values
		// or half-decoded. Code and HINT are raised by reducer code, never by
		// client requests, so a malformed HINT is a defect — fail toward safety
		// by rejecting the parse and letting the caller treat the original
		// error as a generic server failure. json.Unmarshal also enforces the
		// consumed fields' JSON types (string/number), rejecting type-forged
		// payloads rather than silently zeroing them.
		if err := json.Unmarshal([]byte(pgErr.Hint), &rerr); err != nil {
			return nil, err
		}
	}
	if rerr.Type == "" {
		rerr.Type = pgErr.Code
	}
	return &rerr, nil
}
