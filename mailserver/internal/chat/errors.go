package chat

import (
	"net/http"

	"setjoin.com/shared/reducererr"
)

// bzSlug is the chat BZ→RFC7807 `type` slug map (Task 8's locked table,
// extended for BZ171 — Task 17 gate: found the archive/read-only guard's
// code missing from this map, a small drift from when it was added after
// Task 8's table was written; the wire STATUS was never wrong, since
// reducererr's shared codeClass already classifies BZ171 ClassForbidden,
// but the response lost its `code`/`type` fields):
// BZ160 invalid_channel argument · BZ161/163/164/166/167/171 forbidden ·
// BZ162/165/168 invalid-content · BZ169/BZ170 not-found (BZ170 is the
// anti-oracle leg — joining a private/nonexistent channel reads identically,
// same posture as drive's BZ139). Chat A2 (DES-009) adds BZ172 invalid
// attachment payload (>8 cap / bad shape) · BZ173 attachments unavailable
// (feature.drive off, reducer defense) · BZ175 chat-attached node immutable
// via Drive / chat-bound space rejects ad-hoc member grants (raised by the
// drive reducers chat_message_send calls into, so still surfaced here).
// Chat A3 QoL (2026-07-12-chat-A3-qol.md) adds BZ178 invalid-arguments (Task
// 6 voice duration cap), BZ176 forbidden (Task 3 pin/unpin permission),
// BZ179 invalid-arguments (Task 2 scheduled-send invalid), and BZ177
// invalid-arguments (Task 9 poll invalid — poll/option not found, anchor
// message soft-deleted, or already closed; the wrong-actor close case
// reuses BZ161 forbidden instead of BZ177, see chat_poll.sql).
// Chat A4a (2026-07-12-chat-A4a-records-lifecycle.md) reserves BZ191-196:
// BZ191 (Task 2, chat_access_audit unknown action), BZ192/BZ193 (Task 8,
// V126 no-downgrade/WORM triggers), BZ194 (Task 5, V126 legal-hold trigger),
// BZ195 (Task 4, retention/hold/classification invalid arguments), BZ196
// (Task 10, send-rate limit). reducererr.codeClass for BZ192-195 is
// SOLELY registered by Task 1 (V126's own migration commit) — BZ191/BZ196
// each have exactly one registration site (Tasks 2/10). This map's entries
// for those codes are added by the task that raises them, not by Task 1.
// Chat A4b (2026-07-15-chat-A4b-oversight.md) reserves BZ197/BZ198:
// reducererr.codeClass for both is SOLELY registered by Task 1 (V127's own
// migration commit); this package's bzSlug entries are SOLELY registered by
// Task 2 (the first task to RAISE them, in chat_case_hold_set/release) —
// Tasks 3/4 only RAISE, they do not touch this map. BZ197 invalid oversight
// arguments (bad hold scope/query/target, hold not found or already
// released), BZ198 eDiscovery case not open (mutation/read against a closed
// ediscovery_cases row).
// Pillar C1 DM federation (2026-07-17-pillar-C1-dm-federation.md): BZ204/
// BZ206's reducererr.codeClass is SOLELY registered by Task 2 (this file's
// own entries are added by Task 3, the first task to surface them through a
// chat route — federation_dm_ensure.sql/chat_message.sql only RAISE). BZ204
// forbidden (federation_dm_ensure's local refusal — the peer domain isn't
// locally allow-listed/enabled for DM), BZ206 invalid-arguments
// (chat_message_send's federated branch refuse — feature.federation OFF, or
// the federated body exceeds the 64KiB poison cap).
// Pillar C2 rooms federation (2026-07-17-pillar-C2-rooms-presence-
// federation.md): BZ205/BZ209-BZ213's reducererr.codeClass is SOLELY
// registered by earlier tasks (federation_enqueue.sql/V140's own migration
// commit); this file's own entries are added by Task 7, the first task to
// surface a room-scoped send through a chat route. BZ205 conflict
// (federation_enqueue's user-initiated backpressure/stale-peer refusal — a
// spoke room send hits the SAME code a federated DM send already could;
// store.svelte.ts's errorKeyByCode maps it to the dedicated "hub org
// unreachable" copy, the stale-hub surface), BZ209/BZ210/BZ212
// invalid-arguments (room-bind/archive/org-default/gxp/content-scope refusal
// families — federation_room_create.sql, chat_channel_update's archive arm,
// chat_org_default_set, chat_channel_set_classification, chat_message_send's
// room content-scope guard), BZ211/BZ213 forbidden (room membership-
// authority refusals — federation_room_invite/remove.sql, federation_room_
// roster.sql's not-room-bound refusal; the kicked/removed-mirror send
// refusal, chat_message_send).
// Guest Accounts G0 (2026-07-18-guest-G0-substrate.md): BZ215 forbidden
// (guest door deny — join/browse/create/dm-open/member-add and the Meet
// blanket), BZ216 forbidden (federated⇄guest exclusion both arms), BZ219
// forbidden (guest not active — the guest_require_active belt).
// reducererr.codeClass for all three was registered by G0 Task 1. Guest G2
// adds BZ220 forbidden for an explicit can_post=false membership.
//
// Codes absent here aren't chat-specific — the `code` extension is left
// empty and status/detail fall back to the shared reducererr projection.
var bzSlug = map[string]string{
	"BZ160": "invalid-arguments",
	"BZ161": "forbidden",
	"BZ162": "invalid-arguments",
	"BZ163": "forbidden",
	"BZ164": "forbidden",
	"BZ165": "invalid-arguments",
	"BZ166": "forbidden",
	"BZ167": "forbidden",
	"BZ168": "invalid-arguments",
	"BZ169": "not-found",
	"BZ170": "not-found",
	"BZ171": "forbidden",
	"BZ172": "invalid-arguments",
	"BZ173": "forbidden",
	"BZ175": "forbidden",
	"BZ176": "forbidden",
	"BZ177": "invalid-arguments",
	"BZ178": "invalid-arguments",
	"BZ179": "invalid-arguments",
	"BZ191": "invalid-arguments",
	"BZ192": "state-mismatch",
	"BZ193": "immutable",
	"BZ194": "forbidden",
	"BZ195": "invalid-arguments",
	"BZ196": "sending-quota-exceeded",
	"BZ197": "invalid-arguments",
	"BZ198": "state-mismatch",
	"BZ204": "forbidden",
	"BZ206": "invalid-arguments",
	"BZ205": "conflict",
	"BZ209": "invalid-arguments",
	"BZ210": "invalid-arguments",
	"BZ211": "forbidden",
	"BZ212": "invalid-arguments",
	"BZ213": "forbidden",
	"BZ215": "forbidden",
	"BZ216": "forbidden",
	"BZ219": "forbidden",
	"BZ220": "forbidden",
}

// chatProblemOpts is this package's half of the shared reducererr.WriteProblem
// contract (whole-pipeline review arch #3): the namespace + bzSlug table
// above. Unlike drive's problem.go, no per-code status OVERRIDE is needed
// here: every chat BZ code's reducererr.codeClass entry already projects to
// the exact wire status this package wants (BZ160→400,
// BZ161/163/164/166/167/171→403, BZ162/165/168→422, BZ169/BZ170→404); an
// unrecognized error falls through to the shared ClassUnknown default (500).
var chatProblemOpts = reducererr.ProblemOptions{Namespace: "chat", Slugs: bzSlug}

// writeChatProblem projects a reducer error onto RFC 7807 via the shared
// reducererr kit (reducererr.WriteProblem) — the classify/detail/status/type
// wiring itself lives once in internal/reducererr, shared with meet and
// drive; never a hand-rolled pgErr.Code switch here (banned outside
// internal/reducererr by scripts/check-reducererr-contract.sh).
func writeChatProblem(w http.ResponseWriter, r *http.Request, err error) {
	reducererr.WriteProblem(w, r, err, chatProblemOpts)
}
