package meet

import (
	"net/http"

	"setjoin.com/shared/reducererr"
)

// bzSlug is the meet BZ185-BZ190 + BZ199/BZ200 → RFC7807 `type` slug map (the
// plan's locked table, retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md, and
// shared/reducererr's codeClass entries): BZ185 not-found
// (anti-oracle — nonexistent/ended/guest-disallowed/guest_access-off all
// read identically on the PUBLIC surface, the drive BZ139/chat BZ170
// posture) · BZ186 forbidden (host-or-cohost-required action, or a banned
// participant rejoining before host re-admit) · BZ187 meeting-locked (join
// refused — the client falls back to a knock via join-request, a distinct
// slug from BZ186 so the client can branch on it without string-matching
// Detail) · BZ188/BZ189 invalid-arguments (invalid create/mutate args; a
// join-request not decidable — not pending/expired/nonexistent/wrong
// meeting, one code, no oracle on which) · BZ190 conflict (mutation against
// an already-ended meeting). BZ180-BZ184 are an unallocated gap — never
// backfill. B2 (this task, Task 5, is the SOLE Go-surface registration site
// per the plan's ownership split — reducererr's codeClass entries are
// Task 1's): BZ199 recording-guest-exclusion (the §8.2 guest⇄recording
// exclusion, both arms — start blocked by an admitted guest, or an admit
// blocked by a requested|active|stopping recording) · BZ200
// recording-conflict (a recording state-machine conflict — not live,
// already recording, none active to stop, a bind/ingest against the wrong
// state). B3 (this task — internal/meet/breakouts.go's Task 4 — is the SOLE
// Go-surface registration site for BZ201 per the plan's ownership split;
// Task 1 owns reducererr.codeClass, Task 2 owns the RAISEs): BZ201
// breakout-invalid (the meeting_breakout_* anti-oracle lump, F13 —
// breakout not found / not open / foreign to the meeting / target
// unassignable (guest, banned, departed, non-participant) / an open set
// already exists — byte-identical message+HINT on every raise, so this
// slug discloses THAT a breakout argument was invalid, never WHICH
// condition failed).
var bzSlug = map[string]string{
	"BZ185": "not-found",
	"BZ186": "forbidden",
	"BZ187": "meeting-locked",
	"BZ188": "invalid-arguments",
	"BZ189": "invalid-arguments",
	"BZ190": "conflict",
	"BZ199": "recording-guest-exclusion",
	"BZ200": "recording-conflict",
	"BZ201": "breakout-invalid",

	// MEET plan M2 (V265; internal/meet/presentation.go is the sole
	// Go-surface registration site — reducererr.codeClass entries ride the
	// BZ block): the reducer-owned presentation session's codes. BZ274 is
	// deliberately its own slug (not generic "conflict") so the client can
	// branch to the refresh-checkpoint rescue without string-matching
	// Detail. BZ277 was the M4 annotation reservation failing closed; since
	// the M4 admission (V267) it carries ADMITTED-PATH semantics — a
	// well-formed snapshot commit or clear through
	// meeting_presentation_annotation_commit is admitted, and the slug now
	// marks every un-admitted annotation shape (malformed/empty/oversized/
	// reference-less) still refusing fail-closed. No renumbering: same code,
	// same slug, same 403 class.
	"BZ272": "presentation-not-found",
	"BZ273": "presentation-forbidden",
	"BZ274": "stale-presenter-generation",
	"BZ275": "presentation-lifecycle",
	"BZ276": "presentation-invalid-arguments",
	"BZ277": "annotation-not-admitted",

	// MEET plan M4 (V266; worker_semantic.go is this slice's consumer —
	// the semantic recording reducers are worker/reducer-plane, no new HTTP
	// route in slice 1, so no new route-level slug branching exists yet):
	// BZ278 semantic-recording-conflict (one primary recording mode,
	// lifecycle), BZ279 semantic-segment-conflict (duplicate media /
	// untruthful ingest), BZ280 sjrec-package-conflict (delete/hold/restore
	// fencing), BZ281 semantic-export-invalid (no verified interval,
	// coverage drift).
	"BZ278": "semantic-recording-conflict",
	"BZ279": "semantic-segment-conflict",
	"BZ280": "sjrec-package-conflict",
	"BZ281": "semantic-export-invalid",

	// MEET plan M5 (V268; internal/meet/localcapture.go is the sole
	// route-level consumer — the local-capture HTTP surface, flag-gated on
	// feature.meet_local_recording): BZ282 local-capture-lease-conflict
	// (unknown/foreign lease, stale generation — an expired lease is met
	// with the truthful stop FACT and a stop against a terminal lease
	// replays it, never this code), BZ283
	// local-capture-invalid (malformed acquire/heartbeat/stop shapes, a
	// heartbeat seq regression, register before stop), BZ284
	// local-package-not-admitted (an untruthful sjrec-local-v1
	// descriptor — the BZ277 admitted-path genre, same 403 class).
	"BZ282": "local-capture-lease-conflict",
	"BZ283": "local-capture-invalid",
	"BZ284": "local-package-not-admitted",

	// V270 (the durable admitted re-mint fence, occ_bcdf321's reducer half):
	// BZ329 admission-mint-fenced — meeting_lobby_mint_fence refused a mint
	// past the join request's 15-minute admitted re-mint window. The poll
	// catches this code in the reducer and synthesizes its own expired shape,
	// so it never projects onto the wire from the public surface; the slug
	// exists so a direct fence misuse (never expected) projects coherently
	// instead of falling through to the unknown-code 500.
	"BZ329": "stateMismatch",
}

// meetProblemOpts is this package's half of the shared reducererr.WriteProblem
// contract (whole-pipeline review arch #3): the namespace + bzSlug table
// above. No per-code status override is needed: every meet BZ code's
// reducererr.codeClass entry already projects to the exact wire status this
// package wants (BZ185→404, BZ186/BZ187→403, BZ188/BZ189→422, BZ190→409); an
// unrecognized error falls through to the shared ClassUnknown default (500).
var meetProblemOpts = reducererr.ProblemOptions{Namespace: "meet", Slugs: bzSlug}

// writeMeetProblem projects a reducer error onto RFC 7807 via the shared
// reducererr kit (reducererr.WriteProblem) — the classify/detail/status/type
// wiring itself lives once in internal/reducererr, shared with chat and
// drive; never a hand-rolled pgErr.Code switch here (banned outside
// internal/reducererr by scripts/check-reducererr-contract.sh).
func writeMeetProblem(w http.ResponseWriter, r *http.Request, err error) {
	reducererr.WriteProblem(w, r, err, meetProblemOpts)
}
