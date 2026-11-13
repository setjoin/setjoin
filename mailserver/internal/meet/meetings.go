// meetings.go — Task 10: create/list/get/join + the host/cohost control
// surface (lock/settings/role/kick/end). The chat translator discipline
// (channels.go's shape): claims -> parse -> one reducer call -> map error;
// zero business logic in Go. The two eviction-choke-point routes (kick,
// end) each add exactly one h.rooms call AFTER the reducer authorizes and
// mutates (DES-011: authority first, then eviction) — a RoomController
// error there is reported 502 and logged, never panicked; the DB state is
// already correct so a retry (or the Task 12 reconcile sweep) converges.
//
// W4 native-RLS: every reducer/table call below that runs on an
// authenticated request (i.e. everything except webhook.go's receiver and
// lobby.go's PublicHandler, neither of which has a caller identity) is
// GUC-scoped via dbscope.RunUserScoped(claims.UserID) — either through the
// execMeet/queryMeetJSON choke point, or wrapped inline where a route needs
// more than one statement (createMeeting/join/kick/endMeeting). See
// retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md; guarded by
// scripts/check-rls-scope-wrap.sh.
package meet

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerMeetingRoutes registers every route this file serves onto h.mux.
// Called from NewHandler (handler.go) alongside Tasks 11-13's own
// register*Routes, mirroring chat.NewHandler's shape.
func (h *Handler) registerMeetingRoutes(mux router) {
	mux.HandleFunc("POST /meet", h.createMeeting)
	mux.HandleFunc("GET /meet", h.listMeetings)
	mux.HandleFunc("GET /meet/by-slug/{slug}", h.getMeetingBySlug)
	mux.HandleFunc("GET /meet/{id}", h.getMeeting)
	mux.HandleFunc("POST /meet/{id}/join", h.join)
	mux.HandleFunc("POST /meet/{id}/lock", h.lockMeeting)
	mux.HandleFunc("POST /meet/{id}/settings", h.setGuestAllowed)
	mux.HandleFunc("POST /meet/{id}/role", h.setRole)
	mux.HandleFunc("POST /meet/{id}/kick", h.kick)
	mux.HandleFunc("POST /meet/{id}/end", h.endMeeting)
}

// decodeMeetBody decodes the request body into dst, writing a 400 Problem
// and returning false on failure. Shared by every mutating route below that
// takes a JSON body (the decodeChatBody precedent).
func decodeMeetBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := httputil.DecodeJSON(w, r, dst); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	return true
}

// meetIDBody parses the "id" path parameter and decodes the request body
// into a fresh T (the chatIDBody precedent) — the shared skeleton behind
// every route that takes both a meeting id and a JSON body.
func meetIDBody[T any](w http.ResponseWriter, r *http.Request) (id int64, body T, ok bool) {
	id, ok = httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return 0, body, false
	}
	if !decodeMeetBody(w, r, &body) {
		return 0, body, false
	}
	return id, body, true
}

// execMeet runs a void-returning reducer and responds 204, mapping any
// reducer error to an RFC7807 problem (the execChat precedent). Used by
// every route here whose reducer has nothing to return (lock/settings/role).
// userID GUC-scopes the call (W4 — see meetings.go's package-level dbscope
// note, dbscope.RunUserScoped sets `app.current_user_id` transaction-locally
// so the V134 write policies admit it); callers pass userID again inside
// args since the reducer's own p_user_id parameter is a separate bound
// value (the chat.execChat/drive call-site convention, verbatim).
func (h *Handler) execMeet(w http.ResponseWriter, r *http.Request, userID int64, sql string, args ...any) {
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// queryMeetJSON runs a jsonb-returning reducer and writes the result
// verbatim (the queryChatJSON precedent) — meeting_list/get/get_by_slug
// already project exactly the wire shape. userID is GUC-scoped exactly like
// execMeet (W4) — the sole choke point (whole-pipeline review arch #3)
// callers of the old reducererr.QueryJSON kit flow through; chat's
// queryChatJSON is the identical shape.
func (h *Handler) queryMeetJSON(w http.ResponseWriter, r *http.Request, userID int64, sql string, args ...any) {
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

// queryStringColumnScoped runs a single-text-column query GUC-scoped to
// userID (W4) and collects every row into a slice — the shared shape behind
// endMeeting's two "collect room/egress names to act on after the
// transaction closes" reads (the dupl linter flagged the identical
// scan-loop written out twice). A row Scan failure is silently skipped
// (best-effort collection, matching the pre-W4 behavior) rather than
// aborting the whole read.
func (h *Handler) queryStringColumnScoped(ctx context.Context, userID int64, sql string, args ...any) ([]string, error) {
	var out []string
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if rows.Scan(&v) == nil {
				out = append(out, v)
			}
		}
		return rows.Err()
	})
	return out, err
}

// roomNameForMeeting reads the LiveKit room name (the meeting's PARENT
// room only — it has no notion of breakout children) for a meeting a
// reducer call just authorized. Used by recording.go's startRecording and
// captions.go's stopCaptions, always strictly AFTER the caller's own
// reducer call already authorized userID against meetingID, so this trivial
// lookup rides on authorization already proven, not a fresh ownership check
// of its own — but the `meetings` SELECT policy (V134 §A) still requires a
// non-NULL app.current_user_id GUC (any authenticated org user, not just a
// participant), so userID GUC-scopes it exactly like every other call here.
// NOT used by kick anymore (B3 delta 2): meeting_kick itself now RETURNS the
// target's CURRENT room (main or an open child breakout, F1), so the kick
// route Scans that instead of resolving the parent room here.
func (h *Handler) roomNameForMeeting(ctx context.Context, userID, meetingID int64) (string, error) {
	var room string
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT room_name::text FROM meetings WHERE id = $1`, meetingID).Scan(&room)
	})
	return room, err
}

type createMeetingBody struct {
	Title           string     `json:"title"`
	ScheduledStart  *time.Time `json:"scheduledStart"`
	ScheduledEnd    *time.Time `json:"scheduledEnd"`
	ChatChannelID   *int64     `json:"chatChannelId"`
	CalendarEventID *int64     `json:"calendarEventId"`
	GuestAllowed    *bool      `json:"guestAllowed"`
}

// createMeeting serves POST /meet. Optional fields ride as pointers (the
// chat scheduled-send precedent, scheduled.go's FireAt *time.Time) so an
// absent field cleanly becomes SQL NULL — meeting_create's own DEFAULT NULL
// params, never a zero-value time.Time standing in for "not scheduled".
func (h *Handler) createMeeting(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body createMeetingBody
	if !decodeMeetBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_create($1, $2, $3, $4, $5, $6, $7)`,
			claims.UserID, body.Title, body.ScheduledStart, body.ScheduledEnd,
			body.ChatChannelID, body.CalendarEventID, body.GuestAllowed).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, out)
}

// listMeetings serves GET /meet — "my meetings" (owner or participant,
// meeting_list's own not-ended-older-than-24h filter).
func (h *Handler) listMeetings(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	h.queryMeetJSON(w, r, claims.UserID, `SELECT meeting_list($1)`, claims.UserID)
}

// getMeeting serves GET /meet/{id} — detail, org-open read (meeting_get's
// own posture: any authenticated org user, not just a participant).
func (h *Handler) getMeeting(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	h.queryMeetJSON(w, r, claims.UserID, `SELECT meeting_get($1, $2)`, claims.UserID, id)
}

// getMeetingBySlug serves GET /meet/by-slug/{slug} — the member deep-link
// resolve (spec HTTP surface).
func (h *Handler) getMeetingBySlug(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	slug := r.PathValue("slug")
	h.queryMeetJSON(w, r, claims.UserID, `SELECT meeting_get_by_slug($1, $2)`, claims.UserID, slug)
}

// join serves POST /meet/{id}/join -> {token, wsPath, expiresAt, meeting}.
// Flow (locked in the plan): meeting_join composes the grant spec (the
// reducer's job) -> h.rooms.CreateRoom pre-creates the room (idempotent —
// auto-create is OFF in livekit.yaml, DES-011) -> MintToken translates the
// spec into a signed JWT (Go's only job). A CreateRoom failure 502s before
// any token is minted — a token for a room that doesn't exist is useless.
func (h *Handler) join(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}

	ctx := r.Context()
	// meeting_get is moved ahead of CreateRoom (was originally issued AFTER
	// minting) so its roomName can settle which CreateRoom variant to use —
	// no extra query added. D10 (B3): meeting_join can redirect a
	// mid-assignment member straight into their OPEN breakout's child room
	// instead of the parent. A child room needs the D12 generous timeout
	// pair (86400/86400, breakouts.go's breakoutEmptyTimeout/
	// breakoutDepartureTimeout) — pre-creating it with the main room's
	// 300/20 pair lets the SFU self-finish an open breakout nobody closed,
	// which the D12 accept-as-close arm then closes out from under the
	// host (eng retro finding #2). Both reads are quick, no external I/O
	// between them, so they share ONE GUC-scoped transaction (W4).
	var specJSON, meetingJSON json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT meeting_join($1, $2)`, claims.UserID, id).Scan(&specJSON); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT meeting_get($1, $2)`, claims.UserID, id).Scan(&meetingJSON)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	var spec grantSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		h.logger.Error("meet: could not decode grant spec", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	var meetingEnvelope struct {
		RoomName string `json:"roomName"`
	}
	if err := json.Unmarshal(meetingJSON, &meetingEnvelope); err != nil {
		h.logger.Error("meet: could not decode meeting envelope", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}

	var createErr error
	if spec.Room != meetingEnvelope.RoomName {
		createErr = h.rooms.CreateRoomWithTimeouts(r.Context(), spec.Room, breakoutEmptyTimeout, breakoutDepartureTimeout)
	} else {
		createErr = h.rooms.CreateRoom(r.Context(), spec.Room)
	}
	if createErr != nil {
		h.logger.Error("meet: CreateRoom failed", "room", spec.Room, "err", createErr)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "could not prepare the meeting room")
		return
	}

	token, expiresAt, err := MintToken(h.cfg, spec)
	if err != nil {
		h.logger.Error("meet: MintToken failed", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"wsPath":    "/rtc",
		"expiresAt": expiresAt,
		"meeting":   meetingJSON,
		// D5 "rides EVERY admission envelope" (E-F3): the grant spec's own
		// recordingActive, not a second getMeeting read — the join response
		// IS the admission fact Task 10's RecordingBanner seeds from.
		"recordingActive": spec.RecordingActive,
		// B3 Task 14 plan delta 4: whether an ASR sidecar is provisioned on
		// this box at all (h.captions != nil) — distinct from
		// meeting_get's captionsEnabled (the feature.meet_captions toggle)
		// and captionsOn (the live flag); the webmail ControlsBar button
		// needs both signals before it renders (Task 15).
		"captionsConfigured": h.captions != nil,
	})
}

type lockBody struct {
	Locked bool `json:"locked"`
}

type settingsBody struct {
	GuestAllowed bool `json:"guestAllowed"`
}

// execIDBoolBodyRoute is the shared skeleton behind lockMeeting and
// setGuestAllowed below — both are "parse id + one JSON bool field, exec a
// 3-arg void reducer" and were flagged identical by the dupl linter as
// written out twice; a free function (not a method) since Go methods can't
// take their own type parameters.
func execIDBoolBodyRoute[T any](h *Handler, w http.ResponseWriter, r *http.Request, sql string, valueOf func(T) bool) {
	claims := auth.UserFromContext(r.Context())
	id, body, ok := meetIDBody[T](w, r)
	if !ok {
		return
	}
	h.execMeet(w, r, claims.UserID, sql, claims.UserID, id, valueOf(body))
}

// lockMeeting serves POST /meet/{id}/lock {locked}. Documented non-revoke
// route (meeting_lock.sql comment, DES-011): blocks NEW joins only, evicts
// nobody already connected — no h.rooms call here, ever
// (TestEveryRevokePathEvicts pins the absence).
func (h *Handler) lockMeeting(w http.ResponseWriter, r *http.Request) {
	execIDBoolBodyRoute(h, w, r, `SELECT meeting_lock($1, $2, $3)`, func(b lockBody) bool { return b.Locked })
}

// setGuestAllowed serves POST /meet/{id}/settings {guestAllowed} (CEO #4 —
// flip guests on/off mid-meeting). Also a documented non-revoke route:
// affects FUTURE join-requests only, never evicts an already-admitted guest
// (kick is the eviction tool for that).
func (h *Handler) setGuestAllowed(w http.ResponseWriter, r *http.Request) {
	execIDBoolBodyRoute(h, w, r, `SELECT meeting_set_guest_allowed($1, $2, $3)`,
		func(b settingsBody) bool { return b.GuestAllowed })
}

type roleBody struct {
	Identity string `json:"identity"`
	Role     string `json:"role"`
}

// setRole serves POST /meet/{id}/role {identity, role}. Host only; also the
// re-admit path — assigning a role to a banned identity clears banned_at in
// the same reducer call (meeting_set_role.sql), no separate route.
func (h *Handler) setRole(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, body, ok := meetIDBody[roleBody](w, r)
	if !ok {
		return
	}
	h.execMeet(w, r, claims.UserID, `SELECT meeting_set_role($1, $2, $3, $4)`, claims.UserID, id, body.Identity, body.Role)
}

type kickBody struct {
	Identity string `json:"identity"`
}

// kick serves POST /meet/{id}/kick {identity}. Authority first
// (meeting_kick authorizes + bans in one statement), THEN the eviction call
// — DES-011's ordering: a revoke is never just a DB stamp. A
// RemoveParticipant failure is reported 502 and logged; the DB state (the
// ban) is already correct, so a host retry — or Task 5's reconcile sweep —
// converges without re-running the authorization check.
//
// B3 (delta 2): meeting_kick RETURNS the target's CURRENT room name (main
// or an open child breakout — F1: a kick against a mid-breakout target
// must evict from the CHILD room, never assume the parent) instead of
// void, so this route Scans it directly rather than resolving the parent
// room via roomNameForMeeting.
func (h *Handler) kick(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, body, ok := meetIDBody[kickBody](w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var room string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_kick($1, $2, $3)`,
			claims.UserID, id, body.Identity).Scan(&room)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	if err := h.rooms.RemoveParticipant(r.Context(), room, body.Identity); err != nil {
		h.logger.Error("meet: RemoveParticipant failed", "room", room, "identity", body.Identity, "err", err)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "kicked, but eviction failed; will be retried")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// endMeeting serves POST /meet/{id}/end. Host only; meeting_end returns the
// room_name (its Task 4 contract — Go needs it to DeleteRoom), so no extra
// lookup is needed here, unlike kick.
func (h *Handler) endMeeting(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	ctx := r.Context()
	var room string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_end($1, $2)`, claims.UserID, id).Scan(&room)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	// B2 law 1: StopEgress for each in-flight recording BEFORE DeleteRoom
	// (meeting_end already flipped them to 'stopping' in the same reducer
	// txn). Errors are logged, never fatal — the worker's stop leg retries.
	// The egress-id read and the StopEgress calls are two separate
	// GUC-scoped transactions (W4): a pgx tx must not sit open across a
	// slow external network call to the egress sidecar.
	if h.egress != nil {
		ids, qerr := h.queryStringColumnScoped(ctx, claims.UserID,
			`SELECT egress_id FROM meeting_recordings
			  WHERE meeting_id = $1 AND state = 'stopping' AND egress_id IS NOT NULL`, id)
		if qerr == nil {
			for _, eid := range ids {
				if err := h.egress.StopEgress(r.Context(), eid); err != nil {
					h.logger.Error("meet: StopEgress at end failed", "egress_id", eid, "err", err)
				}
			}
		} else {
			h.logger.Error("meet: stopping-recordings query at end failed", "err", qerr)
		}
	}
	// B3 delta 3: meeting_end's return contract is unchanged (still the
	// parent room only) — the reducer already closed every open breakout
	// in the same txn (law 1: ending drops everyone). Go drains the
	// now-closed child room names in a SEPARATE query (the pgx
	// one-active-query rule — this can't ride the same row set as the
	// stopping-recordings query above) and DeleteRooms each, the exact
	// shape that loop already uses. A row missed by a between-query race
	// is healed by Task 5's child-GC worker arm (the B1 502-retry
	// posture) — errors here are logged, never fatal.
	//
	// Scoped to 'open' OR recently-closed (eng retro finding #9b): every
	// breakout row EVER opened for this meeting, unscoped, means a
	// long-since-closed room (already DeleteRoom'd, possibly years ago)
	// gets a DeleteRoom call on every single /end — dead work plus log
	// noise on any meeting with breakout history. 24h matches the worker's
	// own gcClosedBreakoutRooms window (worker.go) — a room closed longer
	// ago than that is the worker's job, not this route's.
	childRooms, cerr := h.queryStringColumnScoped(ctx, claims.UserID,
		`SELECT room_name::text FROM meeting_breakouts
		  WHERE meeting_id = $1
		    AND (state = 'open' OR closed_at > now() - interval '24 hours')`, id)
	if cerr == nil {
		for _, cr := range childRooms {
			if err := h.rooms.DeleteRoom(r.Context(), cr); err != nil {
				h.logger.Error("meet: breakout child DeleteRoom at end failed", "room", cr, "err", err)
			}
		}
	} else {
		h.logger.Error("meet: breakout child-room query at end failed", "meeting_id", id, "err", cerr)
	}
	if err := h.rooms.DeleteRoom(r.Context(), room); err != nil {
		h.logger.Error("meet: DeleteRoom failed", "room", room, "err", err)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "ended, but eviction failed; will be retried")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
