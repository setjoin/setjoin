// breakouts.go — Meet B3 Task 4: breakout open/assign/close/join routes.
// The chat/drive translator discipline (meetings.go's own header comment):
// claims -> gate -> parse -> reducer (authority) -> RoomController calls ->
// respond. F11 toggle posture (Global Constraints): feature.meet_breakouts
// gates OPEN only — assign/close/join run unconditionally so a mid-meeting
// toggle flip never strands anyone in a breakout nobody can close or leave
// (the D11/B2 drain posture, the SAME rule recording.go's stopRecording
// already follows).
package meet

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// breakoutEmptyTimeout/breakoutDepartureTimeout are D12's pinned generous
// child-room params (86400/86400 seconds = 24h) — sized so the SFU never
// self-finishes an open breakout in practice; the meeting_participant_event
// D12 accept-as-close arm is the honest posture for the (practically
// unreachable) case where it does. Used by both breakout room-create call
// sites (open, join-mint — plan delta 6); never by the main-room CreateRoom
// (still 300/20, lkRooms.CreateRoom).
const breakoutEmptyTimeout, breakoutDepartureTimeout uint32 = 86400, 86400

// registerBreakoutRoutes registers this file's four routes onto h.mux,
// called from NewHandler alongside the other register*Routes calls.
func (h *Handler) registerBreakoutRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/breakouts", h.openBreakouts)
	mux.HandleFunc("POST /meet/{id}/breakouts/assign", h.assignBreakout)
	mux.HandleFunc("POST /meet/{id}/breakouts/close", h.closeBreakouts)
	mux.HandleFunc("POST /meet/{id}/breakouts/join", h.joinBreakout)
}

type openBreakoutsBody struct {
	Count      int      `json:"count"`
	Titles     []string `json:"titles"`
	AutoAssign bool     `json:"autoAssign"`
}

// decodeBreakoutRoomNames extracts the roomName field from
// meeting_breakout_open's {breakoutId, idx, title, roomName} array — the
// room names Go pre-creates on the SFU (room.auto_create:false, D11). A
// decode failure returns nil (no rooms to pre-create) rather than erroring
// the whole request — the reducer's write already committed; a client that
// then joins triggers create-on-mint, so a malformed echo here degrades to
// "one extra CreateRoom call later," never a stuck room.
func decodeBreakoutRoomNames(out json.RawMessage) []string {
	var rows []struct {
		RoomName string `json:"roomName"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.RoomName)
	}
	return names
}

// openBreakouts serves POST /meet/{id}/breakouts {count, titles?,
// autoAssign?}. F11/E-F9 (the drive genre, ahead of recording.go's own
// startRecording precedent): the toggle gates BEFORE the path id parses —
// a disabled feature must be indistinguishable from an absent route. Only
// this route is gated; assign/close/join below are NOT.
func (h *Handler) openBreakouts(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if !h.flags.IsEnabled(toggle.FeatureMeetBreakouts) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, body, ok := meetIDBody[openBreakoutsBody](w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_breakout_open($1, $2, $3, $4, $5)`,
			claims.UserID, id, body.Count, body.Titles, body.AutoAssign).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	// room.auto_create:false holds (spike law 2): pre-create every returned
	// child room. A failure here is logged, never rolled back — the
	// reducer's rows are the truth; D11's create-on-mint on the join route
	// heals at the moment of need, and Task 5's worker GC belts it further.
	for _, room := range decodeBreakoutRoomNames(out) {
		if err := h.rooms.CreateRoomWithTimeouts(r.Context(), room, breakoutEmptyTimeout, breakoutDepartureTimeout); err != nil {
			h.logger.Error("meet: breakout CreateRoom failed (join create-on-mint will heal)", "room", room, "err", err)
		}
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"breakouts": out})
}

type assignBreakoutBody struct {
	TargetUserID int64  `json:"targetUserId"`
	BreakoutID   *int64 `json:"breakoutId"`
}

// assignBreakout serves POST /meet/{id}/breakouts/assign {targetUserId,
// breakoutId}. NULL breakoutId = return the target to main. Unconditional
// (F11 drain posture). Authority + the move fact commit first
// (meeting_breakout_assign), THEN the eviction call — DES-011's ordering.
// The reducer returns the target's CURRENT (pre-move) room — main or an
// already-assigned child — so a re-assign from one breakout straight to
// another evicts from the room they are ACTUALLY in, not always main.
func (h *Handler) assignBreakout(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, body, ok := meetIDBody[assignBreakoutBody](w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var currentRoom string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_breakout_assign($1, $2, $3, $4)`,
			claims.UserID, id, body.TargetUserID, body.BreakoutID).Scan(&currentRoom)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	identity := fmt.Sprintf("u:%d", body.TargetUserID)
	if err := h.rooms.RemoveParticipant(r.Context(), currentRoom, identity); err != nil {
		h.logger.Error("meet: breakout assign RemoveParticipant failed", "room", currentRoom, "identity", identity, "err", err)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "assigned, but the move could not be confirmed; will be retried")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// closeBreakouts serves POST /meet/{id}/breakouts/close. Unconditional
// (F11 drain posture) and idempotent — meeting_breakout_close returns '[]'
// when nothing is open, so this 204s with zero DeleteRoom calls rather than
// erroring on a no-op close. Every returned child is attempted even if an
// earlier one fails (drain-then-call, the recording.go stopRecording
// precedent) — a partial failure still 502s so the host knows to retry, but
// never skips a later room because an earlier one errored.
func (h *Handler) closeBreakouts(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_breakout_close($1, $2)`,
			claims.UserID, id).Scan(&out)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	var rooms []string
	if err := json.Unmarshal(out, &rooms); err != nil {
		h.logger.Error("meet: could not decode breakout close result", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	var failed bool
	for _, room := range rooms {
		if err := h.rooms.DeleteRoom(r.Context(), room); err != nil {
			h.logger.Error("meet: breakout DeleteRoom failed", "room", room, "err", err)
			failed = true
		}
	}
	if failed {
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "closed, but some rooms could not be evicted; will be retried")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type joinBreakoutBody struct {
	BreakoutID *int64 `json:"breakoutId"`
}

// joinBreakout serves POST /meet/{id}/breakouts/join {breakoutId?} ->
// {token, wsPath, expiresAt, recordingActive}. Unconditional (F11 drain
// posture — a member already assigned before a toggle flip OFF must still
// be able to mint a token for their room). D11: CreateRoomWithTimeouts runs
// BEFORE MintToken on every call — no client ever holds a token to a room
// that doesn't exist, mirroring meetings.go's join route exactly, just with
// the D12 breakout timeout pair instead of the main room's 300/20.
func (h *Handler) joinBreakout(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, body, ok := meetIDBody[joinBreakoutBody](w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var specJSON json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_breakout_join($1, $2, $3)`,
			claims.UserID, id, body.BreakoutID).Scan(&specJSON)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	var spec grantSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		h.logger.Error("meet: could not decode breakout grant spec", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.rooms.CreateRoomWithTimeouts(r.Context(), spec.Room, breakoutEmptyTimeout, breakoutDepartureTimeout); err != nil {
		h.logger.Error("meet: breakout join CreateRoom failed", "room", spec.Room, "err", err)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "could not prepare the breakout room")
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
		// recordingActive is hard false for a breakout grant (DN4 — breakouts
		// are never recorded, meeting_breakout.sql's meeting_breakout_join).
		// Reserved-for-symmetry with the main-room join envelope (meetings.go)
		// rather than dropped — no webmail consumer reads it here today, but
		// keeping the key means wave B (or any future breakout-aware banner)
		// can start consuming it without a reducer/route change.
		"recordingActive": spec.RecordingActive,
	})
}
