// recording.go — Meet B2: start/stop routes. The chat translator discipline:
// claims → gates → parse → reducer (authority + the banner fact) → ONE
// controller call → bind. Gate order (spec §6.2, the drive genre — toggles
// BEFORE the path id parses, eng E-F9): feature.meet_recording 404 →
// feature.drive 404 → parse → egress runtime 503 → reducer →
// StartRoomComposite → bind_egress. The DELETE (stop) route is NOT
// toggle-gated — D11: a toggle gates new intent, never the draining of
// committed state.
package meet

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

func (h *Handler) registerRecordingRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/recording", h.startRecording)
	mux.HandleFunc("DELETE /meet/{id}/recording", h.stopRecording)
}

func (h *Handler) startRecording(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	// E-F9 (drive genre): toggle gates BEFORE the path id parses — a
	// disabled feature must be indistinguishable from an absent route.
	if !h.flags.IsEnabled(toggle.FeatureMeetRecording) || !h.flags.IsEnabled(toggle.FeatureDrive) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	if h.egress == nil {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"recording is not configured (egress runtime missing)"))
		return
	}

	// 1. The reducer commits the fact (row + banner push) BEFORE any Egress
	//    call — §3.2. It owns every gate: host/cohost, live, no in-flight
	//    recording, the BZ199 guest-admission arm under the row lock.
	ctx := r.Context()
	var recID int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_recording_start($1, $2)`,
			claims.UserID, id).Scan(&recID)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}

	room, err := h.roomNameForMeeting(ctx, claims.UserID, id)
	if err != nil {
		h.logger.Error("meet: room lookup after recording start failed", "meeting_id", id, "err", err)
		h.bindFailed(r, claims.UserID, recID, "internal: room lookup failed")
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	stagingKey := stagingKeyFor(recID, room)

	// 2. The ONE controller call.
	egressID, err := h.egress.StartRoomComposite(r.Context(), room, RecordingRequest{StagingKey: stagingKey})
	if err != nil {
		reason := "egress start failed"
		status := http.StatusBadGateway
		if isEgressBusy(err) {
			reason, status = "egress_busy", http.StatusServiceUnavailable
		}
		h.logger.Error("meet: StartRoomComposite failed", "meeting_id", id, "recording_id", recID, "err", err)
		h.bindFailed(r, claims.UserID, recID, reason) // rolls the banner back (bind p_ok=false pushes failed)
		if reason == "egress_busy" {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: status, Code: "egressBusy",
				Type:   "https://setjoin.com/problems/meet/egress-busy",
				Detail: "recording capacity is in use; try again shortly",
			})
			return
		}
		httputil.WriteProblemStatus(w, status, "could not start the recording")
		return
	}

	// 3. Bind: requested → active, egress_id + staging_key persisted (OURS).
	bindErr := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT meeting_recording_bind_egress($1, $2, $3, true, NULL)`,
			recID, egressID, stagingKey)
		return err
	})
	if bindErr != nil {
		// The recording is running but the bind failed (DB fault). Do NOT
		// stop it: the worker's reconcile binds nothing, but its stale-
		// 'requested' grace marks the row failed and the belt leg stops the
		// SFU-active egress with a terminal row (law 1's belt).
		writeMeetProblem(w, r, bindErr)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]any{"recordingId": recID})
}

// bindFailed marks a requested recording failed (banner-off push carries the
// reason — the client renders egress_busy distinguishably, spec §6.2). userID
// GUC-scopes the write (W4) — every caller is a host/cohost already
// authorized moments earlier in the same request.
func (h *Handler) bindFailed(r *http.Request, userID, recID int64, reason string) {
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT meeting_recording_bind_egress($1, NULL, NULL, false, $2)`,
			recID, reason)
		return err
	})
	if err != nil {
		h.logger.Error("meet: bind_egress(failed) failed", "recording_id", recID, "err", err)
	}
}

func (h *Handler) stopRecording(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	if h.egress == nil {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"recording is not configured (egress runtime missing)"))
		return
	}
	var out struct {
		RecordingID int64   `json:"recordingId"`
		EgressID    *string `json:"egressId"`
	}
	ctx := r.Context()
	var raw json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_recording_stop($1, $2)`,
			claims.UserID, id).Scan(&raw)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		h.logger.Error("meet: could not decode stop result", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Law 1: the API call completes the transition. A failure is 502 —
	// the row is already 'stopping', so the worker's retry leg converges.
	if out.EgressID != nil {
		if err := h.egress.StopEgress(r.Context(), *out.EgressID); err != nil {
			h.logger.Error("meet: StopEgress failed", "egress_id", *out.EgressID, "err", err)
			httputil.WriteProblemStatus(w, http.StatusBadGateway, "stopping, but the egress stop call failed; will be retried")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
