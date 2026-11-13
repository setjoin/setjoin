// captions.go — Meet B3 Task 14: the CaptionsController seam (the
// RoomController/EgressController genre, DES-011's third seam) + the start/
// stop routes. The chat/drive/recording translator discipline: claims ->
// gates -> parse -> reducer (authority + the chip fact) -> ONE controller
// call -> rollback-on-failure. Gate order for POST (the recording.go:25-41
// clone): feature.meet_captions 404 BEFORE the path parses -> parse ->
// h.captions == nil -> 503 -> reducer meeting_captions_set(uid, id, true)
// (the fact + push, BEFORE any sidecar call) -> grant NULL (already on) ->
// 204 idempotent -> else MintToken -> captions.Start; a busy/failed Start
// rolls the chip back via meeting_captions_set(uid, id, false) — the
// bindFailed genre — the chip must never lie. DELETE is UNCONDITIONAL (F11
// drain posture, the recording.go stopRecording precedent): no toggle
// gate — reducer set(false) -> captions.Stop (failure -> 502, the worker
// retries).
package meet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// CaptionsController is the seam the asrbot control API (Task 12) sits
// behind — the RoomController/EgressController genre (DES-011): Start binds
// a captions session to a room with a minted bot token, Stop tears it down,
// Status reports which rooms currently have a live session (the Task 14
// bidirectional worker reconcile arm's input, reconcileCaptions below).
type CaptionsController interface {
	Start(ctx context.Context, room, token string) error
	Stop(ctx context.Context, room string) error
	Status(ctx context.Context) ([]string, error)
}

// errCaptionsBusy is the sentinel the real client maps the bot's 409 (at
// ASR_MAX_MEETINGS capacity, Task 12) onto — startCaptions projects it as
// the distinguishable captionsBusy 503 (the egressBusy genre, plan delta 4).
var errCaptionsBusy = errors.New("captions: asrbot at capacity")

// registerCaptionsRoutes registers this file's two routes onto h.mux, called
// from NewHandler alongside the other register*Routes calls.
func (h *Handler) registerCaptionsRoutes(mux router) {
	mux.HandleFunc("POST /meet/{id}/captions", h.startCaptions)
	mux.HandleFunc("DELETE /meet/{id}/captions", h.stopCaptions)
}

// startCaptions serves POST /meet/{id}/captions. F11/E-F9 (the drive genre,
// the recording.go startRecording precedent): the toggle gates BEFORE the
// path id parses. The reducer commits the fact (settings.captionsOn=true +
// captionsSince, the F5 durable start-grace stamp) and pushes captions_state
// BEFORE any call to the sidecar — the chip is server state ahead of the
// first transcript frame, the B2 recording-banner discipline extended to
// captions. A NULL grant means the flag was already on (idempotent, D8) —
// 204, zero Start calls. Otherwise MintToken translates the reducer-composed
// bot grant (D6 — Go never composes one) and captions.Start binds the
// session; a failure rolls the chip back (bindFailed genre) so it never
// lies about a session that never actually started.
func (h *Handler) startCaptions(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if !h.flags.IsEnabled(toggle.FeatureMeetCaptions) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "not found")
		return
	}
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	if h.captions == nil {
		httputil.WriteProblem(w, r, httputil.NewServiceUnavailableProblem(
			"captions is not configured (ASR runtime missing)"))
		return
	}

	ctx := r.Context()
	var specJSON json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT meeting_captions_set($1, $2, true)`,
			claims.UserID, id).Scan(&specJSON)
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	if specJSON == nil {
		// D8: already on — no-op, no Start call, no re-stamped captionsSince.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var spec grantSpec
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		h.logger.Error("meet: could not decode captions grant spec", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, _, err := MintToken(h.cfg, spec)
	if err != nil {
		h.logger.Error("meet: MintToken (captions) failed", "meeting_id", id, "err", err)
		h.captionsRollback(r.Context(), claims.UserID, id)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.captions.Start(r.Context(), spec.Room, token); err != nil {
		status := http.StatusBadGateway
		busy := errors.Is(err, errCaptionsBusy)
		h.logger.Error("meet: captions Start failed", "meeting_id", id, "busy", busy, "err", err)
		h.captionsRollback(r.Context(), claims.UserID, id) // the chip never lies
		if busy {
			httputil.WriteProblem(w, r, &httputil.Problem{
				Status: http.StatusServiceUnavailable, Code: "captionsBusy",
				Type:   "https://setjoin.com/problems/meet/captions-busy",
				Detail: "caption capacity is in use; try again shortly",
			})
			return
		}
		httputil.WriteProblemStatus(w, status, "could not start captions")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// captionsRollback turns the chip back off (the recording.go bindFailed
// genre): a Start call to the sidecar failed AFTER the reducer already
// committed the ON fact, so that fact must be reversed — the chip must
// never claim a session that never actually started. userID is the SAME
// host/cohost caller who just passed the role check moments earlier in this
// request (meeting_captions_set re-checks it, redundantly but harmlessly).
func (h *Handler) captionsRollback(ctx context.Context, userID, meetingID int64) {
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT meeting_captions_set($1, $2, false)`, userID, meetingID)
		return err
	})
	if err != nil {
		h.logger.Error("meet: captions rollback failed", "meeting_id", meetingID, "err", err)
	}
}

// stopCaptions serves DELETE /meet/{id}/captions. UNCONDITIONAL — NO toggle
// gate (F11 drain posture, the recording.go stopRecording precedent): a
// captions session started before a toggle flip OFF must still be
// stoppable. The reducer's OFF flip is itself idempotent (D8) so this is
// safe to call whether or not captions were actually on.
//
// eng retro finding #5 (the drain-wedge fix): the reducer flip runs FIRST,
// unconditionally — BEFORE the h.captions nil check, not after. The
// previous ordering 503'd on a nil controller before ever reaching the
// reducer, so a box with ASR_URL deconfigured (h.captions == nil) could
// never turn a captionsOn=true row off through this route at all — the
// exact wedge class B2's reconcileRecordingsDBOnly fixed for recordings in
// this same file's sibling. A nil controller means no live session can
// possibly exist (h.captions is the only thing that ever calls Start), so
// once the flag is off there is nothing left to Stop: 204, not 503.
func (h *Handler) stopCaptions(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	id, ok := httputil.ParseIDPath(w, r, "id", "invalid meeting id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT meeting_captions_set($1, $2, false)`,
			claims.UserID, id)
		return err
	})
	if err != nil {
		writeMeetProblem(w, r, err)
		return
	}
	if h.captions == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	room, err := h.roomNameForMeeting(ctx, claims.UserID, id)
	if err != nil {
		h.logger.Error("meet: room lookup after captions stop failed", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Law 1 extended to the ASR sidecar: stop is an API call, never a TTL
	// hope. A failure is 502 — the flag is already off, so the worker's
	// orphaned-session leg (reconcileCaptions leg b) retries the Stop.
	if err := h.captions.Stop(r.Context(), room); err != nil {
		h.logger.Error("meet: captions Stop failed", "meeting_id", id, "err", err)
		httputil.WriteProblemStatus(w, http.StatusBadGateway, "stopping, but the captions stop call failed; will be retried")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// httpCaptionsClient is the real CaptionsController — a small loopback HTTP
// client to the asrbot control API (Task 12, ASR_URL — default
// http://127.0.0.1:7890): POST /start {"room","token"} -> 200, 409
// {"error":"busy"} -> errCaptionsBusy; POST /stop {"room"} -> 200
// (idempotent); GET /status -> {"rooms":[...]}. B3 Task 18 pipeline-review
// finding 1 (the gateway-side follow-up config.go's Config.ASRToken staged):
// every request now carries `Authorization: Bearer <token>` — asrbot's
// control API requires it on /start/stop/status (loopback TCP alone carries
// no peer identity, so an unauthenticated control API let any local uid
// drive the bot directly). token is the shared secret law-3'd alongside
// LIVEKIT_API_SECRET/VALKEY_PASSWORD (install.sh writes it to both
// asrbot.env and config.env in the same run); empty token sends no header
// (a box with ASR_URL set but ASR_TOKEN unset is a deploy misconfiguration,
// not a Go panic — asrbot itself refuses to start with an empty ASR_TOKEN).
type httpCaptionsClient struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewCaptionsClient builds the real CaptionsController. Constructed in
// main.go only when ASR_URL is set — nil-safe everywhere else (both routes
// 503 before touching h.captions, the recording.go/egress.go posture).
func NewCaptionsClient(baseURL, token string) CaptionsController {
	return &httpCaptionsClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// newRequest builds an asrbot control-API request, attaching the bearer
// token (if configured) to every method/path — the one place the
// Authorization header is set, shared by doJSON (POST /start, /stop) and
// Status (GET /status) so neither can drift from the other.
func (c *httpCaptionsClient) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var reader io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(b)
	}
	// G704 (gosec SSRF taint): c.baseURL originates from ASR_URL, an
	// operator-set deployment config value (config.env, the LIVEKIT_URL/
	// egress-endpoint trust class), never request/user input — the same
	// posture as cfg.HTTPURL() feeding lksdk's RoomServiceClient/EgressClient
	// (those don't trip gosec only because it doesn't taint-track through a
	// vendored SDK's own net/http call). path is always a compile-time
	// literal ("/start"/"/stop"/"/status") from this file, never
	// caller-supplied.
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader) //nolint:gosec // G704: see above
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

func (c *httpCaptionsClient) doJSON(ctx context.Context, path string, body any) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req) //nolint:gosec // G704: see above
}

func (c *httpCaptionsClient) Start(ctx context.Context, room, token string) error {
	resp, err := c.doJSON(ctx, "/start", map[string]string{"room": room, "token": token})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return errCaptionsBusy
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asrbot /start: status %d", resp.StatusCode)
	}
	return nil
}

func (c *httpCaptionsClient) Stop(ctx context.Context, room string) error {
	resp, err := c.doJSON(ctx, "/stop", map[string]string{"room": room})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("asrbot /stop: status %d", resp.StatusCode)
	}
	return nil
}

func (c *httpCaptionsClient) Status(ctx context.Context) ([]string, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("asrbot /status: status %d", resp.StatusCode)
	}
	var out struct {
		Rooms []string `json:"rooms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Rooms, nil
}

var _ CaptionsController = (*httpCaptionsClient)(nil)
