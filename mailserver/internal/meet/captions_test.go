// captions_test.go — B3 Task 14: DB-gated route tests for the captions
// start/stop routes, over the real Task 13 meeting_captions_set reducer on
// mailserver_test with fakeCaptions standing in for the asrbot sidecar (the
// recording_test.go precedent — DB_DSN skip-if-absent).
package meet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sawCaptionsPush reports whether _test_notify_log gained a meet:{userID}
// captions_state push whose payload.on matches — the sawRecordingPush genre
// (webhook_test.go), captions' own payload shape ({on, botIdentity}) rather
// than recording's {state}. Requires app.capture_notify='on' already set on
// this pool's one connection (meetSingleConnPool).
func sawCaptionsPush(t *testing.T, pool *pgxpool.Pool, userID int64, on bool) bool {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT payload FROM _test_notify_log WHERE channel = $1 ORDER BY seq`,
		fmt.Sprintf("meet:%d", userID))
	if err != nil {
		t.Fatalf("query _test_notify_log: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan _test_notify_log row: %v", err)
		}
		var decoded struct {
			Event   string `json:"event"`
			Payload struct {
				On bool `json:"on"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			t.Fatalf("decode _test_notify_log payload %q: %v", raw, err)
		}
		if decoded.Event == "captions_state" && decoded.Payload.On == on {
			return true
		}
	}
	return false
}

// TestCaptionsToggleGates pins F11's toggle posture at the route layer:
// feature.meet_captions OFF 404s the start route; the stop route is NOT
// toggle-gated at all — with the toggle OFF and a session already started,
// DELETE still stops it (draining committed state, never gated).
func TestCaptionsToggleGates(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	captions := newFakeCaptions()

	host := meetTestUser(t, pool, "capstogglehost")

	t.Run("captions toggle off", func(t *testing.T) {
		h := meetHandlerWithCaptions(pool, rooms, captions, false)
		meetingID := createTestMeeting(t, h, host, "Captions toggle off test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("feature.meet_captions OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("stop is not toggle-gated", func(t *testing.T) {
		hOn := meetHandlerWithCaptions(pool, rooms, captions, true)
		meetingID := createTestMeeting(t, hOn, host, "Captions stop drains regardless")
		rr := meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("start (toggle ON): want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		hOff := meetHandlerWithCaptions(pool, rooms, captions, false)
		rr = meetDo(t, hOff, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("stop with toggle OFF: want 204 (D11/F11 — draining committed state is never gated), got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestCaptionsTogglePrecedesParse pins E-F9 (the drive/recording genre): the
// toggle check happens BEFORE httputil.ParseIDPath. A non-numeric {id}
// would 400 if parsed, so a 404 here proves the toggle gate ran first.
func TestCaptionsTogglePrecedesParse(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithCaptions(pool, newFakeRooms(), newFakeCaptions(), false)
	rr := meetDo(t, h, meetTestUser(t, pool, "capsparsegate"), "POST", "/meet/not-a-number/captions", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("toggle-off + non-numeric id: want 404 (toggle gate precedes parse), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCaptionsRoutesNilController pins the nil-CaptionsController posture
// (ASR sidecar not configured on this box). eng retro finding #5: START
// still 503s (never got far enough to have a session — nothing to roll
// back), but STOP must NOT 503 — the reducer's OFF-flip runs FIRST,
// unconditionally, so a captionsOn=true row can always be turned off even
// with no controller wired at all; a nil controller means "no sidecar to
// call", not "no fact to flip". This is the exact wedge class B2's
// reconcileRecordingsDBOnly fixed for recordings: before this fix, DELETE
// 503'd BEFORE ever reaching the reducer, so a box with ASR_URL
// deconfigured could never turn a captionsOn=true row off through this
// route at all.
func TestCaptionsRoutesNilController(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithCaptions(pool, newFakeRooms(), nil, true)
	host := meetTestUser(t, pool, "capsnilhost")
	meetingID := createTestMeeting(t, h, host, "Nil captions controller test")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("start with nil captions: want 503, got %d: %s", rr.Code, rr.Body.String())
	}

	// Seed captionsOn=true directly — the start route above could never do
	// it on this box (503 before the reducer call), mirroring a session that
	// was live before ASR_URL was unset.
	if _, err := pool.Exec(context.Background(), `SELECT meeting_captions_set($1, $2, true)`, host, meetingID); err != nil {
		t.Fatalf("seed captionsOn: %v", err)
	}

	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stop with nil captions: want 204 (the reducer flip runs before the nil-controller check), got %d: %s", rr.Code, rr.Body.String())
	}

	var on bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
		meetingID).Scan(&on); err != nil {
		t.Fatalf("query captionsOn: %v", err)
	}
	if on {
		t.Error("DELETE with a nil controller must still flip captionsOn to false")
	}
}

// TestStartCaptionsFactFirst pins the chip-fact-precedes-sidecar-call proof
// at the route level: the reducer row already reads captionsOn=true when
// captions.Start is called (the fake's startHook reads DB state mid-call) —
// the B2 recording-banner discipline extended to captions.
func TestStartCaptionsFactFirst(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	captions := newFakeCaptions()
	h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)

	host := meetTestUser(t, pool, "capsfacthost")
	meetingID := createTestMeeting(t, h, host, "Captions fact-first test")

	var sawOnMidCall bool
	captions.startHook = func() {
		var on bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
			meetingID).Scan(&on); err == nil {
			sawOnMidCall = on
		}
	}

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !sawOnMidCall {
		t.Error("captionsOn must already be true when captions.Start is called — the chip must be server state ahead of the first transcript frame")
	}
	room := roomNameFor(t, pool, meetingID)
	if !captions.sawCall("Start:" + room) {
		t.Errorf("captions did not see the expected Start call for room %s; calls=%v", room, captions.calls)
	}
}

// TestStartCaptionsBusyRollsBack pins the distinguishable captionsBusy
// surface: a Start failure classified as errCaptionsBusy marks the chip
// back off (the chip must never lie) and returns RFC7807 503 with
// code:"captionsBusy" — the off-push is observed via _test_notify_log.
func TestStartCaptionsBusyRollsBack(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}
	captions := newFakeCaptions()
	h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)

	host := meetTestUser(t, pool, "capsbusyhost")
	meetingID := createTestMeeting(t, h, host, "Captions busy test")
	room := roomNameFor(t, pool, meetingID)
	captions.startErrs[room] = errCaptionsBusy

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("captions busy: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "captionsBusy" {
		t.Errorf("problem code = %q, want captionsBusy", code)
	}

	var on bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
		meetingID).Scan(&on); err != nil {
		t.Fatalf("query captionsOn: %v", err)
	}
	if on {
		t.Error("captionsOn must be rolled back to false after a busy Start — the chip must never lie")
	}
	if !sawCaptionsPush(t, pool, host, false) {
		t.Error("want an off captions_state push from the busy-Start rollback")
	}
}

// TestStartCaptionsIdempotentDoubleStart pins D8's idempotency at the route
// layer: a second start while already on 204s with ZERO additional Start
// calls (exactly one Start call total across both requests).
func TestStartCaptionsIdempotentDoubleStart(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	captions := newFakeCaptions()
	h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)

	host := meetTestUser(t, pool, "capsdoublehost")
	meetingID := createTestMeeting(t, h, host, "Captions double-start test")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("first start: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("second start (idempotent): want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	room := roomNameFor(t, pool, meetingID)
	var startCalls int
	for _, c := range captions.calls {
		if c == "Start:"+room {
			startCalls++
		}
	}
	if startCalls != 1 {
		t.Errorf("want exactly ONE Start call across both requests, got %d; calls=%v", startCalls, captions.calls)
	}
}

// TestStopCaptions pins the stop route's happy path (204 + Stop called with
// the meeting's room).
func TestStopCaptions(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	captions := newFakeCaptions()
	h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)

	host := meetTestUser(t, pool, "capsstophost")
	meetingID := createTestMeeting(t, h, host, "Captions stop test")
	room := roomNameFor(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stop: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !captions.sawCall("Stop:" + room) {
		t.Errorf("stop did not call captions.Stop for room %s; calls=%v", room, captions.calls)
	}
}

// TestJoinEnvelopeCaptionsConfigured pins plan delta 4: the join response
// carries captionsConfigured = (h.captions != nil), independent of the
// feature.meet_captions toggle or the live captionsOn flag.
func TestJoinEnvelopeCaptionsConfigured(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	t.Run("configured", func(t *testing.T) {
		h := meetHandlerWithCaptions(pool, newFakeRooms(), newFakeCaptions(), false)
		host := meetTestUser(t, pool, "capsenvyeshost")
		meetingID := createTestMeeting(t, h, host, "Captions envelope configured test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			CaptionsConfigured bool `json:"captionsConfigured"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode join response: %v", err)
		}
		if !out.CaptionsConfigured {
			t.Error("want captionsConfigured=true when h.captions is non-nil")
		}
	})

	t.Run("not configured", func(t *testing.T) {
		h := meetHandler(pool, newFakeRooms()) // no captions controller wired
		host := meetTestUser(t, pool, "capsenvnohost")
		meetingID := createTestMeeting(t, h, host, "Captions envelope not-configured test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			CaptionsConfigured bool `json:"captionsConfigured"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode join response: %v", err)
		}
		if out.CaptionsConfigured {
			t.Error("want captionsConfigured=false when h.captions is nil")
		}
	})
}
