// recording_test.go — B2 Task 5: DB-gated route tests for the recording
// start/stop routes, over the real Task 2 reducers on mailserver_test
// (the meetings_test.go DB_DSN-skip precedent) with fakeEgress standing in
// for the LiveKit Egress sidecar.
package meet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/twitchtv/twirp"
)

// startMeetingLive flips a freshly created meeting from 'scheduled' to
// 'live' the same way the real SFU does — the room_started webhook fact,
// via meeting_participant_event (meeting_join.sql's own contract: join
// composes a grant spec but never touches meetings.state; only the
// webhook-fed room_started transition does). meeting_recording_start
// requires a live meeting (BZ200 otherwise), so every recording test needs
// this immediately after createTestMeeting.
func startMeetingLive(t *testing.T, pool *pgxpool.Pool, meetingID int64) {
	t.Helper()
	room := roomNameFor(t, pool, meetingID)
	if _, err := pool.Exec(context.Background(),
		`SELECT meeting_participant_event($1::uuid, 'room_started')`, room); err != nil {
		t.Fatalf("meeting_participant_event(room_started): %v", err)
	}
}

// admitGuestOnMeeting drives the full public-lobby dance (setGuestAllowed →
// public create join-request → host admit) to seed exactly the fixture the
// BZ199 arm-1 pgTAP case needs at the Go layer: a `role='guest'` participant
// row with joined_at NULL (admitted, never actually connected) — the
// admission FACT, not the webhook-fed attendance stamp.
func admitGuestOnMeeting(t *testing.T, h *Handler, host, meetingID int64) {
	t.Helper()
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, h.pool, meetingID)
	ph := meetPublicHandler(h.pool, true, true)
	rr := publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Recording Test Guest"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("guest join-request: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	created := decodeCreateResp(t, rr)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, created.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit guest: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

type startRecordingOut struct {
	RecordingID int64 `json:"recordingId"`
}

// TestStartRecordingToggleGates pins D11's toggle posture at the route
// layer: feature.meet_recording OFF 404s the start route; feature.drive OFF
// (recording ON) also 404s it; the stop route is NOT toggle-gated at all —
// with both toggles OFF and an 'active' row already seeded, DELETE still
// stops it (draining committed state, never gated).
func TestStartRecordingToggleGates(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	egress := newFakeEgress()

	host := meetTestUser(t, pool, "rectogglehost")

	t.Run("recording toggle off", func(t *testing.T) {
		h := meetHandlerWithEgress(pool, rooms, egress, false, true)
		meetingID := createTestMeeting(t, h, host, "Toggle off test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("feature.meet_recording OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("drive toggle off", func(t *testing.T) {
		h := meetHandlerWithEgress(pool, rooms, egress, true, false)
		meetingID := createTestMeeting(t, h, host, "Drive off test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("feature.drive OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("stop is not toggle-gated", func(t *testing.T) {
		hOn := meetHandlerWithEgress(pool, rooms, egress, true, true)
		meetingID := createTestMeeting(t, hOn, host, "Stop drains regardless")
		startMeetingLive(t, pool, meetingID)
		rr := meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("start (toggles ON): want 201, got %d: %s", rr.Code, rr.Body.String())
		}

		hOff := meetHandlerWithEgress(pool, rooms, egress, false, false)
		rr = meetDo(t, hOff, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("stop with both toggles OFF: want 204 (D11 — draining committed state is never gated), got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestStartRecordingTogglesPrecedeParse pins E-F9 (the drive genre): the
// toggle check happens BEFORE httputil.ParseIDPath. A non-numeric {id}
// would 400 if parsed, so a 404 here proves the toggle gate ran first.
func TestStartRecordingTogglesPrecedeParse(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), false, false)
	rr := meetDo(t, h, meetTestUser(t, pool, "recparsegate"), "POST", "/meet/not-a-number/recording", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("toggle-off + non-numeric id: want 404 (toggle gate precedes parse), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestRecordingRoutesNilEgress503 pins the nil-EgressController posture
// (egress sidecar not configured on this box): both routes 503 rather than
// panicking, mirroring Handler.ServeHTTP's own "not configured" gate leg
// for h.rooms.
func TestRecordingRoutesNilEgress503(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithEgress(pool, newFakeRooms(), nil, true, true)
	host := meetTestUser(t, pool, "recnilegress")
	meetingID := createTestMeeting(t, h, host, "Nil egress test")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("start with nil egress: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("stop with nil egress: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestStartRecordingHappyPath pins the banner-fact-precedes-frames proof at
// the route level: the reducer row exists in 'requested' BEFORE Go's
// StartRoomComposite call runs (the fake's startHook reads DB state
// mid-call), and the row lands 'active' with the OURS-composed .mp4
// staging key persisted after bind.
func TestStartRecordingHappyPath(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "rechappyhost")
	meetingID := createTestMeeting(t, h, host, "Happy path test")
	startMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)

	var sawRequestedMidCall bool
	egress.startHook = func() {
		var state string
		if err := pool.QueryRow(context.Background(),
			`SELECT state FROM meeting_recordings WHERE meeting_id = $1`, meetingID).Scan(&state); err == nil {
			sawRequestedMidCall = state == "requested"
		}
	}

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if !sawRequestedMidCall {
		t.Error("the recording row must already be 'requested' when StartRoomComposite is called — the consent banner must precede the first captured frame")
	}
	var out startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response %q: %v", rr.Body.String(), err)
	}
	wantStagingKey := stagingKeyFor(out.RecordingID, room)
	if !egress.sawCall(fmt.Sprintf("StartRoomComposite:%s:%s", room, wantStagingKey)) {
		t.Errorf("egress did not see the expected StartRoomComposite call; calls=%v", egress.calls)
	}

	var state, stagingKey string
	if err := pool.QueryRow(context.Background(),
		`SELECT state, staging_key FROM meeting_recordings WHERE id = $1`, out.RecordingID).Scan(&state, &stagingKey); err != nil {
		t.Fatalf("query recording row: %v", err)
	}
	if state != "active" {
		t.Errorf("state = %q, want active", state)
	}
	if stagingKey != wantStagingKey {
		t.Errorf("staging_key = %q, want %q", stagingKey, wantStagingKey)
	}
}

// TestStartRecordingEgressError pins the generic-failure path: a
// StartRoomComposite error that is NOT the egress-busy shape marks the row
// 'failed' and returns 502 (bad gateway to the upstream Egress call).
func TestStartRecordingEgressError(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "recerrhost")
	meetingID := createTestMeeting(t, h, host, "Egress error test")
	startMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)
	egress.startErrs[room] = errors.New("boom: egress unreachable")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("egress generic error: want 502, got %d: %s", rr.Code, rr.Body.String())
	}

	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_recordings WHERE meeting_id = $1`, meetingID).Scan(&state); err != nil {
		t.Fatalf("query recording row: %v", err)
	}
	if state != "failed" {
		t.Errorf("state = %q, want failed", state)
	}
}

// TestStartRecordingEgressBusy pins the distinguishable egressBusy surface
// (plan delta 4): a twirp ResourceExhausted from StartRoomComposite marks
// the row 'failed' with error='egress_busy' and returns RFC7807 503 with
// code:"egressBusy" — not a generic 502.
func TestStartRecordingEgressBusy(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "recbusyhost")
	meetingID := createTestMeeting(t, h, host, "Egress busy test")
	startMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)
	egress.startErrs[room] = twirp.NewError(twirp.ResourceExhausted, "max concurrent egress reached")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("egress busy: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "egressBusy" {
		t.Errorf("problem code = %q, want egressBusy", code)
	}

	var state, errMsg string
	if err := pool.QueryRow(context.Background(),
		`SELECT state, error FROM meeting_recordings WHERE meeting_id = $1`, meetingID).Scan(&state, &errMsg); err != nil {
		t.Fatalf("query recording row: %v", err)
	}
	if state != "failed" || errMsg != "egress_busy" {
		t.Errorf("state/error = %q/%q, want failed/egress_busy", state, errMsg)
	}
}

// TestStartRecordingAdmittedGuestBZ199 pins the §8.2 exclusion arm 1 at the
// route layer: a meeting with an admitted-but-unjoined guest refuses to
// start recording, 403 BZ199.
func TestStartRecordingAdmittedGuestBZ199(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)

	host := meetTestUser(t, pool, "recguesthost")
	meetingID := createTestMeeting(t, h, host, "Guest exclusion test")
	startMeetingLive(t, pool, meetingID)
	admitGuestOnMeeting(t, h, host, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("start with admitted guest: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ199" {
		t.Errorf("problem code = %q, want BZ199", code)
	}
}

// TestStartRecordingDoubleStartBZ200 pins the state-conflict arm: a second
// start while the first is still requested/active conflicts, 409 BZ200.
func TestStartRecordingDoubleStartBZ200(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)

	host := meetTestUser(t, pool, "recdoublehost")
	meetingID := createTestMeeting(t, h, host, "Double start test")
	startMeetingLive(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("first start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("second start: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ200" {
		t.Errorf("problem code = %q, want BZ200", code)
	}
}

// TestStopRecording pins the stop route's happy path (204 + StopEgress
// called with the bound egress id) and the none-active conflict (409
// BZ200).
func TestStopRecording(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "recstophost")
	meetingID := createTestMeeting(t, h, host, "Stop test")
	startMeetingLive(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var startOut startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &startOut); err != nil {
		t.Fatalf("decode start response %q: %v", rr.Body.String(), err)
	}
	var egressID string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id FROM meeting_recordings WHERE id = $1`, startOut.RecordingID).Scan(&egressID); err != nil {
		t.Fatalf("query egress_id: %v", err)
	}

	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stop: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !egress.sawCall("StopEgress:" + egressID) {
		t.Errorf("stop did not call StopEgress with the bound egress id %q; calls=%v", egressID, egress.calls)
	}

	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("stop with none active: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ200" {
		t.Errorf("problem code = %q, want BZ200", code)
	}
}

// TestEndMeetingStopsEgressBeforeDeleteRoom pins law 1's ordering: ending a
// meeting with an active recording calls StopEgress for the bound egress id
// BEFORE DeleteRoom evicts the room (endMeeting's StopEgress loop runs
// textually and temporally before its DeleteRoom call, meetings.go) — both
// calls must have fired, and the recording must already read 'stopping'
// (meeting_end's own reducer txn flip, proven at the reducer layer by
// meet_recording.pg's wedge-4 assert; this test pins Go's call-order
// contract on top of that fact).
func TestEndMeetingStopsEgressBeforeDeleteRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, rooms, egress, true, true)

	host := meetTestUser(t, pool, "recendhost")
	meetingID := createTestMeeting(t, h, host, "End with recording test")
	startMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var startOut startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &startOut); err != nil {
		t.Fatalf("decode start response %q: %v", rr.Body.String(), err)
	}
	var egressID string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id FROM meeting_recordings WHERE id = $1`, startOut.RecordingID).Scan(&egressID); err != nil {
		t.Fatalf("query egress_id: %v", err)
	}

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !egress.sawCall("StopEgress:" + egressID) {
		t.Errorf("end did not stop the in-flight egress %q; calls=%v", egressID, egress.calls)
	}
	if !rooms.sawCall("DeleteRoom:" + room) {
		t.Errorf("end did not evict the room; calls=%v", rooms.calls)
	}

	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_recordings WHERE id = $1`, startOut.RecordingID).Scan(&state); err != nil {
		t.Fatalf("query state: %v", err)
	}
	if state != "stopping" {
		t.Errorf("state after end = %q, want stopping (egress_ended hasn't landed yet)", state)
	}
}
