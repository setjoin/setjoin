// breakouts_test.go — Task 4: DB-gated route tests for the breakout surface
// (open/assign/close/join), over the real meeting_breakout.sql reducers on
// mailserver_test with fakeRooms standing in for the SFU (the
// meetings_test.go precedent — DB_DSN skip-if-absent). The reducer-level
// anti-oracle enumeration (guest/banned/departed/foreign/closed all raise
// the SAME BZ201) is already exhaustively pinned in meet_breakouts.pg; this
// file proves the Go-layer wiring on top of it — F11's open-only toggle
// gate, D11's create-before-mint ordering, and F1's kick/assign eviction
// targeting the room the participant is ACTUALLY in (main or a child) —
// not a re-run of the reducer's own coverage.
package meet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/toggle"
)

// meetHandlerWithBreakouts is meetHandler extended with the
// feature.meet_breakouts toggle — the only route this pillar gates (F11).
// Every other test in this package that never opens a breakout has no
// reason to carry this beyond registryDefaults' own false.
func meetHandlerWithBreakouts(pool *pgxpool.Pool, rooms RoomController, breakoutsOn bool) *Handler {
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":           true,
		"feature.meet_breakouts": breakoutsOn,
	}), configuredCfg, rooms, nil, nil, slog.Default())
}

type openedBreakout struct {
	BreakoutID int64  `json:"breakoutId"`
	Idx        int    `json:"idx"`
	RoomName   string `json:"roomName"`
}

func decodeOpenedBreakouts(t *testing.T, rr *httptest.ResponseRecorder) []openedBreakout {
	t.Helper()
	var out struct {
		Breakouts []openedBreakout `json:"breakouts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode open response %q: %v", rr.Body.String(), err)
	}
	return out.Breakouts
}

// TestOpenBreakoutsToggleGate pins F11/E-F9: the toggle gates OPEN and
// nothing else — off is a plain 404 (drive genre, indistinguishable from
// an absent route); on, every returned child room is pre-created via
// RoomController (room.auto_create:false, D11's "no client ever holds a
// token to a room that doesn't exist" premise starts here).
func TestOpenBreakoutsToggleGate(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	off := meetHandlerWithBreakouts(pool, rooms, false)

	host := meetTestUser(t, pool, "brkoffhost")
	meetingID := createTestMeeting(t, off, host, "Breakout toggle off")

	rr := meetDo(t, off, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("open with toggle off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	on := meetHandlerWithBreakouts(pool, rooms, true)
	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open with toggle on: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	opened := decodeOpenedBreakouts(t, rr)
	if len(opened) != 2 {
		t.Fatalf("open(2): got %d breakouts, want 2", len(opened))
	}
	for _, b := range opened {
		if !rooms.sawCall("CreateRoom:" + b.RoomName) {
			t.Errorf("open did not pre-create room %s; calls=%v", b.RoomName, rooms.calls)
		}
	}
}

// TestAssignEvictsFromCurrentRoom pins the F1 wire proof for assign: the
// eviction call always targets wherever the participant ACTUALLY is —
// main on the first move, then the CHILD room on a second move between two
// breakouts — never a stale assumption of "always main". The final
// sub-case proves the controller-error posture: the DB move already
// committed (authority first, DES-011) even though the eviction call
// itself failed.
func TestAssignEvictsFromCurrentRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	on := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "brkassignhost")
	member := meetTestUser(t, pool, "brkassignmember")
	meetingID := createTestMeeting(t, on, host, "Assign test")
	meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	mainRoom := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", member)

	rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	opened := decodeOpenedBreakouts(t, rr)
	b1, b2 := opened[0], opened[1]

	// main -> b1: current room is the parent.
	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b1.BreakoutID))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("assign main->b1: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", mainRoom, identity); !rooms.sawCall(want) {
		t.Errorf("assign did not evict from the main room; want call %q, calls=%v", want, rooms.calls)
	}

	// b1 -> b2: current room is now the CHILD b1 — the F1 wire proof.
	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b2.BreakoutID))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("assign b1->b2: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", b1.RoomName, identity); !rooms.sawCall(want) {
		t.Errorf("assign did not evict from the CHILD room b1; want call %q, calls=%v", want, rooms.calls)
	}

	// b2 -> main, with the eviction call injected to fail.
	rooms.errs[fmt.Sprintf("RemoveParticipant:%s/%s", b2.RoomName, identity)] = errors.New("sfu unreachable")
	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":null}`, member))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("assign with a controller error: want 502, got %d: %s", rr.Code, rr.Body.String())
	}
	var breakoutID *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT breakout_id FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, identity).Scan(&breakoutID); err != nil {
		t.Fatalf("query breakout_id: %v", err)
	}
	if breakoutID != nil {
		t.Error("the move must already be committed (breakout_id cleared) even though the eviction call itself failed")
	}
}

// TestAssignJoinCloseDrainWithToggleOff pins F11's drain posture: once
// breakouts exist, a Handler CONSTRUCTED with feature.meet_breakouts OFF
// still serves assign/close/join against them — a toggle flipped OFF
// mid-meeting must never strand anyone. Close's DeleteRoom sweep is
// asserted against BOTH open rooms (not just the assigned one).
func TestAssignJoinCloseDrainWithToggleOff(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	on := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "brkdrainhost")
	member := meetTestUser(t, pool, "brkdrainmember")
	meetingID := createTestMeeting(t, on, host, "Drain test")
	meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")

	rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	opened := decodeOpenedBreakouts(t, rr)

	off := meetHandlerWithBreakouts(pool, rooms, false)

	rr = meetDo(t, off, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, opened[0].BreakoutID))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("assign with toggle off: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, off, member, "POST", fmt.Sprintf("/meet/%d/breakouts/join", meetingID),
		fmt.Sprintf(`{"breakoutId":%d}`, opened[0].BreakoutID))
	if rr.Code != http.StatusOK {
		t.Fatalf("join with toggle off: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, off, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("close with toggle off: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	for _, b := range opened {
		if !rooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("close did not DeleteRoom %s (every open child, not just the assigned one); calls=%v", b.RoomName, rooms.calls)
		}
	}
}

// TestJoinBreakoutCreateBeforeMintAndRecordingActive pins D11 (a child
// room is pre-created BEFORE any token for it is minted — proven by a
// CreateRoom failure surfacing as 502 with no token ever returned, since
// MintToken has no RoomController call for a call-order assertion to
// observe directly) and F9 (a main-room grant reflects the LIVE recording
// fact; a child grant never does — DN4, breakouts are never recorded).
func TestJoinBreakoutCreateBeforeMintAndRecordingActive(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	t.Run("child: CreateRoom failure means no token, never recorded on success", func(t *testing.T) {
		rooms := newFakeRooms()
		on := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "brkjoinchildhost")
		member := meetTestUser(t, pool, "brkjoinchildmember")
		meetingID := createTestMeeting(t, on, host, "Join child test")
		meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")

		rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		// D11 order proof: a CreateRoom failure must abort BEFORE MintToken
		// runs — the only externally observable signal is that the request
		// as a whole never succeeds (a 502, no token in the body).
		failRooms := newFakeRooms()
		failRooms.errs["CreateRoom:"+b.RoomName] = errors.New("sfu unreachable")
		onFail := meetHandlerWithBreakouts(pool, failRooms, true)
		rr = meetDo(t, onFail, member, "POST", fmt.Sprintf("/meet/%d/breakouts/join", meetingID),
			fmt.Sprintf(`{"breakoutId":%d}`, b.BreakoutID))
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("join with CreateRoom failing: want 502, got %d: %s", rr.Code, rr.Body.String())
		}

		rr = meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/breakouts/join", meetingID),
			fmt.Sprintf(`{"breakoutId":%d}`, b.BreakoutID))
		if rr.Code != http.StatusOK {
			t.Fatalf("join child: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			Token           string `json:"token"`
			WSPath          string `json:"wsPath"`
			ExpiresAt       string `json:"expiresAt"`
			RecordingActive bool   `json:"recordingActive"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode join response %q: %v", rr.Body.String(), err)
		}
		if out.WSPath != "/rtc" {
			t.Errorf("wsPath = %q, want /rtc", out.WSPath)
		}
		if out.Token == "" {
			t.Error("join returned an empty token")
		}
		if out.ExpiresAt == "" {
			t.Error("join returned an empty expiresAt")
		}
		if out.RecordingActive {
			t.Error("a child breakout grant must never carry recordingActive=true (DN4)")
		}
		if !rooms.sawCall("CreateRoom:" + b.RoomName) {
			t.Errorf("join did not pre-create the child room; calls=%v", rooms.calls)
		}
	})

	t.Run("main: recordingActive reflects the live recording fact (F9)", func(t *testing.T) {
		rooms := newFakeRooms()
		on := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "brkjoinmainhost")
		member := meetTestUser(t, pool, "brkjoinmainmember")
		meetingID := createTestMeeting(t, on, host, "Join main test")
		meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")

		if _, err := pool.Exec(context.Background(),
			`INSERT INTO meeting_recordings (meeting_id, state, started_by) VALUES ($1, 'active', $2)`,
			meetingID, host); err != nil {
			t.Fatalf("seed active recording: %v", err)
		}

		// unassigned member + NULL arg = the main-room grant (their own
		// assignment is NULL, matching the NULL arg — meeting_breakout_join's
		// anti-oracle member path).
		rr := meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/breakouts/join", meetingID), `{}`)
		if rr.Code != http.StatusOK {
			t.Fatalf("join main: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			RecordingActive bool `json:"recordingActive"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode join response %q: %v", rr.Body.String(), err)
		}
		if !out.RecordingActive {
			t.Error("main-room join must reflect the live recording fact (F9)")
		}
	})
}

// TestKickEvictsFromChildRoom is the route-level double of the F1 pgTAP
// contract (meeting_breakout.sql's own comment): a kick against a
// mid-breakout target must evict from the CHILD room, not the parent — a
// naive kick that always resolved the parent room would leave a
// mid-breakout target connected to the SFU despite being banned.
func TestKickEvictsFromChildRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	on := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "brkkickhost")
	member := meetTestUser(t, pool, "brkkickmember")
	meetingID := createTestMeeting(t, on, host, "Kick in breakout test")
	meetDo(t, on, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	identity := fmt.Sprintf("u:%d", member)

	rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b := decodeOpenedBreakouts(t, rr)[0]
	if rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, identity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", b.RoomName, identity); !rooms.sawCall(want) {
		t.Errorf("kick did not evict from the child room; want call %q, calls=%v", want, rooms.calls)
	}

	var breakoutID *int64
	var bannedAt *string
	if err := pool.QueryRow(context.Background(),
		`SELECT breakout_id, banned_at::text FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, identity).Scan(&breakoutID, &bannedAt); err != nil {
		t.Fatalf("query participant row: %v", err)
	}
	if breakoutID != nil {
		t.Error("kick must clear breakout_id — a kick is a full eviction, not a move")
	}
	if bannedAt == nil {
		t.Error("kick must stamp banned_at")
	}
}

// TestEndDeletesParentAndEveryChildRoom pins law 1 (end drops everyone,
// every room) at the wire level: DeleteRoom fires for the parent AND for
// every child breakout room that ever existed on this meeting.
func TestEndDeletesParentAndEveryChildRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	on := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "brkendhost")
	meetingID := createTestMeeting(t, on, host, "End with breakouts open")
	parentRoom := roomNameFor(t, pool, meetingID)

	rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	opened := decodeOpenedBreakouts(t, rr)

	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !rooms.sawCall("DeleteRoom:" + parentRoom) {
		t.Errorf("end did not DeleteRoom the parent room; calls=%v", rooms.calls)
	}
	for _, b := range opened {
		if !rooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("end did not DeleteRoom child %s; calls=%v", b.RoomName, rooms.calls)
		}
	}
}

// TestAssignUnreachableTargetBZ201Wire pins the BZ201 RFC7807 projection.
// A user who never joined the meeting is unreachable via p_target_user_id
// the SAME way a guest is (a guest's participant row carries user_id =
// NULL, meeting_admit — meet_breakouts.pg pins that exact reducer-level
// case directly); this proves the identical anti-oracle raise projects
// onto the Go/wire shape without re-scaffolding the full guest-lobby dance
// here just to re-prove a Go concern.
func TestAssignUnreachableTargetBZ201Wire(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	on := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "brkbz201host")
	stranger := meetTestUser(t, pool, "brkbz201stranger")
	meetingID := createTestMeeting(t, on, host, "BZ201 wire test")

	rr := meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b := decodeOpenedBreakouts(t, rr)[0]

	rr = meetDo(t, on, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, stranger, b.BreakoutID))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("assign an unreachable target: want 422, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ201" {
		t.Errorf("problem code = %q, want BZ201", code)
	}
	var p struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem body %q: %v", rr.Body.String(), err)
	}
	if p.Type != "https://setjoin.com/problems/meet/breakout-invalid" {
		t.Errorf("problem type = %q, want .../meet/breakout-invalid", p.Type)
	}
}
