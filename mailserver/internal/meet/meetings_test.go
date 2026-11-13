// meetings_test.go — Task 10: DB-gated route tests for create/list/get/join
// + lock/settings/role/kick/end, over the real reducers on mailserver_test2
// with fakeRooms standing in for the SFU (the tracer_integration_test.go
// precedent — DB_DSN skip-if-absent). TestEveryRevokePathEvicts is the
// machine-checked eviction invariant DES-011 requires: a future revoke
// route added without wiring an eviction call fails this test by omission.
package meet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	lkauth "github.com/livekit/protocol/auth"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func meetDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping DB-gated meet route test")
	}
	return dsn
}

func meetTestPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// meetTestUser creates a fresh user+mailbox via the shared mk_account
// fixture and returns the user id (meet reducers key on users.id, the same
// as chat).
func meetTestUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `SELECT mk_account($1)`, label).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(), `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user_id: %v", err)
	}
	return userID
}

func meetHandler(pool *pgxpool.Pool, rooms RoomController) *Handler {
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.meet": true}), configuredCfg, rooms, nil, nil, slog.Default())
}

// meetHandlerWithEgress is meetHandler extended with recording toggles + an
// EgressController — B2 Task 5's own constructor, used only by
// recording_test.go (every other test in this package has no reason to
// carry an egress double).
func meetHandlerWithEgress(pool *pgxpool.Pool, rooms RoomController, egress EgressController, meetRecordingOn, driveOn bool) *Handler {
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":           true,
		"feature.meet_recording": meetRecordingOn,
		"feature.drive":          driveOn,
	}), configuredCfg, rooms, egress, nil, slog.Default())
}

// meetHandlerWithCaptions is meetHandler extended with the
// feature.meet_captions toggle + a CaptionsController — B3 Task 14's own
// constructor, used only by captions_test.go/worker_test.go's captions
// reconcile tests (every other test in this package has no reason to carry
// a captions double).
func meetHandlerWithCaptions(pool *pgxpool.Pool, rooms RoomController, captions CaptionsController, captionsOn bool) *Handler {
	return NewHandler(pool, toggle.NewTestFlags(map[string]bool{
		"feature.meet":          true,
		"feature.meet_captions": captionsOn,
	}), configuredCfg, rooms, nil, captions, slog.Default())
}

func meetDo(t *testing.T, h *Handler, userID int64, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

// createTestMeeting POSTs /meet as host and returns the new meeting id.
func createTestMeeting(t *testing.T, h *Handler, host int64, title string) int64 {
	t.Helper()
	rr := meetDo(t, h, host, "POST", "/meet", fmt.Sprintf(`{"title":%q}`, title))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create meeting: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		MeetingID int64 `json:"meetingId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	return out.MeetingID
}

func roomNameFor(t *testing.T, pool *pgxpool.Pool, meetingID int64) string {
	t.Helper()
	var room string
	if err := pool.QueryRow(context.Background(), `SELECT room_name::text FROM meetings WHERE id = $1`, meetingID).Scan(&room); err != nil {
		t.Fatalf("resolve room_name: %v", err)
	}
	return room
}

func problemCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var p struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem body %q: %v", rr.Body.String(), err)
	}
	return p.Code
}

// TestCreateListGetBySlugRoutes proves the read surface end to end: create,
// then list/get/get-by-slug all reflect it, and pendingJoinRequests is the
// anti-oracle empty array for a non-host caller (meeting_get's own
// contract, meet_read.pg pins the reducer directly — this proves the route
// wiring on top of it).
func TestCreateListGetBySlugRoutes(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "meetreadhost")
	member := meetTestUser(t, pool, "meetreadmember")

	rr := meetDo(t, h, host, "POST", "/meet", `{"title":"Read route test"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		MeetingID int64  `json:"meetingId"`
		Slug      string `json:"slug"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	rr = meetDo(t, h, host, "GET", "/meet", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, m := range list {
		if int64(m["meetingId"].(float64)) == created.MeetingID {
			found = true
		}
	}
	if !found {
		t.Errorf("GET /meet did not include the meeting just created: %v", list)
	}

	rr = meetDo(t, h, member, "GET", fmt.Sprintf("/meet/%d", created.MeetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get by id: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var detail map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail["title"] != "Read route test" {
		t.Errorf("detail title = %v, want %q", detail["title"], "Read route test")
	}
	if pending, ok := detail["pendingJoinRequests"].([]any); !ok || len(pending) != 0 {
		t.Errorf("non-host detail.pendingJoinRequests = %v, want an empty array (anti-oracle)", detail["pendingJoinRequests"])
	}

	rr = meetDo(t, h, member, "GET", "/meet/by-slug/"+created.Slug, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("get by slug: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var bySlug map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &bySlug); err != nil {
		t.Fatalf("decode by-slug: %v", err)
	}
	if int64(bySlug["meetingId"].(float64)) != created.MeetingID {
		t.Errorf("by-slug meetingId = %v, want %d", bySlug["meetingId"], created.MeetingID)
	}

	rr = meetDo(t, h, host, "GET", "/meet/999999999", "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get nonexistent id: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if problemCode(t, rr) != "BZ185" {
		t.Errorf("nonexistent id problem code = %q, want BZ185", problemCode(t, rr))
	}
}

// TestJoinMintsTokenAndCreatesRoom pins the join flow's locked shape: the
// grant spec becomes a real JWT whose room claim matches the meeting's own
// room_name, and fakeRooms recorded the pre-create (CreateRoom is called
// EVERY join since livekit.yaml's auto_create is off).
func TestJoinMintsTokenAndCreatesRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandler(pool, rooms)

	host := meetTestUser(t, pool, "meetjoinhost")
	meetingID := createTestMeeting(t, h, host, "Join test")
	roomName := roomNameFor(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var joinOut struct {
		Token     string          `json:"token"`
		WSPath    string          `json:"wsPath"`
		ExpiresAt string          `json:"expiresAt"`
		Meeting   json.RawMessage `json:"meeting"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &joinOut); err != nil {
		t.Fatalf("decode join: %v", err)
	}
	if joinOut.WSPath != "/rtc" {
		t.Errorf("wsPath = %q, want /rtc", joinOut.WSPath)
	}
	if joinOut.Token == "" {
		t.Fatal("join returned an empty token")
	}
	if joinOut.ExpiresAt == "" {
		t.Error("join returned an empty expiresAt")
	}

	verifier, err := lkauth.ParseAPIToken(joinOut.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	_, grants, err := verifier.Verify(configuredCfg.APISecret)
	if err != nil {
		t.Fatalf("Verify (with the handler's own configured secret): %v", err)
	}
	if grants.Video.Room != roomName {
		t.Errorf("minted token room = %q, want %q", grants.Video.Room, roomName)
	}
	if !grants.Video.RoomAdmin {
		t.Error("the owner's join grant should carry roomAdmin=true")
	}

	if !rooms.sawCall("CreateRoom:" + roomName) {
		t.Errorf("join did not pre-create the room via RoomController; calls=%v", rooms.calls)
	}

	var meetingEcho map[string]any
	if err := json.Unmarshal(joinOut.Meeting, &meetingEcho); err != nil {
		t.Fatalf("decode meeting echo: %v", err)
	}
	if meetingEcho["roomName"] != roomName {
		t.Errorf("meeting.roomName = %v, want %q", meetingEcho["roomName"], roomName)
	}
}

// TestJoinMidAssignmentUsesBreakoutRoomTimeouts pins eng retro finding #2:
// when meeting_join redirects an already-assigned member straight into
// their OPEN breakout's child room (D10), the join route must pre-create
// THAT room with the D12 breakout timeout pair (86400/86400), never the
// main-room pair (300/20) — a GC'd/never-created child room with main-room
// timeouts lets the SFU self-finish an open breakout out from under the
// D12 accept-as-close arm, closing it behind the host.
func TestJoinMidAssignmentUsesBreakoutRoomTimeouts(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "joinbrktimeouthost")
	member := meetTestUser(t, pool, "joinbrktimeoutmember")
	meetingID := createTestMeeting(t, h, host, "Join mid-assignment timeouts test")

	if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
		t.Fatalf("member join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	mainRoom := roomNameFor(t, pool, meetingID)
	if got, ok := rooms.timeoutsFor(mainRoom); !ok || got != [2]uint32{300, 20} {
		t.Fatalf("main-room join timeouts = %v (ok=%v), want 300/20", got, ok)
	}

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1,"autoAssign":true}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open+autoAssign: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b := decodeOpenedBreakouts(t, rr)[0]

	// D10: the member's own plain /join (not /breakouts/join) now redirects
	// into the assigned child room.
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("mid-assignment join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var joinOut struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &joinOut); err != nil {
		t.Fatalf("decode join: %v", err)
	}
	verifier, err := lkauth.ParseAPIToken(joinOut.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken: %v", err)
	}
	_, grants, err := verifier.Verify(configuredCfg.APISecret)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if grants.Video.Room != b.RoomName {
		t.Fatalf("mid-assignment join minted a token for room %q, want the breakout room %q", grants.Video.Room, b.RoomName)
	}

	got, ok := rooms.timeoutsFor(b.RoomName)
	if !ok {
		t.Fatalf("join did not pre-create the breakout room %s at all; calls=%v", b.RoomName, rooms.calls)
	}
	if got != [2]uint32{breakoutEmptyTimeout, breakoutDepartureTimeout} {
		t.Errorf("mid-assignment join CreateRoom timeouts = %v, want the D12 pair %v (not the main-room 300/20)",
			got, [2]uint32{breakoutEmptyTimeout, breakoutDepartureTimeout})
	}
}

// TestJoinLockedMeetingStrangerBZ187 pins the lock-refusal wire shape.
func TestJoinLockedMeetingStrangerBZ187(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "meetlockhost")
	stranger := meetTestUser(t, pool, "meetlockstranger")
	meetingID := createTestMeeting(t, h, host, "Lock test")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("lock: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, h, stranger, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("stranger join on a locked meeting: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ187" {
		t.Errorf("problem code = %q, want BZ187", code)
	}
}

// TestSettingsRouteHostOnlyMemberForbidden pins the guestAllowed settings
// route: host/cohost only, and the flip is durably visible via GET.
func TestSettingsRouteHostOnlyMemberForbidden(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "meetsettingshost")
	member := meetTestUser(t, pool, "meetsettingsmember")
	meetingID := createTestMeeting(t, h, host, "Settings test")
	meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")

	rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("member settings flip: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("host settings flip: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = meetDo(t, h, host, "GET", fmt.Sprintf("/meet/%d", meetingID), "")
	var detail struct {
		GuestAllowed bool `json:"guestAllowed"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if !detail.GuestAllowed {
		t.Error("guestAllowed did not flip to true")
	}
}

// TestKickBansAndReAdmitRoundTrip proves the kick-then-role-re-admit round
// trip through the routes (the reducer round trip is already pinned in
// meet_control.pg; this proves the Go wiring on top of it, including the
// eviction call and the BZ186 wire shape).
func TestKickBansAndReAdmitRoundTrip(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandler(pool, rooms)

	host := meetTestUser(t, pool, "meetkickhost")
	member := meetTestUser(t, pool, "meetkickmember")
	meetingID := createTestMeeting(t, h, host, "Kick test")
	meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	roomName := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", member)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, identity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	wantCall := fmt.Sprintf("RemoveParticipant:%s/%s", roomName, identity)
	if !rooms.sawCall(wantCall) {
		t.Errorf("kick did not evict via RoomController; want call %q, calls=%v", wantCall, rooms.calls)
	}

	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("kicked member rejoin: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "BZ186" {
		t.Errorf("kicked rejoin problem code = %q, want BZ186", code)
	}

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/role", meetingID), fmt.Sprintf(`{"identity":%q,"role":"member"}`, identity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("role re-admit: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("re-admitted rejoin: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestKickControllerErrorReturns502 proves the RoomController-error leg:
// authorization/ban already committed to the DB before the eviction call
// runs, so a SFU-side failure surfaces as 502 without undoing the ban — a
// host retry (or the Task 12 reconcile sweep) converges without re-running
// the authorization check.
func TestKickControllerErrorReturns502(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandler(pool, rooms)

	host := meetTestUser(t, pool, "meetkickerrhost")
	member := meetTestUser(t, pool, "meetkickerrmember")
	meetingID := createTestMeeting(t, h, host, "Kick error test")
	meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	roomName := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", member)

	rooms.errs[fmt.Sprintf("RemoveParticipant:%s/%s", roomName, identity)] = errors.New("sfu unreachable")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, identity))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("kick with a controller error: want 502, got %d: %s", rr.Code, rr.Body.String())
	}

	var bannedAt *string
	if err := pool.QueryRow(context.Background(),
		`SELECT banned_at::text FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, identity).Scan(&bannedAt); err != nil {
		t.Fatalf("query banned_at: %v", err)
	}
	if bannedAt == nil {
		t.Error("the ban must already be committed even though the eviction call itself failed")
	}
}

// TestEndEvictsRoom pins the end route's eviction call.
func TestEndEvictsRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandler(pool, rooms)

	host := meetTestUser(t, pool, "meetendhost")
	meetingID := createTestMeeting(t, h, host, "End test")
	roomName := roomNameFor(t, pool, meetingID)

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !rooms.sawCall("DeleteRoom:" + roomName) {
		t.Errorf("end did not evict via DeleteRoom; calls=%v", rooms.calls)
	}
}

// TestEndDoesNotSweepLongClosedBreakoutRooms pins eng retro finding #9b: the
// end route's child-room sweep is scoped to state='open' OR closed_at within
// the last 24h (worker.go's gcClosedBreakoutRooms window) — a breakout
// closed long ago must NOT get a DeleteRoom call on every subsequent /end,
// which the unscoped "every row ever opened for this meeting" query used to
// do (dead work + log noise on any meeting with breakout history).
func TestEndDoesNotSweepLongClosedBreakoutRooms(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandlerWithBreakouts(pool, rooms, true)

	host := meetTestUser(t, pool, "endsweepoldhost")
	meetingID := createTestMeeting(t, h, host, "End sweep old-breakout test")

	// A long-closed breakout row, seeded directly (never through the
	// /breakouts/close ROUTE, which itself calls DeleteRoom on close — that
	// would make rooms.sawCall true regardless of what /end does, unable to
	// isolate the fix under test). This is what a meeting with real
	// breakout history looks like months later.
	var oldRoomName string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO meeting_breakouts (meeting_id, idx, title, state, closed_at)
		 VALUES ($1, 99, 'Ancient', 'closed', now() - interval '30 days')
		 RETURNING room_name::text`, meetingID).Scan(&oldRoomName); err != nil {
		t.Fatalf("seed old breakout: %v", err)
	}

	// A SECOND, currently-open breakout — must still be swept (the scoping
	// change must not drop the 'open' arm).
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	openBreakout := decodeOpenedBreakouts(t, rr)[0]

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	if rooms.sawCall("DeleteRoom:" + oldRoomName) {
		t.Errorf("end must not DeleteRoom a breakout closed >24h ago; calls=%v", rooms.calls)
	}
	if !rooms.sawCall("DeleteRoom:" + openBreakout.RoomName) {
		t.Errorf("end must still DeleteRoom the currently-open breakout; calls=%v", rooms.calls)
	}
}

// TestEveryRevokePathEvicts is the machine-checked eviction invariant
// (DES-011 / spike §2 finding 1): kick and end both terminate in a
// RoomController call; lock and settings are the two documented NON-revoke
// routes (future joins blocked only, present participants unaffected) and
// are asserted here to call the controller ZERO times — excluded by
// explicit design, not by omission.
func TestEveryRevokePathEvicts(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	cases := []struct {
		name     string
		wantCall func(room, identity string) string
		fire     func(t *testing.T, h *Handler, hostID, memberID, meetingID int64, identity string)
	}{
		{
			name:     "kick",
			wantCall: func(room, identity string) string { return fmt.Sprintf("RemoveParticipant:%s/%s", room, identity) },
			fire: func(t *testing.T, h *Handler, hostID, _, meetingID int64, identity string) {
				rr := meetDo(t, h, hostID, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, identity))
				if rr.Code != http.StatusNoContent {
					t.Fatalf("kick: want 204, got %d: %s", rr.Code, rr.Body.String())
				}
			},
		},
		{
			name:     "end",
			wantCall: func(room, _ string) string { return "DeleteRoom:" + room },
			fire: func(t *testing.T, h *Handler, hostID, _, meetingID int64, _ string) {
				rr := meetDo(t, h, hostID, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
				if rr.Code != http.StatusNoContent {
					t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rooms := newFakeRooms()
			h := meetHandler(pool, rooms)
			host := meetTestUser(t, pool, "evict-host-"+tc.name)
			member := meetTestUser(t, pool, "evict-member-"+tc.name)
			meetingID := createTestMeeting(t, h, host, "Evict "+tc.name)
			meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
			room := roomNameFor(t, pool, meetingID)
			identity := fmt.Sprintf("u:%d", member)

			tc.fire(t, h, host, member, meetingID, identity)

			want := tc.wantCall(room, identity)
			if !rooms.sawCall(want) {
				t.Errorf("%s did not evict; want call %q, got calls=%v", tc.name, want, rooms.calls)
			}
		})
	}

	t.Run("lock and settings evict nobody (documented non-revoke routes)", func(t *testing.T) {
		rooms := newFakeRooms()
		// feature.meet_breakouts ON: B3's "breakout OPEN is create-only"
		// claim below needs a real open call to prove anything at all.
		h := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "evict-host-noop")
		meetingID := createTestMeeting(t, h, host, "Evict noop test")

		meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
		meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
		// B3: breakout OPEN is create-only by design — it DOES call
		// CreateRoomWithTimeouts (Task 4's pre-create-every-child, fine and
		// expected), so this subtest can no longer assert zero calls
		// overall; only eviction calls (RemoveParticipant/DeleteRoom) must
		// stay zero.
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}

		for _, c := range rooms.calls {
			if strings.HasPrefix(c, "RemoveParticipant:") || strings.HasPrefix(c, "DeleteRoom:") {
				t.Errorf("lock/settings/breakout-open must never evict; got calls=%v", rooms.calls)
			}
		}
	})

	// B3 Task 5: the breakout surface grows four more machine-checked
	// eviction cases onto this SAME invariant test — move/close/end/
	// kick-while-in-breakout all terminate in a RoomController call.
	t.Run("breakout move", func(t *testing.T) {
		rooms := newFakeRooms()
		h := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "evict-brkmove-host")
		member := meetTestUser(t, pool, "evict-brkmove-member")
		meetingID := createTestMeeting(t, h, host, "Evict breakout move")
		meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		mainRoom := roomNameFor(t, pool, meetingID)
		identity := fmt.Sprintf("u:%d", member)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]

		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		if want := fmt.Sprintf("RemoveParticipant:%s/%s", mainRoom, identity); !rooms.sawCall(want) {
			t.Errorf("breakout move did not evict; want call %q, calls=%v", want, rooms.calls)
		}
	})

	t.Run("breakout close", func(t *testing.T) {
		rooms := newFakeRooms()
		h := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "evict-brkclose-host")
		meetingID := createTestMeeting(t, h, host, "Evict breakout close")

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		opened := decodeOpenedBreakouts(t, rr)

		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		for _, b := range opened {
			if want := "DeleteRoom:" + b.RoomName; !rooms.sawCall(want) {
				t.Errorf("breakout close did not evict child %s; want call %q, calls=%v", b.RoomName, want, rooms.calls)
			}
		}
	})

	t.Run("end with breakouts open", func(t *testing.T) {
		rooms := newFakeRooms()
		h := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "evict-brkend-host")
		meetingID := createTestMeeting(t, h, host, "Evict end with breakouts open")
		parentRoom := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		opened := decodeOpenedBreakouts(t, rr)

		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		if !rooms.sawCall("DeleteRoom:" + parentRoom) {
			t.Errorf("end with breakouts open did not evict the parent room; calls=%v", rooms.calls)
		}
		for _, b := range opened {
			if !rooms.sawCall("DeleteRoom:" + b.RoomName) {
				t.Errorf("end with breakouts open did not evict child %s; calls=%v", b.RoomName, rooms.calls)
			}
		}
	})

	// F1 — the machine check: a kick against a mid-breakout target evicts
	// from the CHILD room, never the parent (breakouts_test.go's
	// TestKickEvictsFromChildRoom proves the same fact in more detail; this
	// growing the SAME invariant test is the point — a future revoke route
	// that forgets to resolve the child room fails HERE by omission).
	t.Run("kick while in breakout", func(t *testing.T) {
		rooms := newFakeRooms()
		h := meetHandlerWithBreakouts(pool, rooms, true)
		host := meetTestUser(t, pool, "evict-brkkick-host")
		member := meetTestUser(t, pool, "evict-brkkick-member")
		meetingID := createTestMeeting(t, h, host, "Evict kick while in breakout")
		meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		identity := fmt.Sprintf("u:%d", member)
		mainRoom := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, identity))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("kick: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		if want := fmt.Sprintf("RemoveParticipant:%s/%s", b.RoomName, identity); !rooms.sawCall(want) {
			t.Errorf("kick while in breakout did not evict from the CHILD room; want call %q, calls=%v", want, rooms.calls)
		}
		// mainRoom DOES appear once already — the earlier assign step's own
		// legitimate main->child eviction (F1's own proof). The machine
		// check here is that KICK itself never fires a second, redundant
		// main-room eviction: count, not sawCall (sawCall can't tell which
		// call produced an already-true membership test).
		mainWant := fmt.Sprintf("RemoveParticipant:%s/%s", mainRoom, identity)
		mainCount := 0
		for _, c := range rooms.calls {
			if c == mainWant {
				mainCount++
			}
		}
		if mainCount != 1 {
			t.Errorf("want exactly 1 main-room eviction (assign's, not kick's); got %d, calls=%v", mainCount, rooms.calls)
		}
	})
}
