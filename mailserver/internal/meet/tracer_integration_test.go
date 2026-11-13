// tracer_integration_test.go — Task 18: the full-arc DB-gated integration
// gate (the A1/A2 gate genre — see internal/chat/tracer_integration_test.go
// and internal/drive/handler_live_test.go). Every other _test.go file in
// this package DB-gate-tests one route/reducer pair in isolation; this file
// proves the pieces compose in the realistic order a real meeting goes
// through — create (huddle, p_system arc) -> member join (org-open pin) ->
// kick -> BZ186 rejoin -> re-admit -> rejoin -> lock -> stranger 403 ->
// member knock -> public poll completes it -> mid-arc guestAllowed flip ->
// guest join-request -> host admit -> guest poll mints -> guest kick ->
// poll denied -> end (evicts + expires pending requests) -> a replayed
// room_finished webhook is a no-op. Plus feature.meet OFF on a REAL
// registered route (not handler_test.go's synthetic sentinel).
package meet

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	lkauth "github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

// chatChannelDirect creates a chat channel straight through the reducer
// (bypassing internal/chat's HTTP layer entirely — this package has no
// business standing up a second app's handler just to get a channel row).
// system=true mirrors meeting_create's own bridge call so the fresh-channel
// arc is covered elsewhere; here p_system=false is deliberate: proves a
// caller-owned channel a huddle can bind to, independent of the toggle.
func chatChannelDirect(t *testing.T, pool *pgxpool.Pool, owner int64, name string) int64 {
	t.Helper()
	var channelID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT chat_channel_create($1, $2, NULL, 'private', true)`, owner, name,
	).Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	return channelID
}

func setChatChannelCreationToggle(t *testing.T, pool *pgxpool.Pool, enabled bool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE feature_toggles SET enabled = $1 WHERE key = 'chat.channel_creation'`, enabled); err != nil {
		t.Fatalf("flip chat.channel_creation: %v", err)
	}
}

func hasCallMessage(t *testing.T, pool *pgxpool.Pool, channelID, meetingID int64) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS(
		  SELECT 1 FROM chat_messages
		   WHERE channel_id = $1 AND msg_type = 'call'
		     AND (payload ->> 'meetingId')::bigint = $2)`,
		channelID, meetingID).Scan(&ok); err != nil {
		t.Fatalf("check call message: %v", err)
	}
	return ok
}

// TestFullMeetingArc is the mandatory Task 18 tracer: one continuous run
// through every wire-level seam Tasks 1-17 built, over the real reducers +
// real routes + fakeRooms on mailserver_test2.
func TestFullMeetingArc(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	h := meetHandler(pool, rooms)
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "arc-host")
	member := meetTestUser(t, pool, "arc-member")
	other := meetTestUser(t, pool, "arc-other")
	stranger := meetTestUser(t, pool, "arc-stranger")

	// ── create: huddle bound to a real chat channel, chat.channel_creation
	// OFF the whole time (the p_system bypass — CEO deviation (d) REJECTED,
	// pinned again here at the wire level; meet_create.pg already pins it at
	// the reducer level, this proves the Go route doesn't reintroduce the
	// gate). ──
	channelID := chatChannelDirect(t, pool, host, "arc-huddle-channel")
	setChatChannelCreationToggle(t, pool, false)
	t.Cleanup(func() { setChatChannelCreationToggle(t, pool, true) })

	rr := meetDo(t, h, host, "POST", "/meet",
		fmt.Sprintf(`{"title":"Arc meeting","chatChannelId":%d}`, channelID))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		MeetingID     int64  `json:"meetingId"`
		Slug          string `json:"slug"`
		ChatChannelID int64  `json:"chatChannelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	meetingID := created.MeetingID
	if created.ChatChannelID != channelID {
		t.Fatalf("create bound chatChannelId=%d, want the origin channel %d", created.ChatChannelID, channelID)
	}
	if !hasCallMessage(t, pool, channelID, meetingID) {
		t.Error("huddle create did not post a call-started system message into the origin channel")
	}
	room := roomNameFor(t, pool, meetingID)

	// ── member join: the org-open posture — an authenticated non-participant
	// joins with no invite. A second user proves it's not a one-shot fluke. ──
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member join (org-open): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, other, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("second stranger org-open join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── kick member -> RemoveParticipant -> BZ186 rejoin -> re-admit ->
	// rejoin succeeds. ──
	memberIdentity := fmt.Sprintf("u:%d", member)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, memberIdentity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick member: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", room, memberIdentity); !rooms.sawCall(want) {
		t.Errorf("kick did not evict; want call %q, calls=%v", want, rooms.calls)
	}
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ186" {
		t.Fatalf("kicked member rejoin: want 403/BZ186, got %d/%s", rr.Code, problemCode(t, rr))
	}
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/role", meetingID), fmt.Sprintf(`{"identity":%q,"role":"member"}`, memberIdentity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("re-admit via role route: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("re-admitted member rejoin: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── lock -> a stranger's join is refused, a stranger's knock is not. ──
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("lock: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, h, stranger, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ187" {
		t.Fatalf("stranger join on locked meeting: want 403/BZ187, got %d/%s", rr.Code, problemCode(t, rr))
	}

	// ── stranger knocks -> {requestId, secret} -> completes on the PUBLIC
	// poll route (the knock-completion contract: never a member-only
	// endpoint). ──
	rr = meetDo(t, h, stranger, "POST", fmt.Sprintf("/meet/%d/knock", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("knock: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	knock := decodeCreateResp(t, rr)

	// ── settings flip guestAllowed ON mid-arc (host/cohost only; affects
	// FUTURE knocks/guests only). ──
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("settings guestAllowed flip: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Admit the knock now (after the settings flip, proving the two are
	// independent arms of the lobby surface).
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, knock.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit knock: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", created.Slug, knock.RequestID),
		map[string]string{"slug": created.Slug, "id": strconv.FormatInt(knock.RequestID, 10)}, "",
		secretHeader(knock.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("poll knock after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	knockPoll := decodePollResp(t, rr)
	if knockPoll.State != "admitted" || knockPoll.Token == "" {
		t.Fatalf("knock poll after admit = %+v, want admitted+token", knockPoll)
	}
	verifier, err := lkauth.ParseAPIToken(knockPoll.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken (knock): %v", err)
	}
	if _, grants, err := verifier.Verify(configuredCfg.APISecret); err != nil {
		t.Fatalf("Verify (knock): %v", err)
	} else if grants.Identity != fmt.Sprintf("u:%d", stranger) {
		t.Errorf("knock token identity = %q, want u:%d (never a guest identity)", grants.Identity, stranger)
	}

	// ── guest join-request -> host admits -> guest poll mints a g: token. ──
	rr = publicDo(t, ph, "POST", "/public/meet/"+created.Slug+"/join-request",
		map[string]string{"slug": created.Slug}, `{"displayName":"Arc Guest"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("guest create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	guest := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, guest.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit guest: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", created.Slug, guest.RequestID),
		map[string]string{"slug": created.Slug, "id": strconv.FormatInt(guest.RequestID, 10)}, "",
		secretHeader(guest.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("guest poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	guestPoll := decodePollResp(t, rr)
	if guestPoll.State != "admitted" || guestPoll.Token == "" {
		t.Fatalf("guest poll after admit = %+v, want admitted+token", guestPoll)
	}
	guestIdentity := "g:" + strconv.FormatInt(guest.RequestID, 10)
	verifier, err = lkauth.ParseAPIToken(guestPoll.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken (guest): %v", err)
	}
	if _, grants, err := verifier.Verify(configuredCfg.APISecret); err != nil {
		t.Fatalf("Verify (guest): %v", err)
	} else {
		if grants.Identity != guestIdentity {
			t.Errorf("guest token identity = %q, want %q", grants.Identity, guestIdentity)
		}
		if grants.Video.RoomAdmin {
			t.Error("a guest's minted token must never carry roomAdmin=true")
		}
	}

	// ── guest kick -> RemoveParticipant -> poll now denied, no token. ──
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, guestIdentity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick guest: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", room, guestIdentity); !rooms.sawCall(want) {
		t.Errorf("guest kick did not evict; want call %q, calls=%v", want, rooms.calls)
	}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", created.Slug, guest.RequestID),
		map[string]string{"slug": created.Slug, "id": strconv.FormatInt(guest.RequestID, 10)}, "",
		secretHeader(guest.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("guest poll after kick: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if p := decodePollResp(t, rr); p.State != "denied" || p.Token != "" {
		t.Fatalf("guest poll after kick = %+v, want denied with no token", p)
	}

	// ── end -> DeleteRoom + any still-pending join requests expire. ──
	// (none pending at this point, but meeting_end's own expiry statement
	// runs regardless — asserted via a fresh knock created just before end.)
	rr = meetDo(t, h, stranger, "POST", fmt.Sprintf("/meet/%d/knock", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("pre-end knock: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	preEndKnock := decodeCreateResp(t, rr)

	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !rooms.sawCall("DeleteRoom:" + room) {
		t.Errorf("end did not evict via DeleteRoom; calls=%v", rooms.calls)
	}
	var pendingState string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_join_requests WHERE id = $1`, preEndKnock.RequestID).Scan(&pendingState); err != nil {
		t.Fatalf("resolve pre-end knock state: %v", err)
	}
	if pendingState != "expired" {
		t.Errorf("pending join request state after end = %q, want expired", pendingState)
	}

	// ── a replayed room_finished webhook is a no-op (idempotent — the
	// meeting is already 'ended', ended_at/left_at must not move again). ──
	var endedAtBefore string
	if err := pool.QueryRow(context.Background(),
		`SELECT ended_at::text FROM meetings WHERE id = $1`, meetingID).Scan(&endedAtBefore); err != nil {
		t.Fatalf("resolve ended_at: %v", err)
	}
	event := &livekit.WebhookEvent{Event: "room_finished", Room: &livekit.Room{Name: room}}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr2 := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Fatalf("replayed room_finished: want 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var endedAtAfter string
	if err := pool.QueryRow(context.Background(),
		`SELECT ended_at::text FROM meetings WHERE id = $1`, meetingID).Scan(&endedAtAfter); err != nil {
		t.Fatalf("resolve ended_at after replay: %v", err)
	}
	if endedAtAfter != endedAtBefore {
		t.Errorf("replayed room_finished moved ended_at: before=%s after=%s", endedAtBefore, endedAtAfter)
	}

	// ── feature.meet OFF -> a REAL registered route 404s, no sentinel
	// shortcut (handler_test.go's TestRoutes404WhenMeetOff proves the gate
	// mechanism with a synthetic path; this proves it holds for the actual
	// production route table). ──
	hOff := NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.meet": false}), configuredCfg, newFakeRooms(), nil, nil, slog.Default())
	rr = meetDo(t, hOff, host, "GET", fmt.Sprintf("/meet/%d", meetingID), "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("real route with feature.meet OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ── B3 Task 10: the breakout tracer arc ─────────────────────────────────

// chatDo is meetDo's shape for internal/chat's own *Handler — a distinct
// type from meet's *Handler, so it needs its own thin request driver
// (chat's own _test.go helpers are package-private to internal/chat and
// unreachable from here).
func chatDo(t *testing.T, h *chat.Handler, userID int64, method, path, body string) *httptest.ResponseRecorder {
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

// meetPushEnvelope is notify_meet_state's own wire shape
// ({"event":..,"meetingId":..,"payload":..}), decoded here to inspect the
// _test_notify_log side-channel (webhook_test.go's sawRecordingPush genre).
type meetPushEnvelope struct {
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

// sawBreakoutAssignedPush reports whether _test_notify_log recorded a
// breakout_assigned push on userID's own meet:{userID} channel naming the
// given target identity + breakout id. breakout_assigned is
// targeted-BY-PAYLOAD, not per-user push (notify_meet_state.sql's own
// comment) — it fans to every live participant, so this filters on the
// payload's identity/breakoutId rather than asserting anything about which
// channel it landed on. Requires app.capture_notify='on' already set on
// this pool's one connection (meetSingleConnPool).
func sawBreakoutAssignedPush(t *testing.T, pool *pgxpool.Pool, userID int64, wantIdentity string, wantBreakoutID int64) bool {
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
		var env meetPushEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("decode _test_notify_log payload %q: %v", raw, err)
		}
		if env.Event != "breakout_assigned" {
			continue
		}
		var p struct {
			Identity   string `json:"identity"`
			BreakoutID *int64 `json:"breakoutId"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			t.Fatalf("decode breakout_assigned payload %q: %v", env.Payload, err)
		}
		if p.Identity == wantIdentity && p.BreakoutID != nil && *p.BreakoutID == wantBreakoutID {
			return true
		}
	}
	return false
}

// TestBreakoutTracerArc is Task 10's B3a integration proof: ONE continuous
// arc over the real breakout routes + reducers + fakeRooms + the real chat
// route (the TestFullMeetingArc genre, grown for B3). It composes pieces
// Tasks 1-9 already unit-proved in the realistic order a real breakout
// session goes through — create+join -> F11 toggle wire gate -> open+
// autoAssign -> forced move -> breakout join (D11) -> webhook ordering both
// ways (§4.1) -> meeting_join mid-assignment (D10) -> kick-in-breakout (F1/
// D13) -> guest exclusion (BZ201) -> Q&A through the real chat route (F4) ->
// close-all -> reopen (F3) -> end with breakouts open -> a replayed child
// room_finished after end is a no-op (D12).
func TestBreakoutTracerArc(t *testing.T) {
	dsn := meetDSN(t)
	// A single-connection pool so app.capture_notify='on' (session-scoped
	// GUC) sticks for the whole arc — the recording_test.go/webhook_test.go
	// precedent (meetSingleConnPool) — needed here to observe the
	// breakout_assigned pushes in step 3.
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}
	rooms := newFakeRooms()
	hOff := meetHandlerWithBreakouts(pool, rooms, false)
	hOn := meetHandlerWithBreakouts(pool, rooms, true)
	chatH := chat.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())

	host := meetTestUser(t, pool, "brktracer-host")
	member1 := meetTestUser(t, pool, "brktracer-member1")
	member2 := meetTestUser(t, pool, "brktracer-member2")
	member1Identity := fmt.Sprintf("u:%d", member1)
	member2Identity := fmt.Sprintf("u:%d", member2)

	// ── 1. create -> host + 2 members join (org-open, real routes). Every
	// meeting always gets a bridged chat channel (meeting_create.sql's
	// p_system bypass), so no explicit chatChannelId is needed here. ──
	rr := meetDo(t, hOff, host, "POST", "/meet", `{"title":"Breakout tracer arc"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		MeetingID     int64 `json:"meetingId"`
		ChatChannelID int64 `json:"chatChannelId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	meetingID, channelID := created.MeetingID, created.ChatChannelID
	room := roomNameFor(t, pool, meetingID)

	for _, u := range []int64{member1, member2} {
		rr = meetDo(t, hOff, u, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("member %d join: want 200, got %d: %s", u, rr.Code, rr.Body.String())
		}
	}

	// ── 2. F11 at the wire: toggle OFF -> open 404s; assign/close still
	// route (unconditional — they reach the reducer, never the gate). No
	// breakout has ever been opened yet, so both calls prove the drain
	// posture on a cold surface, not just a warm one. ──
	rr = meetDo(t, hOff, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("open with toggle off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, hOff, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID), `{"targetUserId":-1,"breakoutId":null}`)
	if rr.Code != http.StatusUnprocessableEntity || problemCode(t, rr) != "BZ201" {
		t.Fatalf("assign with toggle off (F11 drain, reaches the reducer): want 422/BZ201, got %d/%s", rr.Code, problemCode(t, rr))
	}
	rr = meetDo(t, hOff, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("close with toggle off (F11 drain, idempotent no-op): want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── 3. toggle ON -> open(2, autoAssign) -> both members' own
	// breakout_assigned pushes observed. Round-robin over live members
	// ordered by join order: member1 (joined first) -> breakout[0],
	// member2 -> breakout[1] (host is role='host', excluded — D7). ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":2,"autoAssign":true}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open(2, autoAssign): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	opened := decodeOpenedBreakouts(t, rr)
	if len(opened) != 2 {
		t.Fatalf("open(2): got %d breakouts, want 2", len(opened))
	}
	b1, b2 := opened[0], opened[1]
	if !sawBreakoutAssignedPush(t, pool, member1, member1Identity, b1.BreakoutID) {
		t.Error("member1's own breakout_assigned push (auto-assigned to b1) not observed")
	}
	if !sawBreakoutAssignedPush(t, pool, member2, member2Identity, b2.BreakoutID) {
		t.Error("member2's own breakout_assigned push (auto-assigned to b2) not observed")
	}

	// ── 4. forced move: host re-assigns member1 b1 -> b2. The eviction call
	// must name b1 — the room member1 is CURRENTLY (per the DB) assigned to
	// — never main, even though member1 never physically evicted from
	// anywhere yet (auto-assign is pure bookkeeping, no eviction call). ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member1, b2.BreakoutID))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("forced move b1->b2: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", b1.RoomName, member1Identity); !rooms.sawCall(want) {
		t.Errorf("forced move did not evict from b1 (the RIGHT current room); want %q, calls=%v", want, rooms.calls)
	}

	// ── 5. member1 joins their new assignment (b2): a child token, minted
	// after a CreateRoomWithTimeouts pre-create. The strict fail-first
	// ordering proof (a CreateRoom failure blocks MintToken) is already
	// unit-pinned in breakouts_test.go's
	// TestJoinBreakoutCreateBeforeMintAndRecordingActive; this composes the
	// happy path in the realistic arc and confirms the pre-create call
	// actually lands here too. ──
	rr = meetDo(t, hOn, member1, "POST", fmt.Sprintf("/meet/%d/breakouts/join", meetingID),
		fmt.Sprintf(`{"breakoutId":%d}`, b2.BreakoutID))
	if rr.Code != http.StatusOK {
		t.Fatalf("member1 breakouts/join b2: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var childJoin struct {
		Token           string `json:"token"`
		WSPath          string `json:"wsPath"`
		RecordingActive bool   `json:"recordingActive"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &childJoin); err != nil {
		t.Fatalf("decode breakouts/join response: %v", err)
	}
	if childJoin.Token == "" {
		t.Error("breakouts/join returned an empty token")
	}
	if childJoin.WSPath != "/rtc" {
		t.Errorf("breakouts/join wsPath = %q, want /rtc", childJoin.WSPath)
	}
	if childJoin.RecordingActive {
		t.Error("DN4: a child breakout grant must never carry recordingActive=true")
	}
	if !rooms.sawCall("CreateRoom:" + b2.RoomName) {
		t.Errorf("breakouts/join did not pre-create the child room (D11); calls=%v", rooms.calls)
	}

	// ── 6. webhook ordering both ways (§4.1 — do not simplify this back):
	// left(parent)/joined(child) in EITHER order must never stamp left_at,
	// since assignment (not physical presence) is the truth a leave is
	// checked against. member1 (just moved) proves order A; member2 (never
	// moved, still on its original auto-assignment to b2) proves order B —
	// the rule holds independent of whether a forced move ever happened. ──
	fireWebhook := func(event *livekit.WebhookEvent) {
		t.Helper()
		req := signWebhookRequest(t, configuredCfg, event, false)
		rrw := httptest.NewRecorder()
		hOn.WebhookHandler().ServeHTTP(rrw, req)
		if rrw.Code != http.StatusOK {
			t.Fatalf("webhook %s: want 200, got %d: %s", event.Event, rrw.Code, rrw.Body.String())
		}
	}
	fireWebhook(&livekit.WebhookEvent{Event: "participant_left", Room: &livekit.Room{Name: room}, Participant: &livekit.ParticipantInfo{Identity: member1Identity}})
	fireWebhook(&livekit.WebhookEvent{Event: "participant_joined", Room: &livekit.Room{Name: b2.RoomName}, Participant: &livekit.ParticipantInfo{Identity: member1Identity}})
	if _, left := participantJoinedAt(t, pool, meetingID, member1Identity); left != nil {
		t.Error("order A (left(parent) then joined(child)) stamped left_at — the parent leave was expected move churn, not a real departure")
	}
	fireWebhook(&livekit.WebhookEvent{Event: "participant_joined", Room: &livekit.Room{Name: b2.RoomName}, Participant: &livekit.ParticipantInfo{Identity: member2Identity}})
	fireWebhook(&livekit.WebhookEvent{Event: "participant_left", Room: &livekit.Room{Name: room}, Participant: &livekit.ParticipantInfo{Identity: member2Identity}})
	if _, left := participantJoinedAt(t, pool, meetingID, member2Identity); left != nil {
		t.Error("order B (joined(child) then left(parent)) stamped left_at — the OTHER webhook ordering must be equally safe")
	}

	// ── 7. meeting_join mid-assignment returns the child room (D10): a
	// member cannot mint a main-room token around a live assignment. ──
	rr = meetDo(t, hOn, member1, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("mid-assignment meeting_join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var midJoin struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &midJoin); err != nil {
		t.Fatalf("decode mid-assignment join: %v", err)
	}
	verifier, err := lkauth.ParseAPIToken(midJoin.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken (mid-assignment join): %v", err)
	}
	if _, grants, err := verifier.Verify(configuredCfg.APISecret); err != nil {
		t.Fatalf("Verify (mid-assignment join): %v", err)
	} else if grants.Video.Room != b2.RoomName {
		t.Errorf("D10: mid-assignment meeting_join room = %q, want the assigned child %q", grants.Video.Room, b2.RoomName)
	}

	// ── 8. kick-in-breakout: eviction names the CHILD room (F1); the
	// bridged-channel membership row is GONE (D13); rejoin refused BZ186. ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, member1Identity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick-in-breakout: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if want := fmt.Sprintf("RemoveParticipant:%s/%s", b2.RoomName, member1Identity); !rooms.sawCall(want) {
		t.Errorf("kick-in-breakout did not evict from the CHILD room b2; want %q, calls=%v", want, rooms.calls)
	}
	var stillChatMember bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM chat_channel_members WHERE channel_id = $1 AND user_id = $2)`,
		channelID, member1).Scan(&stillChatMember); err != nil {
		t.Fatalf("query chat_channel_members: %v", err)
	}
	if stillChatMember {
		t.Error("D13: a kicked participant's bridged-channel membership row must be gone")
	}
	rr = meetDo(t, hOn, member1, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ186" {
		t.Fatalf("kicked member1 rejoin: want 403/BZ186, got %d/%s", rr.Code, problemCode(t, rr))
	}

	// ── 9. guest knock+admit (recording off) -> breakouts/assign of the
	// guest -> 422 BZ201. A guest's participant row carries user_id = NULL
	// (meeting_admit) — no p_target_user_id value can EVER match it, so -1
	// (a value no real user id can ever take) stands in for "the guest" the
	// same way breakouts_test.go's TestAssignUnreachableTargetBZ201Wire
	// uses a never-joined stranger: the anti-oracle raise is identical
	// either way, by construction. ──
	admitGuestOnMeeting(t, hOn, host, meetingID)
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, -1, b1.BreakoutID))
	if rr.Code != http.StatusUnprocessableEntity || problemCode(t, rr) != "BZ201" {
		t.Fatalf("assign targeting a guest (unreachable via p_target_user_id): want 422/BZ201, got %d/%s", rr.Code, problemCode(t, rr))
	}

	// ── 10. Q&A through the REAL chat route: a 'question' message lands in
	// the bridged channel (member2, still a member — only member1 was
	// removed at kick); 'poll' via bare send still 400s (F4 — only
	// chat_poll_create may originate a poll row). ──
	rr = chatDo(t, chatH, member2, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"When do we regroup?","msgType":"question"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("question send: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var qOut struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &qOut); err != nil {
		t.Fatalf("decode question send response: %v", err)
	}
	var dbMsgType string
	if err := pool.QueryRow(context.Background(),
		`SELECT msg_type FROM chat_messages WHERE id = $1`, qOut.MessageID).Scan(&dbMsgType); err != nil {
		t.Fatalf("query msg_type: %v", err)
	}
	if dbMsgType != "question" {
		t.Errorf("question message msg_type = %q, want question", dbMsgType)
	}
	rr = chatDo(t, chatH, member2, "POST", fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"pick one","msgType":"poll"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bare poll send (F4): want 400, got %d: %s", rr.Code, rr.Body.String())
	}

	// ── 11. close-all: every child DeleteRoom'd + assignments cleared +
	// members' rejoin lands in main. ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("close-all: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	for _, b := range []openedBreakout{b1, b2} {
		if !rooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("close-all did not DeleteRoom %s; calls=%v", b.RoomName, rooms.calls)
		}
	}
	var member2BreakoutID *int64
	if err := pool.QueryRow(context.Background(),
		`SELECT breakout_id FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, member2Identity).Scan(&member2BreakoutID); err != nil {
		t.Fatalf("query member2 breakout_id: %v", err)
	}
	if member2BreakoutID != nil {
		t.Error("close-all must clear every assignment")
	}
	rr = meetDo(t, hOn, member2, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member2 rejoin after close-all: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var rejoin struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &rejoin); err != nil {
		t.Fatalf("decode member2 rejoin: %v", err)
	}
	rejoinVerifier, err := lkauth.ParseAPIToken(rejoin.Token)
	if err != nil {
		t.Fatalf("ParseAPIToken (member2 rejoin): %v", err)
	}
	if _, grants, err := rejoinVerifier.Verify(configuredCfg.APISecret); err != nil {
		t.Fatalf("Verify (member2 rejoin): %v", err)
	} else if grants.Video.Room != room {
		t.Errorf("post-close-all rejoin room = %q, want main %q", grants.Video.Room, room)
	}

	// ── 12. open again succeeds (F3 reopen — the partial-unique index
	// allows a second generation once the first is fully closed). ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("reopen after close-all (F3): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b3 := decodeOpenedBreakouts(t, rr)[0]

	// ── 13. end with breakouts open -> DeleteRoom parent AND every child
	// (law 1: ending drops everyone, every room). ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end with breakouts open: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !rooms.sawCall("DeleteRoom:" + room) {
		t.Errorf("end did not DeleteRoom the parent room; calls=%v", rooms.calls)
	}
	if !rooms.sawCall("DeleteRoom:" + b3.RoomName) {
		t.Errorf("end did not DeleteRoom the still-open child b3; calls=%v", rooms.calls)
	}

	// ── 14. a replayed child room_finished webhook after end is a no-op
	// (D12 — already closed by meeting_end's close-every-open-breakout arm;
	// a late/retried SFU delivery must not re-stamp closed_at). ──
	var closedAtBefore string
	if err := pool.QueryRow(context.Background(),
		`SELECT closed_at::text FROM meeting_breakouts WHERE id = $1`, b3.BreakoutID).Scan(&closedAtBefore); err != nil {
		t.Fatalf("resolve b3 closed_at: %v", err)
	}
	fireWebhook(&livekit.WebhookEvent{Event: "room_finished", Room: &livekit.Room{Name: b3.RoomName}})
	var closedAtAfter string
	if err := pool.QueryRow(context.Background(),
		`SELECT closed_at::text FROM meeting_breakouts WHERE id = $1`, b3.BreakoutID).Scan(&closedAtAfter); err != nil {
		t.Fatalf("resolve b3 closed_at after replay: %v", err)
	}
	if closedAtAfter != closedAtBefore {
		t.Errorf("replayed child room_finished after end moved closed_at: before=%s after=%s", closedAtBefore, closedAtAfter)
	}
}

// ── B3 Task 17: the captions tracer arc ─────────────────────────────────

// captionsPushBotIdentity returns the botIdentity carried by the LAST
// captions_state{on:<on>} push observed in _test_notify_log for userID's own
// meet:{userID} channel, or "" if none matched — a more precise probe than
// sawCaptionsPush (captions_test.go, which only checks the `on` bool) for an
// arc that starts/stops captions on MULTIPLE meetings for the same host: the
// botIdentity (cc:{meetingId}) disambiguates which meeting's push this is.
// Requires app.capture_notify='on' already set on this pool's one connection
// (meetSingleConnPool).
func captionsPushBotIdentity(t *testing.T, pool *pgxpool.Pool, userID int64, on bool) string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT payload FROM _test_notify_log WHERE channel = $1 ORDER BY seq`,
		fmt.Sprintf("meet:%d", userID))
	if err != nil {
		t.Fatalf("query _test_notify_log: %v", err)
	}
	defer rows.Close()
	var identity string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan _test_notify_log row: %v", err)
		}
		var env meetPushEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("decode _test_notify_log payload %q: %v", raw, err)
		}
		if env.Event != "captions_state" {
			continue
		}
		var p struct {
			On          bool   `json:"on"`
			BotIdentity string `json:"botIdentity"`
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			t.Fatalf("decode captions_state payload %q: %v", env.Payload, err)
		}
		if p.On == on {
			identity = p.BotIdentity // keep the LATEST match, in seq order
		}
	}
	return identity
}

// captionsCallCount counts EXACT occurrences of call in calls — plain
// sawCall (fake_captions_test.go) only proves "at least once", which is
// already trivially true partway through a multi-meeting arc that already
// called Stop on an earlier meeting's room; this proves a SPECIFIC step
// added exactly one more call.
func captionsCallCount(calls []string, call string) int {
	n := 0
	for _, c := range calls {
		if c == call {
			n++
		}
	}
	return n
}

// captionsOnDB reads meetings.settings->>'captionsOn' directly — the same
// projection captions_test.go's route tests use.
func captionsOnDB(t *testing.T, pool *pgxpool.Pool, meetingID int64) bool {
	t.Helper()
	var on bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
		meetingID).Scan(&on); err != nil {
		t.Fatalf("query captionsOn for meeting %d: %v", meetingID, err)
	}
	return on
}

// TestCaptionsTracerArc is Task 17's B3b integration proof: ONE continuous
// arc over the real captions routes + meeting_captions_set/meeting_get/
// meeting_join_request_poll reducers + fakeCaptions (the TestFullMeetingArc/
// TestBreakoutTracerArc genre, grown for captions). It composes pieces Tasks
// 12-15 already unit-proved in the realistic order a real captioned meeting
// goes through: start (fact precedes the sidecar call) -> the push carries
// the attested cc:{meetingId} botIdentity -> a member's join envelope
// carries captionsConfigured + the meeting's captionsOn -> a guest's
// knock/admit while captions are on SUCCEEDS (DN3 — no BZ199 analogue) and
// the admitted poll envelope carries captionsOn -> busy on a SECOND meeting
// -> 503 captionsBusy + the rollback push -> explicit off -> Stop recorded
// -> a THIRD meeting ends with captions still on (DeleteRoom evicts the bot
// with everyone else, no Stop call from the end route itself — law 1's free
// ride; the worker's orphan leg then Stops the still-reported session) ->
// D11-drain (a FOURTH meeting, toggle flipped off via a fresh handler
// instance — the captions_test.go TestCaptionsToggleGates precedent, since
// h.flags is a static per-Handler snapshot, not a live DB read): DELETE
// still stops, the reconcile still converges regardless of the toggle,
// START now 404s -> reconcile leg (a) on a FIFTH meeting: flag on, bot
// silent (empty Status), stale captionsSince -> flag flips off + push (the
// chip never lies).
func TestCaptionsTracerArc(t *testing.T) {
	dsn := meetDSN(t)
	// A single-connection pool so app.capture_notify='on' (session-scoped
	// GUC) sticks for the whole arc (the TestBreakoutTracerArc precedent) —
	// needed to observe every captions_state push below.
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}
	rooms := newFakeRooms()
	captions := newFakeCaptions()
	hOn := meetHandlerWithCaptions(pool, rooms, captions, true)
	ph := meetPublicHandler(pool, true, true)

	host := meetTestUser(t, pool, "capstracer-host")
	member := meetTestUser(t, pool, "capstracer-member")

	// ── 1. meeting A: create -> start captions -> the fact (captionsOn=true
	// in the DB) precedes the sidecar Start call. ──
	meetingA := createTestMeeting(t, hOn, host, "Captions tracer meeting A")
	roomA := roomNameFor(t, pool, meetingA)

	var sawOnMidStartA bool
	captions.startHook = func() { sawOnMidStartA = captionsOnDB(t, pool, meetingA) }
	rr := meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingA), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start captions on A: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !sawOnMidStartA {
		t.Error("captionsOn must already be true in the DB when captions.Start is called (the chip is server state ahead of the first transcript frame)")
	}
	if !captions.sawCall("Start:" + roomA) {
		t.Errorf("captions did not see the expected Start call for room %s; calls=%v", roomA, captions.calls)
	}

	// ── 2. the push carries the attested cc:{meetingId} botIdentity. ──
	if want, got := fmt.Sprintf("cc:%d", meetingA), captionsPushBotIdentity(t, pool, host, true); got != want {
		t.Errorf("captions_state{on:true} push botIdentity = %q, want %q", got, want)
	}

	// ── 3. a member's join envelope carries captionsConfigured=true (an ASR
	// sidecar IS configured on this handler) + the meeting's own
	// captionsOn=true (meeting_get's live-flag projection, read fresh at
	// join time, not cached from step 1). ──
	rr = meetDo(t, hOn, member, "POST", fmt.Sprintf("/meet/%d/join", meetingA), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member join on A: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var joinOut struct {
		CaptionsConfigured bool `json:"captionsConfigured"`
		Meeting            struct {
			CaptionsOn bool `json:"captionsOn"`
		} `json:"meeting"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &joinOut); err != nil {
		t.Fatalf("decode member join response: %v", err)
	}
	if !joinOut.CaptionsConfigured {
		t.Error("member join envelope captionsConfigured = false, want true (h.captions is non-nil)")
	}
	if !joinOut.Meeting.CaptionsOn {
		t.Error("member join envelope meeting.captionsOn = false, want true (captions are live on A)")
	}

	// ── 4. guest knock/admit while captions are on SUCCEEDS (DN3 — no BZ199
	// analogue: captions retain no content anywhere, so the guest⇄recording
	// exclusion invariant does not extend to them) and the admitted poll
	// envelope carries captionsOn=true. ──
	setGuestAllowed(t, hOn, host, meetingA)
	slugA := meetingSlug(t, pool, meetingA)
	rr = publicDo(t, ph, "POST", "/public/meet/"+slugA+"/join-request",
		map[string]string{"slug": slugA}, `{"displayName":"Captions Tracer Guest"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("guest join-request on captioned meeting: want 201 (DN3, no BZ199 analogue), got %d: %s", rr.Code, rr.Body.String())
	}
	guest := decodeCreateResp(t, rr)
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingA, guest.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit guest on captioned meeting: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = publicDo(t, ph, "GET",
		fmt.Sprintf("/public/meet/%s/join-request/%d", slugA, guest.RequestID),
		map[string]string{"slug": slugA, "id": strconv.FormatInt(guest.RequestID, 10)}, "",
		secretHeader(guest.Secret))
	if rr.Code != http.StatusOK {
		t.Fatalf("guest poll after admit: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	guestPoll := decodePollResp(t, rr)
	if guestPoll.State != "admitted" || guestPoll.Token == "" {
		t.Fatalf("guest poll after admit = %+v, want admitted+token", guestPoll)
	}
	if !guestPoll.CaptionsOn {
		t.Error("admitted guest poll envelope captionsOn = false, want true (DN3 — the captions indicator is guest-visible too)")
	}

	// ── 5. meeting B: busy on a SECOND meeting -> 503 captionsBusy + the
	// chip is rolled back (never claims a session that never started) + the
	// rollback push carries B's own botIdentity. ──
	meetingB := createTestMeeting(t, hOn, host, "Captions tracer meeting B")
	roomB := roomNameFor(t, pool, meetingB)
	captions.startErrs[roomB] = errCaptionsBusy

	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingB), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("start captions on B (busy): want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "captionsBusy" {
		t.Errorf("problem code = %q, want captionsBusy", code)
	}
	if captionsOnDB(t, pool, meetingB) {
		t.Error("captionsOn for B must be rolled back to false after a busy Start")
	}
	if want, got := fmt.Sprintf("cc:%d", meetingB), captionsPushBotIdentity(t, pool, host, false); got != want {
		t.Errorf("busy-rollback captions_state{on:false} push botIdentity = %q, want %q", got, want)
	}

	// ── 6. explicit off on A -> Stop recorded. ──
	rr = meetDo(t, hOn, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingA), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("explicit stop on A: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !captions.sawCall("Stop:" + roomA) {
		t.Errorf("explicit stop did not call captions.Stop for room %s; calls=%v", roomA, captions.calls)
	}

	// ── 7. restart captions on A, then end the meeting WITH captions still
	// on: DeleteRoom evicts the bot along with everyone else (the bot
	// occupies the SAME room as the meeting) — the end route itself makes NO
	// additional captions.Stop call (law 1's free ride: eviction, not a
	// second teardown instruction). The worker's orphan leg then Stops the
	// still-reported session once the (simulated) ASR sidecar catches up. ──
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingA), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("restart captions on A: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	stopCountBeforeEnd := captionsCallCount(captions.calls, "Stop:"+roomA)

	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/end", meetingA), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end A with captions on: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !rooms.sawCall("DeleteRoom:" + roomA) {
		t.Errorf("end did not evict via DeleteRoom; calls=%v", rooms.calls)
	}
	if got := captionsCallCount(captions.calls, "Stop:"+roomA); got != stopCountBeforeEnd {
		t.Errorf("end route made an extra captions.Stop call for A (want none — DeleteRoom is the free ride): before=%d after=%d", stopCountBeforeEnd, got)
	}

	w := meetWorkerCaptions(pool, true, configuredCfg, rooms, captions)
	captions.setSessions([]string{roomA}) // the ASR sidecar hasn't detected the teardown yet
	w.tick(context.Background())
	if got := captionsCallCount(captions.calls, "Stop:"+roomA); got != stopCountBeforeEnd+1 {
		t.Errorf("worker orphan leg did not retry exactly one more Stop for the ended meeting's still-reported room: before=%d after=%d", stopCountBeforeEnd, got)
	}

	// ── 8. meeting C: D11-drain — flip feature.meet_captions OFF (a fresh
	// Handler instance sharing the SAME pool/rooms/captions doubles, the
	// captions_test.go TestCaptionsToggleGates precedent: h.flags is a
	// static per-Handler snapshot, not a live DB read). DELETE still stops
	// (draining committed state is never gated); START now 404s; the
	// reconcile arm converges identically regardless of the toggle (it never
	// reads feature.meet_captions at all — proven here by retrying Stop for
	// a session the sidecar still reports even after the toggle flip). ──
	meetingC := createTestMeeting(t, hOn, host, "Captions tracer meeting C")
	roomC := roomNameFor(t, pool, meetingC)
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingC), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start captions on C: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	hOff := meetHandlerWithCaptions(pool, rooms, captions, false)
	rr = meetDo(t, hOff, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingC), "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("start on C with toggle OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = meetDo(t, hOff, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingC), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stop on C with toggle OFF (D11 drain): want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !captions.sawCall("Stop:" + roomC) {
		t.Errorf("D11-drain stop did not call captions.Stop for room %s; calls=%v", roomC, captions.calls)
	}
	if captionsOnDB(t, pool, meetingC) {
		t.Error("captionsOn for C must read false after the D11-drain stop")
	}

	stopCountCBeforeTick := captionsCallCount(captions.calls, "Stop:"+roomC)
	captions.setSessions([]string{roomC}) // the sidecar still reports it live, toggle state notwithstanding
	w.tick(context.Background())
	if got := captionsCallCount(captions.calls, "Stop:"+roomC); got != stopCountCBeforeTick+1 {
		t.Errorf("reconcile did not converge C's still-reported session with the toggle OFF: before=%d after=%d", stopCountCBeforeTick, got)
	}

	// ── 9. meeting D: reconcile leg (a) — flag on, bot silent (Status()
	// reports nothing at all), STALE captionsSince -> flag flips off + push
	// (the chip never lies about a session the sidecar no longer has). ──
	meetingD := createTestMeeting(t, hOn, host, "Captions tracer meeting D")
	rr = meetDo(t, hOn, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingD), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start captions on D: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET settings = jsonb_set(settings, '{captionsSince}', to_jsonb(now() - interval '2 hours')) WHERE id = $1`,
		meetingD); err != nil {
		t.Fatalf("backdate captionsSince for D: %v", err)
	}

	captions.setSessions(nil) // the bot is silent — Status() reports no sessions at all
	w.tick(context.Background())

	if captionsOnDB(t, pool, meetingD) {
		t.Error("captionsOn for D must be flipped false by the worker's crashed-session leg (stale captionsSince, bot silent in Status())")
	}
	if want, got := fmt.Sprintf("cc:%d", meetingD), captionsPushBotIdentity(t, pool, host, false); got != want {
		t.Errorf("crashed-session captions_state{on:false} push botIdentity = %q, want %q", got, want)
	}
}
