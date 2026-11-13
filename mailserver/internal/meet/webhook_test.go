// webhook_test.go — Task 12: DB-gated tests for POST /meet/webhook, over
// the real meeting_participant_event reducer on mailserver_test2 (the
// tracer_integration_test.go DB_DSN precedent). Every request here is
// signed exactly the way LiveKit's own URLNotifier signs a real webhook
// delivery (protocol/webhook/url_notifier.go's send: protojson-marshal the
// event, sha256+base64 the encoded bytes, sign an AccessToken carrying that
// hash as its Sha256 claim) — the SAME verification path
// webhook.ReceiveWebhookEvent runs on the receiving side, so this proves
// the real wire contract, not a mocked one.
package meet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	lkauth "github.com/livekit/protocol/auth"
	"github.com/livekit/protocol/livekit"
	"github.com/livekit/protocol/utils/protojson"

	"github.com/jackc/pgx/v5/pgxpool"
)

// signWebhookRequest builds a POST /meet/webhook request signed the way a
// real LiveKit sidecar signs one. tamper mutates the body AFTER signing —
// exercising the checksum-mismatch rejection path, not a bad-secret path
// (livekit_test.go's TestMintTokenBadSecretFails already covers a wrong
// secret; a tampered body proves the sha256-of-body claim is actually
// checked, a distinct failure mode).
func signWebhookRequest(t *testing.T, cfg Config, event *livekit.WebhookEvent, tamper bool) *http.Request {
	t.Helper()
	encoded, err := protojson.Marshal(event)
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}
	sum := sha256.Sum256(encoded)
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	token, err := lkauth.NewAccessToken(cfg.APIKey, cfg.APISecret).
		SetValidFor(5 * time.Minute).
		SetSha256(b64).
		ToJWT()
	if err != nil {
		t.Fatalf("ToJWT: %v", err)
	}

	body := encoded
	if tamper {
		body = append(append([]byte{}, encoded...), '!') // mutated post-signing → checksum mismatch
	}
	r := httptest.NewRequest(http.MethodPost, "/meet/webhook", bytes.NewReader(body))
	r.Header.Set("Authorization", token)
	return r
}

func participantJoinedAt(t *testing.T, pool *pgxpool.Pool, meetingID int64, identity string) (joined, left *time.Time) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT joined_at, left_at FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, identity).Scan(&joined, &left)
	if err != nil {
		t.Fatalf("resolve participant: %v", err)
	}
	return joined, left
}

// TestWebhookParticipantJoinedStampsAttendance proves the happy path end to
// end over the real handler + real reducer: a correctly signed
// participant_joined event stamps joined_at on the matching row.
func TestWebhookParticipantJoinedStampsAttendance(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "webhookjoinhost")
	meetingID := createTestMeeting(t, h, host, "Webhook joined test")
	room := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", host)

	joined, _ := participantJoinedAt(t, pool, meetingID, identity)
	if joined != nil {
		t.Fatalf("precondition: joined_at already set before any webhook")
	}

	event := &livekit.WebhookEvent{
		Event:       "participant_joined",
		Room:        &livekit.Room{Name: room},
		Participant: &livekit.ParticipantInfo{Identity: identity},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("webhook: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	joined, _ = participantJoinedAt(t, pool, meetingID, identity)
	if joined == nil {
		t.Error("joined_at not stamped after a signed participant_joined webhook")
	}
}

// TestWebhookTamperedBodyRejected proves the checksum-mismatch rejection is
// real: a body that no longer matches the sha256 claim the signature covers
// is refused with 401, and — critically — no reducer call happens at all
// (the DB stays exactly as it was).
func TestWebhookTamperedBodyRejected(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "webhooktamperhost")
	meetingID := createTestMeeting(t, h, host, "Webhook tamper test")
	room := roomNameFor(t, pool, meetingID)
	identity := fmt.Sprintf("u:%d", host)

	event := &livekit.WebhookEvent{
		Event:       "participant_joined",
		Room:        &livekit.Room{Name: room},
		Participant: &livekit.ParticipantInfo{Identity: identity},
	}
	req := signWebhookRequest(t, configuredCfg, event, true)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("tampered webhook: want 401, got %d: %s", rr.Code, rr.Body.String())
	}

	joined, _ := participantJoinedAt(t, pool, meetingID, identity)
	if joined != nil {
		t.Error("joined_at was stamped from a tampered (unverified) webhook body — authorization leaked through a fact channel")
	}
}

// TestWebhookUnrecognizedEventIgnored proves an event name outside both
// webhookEvents and egressEvents (anything else the SFU ever adds, e.g.
// track_published) is a harmless 200 — never a rejection, since a webhook
// body is untrusted, unversioned input and refusing it would just make
// LiveKit retry forever.
func TestWebhookUnrecognizedEventIgnored(t *testing.T) {
	h := meetHandler(nil, newFakeRooms())
	event := &livekit.WebhookEvent{Event: "track_published"}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unrecognized event: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestWebhookNonUUIDRoomIgnored proves the eng #10 UUID defensiveness: a
// signed, recognized event whose room name is not a UUID (and therefore
// cannot be one of ours — every meet room_name is a gen_random_uuid()
// default) is silently ignored, never passed to
// meeting_participant_event — a cast exception there would 500 a retried
// webhook, the exact failure this guard exists to prevent.
func TestWebhookNonUUIDRoomIgnored(t *testing.T) {
	h := meetHandler(nil, newFakeRooms())
	event := &livekit.WebhookEvent{
		Event: "participant_joined",
		Room:  &livekit.Room{Name: "not-a-uuid"},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("non-UUID room: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ── B2 Task 6: egress_* webhook facts → meeting_recording_event ────────────
//
// egress_* webhooks are facts, never authorization (law 2, D-1): every case
// below either 200s-and-no-ops or forwards to meeting_recording_event,
// which itself never raises. staging_key is never read from the payload —
// only size/duration are trusted from it (spec §4) — so these tests assert
// state + size/duration + the ONE 'stopped' push meeting_recording_event
// fires on a real EGRESS_COMPLETE, never assert anything about staging_key.

// meetSingleConnPool opens a pgxpool limited to 1 connection so that
// SET app.capture_notify='on' (session-scoped GUC) sticks for every query
// driven through it — the admin_ca_guard_test.go D8 genre, needed here to
// observe the recording_state/'stopped' push egress_ended fires.
func meetSingleConnPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// sawRecordingPush reports whether _test_notify_log gained a meet:{userID}
// row whose decoded payload carries the given event/state — requires
// app.capture_notify='on' already set on this pool's one connection
// (meetSingleConnPool).
func sawRecordingPush(t *testing.T, pool *pgxpool.Pool, userID int64, event, state string) bool {
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
				State string `json:"state"`
			} `json:"payload"`
		}
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			t.Fatalf("decode _test_notify_log payload %q: %v", raw, err)
		}
		if decoded.Event == event && decoded.Payload.State == state {
			return true
		}
	}
	return false
}

// startBoundRecording drives the real POST /meet/{id}/recording route
// (Task 5) to seed a live recording row actually bound to an egress id +
// room — meeting_recording_event only acts on a row it can resolve by
// (egress_id, room_name), so this is the fixture every happy-path Task 6
// test needs.
func startBoundRecording(t *testing.T, pool *pgxpool.Pool, host, meetingID int64) (recordingID int64, egressID, room string) {
	t.Helper()
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start recording: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response %q: %v", rr.Body.String(), err)
	}
	room = roomNameFor(t, pool, meetingID)
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id FROM meeting_recordings WHERE id = $1`, out.RecordingID).Scan(&egressID); err != nil {
		t.Fatalf("query egress_id: %v", err)
	}
	return out.RecordingID, egressID, room
}

func recordingState(t *testing.T, pool *pgxpool.Pool, recordingID int64) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_recordings WHERE id = $1`, recordingID).Scan(&state); err != nil {
		t.Fatalf("query recording state: %v", err)
	}
	return state
}

// TestWebhookEgressEndedCompleteMarksPendingIngest pins the happy path end
// to end: a signed egress_ended webhook carrying EGRESS_COMPLETE + a
// FileResults entry lands the bound row in pending_ingest with size/duration
// decoded from the protojson payload (int64 duration in ns → ms), and fires
// the ONE 'stopped' banner-off push (D-1 — meeting_recording_event's own
// comment names this the sole place that push happens).
func TestWebhookEgressEndedCompleteMarksPendingIngest(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}

	host := meetTestUser(t, pool, "webhookegresshost")
	hSetup := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	meetingID := createTestMeeting(t, hSetup, host, "Egress ended test")
	startMeetingLive(t, pool, meetingID)
	recID, egressID, room := startBoundRecording(t, pool, host, meetingID)

	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	event := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID,
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{
				Size:     123456,
				Duration: 5_000_000_000, // 5s in ns → 5000ms
			}},
		},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("egress_ended: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var state string
	var sizeBytes, durationMS int64
	var stoppedAt *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT state, size_bytes, duration_ms, stopped_at FROM meeting_recordings WHERE id = $1`,
		recID).Scan(&state, &sizeBytes, &durationMS, &stoppedAt); err != nil {
		t.Fatalf("query recording row: %v", err)
	}
	if state != "pending_ingest" {
		t.Errorf("state = %q, want pending_ingest", state)
	}
	if sizeBytes != 123456 {
		t.Errorf("size_bytes = %d, want 123456", sizeBytes)
	}
	if durationMS != 5000 {
		t.Errorf("duration_ms = %d, want 5000", durationMS)
	}
	if stoppedAt == nil {
		t.Error("stopped_at not stamped")
	}
	if !sawRecordingPush(t, pool, host, "recording_state", "stopped") {
		t.Error("no recording_state/'stopped' push observed after egress_ended EGRESS_COMPLETE — D-1's ONE push site")
	}
}

// TestWebhookEgressEndedReplayNoop proves the fact rail is idempotent: a
// byte-identical replay of an already-processed egress_ended event is a
// silent 200 that changes nothing (law 2).
func TestWebhookEgressEndedReplayNoop(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	host := meetTestUser(t, pool, "webhookreplayhost")
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	meetingID := createTestMeeting(t, h, host, "Egress replay test")
	startMeetingLive(t, pool, meetingID)
	recID, egressID, room := startBoundRecording(t, pool, host, meetingID)

	event := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID,
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{
				Size:     42,
				Duration: 1_000_000_000,
			}},
		},
	}

	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first egress_ended: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	stateAfterFirst := recordingState(t, pool, recID)
	if stateAfterFirst != "pending_ingest" {
		t.Fatalf("precondition: state after first delivery = %q, want pending_ingest", stateAfterFirst)
	}

	// Byte-identical replay (fresh signed request over the same event body).
	req = signWebhookRequest(t, configuredCfg, event, false)
	rr = httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("replayed egress_ended: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := recordingState(t, pool, recID); got != stateAfterFirst {
		t.Errorf("replay changed state: got %q, want unchanged %q", got, stateAfterFirst)
	}
}

// TestWebhookEgressStartedOutOfOrderAfterEndedNoop proves an out-of-order
// egress_started delivered AFTER egress_ended already settled the row is a
// silent no-op — meeting_recording_event's own settled-state guard
// (state IN ('pending_ingest','ready','failed') → RETURN), never resurrects
// a terminal recording.
func TestWebhookEgressStartedOutOfOrderAfterEndedNoop(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	host := meetTestUser(t, pool, "webhookoutoforderhost")
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	meetingID := createTestMeeting(t, h, host, "Egress out-of-order test")
	startMeetingLive(t, pool, meetingID)
	recID, egressID, room := startBoundRecording(t, pool, host, meetingID)

	endedEvent := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID,
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{
				Size:     1,
				Duration: 1,
			}},
		},
	}
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, signWebhookRequest(t, configuredCfg, endedEvent, false))
	if rr.Code != http.StatusOK {
		t.Fatalf("egress_ended: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	settledState := recordingState(t, pool, recID)
	if settledState != "pending_ingest" {
		t.Fatalf("precondition: state after ended = %q, want pending_ingest", settledState)
	}

	startedEvent := &livekit.WebhookEvent{
		Event: "egress_started",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID,
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_ACTIVE,
		},
	}
	rr = httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, signWebhookRequest(t, configuredCfg, startedEvent, false))
	if rr.Code != http.StatusOK {
		t.Fatalf("out-of-order egress_started: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := recordingState(t, pool, recID); got != settledState {
		t.Errorf("out-of-order egress_started changed state: got %q, want unchanged %q", got, settledState)
	}
}

// TestWebhookEgressUnknownIDIgnored proves an egress event that resolves no
// (egress_id, room_name) row — a pre-bind race, or plain webhook noise — is
// a silent 200, never a fault; meeting_recording_event's own NOT FOUND
// branch RETURNs, and the reconcile sweep self-heals anything real.
func TestWebhookEgressUnknownIDIgnored(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	host := meetTestUser(t, pool, "webhookunknownegresshost")
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	meetingID := createTestMeeting(t, h, host, "Unknown egress id test")
	room := roomNameFor(t, pool, meetingID)

	event := &livekit.WebhookEvent{
		Event: "egress_started",
		EgressInfo: &livekit.EgressInfo{
			EgressId: "EG_does_not_exist",
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_ACTIVE,
		},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown egress id: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestWebhookEgressEventWithoutInfoIgnored proves a signed, recognized
// egress_* event carrying no EgressInfo at all (a stripped/malformed
// delivery) is a silent 200, never a reducer call — mirrors
// TestWebhookNonUUIDRoomIgnored's shape-defensiveness posture for the
// egress rail.
func TestWebhookEgressEventWithoutInfoIgnored(t *testing.T) {
	h := meetHandler(nil, newFakeRooms())
	event := &livekit.WebhookEvent{Event: "egress_started"}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("egress event without EgressInfo: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestWebhookEgressEventNonUUIDRoomIgnored is TestWebhookNonUUIDRoomIgnored
// for the egress rail: a signed, recognized egress event whose
// EgressInfo.RoomName is not a UUID is silently ignored, never passed to
// meeting_recording_event (the eng #10 UUID defensiveness, verbatim on this
// rail too).
func TestWebhookEgressEventNonUUIDRoomIgnored(t *testing.T) {
	h := meetHandler(nil, newFakeRooms())
	event := &livekit.WebhookEvent{
		Event: "egress_started",
		EgressInfo: &livekit.EgressInfo{
			EgressId: "EG_whatever",
			RoomName: "not-a-uuid",
			Status:   livekit.EgressStatus_EGRESS_ACTIVE,
		},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("non-UUID egress room: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestWebhookEgressTamperedBodyRejected is TestWebhookTamperedBodyRejected
// for the egress rail: a checksum-mismatched egress_ended body is refused
// with 401 before the egressEvents dispatch ever runs (signature
// verification is shared, unconditional first-line code for every event
// name — this pins that the egress branch doesn't bypass it).
func TestWebhookEgressTamperedBodyRejected(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	host := meetTestUser(t, pool, "webhookegresstamperhost")
	h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
	meetingID := createTestMeeting(t, h, host, "Egress tamper test")
	startMeetingLive(t, pool, meetingID)
	recID, egressID, room := startBoundRecording(t, pool, host, meetingID)

	event := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID,
			RoomName: room,
			Status:   livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{
				Size:     999,
				Duration: 999,
			}},
		},
	}
	req := signWebhookRequest(t, configuredCfg, event, true)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("tampered egress webhook: want 401, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := recordingState(t, pool, recID); got != "active" {
		t.Errorf("tampered (unverified) egress webhook mutated state: got %q, want unchanged active", got)
	}
}

// TestWebhookEgressEventDBFaultReturns500 proves a genuine DB fault on the
// egress rail — not a shape problem with the webhook body itself — 500s so
// LiveKit's own retry redelivers it, mirroring handleWebhook's
// participant/room arm.
func TestWebhookEgressEventDBFaultReturns500(t *testing.T) {
	dsn := meetDSN(t)
	closedPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	closedPool.Close()

	h := meetHandler(closedPool, newFakeRooms())
	event := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: "EG_whatever",
			RoomName: "00000000-0000-0000-0000-000000000000",
			Status:   livekit.EgressStatus_EGRESS_COMPLETE,
		},
	}
	req := signWebhookRequest(t, configuredCfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("DB fault: want 500, got %d: %s", rr.Code, rr.Body.String())
	}
}
