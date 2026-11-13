// recording_integration_test.go — Meet B2 Task 11: the three integration
// proofs this task owns (spec §10.1-§10.3).
//
//  1. TestEveryRecordingStopPathStopsEgress — the TestEveryRevokePathEvicts
//     genre (meetings_test.go), generalized to every path out of 'active'
//     the plan's §3.1 law 1 enumeration names: explicit stop, meeting_end
//     (with cross-controller ORDERING — StopEgress before DeleteRoom), the
//     room_finished webhook's same-txn flip + the worker's follow-up retry,
//     all four §6.4 wedge states (stale-requested, stopping-still-active,
//     absent-from-ListEgress x2, the wedge-4 unbound-stopping belt), the
//     law-1 belt (an SFU-active egress whose registry row is terminal), and
//     the wedge-4 origin fix (an unbound requested row surviving
//     meeting_end/room_finished as a TERMINAL state, never 'stopping' —
//     plan delta 11 / eng E-F2). A nonRevokePaths case pins that lock/
//     settings/role never touch the EgressController at all.
//  2. TestConcurrentGuestAdmitVsRecordingStart — the chat-A1/A4b two-conn
//     genre (internal/chat/tracer_integration_test.go's
//     TestConcurrentLateCommitterReplay, internal/chat/
//     oversight_integration_test.go's real-pgx-conn interleaving): BOTH
//     orderings of the §8.2 FOR UPDATE race, explicitly NOT commit-then-
//     check — a goroutine on the second connection must still be blocked
//     100ms after the first connection's reducer call returns (uncommitted),
//     then unblock and raise BZ199 once the first connection commits.
//  3. TestRecordingIngestRoundTripLarge — a 105 MiB (deliberately over the
//     chat upload_max_bytes 100 MiB cap — spec §10.3, so an accidental
//     re-clone of that cap fails loudly at BZ148) deterministic staging
//     object through the REAL ingest pipeline (meetStubS3: an httptest TLS
//     server + a real *minio.Client, the admin_chat_ediscovery_export_test.
//     go edStubS3 genre extended with PUT/HEAD/DELETE/COPY), asserting
//     byte-identical SHA-256 end to end, the no-cap meeting-space proof, and
//     the wire-level access plane (host/attendee 200, admitted-never-joined
//     member/non-participant 404, invisible in the member's /drive space
//     list) plus a genuinely-idempotent re-ingest via the fakeStagingStore
//     ingestFaultBeforeFinalize genre (Task 7's worker_test.go).
//  4. TestRecordingTracerArc — the TestFullMeetingArc composition genre
//     (tracer_integration_test.go) extended with the recording surface:
//     banner-precedes-frames, the late-joiner recordingActive signal, guest
//     admit blocked/unblocked around a stop, recordings[]/attendance[]
//     post-end gating (§B2 at the wire), the distinguishable egressBusy
//     surface, and the D11 drain (a committed recording keeps draining with
//     feature.meet_recording OFF; only the start route 404s).
package meet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/livekit/protocol/livekit"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/twitchtv/twirp"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// ── shared test helpers ─────────────────────────────────────────────────

// insertGuestJoinRequest seeds a pending GUEST join request directly (the
// meet_control.pg/meet_recording.pg fixture genre) — user_id NULL is the
// admission-fact predicate meeting_admit's §8.2 arm 2 keys on.
func insertGuestJoinRequest(t *testing.T, pool *pgxpool.Pool, meetingID int64, displayName string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO meeting_join_requests (meeting_id, display_name) VALUES ($1, $2) RETURNING id`,
		meetingID, displayName).Scan(&id); err != nil {
		t.Fatalf("insert guest join request: %v", err)
	}
	return id
}

// stampParticipantJoined fires a real signed participant_joined webhook for
// identity — the webhook_test.go TestWebhookParticipantJoinedStampsAttendance
// genre, reused wherever a test needs an attendee's joined_at actually
// stamped (meeting_attendee_role's member leg requires it; the HTTP join
// route deliberately never touches it — see meeting_join.sql's own comment).
func stampParticipantJoined(t *testing.T, h *Handler, cfg Config, room, identity string) {
	t.Helper()
	event := &livekit.WebhookEvent{
		Event:       "participant_joined",
		Room:        &livekit.Room{Name: room},
		Participant: &livekit.ParticipantInfo{Identity: identity},
	}
	req := signWebhookRequest(t, cfg, event, false)
	rr := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("participant_joined webhook: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// sharedCallLog is a cross-controller ordering recorder: fakeRooms and
// fakeEgress each keep their OWN independent .calls slice (fine for
// sawCall, useless for proving one controller's call preceded the other's).
// TestEveryRecordingStopPathStopsEgress's meeting_end case needs exactly
// that cross-controller ordering (law 1: StopEgress before DeleteRoom), so
// loggedRooms/loggedEgress below decorate the real fakes and additionally
// append into ONE ordered log.
type sharedCallLog struct {
	mu    sync.Mutex
	calls []string
}

func (s *sharedCallLog) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *sharedCallLog) indexOf(call string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, c := range s.calls {
		if c == call {
			return i
		}
	}
	return -1
}

type loggedRooms struct {
	*fakeRooms
	log *sharedCallLog
}

func (r loggedRooms) DeleteRoom(ctx context.Context, room string) error {
	err := r.fakeRooms.DeleteRoom(ctx, room)
	r.log.record("DeleteRoom:" + room)
	return err
}

type loggedEgress struct {
	*fakeEgress
	log *sharedCallLog
}

func (e loggedEgress) StopEgress(ctx context.Context, egressID string) error {
	err := e.fakeEgress.StopEgress(ctx, egressID)
	e.log.record("StopEgress:" + egressID)
	return err
}

var (
	_ RoomController   = loggedRooms{}
	_ EgressController = loggedEgress{}
)

// meetStubS3 stands up an httptest TLS server implementing enough of the S3
// wire protocol for minio-go's GET/HEAD/PUT/DELETE/COPY surface — the
// admin_chat_ediscovery_export_test.go edStubS3 genre (GET-only), extended
// per the plan for the full ingest round trip: drive.PromoteChunk's
// tmp-PUT -> COPY-promote -> tmp-DELETE, plus the worker's own staging
// GetObject/RemoveObject.
//
// TLS + Secure:true is deliberate, not incidental: minio-go's default wire
// format for a PUT over an INSECURE (plain HTTP) connection is streaming
// SigV4 (aws-chunked, each chunk individually signed) — see api.go's
// `case metadata.streamSha256 && !c.secure`. This stub does not decode that
// framing. Secure:true takes the `default:` branch instead (a plain SignV4
// header with X-Amz-Content-Sha256: UNSIGNED-PAYLOAD), so the request body
// on the wire is exactly the caller's bytes — httptest.Server.Client()'s
// pre-trusted transport lets minio-go dial the self-signed cert cleanly.
func meetStubS3(t *testing.T) (mc *minio.Client, bucket string, put func(key string, data []byte), objects func() map[string][]byte) {
	t.Helper()
	bucket = "meet-egress-bucket"
	var mu sync.Mutex
	store := map[string][]byte{}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			mu.Lock()
			data, ok := store[key]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				if r.Method == http.MethodGet {
					fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, key)
				}
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(data)))
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("ETag", `"stub"`)
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				w.Write(data) //nolint:errcheck
			}
		case http.MethodPut:
			if src := r.Header.Get("X-Amz-Copy-Source"); src != "" {
				decoded, _ := url.QueryUnescape(strings.TrimPrefix(src, "/"))
				srcKey := strings.TrimPrefix(decoded, bucket+"/")
				mu.Lock()
				data, ok := store[srcKey]
				if ok {
					store[key] = append([]byte(nil), data...)
				}
				mu.Unlock()
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					fmt.Fprintf(w, `<Error><Code>NoSuchKey</Code><Key>%s</Key></Error>`, srcKey)
					return
				}
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `<CopyObjectResult><ETag>"1"</ETag><LastModified>%s</LastModified></CopyObjectResult>`,
					time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
				return
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			store[key] = body
			mu.Unlock()
			w.Header().Set("ETag", `"1"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			mu.Lock()
			delete(store, key)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(ts.Close)

	host := strings.TrimPrefix(ts.URL, "https://")
	var err error
	mc, err = minio.New(host, &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: true, Region: "us-east-1",
		Transport: ts.Client().Transport,
	})
	if err != nil {
		t.Fatalf("minio.New: %v", err)
	}
	put = func(key string, data []byte) {
		mu.Lock()
		store[key] = append([]byte(nil), data...)
		mu.Unlock()
	}
	objects = func() map[string][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string][]byte, len(store))
		for k, v := range store {
			out[k] = v
		}
		return out
	}
	return mc, bucket, put, objects
}

// ── 1. the machine-checked stop-path enumeration (spec §10.1) ──────────────

// TestEveryRecordingStopPathStopsEgress is the TestEveryRevokePathEvicts
// genre generalized to recording: a future stop path added without wiring
// an Egress call (or without converging to a terminal state) fails one of
// these sub-tests by omission.
func TestEveryRecordingStopPathStopsEgress(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	t.Run("explicit stop", func(t *testing.T) {
		egress := newFakeEgress()
		h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)
		host := meetTestUser(t, pool, "stopcase1host")
		meetingID := createTestMeeting(t, h, host, "Stop case 1")
		startMeetingLive(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var out startRecordingOut
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode start: %v", err)
		}
		var egressID string
		if err := pool.QueryRow(context.Background(),
			`SELECT egress_id FROM meeting_recordings WHERE id = $1`, out.RecordingID).Scan(&egressID); err != nil {
			t.Fatalf("query egress_id: %v", err)
		}

		rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("stop: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		if !egress.sawCall("StopEgress:" + egressID) {
			t.Errorf("explicit stop did not call StopEgress; calls=%v", egress.calls)
		}
	})

	t.Run("meeting_end orders StopEgress before DeleteRoom", func(t *testing.T) {
		log := &sharedCallLog{}
		rooms := loggedRooms{fakeRooms: newFakeRooms(), log: log}
		egress := loggedEgress{fakeEgress: newFakeEgress(), log: log}
		h := meetHandlerWithEgress(pool, rooms, egress, true, true)
		host := meetTestUser(t, pool, "stopcase2host")
		meetingID := createTestMeeting(t, h, host, "Stop case 2")
		startMeetingLive(t, pool, meetingID)
		room := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var out startRecordingOut
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode start: %v", err)
		}
		var egressID string
		if err := pool.QueryRow(context.Background(),
			`SELECT egress_id FROM meeting_recordings WHERE id = $1`, out.RecordingID).Scan(&egressID); err != nil {
			t.Fatalf("query egress_id: %v", err)
		}

		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		stopIdx := log.indexOf("StopEgress:" + egressID)
		deleteIdx := log.indexOf("DeleteRoom:" + room)
		if stopIdx < 0 || deleteIdx < 0 {
			t.Fatalf("missing calls in the shared log: %v", log.calls)
		}
		if stopIdx >= deleteIdx {
			t.Errorf("StopEgress (idx %d) did not precede DeleteRoom (idx %d): %v", stopIdx, deleteIdx, log.calls)
		}
		if got := recordingState(t, pool, out.RecordingID); got != "stopping" {
			t.Errorf("state after end = %q, want stopping (egress_ended hasn't landed)", got)
		}
	})

	t.Run("room_finished webhook flips to stopping same-txn then worker retries StopEgress", func(t *testing.T) {
		egress := newFakeEgress()
		h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)
		host := meetTestUser(t, pool, "stopcase3host")
		meetingID := createTestMeeting(t, h, host, "Stop case 3")
		startMeetingLive(t, pool, meetingID)
		room := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var out startRecordingOut
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode start: %v", err)
		}
		var egressID string
		if err := pool.QueryRow(context.Background(),
			`SELECT egress_id FROM meeting_recordings WHERE id = $1`, out.RecordingID).Scan(&egressID); err != nil {
			t.Fatalf("query egress_id: %v", err)
		}

		event := &livekit.WebhookEvent{Event: "room_finished", Room: &livekit.Room{Name: room}}
		req := signWebhookRequest(t, configuredCfg, event, false)
		rrw := httptest.NewRecorder()
		h.WebhookHandler().ServeHTTP(rrw, req)
		if rrw.Code != http.StatusOK {
			t.Fatalf("room_finished webhook: want 200, got %d: %s", rrw.Code, rrw.Body.String())
		}
		if got := recordingState(t, pool, out.RecordingID); got != "stopping" {
			t.Fatalf("state after room_finished = %q, want stopping (same-txn flip)", got)
		}

		// F1: backdate started_at past requestedGrace — the row was just
		// created via the real route (started_at = now()), and the :357
		// recs query age-guards anything younger against the
		// ListEgress-vs-registry-read race.
		if _, err := pool.Exec(context.Background(),
			`UPDATE meeting_recordings SET started_at = now() - interval '5 minutes' WHERE id = $1`,
			out.RecordingID); err != nil {
			t.Fatalf("backdate started_at: %v", err)
		}

		egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
		w.reconcileRecordings(context.Background())
		if !egress.sawCall("StopEgress:" + egressID) {
			t.Errorf("worker did not retry StopEgress after room_finished; calls=%v", egress.calls)
		}
	})

	t.Run("wedge: stale requested fails (converged out of active's ancestry)", func(t *testing.T) {
		host := meetTestUser(t, pool, "stopcase4host")
		meetingID := createTestMeeting(t, meetHandler(pool, newFakeRooms()), host, "Stop case 4")
		recID := seedRecording(t, pool, meetingID, host, "requested", nil, nil, time.Now().Add(-3*time.Minute), 0)

		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
		w.reconcileRecordings(context.Background())
		if got := recordingState(t, pool, recID); got != "failed" {
			t.Errorf("state = %q, want failed", got)
		}
	})

	t.Run("wedge: stopping still SFU-active retries StopEgress", func(t *testing.T) {
		host := meetTestUser(t, pool, "stopcase5host")
		h := meetHandler(pool, newFakeRooms())
		meetingID := createTestMeeting(t, h, host, "Stop case 5")
		room := roomNameFor(t, pool, meetingID)
		egressID := "EG_" + room
		stagingKey := "meet-egress/case5.mp4"
		// backdated past requestedGrace (F1's age guard on the :357 query).
		seedRecording(t, pool, meetingID, host, "stopping", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

		egress := newFakeEgress()
		egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
		w.reconcileRecordings(context.Background())
		if !egress.sawCall("StopEgress:" + egressID) {
			t.Errorf("want StopEgress retried; calls=%v", egress.calls)
		}
	})

	t.Run("wedge: absent from ListEgress synthetic end", func(t *testing.T) {
		t.Run("staging present -> pending_ingest", func(t *testing.T) {
			host := meetTestUser(t, pool, "stopcase6ahost")
			h := meetHandler(pool, newFakeRooms())
			meetingID := createTestMeeting(t, h, host, "Stop case 6a")
			room := roomNameFor(t, pool, meetingID)
			egressID := "EG_" + room
			stagingKey := "meet-egress/case6a.mp4"
			// backdated past requestedGrace (F1's age guard on the :357 query).
			recID := seedRecording(t, pool, meetingID, host, "active", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

			store := newFakeStagingStore()
			store.put(stagingKey, []byte("bytes"), 0)
			w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), store)
			w.reconcileRecordings(context.Background())
			if got := recordingState(t, pool, recID); got != "pending_ingest" {
				t.Errorf("state = %q, want pending_ingest (staging present)", got)
			}
		})
		t.Run("staging absent -> failed", func(t *testing.T) {
			host := meetTestUser(t, pool, "stopcase6bhost")
			h := meetHandler(pool, newFakeRooms())
			meetingID := createTestMeeting(t, h, host, "Stop case 6b")
			room := roomNameFor(t, pool, meetingID)
			egressID := "EG_" + room
			stagingKey := "meet-egress/case6b.mp4"
			// backdated past requestedGrace (F1's age guard on the :357 query).
			recID := seedRecording(t, pool, meetingID, host, "active", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

			w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
			w.reconcileRecordings(context.Background())
			if got := recordingState(t, pool, recID); got != "failed" {
				t.Errorf("state = %q, want failed (staging absent)", got)
			}
		})
	})

	t.Run("belt: SFU-active egress with a terminal row gets stopped", func(t *testing.T) {
		host := meetTestUser(t, pool, "stopcase7host")
		h := meetHandler(pool, newFakeRooms())
		meetingID := createTestMeeting(t, h, host, "Stop case 7")
		room := roomNameFor(t, pool, meetingID)
		egressID := "EG_" + room
		stagingKey := "meet-egress/case7.mp4"
		seedRecording(t, pool, meetingID, host, "ready", &egressID, &stagingKey, time.Now(), 0)

		egress := newFakeEgress()
		egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
		w.reconcileRecordings(context.Background())
		if !egress.sawCall("StopEgress:" + egressID) {
			t.Errorf("belt did not stop the terminal-row egress; calls=%v", egress.calls)
		}
	})

	t.Run("wedge 4a: end with an unbound requested row lands terminal, never stopping", func(t *testing.T) {
		egress := newFakeEgress()
		h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)
		host := meetTestUser(t, pool, "stopcase8ahost")
		meetingID := createTestMeeting(t, h, host, "Stop case 8a")
		startMeetingLive(t, pool, meetingID)
		recID := seedRecording(t, pool, meetingID, host, "requested", nil, nil, time.Now(), 0)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		if got := recordingState(t, pool, recID); got != "failed" {
			t.Errorf("state = %q, want failed (never stopping — E-F2 / plan delta 11)", got)
		}
		if len(egress.calls) != 0 {
			t.Errorf("an unbound requested row must never reach an Egress call; calls=%v", egress.calls)
		}
	})

	t.Run("wedge 4b belt: a directly-seeded unbound stopping row fails on tick", func(t *testing.T) {
		host := meetTestUser(t, pool, "stopcase8bhost")
		h := meetHandler(pool, newFakeRooms())
		meetingID := createTestMeeting(t, h, host, "Stop case 8b")
		recID := seedRecording(t, pool, meetingID, host, "stopping", nil, nil, time.Now(), 0)

		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
		w.reconcileRecordings(context.Background())
		if got := recordingState(t, pool, recID); got != "failed" {
			t.Errorf("state = %q, want failed (wedge-4 belt sweep)", got)
		}
	})

	t.Run("nonRevokePaths: lock, settings, role fire zero egress calls", func(t *testing.T) {
		egress := newFakeEgress()
		h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)
		host := meetTestUser(t, pool, "stopcase9host")
		meetingID := createTestMeeting(t, h, host, "Stop case 9")
		startMeetingLive(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		afterStart := len(egress.calls)

		meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/lock", meetingID), `{"locked":true}`)
		meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/settings", meetingID), `{"guestAllowed":true}`)
		meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/role", meetingID), `{"identity":"u:999999999","role":"member"}`)

		if len(egress.calls) != afterStart {
			t.Errorf("lock/settings/role must never call the EgressController; calls=%v", egress.calls)
		}
	})
}

// ── 2. the live, genuinely-concurrent two-session race (spec §8.2/§10.2) ──

// TestConcurrentGuestAdmitVsRecordingStart proves the §8.2 FOR UPDATE
// serialization holds under real interleaving — explicitly NOT
// commit-then-check (the chat-A1 TestConcurrentLateCommitterReplay genre):
// the second connection's reducer call must still be blocked 100ms after
// the first connection's own call already returned (uncommitted), then
// unblock and raise BZ199 once the first connection commits. Both
// orderings prove the same invariant: no admitted guest is ever recorded.
func TestConcurrentGuestAdmitVsRecordingStart(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	t.Run("ordering A: start holds the lock, admit blocks then BZ199s", func(t *testing.T) {
		h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
		host := meetTestUser(t, pool, "raceAstartHost")
		meetingID := createTestMeeting(t, h, host, "Race ordering A")
		startMeetingLive(t, pool, meetingID)
		reqID := insertGuestJoinRequest(t, pool, meetingID, "Race Guest A")

		connA, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("pgx.Connect (A): %v", err)
		}
		defer connA.Close(ctx)
		txA, err := connA.Begin(ctx)
		if err != nil {
			t.Fatalf("begin A: %v", err)
		}

		var recID int64
		if err := txA.QueryRow(ctx, `SELECT meeting_recording_start($1, $2)`, host, meetingID).Scan(&recID); err != nil {
			t.Fatalf("A start (pre-commit): %v", err)
		}
		// txA now holds the meetings row FOR UPDATE lock, uncommitted.

		connB, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("pgx.Connect (B): %v", err)
		}
		defer connB.Close(ctx)

		bDone := make(chan error, 1)
		go func() {
			var outB []byte
			bDone <- connB.QueryRow(ctx, `SELECT meeting_admit($1, $2)`, host, reqID).Scan(&outB)
		}()

		select {
		case err := <-bDone:
			t.Fatalf("B's admit returned (err=%v) before A committed — the FOR UPDATE lock did not serialize the two arms", err)
		case <-time.After(100 * time.Millisecond):
			// expected: still blocked on A's held lock.
		}

		if err := txA.Commit(ctx); err != nil {
			t.Fatalf("commit A: %v", err)
		}

		select {
		case err := <-bDone:
			if err == nil {
				t.Fatal("B's admit succeeded — an admitted guest now coexists with a live recording, violating the §8.2 invariant")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "BZ199" {
				t.Fatalf("B's admit error = %v, want a BZ199 pgconn.PgError", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("B's admit never completed after A committed (deadlock?)")
		}
	})

	t.Run("ordering B: admit holds the lock, start blocks then BZ199s", func(t *testing.T) {
		h := meetHandlerWithEgress(pool, newFakeRooms(), newFakeEgress(), true, true)
		host := meetTestUser(t, pool, "raceBadmitHost")
		meetingID := createTestMeeting(t, h, host, "Race ordering B")
		startMeetingLive(t, pool, meetingID)
		reqID := insertGuestJoinRequest(t, pool, meetingID, "Race Guest B")

		connA, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("pgx.Connect (A): %v", err)
		}
		defer connA.Close(ctx)
		txA, err := connA.Begin(ctx)
		if err != nil {
			t.Fatalf("begin A: %v", err)
		}

		var outA []byte
		if err := txA.QueryRow(ctx, `SELECT meeting_admit($1, $2)`, host, reqID).Scan(&outA); err != nil {
			t.Fatalf("A admit (pre-commit): %v", err)
		}
		// txA now holds the meetings row FOR UPDATE lock (the guest arm's own
		// explicit lock), with an uncommitted guest admission.

		connB, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("pgx.Connect (B): %v", err)
		}
		defer connB.Close(ctx)

		bDone := make(chan error, 1)
		go func() {
			var recID int64
			bDone <- connB.QueryRow(ctx, `SELECT meeting_recording_start($1, $2)`, host, meetingID).Scan(&recID)
		}()

		select {
		case err := <-bDone:
			t.Fatalf("B's start returned (err=%v) before A committed — the FOR UPDATE lock did not serialize the two arms", err)
		case <-time.After(100 * time.Millisecond):
			// expected: still blocked on A's held lock.
		}

		if err := txA.Commit(ctx); err != nil {
			t.Fatalf("commit A: %v", err)
		}

		select {
		case err := <-bDone:
			if err == nil {
				t.Fatal("B's start succeeded — a recording started while an admitted guest is present, violating the §8.2 invariant")
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "BZ199" {
				t.Fatalf("B's start error = %v, want a BZ199 pgconn.PgError", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("B's start never completed after A committed (deadlock?)")
		}
	})
}

// ── 3. the >100 MiB ingest round trip (spec §10.3) ─────────────────────────

// TestRecordingIngestRoundTripLarge is the core ingest proof: a 105 MiB
// deterministic staging object through the full staging->chunks->
// put_version pipeline against a real S3-wire stub, asserting byte-identical
// SHA-256 end to end, the meeting-space no-cap proof (BZ148 would fire if
// meeting_space_ensure ever grew the chat upload_max_bytes clone), the
// access-plane wire behavior, and a genuinely idempotent re-ingest.
func TestRecordingIngestRoundTripLarge(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "ingestlargehost")
	member := meetTestUser(t, pool, "ingestlargemember")
	admittedNeverJoined := meetTestUser(t, pool, "ingestlargeadmitted")
	stranger := meetTestUser(t, pool, "ingestlargestranger")

	meetingID := createTestMeeting(t, h, host, "Ingest round-trip large")
	startMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)

	if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
		t.Fatalf("member join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	stampParticipantJoined(t, h, configuredCfg, room, fmt.Sprintf("u:%d", member))
	// admittedNeverJoined joins over HTTP but never gets a participant_joined
	// webhook — meeting_join.sql deliberately never stamps joined_at itself
	// (it is webhook-fed attendance only), so this alone is the
	// "admitted-but-never-attended member" fixture arm 3 must deny.
	if rr := meetDo(t, h, admittedNeverJoined, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
		t.Fatalf("admitted-never-joined member join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// stranger never joins at all.

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var startOut startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &startOut); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	var egressID, stagingKey string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id, staging_key FROM meeting_recordings WHERE id = $1`, startOut.RecordingID).
		Scan(&egressID, &stagingKey); err != nil {
		t.Fatalf("query bound recording: %v", err)
	}

	// seed a 105 MiB deterministic staging object — larger than the chat
	// upload_max_bytes 100 MiB cap so an accidental re-clone of that cap
	// fails loudly at BZ148 (spec §10.3, verbatim intent).
	mc, bucket, put, objects := meetStubS3(t)
	const size = 105 * 1024 * 1024
	data := make([]byte, size)
	rng := rand.New(rand.NewSource(42))
	if _, err := rng.Read(data); err != nil {
		t.Fatalf("rng.Read: %v", err)
	}
	wantSha := sha256.Sum256(data)
	put(stagingKey, data)
	store := drive.MinioStore{Client: mc}

	// synthetic egress_ended (a real signed webhook, EGRESS_COMPLETE) ->
	// pending_ingest. staging_key is never read from this payload (spec §4);
	// only size/duration are confirmed from it.
	completeEvent := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID, RoomName: room, Status: livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{Size: int64(size), Duration: 60_000_000_000}},
		},
	}
	req := signWebhookRequest(t, configuredCfg, completeEvent, false)
	rrw := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rrw, req)
	if rrw.Code != http.StatusOK {
		t.Fatalf("egress_ended webhook: want 200, got %d: %s", rrw.Code, rrw.Body.String())
	}
	if got := recordingState(t, pool, startOut.RecordingID); got != "pending_ingest" {
		t.Fatalf("state after egress_ended = %q, want pending_ingest", got)
	}

	// Precompute the 27 (26x4MiB + a 1MiB tail) chunk shas exactly the way
	// ingestOne splits the stream — used below to prove the fault-then-retry
	// dedup (drive_chunk_register's ON CONFLICT no-op) on a SECOND ingest
	// attempt of the SAME row, never a second recording/node.
	const chunkSize = 4 * 1024 * 1024
	var wantChunkShas []string
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		sum := sha256.Sum256(data[i:end])
		wantChunkShas = append(wantChunkShas, hex.EncodeToString(sum[:]))
	}
	if len(wantChunkShas) != 27 {
		t.Fatalf("test setup: computed %d chunks, want 27 (26x4MiB + tail)", len(wantChunkShas))
	}

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, toggle.NewTestFlags(map[string]bool{"feature.meet": true}),
		configuredCfg, newFakeRooms(), egress, store, bucket, nil, slog.Default())

	// Fault BEFORE the finalize commit: the node/version transaction rolls
	// back entirely (the Task 7 TestWorkerIngestCrashBeforeCommitConverges
	// genre), but every chunk has ALREADY been registered via the single-
	// homed drive.PromoteChunk path (outside that transaction) — this is
	// the genuinely-reachable idempotency proof: a clean retry re-registers
	// the SAME 27 shas as no-ops, not 27 new rows.
	w.ingestFaultBeforeFinalize = func() error { return errors.New("simulated crash before commit") }
	w.ingestRecordings(context.Background())
	if got := recordingState(t, pool, startOut.RecordingID); got != "pending_ingest" {
		t.Fatalf("state after the simulated crash = %q, want pending_ingest (no wedge)", got)
	}
	var preRetryChunkCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_chunks WHERE scope_key = 'g' AND sha256 = ANY($1)`, wantChunkShas).
		Scan(&preRetryChunkCount); err != nil {
		t.Fatalf("count pre-retry chunks: %v", err)
	}
	if preRetryChunkCount != 27 {
		t.Fatalf("chunks registered before the crash = %d, want 27", preRetryChunkCount)
	}
	if _, ok := objects()[stagingKey]; !ok {
		t.Fatalf("staging object must survive a rolled-back ingest attempt")
	}

	// clear the fault; the retry converges.
	w.ingestFaultBeforeFinalize = nil
	w.ingestRecordings(context.Background())

	var state string
	var nodeID, versionID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT state, file_node_id, version_id FROM meeting_recordings WHERE id = $1`, startOut.RecordingID).
		Scan(&state, &nodeID, &versionID); err != nil {
		t.Fatalf("query ingested recording: %v", err)
	}
	if state != "ready" {
		t.Fatalf("state after retry = %q, want ready", state)
	}

	var postRetryChunkCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_chunks WHERE scope_key = 'g' AND sha256 = ANY($1)`, wantChunkShas).
		Scan(&postRetryChunkCount); err != nil {
		t.Fatalf("count post-retry chunks: %v", err)
	}
	if postRetryChunkCount != 27 {
		t.Errorf("chunk count after the retry = %d, want 27 (dedup: no duplicate rows from the second pass)", postRetryChunkCount)
	}

	// upload_max_bytes lives inside export_policy jsonb (§9.2), not a plain
	// column; meeting_space_ensure never writes it, and drive_policy_resolve's
	// 'regular' default carries no such key either — the effective policy
	// must have no cap at all (the BZ148 clone spec §5 forbids).
	var spaceID int64
	var quotaBytes *int64
	var uploadMaxJSON *string
	if err := pool.QueryRow(context.Background(), `
		SELECT id, quota_bytes, drive_policy_resolve(id)->>'upload_max_bytes'
		  FROM drive_spaces WHERE meeting_id = $1`, meetingID).
		Scan(&spaceID, &quotaBytes, &uploadMaxJSON); err != nil {
		t.Fatalf("query meeting space: %v", err)
	}
	if quotaBytes != nil {
		t.Errorf("meeting space quota_bytes = %v, want NULL (spec §5: no server quota on a meeting space)", *quotaBytes)
	}
	if uploadMaxJSON != nil {
		t.Errorf("meeting space effective upload_max_bytes = %v, want NULL (spec §5: no cap on a meeting space)", *uploadMaxJSON)
	}

	var versionChunkCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_version_chunks WHERE version_id = $1`, versionID).Scan(&versionChunkCount); err != nil {
		t.Fatalf("count version chunks: %v", err)
	}
	if versionChunkCount != 27 {
		t.Errorf("version chunk count = %d, want 27 (26x4MiB + tail)", versionChunkCount)
	}

	var contentSha string
	if err := pool.QueryRow(context.Background(),
		`SELECT content_sha256 FROM drive_file_versions WHERE id = $1`, versionID).Scan(&contentSha); err != nil {
		t.Fatalf("query version sha: %v", err)
	}
	if contentSha != hex.EncodeToString(wantSha[:]) {
		t.Errorf("content_sha256 = %q, want %q", contentSha, hex.EncodeToString(wantSha[:]))
	}

	// byte-identity: re-concatenate the version's manifest chunks from the
	// stub and sha-compare against the original staging bytes.
	rows, err := pool.Query(context.Background(), `
		SELECT c.storage_ref FROM drive_version_chunks vc
		  JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
		 WHERE vc.version_id = $1 ORDER BY vc.ordinal`, versionID)
	if err != nil {
		t.Fatalf("query manifest: %v", err)
	}
	var reassembled []byte
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			rows.Close()
			t.Fatalf("scan storage_ref: %v", err)
		}
		chunk, ok := objects()[ref]
		if !ok {
			rows.Close()
			t.Fatalf("chunk object %q missing from the stub", ref)
		}
		reassembled = append(reassembled, chunk...)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("manifest rows: %v", err)
	}
	gotSha := sha256.Sum256(reassembled)
	if gotSha != wantSha {
		t.Errorf("reassembled-chunk sha = %x, want %x (byte-identity)", gotSha, wantSha)
	}

	if _, ok := objects()[stagingKey]; ok {
		t.Errorf("staging object %q must be deleted after a successful ingest", stagingKey)
	}

	// access plane: GET /drive/versions/{id}/content over the real drive
	// routes — host/attended-member 200, admitted-never-joined member and a
	// non-participant 404 (arm 3 at the wire, the single driveMemberScopeSQL
	// choke point).
	driveFlags := toggle.NewTestFlags(map[string]bool{"feature.drive": true})
	driveH := drive.NewHandler(pool, nil, store, bucket, driveFlags, slog.Default())
	contentPath := fmt.Sprintf("/drive/versions/%d/content", versionID)

	for _, tc := range []struct {
		name     string
		userID   int64
		wantCode int
	}{
		{"host", host, http.StatusOK},
		{"attended member", member, http.StatusOK},
		{"admitted-never-joined member", admittedNeverJoined, http.StatusNotFound},
		{"non-participant", stranger, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, contentPath, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: tc.userID}))
			rr := httptest.NewRecorder()
			driveH.ServeHTTP(rr, req)
			if rr.Code != tc.wantCode {
				t.Errorf("GET content as %s: want %d, got %d: %s", tc.name, tc.wantCode, rr.Code, rr.Body.String())
			}
		})
	}

	// the node is invisible in the member's /drive space list (Task 5's
	// s.meeting_id IS NULL filter).
	listReq := httptest.NewRequest(http.MethodGet, "/drive/spaces", nil)
	listReq = listReq.WithContext(auth.ContextWithUser(listReq.Context(), &auth.Claims{UserID: member}))
	listRR := httptest.NewRecorder()
	driveH.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("GET /drive/spaces: want 200, got %d: %s", listRR.Code, listRR.Body.String())
	}
	var spaces []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(listRR.Body.Bytes(), &spaces); err != nil {
		t.Fatalf("decode spaces: %v", err)
	}
	for _, sp := range spaces {
		if sp.ID == spaceID {
			t.Errorf("meeting-bound space %d appeared in the member's /drive space list", spaceID)
		}
	}
}

// ── 4. the full tracer arc, incl. the D11 drain (spec §10.3 arc + D11) ────

// TestRecordingTracerArc composes create -> start -> late-joiner
// recordingActive -> guest admit blocked -> stop -> guest admit unblocked ->
// kick -> second start -> ingest -> post-end recordings[]/attendance[]
// gating -> capacity-busy -> D11 drain, over the real routes/reducers/fakes.
//
// Deviation from the plan's single-mention prose (disclosed, narrowed by
// the F2 fix): recording #1 is converged to a TERMINAL state via a
// synthetic EGRESS_COMPLETE end (not EGRESS_FAILED) because
// meeting_recording_active treats 'stopping' as still-active, so the guest
// admit that must succeed "NOW" (right after stop) cannot until recording
// #1 leaves {requested,active,stopping} entirely — the plan's own arm-2
// predicate requires this; pending_ingest satisfies it exactly as failed
// would. The ORIGINAL reason to avoid EGRESS_COMPLETE here — ingesting BOTH
// recordings from the same meeting would collide at BZ147 on the identical
// minute-granularity node name — is RESOLVED (worker.go's ingestOne now
// suffixes the node name with the recording id): both recording #1 and
// recording #2 are ingested below, and BOTH land 'ready' with distinct
// node names — the exact same-meeting same-minute re-record scenario F2
// fixed, proven end to end rather than routed around.
func TestRecordingTracerArc(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	egress := newFakeEgress()
	h := meetHandlerWithEgress(pool, newFakeRooms(), egress, true, true)

	host := meetTestUser(t, pool, "tracerarchost")
	member := meetTestUser(t, pool, "tracerarcmember")
	stranger := meetTestUser(t, pool, "tracerarcstranger")

	meetingID := createTestMeeting(t, h, host, "Recording tracer arc")
	startMeetingLive(t, pool, meetingID) // "host joins"
	room := roomNameFor(t, pool, meetingID)

	// start: the banner fact precedes the first captured frame.
	var sawRequestedMidCall bool
	egress.startHook = func() {
		var state string
		if err := pool.QueryRow(context.Background(),
			`SELECT state FROM meeting_recordings WHERE meeting_id = $1 ORDER BY id DESC LIMIT 1`,
			meetingID).Scan(&state); err == nil {
			sawRequestedMidCall = state == "requested"
		}
	}
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	if !sawRequestedMidCall {
		t.Error("recording row was not already 'requested' when StartRoomComposite ran — the banner must precede the first frame")
	}
	egress.startHook = nil
	var rec1 startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &rec1); err != nil {
		t.Fatalf("decode start 1: %v", err)
	}
	var egressID1, stagingKey1 string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id, staging_key FROM meeting_recordings WHERE id = $1`, rec1.RecordingID).
		Scan(&egressID1, &stagingKey1); err != nil {
		t.Fatalf("query egress_id 1: %v", err)
	}

	// member joins mid-recording: the envelope carries recordingActive:true
	// (the late-joiner signal).
	rr = meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var joinOut struct {
		RecordingActive bool `json:"recordingActive"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &joinOut); err != nil {
		t.Fatalf("decode join: %v", err)
	}
	if !joinOut.RecordingActive {
		t.Error("member's join envelope must carry recordingActive:true while a recording is in flight")
	}
	stampParticipantJoined(t, h, configuredCfg, room, fmt.Sprintf("u:%d", member))

	// guest join-request -> admit blocked 403 BZ199.
	setGuestAllowed(t, h, host, meetingID)
	slug := meetingSlug(t, pool, meetingID)
	ph := meetPublicHandler(pool, true, true)
	rr = publicDo(t, ph, "POST", "/public/meet/"+slug+"/join-request",
		map[string]string{"slug": slug}, `{"displayName":"Tracer Guest"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("guest create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	guest := decodeCreateResp(t, rr)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, guest.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusForbidden || problemCode(t, rr) != "BZ199" {
		t.Fatalf("admit while recording: want 403/BZ199, got %d/%s", rr.Code, problemCode(t, rr))
	}

	// stop (204, StopEgress recorded).
	rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("stop: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !egress.sawCall("StopEgress:" + egressID1) {
		t.Errorf("stop did not call StopEgress for %s; calls=%v", egressID1, egress.calls)
	}

	// converge recording #1 out of {requested,active,stopping} (see the
	// func-doc deviation note) so meeting_recording_active no longer counts
	// it — pending_ingest via EGRESS_COMPLETE, not failed: F2 means this one
	// gets ingested too, below, alongside recording #2.
	complete1Event := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID1, RoomName: room, Status: livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{Size: 1024, Duration: 2_000_000_000}},
		},
	}
	req := signWebhookRequest(t, configuredCfg, complete1Event, false)
	rrw := httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rrw, req)
	if rrw.Code != http.StatusOK {
		t.Fatalf("egress_ended (recording 1): want 200, got %d: %s", rrw.Code, rrw.Body.String())
	}
	if got := recordingState(t, pool, rec1.RecordingID); got != "pending_ingest" {
		t.Fatalf("state after egress_ended (recording 1) = %q, want pending_ingest", got)
	}

	// NOW the guest admit succeeds.
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/requests/%d", meetingID, guest.RequestID), `{"action":"admit"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("admit after stop: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// guest kicked.
	guestIdentity := fmt.Sprintf("g:%d", guest.RequestID)
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/kick", meetingID), fmt.Sprintf(`{"identity":%q}`, guestIdentity))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("kick guest: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// start again.
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/recording", meetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("second start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var rec2 startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &rec2); err != nil {
		t.Fatalf("decode start 2: %v", err)
	}
	var egressID2, stagingKey2 string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id, staging_key FROM meeting_recordings WHERE id = $1`, rec2.RecordingID).
		Scan(&egressID2, &stagingKey2); err != nil {
		t.Fatalf("query bound recording 2: %v", err)
	}

	// synthetic egress_ended -> ingest.
	completeEvent := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: egressID2, RoomName: room, Status: livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{Size: 2048, Duration: 3_000_000_000}},
		},
	}
	req = signWebhookRequest(t, configuredCfg, completeEvent, false)
	rrw = httptest.NewRecorder()
	h.WebhookHandler().ServeHTTP(rrw, req)
	if rrw.Code != http.StatusOK {
		t.Fatalf("egress_ended (recording 2): want 200, got %d: %s", rrw.Code, rrw.Body.String())
	}

	// F2 un-dodge: recording #1 and recording #2 are the SAME meeting,
	// started within the same minute — the exact BZ147 shape. Both ingest
	// here in one drain call; the per-row id suffix (worker.go's ingestOne)
	// keeps their node names distinct instead of colliding.
	store := newFakeStagingStore()
	store.put(stagingKey1, []byte("tracer arc recording 1 bytes"), 0)
	store.put(stagingKey2, []byte("tracer arc recording 2 bytes"), 0)
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, store)
	w.ingestRecordings(context.Background())
	if got := recordingState(t, pool, rec1.RecordingID); got != "ready" {
		t.Fatalf("recording 1 state after ingest = %q, want ready (F2: same-meeting same-minute re-record must not collide)", got)
	}
	if got := recordingState(t, pool, rec2.RecordingID); got != "ready" {
		t.Fatalf("recording 2 state after ingest = %q, want ready", got)
	}
	var nodeName1, nodeName2 string
	if err := pool.QueryRow(context.Background(),
		`SELECT n.name FROM meeting_recordings r JOIN drive_nodes n ON n.id = r.file_node_id WHERE r.id = $1`,
		rec1.RecordingID).Scan(&nodeName1); err != nil {
		t.Fatalf("resolve node name 1: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT n.name FROM meeting_recordings r JOIN drive_nodes n ON n.id = r.file_node_id WHERE r.id = $1`,
		rec2.RecordingID).Scan(&nodeName2); err != nil {
		t.Fatalf("resolve node name 2: %v", err)
	}
	if nodeName1 == nodeName2 {
		t.Errorf("same-meeting same-minute re-record produced IDENTICAL node names %q — F2 regression (BZ147 data loss)", nodeName1)
	}

	type meetView struct {
		Recordings []struct {
			State string `json:"state"`
		} `json:"recordings"`
		Attendance []struct {
			Identity string `json:"identity"`
		} `json:"attendance"`
	}
	decodeMeetView := func(t *testing.T, rr *httptest.ResponseRecorder) meetView {
		t.Helper()
		var v meetView
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
			t.Fatalf("decode meet view %q: %v", rr.Body.String(), err)
		}
		return v
	}

	// recordings[] on GET /meet/{id} shows BOTH ingested recordings ready
	// for the member, pre-end (F2: neither collided the other out).
	rr = meetDo(t, h, member, "GET", fmt.Sprintf("/meet/%d", meetingID), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("member GET /meet/%d: want 200, got %d: %s", meetingID, rr.Code, rr.Body.String())
	}
	view := decodeMeetView(t, rr)
	readyCount := 0
	for _, r := range view.Recordings {
		if r.State == "ready" {
			readyCount++
		}
	}
	if readyCount != 2 {
		t.Errorf("member's recordings[] ready count = %d, want 2 (both same-meeting same-minute recordings ingested): %+v", readyCount, view.Recordings)
	}

	// meeting ends -> mass-stamp.
	rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// post-end: the member STILL gets recordings[], the host gets
	// attendance[] too, a non-participant's read shows both empty (§B2 at
	// the wire).
	for _, tc := range []struct {
		name           string
		userID         int64
		wantRecordings bool
		wantAttendance bool
	}{
		{"member (attendee, post-end)", member, true, false},
		{"host (attendee, post-end)", host, true, true},
		{"non-participant", stranger, false, false},
	} {
		rr := meetDo(t, h, tc.userID, "GET", fmt.Sprintf("/meet/%d", meetingID), "")
		if rr.Code != http.StatusOK {
			t.Fatalf("%s GET /meet/%d: want 200, got %d: %s", tc.name, meetingID, rr.Code, rr.Body.String())
		}
		v := decodeMeetView(t, rr)
		if tc.wantRecordings && len(v.Recordings) == 0 {
			t.Errorf("%s: want non-empty recordings[], got empty", tc.name)
		}
		if !tc.wantRecordings && len(v.Recordings) != 0 {
			t.Errorf("%s: want empty recordings[], got %+v", tc.name, v.Recordings)
		}
		if tc.wantAttendance && len(v.Attendance) == 0 {
			t.Errorf("%s: want non-empty attendance[], got empty", tc.name)
		}
		if !tc.wantAttendance && len(v.Attendance) != 0 {
			t.Errorf("%s: want empty attendance[], got %+v", tc.name, v.Attendance)
		}
	}

	// capacity-busy: a fresh meeting, fakeEgress injects a resource-exhausted
	// twirp error -> 503 egressBusy, row failed with error='egress_busy'.
	busyHost := meetTestUser(t, pool, "tracerarcbusyhost")
	busyMeetingID := createTestMeeting(t, h, busyHost, "Tracer arc capacity busy")
	startMeetingLive(t, pool, busyMeetingID)
	busyRoom := roomNameFor(t, pool, busyMeetingID)
	egress.startErrs[busyRoom] = twirp.NewError(twirp.ResourceExhausted, "max concurrent egress reached")
	rr = meetDo(t, h, busyHost, "POST", fmt.Sprintf("/meet/%d/recording", busyMeetingID), "")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity busy start: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if code := problemCode(t, rr); code != "egressBusy" {
		t.Errorf("capacity busy: problem code = %q, want egressBusy", code)
	}
	var busyState, busyErr string
	if err := pool.QueryRow(context.Background(),
		`SELECT state, error FROM meeting_recordings WHERE meeting_id = $1`, busyMeetingID).
		Scan(&busyState, &busyErr); err != nil {
		t.Fatalf("query busy recording: %v", err)
	}
	if busyState != "failed" || busyErr != "egress_busy" {
		t.Errorf("capacity busy row = %q/%q, want failed/egress_busy", busyState, busyErr)
	}

	// D11 drain: flip feature.meet_recording OFF via direct UPDATE, seed an
	// active recording -> DELETE still stops it, the webhook still lands it
	// pending_ingest, the worker still ingests it; START now 404s.
	drainEgress := newFakeEgress()
	hOn := meetHandlerWithEgress(pool, newFakeRooms(), drainEgress, true, true)
	drainHost := meetTestUser(t, pool, "tracerarcdrainhost")
	drainMeetingID := createTestMeeting(t, hOn, drainHost, "Tracer arc D11 drain")
	startMeetingLive(t, pool, drainMeetingID)
	drainRoom := roomNameFor(t, pool, drainMeetingID)

	rr = meetDo(t, hOn, drainHost, "POST", fmt.Sprintf("/meet/%d/recording", drainMeetingID), "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("drain start: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var drainRec startRecordingOut
	if err := json.Unmarshal(rr.Body.Bytes(), &drainRec); err != nil {
		t.Fatalf("decode drain start: %v", err)
	}
	var drainEgressID, drainStagingKey string
	if err := pool.QueryRow(context.Background(),
		`SELECT egress_id, staging_key FROM meeting_recordings WHERE id = $1`, drainRec.RecordingID).
		Scan(&drainEgressID, &drainStagingKey); err != nil {
		t.Fatalf("query drain recording: %v", err)
	}

	// D11's toggle gates only the START route; every drain leg below runs
	// against a handler built with meetRecordingOn=false — the same
	// in-memory toggle.NewTestFlags posture every other test in this
	// package uses (meetHandlerWithEgress), deliberately NOT a direct
	// UPDATE of the real feature_toggles row: that table is shared,
	// untransacted state across the whole DB-gated test run, and other
	// packages' tests (e.g. internal/admin's meet-recordings toggle-default
	// assertions) depend on it staying at its seeded default.
	hOff := meetHandlerWithEgress(pool, newFakeRooms(), drainEgress, false, false)
	rr = meetDo(t, hOff, drainHost, "DELETE", fmt.Sprintf("/meet/%d/recording", drainMeetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("D11 drain stop (toggle OFF): want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if !drainEgress.sawCall("StopEgress:" + drainEgressID) {
		t.Errorf("D11 drain stop did not call StopEgress; calls=%v", drainEgress.calls)
	}

	drainCompleteEvent := &livekit.WebhookEvent{
		Event: "egress_ended",
		EgressInfo: &livekit.EgressInfo{
			EgressId: drainEgressID, RoomName: drainRoom, Status: livekit.EgressStatus_EGRESS_COMPLETE,
			FileResults: []*livekit.FileInfo{{Size: 1024, Duration: 1_000_000_000}},
		},
	}
	req = signWebhookRequest(t, configuredCfg, drainCompleteEvent, false)
	rrw = httptest.NewRecorder()
	hOff.WebhookHandler().ServeHTTP(rrw, req)
	if rrw.Code != http.StatusOK {
		t.Fatalf("D11 drain webhook (toggle OFF): want 200, got %d: %s", rrw.Code, rrw.Body.String())
	}
	if got := recordingState(t, pool, drainRec.RecordingID); got != "pending_ingest" {
		t.Fatalf("D11 drain state after webhook = %q, want pending_ingest", got)
	}

	drainStore := newFakeStagingStore()
	drainStore.put(drainStagingKey, []byte("drain bytes"), 0)
	dw := meetWorkerRecording(pool, false, configuredCfg, newFakeRooms(), newFakeEgress(), drainStore)
	dw.ingestRecordings(context.Background())
	if got := recordingState(t, pool, drainRec.RecordingID); got != "ready" {
		t.Fatalf("D11 drain state after worker ingest (feature.meet OFF too) = %q, want ready", got)
	}

	rr = meetDo(t, hOff, drainHost, "POST", fmt.Sprintf("/meet/%d/recording", drainMeetingID), "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("D11 drain: start with feature.meet_recording OFF: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
