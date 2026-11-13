// worker_test.go — Task 12 (B1): the reconcile sweep. TestWorkerTickNoopWhen*
// is hermetic (a zero-value pgxutil.WorkerPool wraps a nil *pgxpool.Pool —
// any query would panic, so it also pins that the gate check happens
// BEFORE any pool access). Everything else is DB-gated over the real
// reducers on mailserver_test2 (the tracer_integration_test.go DB_DSN
// precedent), with fakeRooms standing in for the SFU exactly as the Task 9
// eviction tests do.
//
// B2 Task 7 extends this file with the recording drain legs: fakeEgress
// (fake_egress_test.go) stands in for the SFU's egress view, and
// fakeStagingStore (below) is an in-memory S3 double for the ingest/reaper
// legs — hermetic, no live MinIO. The REAL-client integration stub lives in
// Task 11's tracer_integration_test.go.
package meet

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func meetWorker(pool *pgxpool.Pool, enabled bool, cfg Config, rooms RoomController) *Worker {
	return NewWorker(pgxutil.WorkerPool{Pool: pool},
		toggle.NewTestFlags(map[string]bool{"feature.meet": enabled}), cfg, rooms, nil, nil, "", nil, slog.Default())
}

// meetWorkerRecording is meetWorker extended with the B2 drain legs wired
// (egress + staging store) — the Task 7 test genre.
func meetWorkerRecording(pool *pgxpool.Pool, enabled bool, cfg Config, rooms RoomController,
	egress EgressController, store stagingStore) *Worker {
	return NewWorker(pgxutil.WorkerPool{Pool: pool},
		toggle.NewTestFlags(map[string]bool{"feature.meet": enabled}), cfg, rooms, egress, store,
		"test-bucket", nil, slog.Default())
}

// meetWorkerCaptions is meetWorker extended with a CaptionsController — the
// B3 Task 14 test genre, used only by the captions reconcile tests below.
func meetWorkerCaptions(pool *pgxpool.Pool, enabled bool, cfg Config, rooms RoomController, captions CaptionsController) *Worker {
	return NewWorker(pgxutil.WorkerPool{Pool: pool},
		toggle.NewTestFlags(map[string]bool{"feature.meet": enabled}), cfg, rooms, nil, nil, "", captions, slog.Default())
}

// fakeStagingStore is an in-memory stagingStore double (the drive/
// chunks_test.go fakeStore genre, extended with StatObject) — hermetic, no
// live MinIO. getErr lets a test simulate a store outage (the bounded-retry
// genre); put's age param backdates LastModified without a live clock (the
// reaper's 7-day-threshold tests).
type fakeStagingStore struct {
	mu       sync.Mutex
	objects  map[string][]byte
	modTimes map[string]time.Time
	getErr   error
}

func newFakeStagingStore() *fakeStagingStore {
	return &fakeStagingStore{objects: map[string][]byte{}, modTimes: map[string]time.Time{}}
}

func (f *fakeStagingStore) put(key string, data []byte, age time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
	f.modTimes[key] = time.Now().Add(-age)
}

func (f *fakeStagingStore) GetObject(_ context.Context, _, object string, _ minio.GetObjectOptions) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	data, ok := f.objects[object]
	if !ok {
		return nil, errors.New("fakeStagingStore: not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *fakeStagingStore) PutObject(_ context.Context, _, object string, reader io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return minio.UploadInfo{}, err
	}
	f.mu.Lock()
	f.objects[object] = data
	f.modTimes[object] = time.Now()
	f.mu.Unlock()
	return minio.UploadInfo{Key: object, Size: int64(len(data))}, nil
}

func (f *fakeStagingStore) CopyObject(_ context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[src.Object]
	if !ok {
		return minio.UploadInfo{}, errors.New("fakeStagingStore: copy source not found")
	}
	f.objects[dst.Object] = data
	f.modTimes[dst.Object] = time.Now()
	return minio.UploadInfo{Key: dst.Object}, nil
}

func (f *fakeStagingStore) StatObject(_ context.Context, _, object string, _ minio.StatObjectOptions) (minio.ObjectInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.objects[object]
	if !ok {
		return minio.ObjectInfo{}, errors.New("fakeStagingStore: not found")
	}
	return minio.ObjectInfo{Key: object, Size: int64(len(data))}, nil
}

func (f *fakeStagingStore) RemoveObject(_ context.Context, _, object string, _ minio.RemoveObjectOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, object)
	delete(f.modTimes, object)
	return nil
}

func (f *fakeStagingStore) ListObjects(_ context.Context, _ string, opts minio.ListObjectsOptions) <-chan minio.ObjectInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan minio.ObjectInfo, len(f.objects))
	for key, data := range f.objects {
		if opts.Prefix != "" && !strings.HasPrefix(key, opts.Prefix) {
			continue
		}
		ch <- minio.ObjectInfo{Key: key, Size: int64(len(data)), LastModified: f.modTimes[key]}
	}
	close(ch)
	return ch
}

var _ stagingStore = (*fakeStagingStore)(nil)

// seedRecording inserts a meeting_recordings row directly (the
// setMeetingLive genre: a DB-gated test owns its own fixture) — the
// reconcile/ingest legs operate on row shapes no route creates directly.
func seedRecording(t *testing.T, pool *pgxpool.Pool, meetingID, startedBy int64, state string,
	egressID, stagingKey *string, startedAt time.Time, attempts int) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO meeting_recordings (meeting_id, started_by, state, egress_id, staging_key, started_at, ingest_attempts)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		meetingID, startedBy, state, egressID, stagingKey, startedAt, attempts).Scan(&id); err != nil {
		t.Fatalf("seed recording: %v", err)
	}
	return id
}

// recordingState is defined in webhook_test.go (Task 6) — reused here.

func recordingStateAndAttempts(t *testing.T, pool *pgxpool.Pool, id int64) (string, int) {
	t.Helper()
	var state string
	var attempts int
	if err := pool.QueryRow(context.Background(),
		`SELECT state, ingest_attempts FROM meeting_recordings WHERE id = $1`, id).Scan(&state, &attempts); err != nil {
		t.Fatalf("resolve recording state/attempts: %v", err)
	}
	return state, attempts
}

// setMeetingLive backdates a meeting row to 'live' with a created_at old
// enough to clear staleWindow on its own, and marks the meeting's one
// existing participant (meeting_create's own host row) as having left long
// ago too — simulating "LiveKit told us everyone left (participant_left
// webhooks arrived and were stamped), but the terminating room_finished
// webhook was lost." Without backdating the participant row, meeting_create's
// host insert (left_at NULL) would keep looking like an open participant
// forever, and gcLostWebhooks' NOT EXISTS guard would never fire.
func setMeetingLive(t *testing.T, pool *pgxpool.Pool, meetingID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		UPDATE meetings SET state = 'live', created_at = now() - interval '15 minutes'
		 WHERE id = $1`, meetingID); err != nil {
		t.Fatalf("backdate meeting: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE meeting_participants
		   SET joined_at = now() - interval '16 minutes', left_at = now() - interval '15 minutes'
		 WHERE meeting_id = $1`, meetingID); err != nil {
		t.Fatalf("backdate participant: %v", err)
	}
}

func meetingState(t *testing.T, pool *pgxpool.Pool, meetingID int64) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meetings WHERE id = $1`, meetingID).Scan(&state); err != nil {
		t.Fatalf("resolve state: %v", err)
	}
	return state
}

// TestWorkerTickNoopWhenDisabledOrUnconfigured pins that the gate check
// (feature.meet AND cfg.Configured()) runs BEFORE any RoomController access
// — fakeRooms recording zero calls proves ListRooms was never reached.
//
// Deviation (F5): this used to run against a nil pool (a zero-value
// pgxutil.WorkerPool) to prove ZERO pool access happens before the gate too
// — that invariant no longer holds by design. F5 hoists the DB-only
// recording legs (ended-residue flip, wedge-4 sweep, stale-requested grace)
// out of the w.egress != nil gate so they run whenever the pool exists,
// UNGATED by feature.meet/cfg.Configured() (D11: a toggle never gates the
// draining of already-committed state) — so this test now needs a real
// pool, DB-gated like the rest of the file, and asserts the narrower,
// still-true claim: the RoomController gate.
func TestWorkerTickNoopWhenDisabledOrUnconfigured(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	rooms := newFakeRooms()
	w := meetWorker(pool, false, configuredCfg, rooms)
	w.tick(context.Background())
	if len(rooms.calls) != 0 {
		t.Fatalf("toggle off: want zero RoomController calls, got %v", rooms.calls)
	}

	w2 := meetWorker(pool, true, Config{}, rooms)
	w2.tick(context.Background())
	if len(rooms.calls) != 0 {
		t.Fatalf("unconfigured: want zero RoomController calls, got %v", rooms.calls)
	}
}

// TestWorkerRetriesDeleteForEndedRoomStillOnSFU proves the Task 10 end/kick
// 502 backstop: a meeting already 'ended' in our DB whose room the SFU
// still lists gets a DeleteRoom retry on tick.
func TestWorkerRetriesDeleteForEndedRoomStillOnSFU(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "workerendedhost")
	meetingID := createTestMeeting(t, h, host, "Worker ended-room retry test")
	room := roomNameFor(t, pool, meetingID)

	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET state = 'ended', ended_at = now() WHERE id = $1`, meetingID); err != nil {
		t.Fatalf("mark ended: %v", err)
	}

	rooms := newFakeRooms()
	rooms.setRooms([]string{room}) // the SFU never got (or lost) the original DeleteRoom call
	w := meetWorker(pool, true, configuredCfg, rooms)
	w.tick(context.Background())

	if !rooms.sawCall("DeleteRoom:" + room) {
		t.Errorf("want DeleteRoom retried for room %s, calls: %v", room, rooms.calls)
	}
}

// TestWorkerGCsLostWebhookMeeting proves the core lost-webhook GC leg: a
// 'live' meeting with zero open participants, stale for longer than
// staleWindow, whose room the SFU no longer lists (liveSet empty) gets a
// synthetic room_finished ingested — flipping it to 'ended' without any
// caller and without a real webhook ever arriving.
func TestWorkerGCsLostWebhookMeeting(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "workergchost")
	meetingID := createTestMeeting(t, h, host, "Worker lost-webhook GC test")
	setMeetingLive(t, pool, meetingID)

	rooms := newFakeRooms() // ListRooms() → empty: the SFU has forgotten this room entirely
	w := meetWorker(pool, true, configuredCfg, rooms)
	w.tick(context.Background())

	if got := meetingState(t, pool, meetingID); got != "ended" {
		t.Errorf("state = %q, want %q after the lost-webhook GC leg", got, "ended")
	}
}

// TestWorkerDoesNotGCWhileSFUStillListsRoom is the converse: the identical
// stale-and-quiet meeting, but the SFU still lists the room — not lost, just
// quiet; a real room_finished webhook may still arrive, so the sweep must
// leave it alone.
func TestWorkerDoesNotGCWhileSFUStillListsRoom(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "workernogchost")
	meetingID := createTestMeeting(t, h, host, "Worker no-GC-while-live test")
	setMeetingLive(t, pool, meetingID)
	room := roomNameFor(t, pool, meetingID)

	rooms := newFakeRooms()
	rooms.setRooms([]string{room}) // the SFU still lists it
	w := meetWorker(pool, true, configuredCfg, rooms)
	w.tick(context.Background())

	if got := meetingState(t, pool, meetingID); got != "live" {
		t.Errorf("state = %q, want %q — SFU still lists the room, must not GC", got, "live")
	}
}

// TestWorkerExpiresLobbyRequests proves the worker's first tick step
// (meeting_requests_expire) actually runs — a pending join-request past its
// expires_at flips to 'expired' on tick, with no caller involved.
func TestWorkerExpiresLobbyRequests(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	host := meetTestUser(t, pool, "workerexpirehost")
	meetingID := createTestMeeting(t, h, host, "Worker lobby-expiry test")

	var reqID int64
	err := pool.QueryRow(context.Background(), `
		INSERT INTO meeting_join_requests (meeting_id, display_name, state, expires_at)
		VALUES ($1, 'Stale Guest', 'pending', now() - interval '1 minute')
		RETURNING id`, meetingID).Scan(&reqID)
	if err != nil {
		t.Fatalf("insert stale join request: %v", err)
	}

	rooms := newFakeRooms()
	w := meetWorker(pool, true, configuredCfg, rooms)
	w.tick(context.Background())

	var state string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM meeting_join_requests WHERE id = $1`, reqID).Scan(&state); err != nil {
		t.Fatalf("resolve request state: %v", err)
	}
	if state != "expired" {
		t.Errorf("join request state = %q, want %q", state, "expired")
	}
}

// ── B2 Task 7: the recording drain legs ─────────────────────────────────

// TestWorkerRecordingDrainLegsRunUnconditionally is the D11 gating proof:
// with feature.meet OFF, reconcileRecordings and ingestRecordings/
// reapStaging still run to convergence — a toggle gates new intent (the
// start route), never the draining of already-committed state.
//
// F2 un-dodge: this used to route around the same-minute BZ147 node-name
// collision with two DISTINCT meetings. worker.go's ingestOne now suffixes
// the node name with the recording id, so a SAME-meeting same-minute
// stop+restart no longer collides — seeded here directly (two rows on ONE
// meeting) and asserted: BOTH recordings ingest to ready with distinct
// node names, not just the one the old dodge could prove.
func TestWorkerRecordingDrainLegsRunUnconditionally(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "workerdrainoffhost")
	meeting := createTestMeeting(t, h, host, "Worker drain-unconditional test")
	room := roomNameFor(t, pool, meeting)

	// Both rows share ONE started_at — the exact same-meeting same-minute
	// shape the pre-fix node name ("Recording — {title} — {minute}.mp4")
	// would have collided on. Backdated past requestedGrace: F1's age guard
	// on the :357 recs query would otherwise exclude the stopping row from
	// wedge 3 entirely.
	commonStart := time.Now().Add(-5 * time.Minute)

	// stopping, egress vanished from the SFU, staging object present → the
	// reconcile leg's synthetic-end wedge-3 flips it to pending_ingest, and
	// (same tick, same store) the ingest leg immediately drains that too —
	// both drain legs running end to end proves D11 more thoroughly than a
	// frozen mid-state would.
	egressID := "EG_" + room
	stoppingKey := "meet-egress/drain-stopping.mp4"
	stoppingID := seedRecording(t, pool, meeting, host, "stopping", &egressID, &stoppingKey, commonStart, 0)

	// pending_ingest with real staging bytes, SAME meeting, SAME minute →
	// converges to ready alongside the row above without colliding (F2).
	ingestKey := "meet-egress/drain-ingest.mp4"
	ingestID := seedRecording(t, pool, meeting, host, "pending_ingest", nil, &ingestKey, commonStart, 0)

	store := newFakeStagingStore()
	store.put(stoppingKey, []byte("fake stopping bytes"), 0)
	store.put(ingestKey, []byte("fake ingest bytes"), 0)

	w := meetWorkerRecording(pool, false, configuredCfg, newFakeRooms(), newFakeEgress(), store)
	w.tick(context.Background())

	if got := recordingState(t, pool, stoppingID); got != "ready" {
		t.Errorf("stopping row state = %q, want ready (reconcile's synthetic-end + ingest both ran with feature.meet OFF)", got)
	}
	if got := recordingState(t, pool, ingestID); got != "ready" {
		t.Errorf("pending_ingest row state = %q, want ready (ingest must run with feature.meet OFF)", got)
	}

	var name1, name2 string
	if err := pool.QueryRow(context.Background(),
		`SELECT n.name FROM meeting_recordings r JOIN drive_nodes n ON n.id = r.file_node_id WHERE r.id = $1`,
		stoppingID).Scan(&name1); err != nil {
		t.Fatalf("resolve node name 1: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT n.name FROM meeting_recordings r JOIN drive_nodes n ON n.id = r.file_node_id WHERE r.id = $1`,
		ingestID).Scan(&name2); err != nil {
		t.Fatalf("resolve node name 2: %v", err)
	}
	if name1 == name2 {
		t.Errorf("same-meeting same-minute re-record produced IDENTICAL node names %q — F2 regression (BZ147 data loss)", name1)
	}
}

// TestWorkerReconcileWedge1StaleRequestedFails: a 'requested' row older
// than the 2-minute grace with no egress bound means Go crashed between the
// reducer call and StartRoomComposite — the worker fails it directly.
func TestWorkerReconcileWedge1StaleRequestedFails(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "wedge1host")
	meetingID := createTestMeeting(t, h, host, "Wedge1 test")

	recID := seedRecording(t, pool, meetingID, host, "requested", nil, nil, time.Now().Add(-3*time.Minute), 0)

	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
	w.tick(context.Background())

	if got := recordingState(t, pool, recID); got != "failed" {
		t.Fatalf("state = %q, want failed", got)
	}
	var errMsg string
	if err := pool.QueryRow(context.Background(),
		`SELECT error FROM meeting_recordings WHERE id = $1`, recID).Scan(&errMsg); err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	if !strings.Contains(errMsg, "never bound") {
		t.Errorf("error = %q, want it to mention the grace/never-bound reason", errMsg)
	}
}

// TestWorkerReconcileWedge2RetriesStopEgress: a 'stopping' row whose egress
// the SFU still lists as active means the stop call was lost — retry it
// (law 1: stop is an API call, never a TTL hope).
func TestWorkerReconcileWedge2RetriesStopEgress(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "wedge2host")
	meetingID := createTestMeeting(t, h, host, "Wedge2 test")
	room := roomNameFor(t, pool, meetingID)

	egressID := "EG_" + room
	stagingKey := "meet-egress/wedge2.mp4"
	// started_at backdated past requestedGrace (F1): the :357 recs query
	// excludes anything younger to guard against the ListEgress-vs-
	// registry-read race — a genuinely just-bound row isn't this test's
	// concern, so age it the way a real "stopping and still active" row
	// realistically would be.
	seedRecording(t, pool, meetingID, host, "stopping", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

	egress := newFakeEgress()
	egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
	w.tick(context.Background())

	if !egress.sawCall("StopEgress:" + egressID) {
		t.Errorf("want StopEgress retried for %s, calls: %v", egressID, egress.calls)
	}
}

// TestWorkerReconcileWedge3SyntheticEnd: an 'active' row absent from
// ListEgress (gone from the SFU with no egress_ended webhook) converges via
// a synthetic egress_ended — HEADing the known (ours, persisted-at-bind)
// staging object to decide pending_ingest vs failed.
func TestWorkerReconcileWedge3SyntheticEnd(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())

	t.Run("staging present", func(t *testing.T) {
		host := meetTestUser(t, pool, "wedge3present")
		meetingID := createTestMeeting(t, h, host, "Wedge3 present test")
		room := roomNameFor(t, pool, meetingID)
		egressID := "EG_" + room
		stagingKey := "meet-egress/wedge3-present.mp4"
		// backdated past requestedGrace — F1's age guard on the :357 recs
		// query, see TestWorkerReconcileWedge2RetriesStopEgress's comment.
		recID := seedRecording(t, pool, meetingID, host, "active", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

		store := newFakeStagingStore()
		store.put(stagingKey, []byte("bytes"), 0)
		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), store)
		// reconcileRecordings directly (not the full tick): a full tick would
		// also run ingestRecordings right after, which would immediately
		// drain this exact row past pending_ingest to ready in the same
		// call — this test isolates the reconcile leg's own output.
		w.reconcileRecordings(context.Background())

		if got := recordingState(t, pool, recID); got != "pending_ingest" {
			t.Errorf("state = %q, want pending_ingest (staging object present)", got)
		}
	})

	t.Run("staging absent", func(t *testing.T) {
		host := meetTestUser(t, pool, "wedge3absent")
		meetingID := createTestMeeting(t, h, host, "Wedge3 absent test")
		room := roomNameFor(t, pool, meetingID)
		egressID := "EG_" + room
		stagingKey := "meet-egress/wedge3-absent.mp4"
		recID := seedRecording(t, pool, meetingID, host, "active", &egressID, &stagingKey, time.Now().Add(-5*time.Minute), 0)

		w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
		w.tick(context.Background())

		if got := recordingState(t, pool, recID); got != "failed" {
			t.Errorf("state = %q, want failed (staging object absent)", got)
		}
	})
}

// TestWorkerReconcileWedge4UnboundStoppingSweep: a 'stopping' row with no
// egress binding (the state Task 2's origin fix should make unreachable —
// this seeds it directly) is invisible to every ListEgress-keyed leg above,
// so it needs its own belt: fail it this tick, error recorded.
func TestWorkerReconcileWedge4UnboundStoppingSweep(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "wedge4host")
	meetingID := createTestMeeting(t, h, host, "Wedge4 test")

	recID := seedRecording(t, pool, meetingID, host, "stopping", nil, nil, time.Now(), 0)

	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), newFakeStagingStore())
	w.tick(context.Background())

	if got := recordingState(t, pool, recID); got != "failed" {
		t.Fatalf("state = %q, want failed (wedge-4 sweep: stopping with no egress binding)", got)
	}
	var errMsg string
	if err := pool.QueryRow(context.Background(),
		`SELECT error FROM meeting_recordings WHERE id = $1`, recID).Scan(&errMsg); err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	if errMsg == "" {
		t.Errorf("want an error recorded for the wedge-4 sweep, got empty")
	}
}

// TestWorkerReconcileEndedMeetingResidue: the room_finished mirror's sweep
// half (E-F2 restriction) — a BOUND 'requested'/'active' row on an ended
// meeting flips to 'stopping'; an UNBOUND 'requested' row does NOT (it
// converges via the stale-requested grace leg instead, never this one).
func TestWorkerReconcileEndedMeetingResidue(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "residuehost")
	meetingID := createTestMeeting(t, h, host, "Residue test")
	room := roomNameFor(t, pool, meetingID)

	egressID := "EG_" + room
	stagingKey := "meet-egress/residue-bound.mp4"
	boundID := seedRecording(t, pool, meetingID, host, "requested", &egressID, &stagingKey, time.Now(), 0)
	unboundID := seedRecording(t, pool, meetingID, host, "requested", nil, nil, time.Now(), 0)

	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET state = 'ended', ended_at = now() WHERE id = $1`, meetingID); err != nil {
		t.Fatalf("mark ended: %v", err)
	}

	// The bound row's egress reports Active in the SFU too. Its started_at
	// is fresh (time.Now()), so F1's age guard excludes it from this same
	// tick's wedge 2/3 processing entirely — the assertion below only
	// checks the DB-only residue flip's own output ('stopping'), which
	// fires regardless of the ListEgress-keyed leg.
	egress := newFakeEgress()
	egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
	w.tick(context.Background())

	if got := recordingState(t, pool, boundID); got != "stopping" {
		t.Errorf("bound requested row state = %q, want stopping (ended-residue flip)", got)
	}
	if got := recordingState(t, pool, unboundID); got != "requested" {
		t.Errorf("unbound requested row state = %q, want requested unchanged (E-F2: converges via stale-requested grace, not this leg)", got)
	}
}

// TestWorkerReconcileBeltStopsUnknownActiveEgress: an SFU-active egress
// whose registry row is terminal (or unknown) gets stopped anyway — law 1's
// belt (TestEveryRecordingStopPathStopsEgress's case 7 in Task 11).
func TestWorkerReconcileBeltStopsUnknownActiveEgress(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "belthost")
	meetingID := createTestMeeting(t, h, host, "Belt test")
	room := roomNameFor(t, pool, meetingID)

	egressID := "EG_" + room
	stagingKey := "meet-egress/belt.mp4"
	seedRecording(t, pool, meetingID, host, "ready", &egressID, &stagingKey, time.Now(), 0) // terminal row

	egress := newFakeEgress()
	egress.setEgresses([]EgressStatus{{EgressID: egressID, RoomName: room, Active: true}})
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
	w.tick(context.Background())

	if !egress.sawCall("StopEgress:" + egressID) {
		t.Errorf("want belt StopEgress for terminal-row egress %s, calls: %v", egressID, egress.calls)
	}
}

// ── F1: the ListEgress-vs-registry-read race age guards ─────────────────

// TestWorkerReconcileYoungRowNotSyntheticFailed proves F1's first direction:
// worker.go's ListEgress call (:336-ish) runs BEFORE the registry read
// (:357-ish) — a recording bound in that window can look absent from
// ListEgress even though it's healthy. A registry row younger than
// requestedGrace must NOT be synthetic-failed by wedge 3; it stays
// untouched this tick and converges on a later one once the race resolves.
func TestWorkerReconcileYoungRowNotSyntheticFailed(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "youngrowhost")
	meetingID := createTestMeeting(t, h, host, "Young row race test")
	room := roomNameFor(t, pool, meetingID)

	egressID := "EG_" + room
	stagingKey := "meet-egress/youngrow.mp4"
	// started_at is FRESH (inside requestedGrace) — the exact race window.
	recID := seedRecording(t, pool, meetingID, host, "active", &egressID, &stagingKey, time.Now(), 0)

	// ListEgress reports NOTHING for this egress — without the age guard
	// this hits wedge 3 and synthesizes a failure on a healthy recording.
	egress := newFakeEgress()
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
	w.reconcileRecordings(context.Background())

	if got := recordingState(t, pool, recID); got != "active" {
		t.Errorf("young row state = %q, want active unchanged (F1: age-guarded against the ListEgress race)", got)
	}
}

// TestWorkerReconcileBeltSkipsYoungUnregisteredEgress proves F1's mirror
// direction: an egress ListEgress reports Active with StartedAt inside
// requestedGrace, but with no matching registry row (the bind committed
// AFTER this tick's ListEgress snapshot) must NOT be stopped by the belt —
// that would kill a healthy just-started recording.
func TestWorkerReconcileBeltSkipsYoungUnregisteredEgress(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	egress := newFakeEgress()
	egress.setEgresses([]EgressStatus{
		{EgressID: "EG_unregistered_young", RoomName: "some-room", Active: true, StartedAt: time.Now()},
	})
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, newFakeStagingStore())
	w.reconcileRecordings(context.Background())

	if egress.sawCall("StopEgress:EG_unregistered_young") {
		t.Errorf("want the belt to skip a young unregistered egress, but it called StopEgress; calls=%v", egress.calls)
	}
}

// ── F5: the DB-only recording legs must not wedge behind a nil egress ───

// TestWorkerDBOnlyRecordingLegsRunWithNilEgress proves the three DB-only
// §6.4 legs (ended-residue flip, wedge-4 sweep, stale-requested grace)
// still converge their rows when w.egress is nil (the Egress sidecar
// deconfigured with recordings in flight) — they must not sit behind the
// w.egress != nil gate the ListEgress-keyed legs genuinely need.
func TestWorkerDBOnlyRecordingLegsRunWithNilEgress(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "nilegresshost")

	// stale requested: no egress bound, past the 2-minute grace.
	staleMeeting := createTestMeeting(t, h, host, "Nil-egress stale requested")
	staleID := seedRecording(t, pool, staleMeeting, host, "requested", nil, nil, time.Now().Add(-3*time.Minute), 0)

	// ended-meeting residue: a BOUND requested row on an ended meeting.
	residueMeeting := createTestMeeting(t, h, host, "Nil-egress residue")
	room := roomNameFor(t, pool, residueMeeting)
	egressID := "EG_" + room
	stagingKey := "meet-egress/nilegress-residue.mp4"
	residueID := seedRecording(t, pool, residueMeeting, host, "requested", &egressID, &stagingKey, time.Now(), 0)
	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET state = 'ended', ended_at = now() WHERE id = $1`, residueMeeting); err != nil {
		t.Fatalf("mark ended: %v", err)
	}

	// wedge 4: an unbound stopping row.
	wedge4Meeting := createTestMeeting(t, h, host, "Nil-egress wedge4")
	wedge4ID := seedRecording(t, pool, wedge4Meeting, host, "stopping", nil, nil, time.Now(), 0)

	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), nil, newFakeStagingStore())
	w.tick(context.Background())

	if got := recordingState(t, pool, staleID); got != "failed" {
		t.Errorf("stale-requested row state = %q, want failed (F5: DB-only leg runs with nil egress)", got)
	}
	if got := recordingState(t, pool, residueID); got != "stopping" {
		t.Errorf("residue row state = %q, want stopping (F5: DB-only leg runs with nil egress)", got)
	}
	if got := recordingState(t, pool, wedge4ID); got != "failed" {
		t.Errorf("wedge-4 row state = %q, want failed (F5: DB-only leg runs with nil egress)", got)
	}
}

// TestWorkerIngestHappyPath: a 10 MiB staging object splits into 3 chunks
// (4+4+2 MiB), each promoted through the single-homed drive.PromoteChunk
// path; the node/version land attributed to meetings.owner_user_id (plan
// delta 10, NOT started_by), the row lands 'ready', and the staging object
// is deleted.
func TestWorkerIngestHappyPath(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "ingesthappyhost")
	meetingID := createTestMeeting(t, h, host, "Ingest happy path")

	stagingKey := "meet-egress/ingest-happy.mp4"
	data := make([]byte, 10*1024*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	recID := seedRecording(t, pool, meetingID, host, "pending_ingest", nil, &stagingKey, time.Now(), 0)

	store := newFakeStagingStore()
	store.put(stagingKey, data, 0)

	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), store)
	w.tick(context.Background())

	if got := recordingState(t, pool, recID); got != "ready" {
		t.Fatalf("state = %q, want ready", got)
	}
	var nodeID, versionID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT file_node_id, version_id FROM meeting_recordings WHERE id = $1`, recID).Scan(&nodeID, &versionID); err != nil {
		t.Fatalf("resolve node/version: %v", err)
	}
	var createdBy int64
	var name string
	if err := pool.QueryRow(context.Background(),
		`SELECT created_by, name FROM drive_nodes WHERE id = $1`, nodeID).Scan(&createdBy, &name); err != nil {
		t.Fatalf("resolve node: %v", err)
	}
	if createdBy != host {
		t.Errorf("node created_by = %d, want the meeting owner %d (plan delta 10, not started_by)", createdBy, host)
	}
	if !strings.HasPrefix(name, "Recording — Ingest happy path — ") || !strings.HasSuffix(name, ".mp4") {
		t.Errorf("node name = %q, want the %q shape", name, "Recording — {title} — {ts}.mp4")
	}
	if _, ok := store.objects[stagingKey]; ok {
		t.Errorf("staging object %q must be deleted after a successful ingest", stagingKey)
	}
	var chunkCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_version_chunks WHERE version_id = $1`, versionID).Scan(&chunkCount); err != nil {
		t.Fatalf("count chunks: %v", err)
	}
	if chunkCount != 3 {
		t.Errorf("chunk count = %d, want 3 (4+4+2 MiB split of a 10 MiB recording)", chunkCount)
	}
}

// TestWorkerIngestBoundedRetryExhaustion: a store whose GetObject always
// errors climbs ingest_attempts on ticks 1-5 (state stays pending_ingest);
// tick 6 — the pass AFTER exhaustion — marks the row failed with
// ingest_attempts frozen at 5, and reconcileRecordings still ran every tick
// (no wedge: one row's exhaustion never stalls the rest of the sweep).
func TestWorkerIngestBoundedRetryExhaustion(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "ingestretryhost")
	meetingID := createTestMeeting(t, h, host, "Ingest bounded retry")

	stagingKey := "meet-egress/ingest-retry.mp4"
	recID := seedRecording(t, pool, meetingID, host, "pending_ingest", nil, &stagingKey, time.Now(), 0)

	store := newFakeStagingStore()
	store.getErr = errors.New("simulated store outage")

	egress := newFakeEgress()
	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), egress, store)
	for i := 1; i <= 5; i++ {
		w.tick(context.Background())
		state, attempts := recordingStateAndAttempts(t, pool, recID)
		if state != "pending_ingest" {
			t.Fatalf("tick %d: state = %q, want pending_ingest (attempts %d)", i, state, attempts)
		}
		if attempts != i {
			t.Fatalf("tick %d: ingest_attempts = %d, want %d", i, attempts, i)
		}
	}
	w.tick(context.Background()) // tick 6: the pass AFTER exhaustion
	state, attempts := recordingStateAndAttempts(t, pool, recID)
	if state != "failed" {
		t.Fatalf("tick 6: state = %q, want failed", state)
	}
	if attempts != 5 {
		t.Fatalf("tick 6: ingest_attempts = %d, want 5 (frozen at exhaustion)", attempts)
	}
	var errMsg string
	if err := pool.QueryRow(context.Background(),
		`SELECT error FROM meeting_recordings WHERE id = $1`, recID).Scan(&errMsg); err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	if errMsg == "" {
		t.Errorf("want a recorded error after exhaustion, got empty")
	}

	listCalls := 0
	for _, c := range egress.calls {
		if c == "ListEgress" {
			listCalls++
		}
	}
	if listCalls != 6 {
		t.Errorf("reconcileRecordings must run every tick even after ingest exhaustion; ListEgress calls = %d, want 6", listCalls)
	}
}

// TestWorkerIngestCrashBeforeCommitConverges: a fault injected right after
// drive_file_put_version succeeds (before meeting_recording_ingested)
// leaves NO node row — the whole transaction rolls back — and a clean
// retry converges via content-addressed dedup (the same chunk sha256
// re-registers as a no-op, not a duplicate store).
func TestWorkerIngestCrashBeforeCommitConverges(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "ingestcrashhost")
	meetingID := createTestMeeting(t, h, host, "Ingest crash-before-commit")

	// Bug fix (found running Task 4's full-package gate, mailserver/internal/
	// meet/breakouts_test.go): staging_key must be unique per invocation, the
	// same invariant production's stagingKeyFor(recID, room) already
	// guarantees. A literal hardcoded key collided across repeated runs
	// against the SAME persistent mailserver_test (no schema reload between
	// them): reapStaging's `SELECT state FROM meeting_recordings WHERE
	// staging_key = $1` has no ORDER BY/uniqueness guarantee, so once an
	// earlier run's row reached a terminal state ('ready'), a later run's
	// fresh 'pending_ingest' row sharing the identical literal key could have
	// that SELECT arbitrarily return the OLD terminal row instead — reapStaging
	// then deleted the object out from under the CURRENT in-flight ingest,
	// exactly the "staging object must survive a rolled-back ingest attempt"
	// failure this test caught. meetingID is fresh (a new serial id) every
	// invocation, so folding it in makes the key collision-proof the same way
	// production's own recording-id-keyed convention already is.
	stagingKey := fmt.Sprintf("meet-egress/ingest-crash-%d.mp4", meetingID)
	data := make([]byte, 1024*1024) // 1 MiB — one chunk, keeps the test fast
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	recID := seedRecording(t, pool, meetingID, host, "pending_ingest", nil, &stagingKey, time.Now(), 0)

	store := newFakeStagingStore()
	store.put(stagingKey, data, 0)

	w := meetWorkerRecording(pool, true, configuredCfg, newFakeRooms(), newFakeEgress(), store)
	w.ingestFaultBeforeFinalize = func() error { return errors.New("simulated crash before commit") }
	w.tick(context.Background())

	state, attempts := recordingStateAndAttempts(t, pool, recID)
	if state != "pending_ingest" {
		t.Fatalf("after the simulated crash: state = %q, want pending_ingest (no wedge)", state)
	}
	if attempts != 1 {
		t.Fatalf("ingest_attempts = %d, want 1", attempts)
	}
	var nodeCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM drive_nodes n JOIN drive_spaces s ON s.id = n.space_id
		 WHERE s.meeting_id = $1`, meetingID).Scan(&nodeCount); err != nil {
		t.Fatalf("count nodes: %v", err)
	}
	if nodeCount != 0 {
		t.Errorf("crash-before-commit must leave NO node row, found %d", nodeCount)
	}
	if _, ok := store.objects[stagingKey]; !ok {
		t.Errorf("staging object must survive a rolled-back ingest attempt")
	}

	// The retry converges: clear the fault and re-tick.
	w.ingestFaultBeforeFinalize = nil
	w.tick(context.Background())
	if got := recordingState(t, pool, recID); got != "ready" {
		t.Errorf("retry state = %q, want ready (content-addressed chunks re-register as no-ops)", got)
	}
}

// ── B3 Task 5: the two breakout worker arms ─────────────────────────────

// leftAt resolves a participant's left_at column (nil = still active) — the
// F2 grace assertion's own read, the recordingState genre.
func leftAt(t *testing.T, pool *pgxpool.Pool, meetingID int64, identity string) *string {
	t.Helper()
	var left *string
	if err := pool.QueryRow(context.Background(),
		`SELECT left_at::text FROM meeting_participants WHERE meeting_id = $1 AND identity = $2`,
		meetingID, identity).Scan(&left); err != nil {
		t.Fatalf("query left_at: %v", err)
	}
	return left
}

// TestWorkerReconcileBreakoutChildGC proves leg 1: a child breakout room the
// SFU still lists after its own row closed, or after its parent meeting
// ended, gets DeleteRoom retried — the deleteEndedButLiveRooms shape cloned
// onto meeting_breakouts (the TestWorkerRetriesDeleteForEndedRoomStillOnSFU
// genre: the handler's own fakeRooms is a SEPARATE double from the worker's,
// simulating "the original DeleteRoom call was lost").
func TestWorkerReconcileBreakoutChildGC(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	t.Run("closed breakout room still live -> DeleteRoom retried", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "workerbrkclosedhost")
		meetingID := createTestMeeting(t, h, host, "Worker breakout child GC closed test")

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms()
		wrooms.setRooms([]string{b.RoomName}) // the SFU still lists it — the original DeleteRoom was lost
		w := meetWorker(pool, true, configuredCfg, wrooms)
		w.tick(context.Background())

		if !wrooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("want DeleteRoom retried for closed child room %s, calls=%v", b.RoomName, wrooms.calls)
		}
	})

	t.Run("child of an ended meeting still live -> DeleteRoom retried", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "workerbrkendedhost")
		meetingID := createTestMeeting(t, h, host, "Worker breakout child GC ended test")

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms()
		wrooms.setRooms([]string{b.RoomName})
		w := meetWorker(pool, true, configuredCfg, wrooms)
		w.tick(context.Background())

		if !wrooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("want DeleteRoom retried for the ended meeting's child room %s, calls=%v", b.RoomName, wrooms.calls)
		}
	})

	t.Run("child room already absent from the SFU -> no call", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "workerbrkabsenthost")
		meetingID := createTestMeeting(t, h, host, "Worker breakout child GC absent test")

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms() // no setRooms — the SFU already forgot it
		w := meetWorker(pool, true, configuredCfg, wrooms)
		w.tick(context.Background())

		if wrooms.sawCall("DeleteRoom:" + b.RoomName) {
			t.Errorf("a room already absent from the SFU must not get a redundant DeleteRoom; calls=%v", wrooms.calls)
		}
	})
}

// TestWorkerReconcileBreakoutPresence proves leg 2's core compare-and-heal:
// present-in-the-wrong-room evicts, present-in-the-right-room is a no-op,
// and a meeting with no open breakouts adds ZERO ListParticipants calls
// (the arm's own scoping, asserted on the SAME tick as the two real cases
// so the zero-call claim is proven against live traffic, not an empty run).
func TestWorkerReconcileBreakoutPresence(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)

	// A second, breakout-less meeting in the SAME tick — proves the "zero
	// open breakouts -> zero ListParticipants" scoping isn't vacuous.
	noopHost := meetTestUser(t, pool, "workerbrknoopenhost")
	noopMeeting := createTestMeeting(t, h, noopHost, "Worker breakout presence no-open-breakouts")
	if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, noopMeeting); err != nil {
		t.Fatalf("mark noop meeting live: %v", err)
	}

	host := meetTestUser(t, pool, "workerbrkpresencehost")
	u1 := meetTestUser(t, pool, "workerbrkpresenceu1")
	u2 := meetTestUser(t, pool, "workerbrkpresenceu2")
	meetingID := createTestMeeting(t, h, host, "Worker breakout presence test")
	for _, u := range []int64{u1, u2} {
		if rr := meetDo(t, h, u, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
			t.Fatalf("join u=%d: want 200, got %d: %s", u, rr.Code, rr.Body.String())
		}
	}
	mainRoom := roomNameFor(t, pool, meetingID)
	if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
		t.Fatalf("mark meeting live: %v", err)
	}

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b1 := decodeOpenedBreakouts(t, rr)[0]

	for _, u := range []int64{u1, u2} {
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, u, b1.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign u=%d: want 204, got %d: %s", u, rr.Code, rr.Body.String())
		}
	}

	id1 := fmt.Sprintf("u:%d", u1)
	id2 := fmt.Sprintf("u:%d", u2)

	wrooms := newFakeRooms()
	// u:1 assigned to b1 but present in the PARENT — the stale-token
	// sneak-back / ignored-push case.
	wrooms.setParticipants(mainRoom, []string{id1})
	// u:2 assigned to b1 and present in b1 — the correct, no-op case.
	wrooms.setParticipants(b1.RoomName, []string{id2})
	w := meetWorker(pool, true, configuredCfg, wrooms)
	w.tick(context.Background())

	if want := fmt.Sprintf("RemoveParticipant:%s/%s", mainRoom, id1); !wrooms.sawCall(want) {
		t.Errorf("u:1 present in the wrong room must be evicted; want call %q, calls=%v", want, wrooms.calls)
	}
	if got := fmt.Sprintf("RemoveParticipant:%s/%s", b1.RoomName, id2); wrooms.sawCall(got) {
		t.Errorf("u:2 present in its assigned room must NOT be evicted; calls=%v", wrooms.calls)
	}
	// the noop meeting's main room must never have been ListParticipants'd.
	noopRoom := roomNameFor(t, pool, noopMeeting)
	if wrooms.sawCall("ListParticipants:" + noopRoom) {
		t.Errorf("a meeting with no open breakouts must add zero ListParticipants calls; calls=%v", wrooms.calls)
	}
}

// TestWorkerReconcileBreakoutAbsenceGrace proves the delta-8 one-interval
// grace: not stamped on the first absent tick, stamped after the second;
// reappearing between ticks clears the grace and is never stamped.
func TestWorkerReconcileBreakoutAbsenceGrace(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	setupAssignedMember := func(t *testing.T, label string) (meetingID int64, breakoutRoom, identity string) {
		t.Helper()
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, label+"host")
		member := meetTestUser(t, pool, label+"member")
		meetingID = createTestMeeting(t, h, host, "Worker breakout absence grace "+label)
		if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		identity = fmt.Sprintf("u:%d", member)
		if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
			t.Fatalf("mark meeting live: %v", err)
		}

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		breakoutRoom = b.RoomName
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		return
	}

	t.Run("not stamped on the first absent tick, stamped after the second", func(t *testing.T) {
		meetingID, _, identity := setupAssignedMember(t, "brkgrace1")
		wrooms := newFakeRooms() // absent from every room, both ticks
		w := meetWorker(pool, true, configuredCfg, wrooms)

		w.tick(context.Background())
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Fatalf("must not be stamped left_at on the first absent tick")
		}

		w.tick(context.Background())
		if got := leftAt(t, pool, meetingID, identity); got == nil {
			t.Errorf("must be stamped left_at after a second consecutive absent tick")
		}
	})

	t.Run("reappearing between ticks clears the grace, never stamps", func(t *testing.T) {
		meetingID, breakoutRoom, identity := setupAssignedMember(t, "brkgrace2")
		wrooms := newFakeRooms()
		w := meetWorker(pool, true, configuredCfg, wrooms)

		w.tick(context.Background()) // absent — first-seen, recorded, not stamped
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Fatalf("must not be stamped on the first absent tick")
		}

		wrooms.setParticipants(breakoutRoom, []string{identity}) // reappears in its OWN assigned room
		w.tick(context.Background())
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Errorf("reappearing before the grace elapses must never stamp left_at")
		}

		// a fresh absence after reappearing must restart the grace — never
		// fire on its own first tick (destructive-late, never destructive-early).
		wrooms.setParticipants(breakoutRoom, nil)
		w.tick(context.Background())
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Errorf("a fresh absence right after reappearing must not stamp on its own first tick")
		}
	})
}

// TestWorkerReconcileBreakoutsIgnoresToggleOff proves the F11 drain pin at
// the worker level (breakouts_test.go proves it at the route level): both
// arms run identically whether the Worker's flags carry feature.meet_breakouts
// ON or OFF, because the worker never checks that toggle at all — only
// feature.meet gates whether tick's body runs.
func TestWorkerReconcileBreakoutsIgnoresToggleOff(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)

	host := meetTestUser(t, pool, "workerbrktoggleoffhost")
	meetingID := createTestMeeting(t, h, host, "Worker breakout toggle-off drain test")

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b := decodeOpenedBreakouts(t, rr)[0]
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
		t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	wrooms := newFakeRooms()
	wrooms.setRooms([]string{b.RoomName})
	// The worker's OWN flags carry no feature.meet_breakouts entry at all
	// (meetWorker only ever sets feature.meet) — proving the child-GC arm
	// still fires is proof enough that nothing in this package's worker
	// code path branches on that toggle.
	w := meetWorker(pool, true, configuredCfg, wrooms)
	w.tick(context.Background())

	if !wrooms.sawCall("DeleteRoom:" + b.RoomName) {
		t.Errorf("breakout worker arms must never gate on feature.meet_breakouts; calls=%v", wrooms.calls)
	}
}

// TestWorkerReconcileBreakoutAbsentSweep proves eng retro finding #4: the
// absentSince sweep at the top of reconcileBreakoutPresence settles (stamps
// or drops) every entry whose meeting leaves the candidate set on the very
// tick it happens — never lets it linger.
func TestWorkerReconcileBreakoutAbsentSweep(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	// (c) the phantom-participant hole: an assignee who is genuinely absent
	// from every room (including the parent) when the host closes breakouts
	// before the grace's second tick must still get left_at stamped by the
	// very next tick's sweep — otherwise gcLostWebhooks' NOT EXISTS(open
	// participants) predicate blocks forever, and the entry would linger in
	// absentSince across every future tick.
	t.Run("closed-breakout phantom gets stamped left_at by the sweep", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "brksweepphhost")
		member := meetTestUser(t, pool, "brksweepphmember")
		meetingID := createTestMeeting(t, h, host, "Breakout absent-sweep phantom test")
		if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		identity := fmt.Sprintf("u:%d", member)
		if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
			t.Fatalf("mark live: %v", err)
		}

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms() // absent from every room, both ticks
		w := meetWorker(pool, true, configuredCfg, wrooms)

		w.tick(context.Background()) // first absent tick — recorded, not stamped
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Fatalf("must not be stamped on the first absent tick")
		}
		if _, ok := w.absentSince[fmt.Sprintf("%d/%s", meetingID, identity)]; !ok {
			t.Fatalf("expected an absentSince entry after the first absent tick")
		}

		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		// Without the fix, drainBreakoutAssignments would never select this
		// meeting again (no open breakouts left) and left_at would never
		// stamp.
		w.tick(context.Background())
		if got := leftAt(t, pool, meetingID, identity); got == nil {
			t.Errorf("the absent-sweep must stamp left_at once the meeting leaves the candidate set")
		}
		if _, ok := w.absentSince[fmt.Sprintf("%d/%s", meetingID, identity)]; ok {
			t.Errorf("the swept entry must be removed from absentSince, not linger")
		}
	})

	// (a)+(b): a stale entry from a CLOSED session must not linger
	// (unbounded growth) and must not poison a NEW breakout session on the
	// same meeting/identity — the map key is byte-identical across sessions,
	// so an unswept entry would make the new session's own first absent
	// tick stamp immediately (destructive-early).
	t.Run("stale entry from a closed session does not poison a new session's first tick", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "brksweepstalehost")
		member := meetTestUser(t, pool, "brksweepstalemember")
		meetingID := createTestMeeting(t, h, host, "Breakout absent-sweep staleness test")
		if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		identity := fmt.Sprintf("u:%d", member)
		mainRoom := roomNameFor(t, pool, meetingID)
		if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
			t.Fatalf("mark live: %v", err)
		}

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b1 := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b1.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign session 1: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms()
		w := meetWorker(pool, true, configuredCfg, wrooms)

		w.tick(context.Background()) // session 1's first absent tick — recorded, not stamped

		// Member returns to the parent room before the host closes the
		// breakout — a legitimate "back to main" story, not an actual
		// departure; the sweep must clear the entry without stamping.
		wrooms.setParticipants(mainRoom, []string{identity})
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		w.tick(context.Background()) // the sweep settles the stale entry
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Fatalf("a member who returned to the parent room must not be stamped left_at")
		}
		if len(w.absentSince) != 0 {
			t.Fatalf("absentSince must be empty once session 1's entry is swept; got %v", w.absentSince)
		}

		// A second breakout session on the SAME meeting/identity — the map
		// key is byte-identical to session 1's.
		rr = meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("reopen: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b2 := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b2.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign session 2: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		wrooms.setParticipants(mainRoom, nil) // absent again, session 2

		w.tick(context.Background()) // session 2's OWN first absent tick
		if got := leftAt(t, pool, meetingID, identity); got != nil {
			t.Errorf("a stale entry from a closed session must not stamp left_at on a NEW session's first absent tick")
		}

		w.tick(context.Background()) // session 2's second consecutive absent tick
		if got := leftAt(t, pool, meetingID, identity); got == nil {
			t.Errorf("the new session's own 2-tick grace must still stamp normally")
		}
		if len(w.absentSince) != 0 {
			t.Errorf("absentSince must return to empty once every entry settles; got %v", w.absentSince)
		}
	})

	// map entry count returns to zero once a meeting ENDS (not just closes
	// its breakouts) — the sweep's candidate set excludes non-'live' meetings
	// too (drainOpenBreakoutRooms filters m.state = 'live').
	t.Run("absentSince returns to zero after the meeting ends", func(t *testing.T) {
		h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
		host := meetTestUser(t, pool, "brksweependhost")
		member := meetTestUser(t, pool, "brksweependmember")
		meetingID := createTestMeeting(t, h, host, "Breakout absent-sweep end test")
		if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
			t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
			t.Fatalf("mark live: %v", err)
		}

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		b := decodeOpenedBreakouts(t, rr)[0]
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
			fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		wrooms := newFakeRooms()
		w := meetWorker(pool, true, configuredCfg, wrooms)
		w.tick(context.Background()) // first absent tick — recorded

		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		w.tick(context.Background()) // sweep settles the entry (meeting no longer 'live')

		if len(w.absentSince) != 0 {
			t.Errorf("absentSince must return to zero after the meeting ends; got %v", w.absentSince)
		}
	})
}

// TestWorkerReconcileBreakoutAbsentSweepRetriesOnTransientError is the B3
// confirm-pass fix (eng #5/#6): a transient ListParticipants error while
// settling a stale absentSince entry must retain the entry for a retry next
// tick, never delete it outright — deleting on a transient error used to
// re-open the exact phantom-participant hole this sweep exists to close,
// for that one identity, on every hiccup.
func TestWorkerReconcileBreakoutAbsentSweepRetriesOnTransientError(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	h := meetHandlerWithBreakouts(pool, newFakeRooms(), true)
	host := meetTestUser(t, pool, "brksweeperrhost")
	member := meetTestUser(t, pool, "brksweeperrmember")
	meetingID := createTestMeeting(t, h, host, "Breakout absent-sweep transient-error test")
	if rr := meetDo(t, h, member, "POST", fmt.Sprintf("/meet/%d/join", meetingID), ""); rr.Code != http.StatusOK {
		t.Fatalf("join: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	identity := fmt.Sprintf("u:%d", member)
	mainRoom := roomNameFor(t, pool, meetingID)
	if _, err := pool.Exec(context.Background(), `UPDATE meetings SET state = 'live' WHERE id = $1`, meetingID); err != nil {
		t.Fatalf("mark live: %v", err)
	}

	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts", meetingID), `{"count":1}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("open: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	b := decodeOpenedBreakouts(t, rr)[0]
	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/assign", meetingID),
		fmt.Sprintf(`{"targetUserId":%d,"breakoutId":%d}`, member, b.BreakoutID)); rr.Code != http.StatusNoContent {
		t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	wrooms := newFakeRooms() // absent from every room, every tick below
	w := meetWorker(pool, true, configuredCfg, wrooms)

	w.tick(context.Background()) // first absent tick — recorded, not stamped

	if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/breakouts/close", meetingID), ""); rr.Code != http.StatusNoContent {
		t.Fatalf("close: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// the meeting has left the candidate set — the sweep now owns this entry.
	// Inject a transient failure for its ListParticipants settle-check.
	wrooms.errs[fmt.Sprintf("ListParticipants:%s", mainRoom)] = errors.New("sfu temporarily unreachable")

	w.tick(context.Background()) // the sweep's settle-check errors transiently
	if got := leftAt(t, pool, meetingID, identity); got != nil {
		t.Fatalf("a transient sweep error must never stamp left_at")
	}
	if _, ok := w.absentSince[fmt.Sprintf("%d/%s", meetingID, identity)]; !ok {
		t.Fatalf("a transient sweep error must RETAIN the entry for a retry, not drop it")
	}

	// the transient failure clears — the very next tick gets a definitive
	// answer and settles the entry for good.
	delete(wrooms.errs, fmt.Sprintf("ListParticipants:%s", mainRoom))

	w.tick(context.Background())
	if got := leftAt(t, pool, meetingID, identity); got == nil {
		t.Errorf("the retry, once it gets a clean answer, must stamp left_at")
	}
	if _, ok := w.absentSince[fmt.Sprintf("%d/%s", meetingID, identity)]; ok {
		t.Errorf("the entry must be dropped once definitively settled")
	}
}

// TestWorkerReconcileCaptionsCrashedBot proves leg (a): a captionsOn=true
// meeting whose room the ASR sidecar no longer lists in Status() gets the
// flag flipped off (worker-plane) + a captions_state{on:false} push once
// captionsSince is stale — but a FRESH captionsSince (a Start still in
// flight against a flag commit reconcile cannot yet see in Status()) is
// left untouched this tick (F5's start-grace).
func TestWorkerReconcileCaptionsCrashedBot(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}

	t.Run("stale captionsSince -> flag off + push", func(t *testing.T) {
		captions := newFakeCaptions() // Status() reports zero sessions
		h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)
		host := meetTestUser(t, pool, "workercapsstalehost")
		meetingID := createTestMeeting(t, h, host, "Worker captions crashed stale test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		// Backdate captionsSince past the grace window — the bot crashed a
		// while ago, not mid-Start.
		if _, err := pool.Exec(context.Background(),
			`UPDATE meetings SET settings = jsonb_set(settings, '{captionsSince}', to_jsonb(now() - interval '2 hours')) WHERE id = $1`,
			meetingID); err != nil {
			t.Fatalf("backdate captionsSince: %v", err)
		}

		w := meetWorkerCaptions(pool, true, configuredCfg, newFakeRooms(), captions)
		w.tick(context.Background())

		var on bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
			meetingID).Scan(&on); err != nil {
			t.Fatalf("query captionsOn: %v", err)
		}
		if on {
			t.Error("want captionsOn flipped false for a stale crashed session")
		}
		if !sawCaptionsPush(t, pool, host, false) {
			t.Error("want an off captions_state push from the worker's crashed-session flip")
		}
	})

	t.Run("fresh captionsSince -> untouched this tick", func(t *testing.T) {
		captions := newFakeCaptions() // Status() reports zero sessions — a Start still in flight
		h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)
		host := meetTestUser(t, pool, "workercapsfreshhost")
		meetingID := createTestMeeting(t, h, host, "Worker captions crashed fresh test")
		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
		}

		w := meetWorkerCaptions(pool, true, configuredCfg, newFakeRooms(), captions)
		w.tick(context.Background())

		var on bool
		if err := pool.QueryRow(context.Background(),
			`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
			meetingID).Scan(&on); err != nil {
			t.Fatalf("query captionsOn: %v", err)
		}
		if !on {
			t.Error("want captionsOn left true this tick — captionsSince is fresh (F5's start-grace)")
		}
	})
}

// TestWorkerReconcileCaptionsNilControllerConverges proves eng retro finding
// #5's worker-side half: leg (a) must NOT no-op just because no
// CaptionsController is configured on this box — a nil controller means no
// live session can EVER exist (h.captions is the only thing that ever calls
// Start), so a stale captionsOn=true row must still converge to OFF once
// past the captionsSince grace, exactly like B2's reconcileRecordingsDBOnly
// converges recording rows with a nil EgressController
// (TestWorkerDBOnlyRecordingLegsRunWithNilEgress, this file).
func TestWorkerReconcileCaptionsNilControllerConverges(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}

	h := meetHandler(pool, newFakeRooms())
	host := meetTestUser(t, pool, "workercapsnilhost")
	meetingID := createTestMeeting(t, h, host, "Worker captions nil-controller test")

	// Seed captionsOn=true directly via the reducer — there is no Go route
	// that can do this on a box with no ASR sidecar configured at all
	// (startCaptions 503s when h.captions == nil), but a row can already be
	// ON from before ASR_URL was unset, or a fixture the way this test
	// simulates it.
	if _, err := pool.Exec(context.Background(), `SELECT meeting_captions_set($1, $2, true)`, host, meetingID); err != nil {
		t.Fatalf("seed captionsOn: %v", err)
	}
	// Backdate captionsSince past the grace window.
	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET settings = jsonb_set(settings, '{captionsSince}', to_jsonb(now() - interval '2 hours')) WHERE id = $1`,
		meetingID); err != nil {
		t.Fatalf("backdate captionsSince: %v", err)
	}

	w := meetWorker(pool, true, configuredCfg, newFakeRooms()) // captions == nil
	w.tick(context.Background())

	var on bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
		meetingID).Scan(&on); err != nil {
		t.Fatalf("query captionsOn: %v", err)
	}
	if on {
		t.Error("a stale captionsOn=true row must converge to OFF even with a nil CaptionsController")
	}
	if !sawCaptionsPush(t, pool, host, false) {
		t.Error("want an off captions_state push from the worker's nil-controller flip")
	}
}

// TestWorkerReconcileCaptionsOrphanedSession proves leg (b): a Status()-
// reported session whose meeting is no longer captioning (captionsOn
// already false — a lost Stop) gets Stop retried; a session on an ENDED
// meeting additionally gets the DeleteRoom backstop once captionsSince
// clears the SAME F5 grace leg (a) uses.
func TestWorkerReconcileCaptionsOrphanedSession(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)

	t.Run("captionsOn already false -> Stop retried, no DeleteRoom", func(t *testing.T) {
		captions := newFakeCaptions()
		h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)
		host := meetTestUser(t, pool, "workercapsorphanhost")
		meetingID := createTestMeeting(t, h, host, "Worker captions orphaned test")
		room := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		rr = meetDo(t, h, host, "DELETE", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("stop: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		// The sidecar's own Stop is treated as lost — Status() still reports
		// the room live even though the flag already reads off.
		captions.setSessions([]string{room})

		wrooms := newFakeRooms()
		w := meetWorkerCaptions(pool, true, configuredCfg, wrooms, captions)
		w.tick(context.Background())

		if !captions.sawCall("Stop:" + room) {
			t.Errorf("want Stop retried for the orphaned session, calls=%v", captions.calls)
		}
		if wrooms.sawCall("DeleteRoom:" + room) {
			t.Errorf("a non-ended meeting must not get the DeleteRoom backstop; calls=%v", wrooms.calls)
		}
	})

	t.Run("ended meeting -> Stop retried + DeleteRoom backstop", func(t *testing.T) {
		captions := newFakeCaptions()
		h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)
		host := meetTestUser(t, pool, "workercapsendedhost")
		meetingID := createTestMeeting(t, h, host, "Worker captions ended backstop test")
		room := roomNameFor(t, pool, meetingID)

		rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		// Backdate captionsSince past the grace so the destructive leg is not
		// held back by F5's start-grace.
		if _, err := pool.Exec(context.Background(),
			`UPDATE meetings SET settings = jsonb_set(settings, '{captionsSince}', to_jsonb(now() - interval '2 hours')) WHERE id = $1`,
			meetingID); err != nil {
			t.Fatalf("backdate captionsSince: %v", err)
		}
		if rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/end", meetingID), ""); rr.Code != http.StatusNoContent {
			t.Fatalf("end: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		captions.setSessions([]string{room}) // the bot never got the memo — still connected

		wrooms := newFakeRooms()
		wrooms.setRooms([]string{room}) // the room is still live on the SFU too (the bot keeps it non-empty)
		w := meetWorkerCaptions(pool, true, configuredCfg, wrooms, captions)
		w.tick(context.Background())

		if !captions.sawCall("Stop:" + room) {
			t.Errorf("want Stop retried on the ended meeting too, calls=%v", captions.calls)
		}
		if !wrooms.sawCall("DeleteRoom:" + room) {
			t.Errorf("want the DeleteRoom backstop for the ended meeting's still-live room, calls=%v", wrooms.calls)
		}
	})
}

// TestWorkerReconcileCaptionsIgnoresToggleOff proves the F11/D11 drain pin
// at the worker level (captions_test.go proves it at the route level): the
// reconcile arm runs identically whether the Worker's flags carry
// feature.meet_captions ON or OFF, because the worker never checks that
// toggle at all — only feature.meet gates whether tick's body runs.
func TestWorkerReconcileCaptionsIgnoresToggleOff(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetSingleConnPool(t, dsn)
	if _, err := pool.Exec(context.Background(), "SET app.capture_notify = 'on'"); err != nil {
		t.Fatalf("SET app.capture_notify: %v", err)
	}
	captions := newFakeCaptions()
	h := meetHandlerWithCaptions(pool, newFakeRooms(), captions, true)

	host := meetTestUser(t, pool, "workercapstoggleoffhost")
	meetingID := createTestMeeting(t, h, host, "Worker captions toggle-off drain test")
	rr := meetDo(t, h, host, "POST", fmt.Sprintf("/meet/%d/captions", meetingID), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("start: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE meetings SET settings = jsonb_set(settings, '{captionsSince}', to_jsonb(now() - interval '2 hours')) WHERE id = $1`,
		meetingID); err != nil {
		t.Fatalf("backdate captionsSince: %v", err)
	}

	// The worker's OWN flags carry no feature.meet_captions entry at all
	// (meetWorkerCaptions only ever sets feature.meet) — proving the crashed-
	// session leg still fires is proof enough that nothing in this arm
	// branches on that toggle.
	w := meetWorkerCaptions(pool, true, configuredCfg, newFakeRooms(), captions)
	w.tick(context.Background())

	var on bool
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((settings->>'captionsOn')::boolean, false) FROM meetings WHERE id = $1`,
		meetingID).Scan(&on); err != nil {
		t.Fatalf("query captionsOn: %v", err)
	}
	if on {
		t.Error("captions worker arms must never gate on feature.meet_captions")
	}
}

// TestWorkerExpireLocalCaptureLeases (M5): the worker-plane expiry arm —
// meeting_local_capture_lease_expire, wired into tick's drain posture —
// flips a TTL-past live lease 'expired' and stops its recording truthfully,
// while a lease inside its TTL and already-terminal rows converge to
// nothing. DB-gated over the real reducers (worker_semantic_test.go genre);
// the leg is flag-free by construction (drain-what's-committed), so the
// worker here carries feature.meet OFF.
func TestWorkerExpireLocalCaptureLeases(t *testing.T) {
	dsn := meetDSN(t)
	pool := meetTestPool(t, dsn)
	ctx := context.Background()

	host := meetTestUser(t, pool, "localcapexpirehost")
	var meetingID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO meetings (title, owner_user_id, state) VALUES ('local-cap-expire', $1, 'live') RETURNING id`,
		host).Scan(&meetingID); err != nil {
		t.Fatalf("meeting: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `SELECT meeting_end($1, $2)`, host, meetingID) })
	if _, err := pool.Exec(ctx,
		`INSERT INTO meeting_participants (meeting_id, user_id, identity, role, joined_at)
		 VALUES ($1, $2::bigint, 'u:' || $2::text, 'host', now())`, meetingID, host); err != nil {
		t.Fatalf("participant: %v", err)
	}

	var recID, generation int64
	if err := pool.QueryRow(ctx,
		`SELECT (l->>'recordingId')::bigint, (l->>'leaseGeneration')::bigint
		   FROM meeting_local_capture_lease_acquire($1, $2, 'wklocalcap-dev', '["microphone"]'::jsonb,
		        '{"platform":"darwin","captureApiVersion":"e1"}'::jsonb) l`,
		host, meetingID).Scan(&recID, &generation); err != nil {
		t.Fatalf("lease acquire: %v", err)
	}
	if recID == 0 || generation != 1 {
		t.Fatalf("the lease binds its recording at generation 1: rec=%d gen=%d", recID, generation)
	}

	w := meetWorker(pool, false, configuredCfg, newFakeRooms())

	// Inside its TTL: the leg is a no-op.
	w.expireLocalCaptureLeases(ctx)
	var leaseState, recState string
	if err := pool.QueryRow(ctx,
		`SELECT l.lease_state, r.rec_state
		   FROM meeting_local_capture_leases l
		   JOIN meeting_semantic_recordings r ON r.id = l.recording_id
		  WHERE l.meeting_id = $1 AND l.device_id = 'wklocalcap-dev'`,
		meetingID).Scan(&leaseState, &recState); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if leaseState != "live" || recState != "active" {
		t.Fatalf("a lease inside its TTL must stay live/active: lease=%s rec=%s", leaseState, recState)
	}

	// Force the TTL: the drain flips the lease 'expired' and its still-active
	// recording stops truthfully — the stopped/expired flip, never a
	// refreshed deadline.
	if _, err := pool.Exec(ctx,
		`UPDATE meeting_local_capture_leases SET expires_at = now() - interval '1 minute'
		  WHERE meeting_id = $1 AND device_id = 'wklocalcap-dev'`,
		meetingID); err != nil {
		t.Fatalf("backdate expiry: %v", err)
	}
	w.expireLocalCaptureLeases(ctx)

	if err := pool.QueryRow(ctx,
		`SELECT l.lease_state, r.rec_state
		   FROM meeting_local_capture_leases l
		   JOIN meeting_semantic_recordings r ON r.id = l.recording_id
		  WHERE l.meeting_id = $1 AND l.device_id = 'wklocalcap-dev'`,
		meetingID).Scan(&leaseState, &recState); err != nil {
		t.Fatalf("read back 2: %v", err)
	}
	if leaseState != "expired" || recState != "stopped" {
		t.Fatalf("the TTL-past lease must flip expired with its recording stopped: lease=%s rec=%s", leaseState, recState)
	}

	// Idempotence: a second drain over terminal rows converges to nothing.
	w.expireLocalCaptureLeases(ctx)
	if err := pool.QueryRow(ctx,
		`SELECT l.lease_state, r.rec_state
		   FROM meeting_local_capture_leases l
		   JOIN meeting_semantic_recordings r ON r.id = l.recording_id
		  WHERE l.meeting_id = $1 AND l.device_id = 'wklocalcap-dev'`,
		meetingID).Scan(&leaseState, &recState); err != nil {
		t.Fatalf("read back 3: %v", err)
	}
	if leaseState != "expired" || recState != "stopped" {
		t.Fatalf("terminal rows never resurrect: lease=%s rec=%s", leaseState, recState)
	}

	// The fault arm: a closed pool makes the expirer query fail — the leg
	// must log-and-continue (no panic, no half-mutated state).
	pool.Close()
	w.expireLocalCaptureLeases(ctx)
}
