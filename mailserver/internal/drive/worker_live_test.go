package drive

// White-box (package drive) DB-guarded chunk-GC lifecycle: upload a chunk,
// put a version referencing it, trash+destroy the node, then hard-destroy it
// (cascades the version delete -> ref_count trigger -> zero-ref ->
// drive_chunk_gc_queue), then run the worker's gcChunks and assert the
// storage object, the drive_chunks row, and the gc_queue row are all gone.
// Skip-if-no-DB.
//
// fix-before-continuing (P6 Task 9-12 batch): drive_node_destroy no longer
// physically deletes anything — P6's two-level trash (V117, plan Task 2)
// flipped it to a tier-2 purge mark; the bytes/versions survive a 30-day
// admin grace window. The physical delete this test exercises now lives in
// drive_node_destroy_hard (worker-only, called by drive_maintenance_sweep
// after grace expiry) — this test calls it directly to exercise gcChunks
// without waiting out the grace window.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func TestWorkerGCChunksLifecycle(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvgc")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "gc-me.bin")
	// Content must be unique per run: drive_chunks dedupes globally by
	// (scope_key='g', sha256) — a fixed byte string would collide with
	// whatever a PRIOR run of this same test left in tier-2 (a hard-destroyed
	// chunk drops to ref_count 0 and gets swept away, but a run that stopped
	// short of hard-destroy — e.g. mid-fix — leaves ref_count=1 forever,
	// which would silently mask the very zero-ref assertion this test makes).
	data := []byte("bytes destined for the chunk GC queue #" + strconv.FormatInt(nodeID, 10))
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	driveLivePutVersion(t, h, userID, nodeID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	storageKey := "drive/g/" + sha
	if _, ok := fake.objects[storageKey]; !ok {
		t.Fatalf("setup: canonical chunk object missing at %s", storageKey)
	}

	// Trash then destroy the node — cascades drive_file_versions ->
	// drive_version_chunks (ON DELETE CASCADE) -> the G7 dec-ref trigger ->
	// ref_count 0 -> trg_drive_chunk_zero_ref queues it for GC.
	trashReq := httptest.NewRequest(http.MethodPost, "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/trash", nil)
	trashReq = trashReq.WithContext(auth.ContextWithUser(trashReq.Context(), &auth.Claims{UserID: userID}))
	trashRR := httptest.NewRecorder()
	h.ServeHTTP(trashRR, trashReq)
	if trashRR.Code != http.StatusNoContent {
		t.Fatalf("trash node: want 204, got %d: %s", trashRR.Code, trashRR.Body.String())
	}
	destroyReq := httptest.NewRequest(http.MethodDelete, "/drive/nodes/"+strconv.FormatInt(nodeID, 10), nil)
	destroyReq = destroyReq.WithContext(auth.ContextWithUser(destroyReq.Context(), &auth.Claims{UserID: userID}))
	destroyRR := httptest.NewRecorder()
	h.ServeHTTP(destroyRR, destroyReq)
	if destroyRR.Code != http.StatusNoContent {
		t.Fatalf("destroy node: want 204, got %d: %s", destroyRR.Code, destroyRR.Body.String())
	}

	// P6 two-level trash: destroy only marks the tier-2 purge (bytes/versions
	// survive the 30-day admin grace). drive_node_destroy_hard is the
	// worker-only physical delete drive_maintenance_sweep calls after grace
	// expiry — call it directly here rather than clock-shifting a fixture.
	var hardDestroyed bool
	if err := pool.QueryRow(context.Background(), `SELECT drive_node_destroy_hard($1)`, nodeID).Scan(&hardDestroyed); err != nil {
		t.Fatalf("drive_node_destroy_hard: %v", err)
	}
	if !hardDestroyed {
		t.Fatalf("drive_node_destroy_hard($1=%d) returned false, want true", nodeID)
	}

	var queued int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_chunk_gc_queue WHERE scope_key='g' AND sha256=$1`, sha).Scan(&queued); err != nil {
		t.Fatalf("count gc_queue: %v", err)
	}
	if queued != 1 {
		t.Fatalf("setup: want the chunk queued for GC after destroy, got count=%d", queued)
	}

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", discardLogger())
	if err := w.gcChunks(context.Background()); err != nil {
		t.Fatalf("gcChunks: %v", err)
	}

	if _, ok := fake.objects[storageKey]; ok {
		t.Error("gcChunks must remove the storage object")
	}
	var chunkRows, queueRows int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_chunks WHERE scope_key='g' AND sha256=$1`, sha).Scan(&chunkRows); err != nil {
		t.Fatalf("count drive_chunks: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_chunk_gc_queue WHERE scope_key='g' AND sha256=$1`, sha).Scan(&queueRows); err != nil {
		t.Fatalf("count gc_queue: %v", err)
	}
	if chunkRows != 0 {
		t.Errorf("gcChunks must delete the drive_chunks row, got count=%d", chunkRows)
	}
	if queueRows != 0 {
		t.Errorf("gcChunks must delete the gc_queue row, got count=%d", queueRows)
	}
}

func TestWorkerCanonicalOrphanInventory(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvorphan")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)

	referencedData := []byte("registered canonical inventory object " + strconv.FormatInt(spaceID, 10))
	referencedSum := sha256.Sum256(referencedData)
	referencedSHA := hex.EncodeToString(referencedSum[:])
	if _, err := pool.Exec(context.Background(), `SELECT drive_chunk_register($1, $2, $3, $4)`,
		userID, spaceID, referencedSHA, len(referencedData)); err != nil {
		t.Fatalf("register referenced chunk: %v", err)
	}

	orphanData := []byte("unregistered canonical inventory object " + strconv.FormatInt(spaceID, 10))
	orphanSum := sha256.Sum256(orphanData)
	orphanSHA := hex.EncodeToString(orphanSum[:])
	lockedSum := sha256.Sum256([]byte("retained canonical inventory object " + strconv.FormatInt(spaceID, 10)))
	referencedKey := "drive/g/" + referencedSHA
	orphanKey := "drive/g/" + orphanSHA
	freshKey := "drive/g/" + strings.Repeat("e", 64)
	malformedKey := "drive/not-a-scope/" + strings.Repeat("f", 64)
	lockedKey := "drive/g/" + hex.EncodeToString(lockedSum[:])
	for key, data := range map[string][]byte{
		referencedKey: referencedData,
		orphanKey:     orphanData,
		freshKey:      []byte("fresh"),
		malformedKey:  []byte("unknown"),
		lockedKey:     []byte("retained"),
	} {
		fake.objects[key] = data
		fake.putTimes[key] = time.Now().Add(-25 * time.Hour)
	}
	fake.putTimes[freshKey] = time.Now()
	fake.removeErrs[lockedKey] = storage.ErrObjectLocked

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", discardLogger())
	if err := w.reapCanonicalOrphans(context.Background()); err != nil {
		t.Fatalf("reapCanonicalOrphans: %v", err)
	}
	if _, ok := fake.objects[orphanKey]; ok {
		t.Error("stale canonical object without a drive_chunks row must be reaped")
	}
	for _, key := range []string{referencedKey, freshKey, malformedKey, lockedKey} {
		if _, ok := fake.objects[key]; !ok {
			t.Errorf("inventory removed protected object %s", key)
		}
	}
}

func TestWorkerCanonicalOrphanRaceAgainstConcurrentUpload(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvorphanrace")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	data := []byte("canonical inventory race " + strconv.FormatInt(spaceID, 10))
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	key := "drive/g/" + sha
	fake.objects[key] = append([]byte(nil), data...)
	fake.putTimes[key] = time.Now().Add(-25 * time.Hour)

	staged, err := StageChunk(context.Background(), fake, "b", sha, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("stage concurrent upload: %v", err)
	}
	defer staged.Cleanup(context.Background(), fake, "b")

	done := make(chan error, 1)
	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", discardLogger())
	w.afterCanonicalCheckHook = func() {
		w.afterCanonicalCheckHook = nil
		go func() {
			done <- dbscope.RunUserScoped(context.Background(), pool, userID, func(tx pgx.Tx) error {
				return CommitStagedChunk(context.Background(), tx, fake, "b", userID, spaceID, staged)
			})
		}()
	}
	if err := w.reapCanonicalOrphans(context.Background()); err != nil {
		t.Fatalf("reapCanonicalOrphans: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("concurrent upload: %v", err)
	}
	if got, ok := fake.objects[key]; !ok || !bytes.Equal(got, data) {
		t.Fatalf("concurrent upload must leave canonical bytes present: ok=%v got=%q", ok, got)
	}
	var registered bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM drive_chunks WHERE scope_key='g' AND sha256=$1)`, sha).Scan(&registered); err != nil {
		t.Fatalf("check registered row: %v", err)
	}
	if !registered {
		t.Fatal("concurrent upload must leave a registered drive_chunks row")
	}
}
