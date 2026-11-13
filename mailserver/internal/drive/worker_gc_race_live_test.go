package drive

// B2 (2026-07-11 codebase review): drive_chunk_gc_queue processing commits
// the drive_chunks row delete, then calls storage RemoveObject OUTSIDE that
// transaction. A concurrent re-upload of the exact same content-addressed
// chunk (drive_chunk_register's `INSERT ... ON CONFLICT DO NOTHING`) can
// recreate the (scope_key, sha256) row in the gap between commit and
// RemoveObject, pointing a brand-new ref_count=0 row at the SAME storage key
// GC is about to delete. Left unguarded, a later drive_file_put_version
// bumping that row to ref_count=1 links a live version to deleted bytes.
//
// afterGCRemoveCheckHook (worker.go, test-only) lands the concurrent upload
// after GC's final row-absence check while GC still owns the shared advisory
// lock. The uploader must wait, then re-promote after GC's delete.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func TestWorkerGCChunksRaceAgainstConcurrentReupload(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvgcrace")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "gc-race-me.bin")
	data := []byte("bytes racing the chunk GC queue #" + strconv.FormatInt(nodeID, 10))
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	driveLivePutVersion(t, h, userID, nodeID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	storageKey := "drive/g/" + sha
	if _, ok := fake.objects[storageKey]; !ok {
		t.Fatalf("setup: canonical chunk object missing at %s", storageKey)
	}

	// Trash + destroy (soft), then hard-destroy directly (P6 two-level trash
	// skip, same as TestWorkerGCChunksLifecycle) — cascades the version delete
	// -> ref_count trigger -> zero-ref -> drive_chunk_gc_queue.
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

	staged, err := StageChunk(context.Background(), fake, "b", sha, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("stage concurrent re-upload: %v", err)
	}
	defer staged.Cleanup(context.Background(), fake, "b")

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, fake, "b", discardLogger())
	// Land a concurrent re-upload of the SAME content-addressed chunk exactly
	// after GC's final DB check and before RemoveObject. CommitStagedChunk
	// blocks on GC's advisory lock, so it can only promote after GC deletes.
	done := make(chan error, 1)
	w.afterGCRemoveCheckHook = func() {
		w.afterGCRemoveCheckHook = nil
		go func() {
			done <- dbscope.RunUserScoped(context.Background(), pool, userID, func(tx pgx.Tx) error {
				return CommitStagedChunk(context.Background(), tx, fake, "b", userID, spaceID, staged)
			})
		}()
	}
	if err := w.gcChunks(context.Background()); err != nil {
		t.Fatalf("gcChunks: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("concurrent re-upload: %v", err)
	}

	if _, ok := fake.objects[storageKey]; !ok {
		t.Fatal("BUG: gcChunks removed the storage object even though a concurrent re-upload re-registered it — a future version commit would point at deleted bytes")
	}
	var chunkRows int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_chunks WHERE scope_key='g' AND sha256=$1`, sha).Scan(&chunkRows); err != nil {
		t.Fatalf("count drive_chunks: %v", err)
	}
	if chunkRows != 1 {
		t.Fatalf("want the re-registered drive_chunks row to survive, got count=%d", chunkRows)
	}
}
