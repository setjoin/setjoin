package drive

// White-box (package drive) DB-guarded chunk happy path (Task 19 test
// bullet 3 — "the register call needs the DB"). Store is still a fakeStore
// (no live MinIO test lane in this repo, mirrors the batch-1 correction #5
// posture for content.go's Range tests); the DB round trip through
// drive_chunk_register is real. Skip-if-no-DB, the audit_test.go genre.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestPutChunkThenHeadChunkLiveRoundTrip(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvchunk")

	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	// Auto-provision the personal space (mirrors listSpaces) and read its id.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/drive/spaces", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/spaces: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var spaces []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &spaces); err != nil || len(spaces) == 0 {
		t.Fatalf("decode spaces: err=%v body=%s", err, rr.Body.String())
	}
	spaceID := spaces[0].ID
	spaceParam := strconv.FormatInt(spaceID, 10)

	data := []byte("a live chunk round-tripped through the real reducer")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	putReq := httptest.NewRequest(http.MethodPut, "/drive/chunks/"+sha+"?space="+spaceParam, strings.NewReader(string(data)))
	putReq = putReq.WithContext(auth.ContextWithUser(putReq.Context(), &auth.Claims{UserID: userID}))
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusCreated {
		t.Fatalf("PUT chunk: want 201, got %d: %s", putRR.Code, putRR.Body.String())
	}

	headReq := httptest.NewRequest(http.MethodHead, "/drive/chunks/"+sha+"?space="+spaceParam, nil)
	headReq = headReq.WithContext(auth.ContextWithUser(headReq.Context(), &auth.Claims{UserID: userID}))
	headRR := httptest.NewRecorder()
	h.ServeHTTP(headRR, headReq)
	if headRR.Code != http.StatusOK {
		t.Errorf("HEAD chunk after PUT (own upload claim, I-4): want 200, got %d", headRR.Code)
	}
}

func TestChunkUploadAuthorityLocksClassificationUntilCommit(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvscope-lock")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	ctx := context.Background()

	uploadTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin upload tx: %v", err)
	}
	defer uploadTx.Rollback(ctx) //nolint:errcheck
	var scope string
	if err := uploadTx.QueryRow(ctx, `SELECT drive_chunk_upload_require($1, $2)`, userID, spaceID).Scan(&scope); err != nil {
		t.Fatalf("upload authority: %v", err)
	}
	if scope != "g" {
		t.Fatalf("initial scope = %q, want g", scope)
	}

	upgradeTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin upgrade tx: %v", err)
	}
	if _, err := upgradeTx.Exec(ctx, `SET LOCAL statement_timeout = '150ms'`); err != nil {
		_ = upgradeTx.Rollback(ctx)
		t.Fatalf("set statement timeout: %v", err)
	}
	_, err = upgradeTx.Exec(ctx, `SELECT drive_space_set_classification($1, $2, 'secure')`, userID, spaceID)
	_ = upgradeTx.Rollback(ctx)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "57014" {
		t.Fatalf("classification upgrade must wait on upload's FOR SHARE lock; got %v", err)
	}

	if err := uploadTx.Commit(ctx); err != nil {
		t.Fatalf("commit upload authority tx: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_space_set_classification($1, $2, 'secure')`, userID, spaceID); err != nil {
		t.Fatalf("classification upgrade after upload commit: %v", err)
	}
}
