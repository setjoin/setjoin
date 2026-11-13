package drive

// DB-backed P5 WORM tests: the gxp put-version wormPending response
// override, the worker retry tick, and the audit-chain verify route
// (AUTOPLAN correction #2). Genre: content_live_test.go / branches_test.go.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// driveLivePostVersionRawWithManifest POSTs a version through the real HTTP
// pipeline for an already-uploaded chunk and returns the raw recorder (not
// just the parsed versionId) so callers can inspect the full response body
// (wormPending).
func driveLivePostVersionRawWithManifest(t *testing.T, h *Handler, userID, nodeID int64, content []byte, sha string) *httptest.ResponseRecorder {
	t.Helper()
	sum := sha256.Sum256(content)
	body, _ := json.Marshal(map[string]any{
		"contentSha256": hex.EncodeToString(sum[:]),
		"size":          len(content),
		"contentType":   "text/plain",
		"manifest":      []chunkManifestEntry{{Sha256: sha, Size: len(content)}},
	})
	req := httptest.NewRequest(http.MethodPost, "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestPostVersionGxpWormPending: a gxp space with a failing Retention
// produces a 2xx response carrying wormPending:true (G1 — the save is never
// blocked by a storage-side lock failure); a healthy Retention produces
// wormPending:false; a non-gxp (regular) space never calls Retention at all
// (the reducer's own wormPending:false rides through untouched).
func TestPostVersionGxpWormPending(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvwormresp")
	withFeatureToggleEnabled(t, pool, "feature.drive_compliance")

	t.Run("regular space never calls Retention", func(t *testing.T) {
		ret := &fakeRetention{failKeys: map[string]bool{}}
		h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
		h.SetRetention(ret)
		spaceID := drivePersonalSpaceID(t, h, userID)
		_, _ = driveLiveFileWithVersion(t, h, userID, spaceID, "reg.txt", []byte("v1"))
		if len(ret.calls) != 0 {
			t.Errorf("regular space: Retention calls = %d, want 0", len(ret.calls))
		}
	})

	t.Run("gxp healthy Retention -> wormPending false", func(t *testing.T) {
		ret := &fakeRetention{failKeys: map[string]bool{}}
		h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
		h.SetRetention(ret)
		spaceID := driveLiveCreateGxpSpace(t, h, userID)
		nodeID := driveLiveCreateFile(t, h, userID, spaceID, "gxp-ok.txt")
		content := []byte("gxp v1")
		sha := driveLiveUploadChunk(t, h, userID, spaceID, content)
		rr := driveLivePostVersionRawWithManifest(t, h, userID, nodeID, content, sha)
		if rr.Code != http.StatusCreated {
			t.Fatalf("POST version: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			WormPending bool `json:"wormPending"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.WormPending {
			t.Error("healthy Retention: want wormPending=false")
		}
		if len(ret.calls) == 0 {
			t.Error("gxp space: expected at least one PutObjectRetention call")
		}
	})

	t.Run("gxp failing Retention -> 2xx wormPending true", func(t *testing.T) {
		ret := &fakeRetention{failKeys: map[string]bool{}}
		h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
		h.SetRetention(ret)
		spaceID := driveLiveCreateGxpSpace(t, h, userID)
		nodeID := driveLiveCreateFile(t, h, userID, spaceID, "gxp-fail.txt")
		content := []byte("gxp v1 fail")
		sha := driveLiveUploadChunk(t, h, userID, spaceID, content)
		// Mark the key this exact chunk resolves to (applyWormLocks: "drive/"+scope+"/"+sha) as failing.
		ret.failKeys["drive/s"+strconv.FormatInt(spaceID, 10)+"/"+sha] = true

		rr := driveLivePostVersionRawWithManifest(t, h, userID, nodeID, content, sha)
		if rr.Code != http.StatusCreated {
			t.Fatalf("POST version (gxp, failing retention): want 201 (G1 — never fails the save), got %d: %s", rr.Code, rr.Body.String())
		}
		var out struct {
			WormPending bool `json:"wormPending"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !out.WormPending {
			t.Error("failing Retention: want wormPending=true")
		}
	})
}

// TestListSpacesAdminMergesWormPending: the ?admin=1 spaces read merges each
// space's WORM-pending chunk count (G1 admin visibility). Without the merge the
// admin compliance queue always read 0/clean even when chunks were genuinely
// pending — the frontend was built against a contract the Go read never filled.
func TestListSpacesAdminMergesWormPending(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvwormadmin")
	withFeatureToggleEnabled(t, pool, "feature.drive_compliance")

	// Grant Super Admin (role_group 1 → drive.view) so ?admin=1 is authorized.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, userID); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, userID) //nolint:errcheck
	})

	// gxp space + a version whose Retention apply fails → a genuinely pending chunk.
	ret := &fakeRetention{failKeys: map[string]bool{}}
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	h.SetRetention(ret)
	spaceID := driveLiveCreateGxpSpace(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "pend.txt")
	content := []byte("gxp pending")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, content)
	ret.failKeys["drive/s"+strconv.FormatInt(spaceID, 10)+"/"+sha] = true
	if rr := driveLivePostVersionRawWithManifest(t, h, userID, nodeID, content, sha); rr.Code != http.StatusCreated {
		t.Fatalf("POST version: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	rr := driveLiveDo(t, h, userID, "GET", "/drive/spaces?admin=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin spaces: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var spaces []struct {
		ID          int64 `json:"id"`
		WormPending int64 `json:"wormPending"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &spaces); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var found bool
	for _, s := range spaces {
		if s.ID == spaceID {
			found = true
			if s.WormPending < 1 {
				t.Errorf("space %d: wormPending = %d, want >= 1 (chunk is genuinely pending)", spaceID, s.WormPending)
			}
		}
	}
	if !found {
		t.Fatalf("gxp space %d absent from ?admin=1 response", spaceID)
	}
}

// TestWorkerRetryClearsPending: a chunk saved with no Retention capability
// wired on the handler stays genuinely worm-pending (the derived predicate
// drive_worm_pending.pg proves); one worker tick with a healthy fake
// Retention clears it.
func TestWorkerRetryClearsPending(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvwormretry")
	withFeatureToggleEnabled(t, pool, "feature.drive_compliance")

	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	// No retention wired on h — this test drives the WORKER's own retry path,
	// not the put-version hook, so the chunk starts genuinely pending.
	spaceID := driveLiveCreateGxpSpace(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "retry.txt")
	content := []byte("retry me")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, content)
	rr := driveLivePostVersionRawWithManifest(t, h, userID, nodeID, content, sha)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST version: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	scopeKey := "s" + strconv.FormatInt(spaceID, 10)
	if !driveChunkIsWormPending(t, pool, scopeKey, sha) {
		t.Fatal("precondition: chunk must be worm-pending before the worker tick")
	}

	ret := &fakeRetention{failKeys: map[string]bool{}}
	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, newFakeStore(), "b", discardLogger())
	w.SetRetention(ret)
	w.retryPendingWormLocks(context.Background())

	if driveChunkIsWormPending(t, pool, scopeKey, sha) {
		t.Error("worker retry: chunk still worm-pending after a successful PutObjectRetention")
	}
	if len(ret.calls) == 0 {
		t.Error("worker retry: expected at least one PutObjectRetention call")
	}
}

// TestWorkerRetryNilRetentionNoOps: a worker with no Retention capability
// wired must not panic or query the DB — the tick is a clean no-op (spec
// §12-22 fallback).
func TestWorkerRetryNilRetentionNoOps(t *testing.T) {
	pool := driveLivePool(t)
	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, newFakeStore(), "b", discardLogger())
	w.retryPendingWormLocks(context.Background()) // must not panic
}

// driveChunkIsWormPending reads the worm_pending generated column directly
// (drive_chunks, C3) for one chunk.
func driveChunkIsWormPending(t *testing.T, pool *pgxpool.Pool, scopeKey, sha string) bool {
	t.Helper()
	var pending bool
	if err := pool.QueryRow(context.Background(), `
		SELECT worm_pending FROM drive_chunks WHERE scope_key = $1 AND sha256 = $2`, scopeKey, sha,
	).Scan(&pending); err != nil {
		t.Fatalf("read worm_pending column: %v", err)
	}
	return pending
}

// ── audit-chain verify route (AUTOPLAN correction #2) ───────────────────────

// TestVerifyAuditChain_RequiresDriveView: a caller with no drive.view
// permission is refused, even though the space is theirs.
func TestVerifyAuditChain_RequiresDriveView(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvverifynone")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)

	rr := driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/audit/verify", nil)
	if rr.Code != http.StatusForbidden {
		t.Errorf("no drive.view: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestVerifyAuditChain_HappyPath: a Super Admin (role_group_id=1, V114 seed,
// carries every permission incl. drive.view) gets {checked>=1, broken:[]}
// for a space with at least one audited action (drive_space_create's own
// 'space.create' row, exercised by drivePersonalSpaceID's auto-provision).
func TestVerifyAuditChain_HappyPath(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvverifyok")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, userID); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, userID) //nolint:errcheck
	})

	rr := driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/audit/verify", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify chain: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Checked int     `json:"checked"`
		Broken  []int64 `json:"broken"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Checked == 0 {
		t.Error("checked = 0, want at least the space.create audit row")
	}
	if len(out.Broken) != 0 {
		t.Errorf("broken = %v, want empty (chain untampered)", out.Broken)
	}
}
