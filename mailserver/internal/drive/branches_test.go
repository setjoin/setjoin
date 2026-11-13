package drive

// Live (DB-backed) tests for the branch/label routes — Task 9. Genre:
// content_live_test.go (white-box `package drive`, driveLivePool/
// driveLiveUser/driveLiveCreateFile/driveLiveUploadChunk/driveLivePutVersion/
// drivePersonalSpaceID). DB behavior itself is pgTAP-proven (P4 Tasks 1-8);
// this proves the Go translation layer + the BZ150->409 wire mapping.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// driveLiveFileWithVersion is a small end-to-end fixture: a file at the
// space root with one committed version (via the real chunk-upload +
// put-version HTTP pipeline), returning (nodeID, versionID).
func driveLiveFileWithVersion(t *testing.T, h *Handler, userID, spaceID int64, name string, content []byte) (int64, int64) {
	t.Helper()
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, name)
	sha := driveLiveUploadChunk(t, h, userID, spaceID, content)
	sum := sha256.Sum256(content)
	contentSha := hex.EncodeToString(sum[:])
	versionID := driveLivePutVersion(t, h, userID, nodeID, contentSha, len(content),
		[]chunkManifestEntry{{Sha256: sha, Size: len(content)}})
	return nodeID, versionID
}

func TestBranchCreateListRenameReview(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvbranch")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "budget.xlsx", []byte("v1"))

	// Create.
	rr := driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "budget-redo", "fromVersionId": versionID})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create branch: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		BranchID int64 `json:"branchId"`
	}
	driveLiveDecode(t, rr, &created)
	if created.BranchID == 0 {
		t.Fatal("branchId must be set")
	}

	// Duplicate name (case-insensitive) -> 409 BZ150.
	rr = driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "Budget-Redo", "fromVersionId": versionID})
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate branch name: want 409, got %d: %s", rr.Code, rr.Body.String())
	}
	var prob struct {
		Code string `json:"code"`
	}
	driveLiveDecode(t, rr, &prob)
	if prob.Code != "BZ150" {
		t.Errorf("duplicate branch name: code = %q, want BZ150", prob.Code)
	}

	// List — ffEligible true (fork == main head, still open).
	rr = driveLiveDo(t, h, userID, "GET", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list branches: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var list []branchOut
	driveLiveDecode(t, rr, &list)
	if len(list) != 1 || list[0].ID != created.BranchID {
		t.Fatalf("list branches: want [branch %d], got %v", created.BranchID, list)
	}
	if !list[0].FfEligible {
		t.Error("a fresh branch at the fork point must be ffEligible")
	}
	if list[0].Status != "open" {
		t.Errorf("status = %q, want open", list[0].Status)
	}

	// Rename.
	rr = driveLiveDo(t, h, userID, "PATCH", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10),
		map[string]any{"name": "budget-redo-2"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("rename branch: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Both name+status in one PATCH -> 422 BZ141.
	rr = driveLiveDo(t, h, userID, "PATCH", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10),
		map[string]any{"name": "x", "status": "review"})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("name+status together: want 422, got %d: %s", rr.Code, rr.Body.String())
	}

	// Status -> review.
	rr = driveLiveDo(t, h, userID, "PATCH", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10),
		map[string]any{"status": "review"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("set status review: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, userID, "GET", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches", nil)
	driveLiveDecode(t, rr, &list)
	if len(list) != 1 || list[0].Status != "review" || list[0].Name != "budget-redo-2" {
		t.Fatalf("after rename+review: %v", list)
	}
}

func TestBranchResolveFastForward(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvresolve")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "notes.txt", []byte("v1"))

	rr := driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "draft", "fromVersionId": versionID})
	var created struct {
		BranchID int64 `json:"branchId"`
	}
	driveLiveDecode(t, rr, &created)

	// Resolve ff: main hasn't moved since the fork, so this must succeed.
	rr = driveLiveDo(t, h, userID, "POST", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10)+"/resolve",
		map[string]any{"verb": "ff"})
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve ff: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	driveLiveDecode(t, rr, &out)
	if out["verb"] != "ff" {
		t.Errorf("resolve result = %v, want verb=ff", out)
	}

	// A second resolve on the now-merged branch -> 409 BZ150 (branch closed).
	rr = driveLiveDo(t, h, userID, "POST", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10)+"/resolve",
		map[string]any{"verb": "ff"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("resolve a merged branch: want 409, got %d: %s", rr.Code, rr.Body.String())
	}

	// Unknown verb -> 422 BZ141 (a fresh branch this time).
	rr = driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "draft2", "fromVersionId": versionID})
	driveLiveDecode(t, rr, &created)
	rr = driveLiveDo(t, h, userID, "POST", "/drive/branches/"+strconv.FormatInt(created.BranchID, 10)+"/resolve",
		map[string]any{"verb": "bogus"})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown verb: want 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestVersionLabelSetRemove(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvlabel")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	_, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "report.docx", []byte("v1"))

	rr := driveLiveDo(t, h, userID, "POST", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/labels",
		map[string]any{"label": "Approved"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("set label: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	// Idempotent re-set.
	rr = driveLiveDo(t, h, userID, "POST", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/labels",
		map[string]any{"label": "Approved"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("re-set label: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, userID, "DELETE", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/labels/Approved", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("remove label: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	// Removing again -> 404 BZ139 (label no longer exists).
	rr = driveLiveDo(t, h, userID, "DELETE", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/labels/Approved", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("remove already-removed label: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestBranchRoutesNonMemberAndAuth pins the G5/BZ139/viewer-403 trio + the
// pool-less 404-when-off path (P1 Task 16 genre).
func TestBranchRoutesNonMemberAndAuth(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": false}), discardLogger())
	req := httptest.NewRequest("GET", "/drive/files/1/branches", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("feature.drive off: want 404, got %d", rr.Code)
	}
}

func TestBranchCreateRejectsInvalidJSON(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	req := httptest.NewRequest("POST", "/drive/files/1/branches", bytes.NewReader([]byte("{not json")))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}
