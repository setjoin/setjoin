package drive

// nodes_meta_live_test.go — P2 Task 2: DB-backed tests for GET /drive/nodes
// (skip-if-no-DB, the chunks_live_test.go/content_live_test.go genre). C1
// requires the non-member case run DB-backed (a real membership predicate,
// not RLS) rather than pool-less, so every case here goes through a live
// pool. Reuses driveLivePool/driveLiveUser (live_helpers_test.go) and
// driveLiveCreateFile/driveLiveUploadChunk/driveLivePutVersion/
// drivePersonalSpaceID (content_live_test.go) — no new harness needed.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// driveLiveCreateFolder creates a folder node, optionally under parentID (nil = root).
func driveLiveCreateFolder(t *testing.T, h *Handler, userID, spaceID int64, name string, parentID *int64) int64 {
	t.Helper()
	body := map[string]any{"spaceId": spaceID, "kind": "folder", "name": name}
	if parentID != nil {
		body["parentId"] = *parentID
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/drive/nodes", bytes.NewReader(b))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/nodes (folder): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode folder: %v", err)
	}
	return out.ID
}

func driveNodesMetaGet(t *testing.T, h *Handler, userID int64, ids string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/drive/nodes?ids="+ids, nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// TestNodesMetaBatch pins the happy path: folder + file+version resolved in
// one batch call, an unknown id silently absent (no oracle), the head
// version's whole-file sha/size/contentType surfaced.
func TestNodesMetaBatch(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvnodesmeta")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, userID)
	folderID := driveLiveCreateFolder(t, h, userID, spaceID, "docs", nil)
	fileID := driveLiveCreateFile(t, h, userID, spaceID, "a.txt")
	// re-parent the file under the folder via patchNode (newParentId).
	patchBody, _ := json.Marshal(map[string]any{"newParentId": folderID})
	preq := httptest.NewRequest(http.MethodPatch, "/drive/nodes/"+strconv.FormatInt(fileID, 10), bytes.NewReader(patchBody))
	preq = preq.WithContext(auth.ContextWithUser(preq.Context(), &auth.Claims{UserID: userID}))
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, preq)
	if prr.Code != http.StatusNoContent {
		t.Fatalf("move file under folder: want 204, got %d: %s", prr.Code, prr.Body.String())
	}

	data := []byte("hello")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	driveLivePutVersion(t, h, userID, fileID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	unknownID := int64(999999999)
	rr := driveNodesMetaGet(t, h, userID, strconv.FormatInt(folderID, 10)+","+strconv.FormatInt(fileID, 10)+","+strconv.FormatInt(unknownID, 10))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/nodes: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// nodesMeta writes a bare array (writeJSONList shape — matching every
	// other list route in this package), not a {"nodes": [...]} wrapper.
	var nodes []nodeMetaRow
	if err := json.Unmarshal(rr.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v, body=%s", err, rr.Body.String())
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes (unknown id silently absent), got %d: %+v", len(nodes), nodes)
	}
	byID := map[int64]nodeMetaRow{}
	for _, n := range nodes {
		byID[n.NodeID] = n
	}
	folder, ok := byID[folderID]
	if !ok || folder.Kind != "folder" {
		t.Fatalf("folder row missing or wrong kind: %+v", byID)
	}
	file, ok := byID[fileID]
	if !ok {
		t.Fatalf("file row missing: %+v", byID)
	}
	if file.Kind != "file" {
		t.Errorf("file.Kind = %q, want file", file.Kind)
	}
	if file.ParentID == nil || *file.ParentID != folderID {
		t.Errorf("file.ParentID = %v, want %d", file.ParentID, folderID)
	}
	if file.ContentSha256 == nil || *file.ContentSha256 != contentSha {
		t.Errorf("file.ContentSha256 = %v, want %s", file.ContentSha256, contentSha)
	}
	if file.HeadVersionID == nil || *file.HeadVersionID == 0 {
		t.Errorf("file.HeadVersionID = %v, want nonzero", file.HeadVersionID)
	}
	if file.DeletedAt != nil {
		t.Errorf("file.DeletedAt = %v, want nil", file.DeletedAt)
	}
}

// TestNodesMetaBranchCount pins P4 Task 17's addition: nodesMeta rows carry
// branchCount (reusing tree()'s Task 10 LATERAL) so the mirror's
// reconcileBranches knows to call fileBranches without a tree() round trip.
// A file with one open branch reports 1; a plain file (and a folder) report 0.
func TestNodesMetaBranchCount(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvnmbranch")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)

	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "budget.xlsx", []byte("v1"))
	plainID := driveLiveCreateFile(t, h, userID, spaceID, "plain.txt")
	folderID := driveLiveCreateFolder(t, h, userID, spaceID, "docs", nil)

	rr := driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "budget-redo", "fromVersionId": versionID})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create branch: want 201, got %d: %s", rr.Code, rr.Body.String())
	}

	got := driveNodesMetaGet(t, h, userID,
		strconv.FormatInt(nodeID, 10)+","+strconv.FormatInt(plainID, 10)+","+strconv.FormatInt(folderID, 10))
	if got.Code != http.StatusOK {
		t.Fatalf("GET /drive/nodes: want 200, got %d: %s", got.Code, got.Body.String())
	}
	var nodes []nodeMetaRow
	if err := json.Unmarshal(got.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	byID := map[int64]nodeMetaRow{}
	for _, n := range nodes {
		byID[n.NodeID] = n
	}
	if byID[nodeID].BranchCount != 1 {
		t.Errorf("branched file branchCount = %d, want 1", byID[nodeID].BranchCount)
	}
	if byID[plainID].BranchCount != 0 {
		t.Errorf("plain file branchCount = %d, want 0", byID[plainID].BranchCount)
	}
	if byID[folderID].BranchCount != 0 {
		t.Errorf("folder branchCount = %d, want 0", byID[folderID].BranchCount)
	}
}

// TestNodesMetaNonMemberInvisible: a non-member's request for another user's
// node id gets it silently absent from the response — not 403/404 on the
// batch route (I-1/BZ139 posture: this endpoint has no oracle at all).
func TestNodesMetaNonMemberInvisible(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvnmowner")
	stranger := driveLiveUser(t, pool, "drvnmstranger")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, owner)
	fileID := driveLiveCreateFile(t, h, owner, spaceID, "owner-only.txt")

	rr := driveNodesMetaGet(t, h, stranger, strconv.FormatInt(fileID, 10))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 (no oracle), got %d: %s", rr.Code, rr.Body.String())
	}
	var nodes []nodeMetaRow
	if err := json.Unmarshal(rr.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("non-member must see the node as absent, got %+v", nodes)
	}
}

// TestNodesMetaEmptyAndTooManyIDs: empty ids -> 200 {"nodes":[]} (never
// null); >500 ids -> 422 BZ141 (a pure request-validation error, no DB hit).
func TestNodesMetaEmptyAndTooManyIDs(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvnmlimits")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	rr := driveNodesMetaGet(t, h, userID, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("empty ids: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "[]" {
		t.Errorf("empty ids body = %q, want []", got)
	}

	ids := make([]string, 501)
	for i := range ids {
		ids[i] = strconv.Itoa(i + 1)
	}
	rr = driveNodesMetaGet(t, h, userID, strings.Join(ids, ","))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("501 ids: want 422, got %d: %s", rr.Code, rr.Body.String())
	}
	var problem struct {
		Code string `json:"code"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "BZ141" {
		t.Errorf("Code = %q, want BZ141", problem.Code)
	}
	if !strings.Contains(problem.Type, "invalid-arguments") {
		t.Errorf("Type = %q, want the invalid-arguments slug", problem.Type)
	}
}
