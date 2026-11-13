package drive

// White-box (package drive) DB-guarded content integration tests (Task 20
// test bullets 2-3): a Range GET spanning a chunk boundary, the secure-space
// governed-export gate, and the I-15 admin-non-member 404. Store is
// a fakeStore (Range-aware — see chunks_test.go's GetObject); the DB round
// trips through the real reducers.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// driveLiveUploadChunk PUTs one chunk through the real HTTP pipeline
// (tmp->verify->promote->register) and returns its sha256.
func driveLiveUploadChunk(t *testing.T, h *Handler, userID, spaceID int64, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	req := httptest.NewRequest(http.MethodPut,
		"/drive/chunks/"+sha+"?space="+strconv.FormatInt(spaceID, 10), bytes.NewReader(data))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("PUT chunk: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	return sha
}

// driveLiveCreateFile creates a file node at the space root.
func driveLiveCreateFile(t *testing.T, h *Handler, userID, spaceID int64, name string) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"spaceId": spaceID, "kind": "file", "name": name})
	req := httptest.NewRequest(http.MethodPost, "/drive/nodes", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/nodes: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode node: %v", err)
	}
	return out.ID
}

type chunkManifestEntry struct {
	Sha256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// driveLivePutVersion POSTs a version through the real HTTP pipeline and
// returns the reducer's versionId.
func driveLivePutVersion(t *testing.T, h *Handler, userID, nodeID int64, contentSha string, size int, manifest []chunkManifestEntry) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"contentSha256": contentSha,
		"size":          size,
		"contentType":   "application/octet-stream",
		"manifest":      manifest,
	})
	req := httptest.NewRequest(http.MethodPost, "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST version: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		VersionID int64 `json:"versionId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	return out.VersionID
}

// TestContentRangeSpanningChunkBoundary uploads two real chunks (a full 4 MiB
// first chunk + a short second chunk), puts a version referencing both, then
// GETs a Range that straddles the chunk boundary — asserting 206, the exact
// byte count, the exact bytes (proving chunkRange's O(1) math and the
// per-chunk SetRange skip/clip are both correct), and the Content-Range
// header.
func TestContentRangeSpanningChunkBoundary(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvrange")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "big.bin")

	chunk0 := bytes.Repeat([]byte{0xAA}, int(driveChunkSize)) // exactly one full chunk
	chunk1 := []byte("0123456789")                            // 10 bytes — the tail chunk
	sha0 := driveLiveUploadChunk(t, h, userID, spaceID, chunk0)
	sha1 := driveLiveUploadChunk(t, h, userID, spaceID, chunk1)

	whole := append(append([]byte{}, chunk0...), chunk1...)
	sum := sha256.Sum256(whole)
	contentSha := hex.EncodeToString(sum[:])
	versionID := driveLivePutVersion(t, h, userID, nodeID, contentSha, len(whole), []chunkManifestEntry{
		{Sha256: sha0, Size: len(chunk0)},
		{Sha256: sha1, Size: len(chunk1)},
	})

	// Range spans the boundary: last 4 bytes of chunk0 + first 7 bytes of chunk1.
	start := driveChunkSize - 4
	end := driveChunkSize + 6
	req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
	req.Header.Set("Range", "bytes="+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("want 206, got %d: %s", rr.Code, rr.Body.String())
	}
	wantLen := end - start + 1
	if int64(rr.Body.Len()) != wantLen {
		t.Fatalf("body length = %d, want %d", rr.Body.Len(), wantLen)
	}
	wantBody := whole[start : end+1]
	if !bytes.Equal(rr.Body.Bytes(), wantBody) {
		t.Errorf("body mismatch: got %x, want %x", rr.Body.Bytes(), wantBody)
	}
	wantContentRange := "bytes " + strconv.FormatInt(start, 10) + "-" + strconv.FormatInt(end, 10) + "/" + strconv.FormatInt(int64(len(whole)), 10)
	if got := rr.Header().Get("Content-Range"); got != wantContentRange {
		t.Errorf("Content-Range = %q, want %q", got, wantContentRange)
	}
}

// TestContentSecureSpaceRequiresGovernedExport: neither a caller-controlled
// header nor Range may turn download eligibility into original-byte authority.
// Secure/GxP originals are served only by the one-use export-token route.
func TestContentSecureSpaceRequiresGovernedExport(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvsecure")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := driveLiveCreateSecureSpace(t, h, userID)
	nodeID := driveLiveCreateFile(t, h, userID, spaceID, "secret.txt")
	data := []byte("classified")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	versionID := driveLivePutVersion(t, h, userID, nodeID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	for i, headers := range []map[string]string{
		{},
		{"X-Setjoin-Render": "1"},
		{"X-Setjoin-Render": "1", "Range": "bytes=0-2"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
		for name, value := range headers {
			req.Header.Set(name, value)
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("protected raw GET %d: want 403, got %d: %s", i, rr.Code, rr.Body.String())
		}
	}
	if n := driveAuditViewCount(t, pool, spaceID, userID, versionID); n != 0 {
		t.Errorf("rejected protected raw GETs must not emit view audits, got %d", n)
	}
}

// TestRestoreVersionSecureSpaceStaysServerSide proves that restore-as-new is
// still usable when the protected-original route is correctly closed.  The
// handler clones the authorized manifest through the reducer; no original
// bytes need to cross the HTTP boundary, and the resulting version remains
// governed by the same 403 original-content policy.
func TestRestoreVersionSecureSpaceStaysServerSide(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvsecurerestore")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := driveLiveCreateSecureSpace(t, h, userID)
	nodeID, v1 := driveLiveFileWithVersion(t, h, userID, spaceID, "secret-history.txt", []byte("first"))

	second := []byte("second")
	chunkSha := driveLiveUploadChunk(t, h, userID, spaceID, second)
	whole := sha256.Sum256(second)
	rr := driveLiveDo(t, h, userID, http.MethodPost,
		"/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions",
		map[string]any{
			"contentSha256": hex.EncodeToString(whole[:]),
			"size":          len(second), "contentType": "application/octet-stream",
			"baseVersionId": v1,
			"manifest":      []chunkManifestEntry{{Sha256: chunkSha, Size: len(second)}},
		})
	if rr.Code != http.StatusCreated {
		t.Fatalf("put second version: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var secondOut struct {
		VersionID int64 `json:"versionId"`
	}
	driveLiveDecode(t, rr, &secondOut)
	v2 := secondOut.VersionID

	rr = driveLiveDo(t, h, userID, http.MethodPost,
		"/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions/"+strconv.FormatInt(v1, 10)+"/restore",
		map[string]any{"baseVersionId": v2, "note": "restore first"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("restore protected version: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var restored struct {
		VersionID     int64  `json:"versionId"`
		HeadVersionID *int64 `json:"headVersionId"`
	}
	driveLiveDecode(t, rr, &restored)
	if restored.VersionID == v1 || restored.VersionID == v2 || restored.HeadVersionID == nil || *restored.HeadVersionID != restored.VersionID {
		t.Fatalf("restore response did not create/advance a new main version: %+v", restored)
	}
	rr = driveLiveDo(t, h, userID, http.MethodGet,
		"/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list versions after restore: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var listed []versionOut
	driveLiveDecode(t, rr, &listed)
	var gotSha string
	for _, candidate := range listed {
		if candidate.ID == restored.VersionID {
			gotSha = candidate.Sha256
			break
		}
	}
	firstWhole := sha256.Sum256([]byte("first"))
	if want := hex.EncodeToString(firstWhole[:]); gotSha != want {
		t.Fatalf("restored sha=%s, want source sha=%s", gotSha, want)
	}

	rr = driveLiveDo(t, h, userID, http.MethodGet,
		"/drive/versions/"+strconv.FormatInt(restored.VersionID, 10)+"/content", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("restored protected original: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRestoreVersionRejectsInvalidWireAndMissingSource(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvrestorewire")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true,
	}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)
	nodeID := driveLiveCreateFile(t, h, owner, spaceID, "restore-wire.txt")

	for _, tt := range []struct {
		name string
		path string
		body any
		want int
	}{
		{name: "invalid node", path: "/drive/files/x/versions/1/restore", body: nil, want: http.StatusBadRequest},
		{name: "invalid source version", path: "/drive/files/" + strconv.FormatInt(nodeID, 10) + "/versions/x/restore", body: nil, want: http.StatusBadRequest},
		{name: "missing source", path: "/drive/files/" + strconv.FormatInt(nodeID, 10) + "/versions/9223372036854775807/restore", body: map[string]any{}, want: http.StatusNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rr := driveLiveDo(t, h, owner, http.MethodPost, tt.path, tt.body)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tt.want, rr.Body.String())
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost,
		"/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions/1/restore",
		strings.NewReader(`{"baseVersionId":`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: owner}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: status=%d want=400 body=%s", rr.Code, rr.Body.String())
	}
}

// TestContentAdminNonMemberStill404 pins I-15: a drive.view admin who is NOT
// a space member gets the same opaque 404 as a total stranger — no
// membership oracle on the content route.
func TestContentAdminNonMemberStill404(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvowner")
	admin := driveLiveUser(t, pool, "drvadmin")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, owner)
	nodeID := driveLiveCreateFile(t, h, owner, spaceID, "owner-only.txt")
	data := []byte("owner content")
	sha := driveLiveUploadChunk(t, h, owner, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	versionID := driveLivePutVersion(t, h, owner, nodeID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	// Grant `admin` drive.view via Super Admin (role_group_id=1, V114 seed).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, admin); err != nil {
		t.Fatalf("grant admin role: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: admin}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("drive.view admin, non-member: want 404 (I-15, no oracle), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPostVersionBranchIDReachesReducer pins the P4 Task 17 bug fix: postVersion
// silently dropped body.BranchID (never decoded, never forwarded to
// drive_file_put_version's p_branch_id param), so every save landed on main
// regardless of what the caller asked for. A save with branchId set must
// advance ONLY that branch's head — main's head must not move.
func TestPostVersionBranchIDReachesReducer(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvbranchput")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "notes.txt", []byte("v1"))

	rr := driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "side-edit", "fromVersionId": versionID})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create branch: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		BranchID int64 `json:"branchId"`
	}
	driveLiveDecode(t, rr, &created)

	data := []byte("v2-on-branch")
	sha := driveLiveUploadChunk(t, h, userID, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	rr = driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions", map[string]any{
		"contentSha256": contentSha,
		"size":          len(data),
		"baseVersionId": versionID,
		"branchId":      created.BranchID,
		"manifest":      []chunkManifestEntry{{Sha256: sha, Size: len(data)}},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST version on branch: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var putOut struct {
		VersionID     int64  `json:"versionId"`
		BranchID      *int64 `json:"branchId"`
		HeadVersionID *int64 `json:"headVersionId"`
	}
	driveLiveDecode(t, rr, &putOut)
	if putOut.BranchID == nil || *putOut.BranchID != created.BranchID {
		t.Fatalf("put_version response branchId = %v, want %d — branchId never reached the reducer", putOut.BranchID, created.BranchID)
	}

	// The branch head must have advanced to the new version.
	rr = driveLiveDo(t, h, userID, "GET", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list branches: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var branches []branchOut
	driveLiveDecode(t, rr, &branches)
	if len(branches) != 1 || branches[0].HeadVersionID != putOut.VersionID {
		t.Fatalf("branch head = %+v, want headVersionId=%d", branches, putOut.VersionID)
	}

	// main's head must be untouched — the save must never land on main.
	rr = driveNodesMetaGet(t, h, userID, strconv.FormatInt(nodeID, 10))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/nodes: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var nodes []nodeMetaRow
	driveLiveDecode(t, rr, &nodes)
	if len(nodes) != 1 || nodes[0].HeadVersionID == nil || *nodes[0].HeadVersionID != versionID {
		t.Fatalf("main head = %+v, want unchanged headVersionId=%d", nodes, versionID)
	}
}

// drivePersonalSpaceID auto-provisions (if needed) and returns the caller's
// personal space id via GET /drive/spaces.
func drivePersonalSpaceID(t *testing.T, h *Handler, userID int64) int64 {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/drive/spaces", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /drive/spaces: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var spaces []struct {
		ID         int64 `json:"id"`
		IsPersonal bool  `json:"isPersonal"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &spaces); err != nil || len(spaces) == 0 {
		t.Fatalf("decode spaces: err=%v body=%s", err, rr.Body.String())
	}
	return spaces[0].ID
}

// driveLiveCreateSecureSpace creates a non-personal 'secure' space owned by userID.
func driveLiveCreateSecureSpace(t *testing.T, h *Handler, userID int64) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": "Secure Space", "classification": "secure"})
	req := httptest.NewRequest(http.MethodPost, "/drive/spaces", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/spaces (secure): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode space: %v", err)
	}
	return out.ID
}

// driveAuditViewCount reads drive_audit_log directly (superuser pool, no
// handler surface exposes audit reads in P1) to assert the G3 dedupe count.
func driveAuditViewCount(t *testing.T, pool *pgxpool.Pool, spaceID, userID, versionID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_audit_log
		  WHERE space_id = $1 AND user_id = $2 AND action = 'view' AND target_id = $3`,
		spaceID, userID, versionID).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}
