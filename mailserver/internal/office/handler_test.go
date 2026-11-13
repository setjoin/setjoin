package office

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func TestHashTokenStableAndOpaque(t *testing.T) {
	got := hashToken("secret")
	if got == "secret" || len(got) != 64 || got != hashToken("secret") {
		t.Fatalf("unexpected token digest %q", got)
	}
}

func TestWOPIOffGateAndMissingToken(t *testing.T) {
	off := NewHandler(nil, nil, "", toggle.NewTestFlags(map[string]bool{}), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/office/wopi/files/1", nil)
	rr := httptest.NewRecorder()
	off.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("off status=%d", rr.Code)
	}

	on := NewHandler(nil, nil, "", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureOfficeEditing: true,
	}), discardLogger())
	rr = httptest.NewRecorder()
	on.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing-token status=%d", rr.Code)
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type memoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	failPut bool
}

func newMemoryStore() *memoryStore { return &memoryStore{objects: map[string][]byte{}} }
func (s *memoryStore) PutObject(_ context.Context, _, key string, r io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	if s.failPut {
		return minio.UploadInfo{}, errors.New("injected put failure")
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return minio.UploadInfo{}, err
	}
	s.mu.Lock()
	s.objects[key] = b
	s.mu.Unlock()
	return minio.UploadInfo{Key: key, Size: int64(len(b))}, nil
}
func (s *memoryStore) CopyObject(_ context.Context, dst minio.CopyDestOptions, src minio.CopySrcOptions) (minio.UploadInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[src.Object]
	if !ok {
		return minio.UploadInfo{}, errors.New("missing copy source")
	}
	s.objects[dst.Object] = append([]byte(nil), b...)
	return minio.UploadInfo{Key: dst.Object, Size: int64(len(b))}, nil
}
func (s *memoryStore) RemoveObject(_ context.Context, _, key string, _ minio.RemoveObjectOptions) error {
	s.mu.Lock()
	delete(s.objects, key)
	s.mu.Unlock()
	return nil
}
func (s *memoryStore) GetObject(_ context.Context, _, key string, _ minio.GetObjectOptions) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	if !ok {
		return nil, errors.New("missing object")
	}
	return io.NopCloser(bytes.NewReader(append([]byte(nil), b...))), nil
}

func TestWOPIVerticalSaveToDriveHistory(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.drive", true)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_editing", true)
	ctx := t.Context()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	provider := "fake_" + suffix
	var mailboxID, userID, spaceID, fileID, versionID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "wopi-"+suffix).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1,$2,'regular')`, userID, "WOPI "+suffix).Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,NULL,'file','roundtrip.docx')`, userID, spaceID).Scan(&fileID); err != nil {
		t.Fatal(err)
	}
	original := []byte("office-original")
	chunkHash := sha256.Sum256(original)
	chunkSHA := hex.EncodeToString(chunkHash[:])
	contentHash := sha256.Sum256(original)
	contentSHA := hex.EncodeToString(contentHash[:])
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1,$2,$3,$4)`, userID, spaceID, chunkSHA, len(original)); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`[{"sha256":%q,"size":%d}]`, chunkSHA, len(original))
	if err := pool.QueryRow(ctx, `SELECT (drive_file_put_version($1,$2,$3,$4,$5,NULL,$6::jsonb,NULL,'wopi-test')->>'versionId')::bigint`,
		userID, fileID, contentSHA, len(original), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", manifest).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO office_provider_policies(provider_id,enabled,entitlement_state,build_id,config) VALUES($1,true,'valid','test','{"proofMode":"test_disabled","editorUrl":"https://editor.test/launch","wopiPublicBaseUrl":"https://setjoin.test"}')`, provider); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `WITH qualified AS (
		INSERT INTO office_provider_qualifications(
			provider_id,provider_generation,config_sha256,status,profile,checks,
			discovery_fingerprint,route_revision,created_by,expires_at)
		SELECT provider_id,1,config_sha256,'passed','existing-provider',
			'{"discovery":"pass","proof":"pass","editor":"pass","wopiSave":"pass"}',
			repeat('f',64),1,$2,statement_timestamp()+interval '1 hour'
		FROM office_provider_policies WHERE provider_id=$1 RETURNING id
	), activated AS (
		UPDATE office_provider_policies SET generation=2,route_state='active_for_scope',
			active_qualification_id=(SELECT id FROM qualified)
		WHERE provider_id=$1 RETURNING provider_id
	)
	INSERT INTO office_provider_health_observations(
		provider_id,provider_generation,state,capacity_state,facts,expires_at)
	SELECT provider_id,2,'healthy','available','{"source":"test"}',
		statement_timestamp()+interval '1 hour' FROM activated`, provider, userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM office_save_receipts WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM office_editor_sessions WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	token := "wopi-token-" + suffix
	var launchRaw []byte
	if err := pool.QueryRow(ctx, `SELECT office_launch_begin($1,$2,$3,$4,'device','cohort',$5,3600)`,
		userID, fileID, versionID, provider, hashToken(token)).Scan(&launchRaw); err != nil {
		t.Fatal(err)
	}
	if len(launchRaw) == 0 {
		t.Fatal("office launch returned an empty projection")
	}

	store := newMemoryStore()
	store.objects["drive/g/"+chunkSHA] = original
	h := NewHandler(pool, store, "test", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureOfficeEditing: true,
	}), discardLogger())
	baseURL := "/office/wopi/files/" + strconv.FormatInt(fileID, 10) + "?access_token=" + url.QueryEscape(token)

	invalidIDReq := httptest.NewRequest(http.MethodGet, "/office/wopi/files/not-an-id?access_token=x", nil)
	invalidIDRec := httptest.NewRecorder()
	h.ServeHTTP(invalidIDRec, invalidIDReq)
	if invalidIDRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid id=%d %s", invalidIDRec.Code, invalidIDRec.Body.String())
	}
	wrongTokenReq := httptest.NewRequest(http.MethodGet, "/office/wopi/files/"+strconv.FormatInt(fileID, 10)+"?access_token=wrong", nil)
	wrongTokenRec := httptest.NewRecorder()
	h.ServeHTTP(wrongTokenRec, wrongTokenReq)
	if wrongTokenRec.Code != http.StatusNotFound {
		t.Fatalf("wrong token=%d %s", wrongTokenRec.Code, wrongTokenRec.Body.String())
	}
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/office/wopi/files/" + strconv.FormatInt(fileID, 10) + "/contents?access_token=wrong"},
		{http.MethodPost, "/office/wopi/files/" + strconv.FormatInt(fileID, 10) + "/contents?access_token=wrong"},
		{http.MethodPost, "/office/wopi/files/" + strconv.FormatInt(fileID, 10) + "?access_token=wrong"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("rejected"))
		if tc.method == http.MethodPost && !strings.Contains(tc.path, "/contents") {
			req.Header.Set("X-WOPI-Override", "LOCK")
			req.Header.Set("X-WOPI-Lock", "rejected-lock")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("wrong-token %s %s=%d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE office_provider_policies SET config='{"editorUrl":"https://editor.test/launch"}' WHERE provider_id=$1`, provider); err != nil {
		t.Fatal(err)
	}
	proofReq := httptest.NewRequest(http.MethodGet, baseURL, nil)
	proofRec := httptest.NewRecorder()
	h.ServeHTTP(proofRec, proofReq)
	if proofRec.Code != http.StatusNotFound {
		t.Fatalf("missing proof config=%d %s", proofRec.Code, proofRec.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE office_provider_policies SET config='{"proofMode":"test_disabled","editorUrl":"https://editor.test/launch","wopiPublicBaseUrl":"https://setjoin.test"}' WHERE provider_id=$1`, provider); err != nil {
		t.Fatal(err)
	}

	infoReq := httptest.NewRequest(http.MethodGet, baseURL, nil)
	infoRec := httptest.NewRecorder()
	h.ServeHTTP(infoRec, infoReq)
	if infoRec.Code != http.StatusOK {
		t.Fatalf("CheckFileInfo=%d %s", infoRec.Code, infoRec.Body.String())
	}

	lockReq := httptest.NewRequest(http.MethodPost, baseURL, nil)
	lockReq.Header.Set("X-WOPI-Override", "LOCK")
	lockReq.Header.Set("X-WOPI-Lock", "opaque-lock")
	lockRec := httptest.NewRecorder()
	h.ServeHTTP(lockRec, lockReq)
	if lockRec.Code != http.StatusOK {
		t.Fatalf("LOCK=%d %s", lockRec.Code, lockRec.Body.String())
	}
	missingLockReq := httptest.NewRequest(http.MethodPost, baseURL, nil)
	missingLockReq.Header.Set("X-WOPI-Override", "REFRESH_LOCK")
	missingLockRec := httptest.NewRecorder()
	h.ServeHTTP(missingLockRec, missingLockReq)
	if missingLockRec.Code != http.StatusBadRequest {
		t.Fatalf("missing lock=%d %s", missingLockRec.Code, missingLockRec.Body.String())
	}
	invalidOverrideReq := httptest.NewRequest(http.MethodPost, baseURL, nil)
	invalidOverrideReq.Header.Set("X-WOPI-Override", "INVALID")
	invalidOverrideReq.Header.Set("X-WOPI-Lock", "opaque-lock")
	invalidOverrideRec := httptest.NewRecorder()
	h.ServeHTTP(invalidOverrideRec, invalidOverrideReq)
	if invalidOverrideRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid override=%d %s", invalidOverrideRec.Code, invalidOverrideRec.Body.String())
	}
	conflictReq := httptest.NewRequest(http.MethodPost, baseURL, nil)
	conflictReq.Header.Set("X-WOPI-Override", "LOCK")
	conflictReq.Header.Set("X-WOPI-Lock", "different-lock")
	conflictRec := httptest.NewRecorder()
	h.ServeHTTP(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusConflict || conflictRec.Header().Get("X-WOPI-Lock") != "opaque-lock" {
		t.Fatalf("conflicting LOCK=%d current=%q body=%q", conflictRec.Code,
			conflictRec.Header().Get("X-WOPI-Lock"), conflictRec.Body.String())
	}

	updated := []byte("office-updated-through-wopi")
	putReq := httptest.NewRequest(http.MethodPost, strings.Replace(baseURL, "?", "/contents?", 1), bytes.NewReader(updated))
	putReq.Header.Set("X-WOPI-Lock", "opaque-lock")
	putReq.Header.Set("X-Setjoin-Operation-Key", "wopi-retry-operation")
	// WOPI PutFile commonly uses octet-stream. Because V1 does not advertise
	// PutRelativeFile/format conversion, the Drive version must preserve the
	// file family's authoritative MIME rather than trust this transport header.
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PutFile=%d %s", putRec.Code, putRec.Body.String())
	}
	replayReq := httptest.NewRequest(http.MethodPost, strings.Replace(baseURL, "?", "/contents?", 1), bytes.NewReader(updated))
	replayReq.Header.Set("X-WOPI-Lock", "opaque-lock")
	replayReq.Header.Set("X-Setjoin-Operation-Key", "wopi-retry-operation")
	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusOK || !strings.Contains(replayRec.Body.String(), `"replayed":true`) {
		t.Fatalf("PutFile replay=%d %s", replayRec.Code, replayRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, strings.Replace(baseURL, "?", "/contents?", 1), nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !bytes.Equal(getRec.Body.Bytes(), updated) {
		t.Fatalf("GetFile=%d body=%q", getRec.Code, getRec.Body.Bytes())
	}
	store.failPut = true
	failPutReq := httptest.NewRequest(http.MethodPost, strings.Replace(baseURL, "?", "/contents?", 1), strings.NewReader("cannot-stage"))
	failPutReq.Header.Set("X-WOPI-Lock", "opaque-lock")
	failPutRec := httptest.NewRecorder()
	h.ServeHTTP(failPutRec, failPutReq)
	if failPutRec.Code != http.StatusInternalServerError {
		t.Fatalf("stage failure=%d %s", failPutRec.Code, failPutRec.Body.String())
	}
	store.failPut = false
	store.mu.Lock()
	store.objects = map[string][]byte{}
	store.mu.Unlock()
	missingObjectReq := httptest.NewRequest(http.MethodGet, strings.Replace(baseURL, "?", "/contents?", 1), nil)
	missingObjectRec := httptest.NewRecorder()
	h.ServeHTTP(missingObjectRec, missingObjectReq)
	// DATA-INTEGRITY-FAIL-CLOSED (D-MAILSERVER-INTERNAL-OFFICE-003): an
	// unreadable object must fail the read BEFORE the response head, as a
	// 500 — the old behavior (200 with an empty body) presented unreadable
	// content as a successful read. The failure is expressed in the handler's
	// uniform problem+json shape (the empty-body shape belonged to the old
	// buggy 200 path this assertion originally guarded).
	if missingObjectRec.Code != http.StatusInternalServerError {
		t.Fatalf("missing object response=%d body=%q", missingObjectRec.Code, missingObjectRec.Body.Bytes())
	}
	if ct := missingObjectRec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("missing object content-type=%q, want application/problem+json", ct)
	}
	if !strings.Contains(missingObjectRec.Body.String(), "Office file content is unavailable") {
		t.Fatalf("missing object body=%q, want the fail-closed problem detail", missingObjectRec.Body.String())
	}
	var receipts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM office_save_receipts WHERE file_node_id=$1`, fileID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 {
		t.Fatalf("receipts=%d, want 1", receipts)
	}
	var savedContentType string
	if err := pool.QueryRow(ctx, `SELECT content_type FROM drive_file_versions
		WHERE id=(SELECT result_version_id FROM office_save_receipts WHERE file_node_id=$1)`, fileID).Scan(&savedContentType); err != nil {
		t.Fatal(err)
	}
	if savedContentType != "application/vnd.openxmlformats-officedocument.wordprocessingml.document" {
		t.Fatalf("saved content type=%q", savedContentType)
	}
}

func TestNullableWOPIHeaders(t *testing.T) {
	if nullableHeaderHash("") != nil || nullableHeaderValue("") != nil {
		t.Fatal("empty WOPI headers must become SQL NULL")
	}
	if nullableHeaderHash("lock") == nil || nullableHeaderValue("lock") != "lock" {
		t.Fatal("present WOPI headers were discarded")
	}
}
