package office

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// getfileGapFixture provisions a provider-qualified WOPI session over a
// TWO-chunk file version, mirroring the vertical round-trip fixture.
func getfileGapFixture(t *testing.T) (*Handler, *memoryStore, string, int64, []string) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.drive", true)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_editing", true)
	ctx := context.Background()
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36) + uuid.NewString()[:6]
	provider := "fake_" + suffix
	var mailboxID, userID, spaceID, fileID, versionID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "wopigap-"+suffix).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1,$2,'regular')`, userID, "WOPI gap "+suffix).Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,NULL,'file','gap.docx')`, userID, spaceID).Scan(&fileID); err != nil {
		t.Fatal(err)
	}

	// The reducer requires every non-final chunk to be exactly 4 MiB.
	chunk1, chunk2 := bytes.Repeat([]byte("office-chunk-one!"), 4194304/17+1)[:4194304], []byte("office-chunk-two!")
	h1 := sha256.Sum256(chunk1)
	h2 := sha256.Sum256(chunk2)
	sha1, sha2 := hex.EncodeToString(h1[:]), hex.EncodeToString(h2[:])
	content := append(append([]byte{}, chunk1...), chunk2...)
	contentSHA := sha256.Sum256(content)
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1,$2,$3,$4)`, userID, spaceID, sha1, len(chunk1)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1,$2,$3,$4)`, userID, spaceID, sha2, len(chunk2)); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`[{"sha256":%q,"size":%d},{"sha256":%q,"size":%d}]`, sha1, len(chunk1), sha2, len(chunk2))
	if err := pool.QueryRow(ctx, `SELECT (drive_file_put_version($1,$2,$3,$4,$5,NULL,$6::jsonb,NULL,'wopi-gap-test')->>'versionId')::bigint`,
		userID, fileID, hex.EncodeToString(contentSHA[:]), len(content),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", manifest).Scan(&versionID); err != nil {
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
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM office_save_receipts WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(c, `DELETE FROM office_editor_sessions WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(c, `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})

	token := "wopi-gap-token-" + suffix
	var launchRaw []byte
	if err := pool.QueryRow(ctx, `SELECT office_launch_begin($1,$2,$3,$4,'device','cohort',$5,3600)`,
		userID, fileID, versionID, provider, hashToken(token)).Scan(&launchRaw); err != nil {
		t.Fatal(err)
	}
	if len(launchRaw) == 0 {
		t.Fatal("office launch returned an empty projection")
	}

	store := newMemoryStore()
	store.objects["drive/g/"+sha1] = chunk1
	store.objects["drive/g/"+sha2] = chunk2
	h := NewHandler(pool, store, "test", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureOfficeEditing: true,
	}), discardLogger())
	baseURL := "/office/wopi/files/" + strconv.FormatInt(fileID, 10) + "/contents?access_token=" + url.QueryEscape(token)
	return h, store, baseURL, fileID, []string{sha1, sha2}
}

// serveRecovering runs the handler, absorbing the deliberate
// http.ErrAbortHandler panics the mid-stream guards raise, and reports
// whether that abort panic fired.
func serveRecovering(h *Handler, req *http.Request) (rec *httptest.ResponseRecorder, aborted bool) {
	rec = httptest.NewRecorder()
	defer func() {
		if r := recover(); r != nil {
			aborted = r == http.ErrAbortHandler
		}
	}()
	h.ServeHTTP(rec, req)
	return rec, false
}

// TestWOPIGetFile_MissingMidStreamChunkAborts pins the mid-stream open guard:
// a manifest chunk missing from the store aborts the already-started response
// instead of writing garbage under a 200 header.
func TestWOPIGetFile_MissingMidStreamChunkAborts(t *testing.T) {
	h, store, baseURL, _ /*fileID*/, chunks := getfileGapFixture(t)
	delete(store.objects, "drive/g/"+chunks[1]) // chunk 2 unreadable

	rec, aborted := serveRecovering(h, httptest.NewRequest(http.MethodGet, baseURL, nil))
	if !aborted {
		t.Fatal("mid-stream object failure did not abort the response")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the already-committed 200", rec.Code)
	}
	if strings.HasSuffix(rec.Body.String(), "office-chunk-two!") {
		t.Error("missing chunk was fabricated into the body")
	}
}

// TestWOPIGetFile_ChunkHashMismatchAborts pins the chunk-verification guard:
// stored bytes that disagree with the manifest digest abort the response.
func TestWOPIGetFile_ChunkHashMismatchAborts(t *testing.T) {
	h, store, baseURL, _, chunks := getfileGapFixture(t)
	store.objects["drive/g/"+chunks[1]] = []byte("office-corrupted!?") // same size, wrong bytes

	rec, aborted := serveRecovering(h, httptest.NewRequest(http.MethodGet, baseURL, nil))
	if !aborted {
		t.Fatal("chunk digest mismatch did not abort the response")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want the already-committed 200", rec.Code)
	}
}

// TestWOPIGetFile_ManifestSizeDisagreementRefuses pins the pre-stream guard:
// a projection whose manifest does not sum to the declared size refuses with
// 500 before any byte is written.
func TestWOPIGetFile_ManifestSizeDisagreementRefuses(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h, _ /*store*/, baseURL, fileID, _ := getfileGapFixture(t)

	// Corrupt the declared size so it disagrees with the manifest sum.
	if _, err := pool.Exec(context.Background(),
		`UPDATE drive_file_versions SET size_bytes = size_bytes + 1
		  WHERE id = (SELECT base_version_id FROM office_editor_sessions WHERE file_node_id=$1)`,
		fileID); err != nil {
		t.Fatalf("plant size disagreement: %v", err)
	}

	rec, aborted := serveRecovering(h, httptest.NewRequest(http.MethodGet, baseURL, nil))
	if aborted {
		t.Fatal("manifest disagreement must refuse before streaming, not abort")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body = %s, want 500 manifest disagreement", rec.Code, rec.Body.String())
	}
}
