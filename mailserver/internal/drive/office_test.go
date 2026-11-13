package drive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func TestOfficeRoutesAreIndependentlyOffGated(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureOfficeEditing: false,
	}), discardLogger())
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/drive/files/1/office/choices"},
		{http.MethodPost, "/drive/files/1/office/launches"},
		{http.MethodDelete, "/drive/files/1/office/launches/00000000-0000-0000-0000-000000000000"},
		{http.MethodPost, "/drive/files/1/office/local-open"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s status=%d, want 404", tc.method, tc.path, rr.Code)
		}
	}
}

func TestOfficeDriveRoutesLifecycleAndValidation(t *testing.T) {
	pool := driveLivePool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.drive", true)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_editing", true)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_local_open", true)
	ctx := t.Context()
	userID := driveLiveUser(t, pool, "office-routes")
	var spaceID, fileID, versionID int64
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1,$2,'regular')`, userID, "Office Routes").Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,NULL,'file','routes.docx')`, userID, spaceID).Scan(&fileID); err != nil {
		t.Fatal(err)
	}
	content := []byte("office-route-fixture")
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1,$2,$3,$4)`, userID, spaceID, sha, len(content)); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`[{"sha256":%q,"size":%d}]`, sha, len(content))
	if err := pool.QueryRow(ctx, `SELECT (drive_file_put_version($1,$2,$3,$4,$5,NULL,$6::jsonb,NULL,'office-route-test')->>'versionId')::bigint`,
		userID, fileID, sha, len(content), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", manifest).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	provider := "routes_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := pool.Exec(ctx, `INSERT INTO office_provider_policies(provider_id,enabled,entitlement_state,build_id,config)
		VALUES($1,true,'valid','route-test','{"proofMode":"test_disabled","editorUrl":"https://editor.test/launch","wopiPublicBaseUrl":"https://setjoin.test"}')`, provider); err != nil {
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
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_editor_sessions WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	h := NewHandler(pool, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureOfficeEditing: true, toggle.FeatureOfficeLocalOpen: true,
	}), discardLogger())
	base := "/drive/files/" + strconv.FormatInt(fileID, 10)

	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, base + "/office/choices", "", http.StatusOK},
		{http.MethodGet, base + "/office/choices?platform=electron", "", http.StatusOK},
		{http.MethodGet, base + "/office/choices?platform=invalid", "", http.StatusBadRequest},
		{http.MethodGet, "/drive/files/bad/office/choices", "", http.StatusBadRequest},
		{http.MethodPost, "/drive/files/bad/office/launches", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/drive/files/bad/office/local-open", `{}`, http.StatusBadRequest},
		{http.MethodDelete, "/drive/files/bad/office/launches/00000000-0000-0000-0000-000000000000", "", http.StatusBadRequest},
		{http.MethodPost, base + "/office/launches", `{`, http.StatusBadRequest},
		{http.MethodPost, base + "/office/launches", `{"baseVersionId":1,"providerId":"missing","deviceId":"browser"}`, http.StatusNotFound},
		{http.MethodPost, base + "/office/local-open", `{`, http.StatusBadRequest},
		{http.MethodPost, base + "/office/local-open", `{"appId":"bad","deviceId":"device"}`, http.StatusBadRequest},
		{http.MethodPost, base + "/office/local-open", `{"appId":"microsoft-office","deviceId":"device"}`, http.StatusOK},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s=%d want %d: %s", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}

	launchBody, _ := json.Marshal(map[string]any{"baseVersionId": versionID, "providerId": provider, "deviceId": "browser", "cohortKey": ""})
	launchReq := httptest.NewRequest(http.MethodPost, base+"/office/launches", strings.NewReader(string(launchBody)))
	launchReq = launchReq.WithContext(auth.ContextWithUser(launchReq.Context(), &auth.Claims{UserID: userID}))
	launchRec := httptest.NewRecorder()
	h.ServeHTTP(launchRec, launchReq)
	if launchRec.Code != http.StatusCreated {
		t.Fatalf("launch=%d %s", launchRec.Code, launchRec.Body.String())
	}
	var launch map[string]any
	if err := json.Unmarshal(launchRec.Body.Bytes(), &launch); err != nil {
		t.Fatal(err)
	}
	if launch["accessToken"] == "" || !strings.Contains(launch["editorUrl"].(string), "WOPISrc=") {
		t.Fatalf("launch projection=%v", launch)
	}
	launchID := launch["launchId"].(string)

	badRevoke := httptest.NewRequest(http.MethodDelete, base+"/office/launches/not-a-uuid", nil)
	badRevoke = badRevoke.WithContext(auth.ContextWithUser(badRevoke.Context(), &auth.Claims{UserID: userID}))
	badRevokeRec := httptest.NewRecorder()
	h.ServeHTTP(badRevokeRec, badRevoke)
	if badRevokeRec.Code != http.StatusBadRequest {
		t.Fatalf("bad revoke=%d", badRevokeRec.Code)
	}
	revoke := httptest.NewRequest(http.MethodDelete, base+"/office/launches/"+launchID, nil)
	revoke = revoke.WithContext(auth.ContextWithUser(revoke.Context(), &auth.Claims{UserID: userID}))
	revokeRec := httptest.NewRecorder()
	h.ServeHTTP(revokeRec, revoke)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke=%d %s", revokeRec.Code, revokeRec.Body.String())
	}
	missingRevoke := httptest.NewRequest(http.MethodDelete, base+"/office/launches/00000000-0000-0000-0000-000000000001", nil)
	missingRevoke = missingRevoke.WithContext(auth.ContextWithUser(missingRevoke.Context(), &auth.Claims{UserID: userID}))
	missingRevokeRec := httptest.NewRecorder()
	h.ServeHTTP(missingRevokeRec, missingRevoke)
	if missingRevokeRec.Code != http.StatusNotFound {
		t.Fatalf("missing revoke=%d %s", missingRevokeRec.Code, missingRevokeRec.Body.String())
	}
}
