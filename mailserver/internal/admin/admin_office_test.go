package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	officepkg "setjoin.com/mailserver/internal/office"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

type officeQualificationProberStub struct {
	result officepkg.QualificationResult
	err    error
}

func (s officeQualificationProberStub) Probe(context.Context, officepkg.QualificationTarget) (officepkg.QualificationResult, error) {
	return s.result, s.err
}

func officeAdminRequest(t *testing.T, actor int64, method, target string, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: actor, IsAdmin: true,
		Permissions: []string{permissions.PermOfficeView, permissions.PermOfficeManage}}))
	return r
}

func TestOfficeAdminHandlersLifecycleAndErrors(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	actor := ssCreateUser(t, pool)
	var roleID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM admin_role_groups
		WHERE permissions @> ARRAY['office.view','office.manage']::text[] ORDER BY is_builtin DESC,id LIMIT 1`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,$2,$1) ON CONFLICT DO NOTHING`, actor, roleID); err != nil {
		t.Fatal(err)
	}
	provider := "coverage-provider"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	h := NewOfficeHandler(pool, mailboxTestLogger())

	listReq := officeAdminRequest(t, actor, http.MethodGet, "/api/admin/office", nil)
	listRec := httptest.NewRecorder()
	h.List(listRec, listReq)
	if listRec.Code != http.StatusOK || !json.Valid(listRec.Body.Bytes()) {
		t.Fatalf("list=%d %s", listRec.Code, listRec.Body.String())
	}

	badReq := officeAdminRequest(t, actor, http.MethodPut, "/api/admin/office/providers/"+provider, []byte(`{"expectedGeneration":0}`))
	badReq.SetPathValue("providerId", provider)
	badRec := httptest.NewRecorder()
	h.Configure(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad configure=%d %s", badRec.Code, badRec.Body.String())
	}

	body := []byte(`{"expectedGeneration":0,"profile":"existing-provider","entitlementState":"valid","buildId":"coverage","config":{"proofDiscoveryUrl":"https://office.test/discovery","wopiPublicBaseUrl":"https://setjoin.test","editorUrl":"https://office.test/edit"}}`)
	invalidProviderReq := officeAdminRequest(t, actor, http.MethodPut, "/api/admin/office/providers/INVALID", body)
	invalidProviderReq.SetPathValue("providerId", "INVALID")
	invalidProviderReq.Header.Set("X-Audit-Reason", "invalid provider coverage")
	invalidProviderRec := httptest.NewRecorder()
	h.Configure(invalidProviderRec, invalidProviderReq)
	if invalidProviderRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid provider=%d %s", invalidProviderRec.Code, invalidProviderRec.Body.String())
	}

	setReq := officeAdminRequest(t, actor, http.MethodPut, "/api/admin/office/providers/"+provider, body)
	setReq.SetPathValue("providerId", provider)
	setReq.Header.Set("X-Audit-Reason", "coverage lifecycle")
	setRec := httptest.NewRecorder()
	middleware.RequireReason(permissions.PermOfficeManage, pool)(http.HandlerFunc(h.Configure)).ServeHTTP(setRec, setReq)
	if setRec.Code != http.StatusOK || !json.Valid(setRec.Body.Bytes()) {
		t.Fatalf("set=%d %s", setRec.Code, setRec.Body.String())
	}

	removeReq := officeAdminRequest(t, actor, http.MethodDelete, "/api/admin/office/providers/"+provider, nil)
	removeReq.SetPathValue("providerId", provider)
	removeReq.Header.Set("X-Audit-Reason", "coverage removal")
	removeRec := httptest.NewRecorder()
	middleware.RequireReason(permissions.PermOfficeManage, pool)(http.HandlerFunc(h.Remove)).ServeHTTP(removeRec, removeReq)
	if removeRec.Code != http.StatusOK || !bytes.Contains(removeRec.Body.Bytes(), []byte(`"removed": true`)) {
		t.Fatalf("remove=%d %s", removeRec.Code, removeRec.Body.String())
	}

	forbidden := ssCreateUser(t, pool)
	forbiddenReq := officeAdminRequest(t, forbidden, http.MethodGet, "/api/admin/office", nil)
	forbiddenRec := httptest.NewRecorder()
	h.List(forbiddenRec, forbiddenReq)
	if forbiddenRec.Code != http.StatusForbidden {
		t.Fatalf("forbidden list=%d %s", forbiddenRec.Code, forbiddenRec.Body.String())
	}
	forbiddenRemoveReq := officeAdminRequest(t, forbidden, http.MethodDelete, "/api/admin/office/providers/"+provider, nil)
	forbiddenRemoveReq.SetPathValue("providerId", provider)
	forbiddenRemoveReq.Header.Set("X-Audit-Reason", "forbidden")
	forbiddenRemoveRec := httptest.NewRecorder()
	h.Remove(forbiddenRemoveRec, forbiddenRemoveReq)
	if forbiddenRemoveRec.Code != http.StatusForbidden {
		t.Fatalf("forbidden remove=%d %s", forbiddenRemoveRec.Code, forbiddenRemoveRec.Body.String())
	}
}

// TestOfficeAdminConfigureQualifyActivate exercises the provider lifecycle
// (configure → qualify → activate) including the synthetic WOP save receipt.
func TestOfficeAdminConfigureQualifyActivate(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	actor := ssCreateUser(t, pool)
	driveOwner := officeFixtureOwner(t, pool)
	var roleID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM admin_role_groups
		WHERE permissions @> ARRAY['office.view','office.manage']::text[] ORDER BY is_builtin DESC,id LIMIT 1`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,$2,$1) ON CONFLICT DO NOTHING`, actor, roleID); err != nil {
		t.Fatal(err)
	}
	provider := "qualified-provider"
	var spaceID, nodeID, versionID, receiptID int64
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_health_observations WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `UPDATE office_provider_policies SET active_qualification_id=NULL WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_qualifications WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_save_receipts WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_editor_sessions WHERE provider_id=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	h := NewOfficeHandler(pool, mailboxTestLogger())
	passingProbe := officeQualificationProberStub{result: officepkg.QualificationResult{
		Checks:               map[string]any{"discovery": "pass", "proof": "pass", "editor": "pass", "wopiSave": "pending_receipt"},
		DiscoveryFingerprint: strings.Repeat("a", 64),
	}}
	h.prober = passingProbe
	configureBody := []byte(`{"expectedGeneration":0,"profile":"existing-provider","entitlementState":"evaluation","buildId":"fixture","config":{"profile":"existing-provider","proofDiscoveryUrl":"https://office.example/hosting/discovery","wopiPublicBaseUrl":"https://setjoin.example","editorUrl":"https://office.example/browser"}}`)
	configureReq := officeAdminRequest(t, actor, http.MethodPut, "/api/admin/office/providers/"+provider, configureBody)
	configureReq.SetPathValue("providerId", provider)
	configureReq.Header.Set("X-Audit-Reason", "configure qualification fixture")
	configureRec := httptest.NewRecorder()
	h.Configure(configureRec, configureReq)
	if configureRec.Code != http.StatusOK {
		t.Fatalf("configure=%d %s", configureRec.Code, configureRec.Body.String())
	}
	var configured struct {
		Generation   int64  `json:"generation"`
		ConfigSHA256 string `json:"configSha256"`
	}
	if err := json.Unmarshal(configureRec.Body.Bytes(), &configured); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_space_create($1,'qualification fixture','regular')`, driveOwner).Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT drive_node_create($1,$2,NULL,'file','fixture.docx')`, driveOwner, spaceID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1,$2,$3,10)`, driveOwner, spaceID, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	var versionRaw []byte
	if err := pool.QueryRow(ctx, `SELECT drive_file_put_version($1,$2,$3,10,$4,NULL,$5::jsonb,'v1','test')`,
		driveOwner, nodeID, strings.Repeat("c", 64),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		fmt.Sprintf(`[{"sha256":%q,"size":10}]`, strings.Repeat("b", 64))).Scan(&versionRaw); err != nil {
		t.Fatal(err)
	}
	var versionResult struct {
		VersionID int64 `json:"versionId"`
	}
	if err := json.Unmarshal(versionRaw, &versionResult); err != nil {
		t.Fatal(err)
	}
	versionID = versionResult.VersionID
	var sessionID string
	if err := pool.QueryRow(ctx, `INSERT INTO office_editor_sessions(
		space_id,file_node_id,base_version_id,provider_id,cohort_key,status,lease_expires_at)
		VALUES($1,$2,$3,$4,'qualification','active',now()+interval '1 hour') RETURNING id::text`,
		spaceID, nodeID, versionID, provider).Scan(&sessionID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO office_save_receipts(
		session_id,space_id,file_node_id,provider_id,operation_key,expected_base_id,
		content_sha256,result_version_id,response_class)
		VALUES($1,$2,$3,$4,'qualification-save',$5,$6,$5,'accepted') RETURNING id`,
		sessionID, spaceID, nodeID, provider, versionID, strings.Repeat("c", 64)).Scan(&receiptID); err != nil {
		t.Fatal(err)
	}
	qualifyBody := []byte(fmt.Sprintf(`{"expectedGeneration":%d,"syntheticReceiptId":%d,"buildDigest":"sha256:%s","routeRevision":0}`, configured.Generation, receiptID, strings.Repeat("d", 64)))
	probeFailureReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/office/providers/"+provider+"/qualify", qualifyBody)
	probeFailureReq.SetPathValue("providerId", provider)
	h.prober = officeQualificationProberStub{err: fmt.Errorf("injected probe failure")}
	probeFailureRec := httptest.NewRecorder()
	h.Qualify(probeFailureRec, probeFailureReq)
	if probeFailureRec.Code != http.StatusConflict {
		t.Fatalf("probe failure=%d %s", probeFailureRec.Code, probeFailureRec.Body.String())
	}
	marshalFailureReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/office/providers/"+provider+"/qualify", qualifyBody)
	marshalFailureReq.SetPathValue("providerId", provider)
	h.prober = officeQualificationProberStub{result: officepkg.QualificationResult{
		Checks: map[string]any{"bad": make(chan int)}, DiscoveryFingerprint: strings.Repeat("a", 64)}}
	marshalFailureRec := httptest.NewRecorder()
	h.Qualify(marshalFailureRec, marshalFailureReq)
	if marshalFailureRec.Code != http.StatusInternalServerError {
		t.Fatalf("marshal failure=%d %s", marshalFailureRec.Code, marshalFailureRec.Body.String())
	}
	h.prober = passingProbe
	qualifyReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/office/providers/"+provider+"/qualify", qualifyBody)
	qualifyReq.SetPathValue("providerId", provider)
	qualifyReq.Header.Set("X-Audit-Reason", "qualify fixture")
	qualifyRec := httptest.NewRecorder()
	h.Qualify(qualifyRec, qualifyReq)
	if qualifyRec.Code != http.StatusOK {
		t.Fatalf("qualify=%d %s", qualifyRec.Code, qualifyRec.Body.String())
	}
	var qualified struct {
		QualificationID string `json:"qualificationId"`
	}
	if err := json.Unmarshal(qualifyRec.Body.Bytes(), &qualified); err != nil {
		t.Fatal(err)
	}
	invalidActivateReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/office/providers/"+provider+"/activate",
		[]byte(`{"expectedGeneration":1,"qualificationId":"not-a-uuid"}`))
	invalidActivateRec := httptest.NewRecorder()
	h.Activate(invalidActivateRec, invalidActivateReq)
	if invalidActivateRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid activate=%d %s", invalidActivateRec.Code, invalidActivateRec.Body.String())
	}
	activateBody := []byte(fmt.Sprintf(`{"expectedGeneration":%d,"qualificationId":%q}`, configured.Generation, qualified.QualificationID))
	activateReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/office/providers/"+provider+"/activate", activateBody)
	activateReq.SetPathValue("providerId", provider)
	activateReq.Header.Set("X-Audit-Reason", "activate fixture")
	activateRec := httptest.NewRecorder()
	h.Activate(activateRec, activateReq)
	if activateRec.Code != http.StatusOK || !bytes.Contains(activateRec.Body.Bytes(), []byte(`"routeState": "active_for_scope"`)) {
		t.Fatalf("activate=%d %s", activateRec.Code, activateRec.Body.String())
	}
}

func TestOfficeAdminQualifyRejectsNonPositiveReceipt(t *testing.T) {
	h := NewOfficeHandler(nil, mailboxTestLogger())
	req := officeAdminRequest(t, 1, http.MethodPost, "/api/admin/office/providers/collabora/qualify",
		[]byte(`{"expectedGeneration":1,"syntheticReceiptId":0}`))
	req.SetPathValue("providerId", "collabora")
	rec := httptest.NewRecorder()
	h.Qualify(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("qualify invalid receipt=%d %s", rec.Code, rec.Body.String())
	}
}

func TestOfficeAppAdminLifecycleAndWireErrors(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	actor := ssCreateUser(t, pool)
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,1,$1) ON CONFLICT DO NOTHING`, actor); err != nil {
		t.Fatal(err)
	}
	testsupport.SetFeatureToggleForTest(t, pool, "feature.office_managed_delivery", true)
	provider := "managed-coverage-provider"
	if _, err := pool.Exec(ctx, `INSERT INTO office_provider_policies(
		provider_id,enabled,entitlement_state,build_id,config,route_state)
		VALUES($1,false,'evaluation','coverage','{}','connected_inactive')`, provider); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_app_operations WHERE request->>'providerId'=$1`, provider)
		_, _ = pool.Exec(context.Background(), `DELETE FROM office_provider_policies WHERE provider_id=$1`, provider)
	})
	h := NewOfficeHandler(pool, mailboxTestLogger())

	listReq := officeAdminRequest(t, actor, http.MethodGet, "/api/admin/apps", nil)
	listRec := httptest.NewRecorder()
	h.ListApps(listRec, listReq)
	if listRec.Code != http.StatusOK || !json.Valid(listRec.Body.Bytes()) {
		t.Fatalf("list apps=%d %s", listRec.Code, listRec.Body.String())
	}

	unknownReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/apps/unknown/operations", []byte(`{}`))
	unknownReq.SetPathValue("appId", "unknown")
	unknownRec := httptest.NewRecorder()
	h.RequestAppOperation(unknownRec, unknownReq)
	if unknownRec.Code != http.StatusNotFound {
		t.Fatalf("unknown app=%d %s", unknownRec.Code, unknownRec.Body.String())
	}

	key := "11111111-1111-4111-8111-111111111111"
	operationBody := []byte(fmt.Sprintf(`{"kind":"install","providerId":%q,"expectedProviderGeneration":1,"idempotencyKey":%q,"request":{"profile":"managed-wildcard","ingress":{}}}`, provider, key))
	request := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/apps/collabora-code/operations", operationBody)
	request.SetPathValue("appId", "collabora-code")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("X-Audit-Reason", "managed install coverage")
	requestRec := httptest.NewRecorder()
	h.RequestAppOperation(requestRec, request)
	if requestRec.Code != http.StatusAccepted {
		t.Fatalf("request operation=%d %s", requestRec.Code, requestRec.Body.String())
	}
	var operation struct {
		OperationID string `json:"operationId"`
	}
	if err := json.Unmarshal(requestRec.Body.Bytes(), &operation); err != nil {
		t.Fatal(err)
	}

	badKeyReq := officeAdminRequest(t, actor, http.MethodPost, "/api/admin/apps/collabora-code/operations", operationBody)
	badKeyReq.SetPathValue("appId", "collabora-code")
	badKeyReq.Header.Set("Idempotency-Key", "22222222-2222-4222-8222-222222222222")
	badKeyRec := httptest.NewRecorder()
	h.RequestAppOperation(badKeyRec, badKeyReq)
	if badKeyRec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched key=%d %s", badKeyRec.Code, badKeyRec.Body.String())
	}

	if _, err := pool.Exec(ctx, `UPDATE office_app_operations
		SET state='paused_recoverable',phase='paused_recoverable',
			executor_id='coverage-executor',lease_id='33333333-3333-4333-8333-333333333333',
			last_heartbeat_at=now(),lease_expires_at=now()+interval '1 minute'
		WHERE id=$1`, operation.OperationID); err != nil {
		t.Fatal(err)
	}
	badRecoverReq := officeAdminRequest(t, actor, http.MethodPost,
		"/api/admin/apps/collabora-code/operations/not-a-uuid/recover", []byte(`{"expectedGeneration":1}`))
	badRecoverReq.SetPathValue("appId", "collabora-code")
	badRecoverReq.SetPathValue("operationId", "not-a-uuid")
	badRecoverRec := httptest.NewRecorder()
	h.RecoverAppOperation(badRecoverRec, badRecoverReq)
	if badRecoverRec.Code != http.StatusBadRequest {
		t.Fatalf("bad recovery id=%d %s", badRecoverRec.Code, badRecoverRec.Body.String())
	}

	recoverReq := officeAdminRequest(t, actor, http.MethodPost,
		"/api/admin/apps/collabora-code/operations/"+operation.OperationID+"/recover", []byte(`{"expectedGeneration":1}`))
	recoverReq.SetPathValue("appId", "collabora-code")
	recoverReq.SetPathValue("operationId", operation.OperationID)
	recoverReq.Header.Set("X-Audit-Reason", "managed recovery coverage")
	recoverRec := httptest.NewRecorder()
	h.RecoverAppOperation(recoverRec, recoverReq)
	if recoverRec.Code != http.StatusAccepted || !bytes.Contains(recoverRec.Body.Bytes(), []byte(`"recoveryRequested": true`)) {
		t.Fatalf("recover=%d %s", recoverRec.Code, recoverRec.Body.String())
	}
}

func TestOfficeAdminRejectsMalformedBodiesAndClosedDatabase(t *testing.T) {
	closed := mailboxTestPool(t)
	closed.Close()
	h := NewOfficeHandler(closed, mailboxTestLogger())
	validID := "11111111-1111-4111-8111-111111111111"

	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"list":      h.List,
		"list apps": h.ListApps,
	} {
		req := officeAdminRequest(t, 1, http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		call(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s closed database=%d %s", name, rec.Code, rec.Body.String())
		}
	}

	cases := []struct {
		name string
		body string
		prep func(*http.Request)
		call func(http.ResponseWriter, *http.Request)
		want int
	}{
		{"configure closed", `{"expectedGeneration":1,"profile":"existing-provider","entitlementState":"valid","config":{}}`, func(r *http.Request) { r.SetPathValue("providerId", "provider") }, h.Configure, 500},
		{"configure missing config", `{"expectedGeneration":1}`, nil, h.Configure, 400},
		{"configure trailing", `{} {}`, nil, h.Configure, 400},
		{"qualify closed", `{"expectedGeneration":1,"syntheticReceiptId":1}`, func(r *http.Request) { r.SetPathValue("providerId", "provider") }, h.Qualify, 500},
		{"activate malformed", `{`, nil, h.Activate, 400},
		{"activate closed", `{"expectedGeneration":1,"qualificationId":"` + validID + `"}`, func(r *http.Request) { r.SetPathValue("providerId", "provider") }, h.Activate, 500},
		{"operation malformed", `{`, func(r *http.Request) { r.SetPathValue("appId", "collabora-code") }, h.RequestAppOperation, 400},
		{"operation closed", `{"kind":"install","providerId":"provider","expectedProviderGeneration":1,"idempotencyKey":"` + validID + `","request":{"profile":"managed-wildcard","ingress":{}}}`, func(r *http.Request) {
			r.SetPathValue("appId", "collabora-code")
			r.Header.Set("Idempotency-Key", validID)
		}, h.RequestAppOperation, 500},
		{"operation missing request", `{"kind":"install","providerId":"provider","expectedProviderGeneration":1,"idempotencyKey":"` + validID + `"}`, func(r *http.Request) {
			r.SetPathValue("appId", "collabora-code")
			r.Header.Set("Idempotency-Key", validID)
		}, h.RequestAppOperation, 400},
		{"recover closed", `{"expectedGeneration":1}`, func(r *http.Request) {
			r.SetPathValue("appId", "collabora-code")
			r.SetPathValue("operationId", validID)
		}, h.RecoverAppOperation, 500},
		{"recover unknown app", `{"expectedGeneration":1}`, func(r *http.Request) { r.SetPathValue("appId", "unknown") }, h.RecoverAppOperation, 404},
		{"recover malformed", `{`, func(r *http.Request) {
			r.SetPathValue("appId", "collabora-code")
			r.SetPathValue("operationId", validID)
		}, h.RecoverAppOperation, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := officeAdminRequest(t, 1, http.MethodPost, "/", []byte(tc.body))
			req.Header.Set("X-Audit-Reason", "coverage")
			if tc.prep != nil {
				tc.prep(req)
			}
			rec := httptest.NewRecorder()
			tc.call(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}
