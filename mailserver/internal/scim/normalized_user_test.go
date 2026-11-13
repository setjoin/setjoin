package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func normalizedSCIMContext(sourceID, generation int64, deletion string) context.Context {
	ctx := context.WithValue(context.Background(), ctxSourceID, sourceID)
	ctx = context.WithValue(ctx, ctxSourceGeneration, generation)
	if deletion != "" {
		ctx = context.WithValue(ctx, ctxDeletionPolicy, deletion)
	}
	return ctx
}

func enableIdentityModelForSCIMTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
}

// TestNormalizedSCIMUserLifecycle drives the HTTP adapter and the generation-
// fenced source reducer together. It proves immutable externalId ownership,
// replace/patch behavior, hard-delete refusal, and soft deprovision.
func TestNormalizedSCIMUserLifecycle(t *testing.T) {
	pool := scimTestPool(t)
	enableIdentityModelForSCIMTest(t, pool)
	ctx := context.Background()
	suffix := scimRandomSuffix(t)
	domain := "scim-normalized-" + suffix + ".local"
	sourceKey := "scim:test-" + suffix

	var sourceID, generation int64
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`,
		domain,
	); err != nil {
		t.Fatalf("create SCIM normalized domain: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'scim','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')
		RETURNING id,generation`,
		sourceKey, "SCIM normalized "+suffix,
	).Scan(&sourceID, &generation); err != nil {
		t.Fatalf("create SCIM normalized source: %v", err)
	}
	authServer, revoked := fakeAuthServer(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(),
		authServer.URL, "test-internal-key")
	sourceCtx := normalizedSCIMContext(sourceID, generation, "soft")

	fields := scimUserFields{
		displayName: "Normalized User", firstName: "Normalized", lastName: "User",
		primaryEmail: "person@" + domain, phone: "100", department: "Platform",
		active: true,
	}
	userID, err := s.applySourceUser(sourceCtx, "external-"+suffix, fields, "Engineer", 0)
	if err != nil {
		t.Fatalf("apply normalized SCIM user: %v", err)
	}
	if userID <= 0 {
		t.Fatalf("normalized SCIM user id=%d", userID)
	}

	syncReq := httptest.NewRequest(
		http.MethodGet,
		"/scim/v2/Users?syncToken="+encodeSyncToken(sourceID, time.Now().Add(-time.Hour)),
		nil,
	).WithContext(sourceCtx)
	syncRec := httptest.NewRecorder()
	s.GetUsers(syncRec, syncReq)
	if syncRec.Code != http.StatusOK {
		t.Fatalf("initial normalized SCIM sync status=%d body=%s", syncRec.Code, syncRec.Body.String())
	}
	var syncList ListResponse
	if err := json.Unmarshal(syncRec.Body.Bytes(), &syncList); err != nil {
		t.Fatalf("decode normalized SCIM sync: %v", err)
	}
	if syncList.TotalResults != 1 || syncList.ItemsPerPage != 1 ||
		syncRec.Header().Get("Location") == "" {
		t.Fatalf("normalized SCIM sync did not return the source row and next cursor: response=%+v location=%q",
			syncList, syncRec.Header().Get("Location"))
	}

	subject, err := s.sourceSubjectForUser(sourceCtx, userID)
	if err != nil || subject != "external-"+suffix {
		t.Fatalf("source subject=%q err=%v", subject, err)
	}
	resource, subject, err := s.sourceUserForPatch(sourceCtx, userID)
	if err != nil {
		t.Fatalf("load normalized SCIM patch resource: %v", err)
	}
	if subject != "external-"+suffix || resource.DisplayName != "Normalized User" {
		t.Fatalf("normalized SCIM resource=%+v subject=%q", resource, subject)
	}

	replace := resource
	replace.UserName = fields.primaryEmail
	replace.ExternalID = subject
	replace.DisplayName = "Replaced User"
	replaceBody, _ := json.Marshal(replace)
	req := httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(replaceBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec := httptest.NewRecorder()
	s.ReplaceUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	inactive := false
	replace.Active = &inactive
	replaceBody, _ = json.Marshal(replace)
	req = httptest.NewRequest(http.MethodPut,
		"/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(replaceBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.ReplaceUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace disable normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	select {
	case got := <-revoked:
		if got != userID {
			t.Fatalf("PUT active=false revoked user=%d, want %d", got, userID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PUT active=false did not revoke live sessions")
	}
	active := true
	replace.Active = &active
	replaceBody, _ = json.Marshal(replace)
	req = httptest.NewRequest(http.MethodPut,
		"/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(replaceBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.ReplaceUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace re-enable normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}

	replace.ExternalID = "changed-subject"
	replaceBody, _ = json.Marshal(replace)
	req = httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(replaceBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.ReplaceUser(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("replace changed externalId status=%d body=%s", rec.Code, rec.Body.String())
	}

	unknownID := userID + 1_000_000_000
	replace.ExternalID = subject
	replaceBody, _ = json.Marshal(replace)
	req = httptest.NewRequest(http.MethodPut, "/scim/v2/Users/"+strconv.FormatInt(unknownID, 10), bytes.NewReader(replaceBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(unknownID, 10))
	rec = httptest.NewRecorder()
	s.ReplaceUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("replace unmanaged user status=%d body=%s", rec.Code, rec.Body.String())
	}

	patchBody := []byte(`{"Operations":[{"op":"replace","path":"displayName","value":"Patched User"},{"op":"replace","path":"title","value":"Principal"}]}`)
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(patchBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	fullPatchBody := []byte(fmt.Sprintf(`{"Operations":[
		{"op":"replace","path":"displayName","value":"Fully Patched User"},
		{"op":"replace","path":"name.givenName","value":"Fully"},
		{"op":"replace","path":"name.familyName","value":"Patched"},
		{"op":"replace","path":"title","value":"Architect"},
		{"op":"replace","path":"emails","value":[{"value":%q,"type":"work","primary":true}]},
		{"op":"replace","path":"phoneNumbers","value":[{"value":"200","type":"work"}]},
		{"op":"replace","path":"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department","value":"Architecture"},
		{"op":"replace","path":"active","value":true}
	]}`, "patched@"+domain))
	req = httptest.NewRequest(http.MethodPatch,
		"/scim/v2/Users/"+strconv.FormatInt(userID, 10), bytes.NewReader(fullPatchBody)).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("full patch normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	var fullDisplayName, fullFirstName, fullLastName, fullTitle, fullEmail, fullPhone, fullDepartment string
	if err := pool.QueryRow(ctx, `
		SELECT u.display_name,u.first_name,u.last_name,u.job_title,u.email,u.phone,d.path
		  FROM users u
		  JOIN departments d ON d.id=u.department_id
		 WHERE u.id=$1`, userID,
	).Scan(&fullDisplayName, &fullFirstName, &fullLastName, &fullTitle, &fullEmail, &fullPhone, &fullDepartment); err != nil {
		t.Fatalf("read full patch result: %v", err)
	}
	if fullDisplayName != "Fully Patched User" || fullFirstName != "Fully" ||
		fullLastName != "Patched" || fullTitle != "Architect" ||
		fullEmail != "patched@"+domain || fullPhone != "200" ||
		fullDepartment != "Architecture" {
		t.Fatalf("full patch did not persist every touched field: display=%q first=%q last=%q title=%q email=%q phone=%q department=%q",
			fullDisplayName, fullFirstName, fullLastName, fullTitle, fullEmail, fullPhone, fullDepartment)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET enabled=FALSE WHERE id=$1`, userID); err != nil {
		t.Fatalf("simulate concurrent lifecycle disable: %v", err)
	}
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(userID, 10),
		bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"title","value":"Principal II"}]}`))).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sparse patch normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	var sparseEnabled bool
	var sparseDepartment, sparseTitle string
	if err := pool.QueryRow(ctx, `
		SELECT u.enabled,d.path,u.job_title
		  FROM users u
		  JOIN departments d ON d.id=u.department_id
		 WHERE u.id=$1`, userID,
	).Scan(&sparseEnabled, &sparseDepartment, &sparseTitle); err != nil {
		t.Fatalf("read sparse patch result: %v", err)
	}
	if sparseEnabled || sparseDepartment != "Architecture" || sparseTitle != "Principal II" {
		t.Fatalf("sparse patch overwrote unrelated state: enabled=%v department=%q title=%q",
			sparseEnabled, sparseDepartment, sparseTitle)
	}

	var otherSourceID, otherGeneration int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'scim','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')
		RETURNING id,generation`,
		sourceKey+"-other", "Other SCIM "+suffix,
	).Scan(&otherSourceID, &otherGeneration); err != nil {
		t.Fatalf("create second SCIM source: %v", err)
	}
	otherCtx := normalizedSCIMContext(otherSourceID, otherGeneration, "soft")
	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), nil).
		WithContext(otherCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.GetUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-source direct read status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := decodeSyncToken(encodeSyncToken(sourceID, time.Now()), otherSourceID); err == nil {
		t.Fatal("cross-source sync token must be rejected")
	}

	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(unknownID, 10),
		bytes.NewReader([]byte(`{"Operations":[]}`))).WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(unknownID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch unmanaged user status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(userID, 10),
		bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"unsupported","value":"x"}]}`))).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("patch unsupported path status=%d body=%s", rec.Code, rec.Body.String())
	}

	staleCtx := normalizedSCIMContext(sourceID, generation+1, "soft")
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(userID, 10),
		bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"title","value":"Stale"}]}`))).
		WithContext(staleCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code < http.StatusBadRequest {
		t.Fatalf("patch with stale source generation status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+strconv.FormatInt(userID, 10),
		bytes.NewReader([]byte(`{"Operations":[{"op":"replace","path":"active","value":false}]}`))).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.PatchUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch disable normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}

	hardCtx := normalizedSCIMContext(sourceID, generation, "hard")
	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), nil).
		WithContext(hardCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.DeleteUser(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("hard delete normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+strconv.FormatInt(unknownID, 10), nil).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(unknownID, 10))
	rec = httptest.NewRecorder()
	s.DeleteUser(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unmanaged user status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+strconv.FormatInt(userID, 10), nil).
		WithContext(sourceCtx)
	req.SetPathValue("id", strconv.FormatInt(userID, 10))
	rec = httptest.NewRecorder()
	s.DeleteUser(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("soft delete normalized SCIM status=%d body=%s", rec.Code, rec.Body.String())
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id=$1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read SCIM disabled state: %v", err)
	}
	if enabled {
		t.Fatal("normalized SCIM soft delete did not disable user")
	}
}

func TestNormalizedSCIMApplyRejectsUnboundOrMissingSubject(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	fields := scimUserFields{primaryEmail: "nobody@example.invalid", active: true}
	if _, err := s.applySourceUser(context.Background(), "subject", fields, "", 0); err == nil {
		t.Fatal("unbound SCIM context must fail closed")
	}
	ctx := normalizedSCIMContext(1, 1, "soft")
	if _, err := s.applySourceUser(ctx, "", fields, "", 0); err == nil {
		t.Fatal("empty immutable SCIM subject must be rejected")
	}
	if _, err := s.sourceSubjectForUser(context.Background(), 1); err == nil {
		t.Fatal("source subject lookup without source binding must fail")
	}
}

func TestNormalizedSCIMSourceResolutionFailsClosedOnDatabaseError(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	pool.Close()
	if _, _, err := s.sourceUserForPatch(normalizedSCIMContext(1, 1, "soft"), 1); err == nil {
		t.Fatal("source ownership lookup database failure did not stop mutation")
	}
}

func TestNormalizedSCIMCreateReportsBindingAndSubjectErrors(t *testing.T) {
	pool := scimTestPool(t)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	body := func(externalID string) *bytes.Reader {
		resource := UserResource{
			UserName: "person@example.invalid", ExternalID: externalID,
			Emails: []EmailAttr{{Value: "person@example.invalid"}},
		}
		raw, err := json.Marshal(resource)
		if err != nil {
			t.Fatalf("marshal SCIM resource: %v", err)
		}
		return bytes.NewReader(raw)
	}

	rec := httptest.NewRecorder()
	s.CreateUser(rec, httptest.NewRequest(http.MethodPost, "/scim/v2/Users", body("subject")))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unbound SCIM create status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", body("")).
		WithContext(normalizedSCIMContext(1, 1, "soft"))
	s.CreateUser(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing SCIM externalId status=%d body=%s", rec.Code, rec.Body.String())
	}
}
