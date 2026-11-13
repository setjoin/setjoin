package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestIdentityOperatorEndpointsRejectInvalidAndUnauthorizedRequestsBeforeDatabase(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	pool := testsupport.OpenTestPool(t)
	dbHandler := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	validJobID := uuid.NewString()
	validTransitionID := uuid.NewString()
	validKey := uuid.NewString()
	validDigest := strings.Repeat("a", 64)
	reason := "bounded identity operator contract test"

	adminRequest := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("X-Audit-Reason", reason)
		return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            42,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
	}
	call := func(
		name string,
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}

	call("doctor invalid source", dbHandler.IdentityDoctor,
		adminRequest(http.MethodGet, "/admin/identity/v2/doctor?source=bad%20key", ""),
		http.StatusBadRequest)
	call("doctor missing worker", h.IdentityDoctor,
		adminRequest(http.MethodGet, "/admin/identity/v2/doctor", ""),
		http.StatusServiceUnavailable)
	call("inventory missing permission", h.IdentityInventoryExport,
		httptest.NewRequest(http.MethodGet, "/admin/identity/v2/inventory/export", nil).
			WithContext(auth.ContextWithUser(t.Context(), &auth.Claims{
				UserID: 42, GlobalPermissions: []string{permissions.PermUsersRead},
			})),
		http.StatusForbidden)

	unauthJob := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/jobs/"+validJobID, nil)
	unauthJob.SetPathValue("id", validJobID)
	call("job unauthenticated", h.IdentityJob, unauthJob, http.StatusUnauthorized)
	badJob := adminRequest(http.MethodGet, "/admin/identity/v2/jobs/bad", "")
	badJob.SetPathValue("id", "bad")
	call("job invalid id", h.IdentityJob, badJob, http.StatusBadRequest)

	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		suffix  string
		body    string
		want    int
	}{
		{"cancel unauthenticated", h.IdentityJobCancel, http.MethodPost, "/cancel", "", http.StatusUnauthorized},
		{"results unauthenticated", h.IdentityJobResults, http.MethodGet, "/results", "", http.StatusUnauthorized},
		{"download unauthenticated", h.IdentityDiagnosticDownload, http.MethodGet, "/download", "", http.StatusUnauthorized},
		{"delete malformed JSON", h.IdentityDiagnosticDelete, http.MethodDelete, "", `{`, http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method,
			"/admin/identity/v2/jobs/"+validJobID+tc.suffix, strings.NewReader(tc.body))
		req.SetPathValue("id", validJobID)
		call(tc.name, tc.handler, req, tc.want)
	}

	validDiagnostic := `{"sourceKey":"local:default","sinceSeconds":60,` +
		`"reason":"` + reason + `","idempotencyKey":"` + validKey + `"}`
	for _, tc := range []struct {
		name string
		body string
		edit func(*http.Request)
		want int
	}{
		{"malformed JSON", `{`, nil, http.StatusBadRequest},
		{"reason mismatch", validDiagnostic, func(r *http.Request) {
			r.Header.Set("X-Audit-Reason", "different reason")
		}, http.StatusBadRequest},
		{"idempotency mismatch", validDiagnostic, func(r *http.Request) {
			r.Header.Set("Idempotency-Key", uuid.NewString())
		}, http.StatusBadRequest},
		{"invalid transition", `{"transitionId":"bad","sinceSeconds":60,"reason":"` + reason +
			`","idempotencyKey":"` + validKey + `"}`, nil, http.StatusBadRequest},
		{"both scopes", `{"sourceKey":"local:default","transitionId":"` + validTransitionID +
			`","sinceSeconds":60,"reason":"` + reason + `","idempotencyKey":"` +
			validKey + `"}`, nil, http.StatusBadRequest},
		{"missing scope", `{"sinceSeconds":60,"reason":"` + reason +
			`","idempotencyKey":"` + validKey + `"}`, nil, http.StatusBadRequest},
		{"invalid source", `{"sourceKey":"bad key","sinceSeconds":60,"reason":"` + reason +
			`","idempotencyKey":"` + validKey + `"}`, nil, http.StatusBadRequest},
		{"range too small", `{"sourceKey":"local:default","sinceSeconds":0,"reason":"` +
			reason + `","idempotencyKey":"` + validKey + `"}`, nil, http.StatusBadRequest},
		{"range too large", `{"sourceKey":"local:default","sinceSeconds":86401,"reason":"` +
			reason + `","idempotencyKey":"` + validKey + `"}`, nil, http.StatusBadRequest},
	} {
		req := adminRequest(http.MethodPost, "/admin/identity/v2/diagnostics", tc.body)
		if tc.edit != nil {
			tc.edit(req)
		}
		call("diagnostic "+tc.name, h.IdentityDiagnosticCreate, req, tc.want)
	}
	unauthDiagnostic := httptest.NewRequest(http.MethodPost,
		"/admin/identity/v2/diagnostics", strings.NewReader(validDiagnostic))
	unauthDiagnostic.Header.Set("X-Audit-Reason", reason)
	call("diagnostic unauthenticated", h.IdentityDiagnosticCreate,
		unauthDiagnostic, http.StatusUnauthorized)

	deleteNoReason := adminRequest(http.MethodDelete,
		"/admin/identity/v2/diagnostics/"+validJobID, `{"reason":""}`)
	deleteNoReason.SetPathValue("id", validJobID)
	call("diagnostic delete missing reason", h.IdentityDiagnosticDelete,
		deleteNoReason, http.StatusBadRequest)
	deleteBadID := adminRequest(http.MethodDelete,
		"/admin/identity/v2/diagnostics/bad", `{"reason":"`+reason+`"}`)
	deleteBadID.SetPathValue("id", "bad")
	call("diagnostic delete invalid id", h.IdentityDiagnosticDelete,
		deleteBadID, http.StatusBadRequest)

	call("upgrade preflight missing worker", h.IdentityUpgradePreflight,
		adminRequest(http.MethodGet, "/admin/identity/v2/upgrade/preflight", ""),
		http.StatusServiceUnavailable)
	for _, tc := range []struct {
		name string
		body string
		edit func(*http.Request)
		want int
	}{
		{"malformed JSON", `{`, nil, http.StatusBadRequest},
		{"unknown action", `{"action":"unknown"}`, nil, http.StatusBadRequest},
		{"start missing reason", `{"action":"start"}`, nil, http.StatusBadRequest},
		{"start idempotency mismatch", `{"action":"start","preflightChecksum":"` +
			validDigest + `","reason":"` + reason + `","idempotencyKey":"` +
			validKey + `"}`, func(r *http.Request) {
			r.Header.Set("Idempotency-Key", uuid.NewString())
		}, http.StatusBadRequest},
		{"start invalid checksum", `{"action":"start","preflightChecksum":"bad",` +
			`"reason":"` + reason + `","idempotencyKey":"` + validKey + `"}`,
			nil, http.StatusBadRequest},
	} {
		req := adminRequest(http.MethodPost, "/admin/identity/v2/upgrade/backfill", tc.body)
		if tc.edit != nil {
			tc.edit(req)
		}
		call("backfill "+tc.name, h.IdentityUpgradeBackfill, req, tc.want)
	}
	call("backfill plan missing worker", h.IdentityUpgradeBackfill,
		adminRequest(http.MethodPost, "/admin/identity/v2/upgrade/backfill",
			`{"action":"plan"}`), http.StatusServiceUnavailable)
	call("shadow invalid source", h.IdentityUpgradeShadow,
		adminRequest(http.MethodGet, "/admin/identity/v2/upgrade/shadow?sourceKey=bad%20key", ""),
		http.StatusBadRequest)
	call("retirement missing worker", h.IdentityUpgradeRetirementCheck,
		adminRequest(http.MethodGet, "/admin/identity/v2/upgrade/retirement-check", ""),
		http.StatusServiceUnavailable)
}
