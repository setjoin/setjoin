package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// The identity operator API is intentionally fail-closed when its worker
// credential disappears. This matrix reaches each database call with a valid
// request, then proves connection loss is never mistaken for an empty or
// successful response.
func TestIdentityHandlersFailClosedAfterWorkerDatabaseLoss(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(testConfigSecretCodec(t))

	transitionID := uuid.NewString()
	conflictID := uuid.NewString()
	jobID := uuid.NewString()
	idempotency := uuid.NewString()
	digestForTest := strings.Repeat("a", 64)
	reason := "closed identity worker database test"
	sourceKey := "closed-worker"
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"` + sourceKey + `","displayName":"Closed worker"},` +
		`"spec":{"type":"oidc","providerKey":"closed-worker",` +
		`"issuer":"https://idp.example.test","clientId":"setjoin",` +
		`"subjectClaim":"sub"}}`

	request := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		claims := &auth.Claims{
			UserID:            42,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
			JTI:               "closed-worker-session",
			ACR:               jwtutil.ACRAAL2,
			AMR: []string{
				jwtutil.AMRMultiFactor,
				jwtutil.AMROTP,
				jwtutil.AMRPassword,
			},
		}
		claims.IssuedAt = jwtutil.NewNumericDate(time.Now().Add(-time.Minute))
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		req.Header.Set("X-Audit-Reason", reason)
		return req
	}
	type handlerCase struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		req     *http.Request
	}
	cases := []handlerCase{
		{"doctor", h.IdentityDoctor, request(http.MethodGet,
			"/admin/identity/v2/doctor?source="+sourceKey, "")},
		{"inventory export", h.IdentityInventoryExport, request(http.MethodGet,
			"/admin/identity/v2/inventory/export", "")},
		{"diagnostic create", h.IdentityDiagnosticCreate, request(http.MethodPost,
			"/admin/identity/v2/diagnostics",
			`{"sourceKey":"`+sourceKey+`","sinceSeconds":60,`+
				`"reason":"`+reason+`","idempotencyKey":"`+idempotency+`"}`)},
		{"sources", h.Sources, request(http.MethodGet,
			"/admin/identity/v2/sources", "")},
		{"people", h.IdentityPeople, request(http.MethodGet,
			"/admin/identity/v2/people", "")},
		{"conflicts", h.IdentityConflicts, request(http.MethodGet,
			"/admin/identity/v2/conflicts", "")},
		{"transitions", h.IdentityTransitions, request(http.MethodGet,
			"/admin/identity/v2/transitions", "")},
		{"events", h.IdentityEvents, request(http.MethodGet,
			"/admin/identity/v2/events", "")},
		{"source plan", h.IdentitySourcePlan, request(http.MethodPost,
			"/admin/identity/v2/sources:plan", document)},
		{"source apply", h.IdentitySourceApply, request(http.MethodPost,
			"/admin/identity/v2/sources:apply",
			`{"document":`+document+`,"reason":"`+reason+
				`","idempotencyKey":"`+idempotency+`"}`)},
		{"upgrade status", h.IdentityUpgradeStatus, request(http.MethodGet,
			"/admin/identity/v2/upgrade/status", "")},
		{"upgrade preflight", h.IdentityUpgradePreflight, request(http.MethodGet,
			"/admin/identity/v2/upgrade/preflight", "")},
		{"upgrade backfill plan", h.IdentityUpgradeBackfill, request(http.MethodPost,
			"/admin/identity/v2/upgrade/backfill", `{"action":"plan"}`)},
		{"upgrade backfill start", h.IdentityUpgradeBackfill, request(http.MethodPost,
			"/admin/identity/v2/upgrade/backfill",
			`{"action":"start","preflightChecksum":"`+digestForTest+`",`+
				`"reason":"`+reason+`","idempotencyKey":"`+idempotency+`"}`)},
		{"upgrade shadow", h.IdentityUpgradeShadow, request(http.MethodGet,
			"/admin/identity/v2/upgrade/shadow?sourceKey="+sourceKey, "")},
		{"upgrade retirement", h.IdentityUpgradeRetirementCheck, request(http.MethodGet,
			"/admin/identity/v2/upgrade/retirement-check", "")},
		{"upgrade canary", h.IdentityUpgradeCanary, request(http.MethodPost,
			"/admin/identity/v2/upgrade/canary",
			`{"sourceKey":"`+sourceKey+`","expectedGeneration":"1",`+
				`"enabled":false,"userIds":[],"reason":"`+reason+`"}`)},
		{"upgrade rollback", h.IdentityUpgradeRollback, request(http.MethodPost,
			"/admin/identity/v2/upgrade/rollback",
			`{"readPath":"legacy","reason":"`+reason+`"}`)},
		{"transition preview", h.TransitionPreview, request(http.MethodPost,
			"/admin/identity/v2/transitions/preview",
			`{"userId":"42","reason":"`+reason+
				`","idempotencyKey":"`+idempotency+`"}`)},
	}

	for index := range cases {
		tc := &cases[index]
		switch tc.name {
		case "source apply", "diagnostic create", "upgrade backfill start":
			tc.req.Header.Set("Idempotency-Key", idempotency)
		case "upgrade canary":
			tc.req.Header.Set("If-Match", `"1"`)
		case "transition preview":
			tc.req.Header.Set("Idempotency-Key", idempotency)
		}
	}

	pathCases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		target  string
		path    map[string]string
		body    string
	}{
		{"job", h.IdentityJob, http.MethodGet, "/jobs/" + jobID,
			map[string]string{"id": jobID}, ""},
		{"job cancel", h.IdentityJobCancel, http.MethodPost, "/jobs/" + jobID + "/cancel",
			map[string]string{"id": jobID}, ""},
		{"job results", h.IdentityJobResults, http.MethodGet,
			"/jobs/" + jobID + "/results?after=0&limit=1",
			map[string]string{"id": jobID}, ""},
		{"diagnostic download", h.IdentityDiagnosticDownload, http.MethodGet,
			"/diagnostics/" + jobID + "/download",
			map[string]string{"id": jobID}, ""},
		{"diagnostic delete", h.IdentityDiagnosticDelete, http.MethodDelete,
			"/diagnostics/" + jobID,
			map[string]string{"id": jobID},
			`{"reason":"` + reason + `"}`},
		{"person detail", h.IdentityPersonDetail, http.MethodGet, "/people/42",
			map[string]string{"id": "42"}, ""},
		{"conflict detail", h.IdentityConflictDetail, http.MethodGet,
			"/conflicts/" + conflictID,
			map[string]string{"id": conflictID}, ""},
		{"transition detail", h.IdentityTransition, http.MethodGet,
			"/transitions/" + transitionID,
			map[string]string{"id": transitionID}, ""},
		{"transition report", h.IdentityTransitionReport, http.MethodGet,
			"/transitions/" + transitionID + "/report",
			map[string]string{"id": transitionID}, ""},
		{"source detail", h.IdentitySourceDetail, http.MethodGet,
			"/sources/" + sourceKey,
			map[string]string{"sourceKey": sourceKey}, ""},
		{"source export", h.IdentitySourceExport, http.MethodGet,
			"/sources/" + sourceKey + "/export",
			map[string]string{"sourceKey": sourceKey}, ""},
	}
	for _, tc := range pathCases {
		req := request(tc.method, tc.target, tc.body)
		for key, value := range tc.path {
			req.SetPathValue(key, value)
		}
		cases = append(cases, handlerCase{tc.name, tc.handler, req})
	}

	challengeID := uuid.NewString()
	elevationID := uuid.NewString()
	effectID := uuid.NewString()
	authorizedBody := func(approval bool) string {
		approvalField := ""
		if approval {
			approvalField = `,"approvalRequestId":"42"`
		}
		return `{"previewDigest":"` + digestForTest +
			`","elevationId":"` + elevationID + `","reason":"` + reason +
			`","idempotencyKey":"` + idempotency + `"` + approvalField + `}`
	}
	transitionCases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		body    string
		effect  bool
	}{
		{"challenge issue", h.TransitionChallengeIssue,
			`{"previewDigest":"` + digestForTest +
				`","idempotencyKey":"` + idempotency + `"}`, false},
		{"challenge complete", h.TransitionChallengeComplete,
			`{"challengeId":"` + challengeID + `","previewDigest":"` +
				digestForTest + `","idempotencyKey":"` + idempotency + `"}`, false},
		{"transition request", h.TransitionRequest, authorizedBody(false), false},
		{"transition approve", h.TransitionApprove, authorizedBody(false), false},
		{"transition deny", h.TransitionDeny, authorizedBody(false), false},
		{"transition execute", h.TransitionExecuteAuthorized, authorizedBody(false), false},
		{"transition rollback", h.TransitionRollback, authorizedBody(true), false},
		{"transition cancel", h.TransitionCancel,
			`{"expectedGeneration":"1","reason":"` + reason +
				`","idempotencyKey":"` + idempotency + `"}`, false},
		{"transition rollback preview", h.TransitionRollbackPreview,
			`{"expectedGeneration":"1","reason":"` + reason +
				`","idempotencyKey":"` + idempotency + `"}`, false},
		{"transition retry", h.TransitionRetry,
			`{"expectedGeneration":"1","reason":"` + reason +
				`","idempotencyKey":"` + idempotency + `"}`, true},
	}
	for _, tc := range transitionCases {
		req := request(http.MethodPost, "/transitions/"+transitionID, tc.body)
		req.SetPathValue("id", transitionID)
		if tc.effect {
			req.SetPathValue("effectId", effectID)
		}
		req.Header.Set("Idempotency-Key", idempotency)
		if strings.Contains(tc.body, "previewDigest") {
			req.Header.Set("If-Match", `"`+digestForTest+`"`)
		} else {
			req.Header.Set("If-Match", `"1"`)
		}
		cases = append(cases, handlerCase{tc.name, tc.handler, req})
	}

	lifecycleBody := `{"expectedGeneration":"1","reason":"` + reason +
		`","idempotencyKey":"` + idempotency + `"}`
	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"source activate": h.IdentitySourceActivate,
		"source pause":    h.IdentitySourcePause,
		"source resume":   h.IdentitySourceResume,
		"source retire":   h.IdentitySourceRetire,
		"source dry run":  h.IdentitySourceDryRun,
	} {
		req := request(http.MethodPost, "/sources/"+sourceKey, lifecycleBody)
		req.SetPathValue("sourceKey", sourceKey)
		req.Header.Set("If-Match", `"1"`)
		req.Header.Set("Idempotency-Key", idempotency)
		cases = append(cases, handlerCase{name, handler, req})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, tc.req)
			if rec.Code < http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
