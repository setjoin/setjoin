package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

type scriptedIdentityRow struct {
	scan func(...any) error
}

func (r scriptedIdentityRow) Scan(dest ...any) error {
	return r.scan(dest...)
}

type scriptedIdentityWorker struct {
	rows      []pgx.Row
	queryRows []pgx.Rows
	queryErr  error
}

func (w *scriptedIdentityWorker) Query(
	context.Context, string, ...any,
) (pgx.Rows, error) {
	if len(w.queryRows) > 0 {
		rows := w.queryRows[0]
		w.queryRows = w.queryRows[1:]
		return rows, nil
	}
	return nil, w.queryErr
}

func (w *scriptedIdentityWorker) QueryRow(
	context.Context, string, ...any,
) pgx.Row {
	if len(w.rows) == 0 {
		return scriptedIdentityRow{scan: func(...any) error {
			return errors.New("unexpected identity worker query")
		}}
	}
	row := w.rows[0]
	w.rows = w.rows[1:]
	return row
}

type scriptedIdentityRows struct {
	next      bool
	scanErr   error
	rowsErr   error
	exhausted bool
}

func (r *scriptedIdentityRows) Close() {
	r.exhausted = true
}

func (r *scriptedIdentityRows) Err() error {
	return r.rowsErr
}

func (*scriptedIdentityRows) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}

func (*scriptedIdentityRows) FieldDescriptions() []pgconn.FieldDescription {
	return nil
}

func (r *scriptedIdentityRows) Next() bool {
	if r.exhausted || !r.next {
		r.exhausted = true
		return false
	}
	r.exhausted = true
	return true
}

func (r *scriptedIdentityRows) Scan(...any) error {
	return r.scanErr
}

func (*scriptedIdentityRows) Values() ([]any, error) {
	return nil, errors.New("values are not used")
}

func (*scriptedIdentityRows) RawValues() [][]byte {
	return nil
}

func (*scriptedIdentityRows) Conn() *pgx.Conn {
	return nil
}

func identityRawRow(raw string) pgx.Row {
	return scriptedIdentityRow{scan: func(dest ...any) error {
		value, ok := dest[0].(*json.RawMessage)
		if !ok {
			return errors.New("expected JSON destination")
		}
		*value = append((*value)[:0], raw...)
		return nil
	}}
}

func identityErrorRow(err error) pgx.Row {
	return scriptedIdentityRow{scan: func(...any) error { return err }}
}

func identityBoolRow(value bool) pgx.Row {
	return scriptedIdentityRow{scan: func(dest ...any) error {
		output, ok := dest[0].(*bool)
		if !ok {
			return errors.New("expected bool destination")
		}
		*output = value
		return nil
	}}
}

func identitySourceRowFixture(envelope []byte) pgx.Row {
	return scriptedIdentityRow{scan: func(dest ...any) error {
		*dest[0].(*int64) = 1
		*dest[1].(*string) = "worker-source"
		*dest[2].(*string) = "Worker Source"
		*dest[3].(*string) = "oidc"
		*dest[4].(*string) = "active"
		*dest[5].(*int64) = 1
		*dest[6].(*int64) = 1
		*dest[7].(*int64) = 1
		*dest[8].(*[]byte) = append([]byte(nil), envelope...)
		*dest[9].(*json.RawMessage) = json.RawMessage(`{"authenticate":true}`)
		return nil
	}}
}

type identityReadFailure struct{}

func (identityReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func identityWorkerAdminRequest(
	method string, target string, body string,
) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:            42,
		IsAdmin:           true,
		Permissions:       permissions.AllPermissions,
		GlobalPermissions: permissions.AllPermissions,
	}))
}

func TestIdentityJobAndDiagnosticDefensiveResponseBranches(t *testing.T) {
	jobID := uuid.NewString()
	validJob := `{"kind":"diagnostics","terminal":false}`
	call := func(
		name string,
		worker *scriptedIdentityWorker,
		handler func(*IdentityHandler, http.ResponseWriter, *http.Request),
		method string,
		suffix string,
		body string,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = worker
			req := identityWorkerAdminRequest(method,
				"/admin/identity/v2/jobs/"+jobID+suffix, body)
			req.SetPathValue("id", jobID)
			if body != "" {
				req.Header.Set("X-Audit-Reason", "bounded worker seam")
			}
			rec := httptest.NewRecorder()
			handler(h, rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}

	call("job malformed response",
		&scriptedIdentityWorker{rows: []pgx.Row{identityRawRow(`{`)}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJob(w, r)
		}, http.MethodGet, "", "", http.StatusInternalServerError)
	call("cancel permission query failure",
		&scriptedIdentityWorker{rows: []pgx.Row{identityErrorRow(errors.New("lost"))}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobCancel(w, r)
		}, http.MethodPost, "/cancel", "", http.StatusInternalServerError)
	call("cancel malformed permission response",
		&scriptedIdentityWorker{rows: []pgx.Row{identityRawRow(`{`)}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobCancel(w, r)
		}, http.MethodPost, "/cancel", "", http.StatusForbidden)
	call("cancel missing result",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(validJob), identityRawRow(`null`),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobCancel(w, r)
		}, http.MethodPost, "/cancel", "", http.StatusNotFound)
	call("cancel reducer failure",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(validJob), identityErrorRow(errors.New("cancel failed")),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobCancel(w, r)
		}, http.MethodPost, "/cancel", "", http.StatusInternalServerError)
	call("results missing result",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(validJob), identityRawRow(`null`),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobResults(w, r)
		}, http.MethodGet, "/results?after=1&limit=1", "", http.StatusNotFound)
	call("results reducer failure",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(validJob), identityErrorRow(errors.New("results failed")),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityJobResults(w, r)
		}, http.MethodGet, "/results", "", http.StatusInternalServerError)

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	call("download invalid kind",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(`{"kind":"upgrade_backfill","state":"completed","expiresAt":"` + future + `"}`),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityDiagnosticDownload(w, r)
		}, http.MethodGet, "/download", "", http.StatusInternalServerError)
	call("download invalid expiry",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(`{"kind":"diagnostics","state":"completed","expiresAt":"bad"}`),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityDiagnosticDownload(w, r)
		}, http.MethodGet, "/download", "", http.StatusInternalServerError)
	call("download artifact failure",
		&scriptedIdentityWorker{rows: []pgx.Row{
			identityRawRow(`{"kind":"diagnostics","state":"completed","expiresAt":"` + future + `"}`),
			identityErrorRow(errors.New("artifact failed")),
		}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityDiagnosticDownload(w, r)
		}, http.MethodGet, "/download", "", http.StatusNotFound)
}

func TestIdentityOperationMutationDefensiveResponseBranches(t *testing.T) {
	reason := "bounded worker seam"
	key := uuid.NewString()
	digest := strings.Repeat("a", 64)
	call := func(
		name string,
		worker *scriptedIdentityWorker,
		handler func(*IdentityHandler, http.ResponseWriter, *http.Request),
		method string,
		target string,
		body string,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = worker
			req := identityWorkerAdminRequest(method, target, body)
			req.Header.Set("X-Audit-Reason", reason)
			rec := httptest.NewRecorder()
			handler(h, rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}

	diagnosticBody := `{"sourceKey":"local:default","sinceSeconds":60,` +
		`"reason":"` + reason + `","idempotencyKey":"` + key + `"}`
	call("diagnostic invalid creation result",
		&scriptedIdentityWorker{rows: []pgx.Row{identityRawRow(`{}`)}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityDiagnosticCreate(w, r)
		}, http.MethodPost, "/admin/identity/v2/diagnostics",
		diagnosticBody, http.StatusInternalServerError)
	call("diagnostic creation query failure",
		&scriptedIdentityWorker{rows: []pgx.Row{identityErrorRow(errors.New("create failed"))}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityDiagnosticCreate(w, r)
		}, http.MethodPost, "/admin/identity/v2/diagnostics",
		diagnosticBody, http.StatusInternalServerError)

	deleteReq := `{"reason":"` + reason + `"}`
	call("diagnostic delete query failure",
		&scriptedIdentityWorker{rows: []pgx.Row{identityErrorRow(errors.New("delete failed"))}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			r.SetPathValue("id", uuid.NewString())
			h.IdentityDiagnosticDelete(w, r)
		}, http.MethodDelete, "/admin/identity/v2/diagnostics/id",
		deleteReq, http.StatusInternalServerError)

	backfillBody := `{"action":"start","preflightChecksum":"` + digest +
		`","reason":"` + reason + `","idempotencyKey":"` + key + `"}`
	call("backfill invalid creation result",
		&scriptedIdentityWorker{rows: []pgx.Row{identityRawRow(`{}`)}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeBackfill(w, r)
		}, http.MethodPost, "/admin/identity/v2/upgrade/backfill",
		backfillBody, http.StatusInternalServerError)
	call("backfill query failure",
		&scriptedIdentityWorker{rows: []pgx.Row{identityErrorRow(errors.New("backfill failed"))}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeBackfill(w, r)
		}, http.MethodPost, "/admin/identity/v2/upgrade/backfill",
		backfillBody, http.StatusInternalServerError)
	call("shadow query failure",
		&scriptedIdentityWorker{rows: []pgx.Row{identityErrorRow(errors.New("shadow failed"))}},
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeShadow(w, r)
		}, http.MethodGet,
		"/admin/identity/v2/upgrade/shadow?sourceKey=local:default",
		"", http.StatusInternalServerError)
}

func TestIdentitySourceMutationDefensiveResponseBranches(t *testing.T) {
	reason := "bounded worker seam"
	key := uuid.NewString()
	document := `{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"worker-source","displayName":"Worker Source"},` +
		`"spec":{"type":"local"}}`
	applyBody := `{"document":` + document + `,"reason":"` + reason +
		`","idempotencyKey":"` + key + `"}`
	lifecycleBody := `{"expectedGeneration":"1","reason":"` + reason +
		`","idempotencyKey":"` + key + `"}`

	call := func(name string, rows []pgx.Row, handler func(
		*IdentityHandler, http.ResponseWriter, *http.Request,
	), method, target, body string, want int) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = &scriptedIdentityWorker{rows: rows}
			h.SetSourceSecretCodec(testConfigSecretCodec(t))
			req := identityWorkerAdminRequest(method, target, body)
			req.Header.Set("X-Audit-Reason", reason)
			req.Header.Set("Idempotency-Key", key)
			rec := httptest.NewRecorder()
			handler(h, rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}
	call("apply invalid reducer response", []pgx.Row{
		identityErrorRow(pgx.ErrNoRows), identityRawRow(`{}`),
	}, func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
		h.IdentitySourceApply(w, r)
	}, http.MethodPost, "/admin/identity/v2/sources/worker-source",
		applyBody, http.StatusInternalServerError)
	call("apply reducer failure", []pgx.Row{
		identityErrorRow(pgx.ErrNoRows), identityErrorRow(errors.New("apply failed")),
	}, func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
		h.IdentitySourceApply(w, r)
	}, http.MethodPost, "/admin/identity/v2/sources/worker-source",
		applyBody, http.StatusInternalServerError)

	for _, test := range []struct {
		name string
		row  pgx.Row
		want int
	}{
		{"lifecycle invalid reducer response", identityRawRow(`{}`), http.StatusInternalServerError},
		{"lifecycle reducer failure", identityErrorRow(errors.New("lifecycle failed")), http.StatusInternalServerError},
	} {
		call(test.name, []pgx.Row{test.row},
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				r.SetPathValue("sourceKey", "worker-source")
				r.SetPathValue("action", "activate")
				r.Header.Set("If-Match", `"1"`)
				h.IdentitySourceLifecycle(w, r)
			}, http.MethodPost,
			"/admin/identity/v2/sources/worker-source/activate",
			lifecycleBody, test.want)
	}
}

func TestIdentitySourceSecretDefensiveResponseBranches(t *testing.T) {
	reason := "bounded worker seam"
	key := uuid.NewString()
	codec := testConfigSecretCodec(t)
	document := json.RawMessage(`{"apiVersion":"setjoin.io/v1","kind":"IdentitySource",` +
		`"metadata":{"sourceKey":"worker-source","displayName":"Worker Source"},` +
		`"spec":{"type":"oidc","providerKey":"worker","issuer":"https://idp.example.test",` +
		`"clientId":"setjoin","subjectClaim":"sub"}}`)
	plain, err := json.Marshal(identityStoredSourceDocument{
		Document: document, Secrets: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Encrypt("identity_source.worker-source", plain)
	if err != nil {
		t.Fatal(err)
	}
	call := func(
		name string,
		rows []pgx.Row,
		body any,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = &scriptedIdentityWorker{rows: rows}
			h.SetSourceSecretCodec(codec)
			req := httptest.NewRequest(http.MethodPut,
				"/admin/identity/v2/sources/worker-source/secrets/clientSecret",
				body.(interface{ Read([]byte) (int, error) }))
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
				UserID:            42,
				Permissions:       permissions.AllPermissions,
				GlobalPermissions: permissions.AllPermissions,
			}))
			req.SetPathValue("sourceKey", "worker-source")
			req.SetPathValue("name", "clientSecret")
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("If-Match", `"1"`)
			req.Header.Set("Idempotency-Key", key)
			req.Header.Set("X-Identity-Reason", reason)
			req.Header.Set("X-Audit-Reason", reason)
			rec := httptest.NewRecorder()
			h.IdentitySourceSetSecret(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}
	call("lookup failure",
		[]pgx.Row{identityErrorRow(errors.New("lookup failed"))},
		strings.NewReader("secret"), http.StatusInternalServerError)
	call("body read failure",
		[]pgx.Row{identitySourceRowFixture(envelope)},
		identityReadFailure{}, http.StatusBadRequest)
	call("mutation query failure",
		[]pgx.Row{
			identitySourceRowFixture(envelope),
			identityErrorRow(errors.New("mutation failed")),
		},
		strings.NewReader("secret"), http.StatusInternalServerError)
	call("mutation invalid response",
		[]pgx.Row{
			identitySourceRowFixture(envelope),
			identityRawRow(`{}`),
		},
		strings.NewReader("secret"), http.StatusInternalServerError)
}

func TestIdentityPreviewAndUpgradeDefensiveResponseBranches(t *testing.T) {
	reason := "bounded worker seam"
	key := uuid.NewString()
	previewBody := `{"userId":"7","reason":"` + reason +
		`","idempotencyKey":"` + key + `"}`
	callPreview := func(name string, rows []pgx.Row, want int) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = &scriptedIdentityWorker{rows: rows}
			req := identityWorkerAdminRequest(http.MethodPost,
				"/admin/identity/v2/transitions/preview", previewBody)
			req.Header.Set("X-Audit-Reason", reason)
			req.Header.Set("Idempotency-Key", key)
			rec := httptest.NewRecorder()
			h.TransitionPreview(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}
	callPreview("preview reachability failure",
		[]pgx.Row{identityErrorRow(errors.New("reach failed"))},
		http.StatusInternalServerError)
	callPreview("preview unreachable",
		[]pgx.Row{identityBoolRow(false)}, http.StatusNotFound)
	callPreview("preview reducer failure",
		[]pgx.Row{identityBoolRow(true), identityErrorRow(errors.New("preview failed"))},
		http.StatusInternalServerError)
	callPreview("preview invalid reducer response",
		[]pgx.Row{identityBoolRow(true), identityRawRow(`{}`)},
		http.StatusInternalServerError)

	callUpgrade := func(
		name string,
		row pgx.Row,
		handler func(*IdentityHandler, http.ResponseWriter, *http.Request),
		method, target, body string,
		headers map[string]string,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = &scriptedIdentityWorker{rows: []pgx.Row{row}}
			req := identityWorkerAdminRequest(method, target, body)
			for header, value := range headers {
				req.Header.Set(header, value)
			}
			rec := httptest.NewRecorder()
			handler(h, rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}
	callUpgrade("upgrade status query failure",
		identityErrorRow(errors.New("status failed")),
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeStatus(w, r)
		}, http.MethodGet, "/admin/identity/v2/upgrade/status", "", nil,
		http.StatusInternalServerError)
	canaryBody := `{"sourceKey":"worker-source","expectedGeneration":"1",` +
		`"enabled":true,"userIds":["7"],"reason":"` + reason + `"}`
	canaryHeaders := map[string]string{
		"If-Match": `"1"`, "X-Audit-Reason": reason,
	}
	callUpgrade("canary query failure",
		identityErrorRow(errors.New("canary failed")),
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeCanary(w, r)
		}, http.MethodPost, "/admin/identity/v2/upgrade/canary",
		canaryBody, canaryHeaders, http.StatusInternalServerError)
	callUpgrade("canary invalid reducer response",
		identityRawRow(`{}`),
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeCanary(w, r)
		}, http.MethodPost, "/admin/identity/v2/upgrade/canary",
		canaryBody, canaryHeaders, http.StatusInternalServerError)
	rollbackBody := `{"readPath":"legacy","reason":"` + reason + `"}`
	callUpgrade("rollback query failure",
		identityErrorRow(errors.New("rollback failed")),
		func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
			h.IdentityUpgradeRollback(w, r)
		}, http.MethodPost, "/admin/identity/v2/upgrade/rollback",
		rollbackBody, map[string]string{"X-Audit-Reason": reason},
		http.StatusInternalServerError)
}

func TestIdentityV2ListDatabaseFailureBranches(t *testing.T) {
	handlers := []struct {
		name    string
		path    string
		handler func(*IdentityHandler, http.ResponseWriter, *http.Request)
	}{
		{"sources", "/admin/identity/v2/sources",
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				h.Sources(w, r)
			}},
		{"people", "/admin/identity/v2/people",
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				h.IdentityPeople(w, r)
			}},
		{"conflicts", "/admin/identity/v2/conflicts",
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				h.IdentityConflicts(w, r)
			}},
		{"transitions", "/admin/identity/v2/transitions",
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				h.IdentityTransitions(w, r)
			}},
		{"events", "/admin/identity/v2/events",
			func(h *IdentityHandler, w http.ResponseWriter, r *http.Request) {
				h.IdentityEvents(w, r)
			}},
	}
	failures := []struct {
		name   string
		worker func() *scriptedIdentityWorker
	}{
		{"query", func() *scriptedIdentityWorker {
			return &scriptedIdentityWorker{queryErr: errors.New("query failed")}
		}},
		{"scan", func() *scriptedIdentityWorker {
			return &scriptedIdentityWorker{queryRows: []pgx.Rows{
				&scriptedIdentityRows{next: true, scanErr: errors.New("scan failed")},
			}}
		}},
		{"iteration", func() *scriptedIdentityWorker {
			return &scriptedIdentityWorker{queryRows: []pgx.Rows{
				&scriptedIdentityRows{rowsErr: errors.New("iteration failed")},
			}}
		}},
	}
	for _, endpoint := range handlers {
		for _, failure := range failures {
			t.Run(endpoint.name+"_"+failure.name, func(t *testing.T) {
				h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
				h.workerPool = failure.worker()
				req := identityWorkerAdminRequest(http.MethodGet, endpoint.path, "")
				rec := httptest.NewRecorder()
				endpoint.handler(h, rec, req)
				if rec.Code != http.StatusInternalServerError {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestIdentityTransitionReadDatabaseFailureBranches(t *testing.T) {
	transitionID := uuid.NewString()
	tests := []struct {
		name string
		rows []pgx.Row
		want int
	}{
		{"reachability query failure",
			[]pgx.Row{identityErrorRow(errors.New("reach failed"))},
			http.StatusInternalServerError},
		{"unreachable", []pgx.Row{identityBoolRow(false)}, http.StatusNotFound},
		{"read query failure", []pgx.Row{
			identityBoolRow(true), identityErrorRow(errors.New("read failed")),
		}, http.StatusInternalServerError},
		{"missing read result", []pgx.Row{
			identityBoolRow(true), identityRawRow(`null`),
		}, http.StatusInternalServerError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
			h.workerPool = &scriptedIdentityWorker{rows: test.rows}
			req := identityWorkerAdminRequest(http.MethodGet,
				"/admin/identity/v2/transitions/"+transitionID, "")
			req.SetPathValue("id", transitionID)
			rec := httptest.NewRecorder()
			h.IdentityTransition(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s",
					rec.Code, test.want, rec.Body.String())
			}
		})
	}
}
