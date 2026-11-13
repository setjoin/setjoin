package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestIdentityInventoryExportHandlerBindsExactDigestAndRedaction(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	req := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/inventory/export", nil)
	req = globalIdentityAdminRequest(req)
	rec := httptest.NewRecorder()

	h.IdentityInventoryExport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("inventory export status = %d body=%s", rec.Code, rec.Body.String())
	}
	raw := rec.Body.Bytes()
	sum := sha256.Sum256(raw)
	wantDigest := "sha-256=" + base64.StdEncoding.EncodeToString(sum[:])
	if got := rec.Header().Get("Digest"); got != wantDigest {
		t.Fatalf("Digest = %q, want %q", got, wantDigest)
	}
	var report struct {
		ManifestVersion string            `json:"manifestVersion"`
		SchemaVersion   int               `json:"schemaVersion"`
		SHA256          string            `json:"sha256"`
		RedactionCounts map[string]int64  `json:"redactionCounts"`
		Sources         []json.RawMessage `json:"sources"`
		People          []json.RawMessage `json:"people"`
		Conflicts       []json.RawMessage `json:"conflicts"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.ManifestVersion != "1" || report.SchemaVersion < 167 ||
		len(report.SHA256) != 64 || report.RedactionCounts == nil ||
		report.Sources == nil || report.People == nil || report.Conflicts == nil {
		t.Fatalf("invalid inventory export shape: %+v", report)
	}
	body := rec.Body.String()
	for _, denied := range []string{
		`"email":`, `"externalSubject":`, `"configEnvelope":`,
		`"profile":`, `"secret":`,
	} {
		if strings.Contains(body, denied) {
			t.Fatalf("inventory export contains denied field %s", denied)
		}
	}
}

func TestIdentityDiagnosticCreateRejectsInvalidScopeBeforeDatabaseWork(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	req := identityV2RequestWithActor(http.MethodPost,
		"/admin/identity/v2/diagnostics", `{
			"sourceKey":"corp-ad",
			"transitionId":"00000000-0000-4000-8000-000000000001",
			"sinceSeconds":3600,
			"reason":"bounded diagnostic",
			"idempotencyKey":"00000000-0000-4000-8000-000000000002"
		}`)
	req.Header.Set("X-Audit-Reason", "bounded diagnostic")
	rec := httptest.NewRecorder()

	h.IdentityDiagnosticCreate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid diagnostic status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIdentityJobFollowupsRejectDomainScopedAdminsBeforeDatabaseWork(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	jobID := "00000000-0000-4000-8000-000000000111"
	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"status", http.MethodGet, "/admin/identity/v2/jobs/" + jobID, "", h.IdentityJob},
		{"cancel", http.MethodPost, "/admin/identity/v2/jobs/" + jobID + "/cancel", "", h.IdentityJobCancel},
		{"results", http.MethodGet, "/admin/identity/v2/jobs/" + jobID + "/results", "", h.IdentityJobResults},
		{"download", http.MethodGet, "/admin/identity/v2/diagnostics/" + jobID + "/download", "", h.IdentityDiagnosticDownload},
		{"delete", http.MethodDelete, "/admin/identity/v2/diagnostics/" + jobID,
			`{"reason":"remove bounded diagnostic"}`, h.IdentityDiagnosticDelete},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.SetPathValue("id", jobID)
			if tc.name == "delete" {
				req.Header.Set("X-Audit-Reason", "remove bounded diagnostic")
			}
			ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 42})
			ctx = middleware.ContextWithDomainScope(ctx, 9)
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()

			tc.handler(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("scoped %s status=%d body=%s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityDiagnosticDownloadReturnsGoneForExpiredArtifact(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	suffix := strings.ToLower(uuid.NewString()[:8])
	var mailboxID, actorID int64
	if err := pool.QueryRow(t.Context(),
		`SELECT mk_account($1)`, "identity-ops-expired-"+suffix).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(),
		`SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	if err := pool.QueryRow(t.Context(), `
		SELECT identity_job_create(
			$1,'diagnostics',$2,'local:default',NULL,
			'{"sinceSeconds":60}'::jsonb,'expired diagnostic test'
		)
	`, actorID, uuid.New()).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var job struct {
		JobID uuid.UUID `json:"jobId"`
	}
	if err := json.Unmarshal(raw, &job); err != nil || job.JobID == uuid.Nil {
		t.Fatalf("decode job: %v raw=%s", err, raw)
	}
	if _, err := pool.Exec(t.Context(), `
		UPDATE identity_jobs
		   SET state='expired',
		       created_at=statement_timestamp()-interval '7 days',
		       expires_at=statement_timestamp()-interval '1 minute',
		       completed_at=statement_timestamp()-interval '1 minute',
		       updated_at=statement_timestamp()
		 WHERE id=$1
	`, job.JobID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(t.Context(), `DELETE FROM identity_jobs WHERE id=$1`, job.JobID)
		_, _ = pool.Exec(t.Context(), `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(t.Context(), `DELETE FROM users WHERE id=$1`, actorID)
	})

	req := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/diagnostics/"+job.JobID.String()+"/download", nil)
	req.SetPathValue("id", job.JobID.String())
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: actorID,
		Permissions: []string{
			permissions.PermAuditExport,
		},
		GlobalPermissions: []string{
			permissions.PermAuditExport,
		},
	}))
	rec := httptest.NewRecorder()

	h.IdentityDiagnosticDownload(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("expired diagnostic status = %d body=%s", rec.Code, rec.Body.String())
	}
	if retry := rec.Header().Get("Retry-After"); retry != "" {
		t.Fatalf("expired diagnostic unexpectedly retryable: %q", retry)
	}
}

func TestIdentityOperatorReadinessAndDiagnosticJobLifecycle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])
	sourceKey := "ops-" + suffix

	var mailboxID, actorID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "identity-ops-"+suffix).
		Scan(&mailboxID); err != nil {
		t.Fatalf("create identity operations actor: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID,
	).Scan(&actorID); err != nil {
		t.Fatalf("read identity operations actor: %v", err)
	}
	var sourceID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state,generation
		) VALUES (
			$1,$2,'oidc',
			'{"authenticate":true,"provision_lifecycle":false,"stable_immutable_subject":true}'::jsonb,
			'draft',1
		) RETURNING id
	`, sourceKey, "Operations "+suffix).Scan(&sourceID); err != nil {
		t.Fatalf("create identity operations source: %v", err)
	}
	var backupID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO backup_runs(status,completed_at)
		VALUES('completed',statement_timestamp())
		RETURNING id
	`).Scan(&backupID); err != nil {
		t.Fatalf("create identity operations backup evidence: %v", err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		_, _ = pool.Exec(cleanup,
			`DELETE FROM identity_jobs WHERE actor_user_id=$1`, actorID)
		_, _ = pool.Exec(cleanup, `DELETE FROM backup_runs WHERE id=$1`, backupID)
		cleanupIdentityLinkEventsForSource(t, pool, sourceID)
		if _, err := pool.Exec(cleanup,
			`DELETE FROM identity_sources WHERE id=$1`, sourceID,
		); err != nil {
			t.Errorf("delete identity operations source: %v", err)
		}
		_, _ = pool.Exec(cleanup, `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(cleanup, `DELETE FROM users WHERE id=$1`, actorID)
	})

	var schemaVersion int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).
		Scan(&schemaVersion); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	h.SetSourceSecretCodec(testConfigSecretCodec(t))
	h.SetRuntimeReadiness(IdentityRuntimeReadiness{
		ExpectedSchemaVersion: schemaVersion,
		WorkerDSNReady:        true,
		OwnerDSNReady:         true,
		DirectDSNReady:        true,
		AuthserverConfigured:  true,
	})
	request := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:            actorID,
			IsAdmin:           true,
			Permissions:       permissions.AllPermissions,
			GlobalPermissions: permissions.AllPermissions,
		}))
	}
	call := func(
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s",
				req.Method, req.URL.String(), rec.Code, want, rec.Body.String())
		}
		return rec
	}

	for _, target := range []string{
		"/admin/identity/v2/doctor",
		"/admin/identity/v2/doctor?source=" + sourceKey,
	} {
		call(h.IdentityDoctor, request(http.MethodGet, target, ""), http.StatusOK)
	}
	preflight := call(h.IdentityUpgradePreflight,
		request(http.MethodGet, "/admin/identity/v2/upgrade/preflight", ""),
		http.StatusOK)
	var preflightResult struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(preflight.Body.Bytes(), &preflightResult); err != nil ||
		len(preflightResult.SHA256) != 64 {
		t.Fatalf("decode identity upgrade preflight: %v body=%s",
			err, preflight.Body.String())
	}
	call(h.IdentityUpgradeBackfill,
		request(http.MethodPost, "/admin/identity/v2/upgrade/backfill", `{"action":"plan"}`),
		http.StatusOK)
	backfillKey := uuid.NewString()
	backfillReq := request(http.MethodPost, "/admin/identity/v2/upgrade/backfill",
		`{"action":"start","preflightChecksum":"`+preflightResult.SHA256+
			`","reason":"identity upgrade lifecycle test","idempotencyKey":"`+
			backfillKey+`"}`)
	backfillReq.Header.Set("Idempotency-Key", backfillKey)
	backfillReq.Header.Set("X-Audit-Reason", "identity upgrade lifecycle test")
	call(h.IdentityUpgradeBackfill, backfillReq, http.StatusAccepted)
	call(h.IdentityUpgradeShadow,
		request(http.MethodGet,
			"/admin/identity/v2/upgrade/shadow?sourceKey="+sourceKey, ""),
		http.StatusOK)
	call(h.IdentityUpgradeStatus,
		request(http.MethodGet, "/admin/identity/v2/upgrade/status", ""),
		http.StatusOK)
	canaryReq := request(http.MethodPost, "/admin/identity/v2/upgrade/canary",
		`{"sourceKey":"`+sourceKey+`","expectedGeneration":"1",`+
			`"enabled":false,"userIds":[],`+
			`"reason":"identity upgrade lifecycle test"}`)
	canaryReq.Header.Set("If-Match", `"1"`)
	canaryReq.Header.Set("X-Audit-Reason", "identity upgrade lifecycle test")
	call(h.IdentityUpgradeCanary, canaryReq, http.StatusOK)
	rollbackReq := request(http.MethodPost, "/admin/identity/v2/upgrade/rollback",
		`{"readPath":"legacy","reason":"identity upgrade lifecycle test"}`)
	rollbackReq.Header.Set("X-Audit-Reason", "identity upgrade lifecycle test")
	call(h.IdentityUpgradeRollback, rollbackReq, http.StatusOK)
	call(h.IdentityUpgradeRetirementCheck,
		request(http.MethodGet, "/admin/identity/v2/upgrade/retirement-check", ""),
		http.StatusOK)

	jobKey := uuid.NewString()
	createReq := request(http.MethodPost, "/admin/identity/v2/diagnostics",
		`{"sourceKey":"`+sourceKey+`","sinceSeconds":60,`+
			`"reason":"identity diagnostic lifecycle test",`+
			`"idempotencyKey":"`+jobKey+`"}`)
	createReq.Header.Set("Idempotency-Key", jobKey)
	createReq.Header.Set("X-Audit-Reason", "identity diagnostic lifecycle test")
	created := call(h.IdentityDiagnosticCreate, createReq, http.StatusAccepted)
	var job struct {
		JobID string `json:"jobId"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &job); err != nil ||
		job.JobID == "" {
		t.Fatalf("decode diagnostic job: %v body=%s", err, created.Body.String())
	}

	jobRequest := func(method, suffix, query, body string) *http.Request {
		req := request(method, "/admin/identity/v2/"+suffix+"/"+job.JobID+query, body)
		req.SetPathValue("id", job.JobID)
		return req
	}
	statusReq := jobRequest(http.MethodGet, "jobs", "", "")
	status := call(h.IdentityJob, statusReq, http.StatusOK)
	if status.Header().Get("Retry-After") == "" {
		t.Fatal("queued diagnostic job did not return Retry-After")
	}
	call(h.IdentityDiagnosticStatus,
		jobRequest(http.MethodGet, "diagnostics", "", ""), http.StatusOK)
	call(h.IdentityJobResults,
		jobRequest(http.MethodGet, "jobs", "?after=0&limit=1", ""), http.StatusOK)
	call(h.IdentityJobResults,
		jobRequest(http.MethodGet, "jobs", "?after=bad", ""), http.StatusBadRequest)
	call(h.IdentityJobResults,
		jobRequest(http.MethodGet, "jobs", "?limit=501", ""), http.StatusBadRequest)
	permissionLost := jobRequest(http.MethodGet, "jobs", "", "")
	permissionLost = permissionLost.WithContext(auth.ContextWithUser(
		permissionLost.Context(), &auth.Claims{
			UserID: actorID,
			GlobalPermissions: []string{
				permissions.PermIdentityWrite,
			},
		},
	))
	call(h.IdentityJob, permissionLost, http.StatusForbidden)
	call(h.IdentityDiagnosticDownload,
		jobRequest(http.MethodGet, "diagnostics", "/download", ""), http.StatusConflict)
	call(h.IdentityJobCancel,
		jobRequest(http.MethodPost, "jobs", "/cancel", ""), http.StatusAccepted)
	call(h.IdentityJob,
		jobRequest(http.MethodGet, "jobs", "", ""), http.StatusOK)
	artifact := []byte("bounded identity diagnostic artifact")
	artifactDigest := sha256.Sum256(artifact)
	if _, err := pool.Exec(ctx, `
		UPDATE identity_jobs
		   SET state='completed',
		       artifact=$2,
		       artifact_sha256=$3,
		       artifact_manifest='{"manifestVersion":"1"}'::jsonb,
		       redaction_counts='{"credentials":1}'::jsonb,
		       completed_at=statement_timestamp(),
		       updated_at=statement_timestamp(),
		       worker_id=NULL,
		       lease_expires_at=NULL
		 WHERE id=$1
	`, job.JobID, artifact, artifactDigest[:]); err != nil {
		t.Fatalf("complete diagnostic fixture: %v", err)
	}
	download := call(h.IdentityDiagnosticDownload,
		jobRequest(http.MethodGet, "diagnostics", "/download", ""), http.StatusOK)
	if download.Body.String() != string(artifact) ||
		download.Header().Get("X-Setjoin-Manifest-Version") != "1" {
		t.Fatalf("diagnostic download body/manifest = %q/%q",
			download.Body.String(),
			download.Header().Get("X-Setjoin-Manifest-Version"))
	}

	deleteReq := jobRequest(http.MethodDelete, "diagnostics", "",
		`{"reason":"identity diagnostic lifecycle test"}`)
	deleteReq.Header.Set("X-Audit-Reason", "identity diagnostic lifecycle test")
	call(h.IdentityDiagnosticDelete, deleteReq, http.StatusNoContent)
	call(h.IdentityJob,
		jobRequest(http.MethodGet, "jobs", "", ""), http.StatusOK)
	call(h.IdentityJobCancel,
		jobRequest(http.MethodPost, "jobs", "/cancel", ""), http.StatusAccepted)
	call(h.IdentityJobResults,
		jobRequest(http.MethodGet, "jobs", "/results", ""), http.StatusOK)
	call(h.IdentityDiagnosticDownload,
		jobRequest(http.MethodGet, "diagnostics", "/download", ""), http.StatusGone)

	missingJobID := uuid.NewString()
	missingJobRequest := func(method, suffix, query, body string) *http.Request {
		req := request(method,
			"/admin/identity/v2/"+suffix+"/"+missingJobID+query, body)
		req.SetPathValue("id", missingJobID)
		return req
	}
	call(h.IdentityJob,
		missingJobRequest(http.MethodGet, "jobs", "", ""), http.StatusNotFound)
	call(h.IdentityJobCancel,
		missingJobRequest(http.MethodPost, "jobs", "/cancel", ""), http.StatusNotFound)
	call(h.IdentityJobResults,
		missingJobRequest(http.MethodGet, "jobs", "/results", ""), http.StatusNotFound)
	call(h.IdentityDiagnosticDownload,
		missingJobRequest(http.MethodGet, "diagnostics", "/download", ""),
		http.StatusNotFound)

	if !identityJobPermission(&auth.Claims{
		GlobalPermissions: []string{
			permissions.PermIdentityWrite,
			permissions.PermSystemUpgrade,
		},
	}, "upgrade_backfill") {
		t.Fatal("upgrade job permission was rejected")
	}
	if identityJobPermission(&auth.Claims{
		GlobalPermissions: []string{permissions.PermIdentityWrite},
	}, "upgrade_backfill") {
		t.Fatal("upgrade job permission accepted without system.upgrade")
	}
	if identityJobPermission(nil, "diagnostics") ||
		identityJobPermission(&auth.Claims{
			GlobalPermissions: permissions.AllPermissions,
		}, "unknown") {
		t.Fatal("unknown or anonymous identity job permission was accepted")
	}
}
