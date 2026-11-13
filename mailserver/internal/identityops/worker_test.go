package identityops

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestBuildDiagnosticZIPContainsOnlyCanonicalFiles(t *testing.T) {
	manifest := map[string]any{
		"manifestVersion": "1",
		"redactionPolicy": "identity-diagnostics-v1",
	}
	evidence := []json.RawMessage{
		json.RawMessage(`{"type":"source","sourceKey":"corp-ad"}`),
	}
	raw, err := buildDiagnosticZIP(manifest, evidence)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != 2 {
		t.Fatalf("files = %d, want 2", len(reader.File))
	}
	want := map[string]bool{"manifest.json": true, "evidence.jsonl": true}
	for _, file := range reader.File {
		if !want[file.Name] {
			t.Fatalf("unexpected file %q", file.Name)
		}
		if file.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 0600", file.Name, file.Mode().Perm())
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("password")) ||
			bytes.Contains(body, []byte("externalSubject")) ||
			bytes.Contains(body, []byte("email")) {
			t.Fatalf("%s contains a denied field: %s", file.Name, body)
		}
	}
}

func TestBuildDiagnosticZIPRejectsInvalidEvidence(t *testing.T) {
	if _, err := buildDiagnosticZIP(
		map[string]any{"manifestVersion": "1"},
		[]json.RawMessage{json.RawMessage(`not-json`)},
	); err == nil {
		t.Fatal("expected invalid JSON error")
	}
	if _, err := buildDiagnosticZIP(
		map[string]any{"unsupported": func() {}}, nil,
	); err == nil {
		t.Fatal("expected invalid manifest JSON error")
	}
}

func TestIdentityOperatorWorkerDrainsDiagnosticsBackfillAndUnsupportedJobs(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])
	var mailboxID, actorID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`,
		"identity-worker-"+suffix).Scan(&mailboxID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	sourceKey := "worker-" + suffix
	var sourceID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state,generation
		) VALUES(
			$1,$2,'local',
			'{"authenticate":true,"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active',1
		) RETURNING id
	`, sourceKey, "Worker "+suffix).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		_, _ = pool.Exec(cleanup, `
			DELETE FROM identity_job_results
			 WHERE job_id IN (
				SELECT id FROM identity_jobs WHERE actor_user_id=$1
			 )
		`, actorID)
		_, _ = pool.Exec(cleanup, `DELETE FROM identity_jobs WHERE actor_user_id=$1`, actorID)
		_, _ = pool.Exec(cleanup, `DELETE FROM identity_sources WHERE id=$1`, sourceID)
		_, _ = pool.Exec(cleanup, `DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		_, _ = pool.Exec(cleanup, `DELETE FROM users WHERE id=$1`, actorID)
	})

	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	createJob := func(kind string, request string) uuid.UUID {
		t.Helper()
		var raw json.RawMessage
		source := any(nil)
		if kind == "diagnostics" {
			source = sourceKey
		}
		if err := pool.QueryRow(ctx, `
			SELECT identity_job_create($1,$2,$3,$4,NULL,$5::jsonb,$6)
		`, actorID, kind, uuid.New(), source, request,
			"identity operator worker integration test").Scan(&raw); err != nil {
			t.Fatalf("create %s job: %v", kind, err)
		}
		var created struct {
			JobID uuid.UUID `json:"jobId"`
		}
		if err := json.Unmarshal(raw, &created); err != nil || created.JobID == uuid.Nil {
			t.Fatalf("decode %s job: %v raw=%s", kind, err, raw)
		}
		if _, err := pool.Exec(ctx, `
			UPDATE identity_jobs
			   SET created_at=statement_timestamp()-interval '7 days 3 minutes',
			       updated_at=statement_timestamp()-interval '7 days 3 minutes',
			       expires_at=statement_timestamp()+interval '1 minute'
			 WHERE id=$1
		`, created.JobID); err != nil {
			t.Fatal(err)
		}
		return created.JobID
	}

	diagnosticID := createJob("diagnostics", `{"sinceSeconds":60}`)
	if err := worker.tick(ctx); err != nil {
		t.Fatalf("diagnostic tick: %v", err)
	}
	var diagnosticState string
	var artifact []byte
	var manifest, redactions json.RawMessage
	if err := pool.QueryRow(ctx, `
		SELECT state,artifact,artifact_manifest,redaction_counts
		  FROM identity_jobs WHERE id=$1
	`, diagnosticID).Scan(&diagnosticState, &artifact, &manifest, &redactions); err != nil {
		t.Fatal(err)
	}
	if diagnosticState != "completed" || len(artifact) == 0 ||
		!json.Valid(manifest) || !json.Valid(redactions) {
		var retryRaw []byte
		if err := pool.QueryRow(ctx,
			`SELECT identity_job_claim($1)`, worker.workerID).Scan(&retryRaw); err == nil {
			var retryJob claimedJob
			if json.Unmarshal(retryRaw, &retryJob) == nil &&
				retryJob.JobID == diagnosticID {
				if err := worker.runDiagnostics(ctx, retryJob); err != nil {
					t.Fatalf("diagnostic execution failed: %v", err)
				}
			}
		}
		t.Fatalf("diagnostic state=%s artifact=%d manifest=%s redactions=%s",
			diagnosticState, len(artifact), manifest, redactions)
	}
	if _, err := zip.NewReader(bytes.NewReader(artifact), int64(len(artifact))); err != nil {
		t.Fatalf("diagnostic artifact is not a zip: %v", err)
	}

	backfillID := createJob("upgrade_backfill", `{"preflightChecksum":"test"}`)
	if err := worker.tick(ctx); err != nil {
		t.Fatalf("backfill tick: %v", err)
	}
	var backfillState string
	var progress json.RawMessage
	if err := pool.QueryRow(ctx,
		`SELECT state,progress FROM identity_jobs WHERE id=$1`,
		backfillID).Scan(&backfillState, &progress); err != nil {
		t.Fatal(err)
	}
	if backfillState != "completed" && backfillState != "completed_with_failures" &&
		backfillState != "queued" {
		t.Fatalf("backfill state=%s progress=%s", backfillState, progress)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM identity_job_results WHERE job_id=$1`, backfillID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM identity_jobs WHERE id=$1`, backfillID); err != nil {
		t.Fatal(err)
	}
	unsupportedID := createJob("cohort_preview", `{}`)
	if err := worker.tick(ctx); err != nil {
		t.Fatalf("unsupported job tick should settle failure: %v", err)
	}
	var failureCount int
	if err := pool.QueryRow(ctx,
		`SELECT failure_count FROM identity_jobs WHERE id=$1`,
		unsupportedID).Scan(&failureCount); err != nil {
		t.Fatal(err)
	}
	if failureCount != 1 {
		t.Fatalf("unsupported job failure count=%d", failureCount)
	}

	if err := worker.runBackfill(ctx, claimedJob{
		Progress: json.RawMessage(`{"nextAfterUserId":"bad"}`),
	}); err == nil {
		t.Fatal("invalid persisted backfill cursor accepted")
	}
	if err := worker.runDiagnostics(ctx, claimedJob{
		Request: json.RawMessage(`{"sinceSeconds":0}`),
	}); err == nil {
		t.Fatal("invalid diagnostic scope accepted")
	}
	badSource := "bad"
	if _, _, err := worker.diagnosticEvidence(ctx, claimedJob{
		SourceID: &badSource,
	}, 60); err == nil {
		t.Fatal("invalid diagnostic source id accepted")
	}
	missingSource := "9223372036854775807"
	if _, _, err := worker.diagnosticEvidence(ctx, claimedJob{
		SourceID: &missingSource,
	}, 60); err == nil {
		t.Fatal("missing diagnostic source was accepted")
	}
	missingTransition := uuid.New()
	if _, _, err := worker.diagnosticEvidence(ctx, claimedJob{
		TransitionID: &missingTransition,
	}, 60); err == nil {
		t.Fatal("missing diagnostic transition was accepted")
	}
}

func TestIdentityOperatorWorkerStopsOnCancellationWithUnavailableDatabase(t *testing.T) {
	t.Parallel()
	pool, err := pgxpool.New(context.Background(),
		"postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("identity operator worker ignored cancellation")
	}
}
