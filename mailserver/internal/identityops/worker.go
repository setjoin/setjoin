// Package identityops drains bounded Identity Model Modernization operator jobs.
//
// Jobs are admitted by audited reducers and run unconditionally: disabling an
// identity feature flag must not strand an already accepted backfill or
// diagnostic bundle. Every batch settles through a reducer so PostgreSQL remains
// the authority for leases, cancellation, progress, and terminal state.
package identityops

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/shared/pgxutil"
)

const (
	jobPollInterval  = 2 * time.Second
	maxArtifactBytes = 25 << 20
)

type Worker struct {
	pool     pgxutil.WorkerPool
	logger   *slog.Logger
	workerID uuid.UUID
}

func NewWorker(pool pgxutil.WorkerPool, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, logger: logger, workerID: uuid.New()}
}

func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(jobPollInterval)
	defer ticker.Stop()
	for {
		if err := w.tick(ctx); err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("identity operator job tick failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type claimedJob struct {
	JobID        uuid.UUID       `json:"jobId"`
	Kind         string          `json:"kind"`
	ActorUserID  string          `json:"actorUserId"`
	SourceID     *string         `json:"sourceId"`
	TransitionID *uuid.UUID      `json:"transitionId"`
	Request      json.RawMessage `json:"request"`
	Progress     json.RawMessage `json:"progress"`
	AttemptCount int             `json:"attemptCount"`
	FailureCount int             `json:"failureCount"`
}

func (w *Worker) tick(ctx context.Context) error {
	var raw []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT identity_job_claim($1)`, w.workerID).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	var job claimedJob
	if err := json.Unmarshal(raw, &job); err != nil || job.JobID == uuid.Nil {
		return fmt.Errorf("decode identity job claim: %w", err)
	}
	var err error
	switch job.Kind {
	case "upgrade_backfill":
		err = w.runBackfill(ctx, job)
	case "diagnostics":
		err = w.runDiagnostics(ctx, job)
	default:
		err = fmt.Errorf("unsupported identity job kind %q", job.Kind)
	}
	if err == nil {
		return nil
	}
	retryable := job.FailureCount < 20
	if _, settleErr := w.pool.Exec(ctx,
		`SELECT identity_job_fail($1,$2,$3,$4)`,
		job.JobID, w.workerID, "IDENTITY_JOB_EXECUTION", retryable,
	); settleErr != nil {
		return fmt.Errorf("identity job failed (%v), settle failed: %w", err, settleErr)
	}
	w.logger.Warn("identity operator job attempt failed",
		"job_id", job.JobID, "kind", job.Kind, "retryable", retryable, "error", err)
	return nil
}

type backfillProgress struct {
	Processed         int    `json:"processed"`
	LinksObserved     int    `json:"linksObserved"`
	ConflictsRecorded int    `json:"conflictsRecorded"`
	NextAfterUserID   string `json:"nextAfterUserId"`
	Complete          bool   `json:"complete"`
	Items             []struct {
		UserID string          `json:"userId"`
		State  string          `json:"state"`
		Result json.RawMessage `json:"result"`
	} `json:"items"`
}

func (w *Worker) runBackfill(ctx context.Context, job claimedJob) error {
	var current struct {
		Processed         int    `json:"processed"`
		LinksObserved     int    `json:"linksObserved"`
		ConflictsRecorded int    `json:"conflictsRecorded"`
		NextAfterUserID   string `json:"nextAfterUserId"`
	}
	if len(job.Progress) > 0 {
		_ = json.Unmarshal(job.Progress, &current)
	}
	after := int64(0)
	if current.NextAfterUserID != "" {
		parsed, err := strconv.ParseInt(current.NextAfterUserID, 10, 64)
		if err != nil || parsed < 0 {
			return errors.New("invalid persisted backfill cursor")
		}
		after = parsed
	}
	var raw []byte
	if err := w.pool.QueryRow(ctx,
		`SELECT identity_legacy_backfill($1,$2)`, after, 500).Scan(&raw); err != nil {
		return err
	}
	var batch backfillProgress
	if err := json.Unmarshal(raw, &batch); err != nil {
		return fmt.Errorf("decode identity backfill result: %w", err)
	}
	if len(batch.Items) > 500 {
		return errors.New("identity backfill result exceeds the 500-person batch bound")
	}
	items, err := json.Marshal(batch.Items)
	if err != nil {
		return fmt.Errorf("encode identity backfill results: %w", err)
	}
	batch.Processed += current.Processed
	batch.LinksObserved += current.LinksObserved
	batch.ConflictsRecorded += current.ConflictsRecorded
	batch.Items = nil
	progress, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	_, err = w.pool.Exec(ctx, `
		SELECT identity_job_batch_settle(
			$1,$2,$3::jsonb,$4::jsonb,$5,$6
		)
	`, job.JobID, w.workerID, string(items), string(progress),
		batch.Complete, batch.ConflictsRecorded > 0)
	return err
}

type diagnosticScope struct {
	SinceSeconds int `json:"sinceSeconds"`
}

func (w *Worker) runDiagnostics(ctx context.Context, job claimedJob) error {
	var req diagnosticScope
	if err := json.Unmarshal(job.Request, &req); err != nil ||
		req.SinceSeconds < 1 || req.SinceSeconds > 86400 {
		return errors.New("invalid diagnostic request scope")
	}
	evidence, redactions, err := w.diagnosticEvidence(ctx, job, req.SinceSeconds)
	if err != nil {
		return err
	}
	manifest := map[string]any{
		"manifestVersion": "1",
		"jobId":           job.JobID.String(),
		"createdAt":       time.Now().UTC().Format(time.RFC3339Nano),
		"scope": map[string]any{
			"sourceId": job.SourceID, "transitionId": job.TransitionID,
			"sinceSeconds": req.SinceSeconds,
		},
		"redactionPolicy": "identity-diagnostics-v1",
		"files":           []string{"evidence.jsonl"},
	}
	artifact, err := buildDiagnosticZIP(manifest, evidence)
	if err != nil {
		return err
	}
	if len(artifact) > maxArtifactBytes {
		return errors.New("diagnostic artifact exceeds 25 MiB")
	}
	manifestJSON, _ := json.Marshal(manifest)
	redactionsJSON, _ := json.Marshal(redactions)
	progress, _ := json.Marshal(map[string]any{
		"processed": len(evidence), "failed": 0, "bytes": len(artifact),
	})
	_, err = w.pool.Exec(ctx,
		`SELECT identity_job_complete($1,$2,'completed',$3::jsonb,$4,$5::jsonb,$6::jsonb)`,
		job.JobID, w.workerID, string(progress), artifact,
		string(manifestJSON), string(redactionsJSON))
	return err
}

func (w *Worker) diagnosticEvidence(
	ctx context.Context,
	job claimedJob,
	sinceSeconds int,
) ([]json.RawMessage, map[string]int, error) {
	rows := make([]json.RawMessage, 0, 8)
	if job.SourceID != nil {
		sourceID, err := strconv.ParseInt(*job.SourceID, 10, 64)
		if err != nil || sourceID <= 0 {
			return nil, nil, errors.New("invalid claimed source id")
		}
		var raw []byte
		err = w.pool.QueryRow(ctx, `
			SELECT jsonb_build_object(
				'type','source',
				'sourceId',s.id::text,
				'sourceKey',s.source_key,
				'kind',s.kind,
				'state',s.state,
				'generation',s.generation::text,
				'mappingVersion',s.mapping_version::text,
				'readMode',s.read_mode,
				'lastSuccessAt',s.last_success_at,
				'lastFailureAt',s.last_failure_at,
				'lastErrorCode',s.last_error_code,
				'inbox',jsonb_build_object(
					'pending',(SELECT count(*) FROM identity_source_inbox i
						WHERE i.source_id=s.id AND i.state='pending'),
					'quarantined',(SELECT count(*) FROM identity_source_inbox i
						WHERE i.source_id=s.id AND i.state='quarantined')
				),
				'divergences',jsonb_build_object(
					'critical',(SELECT count(*) FROM identity_shadow_divergences d
						WHERE d.source_id=s.id AND d.state='open'
						  AND d.divergence_class IN (
							'person_mismatch','authority_mismatch','access_mismatch')),
					'expectedAmbiguity',(SELECT count(*) FROM identity_shadow_divergences d
						WHERE d.source_id=s.id AND d.state='open'
						  AND d.divergence_class='expected_legacy_ambiguity')
				)
			)
			  FROM identity_sources s WHERE s.id=$1
		`, sourceID).Scan(&raw)
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, raw)
	}
	if job.TransitionID != nil {
		var raw []byte
		err := w.pool.QueryRow(ctx, `
			SELECT jsonb_build_object(
				'type','transition',
				'transitionId',t.id,
				'state',t.state,
				'generation',t.transition_generation::text,
				'transitionType',t.kind,
				'createdAt',t.created_at,
				'updatedAt',t.updated_at,
				'effects',COALESCE((
					SELECT jsonb_agg(jsonb_build_object(
						'effectId',e.effect_id,'kind',e.effect_kind,
						'state',e.state,'attemptCount',e.attempt_count,
						'lastErrorCode',e.last_error_code
					) ORDER BY e.effect_kind)
					  FROM identity_transition_effects e
					 WHERE e.transition_id=t.id
				),'[]'::jsonb)
			)
			  FROM identity_transitions t WHERE t.id=$1
		`, *job.TransitionID).Scan(&raw)
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, raw)
	}
	var metrics []byte
	err := w.pool.QueryRow(ctx, `
		SELECT jsonb_build_object(
			'type','boundedMetrics',
			'sinceSeconds',$1::integer,
			'jobs',jsonb_build_object(
				'queued',(SELECT count(*) FROM identity_jobs WHERE state='queued'),
				'running',(SELECT count(*) FROM identity_jobs WHERE state='running')
			),
			'transitions',jsonb_build_object(
				'pendingEffects',(SELECT count(*) FROM identity_transition_effects
					WHERE state<>'completed'),
				'failedEffects',(SELECT count(*) FROM identity_transition_effects
					WHERE state='failed')
			),
			'candidates',jsonb_build_object(
				'pending',(SELECT count(*) FROM identity_match_candidates
					WHERE status='pending'),
				'deferred',(SELECT count(*) FROM identity_match_candidates
					WHERE status='deferred')
			)
		)
	`, sinceSeconds).Scan(&metrics)
	if err != nil {
		return nil, nil, err
	}
	rows = append(rows, metrics)
	return rows, map[string]int{
		"credentials":      1,
		"externalSubjects": 1,
		"emails":           1,
		"personalProfiles": 1,
		"rawAssertions":    1,
	}, nil
}

func buildDiagnosticZIP(
	manifest map[string]any,
	evidence []json.RawMessage,
) ([]byte, error) {
	var out bytes.Buffer
	zw := zip.NewWriter(&out)
	write := func(name string, payload []byte) error {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetModTime(time.Unix(0, 0).UTC())
		header.SetMode(0o600)
		entry, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = entry.Write(payload)
		return err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifestJSON = append(manifestJSON, '\n')
	if err := write("manifest.json", manifestJSON); err != nil {
		return nil, err
	}
	var lines bytes.Buffer
	for _, row := range evidence {
		if !json.Valid(row) {
			return nil, errors.New("invalid diagnostic evidence JSON")
		}
		lines.Write(row)
		lines.WriteByte('\n')
	}
	if err := write("evidence.jsonl", lines.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
