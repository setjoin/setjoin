package appmarket

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Operation struct {
	OperationID     uuid.UUID       `json:"operationId"`
	Kind            string          `json:"kind"`
	State           string          `json:"state"`
	StateGeneration int64           `json:"stateGeneration"`
	ExecutorID      string          `json:"executorId"`
	LeaseID         uuid.UUID       `json:"leaseId"`
	LeaseExpiresAt  string          `json:"leaseExpiresAt"`
	Reclaimed       bool            `json:"reclaimed"`
	Request         json.RawMessage `json:"request"`
}

type ControlPlane interface {
	Claim(context.Context, string, uuid.UUID) (*Operation, error)
	// Heartbeat renews the lease for leaseSeconds (the reducer accepts
	// 10..300). Callers pass a step-aware TTL covering the worst-case
	// duration of the step about to run, so a merely slow step can never
	// expire the lease mid-flight.
	Heartbeat(context.Context, *Operation, int) error
	Advance(context.Context, *Operation, string, string, map[string]any, map[string]any) error
	CommitInstall(context.Context, *Operation, Manifest) error
}

func (p *PGControlPlane) CommitInstall(ctx context.Context, op *Operation, manifest Manifest) error {
	plan, err := CompileRuntimePlan(manifest)
	if err != nil {
		return err
	}
	canonicalPlan, err := plan.CanonicalJSON()
	if err != nil {
		return err
	}
	artifact, _ := json.Marshal(map[string]any{"source": manifest.Source, "digest": manifest.Digest,
		"platformDigests": manifest.PlatformDigests, "license": manifest.License,
		"sourceCode": manifest.SourceCode, "retrievedAt": manifest.RetrievedAt,
		"runtimePlanHash": plan.PlanHash})
	runtime, _ := json.Marshal(map[string]any{"planHash": plan.PlanHash,
		"canonicalPlan": json.RawMessage(canonicalPlan), "installationId": plan.Execution.InstallationID,
		"operationId": plan.Execution.OperationID})
	var raw []byte
	if err := p.conn.QueryRow(ctx, `SELECT office_app_install_commit($1,$2,$3,$4,$5,$6,$7,$8)`,
		op.OperationID, op.StateGeneration, op.ExecutorID, op.LeaseID, manifest.Image,
		manifest.Digest, string(artifact), string(runtime)).Scan(&raw); err != nil {
		return err
	}
	var updated struct {
		State           string `json:"state"`
		StateGeneration int64  `json:"stateGeneration"`
	}
	if err := json.Unmarshal(raw, &updated); err != nil {
		return fmt.Errorf("decode managed app install commit: %w", err)
	}
	op.State, op.StateGeneration = updated.State, updated.StateGeneration
	return nil
}

func (p *PGControlPlane) InstallationID(ctx context.Context) (string, error) {
	var installationID string
	if err := p.conn.QueryRow(ctx,
		`SELECT installation_id::text FROM upgrade_control_state WHERE singleton`).Scan(&installationID); err != nil {
		return "", fmt.Errorf("read managed app installation identity: %w", err)
	}
	return installationID, nil
}

type PGControlPlane struct{ conn *pgx.Conn }

func OpenPGControlPlane(ctx context.Context, dsn string) (*PGControlPlane, error) {
	conn, err := pgx.Connect(ctx, strings.TrimSpace(dsn))
	if err != nil {
		return nil, fmt.Errorf("open managed app control plane: %w", err)
	}
	return &PGControlPlane{conn: conn}, nil
}

func (p *PGControlPlane) Close(ctx context.Context) error { return p.conn.Close(ctx) }

func (p *PGControlPlane) Claim(ctx context.Context, executor string, lease uuid.UUID) (*Operation, error) {
	var raw []byte
	if err := p.conn.QueryRow(ctx, `SELECT office_app_operation_claim_next($1,$2)`, executor, lease).Scan(&raw); err != nil {
		return nil, err
	}
	if string(raw) == "{}" {
		return nil, nil
	}
	var op Operation
	if err := json.Unmarshal(raw, &op); err != nil {
		return nil, fmt.Errorf("decode managed app claim: %w", err)
	}
	return &op, nil
}

func (p *PGControlPlane) Heartbeat(ctx context.Context, op *Operation, leaseSeconds int) error {
	var raw []byte
	return p.conn.QueryRow(ctx,
		`SELECT office_app_operation_heartbeat($1,$2,$3,$4,$5)`,
		op.OperationID, op.StateGeneration, op.ExecutorID, op.LeaseID, leaseSeconds).Scan(&raw)
}

func (p *PGControlPlane) Advance(ctx context.Context, op *Operation, next, phase string, progress, failure map[string]any) error {
	progressRaw, _ := json.Marshal(progress)
	var failureRaw any
	if failure != nil {
		encoded, _ := json.Marshal(failure)
		failureRaw = string(encoded)
	}
	var raw []byte
	if err := p.conn.QueryRow(ctx,
		`SELECT office_app_operation_advance($1,$2,$3,$4,$5,$6,$7,$8)`,
		op.OperationID, op.StateGeneration, op.ExecutorID, op.LeaseID,
		next, phase, string(progressRaw), failureRaw).Scan(&raw); err != nil {
		return err
	}
	var updated struct {
		State           string `json:"state"`
		StateGeneration int64  `json:"stateGeneration"`
	}
	if err := json.Unmarshal(raw, &updated); err != nil {
		return err
	}
	op.State, op.StateGeneration = updated.State, updated.StateGeneration
	return nil
}
