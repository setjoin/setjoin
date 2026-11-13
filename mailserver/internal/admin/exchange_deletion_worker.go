package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/minio/minio-go/v7"
	"setjoin.com/shared/exchangeartifact"
)

type exchangeDeletionArtifact struct {
	ID        int64  `json:"id"`
	RunID     int64  `json:"runId"`
	ObjectKey string `json:"objectKey"`
	SHA256    string `json:"sha256"`
}

type exchangeDeletionWork struct {
	ID             int64
	ProjectID      int64
	DomainID       int64
	RunID          sql.NullInt64
	Scope          string
	InstallationID string
	Artifacts      []exchangeDeletionArtifact
}

// RunDeletionWorker drains already-authorized requests even while the feature
// toggle is OFF. It removes only active-store objects and records the truthful
// backup_expiry_pending disposition; backup closure needs a later attestation.
func (h *ExchangeAssessmentHandler) RunDeletionWorker(ctx context.Context) {
	if h == nil || h.pool == nil || h.objects == nil || h.bucket == "" || h.signer == nil {
		return
	}
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		h.drainExchangeDeletions(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h *ExchangeAssessmentHandler) drainExchangeDeletions(ctx context.Context) {
	rows, err := h.pool.Query(ctx, `
		SELECT d.id,d.project_id,p.domain_id,d.run_id,d.scope,u.installation_id::text,
		  COALESCE(jsonb_agg(jsonb_build_object('id',a.id,'runId',a.run_id,
		    'objectKey',a.object_key,'sha256',a.sha256) ORDER BY a.id)
		    FILTER (WHERE a.id IS NOT NULL),'[]'::jsonb)
		FROM exchange_assessment_deletion_requests d
		JOIN exchange_assessment_projects p ON p.id=d.project_id
		JOIN upgrade_control_state u ON u.singleton
		LEFT JOIN exchange_assessment_runs r ON r.project_id=d.project_id
		LEFT JOIN exchange_assessment_artifacts a ON a.run_id=r.id AND (
		  (d.scope='artifact' AND a.id=d.artifact_id) OR
		  (d.scope='run' AND a.run_id=d.run_id) OR d.scope='project')
		WHERE d.state='requested'
		GROUP BY d.id,d.project_id,p.domain_id,d.run_id,d.scope,u.installation_id
		ORDER BY d.id LIMIT 20`)
	if err != nil {
		h.logger.Error("list Exchange deletion work failed", "error", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var work exchangeDeletionWork
		var artifacts json.RawMessage
		if err := rows.Scan(&work.ID, &work.ProjectID, &work.DomainID, &work.RunID,
			&work.Scope, &work.InstallationID, &artifacts); err != nil || json.Unmarshal(artifacts, &work.Artifacts) != nil {
			h.logger.Error("decode Exchange deletion work failed", "error", err)
			continue
		}
		h.executeExchangeDeletion(ctx, work)
	}
}

func (h *ExchangeAssessmentHandler) executeExchangeDeletion(ctx context.Context, work exchangeDeletionWork) {
	for _, artifact := range work.Artifacts {
		if err := h.objects.RemoveObject(ctx, h.bucket, artifact.ObjectKey, minio.RemoveObjectOptions{}); err != nil {
			h.logger.Error("delete Exchange active-store artifact failed", "request_id", work.ID, "artifact_id", artifact.ID, "error", err)
			return
		}
	}
	subjectRaw, _ := json.Marshal(struct {
		RequestID int64                      `json:"requestId"`
		ProjectID int64                      `json:"projectId"`
		Scope     string                     `json:"scope"`
		Artifacts []exchangeDeletionArtifact `json:"artifacts"`
	}{work.ID, work.ProjectID, work.Scope, work.Artifacts})
	subject := sha256.Sum256(subjectRaw)
	receipt, err := h.signer.SignExchangeReceipt(exchangeartifact.ReceiptClaims{
		Kind: "deletion", SubjectSHA256: hex.EncodeToString(subject[:]),
		InstallationID: work.InstallationID, TenantID: work.DomainID,
		ProjectID: work.ProjectID, Disposition: "backup_expiry_pending",
	})
	if err != nil {
		h.logger.Error("sign Exchange deletion receipt failed", "request_id", work.ID, "error", err)
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil {
		h.logger.Error("decode Exchange deletion signature failed", "request_id", work.ID, "error", err)
		return
	}
	receiptRaw, _ := json.Marshal(receipt)
	if _, err := h.pool.Exec(ctx, `SELECT exchange_assessment_delete_finalize($1,$2,$3,$4,$5,$6)`,
		work.ID, receipt.Claims.SubjectSHA256, receiptRaw, receipt.Algorithm,
		receipt.Claims.KeyID, signature); err != nil {
		h.logger.Error("finalize Exchange deletion failed", slog.Int64("request_id", work.ID), "error", err)
	}
}
