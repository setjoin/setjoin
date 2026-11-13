package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/exchangeartifact"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
)

const maxExchangeAssessmentRequestBytes = 1 << 20

// ExchangeAssessmentHandler exposes the V1A assessment control plane. Reads
// use the worker pool because the registry and domain-scoped project inventory
// are administrator data; every mutation is delegated to reducer authority.
type ExchangeAssessmentHandler struct {
	pool      *pgxpool.Pool
	logger    *slog.Logger
	objects   *minio.Client
	bucket    string
	masterKey []byte
	profile   cryptokey.CryptoProfile
	signer    exchangeReceiptSigner
}

type exchangeReceiptSigner interface {
	SignExchangeReceipt(exchangeartifact.ReceiptClaims) (exchangeartifact.SignedReceipt, error)
}

func NewExchangeAssessmentHandler(workerPool pgxutil.WorkerPool, objects *minio.Client, bucket string, masterKey []byte, profile cryptokey.CryptoProfile, signer exchangeReceiptSigner, logger *slog.Logger) *ExchangeAssessmentHandler {
	return &ExchangeAssessmentHandler{pool: workerPool.Pool, objects: objects, bucket: bucket, masterKey: append([]byte(nil), masterKey...), profile: profile, signer: signer, logger: logger}
}

const maxExchangeBundleBytes = 64 << 20

func exchangeClaims(w http.ResponseWriter, r *http.Request, permission string) (*auth.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil, false
	}
	if !claims.HasPermission(permission) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: permission + " required"})
		return nil, false
	}
	if permission != permissions.PermExchangeAssessmentRead {
		if _, err := jwtutil.VerifyFreshAAL2(claims, time.Now(), jwtutil.CurrentFreshAAL2Policy()); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "fresh AAL2 authority is required"})
			return nil, false
		}
	}
	return claims, true
}

func (h *ExchangeAssessmentHandler) Registry(w http.ResponseWriter, r *http.Request) {
	if _, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRead); !ok {
		return
	}
	var projection json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `
		SELECT projection FROM exchange_registry_snapshots ORDER BY registry_version DESC LIMIT 1`).Scan(&projection); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "read Exchange registry failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, projection)
}

func (h *ExchangeAssessmentHandler) ListProjects(w http.ResponseWriter, r *http.Request) {
	if _, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRead); !ok {
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	rows, err := h.pool.Query(r.Context(), `
		SELECT id,domain_id,name,state,retention_until,created_by,created_at,updated_at
		FROM exchange_assessment_projects
		WHERE ($1::bigint=0 OR domain_id=$1) AND state<>'deleted'
		ORDER BY updated_at DESC,id DESC LIMIT 500`, domainScope)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list Exchange assessment projects failed", err)
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, domainID, createdBy int64
		var name, state string
		var retention, created, updated any
		if err := rows.Scan(&id, &domainID, &name, &state, &retention, &createdBy, &created, &updated); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan Exchange assessment project failed", err)
			return
		}
		out = append(out, map[string]any{"id": id, "domainId": domainID, "name": name, "state": state,
			"retentionUntil": retention, "createdBy": createdBy, "createdAt": created, "updatedAt": updated})
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *ExchangeAssessmentHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRun)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		DomainID       int64   `json:"domainId"`
		Name           string  `json:"name"`
		RetentionUntil *string `json:"retentionUntil"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		return
	}
	idempotencyKey, payloadDigest, ok := exchangeIdempotency(w, r, req)
	if !ok {
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT exchange_assessment_project_create_idempotent($1,$2,$3,$4,$5,$6::timestamptz)`,
		claims.UserID, idempotencyKey, payloadDigest, req.DomainID, req.Name, req.RetentionUntil).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *ExchangeAssessmentHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	if _, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRead); !ok {
		return
	}
	projectID, ok := httputil.ParseIDPath(w, r, "projectId", "invalid project id")
	if !ok {
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	rows, err := h.pool.Query(r.Context(), `
		SELECT r.id,r.project_id,r.generation,r.state,r.support_cell_id,r.support_cell_digest,
		       r.registry_version,r.registry_digest,r.catalog_version,r.collector_version,
		       r.error_code,r.created_at,r.updated_at,r.completed_at
		FROM exchange_assessment_runs r
		JOIN exchange_assessment_projects p ON p.id=r.project_id
		WHERE r.project_id=$1 AND ($2::bigint=0 OR p.domain_id=$2)
		ORDER BY r.id DESC LIMIT 500`, projectID, domainScope)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "list Exchange assessment runs failed", err)
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, pid, generation, registryVersion, catalogVersion int64
		var state, cellID, cellDigest, registryDigest, collectorVersion string
		var errorCode, created, updated, completed any
		if err := rows.Scan(&id, &pid, &generation, &state, &cellID, &cellDigest, &registryVersion,
			&registryDigest, &catalogVersion, &collectorVersion, &errorCode, &created, &updated, &completed); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "scan Exchange assessment run failed", err)
			return
		}
		out = append(out, map[string]any{"id": id, "projectId": pid, "generation": generation, "state": state,
			"supportCellId": cellID, "supportCellDigest": cellDigest, "registryVersion": registryVersion,
			"registryDigest": registryDigest, "catalogVersion": catalogVersion, "collectorVersion": collectorVersion,
			"errorCode": errorCode, "createdAt": created, "updatedAt": updated, "completedAt": completed})
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *ExchangeAssessmentHandler) CreateRun(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRun)
	if !ok {
		return
	}
	projectID, ok := httputil.ParseIDPath(w, r, "projectId", "invalid project id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		SupportCellID     string `json:"supportCellId"`
		SupportCellDigest string `json:"supportCellDigest"`
		RegistryVersion   int    `json:"registryVersion"`
		RegistryDigest    string `json:"registryDigest"`
		CatalogVersion    int    `json:"catalogVersion"`
		CollectorVersion  string `json:"collectorVersion"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		return
	}
	idempotencyKey, payloadDigest, ok := exchangeIdempotency(w, r, req)
	if !ok {
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_run_create_idempotent($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		claims.UserID, idempotencyKey, payloadDigest, projectID, req.SupportCellID, req.SupportCellDigest, req.RegistryVersion,
		req.RegistryDigest, req.CatalogVersion, req.CollectorVersion).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func exchangeIdempotency(w http.ResponseWriter, r *http.Request, payload any) (uuid.UUID, string, bool) {
	key, err := uuid.Parse(r.Header.Get("Idempotency-Key"))
	if err != nil || key.String() != r.Header.Get("Idempotency-Key") {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "Idempotency-Key must be one canonical UUID"})
		return uuid.Nil, "", false
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "request canonicalization failed"})
		return uuid.Nil, "", false
	}
	digest := sha256.Sum256(raw)
	return key, hex.EncodeToString(digest[:]), true
}

func (h *ExchangeAssessmentHandler) TransitionRun(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRun)
	if !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		ExpectedGeneration int64   `json:"expectedGeneration"`
		State              string  `json:"state"`
		ErrorCode          *string `json:"errorCode"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_run_transition($1,$2,$3,$4,$5)`,
		claims.UserID, runID, req.ExpectedGeneration, req.State, req.ErrorCode).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *ExchangeAssessmentHandler) UploadBundle(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentRun)
	if !ok {
		return
	}
	if h.objects == nil || h.bucket == "" || len(h.masterKey) < 32 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "assessment artifact storage is unavailable"})
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	generation, err := strconv.ParseInt(r.Header.Get("X-Run-Generation"), 10, 64)
	if err != nil || generation < 1 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "X-Run-Generation must be a positive integer"})
		return
	}
	declared := strings.ToLower(r.Header.Get("X-Content-SHA256"))
	if decoded, decodeErr := hex.DecodeString(declared); decodeErr != nil || len(decoded) != sha256.Size {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "X-Content-SHA256 is required"})
		return
	}
	var projectID, domainID, currentGeneration int64
	var installationID string
	var retention *time.Time
	err = h.pool.QueryRow(r.Context(), `
		SELECT r.project_id,p.domain_id,p.retention_until,r.generation,u.installation_id::text
		FROM exchange_assessment_runs r
		JOIN exchange_assessment_projects p ON p.id=r.project_id
		JOIN upgrade_control_state u ON u.singleton
		WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.run')`,
		runID, claims.UserID).Scan(&projectID, &domainID, &retention, &currentGeneration, &installationID)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 404, Detail: "assessment run not found"})
		return
	}
	var replay json.RawMessage
	err = h.pool.QueryRow(r.Context(), `
		SELECT to_jsonb(a)||jsonb_build_object('replayed',true,'runGeneration',$3::bigint)
		FROM exchange_assessment_artifacts a
		WHERE a.run_id=$1 AND a.kind='bundle' AND a.sha256=$2`, runID, declared, currentGeneration).Scan(&replay)
	if err == nil {
		httputil.WriteJSON(w, http.StatusOK, replay)
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteDBErr(w, r, h.logger, "read Exchange assessment artifact failed", err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBundleBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusRequestEntityTooLarge, Detail: "bundle exceeds 64 MiB"})
			return
		}
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "bundle could not be read"})
		return
	}
	if len(raw) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "bundle is empty"})
		return
	}
	digest := sha256.Sum256(raw)
	actual := hex.EncodeToString(digest[:])
	if actual != declared {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: "bundle digest mismatch"})
		return
	}
	binding := exchangeartifact.Binding{InstallationID: installationID, TenantID: domainID, ProjectID: projectID, Kind: "exchange-assessment-bundle", PlainSHA256: actual}
	envelope, err := exchangeartifact.Seal(raw, h.masterKey, h.profile, binding)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "artifact encryption failed"})
		return
	}
	meta, err := envelope.Metadata()
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "artifact metadata failed"})
		return
	}
	sealed, err := json.Marshal(envelope)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "artifact encoding failed"})
		return
	}
	objectKey := fmt.Sprintf("exchange-assessment/%d/%d/%d/%s.sjae", domainID, projectID, runID, uuid.NewString())
	if _, err = h.objects.PutObject(r.Context(), h.bucket, objectKey, bytes.NewReader(sealed), int64(len(sealed)), minio.PutObjectOptions{ContentType: "application/vnd.setjoin.exchange-artifact+json"}); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 503, Detail: "artifact storage write failed"})
		return
	}
	var result json.RawMessage
	err = h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_artifact_commit($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, claims.UserID, runID, generation, actual, objectKey, string(h.profile), "db-encryption-key:v1", meta.CiphertextSize, meta.Nonce, meta.WrappedDEK, meta.AADSHA256, retention).Scan(&result)
	if err != nil {
		_ = h.objects.RemoveObject(r.Context(), h.bucket, objectKey, minio.RemoveObjectOptions{})
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *ExchangeAssessmentHandler) SetDecision(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentDecide)
	if !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		ExpectedGeneration int64   `json:"expectedGeneration"`
		CapabilityID       string  `json:"capabilityId"`
		OutcomeMapping     string  `json:"outcomeMapping"`
		Decision           string  `json:"decision"`
		Reason             string  `json:"reason"`
		WaiverExpiresAt    *string `json:"waiverExpiresAt"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: err.Error()})
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_decision_set($1,$2,$3,$4,$5,$6,$7,$8::timestamptz)`,
		claims.UserID, runID, req.ExpectedGeneration, req.CapabilityID, req.OutcomeMapping, req.Decision, req.Reason, req.WaiverExpiresAt).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result)
}

func (h *ExchangeAssessmentHandler) CreateAttestation(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentAttest)
	if !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		Kind          string          `json:"kind"`
		SubjectDigest string          `json:"subjectDigest"`
		Statement     json.RawMessage `json:"statement"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: err.Error()})
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_attestation_create($1,$2,$3,$4,$5)`, claims.UserID, runID, req.Kind, req.SubjectDigest, req.Statement).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *ExchangeAssessmentHandler) ResolveClaims(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentAudit)
	if !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		ExpectedGeneration int64 `json:"expectedGeneration"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: err.Error()})
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_claim_resolve($1,$2,$3)`, claims.UserID, runID, req.ExpectedGeneration).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *ExchangeAssessmentHandler) AuditSnapshot(w http.ResponseWriter, r *http.Request) {
	if _, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentAudit); !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	var out json.RawMessage
	err := h.pool.QueryRow(r.Context(), `SELECT jsonb_build_object(
		'claims',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id DESC) FROM exchange_assessment_claim_snapshots s WHERE s.run_id=r.id),'[]'::jsonb),
		'attestations',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id DESC) FROM exchange_assessment_attestations a WHERE a.run_id=r.id),'[]'::jsonb),
		'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id DESC) FROM exchange_assessment_evidence e WHERE e.run_id=r.id),'[]'::jsonb),
		'publications',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id DESC) FROM exchange_assessment_publications x WHERE x.run_id=r.id),'[]'::jsonb))
		FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id
		WHERE r.id=$1 AND ($2::bigint=0 OR p.domain_id=$2)`, runID, domainScope).Scan(&out)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "read Exchange assessment evidence failed", err)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}

func (h *ExchangeAssessmentHandler) Publish(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentPublish)
	if !ok {
		return
	}
	runID, ok := httputil.ParseIDPath(w, r, "runId", "invalid run id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		ProjectionDigest string `json:"projectionDigest"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: err.Error()})
		return
	}
	if h.objects == nil || h.bucket == "" || len(h.masterKey) < 32 || h.signer == nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusServiceUnavailable, Detail: "signed publication storage is unavailable"})
		return
	}
	var projectID, domainID int64
	var installationID string
	if err := h.pool.QueryRow(r.Context(), `SELECT r.project_id,p.domain_id,u.installation_id::text FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id JOIN upgrade_control_state u ON u.singleton WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.publish')`, runID, claims.UserID).Scan(&projectID, &domainID, &installationID); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 404, Detail: "assessment run not found"})
		return
	}
	// Authorization must precede even an idempotent replay lookup. Otherwise a
	// scoped administrator could use run IDs to learn that another tenant has a
	// publication without being allowed to see the run itself.
	var replay json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT to_jsonb(p)||'{"replayed":true}'::jsonb FROM exchange_assessment_publications p WHERE p.run_id=$1 AND p.projection_digest=$2 AND p.revoked_at IS NULL`, runID, req.ProjectionDigest).Scan(&replay); err == nil {
		httputil.WriteJSON(w, http.StatusOK, replay)
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteDBErr(w, r, h.logger, "read Exchange publication failed", err)
		return
	}
	signed, err := h.signer.SignExchangeReceipt(exchangeartifact.ReceiptClaims{Kind: "publication", SubjectSHA256: req.ProjectionDigest, InstallationID: installationID, TenantID: domainID, ProjectID: projectID, Disposition: "published_evidence_snapshot"})
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 503, Detail: "publication receipt signing is unavailable"})
		return
	}
	receiptRaw, _ := json.Marshal(signed)
	receiptDigest := sha256.Sum256(receiptRaw)
	receiptSHA := hex.EncodeToString(receiptDigest[:])
	binding := exchangeartifact.Binding{InstallationID: installationID, TenantID: domainID, ProjectID: projectID, Kind: "exchange-assessment-receipt", PlainSHA256: receiptSHA}
	envelope, err := exchangeartifact.Seal(receiptRaw, h.masterKey, h.profile, binding)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "publication receipt encryption failed"})
		return
	}
	meta, err := envelope.Metadata()
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 500, Detail: "publication receipt metadata failed"})
		return
	}
	sealed, _ := json.Marshal(envelope)
	objectKey := fmt.Sprintf("exchange-assessment/%d/%d/%d/receipts/%s.sjae", domainID, projectID, runID, uuid.NewString())
	if _, err = h.objects.PutObject(r.Context(), h.bucket, objectKey, bytes.NewReader(sealed), int64(len(sealed)), minio.PutObjectOptions{ContentType: "application/vnd.setjoin.exchange-artifact+json"}); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 503, Detail: "publication receipt storage failed"})
		return
	}
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_publish_signed($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, claims.UserID, runID, req.ProjectionDigest, receiptSHA, objectKey, string(h.profile), "db-encryption-key:v1", meta.CiphertextSize, meta.Nonce, meta.WrappedDEK, meta.AADSHA256, receiptRaw, signed.Algorithm, signed.Claims.KeyID, signature).Scan(&result); err != nil {
		_ = h.objects.RemoveObject(r.Context(), h.bucket, objectKey, minio.RemoveObjectOptions{})
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, result)
}

func (h *ExchangeAssessmentHandler) RequestDeletion(w http.ResponseWriter, r *http.Request) {
	claims, ok := exchangeClaims(w, r, permissions.PermExchangeAssessmentDelete)
	if !ok {
		return
	}
	projectID, ok := httputil.ParseIDPath(w, r, "projectId", "invalid project id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeAssessmentRequestBytes)
	var req struct {
		Scope      string `json:"scope"`
		RunID      *int64 `json:"runId"`
		ArtifactID *int64 `json:"artifactId"`
		Reason     string `json:"reason"`
	}
	if err := decodeExchangeRequest(r, &req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: 400, Detail: err.Error()})
		return
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT exchange_assessment_delete_request($1,$2,$3,$4,$5,$6)`, claims.UserID, projectID, req.Scope, req.RunID, req.ArtifactID, req.Reason).Scan(&result); err != nil {
		h.writeReducerError(w, r, err)
		return
	}
	httputil.WriteJSON(w, http.StatusAccepted, result)
}

func decodeExchangeRequest(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return strconv.ErrSyntax
		}
		return err
	}
	return nil
}

func (h *ExchangeAssessmentHandler) writeReducerError(w http.ResponseWriter, r *http.Request, err error) {
	h.logger.Info("Exchange assessment request rejected", "error", err)
	if !reducererr.WriteClassified(w, r, err) {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "request failed"})
	}
}
