package admin

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/office"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

type OfficeHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	prober office.ProviderProber
}

func NewOfficeHandler(pool *pgxpool.Pool, logger *slog.Logger) *OfficeHandler {
	return &OfficeHandler{pool: pool, logger: logger, prober: office.LiveProviderProber{}}
}

func (h *OfficeHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT office_admin_list($1)`, claims.UserID).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

type officeConfigureBody struct {
	ExpectedGeneration int64           `json:"expectedGeneration"`
	Profile            string          `json:"profile"`
	EntitlementState   string          `json:"entitlementState"`
	BuildID            *string         `json:"buildId"`
	Config             json.RawMessage `json:"config"`
}

type officeQualifyBody struct {
	ExpectedGeneration int64  `json:"expectedGeneration"`
	SyntheticReceiptID int64  `json:"syntheticReceiptId"`
	BuildDigest        string `json:"buildDigest"`
	RouteRevision      int64  `json:"routeRevision"`
}

type officeActivateBody struct {
	ExpectedGeneration int64           `json:"expectedGeneration"`
	QualificationID    string          `json:"qualificationId"`
	Scope              json.RawMessage `json:"scope"`
}

type officeAppOperationBody struct {
	Kind                       string          `json:"kind"`
	ProviderID                 string          `json:"providerId"`
	ExpectedProviderGeneration int64           `json:"expectedProviderGeneration"`
	IdempotencyKey             string          `json:"idempotencyKey"`
	Request                    json.RawMessage `json:"request"`
}

type officeAppRecoverBody struct {
	ExpectedGeneration int64 `json:"expectedGeneration"`
}

func decodeOfficeBody(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "exactly one JSON value is required")
		return false
	}
	return true
}

func writeOfficeJSON(w http.ResponseWriter, status int, out json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func (h *OfficeHandler) Configure(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body officeConfigureBody
	if !decodeOfficeBody(w, r, &body) {
		return
	}
	if len(body.Config) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "config is required")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT office_provider_configure($1,$2,$3,$4,$5,$6,$7,$8)`,
		claims.UserID, r.PathValue("providerId"), body.ExpectedGeneration,
		body.Profile, body.EntitlementState, body.BuildID, string(body.Config),
		officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

func (h *OfficeHandler) Qualify(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body officeQualifyBody
	if !decodeOfficeBody(w, r, &body) {
		return
	}
	if body.SyntheticReceiptID <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "syntheticReceiptId must be positive")
		return
	}
	var targetRaw []byte
	if err := h.pool.QueryRow(r.Context(), `SELECT office_provider_qualification_target($1,$2,$3)`,
		claims.UserID, r.PathValue("providerId"), body.ExpectedGeneration).Scan(&targetRaw); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	target, err := office.DecodeQualificationTarget(targetRaw)
	if err != nil {
		h.logger.Error("decode Office qualification target", "error", err)
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office qualification target is invalid")
		return
	}
	result, err := h.prober.Probe(r.Context(), target)
	if err != nil {
		h.logger.Info("Office provider qualification probe failed", "provider_id", target.ProviderID, "error", err)
		httputil.WriteProblemStatus(w, http.StatusConflict, "Office provider qualification failed: "+err.Error())
		return
	}
	result.Checks["wopiSave"] = "pass"
	checks, err := json.Marshal(result.Checks)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "Office qualification result is invalid")
		return
	}
	if body.RouteRevision <= 0 {
		body.RouteRevision = 1
	}
	var buildDigest any
	if body.BuildDigest != "" {
		buildDigest = body.BuildDigest
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT office_provider_qualify($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		claims.UserID, target.ProviderID, target.Generation, target.Profile,
		target.ConfigSHA256, string(checks), result.DiscoveryFingerprint,
		buildDigest, body.RouteRevision, body.SyntheticReceiptID,
		officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

func (h *OfficeHandler) Activate(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var body officeActivateBody
	if !decodeOfficeBody(w, r, &body) {
		return
	}
	receiptID, err := uuid.Parse(body.QualificationID)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "qualificationId must be a UUID")
		return
	}
	if len(body.Scope) == 0 {
		body.Scope = json.RawMessage(`{}`)
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT office_provider_activate($1,$2,$3,$4,$5,$6)`,
		claims.UserID, r.PathValue("providerId"), body.ExpectedGeneration,
		receiptID, string(body.Scope), officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

func (h *OfficeHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT office_app_admin_list($1)`, claims.UserID).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

func (h *OfficeHandler) RequestAppOperation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if r.PathValue("appId") != "collabora-code" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "unknown curated application")
		return
	}
	var body officeAppOperationBody
	if !decodeOfficeBody(w, r, &body) {
		return
	}
	key, err := uuid.Parse(body.IdempotencyKey)
	if err != nil || key.String() != body.IdempotencyKey || r.Header.Get("Idempotency-Key") != body.IdempotencyKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "one canonical Idempotency-Key must match body idempotencyKey")
		return
	}
	if len(body.Request) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "request is required")
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT office_app_operation_request($1,$2,$3,$4,$5,$6,$7)`,
		claims.UserID, body.Kind, body.ProviderID, body.ExpectedProviderGeneration,
		key, string(body.Request), officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusAccepted, out)
}

func (h *OfficeHandler) RecoverAppOperation(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if r.PathValue("appId") != "collabora-code" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "unknown curated application")
		return
	}
	operationID, err := uuid.Parse(r.PathValue("operationId"))
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "operationId must be a UUID")
		return
	}
	var body officeAppRecoverBody
	if !decodeOfficeBody(w, r, &body) {
		return
	}
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(),
		`SELECT office_app_operation_recover_request($1,$2,$3,$4)`,
		claims.UserID, operationID, body.ExpectedGeneration, officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusAccepted, out)
}

func (h *OfficeHandler) Remove(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	providerID := r.PathValue("providerId")
	var out json.RawMessage
	if err := h.pool.QueryRow(r.Context(), `SELECT office_provider_remove($1,$2,$3)`,
		claims.UserID, providerID, officeAuditReason(r)).Scan(&out); err != nil {
		reducererr.WriteProblem(w, r, err, officeAdminProblemOptions)
		return
	}
	writeOfficeJSON(w, http.StatusOK, out)
}

// The route-level reason middleware is authoritative for enforcing presence.
// Forward the original header so rolling-upgrade policy drift cannot erase it;
// the reducer independently rejects an empty removal reason.
func officeAuditReason(r *http.Request) string {
	return r.Header.Get("X-Audit-Reason")
}

var officeAdminProblemOptions = reducererr.ProblemOptions{Namespace: "office", Slugs: map[string]string{
	"BZ322": "invalid-arguments", "BZ323": "forbidden", "BZ324": "state-mismatch",
	"BZ326": "replay-conflict", "BZ327": "provider-unavailable",
}}
