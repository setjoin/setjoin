package admin

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/reducererr"
)

type UpgradeHandler struct {
	pool *pgxpool.Pool
	db   interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}
}

func NewUpgradeHandler(pool *pgxpool.Pool) *UpgradeHandler {
	handler := &UpgradeHandler{pool: pool}
	if pool != nil {
		handler.db = pool
	}
	return handler
}

const maxUpgradeBodyBytes = 64 << 10

var upgradeDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func decodeUpgradeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxUpgradeBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "upgrade request must contain one JSON object")
		return false
	}
	return true
}

func writeUpgradeRaw(w http.ResponseWriter, status int, raw json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func (h *UpgradeHandler) queryRaw(w http.ResponseWriter, r *http.Request, status int, query string, args ...any) {
	if h.db == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "upgrade control plane unavailable")
		return
	}
	var raw json.RawMessage
	if err := h.db.QueryRow(r.Context(), query, args...).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError, "upgrade control operation failed")
		}
		return
	}
	writeUpgradeRaw(w, status, raw)
}

func upgradeClaims(w http.ResponseWriter, r *http.Request) (*jwtutil.Claims, bool) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil || claims.UserID <= 0 {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return nil, false
	}
	return claims, true
}

func validateUpgradeReason(w http.ResponseWriter, r *http.Request, reason string) bool {
	reason = strings.TrimSpace(reason)
	if len(reason) < 8 || len(reason) > 1024 || strings.ContainsAny(reason, "\r\n\x00") ||
		strings.TrimSpace(r.Header.Get("X-Audit-Reason")) != reason {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body reason must exactly match X-Audit-Reason and contain 8-1024 safe characters")
		return false
	}
	return true
}

func validateUpgradeIdempotency(w http.ResponseWriter, r *http.Request, body string) (uuid.UUID, bool) {
	header := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if body == "" || header != body {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "body idempotencyKey must exactly match Idempotency-Key")
		return uuid.Nil, false
	}
	value, err := uuid.Parse(body)
	if err != nil || value == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid Idempotency-Key")
		return uuid.Nil, false
	}
	return value, true
}

// Console returns the one release-first read model used by the web UI and CLI.
func (h *UpgradeHandler) Console(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_console_read($1)`, claims.UserID)
}

func (h *UpgradeHandler) Preview(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		ReleaseID  string     `json:"releaseId"`
		Reason     string     `json:"reason"`
		ScheduleAt *time.Time `json:"scheduleAt"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_intent_preview($1,$2,$3,$4)`,
		claims.UserID, req.ReleaseID, req.Reason, req.ScheduleAt)
}

func (h *UpgradeHandler) ChallengeIssue(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		ReleaseID      string     `json:"releaseId"`
		Reason         string     `json:"reason"`
		ScheduleAt     *time.Time `json:"scheduleAt"`
		PreviewDigest  string     `json:"previewDigest"`
		IdempotencyKey string     `json:"idempotencyKey"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	if !upgradeDigestPattern.MatchString(req.PreviewDigest) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade preview digest")
		return
	}
	key, ok := validateUpgradeIdempotency(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_challenge_issue($1,$2,$3,$4,$5,$6)`,
		claims.UserID, req.ReleaseID, req.Reason, req.ScheduleAt, req.PreviewDigest, key)
}

func (h *UpgradeHandler) ChallengeComplete(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		ChallengeID string `json:"challengeId"`
	}
	if !decodeUpgradeJSON(w, r, &req) {
		return
	}
	challengeID, err := uuid.Parse(req.ChallengeID)
	if err != nil || challengeID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade challenge id")
		return
	}
	session, factor, amr, ok := upgradeStepUpBindings(claims, challengeID, time.Now())
	if !ok {
		httputil.WriteProblemStatus(w, http.StatusForbidden, "fresh AAL2 step-up with two verified factors is required")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_challenge_complete($1,$2,$3,$4,$5,$6)`,
		claims.UserID, challengeID, session[:], factor[:], amr, jwtutil.ACRAAL2)
}

func (h *UpgradeHandler) RequestIntent(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		ReleaseID      string     `json:"releaseId"`
		Reason         string     `json:"reason"`
		ScheduleAt     *time.Time `json:"scheduleAt"`
		PreviewDigest  string     `json:"previewDigest"`
		ElevationID    string     `json:"elevationId"`
		IdempotencyKey string     `json:"idempotencyKey"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	if !upgradeDigestPattern.MatchString(req.PreviewDigest) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade preview digest")
		return
	}
	elevationID, err := uuid.Parse(req.ElevationID)
	if err != nil || elevationID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade elevation id")
		return
	}
	key, ok := validateUpgradeIdempotency(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	h.queryRaw(w, r, http.StatusAccepted, `SELECT upgrade_intent_request($1,$2,$3,$4,$5,$6,$7)`,
		claims.UserID, req.ReleaseID, req.Reason, req.ScheduleAt,
		req.PreviewDigest, elevationID, key)
}

func (h *UpgradeHandler) Intent(w http.ResponseWriter, r *http.Request) {
	if _, ok := upgradeClaims(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != r.PathValue("id") {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade intent id")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_intent_read($1)`, id)
}

func (h *UpgradeHandler) Diagnostics(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != r.PathValue("id") {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade intent id")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_intent_diagnostics($1,$2)`, claims.UserID, id)
}

func (h *UpgradeHandler) CancelIntent(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != r.PathValue("id") {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade intent id")
		return
	}
	var req struct {
		ExpectedGeneration string `json:"expectedGeneration"`
		Reason             string `json:"reason"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	generation, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || generation <= 0 || strconv.FormatInt(generation, 10) != req.ExpectedGeneration {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid upgrade state generation")
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_intent_cancel($1,$2,$3,$4)`,
		claims.UserID, id, generation, req.Reason)
}

func (h *UpgradeHandler) RecordRecoverySet(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		RecoverySetID   string          `json:"recoverySetId"`
		TimelineID      string          `json:"timelineId"`
		SourceReleaseID string          `json:"sourceReleaseId"`
		SchemaVersion   int             `json:"schemaVersion"`
		ManifestDigest  string          `json:"manifestDigest"`
		Checks          map[string]bool `json:"checks"`
		CreatedAt       time.Time       `json:"createdAt"`
		ExpiresAt       time.Time       `json:"expiresAt"`
		Reason          string          `json:"reason"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	if !upgradeDigestPattern.MatchString(req.ManifestDigest) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery-set manifest digest")
		return
	}
	setID, setErr := uuid.Parse(req.RecoverySetID)
	timelineID, timelineErr := uuid.Parse(req.TimelineID)
	if setErr != nil || timelineErr != nil || setID == uuid.Nil || timelineID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid recovery-set identity")
		return
	}
	checks, _ := json.Marshal(req.Checks)
	h.queryRaw(w, r, http.StatusCreated, `SELECT upgrade_recovery_set_record($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		claims.UserID, setID, timelineID, req.SourceReleaseID, req.SchemaVersion,
		req.ManifestDigest, checks, req.CreatedAt, req.ExpiresAt)
}

// RecoveryContext returns only the authoritative, non-secret identities and
// counts needed to construct a recovery-set manifest. It never exposes DSNs,
// object-store credentials, configuration values, addresses, or mail content.
func (h *UpgradeHandler) RecoveryContext(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	h.queryRaw(w, r, http.StatusOK, `SELECT upgrade_recovery_context_read($1)`, claims.UserID)
}

func (h *UpgradeHandler) RecordRestoreProof(w http.ResponseWriter, r *http.Request) {
	claims, ok := upgradeClaims(w, r)
	if !ok {
		return
	}
	var req struct {
		ProofID       string          `json:"proofId"`
		RecoverySetID string          `json:"recoverySetId"`
		TargetID      string          `json:"targetId"`
		Checks        map[string]bool `json:"checks"`
		ProvedAt      time.Time       `json:"provedAt"`
		Reason        string          `json:"reason"`
	}
	if !decodeUpgradeJSON(w, r, &req) || !validateUpgradeReason(w, r, req.Reason) {
		return
	}
	proofID, proofErr := uuid.Parse(req.ProofID)
	setID, setErr := uuid.Parse(req.RecoverySetID)
	if proofErr != nil || setErr != nil || proofID == uuid.Nil || setID == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid restore-proof identity")
		return
	}
	checks, _ := json.Marshal(req.Checks)
	h.queryRaw(w, r, http.StatusCreated, `SELECT upgrade_restore_proof_record($1,$2,$3,$4,$5,$6)`,
		claims.UserID, proofID, setID, req.TargetID, checks, req.ProvedAt)
}

func upgradeStepUpBindings(claims *jwtutil.Claims, challengeID uuid.UUID, now time.Time) ([sha256.Size]byte, [sha256.Size]byte, []string, bool) {
	var empty [sha256.Size]byte
	evidence, err := jwtutil.VerifyFreshAAL2(claims, now, jwtutil.CurrentFreshAAL2Policy())
	if err != nil {
		return empty, empty, nil, false
	}
	issuedAt := evidence.IssuedAt.UTC().Format(time.RFC3339Nano)
	session := sha256.Sum256([]byte(fmt.Sprintf("setjoin-upgrade-session-v1\n%d\n%s\n%s", evidence.UserID, evidence.JTI, issuedAt)))
	factor := sha256.Sum256([]byte(fmt.Sprintf("setjoin-upgrade-factor-v1\n%d\n%s\n%s\n%s\n%s", evidence.UserID, challengeID, evidence.ACR, strings.Join(evidence.AMR, ","), evidence.JTI)))
	return session, factor, evidence.AMR, true
}

const legacyUpgradeRetiredType = "https://setjoin.com/errors/legacy-upgrade-retired"

func writeLegacyUpgradeRetired(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Type:   legacyUpgradeRetiredType,
		Title:  "Legacy server upgrade retired",
		Status: http.StatusGone,
		Detail: "Gateway-managed server upgrades are retired because they cannot provide a complete application recovery point or crash-safe rollback.",
		Remediation: "Open /admin/updates/server to preview or schedule a signed release. " +
			"Use mailctl upgrade status --json for read-only host status and follow docs/guides/UPGRADE.md for operator recovery.",
	})
}

func (h *UpgradeHandler) CheckUpgrade(w http.ResponseWriter, r *http.Request) {
	writeLegacyUpgradeRetired(w, r)
}

func (h *UpgradeHandler) ApplyUpgrade(w http.ResponseWriter, r *http.Request) {
	writeLegacyUpgradeRetired(w, r)
}

func (h *UpgradeHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	writeLegacyUpgradeRetired(w, r)
}

type UpgradeHistoryEntry struct {
	ID           int64      `json:"id"`
	FromVersion  string     `json:"from_version"`
	ToVersion    string     `json:"to_version"`
	Mode         string     `json:"mode"`
	DDLClass     string     `json:"ddl_classification"`
	Status       string     `json:"status"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	DowntimeMs   int        `json:"downtime_ms"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

func (h *UpgradeHandler) GetUpgradeHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, from_version, to_version, mode, ddl_classification, status, started_at, completed_at, downtime_ms, COALESCE(error_message, '')
		 FROM upgrade_history ORDER BY started_at DESC LIMIT 50`)
	if err != nil {
		httputil.WriteJSON(w, http.StatusOK, []UpgradeHistoryEntry{})
		return
	}
	defer rows.Close()
	history := []UpgradeHistoryEntry{}
	for rows.Next() {
		var e UpgradeHistoryEntry
		rows.Scan(&e.ID, &e.FromVersion, &e.ToVersion, &e.Mode, &e.DDLClass, &e.Status, &e.StartedAt, &e.CompletedAt, &e.DowntimeMs, &e.ErrorMessage)
		history = append(history, e)
	}
	httputil.WriteJSON(w, http.StatusOK, history)
}
