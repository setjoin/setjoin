package admin

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/httputil"
)

// TrustAnchorHandler serves admin S/MIME trust-anchor CRUD endpoints.
// Domain scoping mirrors admin_dlp.go: domainScope == 0 means global/super-admin
// (sees all anchors; imports are deployment-wide with domain_id = NULL).
// domainScope > 0 means scoped admin (sees anchors where domain_id IS NULL OR
// domain_id = domainScope; imports store domain_id = domainScope; may only
// delete their own domain's anchors).
type TrustAnchorHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewTrustAnchorHandler creates a TrustAnchorHandler.
func NewTrustAnchorHandler(pool *pgxpool.Pool, logger *slog.Logger) *TrustAnchorHandler {
	return &TrustAnchorHandler{pool: pool, logger: logger}
}

// trustAnchorRow is the JSON wire format for a single trust anchor.
type trustAnchorRow struct {
	ID          int64  `json:"id"`
	Label       string `json:"label"`
	SubjectCN   string `json:"subjectCn"`
	Fingerprint string `json:"fingerprint"`
	DomainID    *int64 `json:"domainId"`
	NotBefore   string `json:"notBefore"`
	NotAfter    string `json:"notAfter"`
	CreatedAt   string `json:"createdAt"`
}

// List returns trust anchors visible to the caller.
// GET /admin/smime/trust-anchors
func (h *TrustAnchorHandler) List(w http.ResponseWriter, r *http.Request) {
	domainScope := middleware.DomainScopeFromContext(r.Context())

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, label, COALESCE(subject_cn,''), fingerprint, domain_id, not_before, not_after, created_at
		 FROM smime_trust_anchors
		 WHERE ($1 = 0 OR domain_id IS NULL OR domain_id = $1)
		 ORDER BY created_at DESC`,
		domainScope,
	)
	if err != nil {
		h.logger.Error("trust_anchors: list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	anchors := make([]trustAnchorRow, 0)
	for rows.Next() {
		var a trustAnchorRow
		var notBefore, notAfter, createdAt time.Time
		if err := rows.Scan(&a.ID, &a.Label, &a.SubjectCN, &a.Fingerprint,
			&a.DomainID, &notBefore, &notAfter, &createdAt); err != nil {
			continue
		}
		a.NotBefore = notBefore.UTC().Format(time.RFC3339)
		a.NotAfter = notAfter.UTC().Format(time.RFC3339)
		a.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		anchors = append(anchors, a)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"anchors": anchors})
}

// validateAnchorChain parses EVERY certificate of the uploaded PEM (round 6,
// Astra HOLD: the old import fingerprinted only the FIRST certificate while
// storing the complete bundle — the unfingerprinted extra certs still entered
// every trust pool and their missing fingerprint rows later made the anchor
// resolver fail open). It fails closed when any block does not parse. The
// expiry gate matches the pre-round-6 semantics: the FIRST certificate (the
// anchor the admin is importing) must not already be expired.
func validateAnchorChain(certPEM string) ([]smime.ParsedAnchorCert, error) {
	certs, err := smime.ParseAnchorChain(certPEM)
	if err != nil {
		return nil, err
	}
	if time.Now().After(certs[0].NotAfter) {
		return nil, errAnchorExpired
	}
	return certs, nil
}

// errAnchorExpired marks a first-certificate expiry failure (mapped to 400).
var errAnchorExpired = errors.New("trust_anchors: certificate is already expired")

// Import uploads a new trust anchor (multipart: label + cert file).
// POST /admin/smime/trust-anchors
func (h *TrustAnchorHandler) Import(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	domainScope := middleware.DomainScopeFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)        // 1 MB
	if err := r.ParseMultipartForm(1 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (1MB) above
		httputil.WriteError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = "imported"
	}

	certFile, _, err := r.FormFile("cert")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "missing cert file")
		return
	}
	defer certFile.Close()
	certBytes, _ := io.ReadAll(certFile)

	certPEM := string(certBytes)
	certs, cerr := validateAnchorChain(certPEM)
	if cerr != nil {
		if errors.Is(cerr, errAnchorExpired) {
			httputil.WriteError(w, http.StatusBadRequest, "certificate is already expired")
			return
		}
		h.logger.Warn("trust_anchors: invalid PEM", "error", cerr)
		httputil.WriteError(w, http.StatusBadRequest, "not a valid PEM certificate")
		return
	}

	// Persist ONE ROW PER CERTIFICATE: each row stores its own single-cert PEM,
	// fingerprint, subject and validity window, so the stored fingerprint list
	// covers EVERY certificate of the uploaded bundle. Pool construction loads
	// only certs whose fingerprint matches a stored row, and the anchor
	// resolver can always attribute a validated chain's root to its granting
	// row(s) — an imported bundle can no longer smuggle unfingerprinted trust.
	ctx := r.Context()
	for _, c := range certs {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO smime_trust_anchors (label, cert_pem, subject_cn, fingerprint, domain_id, not_before, not_after, created_by)
			 VALUES ($1, $2, $3, $4, NULLIF($5, 0), $6, $7, $8)
			 ON CONFLICT (fingerprint, domain_id) DO UPDATE SET label = EXCLUDED.label`,
			label, c.PEM, c.SubjectCN, c.Fingerprint, domainScope, c.NotBefore, c.NotAfter, claims.UserID,
		); err != nil {
			h.logger.Error("trust_anchors: import failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "failed to store trust anchor")
			return
		}
	}

	h.notifyTrustChanged(ctx)
	h.logger.Info("trust_anchors: imported",
		"certificates", len(certs), "fingerprint", certs[0].Fingerprint,
		"label", label, "domain_scope", domainScope)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "fingerprint": certs[0].Fingerprint})
}

// Delete removes a trust anchor by id.
// DELETE /admin/smime/trust-anchors/{id}
// A scoped admin (domainScope > 0) can only delete their domain's anchors.
// A global admin (domainScope == 0) can delete any anchor.
func (h *TrustAnchorHandler) Delete(w http.ResponseWriter, r *http.Request) {
	domainScope := middleware.DomainScopeFromContext(r.Context())

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid id")
		return
	}

	ctx := r.Context()
	tag, err := h.pool.Exec(ctx,
		`DELETE FROM smime_trust_anchors
		 WHERE id = $1 AND ($2 = 0 OR domain_id = $2)`,
		id, domainScope,
	)
	if err != nil {
		h.logger.Error("trust_anchors: delete failed", "error", err, "id", id)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "trust anchor not found")
		return
	}

	h.notifyTrustChanged(ctx)
	h.logger.Info("trust_anchors: deleted", "id", id, "domain_scope", domainScope)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// notifyTrustChanged sends a pg_notify on the dedicated smime_trust_changed channel
// so the verification layer can reload its trust pool without a restart.
// Uses a separate channel (not config_changed) to avoid the toggle subscriber
// mis-parsing the payload.
func (h *TrustAnchorHandler) notifyTrustChanged(ctx context.Context) {
	if _, err := h.pool.Exec(ctx, `SELECT pg_notify('smime_trust_changed', '1')`); err != nil {
		h.logger.Warn("smime: failed to notify smime_trust_changed", "error", err)
	}
}
