package admin

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/httputil"
)

// SMIMEHandler manages S/MIME certificate upload and listing for authenticated users.
type SMIMEHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewSMIMEHandler creates a new S/MIME cert handler.
func NewSMIMEHandler(pool *pgxpool.Pool, logger *slog.Logger) *SMIMEHandler {
	return &SMIMEHandler{pool: pool, logger: logger}
}

// ListCerts returns the current user's S/MIME certificates.
// GET /auth/me/smime/certs
func (h *SMIMEHandler) ListCerts(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, label, cert_pem, is_default, created_at
		 FROM user_smime_certs
		 WHERE user_id = $1
		 ORDER BY is_default DESC, created_at DESC`, claims.UserID,
	)
	if err != nil {
		h.logger.Error("smime: list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	type certEntry struct {
		ID        int64  `json:"id"`
		Label     string `json:"label"`
		IssuedAt  string `json:"issuedAt,omitempty"`
		ExpiresAt string `json:"expiresAt,omitempty"`
		IsDefault bool   `json:"isDefault"`
	}

	var certs []certEntry
	for rows.Next() {
		var e certEntry
		var certPEM string
		var isDefault bool
		var createdAt interface{}
		if err := rows.Scan(&e.ID, &e.Label, &certPEM, &isDefault, &createdAt); err != nil {
			continue
		}
		e.IsDefault = isDefault
		// Dates are populated from cert below

		if certPEM != "" {
			cert, err := smime.ParseCert([]byte(certPEM))
			if err == nil {
				if cert.NotBefore.Unix() > 0 {
					e.IssuedAt = cert.NotBefore.Format("2006-01-02T15:04:05Z")
				}
				if cert.NotAfter.Unix() > 0 && cert.NotAfter.Year() < 9999 {
					e.ExpiresAt = cert.NotAfter.Format("2006-01-02T15:04:05Z")
				}
			}
		}
		certs = append(certs, e)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

// UploadCert uploads an S/MIME certificate and private key.
// POST /auth/me/smime/certs
// Supports multipart form with fields: cert (PEM), key (PEM), label
func (h *SMIMEHandler) UploadCert(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)        // 5MB max
	if err := r.ParseMultipartForm(5 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (5MB) above
		httputil.WriteError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	certFile, _, err := r.FormFile("cert")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "missing cert file")
		return
	}
	defer certFile.Close()
	certBytes, _ := io.ReadAll(certFile)

	keyFile, _, err := r.FormFile("key")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "missing key file")
		return
	}
	defer keyFile.Close()
	keyBytes, _ := io.ReadAll(keyFile)

	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = "default"
	}

	// Parse and validate certificate
	cert, err := smime.ParseCert(certBytes)
	if err != nil {
		h.logger.Warn("smime: invalid certificate", "error", err)
		httputil.WriteError(w, http.StatusBadRequest, "Invalid certificate format. Ensure the certificate is PEM-encoded.")
		return
	}

	// Parse and validate private key
	_, err = smime.ParsePrivateKey(keyBytes)
	if err != nil {
		h.logger.Warn("smime: invalid private key", "error", err)
		httputil.WriteError(w, http.StatusBadRequest, "Invalid private key format. Ensure the key is PEM-encoded and not encrypted.")
		return
	}

	// Store cert (unencrypted) and key (encrypted via pgp_sym_encrypt).
	// is_default is TRUE iff this is the user's first cert (no prior rows), so the
	// uploaded cert is immediately available to signSMIME without a separate set-default call.
	ctx := r.Context()
	_, err = h.pool.Exec(ctx,
		`INSERT INTO user_smime_certs (user_id, label, cert_pem, private_key_enc, issued_at, expires_at, is_default)
		 VALUES ($1, $2, $3, pgp_sym_encrypt($4, current_setting('app.encryption_key')), $5, $6,
		         NOT EXISTS (SELECT 1 FROM user_smime_certs WHERE user_id = $1))
		 ON CONFLICT (user_id, label) DO UPDATE SET
		   cert_pem = EXCLUDED.cert_pem,
		   private_key_enc = EXCLUDED.private_key_enc,
		   issued_at = EXCLUDED.issued_at,
		   expires_at = EXCLUDED.expires_at`,
		claims.UserID, label, string(certBytes), string(keyBytes),
		cert.NotBefore, cert.NotAfter,
	)
	if err != nil {
		h.logger.Error("smime: upload failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to store certificate")
		return
	}

	h.logger.Info("smime: cert uploaded", "user", claims.Email, "label", label)
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "stored", "label": label})
}

// SetDefaultCert makes the chosen cert the user's default S/MIME cert and clears the
// flag on all others. Guards ownership FIRST (same tx) so a foreign or nonexistent id
// returns 404 and never clears the user's existing default (leaving them with none).
// POST /auth/me/smime/certs/{id}/default
func (h *SMIMEHandler) SetDefaultCert(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "bad id")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.logger.Error("smime: set-default tx begin failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "tx failed")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // best-effort rollback

	// Ownership guard: verify the cert exists and belongs to this user BEFORE clearing others.
	var owned bool
	if err := tx.QueryRow(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM user_smime_certs WHERE id = $1 AND user_id = $2)`,
		id, claims.UserID).Scan(&owned); err != nil {
		h.logger.Error("smime: set-default ownership check failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if !owned {
		httputil.WriteError(w, http.StatusNotFound, "certificate not found")
		return
	}

	// Flip is_default: TRUE for the chosen cert, FALSE for all others owned by this user.
	if _, err := tx.Exec(r.Context(),
		`UPDATE user_smime_certs SET is_default = (id = $1) WHERE user_id = $2`,
		id, claims.UserID); err != nil {
		h.logger.Error("smime: set-default update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("smime: set-default commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	h.logger.Info("smime: default cert set", "user", claims.Email, "cert_id", id)
	httputil.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// DeleteCert deletes an S/MIME certificate.
// If the deleted cert was the user's default AND other certs remain, the
// most-recently-created survivor is promoted to is_default=TRUE so the user
// always has a usable default (avoids a misleading "no certificate" error).
// All steps run in a single transaction, ownership-scoped by user_id.
// DELETE /auth/me/smime/certs/{id}
func (h *SMIMEHandler) DeleteCert(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid cert id")
		return
	}

	tx, err := h.pool.Begin(r.Context())
	if err != nil {
		h.logger.Error("smime: delete tx begin failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "tx failed")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // best-effort rollback

	// Delete the cert (ownership-scoped). Capture whether it was the default.
	var wasDefault bool
	if err := tx.QueryRow(r.Context(),
		`DELETE FROM user_smime_certs
		 WHERE id = $1 AND user_id = $2
		 RETURNING is_default`,
		id, claims.UserID).Scan(&wasDefault); err != nil {
		// pgx returns pgx.ErrNoRows when no row matched (wrong id or wrong owner).
		h.logger.Error("smime: delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to delete cert")
		return
	}

	// If the deleted cert was the default, promote the most-recently-created survivor.
	if wasDefault {
		if _, err := tx.Exec(r.Context(),
			`UPDATE user_smime_certs
			 SET is_default = TRUE
			 WHERE user_id = $1
			   AND id = (SELECT id FROM user_smime_certs
			             WHERE user_id = $1
			             ORDER BY created_at DESC
			             LIMIT 1)`,
			claims.UserID); err != nil {
			h.logger.Error("smime: delete survivor promote failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "failed to promote survivor cert")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("smime: delete commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
