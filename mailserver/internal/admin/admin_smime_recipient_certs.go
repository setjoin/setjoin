package admin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/httputil"
)

// RecipientCertHandler serves the end-user "Contacts' certs" REST surface.
// Endpoints:
//
//	GET    /auth/me/smime/recipient-certs
//	POST   /auth/me/smime/recipient-certs   (multipart: cert PEM, label optional)
//	DELETE /auth/me/smime/recipient-certs/{id}
type RecipientCertHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewRecipientCertHandler creates a new recipient-cert handler.
func NewRecipientCertHandler(pool *pgxpool.Pool, logger *slog.Logger) *RecipientCertHandler {
	return &RecipientCertHandler{pool: pool, logger: logger}
}

// RecipientCertEntry is the JSON shape returned for each row.
type RecipientCertEntry struct {
	ID               int64  `json:"id"`
	Email            string `json:"email"`
	Label            string `json:"label,omitempty"`
	Source           string `json:"source"` // "harvested" | "imported"
	NotBefore        string `json:"notBefore,omitempty"`
	NotAfter         string `json:"notAfter,omitempty"`
	Fingerprint      string `json:"fingerprint"`
	IsEncryptCapable bool   `json:"isEncryptCapable"`
}

// ListRecipientCerts returns the authenticated user's saved recipient certificates.
// GET /auth/me/smime/recipient-certs
func (h *RecipientCertHandler) ListRecipientCerts(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, email, COALESCE(label,''), source, not_before, not_after, fingerprint, cert_pem
		   FROM recipient_smime_certs
		  WHERE owner_user_id = $1
		  ORDER BY last_seen DESC`,
		claims.UserID,
	)
	if err != nil {
		h.logger.Error("recipient-certs: list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	var certs []RecipientCertEntry
	for rows.Next() {
		var e RecipientCertEntry
		var certPEM string
		var notBefore, notAfter *time.Time
		if err := rows.Scan(&e.ID, &e.Email, &e.Label, &e.Source, &notBefore, &notAfter, &e.Fingerprint, &certPEM); err != nil {
			continue
		}
		if notBefore != nil && !notBefore.IsZero() {
			e.NotBefore = notBefore.Format("2006-01-02T15:04:05Z")
		}
		if notAfter != nil && !notAfter.IsZero() {
			e.NotAfter = notAfter.Format("2006-01-02T15:04:05Z")
		}
		// Populate isEncryptCapable from the parsed cert (defense-in-depth: use parsed, not stored col).
		if certPEM != "" {
			cert, parseErr := smime.ParseCert([]byte(certPEM))
			if parseErr == nil {
				e.IsEncryptCapable = smime.IsEncryptionCapable(cert)
			}
		}
		// cert_pem is NOT included in the JSON response.
		certs = append(certs, e)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"certs": certs})
}

// ImportRecipientCert imports a PEM-encoded recipient certificate (no private key).
// POST /auth/me/smime/recipient-certs
func (h *RecipientCertHandler) ImportRecipientCert(w http.ResponseWriter, r *http.Request) {
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2<<20) // 2 MB: cert only, no key
	//nolint:gosec // G120: bounded by MaxBytesReader (2 MB) above
	if err := r.ParseMultipartForm(2 << 20); err != nil {
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

	// Parse and validate the certificate.
	cert, err := smime.ParseCert(certBytes)
	if err != nil {
		h.logger.Warn("recipient-certs: invalid certificate", "error", err)
		httputil.WriteError(w, http.StatusBadRequest, "Invalid certificate format. Ensure it is PEM-encoded.")
		return
	}

	// Expiry check (authoritative: use parsed cert, not stored column).
	if !cert.NotAfter.IsZero() && cert.NotAfter.Before(time.Now()) {
		httputil.WriteError(w, http.StatusBadRequest, "Certificate is expired.")
		return
	}

	// Extract email from SAN (rfc822Name) or EmailAddresses field.
	email := certFirstEmail(cert)
	if email == "" {
		httputil.WriteError(w, http.StatusBadRequest, "Certificate has no email address in subject-alternative-name.")
		return
	}

	// Encryption-capable check.
	if !smime.IsEncryptionCapable(cert) {
		httputil.WriteError(w, http.StatusBadRequest, "Certificate is not encryption-capable (signing-only or EC key).")
		return
	}

	// Compute fingerprint: hex(sha256(DER bytes)).
	sum := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(sum[:])

	label := strings.TrimSpace(r.FormValue("label"))

	// Upsert: dedup by (owner_user_id, email, fingerprint).
	// On conflict: bump last_seen, force source='imported', keep existing label if new label is blank.
	_, err = h.pool.Exec(r.Context(),
		`INSERT INTO recipient_smime_certs
		   (owner_user_id, email, cert_pem, fingerprint, not_before, not_after, source, label, first_seen, last_seen)
		 VALUES ($1, $2, $3, $4, $5, $6, 'imported', $7, now(), now())
		 ON CONFLICT ON CONSTRAINT recipient_smime_certs_dedup_key
		 DO UPDATE SET
		   last_seen = now(),
		   source    = 'imported',
		   label     = COALESCE(NULLIF($7, ''), recipient_smime_certs.label)`,
		claims.UserID, email, string(certBytes), fingerprint,
		cert.NotBefore, cert.NotAfter,
		label,
	)
	if err != nil {
		h.logger.Error("recipient-certs: upsert failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to store certificate")
		return
	}

	h.logger.Info("recipient-certs: imported", "user", claims.Email, "email", email)
	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "stored", "email": email})
}

// DeleteRecipientCert removes one of the caller's recipient certificates.
// DELETE /auth/me/smime/recipient-certs/{id}
func (h *RecipientCertHandler) DeleteRecipientCert(w http.ResponseWriter, r *http.Request) {
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
		h.logger.Error("recipient-certs: delete tx begin failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "tx failed")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck // best-effort rollback

	var deleted int64
	if err := tx.QueryRow(r.Context(),
		`DELETE FROM recipient_smime_certs
		  WHERE id = $1 AND owner_user_id = $2
		  RETURNING id`,
		id, claims.UserID).Scan(&deleted); err != nil {
		if err == pgx.ErrNoRows {
			httputil.WriteError(w, http.StatusNotFound, "certificate not found")
			return
		}
		h.logger.Error("recipient-certs: delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to delete certificate")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("recipient-certs: delete commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// certFirstEmail returns the first email address from a certificate's
// SAN rfc822Name fields (preferred) or EmailAddresses (legacy), lower-cased and trimmed.
// Returns "" when the cert has no email addresses.
func certFirstEmail(cert *x509.Certificate) string {
	// SAN rfc822Name entries are in cert.EmailAddresses (populated by Go's x509 parser
	// from the SubjectAltName extension for rfc822Name entries).
	for _, e := range cert.EmailAddresses {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			return e
		}
	}
	return ""
}
