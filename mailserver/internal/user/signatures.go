package user

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

// ER5 occ_32e2290b6545ec3b8e1f780b (unbounded-json-request-decoding): the PUT
// body and the persisted signature fields are bounded. Before these caps the
// handler decoded an arbitrarily large JSON body into memory and stored
// arbitrarily large HTML/text per (user, alias) row — memory exhaustion on
// decode and persistent resource exhaustion in user_signatures. The limits
// follow the repo's http.MaxBytesReader precedent (telemetry ingest 64KB,
// admin config writes 1MB) and the practical size of a mail signature.
const (
	// maxSignatureBodyBytes bounds the whole PUT body (both signature fields
	// plus JSON overhead must fit inside it).
	maxSignatureBodyBytes = 128 << 10 // 128 KB
	// maxSignatureHTMLBytes bounds one stored HTML signature.
	maxSignatureHTMLBytes = 64 << 10 // 64 KB
	// maxSignatureTextBytes bounds one stored plain-text signature.
	maxSignatureTextBytes = 8 << 10 // 8 KB
	// maxSignatureAliasEmail bounds alias_email (RFC 5321 maximum forward and
	// reverse path length is 256; 320 covers the full RFC 5322 address form).
	maxSignatureAliasEmail = 320
	// maxSignaturesPerUser bounds how many signature rows ONE user can stack
	// (ER5 occ_9979c4508a62dc7bf33c6857, unbounded-signature-storage): the
	// per-field caps bound one row, but without a row bound an authenticated
	// user could still mint unlimited (user, alias) rows — every List response
	// and every outbound-compose signature lookup scans them. Same admission
	// control as maxRulesPerMailbox (user_rules.go): COUNT-before-insert on the
	// auth-context user, updates of an existing alias never count against it.
	maxSignaturesPerUser = 100
)

// SignatureHandler provides per-alias signature CRUD at /settings/signatures.
type SignatureHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewSignatureHandler creates a SignatureHandler.
func NewSignatureHandler(pool *pgxpool.Pool, logger *slog.Logger) *SignatureHandler {
	return &SignatureHandler{pool: pool, logger: logger}
}

// signatureRow mirrors the user_signatures table for JSON responses.
type signatureRow struct {
	ID            int64     `json:"id"`
	AliasEmail    string    `json:"alias_email"`
	SignatureHTML string    `json:"signature_html"`
	SignatureText string    `json:"signature_text"`
	IsDefault     bool      `json:"is_default"`
	DefaultFor    string    `json:"default_for"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// List returns all signatures for the current user. GET /settings/signatures
func (h *SignatureHandler) List(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rows, err := h.pool.Query(r.Context(),
		`SELECT id, alias_email, signature_html, signature_text, is_default, default_for, created_at, updated_at
		 FROM user_signatures
		 WHERE user_id = $1
		 ORDER BY alias_email`,
		u.UserID,
	)
	if err != nil {
		h.logger.Error("signatures list query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	sigs := make([]signatureRow, 0)
	for rows.Next() {
		var s signatureRow
		if err := rows.Scan(&s.ID, &s.AliasEmail, &s.SignatureHTML, &s.SignatureText,
			&s.IsDefault, &s.DefaultFor, &s.CreatedAt, &s.UpdatedAt); err != nil {
			continue
		}
		sigs = append(sigs, s)
	}

	httputil.WriteJSON(w, http.StatusOK, sigs)
}

// Put creates or updates a signature for a given alias. PUT /settings/signatures
func (h *SignatureHandler) Put(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Bound the decoded body before json.Decode can buffer it (the
	// MaxBytesReader returns an oversized body as a decode error → 400).
	r.Body = http.MaxBytesReader(w, r.Body, maxSignatureBodyBytes)

	var req struct {
		AliasEmail    string `json:"alias_email"`
		SignatureHTML string `json:"signature_html"`
		SignatureText string `json:"signature_text"`
		IsDefault     string `json:"is_default"`
		DefaultFor    string `json:"default_for"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid json")
		return
	}
	// Persisted-field bounds: every stored signature (and its List response)
	// stays inside the advertised caps regardless of what the body carried.
	if req.AliasEmail == "" {
		httputil.WriteError(w, http.StatusBadRequest, "alias_email is required")
		return
	}
	if len(req.AliasEmail) > maxSignatureAliasEmail {
		httputil.WriteError(w, http.StatusBadRequest, "alias_email is too long")
		return
	}
	if len(req.SignatureHTML) > maxSignatureHTMLBytes {
		httputil.WriteError(w, http.StatusBadRequest, "signature_html is too long")
		return
	}
	if len(req.SignatureText) > maxSignatureTextBytes {
		httputil.WriteError(w, http.StatusBadRequest, "signature_text is too long")
		return
	}
	// Per-user row-count admission (occ_9979c4508a62dc7bf33c6857): refuse a
	// NEW alias beyond maxSignaturesPerUser. Counting rows whose alias differs
	// from the one being PUT keeps every update of an existing signature
	// allowed at the cap. The authenticated user comes from the auth context
	// (R2), never from the request.
	var otherRows int
	if err := h.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM user_signatures WHERE user_id = $1 AND alias_email <> $2`,
		u.UserID, req.AliasEmail,
	).Scan(&otherRows); err != nil {
		h.logger.Error("signature count failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if otherRows >= maxSignaturesPerUser {
		httputil.WriteError(w, http.StatusBadRequest, "signature limit reached")
		return
	}

	isDefault := req.IsDefault == "true"

	// default_for (A1, new vs reply default). Default 'none'; reject unknown values
	// so the column CHECK is never the first line of defence.
	defaultFor := req.DefaultFor
	if defaultFor == "" {
		defaultFor = "none"
	}
	switch defaultFor {
	case "new", "reply", "both", "none":
	default:
		httputil.WriteError(w, http.StatusBadRequest, "invalid default_for")
		return
	}

	// The whole mutation runs in one transaction so the is_default clear, the
	// upsert, and the default_for role flip are atomic. Two concurrent PUTs can
	// no longer leave a window with no default (or two signatures holding the same
	// new/reply role) — the role-clearing is delegated to the set_signature_default
	// reducer ("logic where the data is"), which enforces "at most one signature
	// holds each role per user".
	ctx := r.Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.logger.Error("signature tx begin failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after a successful Commit

	// If setting as default, clear any existing is_default for this user first
	// (same transaction — no concurrent window with zero defaults).
	if isDefault {
		if _, err := tx.Exec(ctx,
			`UPDATE user_signatures SET is_default = FALSE WHERE user_id = $1`,
			u.UserID,
		); err != nil {
			h.logger.Error("clear defaults failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "database error")
			return
		}
	}

	// Upsert: insert or update based on (user_id, alias_email) unique constraint.
	// RETURNING id so the default_for role flip can be delegated to the reducer.
	var sigID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO user_signatures (user_id, alias_email, signature_html, signature_text, is_default, default_for)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (user_id, alias_email) DO UPDATE SET
		   signature_html = EXCLUDED.signature_html,
		   signature_text = EXCLUDED.signature_text,
		   is_default     = COALESCE(NULLIF(EXCLUDED.is_default, FALSE), user_signatures.is_default),
		   default_for    = EXCLUDED.default_for,
		   updated_at     = now()
		 RETURNING id`,
		u.UserID, req.AliasEmail, req.SignatureHTML, req.SignatureText, isDefault, defaultFor,
	).Scan(&sigID); err != nil {
		h.logger.Error("signature upsert failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Route the default_for role change through set_signature_default so the
	// atomic role-clearing ("at most one signature per new/reply/both role per
	// user") runs in the reducer. Skip for 'none' — the upsert already wrote it
	// and there is no role to claim/clear.
	if defaultFor != "none" {
		if _, err := tx.Exec(ctx,
			`SELECT set_signature_default($1, $2, $3)`,
			u.UserID, sigID, defaultFor,
		); err != nil {
			h.logger.Error("set_signature_default failed", "error", err)
			// Classify the reducer's BZ business error (forbidden / not-found /
			// conflict) so it surfaces as 403 / 404 / 409 instead of a blanket 500;
			// an unrecognized error keeps the 500 fallback (ClassUnknown → 500).
			httputil.WriteError(w, reducerErrorStatus(err), "database error")
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("signature tx commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Delete removes a signature. DELETE /settings/signatures/{id}
func (h *SignatureHandler) Delete(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid signature id")
		return
	}

	// Delete with ownership check: only delete if user_id matches.
	tag, err := h.pool.Exec(r.Context(),
		`DELETE FROM user_signatures WHERE id = $1 AND user_id = $2`,
		id, u.UserID,
	)
	if err != nil {
		h.logger.Error("signature delete failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "signature not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
