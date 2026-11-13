package admin

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/handlerutil"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/validate"
)

// DomainsHandler provides admin CRUD for email domains.
type DomainsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDomainsHandler creates a domains admin handler.
func NewDomainsHandler(pool *pgxpool.Pool, logger *slog.Logger) *DomainsHandler {
	return &DomainsHandler{pool: pool, logger: logger}
}

type domainResponse struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	IsPrimary         bool    `json:"isPrimary"`
	IsLocal           bool    `json:"isLocal"`
	CatchAllMailboxID *int64  `json:"catchAllMailboxId,omitempty"`
	DKIMSelector      string  `json:"dkimSelector,omitempty"`
	DKIMKeyExpiresAt  *string `json:"dkimKeyExpiresAt,omitempty"`
	SPFRecord         string  `json:"spfRecord,omitempty"`
	DMARCPolicy       string  `json:"dmarcPolicy"`
	DMARCRUA          string  `json:"dmarcRua,omitempty"`
	DMARCRUF          string  `json:"dmarcRuf,omitempty"`
	MTASTSPolicy      string  `json:"mtaStsPolicy"`
	MaxMessageBytes   int64   `json:"maxMessageBytes"`
	QuotaBytes        *int64  `json:"quotaBytes,omitempty"`
	CreatedAt         string  `json:"createdAt"`
}

// List returns all domains (scoped to the admin's domain if applicable).
func (h *DomainsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domainScope := middleware.DomainScopeFromContext(ctx)
	var rows pgx.Rows
	var err error
	if domainScope > 0 {
		rows, err = h.pool.Query(ctx,
			`SELECT id, name, is_primary, is_local, catch_all_mailbox_id,
			        dkim_selector, dkim_key_expires_at::TEXT, spf_record,
			        dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy,
			        max_message_bytes, quota_bytes, created_at::TEXT
			 FROM domains WHERE id = $1
			 ORDER BY is_primary DESC, name ASC`, domainScope)
	} else {
		rows, err = h.pool.Query(ctx,
			`SELECT id, name, is_primary, is_local, catch_all_mailbox_id,
			        dkim_selector, dkim_key_expires_at::TEXT, spf_record,
			        dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy,
			        max_message_bytes, quota_bytes, created_at::TEXT
			 FROM domains ORDER BY is_primary DESC, name ASC`)
	}
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "domains list failed", err)
		return
	}
	defer rows.Close()

	out := make([]domainResponse, 0)
	for rows.Next() {
		var d domainResponse
		var catchAll *int64
		var dkimExpires *string
		var dkimSelector, spfRecord, dmarcRua, dmarcRuf *string
		if err := rows.Scan(&d.ID, &d.Name, &d.IsPrimary, &d.IsLocal, &catchAll,
			&dkimSelector, &dkimExpires, &spfRecord,
			&d.DMARCPolicy, &dmarcRua, &dmarcRuf, &d.MTASTSPolicy,
			&d.MaxMessageBytes, &d.QuotaBytes, &d.CreatedAt); err != nil {
			continue
		}
		d.CatchAllMailboxID = catchAll
		if dkimSelector != nil {
			d.DKIMSelector = *dkimSelector
		}
		d.DKIMKeyExpiresAt = dkimExpires
		if spfRecord != nil {
			d.SPFRecord = *spfRecord
		}
		if dmarcRua != nil {
			d.DMARCRUA = *dmarcRua
		}
		if dmarcRuf != nil {
			d.DMARCRUF = *dmarcRuf
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "domains list rows error", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Get returns a single domain (scoped).
func (h *DomainsHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid domain id"})
		return
	}

	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 && id != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "access denied: domain not in scope"})
		return
	}

	var d domainResponse
	var catchAll *int64
	var dkimExpires *string
	err = h.pool.QueryRow(ctx,
		`SELECT id, name, is_primary, is_local, catch_all_mailbox_id,
		        dkim_selector, dkim_key_expires_at::TEXT, spf_record,
		        dmarc_policy, dmarc_rua, dmarc_ruf, mta_sts_policy,
		        max_message_bytes, quota_bytes, created_at::TEXT
		 FROM domains WHERE id = $1`, id,
	).Scan(&d.ID, &d.Name, &d.IsPrimary, &d.IsLocal, &catchAll,
		&d.DKIMSelector, &dkimExpires, &d.SPFRecord,
		&d.DMARCPolicy, &d.DMARCRUA, &d.DMARCRUF, &d.MTASTSPolicy,
		&d.MaxMessageBytes, &d.QuotaBytes, &d.CreatedAt)
	if err != nil {
		if isPGNoRows(err) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "domain not found"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "domain get failed", err)
		return
	}
	d.CatchAllMailboxID = catchAll
	d.DKIMKeyExpiresAt = dkimExpires

	httputil.WriteJSON(w, http.StatusOK, d)
}

// Create adds a new domain.  Scoped admins cannot create domains (they
// are limited to their assigned domain).
func (h *DomainsHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "scoped admins cannot create domains"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		Name            string `json:"name"`
		IsLocal         bool   `json:"isLocal"`
		IsPrimary       bool   `json:"isPrimary"`
		DMARCPolicy     string `json:"dmarcPolicy"`
		MTASTSPolicy    string `json:"mtaStsPolicy"`
		MaxMessageBytes int64  `json:"maxMessageBytes"`
		QuotaBytes      *int64 `json:"quotaBytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "domain name is required"})
		return
	}
	// Canonicalize BEFORE validating so the validated value is byte-identical to
	// the persisted one: domains.name is DNS case-insensitive (comparison paths
	// fold with lower(name)), so the canonical form is trimmed + lowercased. The
	// prior shape validated ValidateDomain's trimmed copy but persisted the raw
	// request string, storing whitespace-padded names the validator never saw.
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if err := validate.ValidateDomain(req.Name); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	if req.DMARCPolicy == "" {
		req.DMARCPolicy = "none"
	}
	if req.MTASTSPolicy == "" {
		req.MTASTSPolicy = "none"
	}
	if req.MaxMessageBytes <= 0 {
		req.MaxMessageBytes = 52428800 // 50 MB default
	}

	var id int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local, is_primary, dmarc_policy, mta_sts_policy, max_message_bytes, quota_bytes)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id`,
		req.Name, req.IsLocal, req.IsPrimary, req.DMARCPolicy, req.MTASTSPolicy, req.MaxMessageBytes, req.QuotaBytes,
	).Scan(&id)
	if err != nil {
		h.logger.Error("domain create failed", "error", err)
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusConflict, Detail: "domain already exists"})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
		}
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// Update patches a domain (scoped).
func (h *DomainsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid domain id"})
		return
	}

	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 && id != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "access denied: domain not in scope"})
		return
	}

	var req struct {
		Name              *string `json:"name,omitempty"`
		IsLocal           *bool   `json:"isLocal,omitempty"`
		IsPrimary         *bool   `json:"isPrimary,omitempty"`
		CatchAllMailboxID *int64  `json:"catchAllMailboxId,omitempty"`
		DMARCPolicy       *string `json:"dmarcPolicy,omitempty"`
		MTASTSPolicy      *string `json:"mtaStsPolicy,omitempty"`
		MaxMessageBytes   *int64  `json:"maxMessageBytes,omitempty"`
		QuotaBytes        *int64  `json:"quotaBytes,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	// Canonical + validated name: trim + lowercase (DNS case-insensitive, match
	// paths use lower(name)), then the same RFC 1035 gate Create applies — the
	// Update path previously wrote req.Name through with no validation at all.
	if req.Name != nil {
		name := strings.ToLower(strings.TrimSpace(*req.Name))
		if err := validate.ValidateDomain(name); err != nil {
			if ve, ok := err.(*validate.ValidationError); ok {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
			} else {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
			}
			return
		}
		req.Name = &name
	}

	b := &handlerutil.UpdateBuilder{}
	b.SetStr("name", req.Name)
	b.SetBool("is_local", req.IsLocal)
	b.SetBool("is_primary", req.IsPrimary)
	b.SetInt("catch_all_mailbox_id", req.CatchAllMailboxID)
	b.SetStr("dmarc_policy", req.DMARCPolicy)
	b.SetStr("mta_sts_policy", req.MTASTSPolicy)
	b.SetInt("max_message_bytes", req.MaxMessageBytes)
	b.SetInt("quota_bytes", req.QuotaBytes)
	tag, err := b.BuildAndExec(ctx, h.pool, "domains", "id", id, true, "")
	if err != nil {
		if errors.Is(err, handlerutil.ErrNoFields) {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "no fields to update"})
			return
		}
		httputil.WriteDBErr(w, r, h.logger, "domain update failed", err)
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "domain not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a domain (scoped).
func (h *DomainsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid domain id"})
		return
	}

	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 && id != domainScope {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "access denied: domain not in scope"})
		return
	}

	_, err = h.pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "domain delete failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
