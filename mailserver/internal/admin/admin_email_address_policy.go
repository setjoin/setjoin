// Admin REST surface for Email Address Policy CRUD + apply + preview.
//
// Routes (registered in main.go):
//   GET    /admin/email-address-policies                    — List all policies (priority-ordered)
//   POST   /admin/email-address-policies                    — Create a policy
//   PUT    /admin/email-address-policies/{id}               — Update a policy
//   DELETE /admin/email-address-policies/{id}               — Delete a policy
//   POST   /admin/email-address-policies/reorder            — Reorder (accepts {"order":[ids]})
//   POST   /admin/email-address-policies/{id}/preview       — Preview rendered addresses
//   POST   /admin/email-address-policies/match-count        — Count matching recipients
//   POST   /admin/email-address-policies/apply              — Enqueue bulk-apply job (202)
//   GET    /admin/email-address-policies/apply/{jobId}      — Poll apply job status

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/httputil"
)

// EmailAddressPolicyHandler provides CRUD + apply + preview for email address policies.
type EmailAddressPolicyHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewEmailAddressPolicyHandler creates an email address policy admin handler.
func NewEmailAddressPolicyHandler(pool *pgxpool.Pool, logger *slog.Logger) *EmailAddressPolicyHandler {
	return &EmailAddressPolicyHandler{pool: pool, logger: logger}
}

// eapPolicyResponse is the JSON shape returned by the API.
type eapPolicyResponse struct {
	ID                        int64    `json:"id"`
	Priority                  int      `json:"priority"`
	Name                      string   `json:"name"`
	Enabled                   bool     `json:"enabled"`
	OverwriteDirectoryAddress bool     `json:"overwriteDirectoryAddress"`
	CondDepartment            []string `json:"condDepartment,omitempty"`
	CondDomainIds             []int64  `json:"condDomainIds,omitempty"`
	CondMailboxType           []string `json:"condMailboxType,omitempty"`
	CondAdOu                  []string `json:"condAdOu,omitempty"`
	PrimaryTemplate           string   `json:"primaryTemplate"`
	AdditionalTemplates       []string `json:"additionalTemplates,omitempty"`
	DuplicateResolution       string   `json:"duplicateResolution"`
	CreatedAt                 string   `json:"createdAt"`
	UpdatedAt                 string   `json:"updatedAt"`
}

// eapPolicyCreate is the request body for creating a policy.
type eapPolicyCreate struct {
	Priority                  *int     `json:"priority,omitempty"`
	Name                      string   `json:"name"`
	Enabled                   *bool    `json:"enabled,omitempty"`
	OverwriteDirectoryAddress *bool    `json:"overwriteDirectoryAddress,omitempty"`
	CondDepartment            []string `json:"condDepartment,omitempty"`
	CondDomainIds             []int64  `json:"condDomainIds,omitempty"`
	CondMailboxType           []string `json:"condMailboxType,omitempty"`
	CondAdOu                  []string `json:"condAdOu,omitempty"`
	PrimaryTemplate           string   `json:"primaryTemplate"`
	AdditionalTemplates       []string `json:"additionalTemplates,omitempty"`
	DuplicateResolution       *string  `json:"duplicateResolution,omitempty"`
}

// ── Template validator ────────────────────────────────────────────────────────

var eapVar = regexp.MustCompile(`\{([a-z_]+)\}`)
var eapValidVars = map[string]bool{
	"given_name":    true,
	"surname":       true,
	"first_initial": true,
	"user_name":     true,
	"department":    true,
	"domain":        true,
}

// validateEAPTemplate checks that t contains '@' and at least one known {var}.
func validateEAPTemplate(t string) error {
	if !strings.Contains(t, "@") {
		return fmt.Errorf("template must contain @")
	}
	m := eapVar.FindAllStringSubmatch(t, -1)
	if len(m) == 0 {
		return fmt.Errorf("template must contain at least one {var}")
	}
	for _, g := range m {
		if !eapValidVars[g[1]] {
			return fmt.Errorf("unknown variable {%s}", g[1])
		}
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// nilIfEmpty returns nil when s is empty, else &s.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nullableStrings returns nil when the slice is empty (maps to SQL NULL).
func nullableStrings(ss []string) interface{} {
	if len(ss) == 0 {
		return nil
	}
	return ss
}

// nullableInt64s returns nil when the slice is empty (maps to SQL NULL).
func nullableInt64s(ii []int64) interface{} {
	if len(ii) == 0 {
		return nil
	}
	return ii
}

// scanEAPRow scans a single policy row into eapPolicyResponse.
// Columns: id, priority, name, enabled, overwrite_directory_address,
//
//	cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou,
//	primary_template, additional_templates, duplicate_resolution,
//	created_at, updated_at
func scanEAPRow(rows interface {
	Scan(dest ...any) error
}) (eapPolicyResponse, error) {
	var p eapPolicyResponse
	err := rows.Scan(
		&p.ID, &p.Priority, &p.Name, &p.Enabled, &p.OverwriteDirectoryAddress,
		&p.CondDepartment, &p.CondDomainIds, &p.CondMailboxType, &p.CondAdOu,
		&p.PrimaryTemplate, &p.AdditionalTemplates, &p.DuplicateResolution,
		&p.CreatedAt, &p.UpdatedAt,
	)
	return p, err
}

const eapSelectCols = `
	id, priority, name, enabled, overwrite_directory_address,
	cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou,
	primary_template, additional_templates, duplicate_resolution,
	created_at::text, updated_at::text`

// ── Handlers ──────────────────────────────────────────────────────────────────

// List returns all policies ordered by priority.
func (h *EmailAddressPolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT`+eapSelectCols+`
		 FROM email_address_policies
		 ORDER BY priority ASC`)
	if err != nil {
		h.logger.Error("eap list failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	out := []eapPolicyResponse{}
	for rows.Next() {
		p, err := scanEAPRow(rows)
		if err != nil {
			h.logger.Warn("eap list scan failed", "error", err)
			continue
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("eap list rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Create inserts a new email address policy.
func (h *EmailAddressPolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req eapPolicyCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Name == "" {
		httputil.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := validateEAPTemplate(req.PrimaryTemplate); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "primaryTemplate: "+err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	overwrite := false
	if req.OverwriteDirectoryAddress != nil {
		overwrite = *req.OverwriteDirectoryAddress
	}
	dupres := "numeric_suffix"
	if req.DuplicateResolution != nil {
		dupres = *req.DuplicateResolution
	}

	priority := 0
	if req.Priority != nil {
		priority = *req.Priority
	} else {
		if err := h.pool.QueryRow(ctx,
			`SELECT COALESCE(MAX(priority), 0) + 10 FROM email_address_policies`,
		).Scan(&priority); err != nil {
			h.logger.Error("eap auto-priority failed", "error", err)
			httputil.WriteError(w, http.StatusInternalServerError, "failed to assign priority")
			return
		}
	}

	row := h.pool.QueryRow(ctx,
		`INSERT INTO email_address_policies
		   (priority, name, enabled, overwrite_directory_address,
		    cond_department, cond_domain_ids, cond_mailbox_type, cond_ad_ou,
		    primary_template, additional_templates, duplicate_resolution)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 RETURNING`+eapSelectCols,
		priority, req.Name, enabled, overwrite,
		nullableStrings(req.CondDepartment),
		nullableInt64s(req.CondDomainIds),
		nullableStrings(req.CondMailboxType),
		nullableStrings(req.CondAdOu),
		req.PrimaryTemplate,
		nullableStrings(req.AdditionalTemplates),
		dupres,
	)
	p, err := scanEAPRow(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteError(w, http.StatusConflict, "a policy with this priority already exists (unique enabled-priority)")
			return
		}
		h.logger.Error("eap create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, p)
}

// Update patches an existing email address policy.
func (h *EmailAddressPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	idStr := r.PathValue("id")
	policyID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var req eapPolicyCreate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.PrimaryTemplate != "" {
		if err := validateEAPTemplate(req.PrimaryTemplate); err != nil {
			httputil.WriteError(w, http.StatusBadRequest, "primaryTemplate: "+err.Error())
			return
		}
	}

	p, err := scanEAPRow(h.pool.QueryRow(ctx,
		`UPDATE email_address_policies SET
		    priority                    = COALESCE($2, priority),
		    name                        = COALESCE($3, name),
		    enabled                     = COALESCE($4, enabled),
		    overwrite_directory_address = COALESCE($5, overwrite_directory_address),
		    cond_department             = COALESCE($6, cond_department),
		    cond_domain_ids             = COALESCE($7, cond_domain_ids),
		    cond_mailbox_type           = COALESCE($8, cond_mailbox_type),
		    cond_ad_ou                  = COALESCE($9, cond_ad_ou),
		    primary_template            = COALESCE($10, primary_template),
		    additional_templates        = COALESCE($11, additional_templates),
		    duplicate_resolution        = COALESCE($12, duplicate_resolution),
		    updated_at                  = now()
		 WHERE id = $1
		 RETURNING`+eapSelectCols,
		policyID,
		req.Priority, nilIfEmpty(req.Name), req.Enabled, req.OverwriteDirectoryAddress,
		nullableStrings(req.CondDepartment),
		nullableInt64s(req.CondDomainIds),
		nullableStrings(req.CondMailboxType),
		nullableStrings(req.CondAdOu),
		nilIfEmpty(req.PrimaryTemplate),
		nullableStrings(req.AdditionalTemplates),
		req.DuplicateResolution,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httputil.WriteError(w, http.StatusConflict, "priority already in use")
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("eap update failed", "error", err, "id", policyID)
		httputil.WriteError(w, http.StatusInternalServerError, "update failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, p)
}

// Delete removes an email address policy.
func (h *EmailAddressPolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	idStr := r.PathValue("id")
	policyID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	tag, err := h.pool.Exec(ctx,
		`DELETE FROM email_address_policies WHERE id = $1`, policyID)
	if err != nil {
		h.logger.Error("eap delete failed", "error", err, "id", policyID)
		httputil.WriteError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		httputil.WriteError(w, http.StatusNotFound, "policy not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Reorder accepts {"order":[ids int64]} and sets stepped priorities in a tx.
func (h *EmailAddressPolicyHandler) Reorder(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var body struct {
		Order []int64 `json:"order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON: expected {\"order\":[ids]}")
		return
	}
	if len(body.Order) == 0 {
		httputil.WriteError(w, http.StatusBadRequest, "at least one policy ID required")
		return
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		h.logger.Error("eap reorder tx failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "transaction error")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	for i, id := range body.Order {
		priority := (i + 1) * 10
		_, err := tx.Exec(ctx,
			`UPDATE email_address_policies SET priority = $1, updated_at = now() WHERE id = $2`,
			priority, id)
		if err != nil {
			h.logger.Error("eap reorder update failed", "error", err, "id", id)
			httputil.WriteError(w, http.StatusInternalServerError, "reorder update failed")
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("eap reorder commit failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "commit failed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Preview calls email_address_policy_render and returns the jsonb result.
func (h *EmailAddressPolicyHandler) Preview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		PolicyID  int64 `json:"policyId"`
		UserID    int64 `json:"userId"`
		MailboxID int64 `json:"mailboxId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var result json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT email_address_policy_render($1, $2, $3)`,
		req.PolicyID, req.UserID, req.MailboxID,
	).Scan(&result)
	if err != nil {
		h.logger.Error("eap preview failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "preview failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, result)
}

// MatchCount counts recipients matching the given conditions.
func (h *EmailAddressPolicyHandler) MatchCount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		CondDepartment  []string `json:"condDepartment"`
		CondDomainIds   []int64  `json:"condDomainIds"`
		CondMailboxType []string `json:"condMailboxType"`
		CondAdOu        []string `json:"condAdOu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var count int
	err := h.pool.QueryRow(ctx,
		`SELECT email_address_policy_match_count($1, $2, $3, $4)`,
		nullableStrings(req.CondDepartment),
		nullableInt64s(req.CondDomainIds),
		nullableStrings(req.CondMailboxType),
		nullableStrings(req.CondAdOu),
	).Scan(&count)
	if err != nil {
		h.logger.Error("eap match-count failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "match-count failed")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]int{"count": count})
}

// Apply enqueues a bulk-apply job and returns 202 + {jobId}.
func (h *EmailAddressPolicyHandler) Apply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		PolicyID *int64 `json:"policyId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	var jobID int64
	err := h.pool.QueryRow(ctx,
		`INSERT INTO eap_apply_jobs (policy_id, status) VALUES ($1, 'queued') RETURNING id`,
		req.PolicyID,
	).Scan(&jobID)
	if err != nil {
		h.logger.Error("eap apply enqueue failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "failed to enqueue apply job")
		return
	}

	httputil.WriteJSON(w, http.StatusAccepted, map[string]int64{"jobId": jobID})
}

// ApplyStatus polls the status of a bulk-apply job.
func (h *EmailAddressPolicyHandler) ApplyStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	jobIDStr := r.PathValue("jobId")
	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	var status string
	var applied int
	var total *int
	var jobErr *string
	err = h.pool.QueryRow(ctx,
		`SELECT status, applied, total, error FROM eap_apply_jobs WHERE id = $1`, jobID,
	).Scan(&status, &applied, &total, &jobErr)
	if err != nil {
		httputil.WriteError(w, http.StatusNotFound, "job not found")
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status":  status,
		"applied": applied,
		"total":   total,
		"error":   jobErr,
	})
}
