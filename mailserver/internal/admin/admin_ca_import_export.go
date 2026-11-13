// Admin API: CA policy export / import / diff endpoints (CA-1 D7).
//
// Routes (registered in main.go):
//
//	GET  /admin/conditional-access/export           — Export live state as a policy document
//	POST /admin/conditional-access/import?mode=...  — Bulk import (merge|replace|prune)
//	POST /admin/conditional-access/diff             — Structured add/change/remove plan
//
// Export and diff: requireCAPolicyRead. Import: requireCAPolicyWrite.
package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/threat"
)

// exportSchemaVersion is the current schema version for the policy export document.
// Bump here when the schema changes; ca_policy_import BZ088 guards the reader side.
const exportSchemaVersion = 1

// generatedByLabel is the generatedBy field value in export documents.
const generatedByLabel = "setjoin"

// CAImportExportHandler provides export / import / diff endpoints.
type CAImportExportHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewCAImportExportHandler creates a CAImportExportHandler.
func NewCAImportExportHandler(pool *pgxpool.Pool, logger *slog.Logger) *CAImportExportHandler {
	return &CAImportExportHandler{pool: pool, logger: logger}
}

// importDoc is the top-level shape shared by import, diff, and the export response.
// ponytail: no omitempty on arrays — the UI's ALL-CLEAR state relies on
// named_locations/auth_strengths being [] not absent.
type importDoc struct {
	SchemaVersion  int               `json:"schemaVersion"`
	GeneratedBy    string            `json:"generatedBy,omitempty"`
	Policies       []importDocPolicy `json:"policies"`
	NamedLocations []json.RawMessage `json:"named_locations"`
	AuthStrengths  []json.RawMessage `json:"auth_strengths"`
}

// importDocPolicy is one policy item inside importDoc.Policies.
// ponytail: minimal fields — only what ca_policy_import and diff require.
type importDocPolicy struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Priority    *int            `json:"priority,omitempty"`
	ScopeType   string          `json:"scope_type,omitempty"`
	ScopeTarget string          `json:"scope_target,omitempty"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	Actions     json.RawMessage `json:"actions,omitempty"`
}

// Export assembles a policy document from live rows:
// {schemaVersion, generatedBy, policies, named_locations, auth_strengths}.
// Live rows only (deleted_at IS NULL). Gated: requireCAPolicyRead at the route.
func (h *CAImportExportHandler) Export(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	store := threat.NewPolicyStore(h.pool, h.logger)

	// ── Policies ──
	rows, err := h.pool.Query(ctx,
		`SELECT name, description, priority, scope_type, scope_target, conditions, actions
		 FROM conditional_access_policies
		 WHERE deleted_at IS NULL
		 ORDER BY priority ASC`)
	if err != nil {
		h.logger.Error("ca export: query policies failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer rows.Close()

	policies := make([]importDocPolicy, 0)
	for rows.Next() {
		var p importDocPolicy
		var pri int
		var cond, act []byte
		if err := rows.Scan(&p.Name, &p.Description, &pri, &p.ScopeType, &p.ScopeTarget, &cond, &act); err != nil {
			h.logger.Warn("ca export: scan policy failed", "error", err)
			continue
		}
		p.Priority = &pri
		p.Conditions = json.RawMessage(cond)
		p.Actions = json.RawMessage(act)
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		h.logger.Error("ca export: rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	// ── Named locations ──
	locs, err := store.LoadNamedLocations(ctx)
	if err != nil {
		h.logger.Error("ca export: load named locations failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	locJSON := make([]json.RawMessage, 0, len(locs))
	for _, l := range locs {
		b, _ := json.Marshal(l)
		locJSON = append(locJSON, b)
	}

	// ── Auth strengths ──
	strengths, err := store.LoadAuthStrengths(ctx)
	if err != nil {
		h.logger.Error("ca export: load auth strengths failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	strJSON := make([]json.RawMessage, 0, len(strengths))
	for _, s := range strengths {
		b, _ := json.Marshal(s)
		strJSON = append(strJSON, b)
	}

	doc := importDoc{
		SchemaVersion:  exportSchemaVersion,
		GeneratedBy:    generatedByLabel,
		Policies:       policies,
		NamedLocations: locJSON,
		AuthStrengths:  strJSON,
	}
	httputil.WriteJSON(w, http.StatusOK, doc)
}

// Import calls ca_policy_import(p_doc, p_admin_id, p_mode) and returns the summary.
// BZ088 (bad schemaVersion) → 422. BZ090 (invalid shape) → 422. BZ091 (unknown slug) → 404.
// BZ092 (invalid mode) → 422. Gated: requireCAPolicyWrite at the route.
func (h *CAImportExportHandler) Import(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<20) // 4 MB cap for large policy docs
	var doc json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "merge" // ponytail: safe default; prune requires explicit opt-in
	}

	// ca_policy_import owns all validation (schemaVersion, shape, slug resolution),
	// audit, and ca_notify_policy_change. We just map BZ codes → HTTP status.
	var out []byte
	err := h.pool.QueryRow(ctx,
		`SELECT ca_policy_import($1, $2, $3)`,
		[]byte(doc), claims.UserID, mode,
	).Scan(&out)
	if err != nil {
		h.logger.Error("ca_policy_import failed", "error", err, "mode", mode)
		httputil.WriteError(w, caErrorStatus(err), caErrorDetail(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// Diff computes the structured add/change/remove plan for a policy document
// against live state, server-side, without mutating the DB.
//
// Returns: {added:[{name}], changed:[{name}], removed:[{name}]}.
// "added" = name in doc but not in live. "removed" = live name not in doc.
// "changed" = name present in both (conditions or actions differ from live).
//
// Change detection normalizes both sides via json.Compact to avoid spurious
// diffs from whitespace/key-ordering differences between Postgres and Go JSON.
//
// Gated: requireCAPolicyRead at the route.
func (h *CAImportExportHandler) Diff(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var doc importDoc
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Load live policy names + conditions+actions bytes for change detection.
	// ponytail: diff is advisory-only; semantic equality is what matters.
	liveRows, err := h.pool.Query(ctx,
		`SELECT name, conditions, actions
		 FROM conditional_access_policies
		 WHERE deleted_at IS NULL`)
	if err != nil {
		h.logger.Error("ca diff: query policies failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	defer liveRows.Close()

	live := make(map[string]string) // name → compact(cond)+compact(act)
	for liveRows.Next() {
		var name string
		var cond, act []byte
		if err := liveRows.Scan(&name, &cond, &act); err != nil {
			continue
		}
		live[name] = compactJSON(cond) + compactJSON(act)
	}
	if err := liveRows.Err(); err != nil {
		h.logger.Error("ca diff: rows error", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	type nameOnly struct {
		Name string `json:"name"`
	}
	added := make([]nameOnly, 0)
	changed := make([]nameOnly, 0)
	inDoc := make(map[string]bool, len(doc.Policies))

	for _, p := range doc.Policies {
		inDoc[p.Name] = true
		liveFP, exists := live[p.Name]
		if !exists {
			added = append(added, nameOnly{p.Name})
		} else {
			// Normalize via json.Compact so whitespace/key-order don't produce false diffs.
			cond := p.Conditions
			if cond == nil {
				cond = json.RawMessage("{}")
			}
			act := p.Actions
			if act == nil {
				act = json.RawMessage("{}")
			}
			incomingFP := compactJSON(cond) + compactJSON(act)
			if incomingFP != liveFP {
				changed = append(changed, nameOnly{p.Name})
			}
		}
	}

	removed := make([]nameOnly, 0)
	for name := range live {
		if !inDoc[name] {
			removed = append(removed, nameOnly{name})
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"added":   added,
		"changed": changed,
		"removed": removed,
	})
}

// compactJSON returns the compact (whitespace-stripped) form of a JSON byte slice.
// Returns "{}" for nil/empty input. Used for change-detection fingerprints.
func compactJSON(b []byte) string {
	if len(b) == 0 {
		return "{}"
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return string(b) // fallback: use as-is; diff may over-report but never under-report
	}
	return buf.String()
}

// ca_policy_import BZ codes route through caErrorStatus → reducererr (c6):
// BZ088/090/092 → 422 (ClassUnprocessable — valid JSON but semantically bad
// doc, ≠ 400 malformed JSON), BZ091 → 404 (unknown slug). The per-code table
// the former caImportErrorStatus held lives in reducererr.codeClass now.
