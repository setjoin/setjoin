// branches.go — Go routes for P4 branches + version labels (plan Task 9).
// Thin 1:1 translation over drive_branch_create/_rename/_set_status/_resolve
// and drive_version_label_set/_remove — same genre as handler.go's nodes/
// members routes: one reducer call per route, membership/role checks live in
// the reducer, writeDriveProblem projects the BZ139/140/141/149/150 map.
package drive

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerBranchRoutes registers the branch + version-label routes on h.mux.
// Split out of NewHandler for the same reason registerContentRoutes is.
func (h *Handler) registerBranchRoutes(mux router) {
	mux.HandleFunc("POST /drive/files/{id}/branches", h.createBranch)
	mux.HandleFunc("GET /drive/files/{id}/branches", h.listBranches)
	mux.HandleFunc("PATCH /drive/branches/{id}", h.patchBranch)
	mux.HandleFunc("POST /drive/branches/{id}/resolve", h.resolveBranch)
	mux.HandleFunc("POST /drive/versions/{id}/labels", h.setLabel)
	mux.HandleFunc("DELETE /drive/versions/{id}/labels/{label}", h.removeLabel)
}

// ── branches ─────────────────────────────────────────────────────────────

type createBranchBody struct {
	Name          string `json:"name"`
	FromVersionID int64  `json:"fromVersionId"`
}

func (h *Handler) createBranch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createBranchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ctx := r.Context()
	var id int64
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_branch_create($1, $2, $3, $4)`,
			claims.UserID, nodeID, body.Name, body.FromVersionID).Scan(&id)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"branchId": id})
}

type branchOut struct {
	ID                  int64   `json:"id"`
	Name                string  `json:"name"`
	Status              string  `json:"status"`
	AutoCreated         bool    `json:"autoCreated"`
	HeadVersionID       int64   `json:"headVersionId"`
	ForkedFromVersionID int64   `json:"forkedFromVersionId"`
	CreatedBy           int64   `json:"createdBy"`
	CreatedAt           string  `json:"createdAt"`
	ResolvedBy          *int64  `json:"resolvedBy"`
	ResolvedAt          *string `json:"resolvedAt"`
	FfEligible          bool    `json:"ffEligible"`
}

// branchListSQL computes ffEligible in the read (spec §11.1): a branch can
// fast-forward iff main never moved since its fork point and it is still
// open/review. merged/discarded rows are hidden unless ?all=1 (§5.2 — the
// panel shows live lanes by default, closed history behind a toggle).
const branchListSQL = `
	SELECT b.id, b.name, b.status, b.auto_created, b.head_version_id, b.forked_from_version_id,
	       b.created_by, b.created_at, b.resolved_by, b.resolved_at,
	       (b.forked_from_version_id = f.head_version_id AND b.status IN ('open','review')) AS ff_eligible
	  FROM drive_file_branches b
	  JOIN drive_files f ON f.node_id = b.file_node_id
	 WHERE b.file_node_id = $1
	   AND ($2::boolean OR b.status IN ('open','review'))
	 ORDER BY b.created_at DESC`

func (h *Handler) listBranches(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid file id")
	if !ok {
		return
	}
	all := r.URL.Query().Get("all") == "1"

	ctx := r.Context()
	var out []branchOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var canRead bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM drive_nodes n
			 WHERE n.id = $1
			   AND drive_runtime_has_node_capability($2,n.id,'read_metadata'))`, nodeID, claims.UserID).Scan(&canRead); err != nil {
			return err
		}
		if !canRead {
			return errSpaceNotFound
		}
		rows, err := tx.Query(ctx, branchListSQL, nodeID, all)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b branchOut
			var createdAt time.Time
			var resolvedAt *time.Time
			if err := rows.Scan(&b.ID, &b.Name, &b.Status, &b.AutoCreated, &b.HeadVersionID,
				&b.ForkedFromVersionID, &b.CreatedBy, &createdAt, &b.ResolvedBy, &resolvedAt, &b.FfEligible); err != nil {
				return err
			}
			b.CreatedAt = createdAt.UTC().Format(time.RFC3339)
			if resolvedAt != nil {
				s := resolvedAt.UTC().Format(time.RFC3339)
				b.ResolvedAt = &s
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		if err == errSpaceNotFound {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "file not found"})
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

// patchBranch is field-driven, mirroring patchSpace/patchNode: "name" renames,
// "status" flips open<->review — exactly one per request (merge/discard are
// resolveBranch-only, never a PATCH).
func (h *Handler) patchBranch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	branchID, ok := httputil.ParseIDPath(w, r, "id", "invalid branch id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	_, hasName := fields["name"]
	_, hasStatus := fields["status"]
	if hasName == hasStatus { // neither, or both — exactly one field is valid
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusUnprocessableEntity,
			Type:   "https://setjoin.com/problems/drive/invalid-arguments",
			Detail: "exactly one of name or status is required",
			Code:   "BZ141",
		})
		return
	}

	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if hasName {
			var name string
			if err := json.Unmarshal(fields["name"], &name); err != nil {
				return errInvalidField
			}
			_, err := tx.Exec(ctx, `SELECT drive_branch_rename($1, $2, $3)`, claims.UserID, branchID, name)
			return err
		}
		var status string
		if err := json.Unmarshal(fields["status"], &status); err != nil {
			return errInvalidField
		}
		_, err := tx.Exec(ctx, `SELECT drive_branch_set_status($1, $2, $3)`, claims.UserID, branchID, status)
		return err
	})
	if err != nil {
		if err == errInvalidField {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid patch field"})
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type resolveBranchBody struct {
	Verb    string  `json:"verb"`
	NewName *string `json:"newName"`
}

// resolveBranch is a thin passthrough to drive_branch_resolve — the reducer
// owns every decision (ff/adopt/keep_both/discard); its jsonb result
// ({verb, headVersionId, newNodeId}) rides straight through.
func (h *Handler) resolveBranch(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	branchID, ok := httputil.ParseIDPath(w, r, "id", "invalid branch id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body resolveBranchBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	ctx := r.Context()
	var out json.RawMessage
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_branch_resolve($1, $2, $3, $4)`,
			claims.UserID, branchID, body.Verb, body.NewName).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// ── version labels ───────────────────────────────────────────────────────

type setLabelBody struct {
	Label string `json:"label"`
}

func (h *Handler) setLabel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	versionID, ok := httputil.ParseIDPath(w, r, "id", "invalid version id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body setLabelBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_version_label_set($1, $2, $3)`, claims.UserID, versionID, body.Label)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeLabel's {label} path segment may be arbitrary text (spec §11.1 label
// chips are free-form, up to 60 chars) — r.PathValue returns it already
// percent-decoded by net/http's request-URI parsing, so no extra unescape.
func (h *Handler) removeLabel(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	versionID, ok := httputil.ParseIDPath(w, r, "id", "invalid version id")
	if !ok {
		return
	}
	label := r.PathValue("label")
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT drive_version_label_remove($1, $2, $3)`, claims.UserID, versionID, label)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
