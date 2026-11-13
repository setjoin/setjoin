package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/handlerutil"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/validate"
)

// DepartmentsHandler provides CRUD for department hierarchy.
type DepartmentsHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDepartmentsHandler creates a departments handler.
func NewDepartmentsHandler(pool *pgxpool.Pool, logger *slog.Logger) *DepartmentsHandler {
	return &DepartmentsHandler{pool: pool, logger: logger}
}

// Department represents a department node.
type Department struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ParentID  *int64 `json:"parentId,omitempty"`
	Path      string `json:"path"`
	LDAPOU    string `json:"ldapOu"`
	SortOrder int    `json:"sortOrder"`
	UserCount int    `json:"userCount"`
}

// TreeNode wraps a department for tree rendering.
type TreeNode struct {
	Department
	Children []TreeNode `json:"children"`
}

// List returns all departments as a flat list.
func (h *DepartmentsHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT d.id, d.name, d.parent_id, d.path, d.ldap_ou, d.sort_order,
		       (SELECT COUNT(*) FROM users WHERE department_id = d.id)
		FROM departments d
		ORDER BY d.path
	`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "departments list failed", err)
		return
	}
	defer rows.Close()

	out := []Department{}
	for rows.Next() {
		var d Department
		var parentID *int64
		if err := rows.Scan(&d.ID, &d.Name, &parentID, &d.Path, &d.LDAPOU, &d.SortOrder, &d.UserCount); err != nil {
			continue
		}
		d.ParentID = parentID
		out = append(out, d)
	}

	httputil.WriteJSON(w, http.StatusOK, out)
}

// Tree returns departments nested by parent_id.
func (h *DepartmentsHandler) Tree(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.pool.Query(ctx, `
		SELECT d.id, d.name, d.parent_id, d.path, d.ldap_ou, d.sort_order,
		       (SELECT COUNT(*) FROM users WHERE department_id = d.id)
		FROM departments d
		ORDER BY d.sort_order, d.name
	`)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "departments tree failed", err)
		return
	}
	defer rows.Close()

	byID := map[int64]*TreeNode{}
	roots := []*TreeNode{}
	for rows.Next() {
		var d Department
		var parentID *int64
		if err := rows.Scan(&d.ID, &d.Name, &parentID, &d.Path, &d.LDAPOU, &d.SortOrder, &d.UserCount); err != nil {
			continue
		}
		d.ParentID = parentID
		node := &TreeNode{Department: d}
		byID[d.ID] = node
		if parentID == nil {
			roots = append(roots, node)
		}
	}
	// Second pass to attach children
	for _, node := range byID {
		if node.ParentID != nil {
			if parent, ok := byID[*node.ParentID]; ok {
				parent.Children = append(parent.Children, *node)
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, roots)
}

// deptScopeOK checks whether department deptID is within the actor's
// administrative reach. deptID == nil means "root-level / unconfined" (no
// OU parent) — admin_scope_within fails closed on a NULL scope for any
// object-confined actor, so this doubles as the "must be a global admin"
// check for root-level department creation. Mirrors the admin_scope_within
// guard in AssignUser; all write paths (Create/Update/Delete) route through
// this one helper instead of repeating the query.
func (h *DepartmentsHandler) deptScopeOK(ctx context.Context, actorID int64, deptID *int64, grantDomain *int64) (bool, error) {
	var scopeType *string
	if deptID != nil {
		t := "ou"
		scopeType = &t
	}
	var ok bool
	err := h.pool.QueryRow(ctx, `SELECT admin_scope_within($1, $2, $3, $4)`,
		actorID, scopeType, deptID, grantDomain).Scan(&ok)
	return ok, err
}

// grantDomainFromContext returns the actor's own domain scope for passing as
// p_grant_domain, or nil for a global actor (see AssignUser's ponytail note:
// nil grant-domain with a domain-scoped actor wrongly triggers the domain
// arm's "broadening" rejection).
func grantDomainFromContext(ctx context.Context) *int64 {
	if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
		return &scope
	}
	return nil
}

// Create adds a new department.
func (h *DepartmentsHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Name     string `json:"name"`
		ParentID *int64 `json:"parentId,omitempty"`
		LDAPOU   string `json:"ldapOu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.LDAPOU = strings.TrimSpace(req.LDAPOU)
	if req.Name == "" {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "name required"})
		return
	}
	if err := validate.ValidateResourceName(req.Name); err != nil {
		if ve, ok := err.(*validate.ValidationError); ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: ve.ToFieldError().Message})
		} else {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: err.Error()})
		}
		return
	}
	if req.LDAPOU == "" {
		req.LDAPOU = req.Name
	}

	// Scope check: actor must be able to administer the parent OU. A root-level
	// create (no parent) requires unconfined authority — deptScopeOK(nil) fails
	// closed for any OU-scoped actor via admin_scope_within's NULL-scope rule.
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	grantDomain := grantDomainFromContext(ctx)
	var effParent *int64
	if req.ParentID != nil && *req.ParentID > 0 {
		effParent = req.ParentID
	}
	if ok, err := h.deptScopeOK(ctx, claims.UserID, effParent, grantDomain); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department create scope check failed", err)
		return
	} else if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "department not within your administrative scope"})
		return
	}

	var path string
	if req.ParentID != nil && *req.ParentID > 0 {
		var parentPath string
		if err := h.pool.QueryRow(ctx, `SELECT path FROM departments WHERE id = $1`, *req.ParentID).Scan(&parentPath); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "parent not found"})
			return
		}
		path = parentPath + "/" + req.Name
	} else {
		path = req.Name
	}

	var id int64
	err := h.pool.QueryRow(ctx, `
		INSERT INTO departments (name, parent_id, path, ldap_ou, sort_order)
		VALUES ($1, $2, $3, $4, (SELECT COALESCE(MAX(sort_order),0)+1 FROM departments WHERE parent_id IS NOT DISTINCT FROM $2))
		RETURNING id
	`, req.Name, req.ParentID, path, req.LDAPOU).Scan(&id)
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department create failed", err)
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{"id": id})
}

// Update renames or moves a department.
func (h *DepartmentsHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid id"})
		return
	}

	var req struct {
		Name      string `json:"name,omitempty"`
		ParentID  *int64 `json:"parentId,omitempty"`
		LDAPOU    string `json:"ldapOu,omitempty"`
		SortOrder *int   `json:"sortOrder,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	// Scope check: actor must be able to administer the department being moved,
	// and — if reparenting — the destination parent too. Otherwise an OU-scoped
	// admin could PUT an out-of-scope department under their own subtree,
	// flipping admin_can_reach TRUE for all of that department's users.
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	grantDomain := grantDomainFromContext(ctx)
	if ok, err := h.deptScopeOK(ctx, claims.UserID, &id, grantDomain); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department update scope check failed", err)
		return
	} else if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "department not within your administrative scope"})
		return
	}
	if req.ParentID != nil && *req.ParentID > 0 {
		if ok, err := h.deptScopeOK(ctx, claims.UserID, req.ParentID, grantDomain); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "department update dest scope check failed", err)
			return
		} else if !ok {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "department not within your administrative scope"})
			return
		}
	}

	// Rebuild path if name or parent changed
	if req.Name != "" || req.ParentID != nil {
		var oldPath string
		if err := h.pool.QueryRow(ctx, `SELECT path FROM departments WHERE id = $1`, id).Scan(&oldPath); err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "department not found"})
			return
		}
		parts := strings.Split(oldPath, "/")
		oldName := parts[len(parts)-1]
		name := req.Name
		if name == "" {
			name = oldName
		}

		var parentPath string
		if req.ParentID != nil && *req.ParentID > 0 {
			if err := h.pool.QueryRow(ctx, `SELECT path FROM departments WHERE id = $1`, *req.ParentID).Scan(&parentPath); err != nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "parent not found"})
				return
			}
		}
		newPath := name
		if parentPath != "" {
			newPath = parentPath + "/" + name
		}

		// Update this node and all descendants
		_, err := h.pool.Exec(ctx, `
			WITH RECURSIVE subtree AS (
				SELECT id, path FROM departments WHERE id = $1
				UNION ALL
				SELECT d.id, d.path FROM departments d
				JOIN subtree s ON d.parent_id = s.id
			)
			UPDATE departments d SET path = $2 || SUBSTRING(s.path FROM LENGTH($3)+1)
			FROM subtree s
			WHERE d.id = s.id
		`, id, newPath, oldPath)
		if err != nil {
			httputil.WriteDBErr(w, r, h.logger, "department path update failed", err)
			return
		}
	}

	b := &handlerutil.UpdateBuilder{}
	if req.Name != "" {
		b.SetStr("name", &req.Name)
	}
	if req.LDAPOU != "" {
		b.SetStr("ldap_ou", &req.LDAPOU)
	}
	b.SetInt("parent_id", req.ParentID)
	b.SetIntVal("sort_order", req.SortOrder)
	if _, err := b.BuildAndExec(ctx, h.pool, "departments", "id", id, false, ""); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department update failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a department (only if no users and no children).
func (h *DepartmentsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := r.PathValue("id")
	id, _ := strconv.ParseInt(idStr, 10, 64)
	if id <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid id"})
		return
	}

	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	grantDomain := grantDomainFromContext(ctx)
	if ok, err := h.deptScopeOK(ctx, claims.UserID, &id, grantDomain); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department delete scope check failed", err)
		return
	} else if !ok {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "department not within your administrative scope"})
		return
	}

	var childCount, userCount int
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM departments WHERE parent_id = $1`, id).Scan(&childCount); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department delete check failed", err)
		return
	}
	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE department_id = $1`, id).Scan(&userCount); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department delete check failed", err)
		return
	}
	if childCount > 0 {
		httputil.WriteProblem(w, r, httputil.NewConflictProblem("cannot delete department with sub-departments"))
		return
	}
	if userCount > 0 {
		httputil.WriteProblem(w, r, httputil.NewConflictProblem("cannot delete department with assigned users"))
		return
	}

	if _, err := h.pool.Exec(ctx, `DELETE FROM departments WHERE id = $1`, id); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "department delete failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssignUser updates a user's department.
func (h *DepartmentsHandler) AssignUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		UserID       int64  `json:"userId"`
		DepartmentID *int64 `json:"departmentId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if req.UserID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "userId required"})
		return
	}

	// Reach check: actor must be able to administer the target user's OU/domain.
	claims := auth.RequireUser(w, r)
	if claims == nil {
		return
	}
	var canReach bool
	if err := h.pool.QueryRow(ctx, `SELECT admin_can_reach($1, $2)`, claims.UserID, req.UserID).Scan(&canReach); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign user reach check failed", err)
		return
	}
	if !canReach {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target user not within your administrative scope"})
		return
	}

	if req.DepartmentID != nil && *req.DepartmentID > 0 {
		var exists bool
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM departments WHERE id = $1)`, *req.DepartmentID).Scan(&exists); err != nil || !exists {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "department not found"})
			return
		}
		// ponytail: scope containment check — actor must be able to write a grant
		// scoped to the target department. Pass the actor's own domain scope so the
		// domain arm in admin_scope_within passes for same-domain operations: a
		// domain-scoped actor (v_actor.scope non-null) with p_grant_domain=nil
		// triggers "p_grant_domain IS NULL" → wrongly returns FALSE (over-block).
		// Global actor gets nil (domain-wide grant → domain arm inert when scope IS NULL).
		var scopeOK bool
		var grantDomain *int64
		if scope := middleware.DomainScopeFromContext(ctx); scope > 0 {
			grantDomain = &scope
		}
		if err := h.pool.QueryRow(ctx, `SELECT admin_scope_within($1, $2, $3, $4)`,
			claims.UserID, "ou", *req.DepartmentID, grantDomain).Scan(&scopeOK); err != nil {
			httputil.WriteDBErr(w, r, h.logger, "assign user scope_within check failed", err)
			return
		}
		if !scopeOK {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "target department not within your administrative scope"})
			return
		}
	} else {
		req.DepartmentID = nil
	}

	if _, err := h.pool.Exec(ctx, `UPDATE users SET department_id = $1 WHERE id = $2`, req.DepartmentID, req.UserID); err != nil {
		httputil.WriteDBErr(w, r, h.logger, "assign user department failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
