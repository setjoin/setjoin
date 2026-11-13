// folderadmins.go — Go routes for delegated folder admins (plan Task 11,
// LR-1). Thin 1:1 translation over drive_folder_admin_grant/_revoke (the
// space-manager-only roster) plus the "?folder=" delegated member-management
// variant riding the EXISTING /drive/spaces/{id}/members routes (handler.go).
package drive

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// registerFolderAdminRoutes registers the folder-admin roster routes on h.mux.
func (h *Handler) registerFolderAdminRoutes(mux router) {
	mux.HandleFunc("GET /drive/nodes/{id}/folder-admins", h.listFolderAdmins)
	mux.HandleFunc("PUT /drive/nodes/{id}/folder-admins/{userId}", h.grantFolderAdmin)
	mux.HandleFunc("DELETE /drive/nodes/{id}/folder-admins/{userId}", h.revokeFolderAdmin)
}

type folderAdminOut struct {
	UserID      int64  `json:"userId"`
	DisplayName string `json:"displayName"`
	GrantedBy   int64  `json:"grantedBy"`
	GrantedAt   string `json:"grantedAt"`
}

func (h *Handler) listFolderAdmins(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	ctx := r.Context()
	var out []folderAdminOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var canManage bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(SELECT 1 FROM drive_nodes n
			 WHERE n.id = $1
			   AND drive_runtime_has_node_capability($2,n.id,'manage_acl'))`, nodeID, claims.UserID).Scan(&canManage); err != nil {
			return err
		}
		if !canManage {
			return errSpaceNotFound
		}
		rows, err := tx.Query(ctx, `
			SELECT fa.user_id, u.display_name, fa.granted_by, fa.granted_at
			  FROM drive_folder_admins fa JOIN users u ON u.id = fa.user_id
			 WHERE fa.node_id = $1 ORDER BY fa.granted_at`, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f folderAdminOut
			var g time.Time
			if err := rows.Scan(&f.UserID, &f.DisplayName, &f.GrantedBy, &g); err != nil {
				return err
			}
			f.GrantedAt = g.UTC().Format(time.RFC3339)
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		if err == errSpaceNotFound {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "node not found"})
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

func (h *Handler) grantFolderAdmin(w http.ResponseWriter, r *http.Request) {
	h.folderAdminAction(w, r, "drive_folder_admin_grant")
}

func (h *Handler) revokeFolderAdmin(w http.ResponseWriter, r *http.Request) {
	h.folderAdminAction(w, r, "drive_folder_admin_revoke")
}

// folderAdminAction is the shared shape for the two (p_user_id, p_node_id,
// p_grantee) folder-admin roster reducers — grant/revoke — the nodeAction
// (handler.go) genre.
func (h *Handler) folderAdminAction(w http.ResponseWriter, r *http.Request, fn string) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	granteeID, ok := httputil.ParseIDPath(w, r, "userId", "invalid user id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT `+fn+`($1, $2, $3)`, claims.UserID, nodeID, granteeID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
