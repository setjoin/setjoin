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

// ── members ──────────────────────────────────────────────────────────────

type memberOut struct {
	UserID      int64  `json:"userId"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	GrantedAt   string `json:"grantedAt"`
}

func (h *Handler) listMembers(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	ctx := r.Context()
	var out []memberOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.user_id, m.role, u.email, u.display_name, m.granted_at
			  FROM drive_space_members m JOIN users u ON u.id = m.user_id
			 WHERE m.space_id = $2
			   AND drive_runtime_has_space_root_capability($1,$2,'manage_acl')
			 ORDER BY m.role, u.display_name`, claims.UserID, spaceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m memberOut
			var g time.Time
			if err := rows.Scan(&m.UserID, &m.Role, &m.Email, &m.DisplayName, &g); err != nil {
				return err
			}
			m.GrantedAt = g.UTC().Format(time.RFC3339)
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	if len(out) == 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "space not found"})
		return
	}
	writeJSONList(w, out)
}

type grantMemberBody struct {
	UserID int64  `json:"userId"`
	Role   string `json:"role"`
}

// grantMember is dual-purpose (spec §7 "?folder=" variant, LR-1/Task 11): with
// no query param it is the space-manager-only drive_member_grant; with
// ?folder=<nodeId> it routes to drive_folder_member_grant, the delegated
// folder-admin path (§5.5) — same body shape, different reducer.
func (h *Handler) grantMember(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body grantMemberBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID <= 0 {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	folderID, ok := parseOptionalInt64Query(w, r, "folder")
	if !ok {
		return
	}
	var out json.RawMessage
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if folderID != nil {
			return tx.QueryRow(ctx, `SELECT drive_folder_member_grant($1, $2, $3, $4, $5)`,
				claims.UserID, spaceID, *folderID, body.UserID, body.Role).Scan(&out)
		}
		return tx.QueryRow(ctx, `SELECT drive_member_grant($1, $2, $3, $4)`,
			claims.UserID, spaceID, body.UserID, body.Role).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

// revokeMember is the ?folder= twin of grantMember: with no query param it is
// the space-manager-only drive_member_revoke; with ?folder=<nodeId> it routes
// to the delegated drive_folder_member_revoke.
func (h *Handler) revokeMember(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	targetUserID, ok := httputil.ParseIDPath(w, r, "userId", "invalid user id")
	if !ok {
		return
	}
	folderID, ok := parseOptionalInt64Query(w, r, "folder")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if folderID != nil {
			_, err := tx.Exec(ctx, `SELECT drive_folder_member_revoke($1, $2, $3, $4)`,
				claims.UserID, spaceID, *folderID, targetUserID)
			return err
		}
		_, err := tx.Exec(ctx, `SELECT drive_member_revoke($1, $2, $3)`, claims.UserID, spaceID, targetUserID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
