package drive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// ── nodes ────────────────────────────────────────────────────────────────

type createNodeBody struct {
	SpaceID     int64   `json:"spaceId"`
	ParentID    *int64  `json:"parentId"`
	Kind        string  `json:"kind"`
	Name        string  `json:"name"`
	ContentType *string `json:"contentType"`
}

// allowNameMutation records the attempt in its own committed transaction so
// a later name collision cannot roll the counter back with the failed
// reducer statement. The bounded key contains no user-controlled name data.
func (h *Handler) allowNameMutation(ctx context.Context, userID int64) (bool, error) {
	var allowed bool
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT rate_limit_check($1,120,1,5)`,
			fmt.Sprintf("drive:name-mutation:%d", userID)).Scan(&allowed)
	})
	return allowed, err
}

func (h *Handler) requireNameMutationRate(w http.ResponseWriter, r *http.Request, userID int64) bool {
	allowed, err := h.allowNameMutation(r.Context(), userID)
	if err != nil {
		writeDriveProblem(w, r, err)
		return false
	}
	if allowed {
		return true
	}
	w.Header().Set("Retry-After", "60")
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusTooManyRequests,
		Type:   "https://setjoin.com/problems/drive/mutation-rate-limited",
		Detail: "too many name or placement changes; retry later",
	})
	return false
}

func (h *Handler) createNode(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body createNodeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if !h.requireNameMutationRate(w, r, claims.UserID) {
		return
	}
	var id int64
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_node_create($1, $2, $3, $4, $5, $6)`,
			claims.UserID, body.SpaceID, body.ParentID, body.Kind, body.Name, body.ContentType).Scan(&id)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// patchNode handles rename and/or move: newName present renames, newParentId
// present (explicit JSON null included — root move) moves. Both may be sent
// in the same request; rename runs first so a combined rename+move lands as
// one logical client-visible change even though it is two reducer calls.
func (h *Handler) patchNode(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var fields map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}
	if _, rename := fields["newName"]; rename {
		if !h.requireNameMutationRate(w, r, claims.UserID) {
			return
		}
	} else if _, move := fields["newParentId"]; move {
		if !h.requireNameMutationRate(w, r, claims.UserID) {
			return
		}
	}

	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		if raw, present := fields["newName"]; present {
			var newName string
			if err := json.Unmarshal(raw, &newName); err != nil {
				return errInvalidField
			}
			if _, err := tx.Exec(ctx, `SELECT drive_node_rename($1, $2, $3)`, claims.UserID, nodeID, newName); err != nil {
				return err
			}
		}
		if raw, present := fields["newParentId"]; present {
			var newParentID *int64
			if err := json.Unmarshal(raw, &newParentID); err != nil {
				return errInvalidField
			}
			if _, err := tx.Exec(ctx, `SELECT drive_node_move($1, $2, $3)`, claims.UserID, nodeID, newParentID); err != nil {
				return err
			}
		}
		return nil
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

func (h *Handler) trashNode(w http.ResponseWriter, r *http.Request) {
	h.nodeAction(w, r, "drive_node_trash")
}
func (h *Handler) restoreNode(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if !h.requireNameMutationRate(w, r, claims.UserID) {
		return
	}
	h.nodeAction(w, r, "drive_node_restore")
}
func (h *Handler) destroyNode(w http.ResponseWriter, r *http.Request) {
	h.nodeAction(w, r, "drive_node_destroy")
}

// nodeAction is the shared shape for the three single-arg (p_user_id,
// p_node_id) node lifecycle reducers — trash/restore/destroy.
func (h *Handler) nodeAction(w http.ResponseWriter, r *http.Request, fn string) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	ctx := r.Context()
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT `+fn+`($1, $2)`, claims.UserID, nodeID)
		return err
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
