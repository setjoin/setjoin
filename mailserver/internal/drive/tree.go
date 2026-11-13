package drive

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// ── tree ─────────────────────────────────────────────────────────────────

type nodeOut struct {
	ID            int64            `json:"id"`
	ParentID      *int64           `json:"parentId"`
	Kind          string           `json:"kind"`
	Name          string           `json:"name"`
	Size          *int64           `json:"size,omitempty"`
	ContentType   *string          `json:"contentType,omitempty"`
	HeadVersionID *int64           `json:"headVersionId,omitempty"`
	DeletedAt     *string          `json:"deletedAt,omitempty"`
	BranchCount   int64            `json:"branchCount"` // P4 Task 10: open+review branch count (0 for folders)
	Lock          *lockPresenceOut `json:"lock"`        // P4 Task 10: unexpired lock row, or null
	Capabilities  []string         `json:"capabilities"`
	TraverseOnly  bool             `json:"traverseOnly"`
}

// lockPresenceOut is the tree()/nodeOut lock-presence badge (P4 Task 10) —
// the same shape drive_lock_list's rows carry, scoped to one node.
type lockPresenceOut struct {
	HolderID   int64  `json:"holderId"`
	HolderName string `json:"holderName"`
	Mode       string `json:"mode"`
	BranchID   *int64 `json:"branchId"`
	AcquiredAt string `json:"acquiredAt"`
	ExpiresAt  string `json:"expiresAt"`
}

func (h *Handler) tree(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, ok := httputil.ParseIDPath(w, r, "id", "invalid space id")
	if !ok {
		return
	}
	var parentID *int64
	if p := r.URL.Query().Get("parent"); p != "" {
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid parent id"})
			return
		}
		parentID = &v
	}
	deleted := r.URL.Query().Get("deleted") == "1"

	ctx := r.Context()
	var out []nodeOut
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		var canList bool
		if err := tx.QueryRow(ctx, `SELECT CASE WHEN $3::bigint IS NULL
			THEN drive_user_has_space_access($2,$1)
			ELSE drive_runtime_has_node_capability($2,$3,'list_children')
			  OR drive_runtime_has_node_capability($2,$3,'traverse') END`,
			spaceID, claims.UserID, parentID).Scan(&canList); err != nil {
			return err
		}
		if !canList {
			return errSpaceNotFound
		}
		rows, err := tx.Query(ctx, `
			SELECT n.id, n.parent_id, n.kind, n.name, f.size_bytes, f.content_type, f.head_version_id, n.deleted_at,
			       COALESCE(bc.branch_count, 0),
			       l.holder_id, l.holder_name, l.mode, l.branch_id, l.acquired_at, l.expires_at,
			       ARRAY(SELECT capability
			               FROM drive_runtime_capability_sources($4,n.space_id,n.id)
			              ORDER BY capability),
			       drive_runtime_has_node_capability($4,n.id,'traverse')
			         AND NOT drive_runtime_has_node_capability($4,n.id,'read_metadata')
			  FROM drive_nodes n
			  LEFT JOIN drive_files f ON f.node_id = n.id
			  LEFT JOIN LATERAL (
			      SELECT count(*) AS branch_count FROM drive_file_branches b
			       WHERE b.file_node_id = n.id AND b.status IN ('open','review')
			  ) bc ON TRUE
			  LEFT JOIN LATERAL (
			      SELECT lk.user_id AS holder_id, m.display_name AS holder_name, lk.mode,
			             lk.branch_id, lk.acquired_at, lk.expires_at
			        FROM drive_file_locks lk
			        LEFT JOIN mailboxes m ON m.user_id = lk.user_id AND m.is_primary
			       WHERE lk.node_id = n.id AND lk.expires_at > now()
			  ) l ON TRUE
			 WHERE n.space_id = $1
			   AND n.parent_id IS NOT DISTINCT FROM $2
			   AND (n.deleted_at IS NOT NULL) = $3
			   AND (drive_runtime_has_node_capability($4,n.id,'read_metadata')
			     OR drive_runtime_has_node_capability($4,n.id,'traverse'))
			 ORDER BY n.kind DESC, n.name`, spaceID, parentID, deleted, claims.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n nodeOut
			var deletedAt *time.Time
			var holderID *int64
			var holderName, lockMode *string
			var lockBranchID *int64
			var acquiredAt, expiresAt *time.Time
			if err := rows.Scan(&n.ID, &n.ParentID, &n.Kind, &n.Name, &n.Size, &n.ContentType, &n.HeadVersionID, &deletedAt,
				&n.BranchCount, &holderID, &holderName, &lockMode, &lockBranchID, &acquiredAt, &expiresAt,
				&n.Capabilities, &n.TraverseOnly); err != nil {
				return err
			}
			if deletedAt != nil {
				s := deletedAt.UTC().Format(time.RFC3339)
				n.DeletedAt = &s
			}
			if holderID != nil {
				lock := &lockPresenceOut{HolderID: *holderID, BranchID: lockBranchID}
				if holderName != nil {
					lock.HolderName = *holderName
				}
				if lockMode != nil {
					lock.Mode = *lockMode
				}
				if acquiredAt != nil {
					lock.AcquiredAt = acquiredAt.UTC().Format(time.RFC3339)
				}
				if expiresAt != nil {
					lock.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
				}
				n.Lock = lock
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	if err != nil {
		if err == errSpaceNotFound {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "space not found"})
			return
		}
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

// ── changes ──────────────────────────────────────────────────────────────

func (h *Handler) changes(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	spaceID, err := strconv.ParseInt(r.URL.Query().Get("space"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "space is required"})
		return
	}
	since, err := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "since is required"})
		return
	}

	ctx := r.Context()
	var out json.RawMessage
	err = dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_changes_since($1, $2, $3)`, claims.UserID, spaceID, since).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	var probe struct {
		CannotCalculateChanges bool `json:"cannotCalculateChanges"`
	}
	if json.Unmarshal(out, &probe) == nil && probe.CannotCalculateChanges {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusConflict,
			Type:   "https://setjoin.com/problems/drive/cannot-calculate-changes",
			Detail: "client must resync (since is older than the retained journal)",
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}
