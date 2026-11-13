package drive

// nodes_meta.go — GET /drive/nodes?ids=1,2,3 (P2 Task 2): a batch metadata
// read for the sync client's delta apply. The change feed (handler.go's
// changes) gives (nodeId, op) only; walking tree?parent= per node is O(depth)
// requests, so the mirror resolves a whole feed batch in one call.
//
// RLS is NOT the row filter here — RLS is a latent backstop pre-DSN-flip
// (dbscope package doc; ARCH-006 app-level-primary posture), so the query
// carries its own explicit membership predicate, same shape as tree()'s and
// listVersions'. Invisible/unknown ids are silently absent from the response,
// never a 403/404 — indistinguishable from "doesn't exist" (BZ139 posture).

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// maxNodesMetaIDs caps a single batch read (BZ141 gate below).
const maxNodesMetaIDs = 500

type nodeMetaRow struct {
	NodeID        int64    `json:"nodeId"`
	SpaceID       int64    `json:"spaceId"`
	ParentID      *int64   `json:"parentId"`
	Kind          string   `json:"kind"`
	Name          string   `json:"name"`
	DeletedAt     *string  `json:"deletedAt"`
	HeadVersionID *int64   `json:"headVersionId"`
	ContentSha256 *string  `json:"contentSha256"`
	SizeBytes     *int64   `json:"sizeBytes"`
	ContentType   *string  `json:"contentType"`
	BranchCount   int64    `json:"branchCount"` // P4 Task 17: open+review branch count (reuses handler.go tree()'s LATERAL; 0 for folders)
	Capabilities  []string `json:"capabilities"`
	TraverseOnly  bool     `json:"traverseOnly"`
}

var nodesMetaSQL = `
SELECT n.id, n.space_id, n.parent_id, n.kind, n.name, n.deleted_at,
       f.head_version_id, v.content_sha256, f.size_bytes, f.content_type,
       COALESCE(bc.branch_count, 0),
       ARRAY(SELECT capability
               FROM drive_runtime_capability_sources($2,n.space_id,n.id)
              ORDER BY capability),
       drive_runtime_has_node_capability($2,n.id,'traverse')
         AND NOT drive_runtime_has_node_capability($2,n.id,'read_metadata')
  FROM drive_nodes n
  LEFT JOIN drive_files f        ON f.node_id = n.id
  LEFT JOIN drive_file_versions v ON v.id = f.head_version_id
  LEFT JOIN LATERAL (
      SELECT count(*) AS branch_count FROM drive_file_branches b
       WHERE b.file_node_id = n.id AND b.status IN ('open','review')
  ) bc ON TRUE
 WHERE n.id = ANY($1)
   AND drive_runtime_has_node_capability($2,n.id,'read_metadata')
   AND ` + chatAttachmentNodeVisibleSQL("n.id", "$2") + `
 ORDER BY n.id`

// nodesMeta serves GET /drive/nodes?ids=1,2,3 — see file header.
func (h *Handler) nodesMeta(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())

	ids, ok := parseNodeIDsParam(w, r)
	if !ok {
		return
	}
	if len(ids) == 0 {
		writeJSONList(w, []nodeMetaRow{})
		return
	}

	ctx := r.Context()
	var out []nodeMetaRow
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, nodesMetaSQL, ids, claims.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n nodeMetaRow
			var deletedAt *time.Time
			if err := rows.Scan(&n.NodeID, &n.SpaceID, &n.ParentID, &n.Kind, &n.Name, &deletedAt,
				&n.HeadVersionID, &n.ContentSha256, &n.SizeBytes, &n.ContentType, &n.BranchCount,
				&n.Capabilities, &n.TraverseOnly); err != nil {
				return err
			}
			if deletedAt != nil {
				s := deletedAt.UTC().Format(time.RFC3339)
				n.DeletedAt = &s
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

// parseNodeIDsParam parses the "ids" query param into a validated int64
// slice. Absent/empty -> (nil, true) — the empty-list 200 short-circuit in
// nodesMeta. A non-numeric entry or more than maxNodesMetaIDs ids is a client
// error, not a reducer error, so it is reported directly (BZ141 —
// invalid-arguments, matching bzSlug's mapping for the same code raised
// server-side).
func parseNodeIDsParam(w http.ResponseWriter, r *http.Request) ([]int64, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get("ids"))
	if raw == "" {
		return nil, true
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxNodesMetaIDs {
		writeNodesMetaInvalidArgs(w, r, "too many ids (max 500)")
		return nil, false
	}
	ids := make([]int64, 0, len(parts))
	for _, p := range parts {
		id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil {
			writeNodesMetaInvalidArgs(w, r, "invalid id in ids list")
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

func writeNodesMetaInvalidArgs(w http.ResponseWriter, r *http.Request, detail string) {
	httputil.WriteProblem(w, r, &httputil.Problem{
		Status: http.StatusUnprocessableEntity,
		Type:   "https://setjoin.com/problems/drive/invalid-arguments",
		Detail: detail,
		Code:   "BZ141",
	})
}
