package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ── GET /scim/v2/Groups ─────────────────────────────────────────────────────

// GetGroups handles GET /scim/v2/Groups — list groups.
func (s *Server) GetGroups(w http.ResponseWriter, r *http.Request) {
	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	q := r.URL.Query()
	startIndex := 1
	if v := q.Get("startIndex"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			startIndex = n
		}
	}
	count := 100
	if v := q.Get("count"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 1000 {
			count = n
		}
	}

	offset := startIndex - 1

	var total int
	if err := s.pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM distribution_groups WHERE scim_source_id=$1`,
		sourceID,
	).Scan(&total); err != nil {
		s.logger.Error("scim count groups query failed", "error", err)
		WriteSCIMError(w, http.StatusInternalServerError, "Query failed", "")
		return
	}

	rows, err := s.pool.Query(r.Context(),
		`SELECT dg.id, dg.scim_external_id, mb.display_name,
		        dg.created_at
		 FROM distribution_groups dg
		 JOIN mailboxes mb ON mb.id = dg.mailbox_id
		 WHERE dg.scim_source_id=$1
		 ORDER BY dg.id LIMIT $2 OFFSET $3`, sourceID, count, offset)
	if err != nil {
		s.logger.Error("scim get groups query failed", "error", err)
		WriteSCIMError(w, http.StatusInternalServerError, "Query failed", "")
		return
	}
	defer rows.Close()

	var groups []GroupResource
	for rows.Next() {
		var id int64
		var extID, displayName *string
		var createdAt time.Time

		if err := rows.Scan(&id, &extID, &displayName, &createdAt); err != nil {
			continue
		}

		g := GroupResource{
			Schemas: DefaultGroupSchemas,
			ID:      idToStr(id),
			Meta: &Meta{
				ResourceType: "Group",
				Created:      createdAt.Format(time.RFC3339),
				Location:     "/scim/v2/Groups/" + idToStr(id),
			},
		}
		if extID != nil {
			g.ExternalID = *extID
		}
		if displayName != nil {
			g.DisplayName = *displayName
		}

		// Fetch members
		g.Members = s.getGroupMembers(r.Context(), sourceID, id)

		groups = append(groups, g)
	}

	resources, _ := json.Marshal(groups)
	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(groups),
		Resources:    resources,
	}

	WriteSCIM(w, http.StatusOK, resp)
}

// ── GET /scim/v2/Groups/{id} ────────────────────────────────────────────────

// GetGroup handles GET /scim/v2/Groups/{id} — fetch a single group.
func (s *Server) GetGroup(w http.ResponseWriter, r *http.Request) {
	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid group ID", "invalidValue")
		return
	}

	var extID, displayName *string
	var createdAt time.Time

	err = s.pool.QueryRow(r.Context(),
		`SELECT dg.scim_external_id, mb.display_name, dg.created_at
		 FROM distribution_groups dg
		 JOIN mailboxes mb ON mb.id = dg.mailbox_id
		 WHERE dg.id=$1 AND dg.scim_source_id=$2`, id, sourceID,
	).Scan(&extID, &displayName, &createdAt)

	if err == pgx.ErrNoRows {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("Group %s not found", idStr), "invalidValue")
		return
	}
	if err != nil {
		s.logger.Error("scim get group failed", "error", err)
		WriteSCIMError(w, http.StatusInternalServerError, "Query failed", "")
		return
	}

	g := GroupResource{
		Schemas: DefaultGroupSchemas,
		ID:      idStr,
		Meta: &Meta{
			ResourceType: "Group",
			Created:      createdAt.Format(time.RFC3339),
			Location:     "/scim/v2/Groups/" + idStr,
		},
	}
	if extID != nil {
		g.ExternalID = *extID
	}
	if displayName != nil {
		g.DisplayName = *displayName
	}

	g.Members = s.getGroupMembers(r.Context(), sourceID, id)

	WriteSCIM(w, http.StatusOK, g)
}

func (s *Server) getGroupMembers(ctx context.Context, sourceID, groupID int64) []MemberRef {
	// workerPool (BYPASSRLS), NOT s.pool: the join reads user_identity_links
	// (V156 — FORCE RLS, zero setjoin_app policies; "admin/worker reads use
	// setjoin_worker"), matching every other identity-link read in this server
	// (user.go queryUsers*/GetUser ride s.workerPool). s.workerPool aliases
	// s.pool until DB_WORKER_DSN is set, so this is INERT until the flip.
	rows, err := s.workerPool.Query(ctx,
		`SELECT l.external_subject, COALESCE(u.display_name, ''),
		        u.id
		 FROM distribution_group_members dgm
		 JOIN mailboxes mb ON mb.id = dgm.mailbox_id
		 JOIN users u ON u.id = mb.user_id
		 JOIN user_identity_links l ON l.user_id=u.id
		 JOIN distribution_groups dg ON dg.id=dgm.group_id
		 WHERE dgm.group_id=$1
		   AND dg.scim_source_id=$2
		   AND l.source_id=$2
		   AND l.state='active'
		   AND 'provision'=ANY(l.purposes)
		   AND NOT is_guest_account(u.id)
		 ORDER BY u.display_name`, groupID, sourceID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var members []MemberRef
	for rows.Next() {
		var extID, displayName string
		var userID int64
		if err := rows.Scan(&extID, &displayName, &userID); err != nil {
			continue
		}
		members = append(members, MemberRef{
			Value:   extID,
			Display: displayName,
			Type:    "User",
			Ref:     "/scim/v2/Users/" + idToStr(userID),
		})
	}
	return members
}

// ── POST /scim/v2/Groups ────────────────────────────────────────────────────

// CreateGroup handles POST /scim/v2/Groups — create a new group.
func (s *Server) CreateGroup(w http.ResponseWriter, r *http.Request) {
	sourceID, sourceGeneration, ok := scimSourceFence(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	var req GroupResource
	if !decodeSCIMBody(w, r, &req) {
		return
	}

	if req.DisplayName == "" {
		WriteSCIMError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
		return
	}

	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		WriteSCIMError(w, http.StatusInternalServerError, "Failed to create group", "")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()

	var id int64
	err = tx.QueryRow(r.Context(),
		`SELECT scim_upsert_group($1, $2, $3, $4)`,
		sourceID, sourceGeneration, req.ExternalID, req.DisplayName,
	).Scan(&id)
	if err != nil {
		WriteSCIMError(w, s.logReducerError("scim create group failed", err), "Failed to create group", "")
		return
	}

	memberIDs := make([]string, len(req.Members))
	for i, m := range req.Members {
		memberIDs[i] = m.Value
	}
	if _, err = tx.Exec(r.Context(),
		`SELECT scim_apply_group_members($1, $2, $3, $4, TRUE)`,
		sourceID, sourceGeneration, req.ExternalID, memberIDs,
	); err != nil {
		WriteSCIMError(w, s.logReducerError("scim create group members failed", err),
			"Failed to create group", "")
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		WriteSCIMError(w, http.StatusInternalServerError, "Failed to create group", "")
		return
	}

	g := GroupResource{
		Schemas:     DefaultGroupSchemas,
		ID:          idToStr(id),
		ExternalID:  req.ExternalID,
		DisplayName: req.DisplayName,
		Members:     s.getGroupMembers(r.Context(), sourceID, id),
		Meta: &Meta{
			ResourceType: "Group",
			Location:     "/scim/v2/Groups/" + idToStr(id),
		},
	}

	WriteSCIM(w, http.StatusCreated, g)
}

// ── PATCH /scim/v2/Groups/{id} ──────────────────────────────────────────────

// PatchGroup handles PATCH /scim/v2/Groups/{id}.
func (s *Server) PatchGroup(w http.ResponseWriter, r *http.Request) {
	sourceID, sourceGeneration, ok := scimSourceFence(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid group ID", "invalidValue")
		return
	}

	// Get group external ID
	var extID string
	err = s.pool.QueryRow(r.Context(),
		`SELECT COALESCE(scim_external_id, '')
		   FROM distribution_groups
		  WHERE id=$1 AND scim_source_id=$2`, id, sourceID,
	).Scan(&extID)
	if err != nil || extID == "" {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("Group %s not found", idStr), "invalidValue")
		return
	}

	var req PatchRequest
	if !decodeSCIMBody(w, r, &req) {
		return
	}

	if err := applyGroupPatch(s, r.Context(), sourceID, sourceGeneration, id, extID, req.Operations); err != nil {
		if scimErr, ok := err.(*httpError); ok {
			WriteSCIMError(w, scimErr.Status, scimErr.Detail, scimErr.ScimType)
		} else {
			// A raw reducer error from the patch (e.g. scim_apply_group_members on
			// a members replace/add) — classify the BZ code instead of a blanket
			// 500. A non-BZ/transport error keeps the 500 fallback.
			WriteSCIMError(w, s.logReducerError("scim patch group failed", err), "PATCH failed", "")
		}
		return
	}

	// Return updated resource
	s.GetGroup(w, r)
}

// ── DELETE /scim/v2/Groups/{id} ─────────────────────────────────────────────

// DeleteGroup handles DELETE /scim/v2/Groups/{id}.
func (s *Server) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	sourceID, sourceGeneration, ok := scimSourceFence(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid group ID", "invalidValue")
		return
	}

	var deleted bool
	if err := s.pool.QueryRow(r.Context(),
		`SELECT scim_delete_group($1, $2, $3)`, sourceID, sourceGeneration, id).Scan(&deleted); err != nil {
		WriteSCIMError(w, s.logReducerError("scim delete group failed", err), "Failed to delete group", "")
		return
	}
	if !deleted {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("Group %s not found", idStr), "invalidValue")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
