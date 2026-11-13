package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/reducererr"
)

type identityConflictDecisionRequest struct {
	Decision           string `json:"decision"`
	PersonID           string `json:"personId,omitempty"`
	ExpectedGeneration string `json:"expectedGeneration"`
	Reason             string `json:"reason"`
	IdempotencyKey     string `json:"idempotencyKey"`
}

func identityPersonPathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid person id")
		return 0, false
	}
	return id, true
}

func identityConflictPathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid conflict id")
		return uuid.Nil, false
	}
	return id, true
}

// IdentityPersonDetail returns the authoritative, bounded People read model.
// The reducer applies the same no-oracle domain reachability rule as list APIs.
func (h *IdentityHandler) IdentityPersonDetail(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityPersonPathID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_person_read($1,$2)`,
		claims.UserID, id,
	).Scan(&raw); err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity person read failed")
		}
		return
	}
	if len(raw) == 0 || string(raw) == "null" {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity person not found")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

// IdentityConflictDetail returns redacted evidence and bounded decision
// history. Raw external subjects and source payloads never cross this API.
func (h *IdentityHandler) IdentityConflictDetail(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityConflictPathID(w, r)
	if !ok || !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	err := h.workerPool.QueryRow(r.Context(), `
		SELECT jsonb_build_object(
		    'id', c.id,
		    'source', jsonb_build_object(
		        'sourceKey', s.source_key,
		        'displayName', s.display_name,
		        'kind', s.kind,
		        'state', s.state,
		        'generation', s.generation::text
		    ),
		    'subjectFingerprint',
		        substr(encode(digest(c.external_subject,'sha256'),'hex'),1,16),
		    'evidenceClass', c.evidence_class,
		    'evidenceDigest', encode(c.evidence_digest,'hex'),
		    'explanation', c.redacted_explanation,
		    'state', c.status,
		    'generation', c.generation::text,
		    'createdAt', c.created_at,
		    'expiresAt', c.expires_at,
		    'decidedAt', c.decided_at,
		    'candidatePerson', CASE WHEN u.id IS NULL THEN NULL ELSE
		        jsonb_build_object(
		            'userId', u.id::text,
		            'email', u.email,
		            'displayName', u.display_name,
		            'enabled', u.enabled,
		            'protected', protection.is_protected
		        ) END,
		    'allowedDecisions', CASE
		        WHEN c.status NOT IN ('pending','deferred')
		             OR c.expires_at<=statement_timestamp()
		             OR c.generation<>s.generation
		            THEN '[]'::jsonb
		        WHEN c.candidate_user_id IS NULL
		             AND s.state='active'
		             AND source_payload.available
		            THEN '["create","reject","defer"]'::jsonb
		        WHEN c.candidate_user_id IS NULL
		             OR c.evidence_class='soft'
		             OR protection.is_protected
		             OR s.state<>'active'
		            THEN '["reject","defer"]'::jsonb
		        ELSE '["link","reject","defer"]'::jsonb
		    END,
		    'decisionHistory', COALESCE((
		        SELECT jsonb_agg(history.row ORDER BY history.occurred_at DESC)
		          FROM (
		            SELECT d.occurred_at,
		                   jsonb_build_object(
		                       'id', d.id::text,
		                       'decision', d.decision,
		                       'reason', d.reason,
		                       'personId', CASE WHEN d.person_id IS NULL THEN NULL
		                                        ELSE d.person_id::text END,
		                       'linkId', CASE WHEN d.link_id IS NULL THEN NULL
		                                      ELSE d.link_id::text END,
		                       'decidedBy', d.decided_by::text,
		                       'occurredAt', d.occurred_at
		                   ) AS row
		              FROM identity_match_decisions d
		             WHERE d.candidate_id=c.id
		             ORDER BY d.occurred_at DESC,d.id DESC
		             LIMIT 50
		          ) history
		    ),'[]'::jsonb)
		)
		  FROM identity_match_candidates c
		  JOIN identity_sources s ON s.id=c.source_id
		  LEFT JOIN users u ON u.id=c.candidate_user_id
		  LEFT JOIN LATERAL (
		      SELECT u.id IS NOT NULL AND (
		          EXISTS (
		              SELECT 1
		                FROM admin_role_assignments ara
		                JOIN admin_role_groups arg ON arg.id=ara.role_group_id
		               WHERE ara.user_id=u.id
		                 AND (ara.expires_at IS NULL
		                      OR ara.expires_at>statement_timestamp())
		                 AND admin_assignment_active(
		                     ara.eligible,ara.activated_until
		                 )
		                 AND EXISTS (
		                     SELECT 1 FROM admin_permissions ap
		                      WHERE ap.permission_key=ANY(arg.permissions)
		                        AND ap.is_sensitive
		                 )
		          )
		          OR EXISTS (
		              SELECT 1
		                FROM system_config cfg,
		                     LATERAL jsonb_array_elements_text(cfg.value) x(raw)
		               WHERE cfg.key='ca_break_glass_user_ids'
		                 AND x.raw::bigint=u.id
		          )
		      ) AS is_protected
		  ) protection ON true
		  LEFT JOIN LATERAL (
		      SELECT false AS available
		  ) source_payload ON true
		 WHERE c.id=$2
		   AND identity_admin_scope_allows(
		       $1,c.candidate_user_id,'users.read'
		   )
	`, claims.UserID, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity conflict not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity conflict read failed")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

// IdentityConflictDecision resolves exactly one current candidate. Reducer
// authority owns link/create/reject/defer semantics and durable replay.
func (h *IdentityHandler) IdentityConflictDecision(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	id, ok := identityConflictPathID(w, r)
	if !ok {
		return
	}
	var req identityConflictDecisionRequest
	if !decodeIdentityJSON(w, r, &req, "invalid identity conflict decision") {
		return
	}
	if !validIdentityReason(req.Reason) ||
		!oneOfIdentityDecision(req.Decision) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid identity conflict decision")
		return
	}
	if r.Header.Get("X-Audit-Reason") != req.Reason {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"body reason must exactly match X-Audit-Reason")
		return
	}
	idempotency, ok := identityMutationHeaders(w, r, req.IdempotencyKey)
	if !ok {
		return
	}
	generation, ok := identityExpectedGeneration(w, r, req.ExpectedGeneration)
	if !ok {
		return
	}

	var personID *int64
	if req.PersonID != "" {
		parsed, err := strconv.ParseInt(req.PersonID, 10, 64)
		if err != nil || parsed <= 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid personId")
			return
		}
		personID = &parsed
	}
	if (req.Decision == "link") != (personID != nil) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"personId is required only for link decisions")
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}

	var candidatePersonID *int64
	err := h.workerPool.QueryRow(r.Context(),
		`SELECT candidate_user_id FROM identity_match_candidates WHERE id=$1`,
		id,
	).Scan(&candidatePersonID)
	if errors.Is(err, pgx.ErrNoRows) {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity conflict not found")
		return
	}
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity conflict scope check failed")
		return
	}
	if candidatePersonID == nil {
		if !requireUnscopedIdentityAdmin(w, r) {
			return
		}
	} else {
		var reachable bool
		if err := h.workerPool.QueryRow(r.Context(),
			`SELECT identity_admin_scope_allows($1,$2,'identity.write')`,
			claims.UserID, *candidatePersonID,
		).Scan(&reachable); err != nil {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity conflict scope check failed")
			return
		}
		if !reachable {
			httputil.WriteProblemStatus(w, http.StatusNotFound,
				"identity conflict not found")
			return
		}
	}

	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(), `
		SELECT identity_match_decide($1,$2,$3,$4,$5,$6,$7)
	`, claims.UserID, id, generation, req.Decision, personID, req.Reason,
		idempotency).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteProblemStatus(w, http.StatusInternalServerError,
				"identity conflict decision failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, req.ExpectedGeneration)
}

func oneOfIdentityDecision(value string) bool {
	switch strings.TrimSpace(value) {
	case "link", "create", "reject", "defer":
		return value == strings.TrimSpace(value)
	default:
		return false
	}
}
