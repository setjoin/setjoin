package drive

// A8 Drive ACL REST projections.  The public R1 grant contract accepts one of
// four presets and self/subtree scope only.  Internal capability arrays remain
// SQL-owned and are never accepted on a direct-grant route.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

type aclGrantBody struct {
	SubjectKind   string  `json:"subjectKind"`
	SubjectID     string  `json:"subjectId"`
	Preset        string  `json:"preset"`
	Scope         string  `json:"scope"`
	StartsAt      *string `json:"startsAt,omitempty"`
	ExpiresAt     *string `json:"expiresAt,omitempty"`
	MaxUses       *int    `json:"maxUses,omitempty"`
	Reason        *string `json:"reason,omitempty"`
	ExpectedEpoch string  `json:"expectedEpoch,omitempty"`
	Idempotency   string  `json:"idempotencyKey,omitempty"`
}

type inheritanceBody struct {
	Break         bool   `json:"break"`
	ExpectedEpoch string `json:"expectedEpoch,omitempty"`
}

type accessRequestBody struct {
	SubjectKind     string   `json:"subjectKind"`
	SubjectID       string   `json:"subjectId"`
	Capabilities    []string `json:"capabilities"`
	Propagation     string   `json:"propagation"`
	DurationMinutes int      `json:"durationMinutes"`
	MaxUses         *int     `json:"maxUses,omitempty"`
	Emergency       bool     `json:"emergency"`
	MFASessionID    *string  `json:"mfaSessionId,omitempty"`
	Reason          string   `json:"reason"`
	Idempotency     string   `json:"idempotencyKey,omitempty"`
}

type aclSubjectOut struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	Label     string `json:"label"`
	Secondary string `json:"secondary,omitempty"`
}

func (h *Handler) registerACLGovernanceRoutes(mux router) {
	mux.HandleFunc("GET /drive/nodes/{id}/access", h.aclNodeDetail)
	mux.HandleFunc("GET /drive/acl-subjects", h.aclSubjects)
	mux.HandleFunc("POST /drive/nodes/{id}/acl/preview", h.aclGrantPreview)
	mux.HandleFunc("POST /drive/nodes/{id}/acl", h.aclGrant)
	mux.HandleFunc("DELETE /drive/acl-grants/{id}", h.aclRevoke)
	mux.HandleFunc("POST /drive/nodes/{id}/inheritance/preview", h.aclInheritancePreview)
	mux.HandleFunc("PUT /drive/nodes/{id}/inheritance", h.aclInheritanceSet)
	mux.HandleFunc("GET /drive/quick-views", h.aclQuickView)
	mux.HandleFunc("POST /drive/nodes/{id}/access-requests/preview", h.accessRequestPreview)
	mux.HandleFunc("POST /drive/nodes/{id}/access-requests", h.accessRequestCreate)
}

func decodeACLJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return false
	}
	return true
}

func parseDecimalID(raw string) (int64, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	return v, err == nil && v > 0
}

func parseEpoch(raw string) (int64, bool) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	return v, err == nil && v >= 0
}

func validACLIdempotency(r *http.Request, bodyValue string) bool {
	values := r.Header.Values("Idempotency-Key")
	if len(values) != 1 || values[0] == "" || values[0] != bodyValue || len(bodyValue) != 36 {
		return false
	}
	parsed, err := uuid.Parse(bodyValue)
	return err == nil && strings.EqualFold(parsed.String(), bodyValue)
}

func parseOptionalTime(raw *string) (*time.Time, bool) {
	if raw == nil {
		return nil, true
	}
	v, err := time.Parse(time.RFC3339, *raw)
	if err != nil {
		return nil, false
	}
	v = v.UTC()
	return &v, true
}

func validPublicPreset(p string) bool {
	return p == "viewer" || p == "contributor" || p == "editor" || p == "folder_manager"
}

func validateGrantWire(body aclGrantBody, advanced bool) (subjectID int64, startsAt, expiresAt *time.Time, ok bool) {
	subjectID, ok = parseDecimalID(body.SubjectID)
	if !ok || !validPublicPreset(body.Preset) || (body.Scope != "self" && body.Scope != "subtree") {
		return 0, nil, nil, false
	}
	if body.SubjectKind != "user" && !(advanced && body.SubjectKind == "group") {
		return 0, nil, nil, false
	}
	startsAt, ok = parseOptionalTime(body.StartsAt)
	if !ok {
		return 0, nil, nil, false
	}
	expiresAt, ok = parseOptionalTime(body.ExpiresAt)
	if !ok || (!advanced && (startsAt != nil || expiresAt != nil || body.MaxUses != nil)) {
		return 0, nil, nil, false
	}
	return subjectID, startsAt, expiresAt, true
}

func (h *Handler) writeACLWireError(w http.ResponseWriter, r *http.Request) {
	httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid Drive access input"})
}

func (h *Handler) requireACLMutationRate(w http.ResponseWriter, r *http.Request, userID int64) bool {
	var allowed bool
	err := dbscope.RunUserScoped(r.Context(), h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT rate_limit_check($1,30,1,5)`,
			fmt.Sprintf("drive:acl-mutation:%d", userID)).Scan(&allowed)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return false
	}
	if allowed {
		return true
	}
	w.Header().Set("Retry-After", "60")
	httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusTooManyRequests, Detail: "too many permission changes; retry later"})
	return false
}

func (h *Handler) aclNodeDetail(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	h.aclJSONQuery(w, r, `SELECT drive_acl_node_detail($1,$2)`, nodeID)
}

func (h *Handler) aclJSONQuery(w http.ResponseWriter, r *http.Request, sql string, args ...any) {
	claims := auth.UserFromContext(r.Context())
	params := append([]any{claims.UserID}, args...)
	var out json.RawMessage
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), sql, params...).Scan(&out)
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (h *Handler) aclGrantPreview(w http.ResponseWriter, r *http.Request) {
	h.aclGrantAction(w, r, true)
}

func (h *Handler) aclGrant(w http.ResponseWriter, r *http.Request) {
	h.aclGrantAction(w, r, false)
}

func (h *Handler) aclGrantAction(w http.ResponseWriter, r *http.Request, preview bool) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	var body aclGrantBody
	if !decodeACLJSON(w, r, &body) {
		return
	}
	advanced := h.flags.IsEnabled(toggle.FeatureDriveAccessGovernance)
	subjectID, startsAt, expiresAt, ok := validateGrantWire(body, advanced)
	if !ok {
		h.writeACLWireError(w, r)
		return
	}
	if preview {
		h.aclJSONQuery(w, r,
			`SELECT drive_acl_grant_preview($1,$2,$3,$4,$5,NULL::text[],$6,$7,$8,$9,$10)`,
			nodeID, body.SubjectKind, subjectID, body.Preset, body.Scope,
			startsAt, expiresAt, body.MaxUses, body.Reason)
		return
	}
	epoch, epochOK := parseEpoch(body.ExpectedEpoch)
	if !epochOK || !validACLIdempotency(r, body.Idempotency) {
		h.writeACLWireError(w, r)
		return
	}
	if !h.requireACLMutationRate(w, r, claims.UserID) {
		return
	}
	h.aclJSONQuery(w, r,
		`SELECT drive_acl_grant($1,$2,$3,$4,$5,NULL::text[],$6,$7,$8,$9,$10,$11,$12)`,
		nodeID, body.SubjectKind, subjectID, body.Preset, body.Scope,
		startsAt, expiresAt, body.MaxUses, body.Reason, epoch, body.Idempotency)
}

func (h *Handler) aclRevoke(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	grantID, ok := httputil.ParseIDPath(w, r, "id", "invalid grant id")
	if !ok {
		return
	}
	var body struct {
		ExpectedEpoch string `json:"expectedEpoch"`
		Reason        string `json:"reason"`
	}
	if !decodeACLJSON(w, r, &body) {
		return
	}
	epoch, ok := parseEpoch(body.ExpectedEpoch)
	if !ok || len(body.Reason) < 1 || len(body.Reason) > 1000 || body.Reason != strings.TrimSpace(body.Reason) {
		h.writeACLWireError(w, r)
		return
	}
	if !h.requireACLMutationRate(w, r, claims.UserID) {
		return
	}
	h.aclJSONQuery(w, r, `SELECT drive_acl_revoke($1,$2,$3,$4)`, grantID, epoch, body.Reason)
}

func (h *Handler) aclInheritancePreview(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	var body inheritanceBody
	if !decodeACLJSON(w, r, &body) {
		return
	}
	h.aclJSONQuery(w, r, `SELECT drive_acl_inheritance_preview($1,$2,$3)`, nodeID, body.Break)
}

func (h *Handler) aclInheritanceSet(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	var body inheritanceBody
	if !decodeACLJSON(w, r, &body) {
		return
	}
	epoch, ok := parseEpoch(body.ExpectedEpoch)
	if !ok {
		h.writeACLWireError(w, r)
		return
	}
	if !h.requireACLMutationRate(w, r, claims.UserID) {
		return
	}
	h.aclJSONQuery(w, r, `SELECT drive_acl_inheritance_set($1,$2,$3,$4)`, nodeID, body.Break, epoch)
}

func (h *Handler) aclQuickView(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	max, ok := parseBoundedPageSize(w, r, 100, 200)
	if !ok {
		return
	}
	if view != "shared" && view != "shares" && view != "requests" {
		h.writeACLWireError(w, r)
		return
	}
	h.aclJSONQuery(w, r, `SELECT drive_acl_quick_view($1,$2,$3)`, view, max)
}

func (h *Handler) aclSubjects(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := parseDecimalID(r.URL.Query().Get("node"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if !ok || len(q) < 2 || len(q) > 128 {
		h.writeACLWireError(w, r)
		return
	}
	includeGroups := h.flags.IsEnabled(toggle.FeatureDriveAccessGovernance)
	var out []aclSubjectOut
	err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			WITH target AS (
			  SELECT u.domain_id FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id
			  JOIN users u ON u.id=s.owner_user_id
			  WHERE n.id=$2 AND drive_runtime_has_node_capability($1,n.id,'manage_acl')
			), candidates AS (
			  SELECT 'user'::text kind,u.id,COALESCE(NULLIF(u.display_name,''),u.email) label,u.email secondary
			  FROM users u,target t WHERE u.domain_id=t.domain_id AND u.enabled AND u.id<>$1
			    AND (strpos(lower(COALESCE(u.display_name,'')),lower($3))>0
			      OR strpos(lower(u.email),lower($3))>0)
			  UNION ALL
			  SELECT 'group',g.id,g.name,'' FROM directory_groups g,target t
			  WHERE $4 AND g.domain_id=t.domain_id AND g.state='active'
			    AND g.visibility<>'hidden' AND strpos(lower(g.name),lower($3))>0
			)
			SELECT kind,id::text,label,secondary FROM candidates ORDER BY label,id LIMIT 50`,
			claims.UserID, nodeID, q, includeGroups)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x aclSubjectOut
			if err := rows.Scan(&x.Kind, &x.ID, &x.Label, &x.Secondary); err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	if err != nil {
		writeDriveProblem(w, r, err)
		return
	}
	writeJSONList(w, out)
}

func validRequestedCapabilities(caps []string) bool {
	if len(caps) == 0 || len(caps) > 15 {
		return false
	}
	seen := make(map[string]struct{}, len(caps))
	for _, cap := range caps {
		if cap == "" || len(cap) > 64 {
			return false
		}
		if _, exists := seen[cap]; exists {
			return false
		}
		seen[cap] = struct{}{}
	}
	return true
}

func (h *Handler) accessRequestPreview(w http.ResponseWriter, r *http.Request) {
	h.accessRequestAction(w, r, true)
}

func (h *Handler) accessRequestCreate(w http.ResponseWriter, r *http.Request) {
	h.accessRequestAction(w, r, false)
}

func (h *Handler) accessRequestAction(w http.ResponseWriter, r *http.Request, preview bool) {
	claims := auth.UserFromContext(r.Context())
	nodeID, ok := httputil.ParseIDPath(w, r, "id", "invalid node id")
	if !ok {
		return
	}
	var body accessRequestBody
	if !decodeACLJSON(w, r, &body) {
		return
	}
	subjectID, idOK := parseDecimalID(body.SubjectID)
	if !idOK || (body.SubjectKind != "user" && body.SubjectKind != "group") ||
		!validRequestedCapabilities(body.Capabilities) ||
		(body.Propagation != "self" && body.Propagation != "children" && body.Propagation != "subtree") ||
		body.DurationMinutes < 1 || body.DurationMinutes > 525600 || len(body.Reason) < 8 || len(body.Reason) > 1000 {
		h.writeACLWireError(w, r)
		return
	}
	if !preview && !validACLIdempotency(r, body.Idempotency) {
		h.writeACLWireError(w, r)
		return
	}
	if preview {
		h.aclJSONQuery(w, r,
			`SELECT drive_access_request_preview($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			nodeID, body.SubjectKind, subjectID, body.Capabilities, body.Propagation,
			body.DurationMinutes, body.MaxUses, body.Emergency, body.MFASessionID, body.Reason)
		return
	}
	if !h.requireACLMutationRate(w, r, claims.UserID) {
		return
	}
	h.aclJSONQuery(w, r,
		`SELECT drive_access_request($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		nodeID, body.SubjectKind, subjectID, body.Capabilities, body.Propagation,
		body.DurationMinutes, body.MaxUses, body.Emergency, body.MFASessionID,
		body.Reason, body.Idempotency)
}
