package admin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
)

const (
	identityListDefaultLimit = 100
	identityListMaxLimit     = 500
	identityFilterMaxBytes   = 256
	identityCursorMaxBytes   = 4096
	identityReasonMaxBytes   = 1024
	identityBodyMaxBytes     = 64 << 10
	identityCursorTTL        = 15 * time.Minute
)

type identityListSpec struct {
	resource     string
	defaultSort  string
	filterBounds map[string]int
	filterEnums  map[string]map[string]struct{}
}

type identityListCursor struct {
	Version  int    `json:"v"`
	Resource string `json:"resource"`
	Binding  string `json:"binding"`
	Expires  int64  `json:"expires"`
	Text     string `json:"text,omitempty"`
	Number   int64  `json:"number,omitempty"`
	Time     string `json:"time,omitempty"`
	ID       string `json:"id,omitempty"`
}

type identityListOptions struct {
	limit   int
	filter  string
	source  string
	state   string
	sort    string
	binding string
	cursor  identityListCursor
}

func identityEnum(values ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func parseIdentityListOptions(
	w http.ResponseWriter,
	r *http.Request,
	spec identityListSpec,
	actorID, domainScope int64,
) (identityListOptions, bool) {
	query := r.URL.Query()
	allowed := map[string]struct{}{
		"cursor": {}, "limit": {}, "sort": {},
	}
	for name := range spec.filterBounds {
		allowed[name] = struct{}{}
	}
	for name, values := range query {
		if _, ok := allowed[name]; !ok || len(values) != 1 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"unsupported or repeated identity list query parameter")
			return identityListOptions{}, false
		}
	}

	opts := identityListOptions{
		limit:  identityListDefaultLimit,
		filter: query.Get("filter"),
		source: query.Get("source"),
		state:  query.Get("state"),
		sort:   query.Get("sort"),
	}
	if opts.sort == "" {
		opts.sort = spec.defaultSort
	}
	if opts.sort != spec.defaultSort {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"unsupported identity list sort")
		return identityListOptions{}, false
	}
	if rawLimit := query.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > identityListMaxLimit {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"identity list limit must be between 1 and 500")
			return identityListOptions{}, false
		}
		opts.limit = limit
	}
	for name, maxBytes := range spec.filterBounds {
		value := query.Get(name)
		if len(value) > maxBytes {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				fmt.Sprintf("identity list %s exceeds %d bytes", name, maxBytes))
			return identityListOptions{}, false
		}
		if enum := spec.filterEnums[name]; value != "" && enum != nil {
			if _, ok := enum[value]; !ok {
				httputil.WriteProblemStatus(w, http.StatusBadRequest,
					"unsupported identity list "+name)
				return identityListOptions{}, false
			}
		}
	}
	if opts.source != "" && !validIdentitySourceKey(opts.source) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"invalid identity source filter")
		return identityListOptions{}, false
	}

	bindingMaterial := fmt.Sprintf(
		"v1\n%s\n%d\n%d\n%s\n%s\n%s\n%s",
		spec.resource, actorID, domainScope, opts.sort, opts.filter, opts.source, opts.state,
	)
	binding := sha256.Sum256([]byte(bindingMaterial))
	opts.binding = hex.EncodeToString(binding[:])

	rawCursor := query.Get("cursor")
	if rawCursor == "" {
		return opts, true
	}
	if len(rawCursor) > identityCursorMaxBytes {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return identityListOptions{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(rawCursor)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return identityListOptions{}, false
	}
	dec := json.NewDecoder(strings.NewReader(string(decoded)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&opts.cursor); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return identityListOptions{}, false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return identityListOptions{}, false
	}
	if opts.cursor.Version != 1 || opts.cursor.Resource != spec.resource ||
		opts.cursor.Binding != opts.binding {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"identity list cursor does not match the requested filters")
		return identityListOptions{}, false
	}
	if opts.cursor.Expires <= time.Now().Unix() {
		httputil.WriteProblemStatus(w, http.StatusGone, "identity list cursor has expired")
		return identityListOptions{}, false
	}
	return opts, true
}

func encodeIdentityListCursor(
	spec identityListSpec,
	opts identityListOptions,
	mutate func(*identityListCursor),
) string {
	cursor := identityListCursor{
		Version:  1,
		Resource: spec.resource,
		Binding:  opts.binding,
		Expires:  time.Now().Add(identityCursorTTL).Unix(),
	}
	mutate(&cursor)
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func writeIdentityJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity response encoding failed")
		return
	}
	writeIdentityRawJSON(w, r, status, raw, "")
}

func writeIdentityRawJSON(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	raw json.RawMessage,
	version string,
) {
	if version == "" {
		sum := sha256.Sum256(raw)
		version = hex.EncodeToString(sum[:])
	}
	etag := `"` + version + `"`
	w.Header().Set("ETag", etag)
	if identityETagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func identityETagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
	}
	return false
}

func identityIfMatch(w http.ResponseWriter, r *http.Request, version string) bool {
	header := strings.TrimSpace(r.Header.Get("If-Match"))
	if header == "" {
		return true
	}
	if identityETagMatches(header, `"`+version+`"`) {
		return true
	}
	httputil.WriteProblemStatus(w, http.StatusPreconditionFailed,
		"identity resource version does not match If-Match")
	return false
}

func decodeIdentityJSON(w http.ResponseWriter, r *http.Request, dst any, detail string) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, identityBodyMaxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			httputil.WriteProblemStatus(w, http.StatusRequestEntityTooLarge,
				"identity request body exceeds 65536 bytes")
			return false
		}
		httputil.WriteProblemStatus(w, http.StatusBadRequest, detail)
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, detail)
		return false
	}
	return true
}

func validIdentityReason(reason string) bool {
	if len(reason) > identityReasonMaxBytes || strings.TrimSpace(reason) == "" {
		return false
	}
	for _, char := range reason {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func validIdentitySourceKey(sourceKey string) bool {
	if sourceKey == "" || len(sourceKey) > 64 {
		return false
	}
	for index, char := range sourceKey {
		if index == 0 && !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
			return false
		}
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') &&
			char != ':' && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func validIdentityDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (h *IdentityHandler) requireIdentityWorker(w http.ResponseWriter) bool {
	if h.workerPool == nil {
		httputil.WriteProblemStatus(w, http.StatusServiceUnavailable, "identity worker database is unavailable")
		return false
	}
	return true
}

func requireUnscopedIdentityAdmin(
	w http.ResponseWriter,
	r *http.Request,
	required ...string,
) bool {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return false
	}
	if len(required) == 0 {
		required = []string{permissions.PermIdentityWrite}
	}
	for _, permission := range required {
		if !permissions.HasPermission(claims.GlobalPermissions, permission) {
			httputil.WriteProblemStatus(w, http.StatusForbidden,
				"source-wide identity operations require a live unscoped permission grant")
			return false
		}
	}
	if middleware.DomainScopeFromContext(r.Context()) != 0 {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"source-wide identity operations require unscoped authority")
		return false
	}
	return true
}

func requireAnyUnscopedIdentityAdmin(
	w http.ResponseWriter,
	r *http.Request,
	required ...string,
) bool {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return false
	}
	if middleware.DomainScopeFromContext(r.Context()) != 0 {
		httputil.WriteProblemStatus(w, http.StatusForbidden,
			"source-wide identity operations require unscoped authority")
		return false
	}
	for _, permission := range required {
		if permissions.HasPermission(claims.GlobalPermissions, permission) {
			return true
		}
	}
	httputil.WriteProblemStatus(w, http.StatusForbidden,
		"source-wide identity operations require a live unscoped permission grant")
	return false
}

// Sources returns non-secret source health and generation facts.
func (h *IdentityHandler) Sources(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	spec := identityListSpec{
		resource:    "sources",
		defaultSort: "sourceKey",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
			"state":  16,
		},
		filterEnums: map[string]map[string]struct{}{
			"state": identityEnum("draft", "validated", "active", "paused", "error", "retired"),
		},
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	opts, ok := parseIdentityListOptions(w, r, spec, claims.UserID, domainScope)
	if !ok {
		return
	}
	if r.URL.Query().Get("cursor") != "" && opts.cursor.Text == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT source_key,display_name,kind,state,generation,mapping_version,
		       capabilities,last_success_at,last_failure_at,last_error_code,
		       committed_cursor IS NOT NULL,
		       (SELECT count(*) FROM identity_source_inbox i
		         WHERE i.source_id=s.id AND i.state IN ('pending','quarantined'))
		  FROM identity_sources s
		 WHERE ($2::bigint = 0 OR EXISTS (
		         SELECT 1 FROM user_identity_links scoped_link
		          WHERE scoped_link.source_id=s.id
		            AND admin_can_reach($1,scoped_link.user_id)
		       ))
		   AND ($3::text = '' OR s.source_key ILIKE '%' || $3 || '%'
		        OR s.display_name ILIKE '%' || $3 || '%')
		   AND ($4::text = '' OR s.source_key=$4)
		   AND ($5::text = '' OR s.state=$5)
		   AND ($6::text = '' OR s.source_key>$6)
		 ORDER BY s.source_key
		 LIMIT $7
	`, claims.UserID, domainScope, opts.filter, opts.source, opts.state,
		opts.cursor.Text, opts.limit+1)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity source query failed")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var key, name, kind, state string
		var generation, mapping int64
		var capabilities json.RawMessage
		var lastSuccess, lastFailure *time.Time
		var lastError *string
		var hasCursor bool
		var backlog int64
		if err := rows.Scan(&key, &name, &kind, &state, &generation, &mapping,
			&capabilities, &lastSuccess, &lastFailure, &lastError, &hasCursor,
			&backlog); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "identity source decode failed")
			return
		}
		out = append(out, map[string]any{
			"sourceKey": key, "displayName": name, "kind": kind, "state": state,
			"generation":     strconv.FormatInt(generation, 10),
			"mappingVersion": strconv.FormatInt(mapping, 10),
			"capabilities":   capabilities, "lastSuccessAt": lastSuccess,
			"lastFailureAt": lastFailure, "lastErrorCode": lastError,
			"hasCursor": hasCursor, "attentionCount": backlog,
		})
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity source query failed")
		return
	}
	response := map[string]any{"items": out}
	if len(out) > opts.limit {
		out = out[:opts.limit]
		response["items"] = out
		last := out[len(out)-1]
		response["nextCursor"] = encodeIdentityListCursor(spec, opts,
			func(cursor *identityListCursor) {
				cursor.Text = last["sourceKey"].(string)
			})
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

// People returns a bounded admin projection; opaque subjects are never returned.
func (h *IdentityHandler) IdentityPeople(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	spec := identityListSpec{
		resource:    "people",
		defaultSort: "userId",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
			"state":  16,
		},
		filterEnums: map[string]map[string]struct{}{
			"state": identityEnum("enabled", "disabled"),
		},
	}
	opts, ok := parseIdentityListOptions(w, r, spec, claims.UserID,
		middleware.DomainScopeFromContext(r.Context()))
	if !ok {
		return
	}
	if r.URL.Query().Get("cursor") != "" && opts.cursor.Number <= 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT u.id,u.email,u.display_name,u.enabled,a.authority_kind,
		       s.source_key,
		       count(l.id) FILTER (WHERE l.state='active')::integer,
		       count(l.id) FILTER (WHERE l.state='detached')::integer
		  FROM users u
		  JOIN user_lifecycle_authorities a ON a.user_id=u.id
		  LEFT JOIN user_identity_links al ON al.id=a.link_id
		  LEFT JOIN identity_sources s ON s.id=al.source_id
		  LEFT JOIN user_identity_links l ON l.user_id=u.id
		 WHERE NOT is_guest_account(u.id)
		   AND admin_can_reach($1,u.id)
		   AND ($2::text = '' OR u.email ILIKE '%' || $2 || '%'
		        OR COALESCE(u.display_name,'') ILIKE '%' || $2 || '%')
		   AND ($3::text = '' OR s.source_key=$3)
		   AND ($4::text = '' OR ($4='enabled' AND u.enabled)
		        OR ($4='disabled' AND NOT u.enabled))
		   AND ($5::bigint = 0 OR u.id>$5)
		 GROUP BY u.id,u.email,u.display_name,u.enabled,a.authority_kind,s.source_key
		 ORDER BY u.id LIMIT $6
	`, claims.UserID, opts.filter, opts.source, opts.state, opts.cursor.Number,
		opts.limit+1)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity people query failed")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id int64
		var email string
		var name *string
		var enabled bool
		var authority string
		var source *string
		var active, detached int
		if err := rows.Scan(&id, &email, &name, &enabled, &authority, &source, &active, &detached); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "identity people decode failed")
			return
		}
		out = append(out, map[string]any{
			"userId": strconv.FormatInt(id, 10), "email": email,
			"displayName": name, "enabled": enabled, "lifecycleAuthority": authority,
			"sourceKey": source, "activeLinks": active, "detachedLinks": detached,
		})
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity people query failed")
		return
	}
	response := map[string]any{"items": out}
	if len(out) > opts.limit {
		out = out[:opts.limit]
		response["items"] = out
		last := out[len(out)-1]
		lastID, _ := strconv.ParseInt(last["userId"].(string), 10, 64)
		response["nextCursor"] = encodeIdentityListCursor(spec, opts,
			func(cursor *identityListCursor) {
				cursor.Number = lastID
			})
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

func (h *IdentityHandler) IdentityConflicts(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	spec := identityListSpec{
		resource:    "conflicts",
		defaultSort: "-createdAt",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
			"state":  16,
		},
		filterEnums: map[string]map[string]struct{}{
			"state": identityEnum("pending", "deferred"),
		},
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	opts, ok := parseIdentityListOptions(w, r, spec, claims.UserID, domainScope)
	if !ok {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var cursorTime any
	var cursorID any
	if opts.cursor.Time != "" || opts.cursor.ID != "" {
		parsedTime, timeErr := time.Parse(time.RFC3339Nano, opts.cursor.Time)
		parsedID, idErr := uuid.Parse(opts.cursor.ID)
		if timeErr != nil || idErr != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
			return
		}
		cursorTime, cursorID = parsedTime, parsedID
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT c.id::text,s.source_key,c.evidence_class,c.status,c.generation,
		       c.created_at,c.expires_at,c.redacted_explanation
		  FROM identity_match_candidates c
		  JOIN identity_sources s ON s.id=c.source_id
		 WHERE c.status IN ('pending','deferred')
		   AND (($2::bigint = 0 AND c.candidate_user_id IS NULL)
		        OR (c.candidate_user_id IS NOT NULL
		            AND admin_can_reach($1,c.candidate_user_id)))
		   AND ($3::text = '' OR c.redacted_explanation ILIKE '%' || $3 || '%'
		        OR c.evidence_class ILIKE '%' || $3 || '%')
		   AND ($4::text = '' OR s.source_key=$4)
		   AND ($5::text = '' OR c.status=$5)
		   AND ($6::timestamptz IS NULL OR (c.created_at,c.id)<($6,$7::uuid))
		 ORDER BY c.created_at DESC,c.id DESC
		 LIMIT $8
	`, claims.UserID, domainScope, opts.filter, opts.source, opts.state,
		cursorTime, cursorID, opts.limit+1)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity conflict query failed")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, key, class, state, explanation string
		var generation int64
		var created, expires time.Time
		if err := rows.Scan(&id, &key, &class, &state, &generation, &created, &expires, &explanation); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "identity conflict decode failed")
			return
		}
		out = append(out, map[string]any{
			"id": id, "sourceKey": key, "evidenceClass": class, "state": state,
			"generation": strconv.FormatInt(generation, 10),
			"createdAt":  created, "expiresAt": expires, "explanation": explanation,
		})
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity conflict query failed")
		return
	}
	response := map[string]any{"items": out}
	if len(out) > opts.limit {
		out = out[:opts.limit]
		response["items"] = out
		last := out[len(out)-1]
		response["nextCursor"] = encodeIdentityListCursor(spec, opts,
			func(cursor *identityListCursor) {
				cursor.Time = last["createdAt"].(time.Time).UTC().Format(time.RFC3339Nano)
				cursor.ID = last["id"].(string)
			})
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

func (h *IdentityHandler) IdentityTransitions(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	spec := identityListSpec{
		resource:    "transitions",
		defaultSort: "-createdAt",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
			"state":  32,
		},
		filterEnums: map[string]map[string]struct{}{
			"state": identityEnum(
				"draft", "previewed", "awaiting_approval", "authorized",
				"executing", "authority_committed", "effects_pending", "completed",
				"failed_precommit", "failed_recoverable", "rollback_previewed",
				"rolling_back", "rolled_back", "cancelled", "expired",
			),
		},
	}
	opts, ok := parseIdentityListOptions(w, r, spec, claims.UserID,
		middleware.DomainScopeFromContext(r.Context()))
	if !ok {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var cursorTime any
	var cursorID any
	if opts.cursor.Time != "" || opts.cursor.ID != "" {
		parsedTime, timeErr := time.Parse(time.RFC3339Nano, opts.cursor.Time)
		parsedID, idErr := uuid.Parse(opts.cursor.ID)
		if timeErr != nil || idErr != nil {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
			return
		}
		cursorTime, cursorID = parsedTime, parsedID
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT t.id::text,t.user_id::text,t.kind,t.state,s.source_key,
		       t.protected,t.reason,t.failure_code,t.created_at,t.updated_at,
		       count(e.effect_kind) FILTER (WHERE e.state<>'completed')::integer
		  FROM identity_transitions t
		  JOIN identity_sources s ON s.id=t.source_id
		  LEFT JOIN identity_transition_effects e ON e.transition_id=t.id
		 WHERE admin_can_reach($1,t.user_id)
		   AND ($2::text = '' OR t.kind ILIKE '%' || $2 || '%'
		        OR t.state ILIKE '%' || $2 || '%'
		        OR s.source_key ILIKE '%' || $2 || '%')
		   AND ($3::text = '' OR s.source_key=$3)
		   AND ($4::text = '' OR t.state=$4)
		   AND ($5::timestamptz IS NULL OR (t.created_at,t.id)<($5,$6::uuid))
		 GROUP BY t.id,s.source_key
		 ORDER BY t.created_at DESC,t.id DESC
		 LIMIT $7
	`, claims.UserID, opts.filter, opts.source, opts.state, cursorTime, cursorID,
		opts.limit+1)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity transition query failed")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, userID, kind, state, source, reason string
		var protected bool
		var failure *string
		var created, updated time.Time
		var pending int
		if err := rows.Scan(&id, &userID, &kind, &state, &source, &protected,
			&reason, &failure, &created, &updated, &pending); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "identity transition decode failed")
			return
		}
		out = append(out, map[string]any{
			"id": id, "userId": userID, "kind": kind, "state": state,
			"sourceKey": source, "protected": protected, "reason": reason,
			"failureCode": failure, "createdAt": created, "updatedAt": updated,
			"pendingEffects": pending,
		})
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition query failed")
		return
	}
	response := map[string]any{"items": out}
	if len(out) > opts.limit {
		out = out[:opts.limit]
		response["items"] = out
		last := out[len(out)-1]
		response["nextCursor"] = encodeIdentityListCursor(spec, opts,
			func(cursor *identityListCursor) {
				cursor.Time = last["createdAt"].(time.Time).UTC().Format(time.RFC3339Nano)
				cursor.ID = last["id"].(string)
			})
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

func (h *IdentityHandler) IdentityEvents(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	spec := identityListSpec{
		resource:    "events",
		defaultSort: "-occurredAt",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
		},
	}
	domainScope := middleware.DomainScopeFromContext(r.Context())
	opts, ok := parseIdentityListOptions(w, r, spec, claims.UserID, domainScope)
	if !ok {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var cursorTime any
	var cursorID int64
	if opts.cursor.Time != "" || opts.cursor.Number != 0 {
		parsedTime, timeErr := time.Parse(time.RFC3339Nano, opts.cursor.Time)
		if timeErr != nil || opts.cursor.Number <= 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity list cursor")
			return
		}
		cursorTime, cursorID = parsedTime, opts.cursor.Number
	}
	rows, err := h.workerPool.Query(r.Context(), `
		SELECT e.id::text,e.occurred_at,e.user_id::text,s.source_key,
		       e.link_id::text,e.transition_id::text,e.action,e.reason,
		       e.correlation_id::text,e.metadata
		  FROM identity_link_events e
		  LEFT JOIN identity_sources s ON s.id=e.source_id
		 WHERE (($2::bigint = 0 AND e.user_id IS NULL)
		        OR (e.user_id IS NOT NULL AND admin_can_reach($1,e.user_id)))
		   AND ($3::text = '' OR e.action ILIKE '%' || $3 || '%'
		        OR COALESCE(s.source_key,'') ILIKE '%' || $3 || '%')
		   AND ($4::text = '' OR s.source_key=$4)
		   AND ($5::timestamptz IS NULL OR (e.occurred_at,e.id)<($5,$6))
		 ORDER BY e.occurred_at DESC,e.id DESC
		 LIMIT $7
	`, claims.UserID, domainScope, opts.filter, opts.source, cursorTime, cursorID,
		opts.limit+1)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity event query failed")
		return
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id, action, reason, correlation string
		var userID, sourceKey, linkID, transitionID *string
		var occurred time.Time
		var metadata json.RawMessage
		if err := rows.Scan(&id, &occurred, &userID, &sourceKey, &linkID,
			&transitionID, &action, &reason, &correlation, &metadata); err != nil {
			httputil.WriteError(w, http.StatusInternalServerError, "identity event decode failed")
			return
		}
		out = append(out, map[string]any{
			"id": id, "occurredAt": occurred, "userId": userID,
			"sourceKey": sourceKey, "linkId": linkID,
			"transitionId": transitionID, "action": action, "reason": reason,
			"correlationId": correlation, "metadata": metadata,
		})
	}
	if err := rows.Err(); err != nil {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity event query failed")
		return
	}
	response := map[string]any{"items": out}
	if len(out) > opts.limit {
		out = out[:opts.limit]
		response["items"] = out
		last := out[len(out)-1]
		lastID, _ := strconv.ParseInt(last["id"].(string), 10, 64)
		response["nextCursor"] = encodeIdentityListCursor(spec, opts,
			func(cursor *identityListCursor) {
				cursor.Time = last["occurredAt"].(time.Time).UTC().Format(time.RFC3339Nano)
				cursor.Number = lastID
			})
	}
	writeIdentityJSON(w, r, http.StatusOK, response)
}

func (h *IdentityHandler) IdentityTransitionReport(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(w, r, permissions.PermAuditExport) {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid transition id")
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(), `
		SELECT jsonb_build_object(
		  'schemaVersion',1,
		  'generatedAt',statement_timestamp(),
		  'transition',(to_jsonb(t)-'preview_digest') || jsonb_build_object(
		    'approval_request_id',CASE WHEN t.approval_request_id IS NULL THEN NULL ELSE t.approval_request_id::text END,
		    'rollback_approval_request_id',CASE WHEN t.rollback_approval_request_id IS NULL THEN NULL ELSE t.rollback_approval_request_id::text END
		  ),
		  'effects',COALESCE((
		    SELECT jsonb_agg(to_jsonb(e) ORDER BY e.effect_kind)
		      FROM identity_transition_effects e WHERE e.transition_id=t.id
		  ),'[]'::jsonb),
		  'events',COALESCE((
		    SELECT jsonb_agg(ev.row ORDER BY ev.occurred_at,ev.id)
		      FROM (
		        SELECT occurred_at,id,jsonb_build_object(
		          'occurredAt',occurred_at,'action',action,
		          'reason',reason,'correlationId',correlation_id,
		          'metadata',metadata
		        ) AS row
		          FROM identity_link_events
		         WHERE transition_id=t.id
		         ORDER BY occurred_at,id
		         LIMIT 100
		      ) ev
		  ),'[]'::jsonb)
		)
		FROM identity_transitions t
		WHERE t.id=$1 AND admin_can_reach($2,t.user_id)
	`, id, claims.UserID).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httputil.WriteProblemStatus(w, http.StatusNotFound,
				"identity transition not found")
			return
		}
		if h.logger != nil {
			h.logger.Error("identity transition report query failed",
				"transition_id", id.String(), "error", err)
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity transition report failed")
		return
	}
	w.Header().Set("Content-Disposition",
		`attachment; filename="identity-transition-`+id.String()+`.json"`)
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func (h *IdentityHandler) TransitionPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID         string `json:"userId"`
		Reason         string `json:"reason"`
		IdempotencyKey string `json:"idempotencyKey"`
		TargetLinkID   string `json:"targetLinkId,omitempty"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid transition preview") {
		return
	}
	if !identityReasonMatches(w, r, req.Reason) {
		return
	}
	headerKey := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if headerKey != "" && req.IdempotencyKey != "" && headerKey != req.IdempotencyKey {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"Idempotency-Key must match body idempotencyKey")
		return
	}
	if headerKey != "" {
		req.IdempotencyKey = headerKey
	}
	userID, err := strconv.ParseInt(req.UserID, 10, 64)
	key, keyErr := uuid.Parse(req.IdempotencyKey)
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if err != nil || userID <= 0 || keyErr != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid transition preview")
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var canReach bool
	if err := h.workerPool.QueryRow(r.Context(),
		`SELECT admin_can_reach($1,$2)`, claims.UserID, userID).Scan(&canReach); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity transition scope check failed")
		return
	}
	if !canReach {
		httputil.WriteProblemStatus(w, http.StatusNotFound, "identity user not found")
		return
	}
	var raw json.RawMessage
	if req.TargetLinkID == "" {
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_transition_preview($1,$2,$3,$4)`,
			claims.UserID, userID, req.Reason, key).Scan(&raw)
	} else {
		targetLinkID, parseErr := strconv.ParseInt(req.TargetLinkID, 10, 64)
		if parseErr != nil || targetLinkID <= 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid targetLinkId")
			return
		}
		err = h.workerPool.QueryRow(r.Context(),
			`SELECT identity_source_rebind_preview($1,$2,$3,$4,$5)`,
			claims.UserID, userID, targetLinkID, req.Reason, key).Scan(&raw)
	}
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteError(w, http.StatusInternalServerError, "transition preview failed")
		}
		return
	}
	var result struct {
		PreviewDigest string `json:"previewDigest"`
	}
	if err := json.Unmarshal(raw, &result); err != nil ||
		!validIdentityDigest(result.PreviewDigest) {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"transition preview returned an invalid response")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, result.PreviewDigest)
}

func (h *IdentityHandler) IdentityUpgradeStatus(w http.ResponseWriter, r *http.Request) {
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	if err := h.workerPool.QueryRow(r.Context(), `SELECT identity_upgrade_status()`).Scan(&raw); err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, "identity upgrade status failed")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func (h *IdentityHandler) IdentityUpgradeCanary(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceKey          string   `json:"sourceKey"`
		ExpectedGeneration string   `json:"expectedGeneration"`
		Enabled            bool     `json:"enabled"`
		UserIDs            []string `json:"userIds"`
		Reason             string   `json:"reason"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid identity canary request") {
		return
	}
	if !identityReasonMatches(w, r, req.Reason) {
		return
	}
	generation, err := strconv.ParseInt(req.ExpectedGeneration, 10, 64)
	if err != nil || generation <= 0 || !validIdentitySourceKey(req.SourceKey) {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity canary request")
		return
	}
	if !identityIfMatch(w, r, req.ExpectedGeneration) {
		return
	}
	userIDs := make([]int64, 0, len(req.UserIDs))
	seenUserIDs := make(map[int64]struct{}, len(req.UserIDs))
	if len(req.UserIDs) > 500 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "identity canary cohort exceeds 500 users")
		return
	}
	for _, raw := range req.UserIDs {
		id, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || id <= 0 {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity canary user id")
			return
		}
		if _, duplicate := seenUserIDs[id]; duplicate {
			httputil.WriteProblemStatus(w, http.StatusBadRequest,
				"identity canary user ids must be unique")
			return
		}
		seenUserIDs[id] = struct{}{}
		userIDs = append(userIDs, id)
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if req.Enabled && len(userIDs) == 0 {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid identity canary request")
		return
	}
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	err = h.workerPool.QueryRow(r.Context(),
		`SELECT identity_upgrade_canary($1,$2,$3,$4,$5,$6)`,
		claims.UserID, req.SourceKey, generation, req.Enabled, userIDs, req.Reason).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteError(w, http.StatusInternalServerError, "identity canary failed")
		}
		return
	}
	var result struct {
		Generation string `json:"generation"`
	}
	if err := json.Unmarshal(raw, &result); err != nil ||
		result.Generation == "" {
		httputil.WriteProblemStatus(w, http.StatusInternalServerError,
			"identity canary returned an invalid response")
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, result.Generation)
}

func (h *IdentityHandler) IdentityUpgradeRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReadPath string `json:"readPath"`
		Reason   string `json:"reason"`
	}
	if !decodeIdentityJSON(w, r, &req, "invalid identity rollback request") {
		return
	}
	if !identityReasonMatches(w, r, req.Reason) {
		return
	}
	if req.ReadPath != "legacy" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"identity rollback readPath must be legacy")
		return
	}
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	if !requireUnscopedIdentityAdmin(
		w, r, permissions.PermIdentityWrite, permissions.PermSystemUpgrade,
	) {
		return
	}
	if !h.requireIdentityWorker(w) {
		return
	}
	var raw json.RawMessage
	err := h.workerPool.QueryRow(r.Context(),
		`SELECT identity_upgrade_rollback($1,$2)`, claims.UserID, req.Reason).Scan(&raw)
	if err != nil {
		if !reducererr.WriteClassified(w, r, err) {
			httputil.WriteError(w, http.StatusInternalServerError, "identity rollback failed")
		}
		return
	}
	writeIdentityRawJSON(w, r, http.StatusOK, raw, "")
}

func identityReasonMatches(w http.ResponseWriter, r *http.Request, bodyReason string) bool {
	headerReason := middleware.ReasonFromContext(r.Context())
	// RequireReason only attaches context when the deployment's audit policy
	// lists the identity area. Identity transitions and cutover operations
	// always require an exact reason even when that optional global policy list
	// is empty, so fall back to the original header and enforce it here.
	if headerReason == "" {
		headerReason = r.Header.Get("X-Audit-Reason")
	}
	if !validIdentityReason(bodyReason) || !validIdentityReason(headerReason) ||
		bodyReason != headerReason {
		httputil.WriteProblemStatus(w, http.StatusBadRequest,
			"body reason must exactly match X-Audit-Reason")
		return false
	}
	return true
}
