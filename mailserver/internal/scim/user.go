package scim

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/genutil"
)

// ── GET /scim/v2/Users ──────────────────────────────────────────────────────

// GetUsers handles GET /scim/v2/Users — list or search users.
func (s *Server) GetUsers(w http.ResponseWriter, r *http.Request) {
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

	filter := q.Get("filter")
	syncToken := q.Get("syncToken")

	var rows pgx.Rows
	var total int
	var err error

	if filter != "" {
		rows, total, err = s.queryUsersFilter(r, filter, startIndex, count)
	} else if syncToken != "" {
		rows, total, err = s.queryUsersSyncToken(r, syncToken, count)
	} else {
		rows, total, err = s.queryUsersPaginated(r, startIndex, count)
	}

	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			WriteSCIMError(w, he.Status, he.Detail, he.ScimType)
			return
		}
		s.logger.Error("scim get users query failed", "error", err)
		WriteSCIMError(w, http.StatusInternalServerError, "Query failed", "")
		return
	}

	users, totalResults, newSyncToken := s.scanUsers(rows, total, syncToken != "", sourceID)

	resources, _ := json.Marshal(users)
	resp := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: len(users),
		Resources:    resources,
	}

	if newSyncToken != "" {
		w.Header().Set("Location", fmt.Sprintf("/scim/v2/Users?syncToken=%s", newSyncToken))
	}

	WriteSCIM(w, http.StatusOK, resp)
}

func (s *Server) queryUsersFilter(r *http.Request, filter string, startIndex, count int) (pgx.Rows, int, error) {
	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		return nil, 0, &httpError{Status: http.StatusUnauthorized, Detail: "Invalid SCIM source", ScimType: "invalidToken"}
	}
	node, err := parseFilter(filter)
	if err != nil {
		return nil, 0, &httpError{Status: http.StatusBadRequest, Detail: "Invalid filter syntax", ScimType: "invalidFilter"}
	}

	where, args, ok := nodeToSQL(node)
	if !ok {
		return nil, 0, &httpError{Status: http.StatusBadRequest, Detail: "Unsupported filter attribute", ScimType: "invalidFilter"}
	}
	offset := startIndex - 1

	// Guest Accounts P17: SCIM list omits guest rows — SCIM is an identity-plane
	// surface, and a guest is provisioned/managed via the guest console, not IdP sync.
	sourceArg := len(args) + 1
	scopedArgs := append(append([]interface{}{}, args...), sourceID)
	totalRow := s.workerPool.QueryRow(r.Context(),
		fmt.Sprintf(`SELECT COUNT(*)
		  FROM user_identity_links l
		  JOIN users u ON u.id=l.user_id
		 WHERE l.source_id=$%d AND l.state='active'
		   AND 'provision'=ANY(l.purposes)
		   AND NOT is_guest_account(u.id) AND %s`, sourceArg, where),
		scopedArgs...)

	var total int
	if err := totalRow.Scan(&total); err != nil {
		return nil, 0, err
	}

	query := fmt.Sprintf(
		`SELECT u.id, l.external_subject, u.username, u.email, u.display_name,
		        u.first_name, u.last_name, u.job_title, u.phone,
		        u.enabled, u.created_at, u.updated_at
		   FROM user_identity_links l
		   JOIN users u ON u.id=l.user_id
		  WHERE l.source_id=$%d AND l.state='active'
		    AND 'provision'=ANY(l.purposes)
		    AND NOT is_guest_account(u.id) AND %s
		  ORDER BY u.id LIMIT $%d OFFSET $%d`,
		sourceArg, where, len(args)+2, len(args)+3,
	)

	allArgs := append(scopedArgs, count, offset)
	rows, err := s.workerPool.Query(r.Context(), query, allArgs...)
	return rows, total, err
}

func (s *Server) queryUsersSyncToken(r *http.Request, syncToken string, count int) (pgx.Rows, int, error) {
	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		return nil, 0, &httpError{Status: http.StatusUnauthorized, Detail: "Invalid SCIM source", ScimType: "invalidToken"}
	}
	cursor, err := decodeSyncToken(syncToken, sourceID)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid syncToken: %w", err)
	}

	// Guest Accounts P17: SCIM list omits guest rows (see queryUsersFilter).
	rows, err := s.workerPool.Query(r.Context(),
		`SELECT u.id, l.external_subject, u.username, u.email, u.display_name,
		        u.first_name, u.last_name, u.job_title, u.phone,
		        u.enabled, u.created_at, u.updated_at
		   FROM user_identity_links l
		   JOIN users u ON u.id=l.user_id
		  WHERE l.source_id=$1 AND l.state='active'
		    AND 'provision'=ANY(l.purposes)
		    AND u.updated_at > $2 AND NOT is_guest_account(u.id)
		 ORDER BY u.updated_at
		 LIMIT $3`, sourceID, cursor, count)
	return rows, 0, err
}

func (s *Server) queryUsersPaginated(r *http.Request, startIndex, count int) (pgx.Rows, int, error) {
	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		return nil, 0, &httpError{Status: http.StatusUnauthorized, Detail: "Invalid SCIM source", ScimType: "invalidToken"}
	}
	offset := startIndex - 1

	// Guest Accounts P17: SCIM list omits guest rows (see queryUsersFilter).
	var total int
	totalRow := s.workerPool.QueryRow(r.Context(), `
		SELECT COUNT(*)
		  FROM user_identity_links l
		  JOIN users u ON u.id=l.user_id
		 WHERE l.source_id=$1 AND l.state='active'
		   AND 'provision'=ANY(l.purposes)
		   AND NOT is_guest_account(u.id)`, sourceID)
	if err := totalRow.Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.workerPool.Query(r.Context(),
		`SELECT u.id, l.external_subject, u.username, u.email, u.display_name,
		        u.first_name, u.last_name, u.job_title, u.phone,
		        u.enabled, u.created_at, u.updated_at
		   FROM user_identity_links l
		   JOIN users u ON u.id=l.user_id
		  WHERE l.source_id=$1 AND l.state='active'
		    AND 'provision'=ANY(l.purposes)
		    AND NOT is_guest_account(u.id)
		  ORDER BY u.id LIMIT $2 OFFSET $3`, sourceID, count, offset)
	return rows, total, err
}

func (s *Server) scanUsers(rows pgx.Rows, total int, isSync bool, sourceID int64) ([]UserResource, int, string) {
	var users []UserResource
	var maxUpdatedAt time.Time

	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var u UserResource
			var id int64
			var extID, username, email, displayName *string
			var firstName, lastName, jobTitle, phone *string
			var enabled *bool
			var createdAt, updatedAt time.Time

			if err := rows.Scan(&id, &extID, &username, &email, &displayName,
				&firstName, &lastName, &jobTitle, &phone,
				&enabled, &createdAt, &updatedAt); err != nil {
				continue
			}

			u = userRowToResource(id, extID, username, email, displayName,
				firstName, lastName, jobTitle, phone, enabled, createdAt, updatedAt)
			users = append(users, u)

			if updatedAt.After(maxUpdatedAt) {
				maxUpdatedAt = updatedAt
			}
		}
	}

	if isSync {
		total = len(users)
	}

	var newSyncToken string
	if isSync && maxUpdatedAt.After(time.Time{}) {
		newSyncToken = encodeSyncToken(sourceID, maxUpdatedAt)
	}

	return users, total, newSyncToken
}

func userRowToResource(id int64, extID, username, email, displayName *string,
	firstName, lastName, jobTitle, phone *string, enabled *bool,
	createdAt, updatedAt time.Time) UserResource {

	u := UserResource{
		Schemas: DefaultUserSchemas,
		ID:      idToStr(id),
		Meta: &Meta{
			ResourceType: "User",
			Created:      createdAt.Format(time.RFC3339),
			LastModified: updatedAt.Format(time.RFC3339),
			Location:     "/scim/v2/Users/" + idToStr(id),
		},
	}
	if extID != nil {
		u.ExternalID = *extID
	}
	if username != nil {
		u.UserName = *username
	}
	if displayName != nil {
		u.DisplayName = *displayName
	}
	if email != nil {
		workType := "work"
		primary := true
		u.Emails = []EmailAttr{{Value: *email, Type: workType, Primary: &primary}}
	}
	if firstName != nil || lastName != nil {
		u.Name = &Name{}
		if firstName != nil {
			u.Name.GivenName = *firstName
		}
		if lastName != nil {
			u.Name.FamilyName = *lastName
		}
		if firstName != nil && lastName != nil {
			u.Name.Formatted = *firstName + " " + *lastName
		}
	}
	if jobTitle != nil {
		u.Title = *jobTitle
	}
	if phone != nil {
		u.PhoneNumbers = []PhoneNumberAttr{{Value: *phone, Type: "work"}}
	}
	if enabled != nil {
		u.Active = enabled
	}

	return u
}

// ── GET /scim/v2/Users/{id} ─────────────────────────────────────────────────

// GetUser handles GET /scim/v2/Users/{id} — fetch a single user.
func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid user ID", "invalidValue")
		return
	}

	var u UserResource
	var extID, username, email, displayName *string
	var firstName, lastName, jobTitle, phone *string
	var enabled *bool
	var createdAt, updatedAt time.Time

	sourceID, ok := scimSourceID(r.Context())
	if !ok {
		WriteSCIMError(w, http.StatusUnauthorized, "Invalid SCIM source", "invalidToken")
		return
	}
	err = s.workerPool.QueryRow(r.Context(),
		`SELECT u.id, l.external_subject, u.username, u.email, u.display_name,
		        u.first_name, u.last_name, u.job_title, u.phone,
		        u.enabled, u.created_at, u.updated_at
		   FROM user_identity_links l
		   JOIN users u ON u.id=l.user_id
		  WHERE l.source_id=$1 AND u.id=$2
		    AND l.state='active' AND 'provision'=ANY(l.purposes)
		    AND NOT is_guest_account(u.id)`, sourceID, id,
	).Scan(&id, &extID, &username, &email, &displayName,
		&firstName, &lastName, &jobTitle, &phone,
		&enabled, &createdAt, &updatedAt)

	if err != nil {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("User %s not found", idStr), "invalidValue")
		return
	}

	u = userRowToResource(id, extID, username, email, displayName,
		firstName, lastName, jobTitle, phone, enabled, createdAt, updatedAt)

	WriteSCIM(w, http.StatusOK, u)
}

// scimUserFields holds the reducer arguments extracted from a SCIM UserResource,
// shared by CreateUser (POST) and ReplaceUser (PUT) which extract identically.
type scimUserFields struct {
	displayName  string
	firstName    string
	lastName     string
	primaryEmail string
	phone        string
	department   string
	managerExtID string
	active       bool
}

func scimSourceID(ctx context.Context) (int64, bool) {
	sourceID, ok := ctx.Value(ctxSourceID).(int64)
	return sourceID, ok && sourceID > 0
}

func scimSourceFence(ctx context.Context) (sourceID, generation int64, ok bool) {
	sourceID, okSource := scimSourceID(ctx)
	generation, okGeneration := ctx.Value(ctxSourceGeneration).(int64)
	return sourceID, generation, okSource && okGeneration && generation > 0
}

// extractUserFields maps a SCIM UserResource onto scim_upsert_user's arguments,
// applying the fallbacks (displayName←Name.Formatted←userName, primaryEmail←userName,
// active defaults true).
func extractUserFields(req UserResource) scimUserFields {
	displayName := req.DisplayName
	if displayName == "" && req.Name != nil {
		displayName = req.Name.Formatted
	}
	if displayName == "" {
		displayName = req.UserName
	}

	var firstName, lastName string
	if req.Name != nil {
		firstName = req.Name.GivenName
		lastName = req.Name.FamilyName
	}

	primaryEmail := ""
	if len(req.Emails) > 0 {
		primaryEmail = req.Emails[0].Value
	}
	if primaryEmail == "" {
		primaryEmail = req.UserName
	}

	var phone string
	if len(req.PhoneNumbers) > 0 {
		phone = req.PhoneNumbers[0].Value
	}

	var department string
	if req.EntExt != nil {
		department = req.EntExt.Department
	}

	var managerExtID string
	if req.EntExt != nil && req.EntExt.Manager != nil {
		managerExtID = req.EntExt.Manager.Value
	}

	return scimUserFields{
		displayName:  displayName,
		firstName:    firstName,
		lastName:     lastName,
		primaryEmail: primaryEmail,
		phone:        phone,
		department:   department,
		managerExtID: managerExtID,
		active:       genutil.PtrOr(req.Active, true),
	}
}

func (s *Server) applySourceUser(
	ctx context.Context,
	externalID string,
	fields scimUserFields,
	title string,
	expectedUserID int64,
) (int64, error) {
	sourceID, okID := ctx.Value(ctxSourceID).(int64)
	generation, okGeneration := ctx.Value(ctxSourceGeneration).(int64)
	if !okID || !okGeneration || sourceID <= 0 || generation <= 0 {
		return 0, errors.New("SCIM token is not bound to an active identity source")
	}
	if externalID == "" {
		return 0, &httpError{
			Status: http.StatusBadRequest, Detail: "externalId is required as the immutable SCIM subject",
			ScimType: "invalidValue",
		}
	}
	operation := "upsert"
	if !fields.active {
		operation = "disable"
	}
	payload, err := json.Marshal(map[string]any{
		"operation": operation, "email": fields.primaryEmail,
		"displayName": fields.displayName, "firstName": fields.firstName,
		"lastName": fields.lastName, "jobTitle": title, "phone": fields.phone,
		"department": fields.department, "enabled": fields.active,
		"managerSubject": fields.managerExtID,
		"expectedUserId": expectedUserID, "replaceAll": true,
	})
	if err != nil {
		return 0, err
	}
	var raw []byte
	if err := s.workerPool.QueryRow(ctx,
		`SELECT identity_source_scim_apply($1,$2,$3,$4,$5::jsonb)`,
		sourceID, generation, uuid.New(), externalID, payload,
	).Scan(&raw); err != nil {
		return 0, err
	}
	var result struct {
		State  string `json:"state"`
		Code   string `json:"code"`
		UserID string `json:"userId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, err
	}
	if result.State != "applied" || result.UserID == "" {
		return 0, fmt.Errorf("SCIM source entry %s (%s)", result.State, result.Code)
	}
	return strconv.ParseInt(result.UserID, 10, 64)
}

func (s *Server) applySourceUserPatch(
	ctx context.Context,
	externalID string,
	fields scimUserFields,
	title string,
	expectedUserID int64,
	touched userPatchFields,
) (int64, error) {
	sourceID, okID := ctx.Value(ctxSourceID).(int64)
	generation, okGeneration := ctx.Value(ctxSourceGeneration).(int64)
	if !okID || !okGeneration || sourceID <= 0 || generation <= 0 {
		return 0, errors.New("SCIM token is not bound to an active identity source")
	}
	if externalID == "" {
		return 0, &httpError{
			Status: http.StatusBadRequest, Detail: "externalId is required as the immutable SCIM subject",
			ScimType: "invalidValue",
		}
	}
	payload := map[string]any{
		"operation":      "upsert",
		"expectedUserId": expectedUserID,
		"replaceAll":     false,
	}
	if touched["displayName"] {
		payload["displayName"] = fields.displayName
	}
	if touched["givenName"] {
		payload["firstName"] = fields.firstName
	}
	if touched["familyName"] {
		payload["lastName"] = fields.lastName
	}
	if touched["title"] {
		payload["jobTitle"] = title
	}
	if touched["emails"] {
		payload["email"] = fields.primaryEmail
	}
	if touched["phoneNumbers"] {
		payload["phone"] = fields.phone
	}
	if touched["department"] {
		payload["department"] = fields.department
	}
	if touched["active"] {
		payload["enabled"] = fields.active
		if !fields.active {
			payload["operation"] = "disable"
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var raw []byte
	if err := s.workerPool.QueryRow(ctx,
		`SELECT identity_source_scim_apply($1,$2,$3,$4,$5::jsonb)`,
		sourceID, generation, uuid.New(), externalID, encoded,
	).Scan(&raw); err != nil {
		return 0, err
	}
	var result struct {
		State  string `json:"state"`
		Code   string `json:"code"`
		UserID string `json:"userId"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return 0, err
	}
	if result.State != "applied" || result.UserID == "" {
		return 0, fmt.Errorf("SCIM source entry %s (%s)", result.State, result.Code)
	}
	return strconv.ParseInt(result.UserID, 10, 64)
}

// ── POST /scim/v2/Users ─────────────────────────────────────────────────────

// CreateUser handles POST /scim/v2/Users — create a new user.
func (s *Server) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req UserResource
	if !decodeSCIMBody(w, r, &req) {
		return
	}

	if req.UserName == "" {
		WriteSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	f := extractUserFields(req)

	id, err := s.applySourceUser(r.Context(), req.ExternalID, f, req.Title, 0)

	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			WriteSCIMError(w, he.Status, he.Detail, he.ScimType)
			return
		}
		WriteSCIMError(w, s.logReducerError("scim create user failed", err), "Failed to create user", "")
		return
	}

	// Welcome email: SCIM POST /Users is an interactive single create (spec §7).
	// scim_upsert_user has upsert semantics and does not surface created, so we
	// rely on SendWelcomeEmail's idempotency guard (system:welcome:<id> sentinel)
	// to avoid double-sending on a re-POST of an existing user. Locale "" → the
	// configured default_locale.
	//
	// native-RLS: this welcome runs deliver() into another tenant's mailbox, so it
	// runs on the worker (BYPASSRLS) pool, like admin-create (h.workerPool).
	// s.workerPool aliases s.pool until DB_WORKER_DSN is set, so this is INERT
	// until the native-RLS flip (see retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md).
	go notify.SendWelcomeEmail(context.Background(), s.workerPool, id, "", s.logger) //nolint:gosec // G118: fire-and-forget must outlive the request

	// Fetch the created user to return full resource
	createdAt := time.Now()
	u := userRowToResource(id, &req.ExternalID, &req.UserName, &f.primaryEmail, &f.displayName,
		&f.firstName, &f.lastName, &req.Title, &f.phone, &f.active, createdAt, createdAt)
	u.ID = idToStr(id)

	WriteSCIM(w, http.StatusCreated, u)
}

// ── PUT /scim/v2/Users/{id} ─────────────────────────────────────────────────

// ReplaceUser handles PUT /scim/v2/Users/{id} — full replacement via scim_upsert_user.
func (s *Server) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	pathID, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid user ID", "invalidValue")
		return
	}

	var req UserResource
	if !decodeSCIMBody(w, r, &req) {
		return
	}

	if req.UserName == "" {
		WriteSCIMError(w, http.StatusBadRequest, "userName is required", "invalidValue")
		return
	}

	externalID, err := s.sourceSubjectForUser(r.Context(), pathID)
	if err != nil {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("User %s is not managed by this SCIM source", idStr), "invalidValue")
		return
	}
	if req.ExternalID != "" && req.ExternalID != externalID {
		WriteSCIMError(w, http.StatusConflict, "externalId is immutable for this SCIM source", "uniqueness")
		return
	}
	req.ExternalID = externalID
	f := extractUserFields(req)

	id, err := s.applySourceUser(r.Context(), externalID, f, req.Title, pathID)

	if err != nil {
		var he *httpError
		if errors.As(err, &he) {
			WriteSCIMError(w, he.Status, he.Detail, he.ScimType)
			return
		}
		WriteSCIMError(w, s.logReducerError("scim replace user failed", err), "Failed to replace user", "")
		return
	}

	now := time.Now()
	u := userRowToResource(id, &req.ExternalID, &req.UserName, &f.primaryEmail, &f.displayName,
		&f.firstName, &f.lastName, &req.Title, &f.phone, &f.active, now, now)
	if !f.active {
		go RevokeAuthSessions(r.Context(), s.logger, s.authServerURL, s.internalAPIKey, id)
	}

	WriteSCIM(w, http.StatusOK, u)
}

// ── PATCH /scim/v2/Users/{id} ───────────────────────────────────────────────

// PatchUser handles PATCH /scim/v2/Users/{id}.
func (s *Server) PatchUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid user ID", "invalidValue")
		return
	}

	var req PatchRequest
	if !decodeSCIMBody(w, r, &req) {
		return
	}
	current, externalID, err := s.sourceUserForPatch(r.Context(), id)
	if err != nil {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("User %s is not managed by this SCIM source", idStr), "invalidValue")
		return
	}
	touched, err := applyUserPatchTracked(&current, req.Operations)
	if err != nil {
		if scimErr, ok := err.(*httpError); ok {
			WriteSCIMError(w, scimErr.Status, scimErr.Detail, scimErr.ScimType)
		}
		return
	}
	fields := extractUserFields(current)
	if _, err := s.applySourceUserPatch(
		r.Context(), externalID, fields, current.Title, id, touched,
	); err != nil {
		WriteSCIMError(w, s.logReducerError("scim patch user failed", err), "PATCH failed", "")
		return
	}
	if !fields.active {
		go RevokeAuthSessions(r.Context(), s.logger, s.authServerURL, s.internalAPIKey, id)
	}

	// Return updated resource
	s.GetUser(w, r)
}

// ── DELETE /scim/v2/Users/{id} ──────────────────────────────────────────────

// DeleteUser handles DELETE /scim/v2/Users/{id}.
func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strToID(idStr)
	if err != nil {
		WriteSCIMError(w, http.StatusBadRequest, "Invalid user ID", "invalidValue")
		return
	}
	current, externalID, err := s.sourceUserForPatch(r.Context(), id)
	if err != nil {
		WriteSCIMError(w, http.StatusNotFound, fmt.Sprintf("User %s is not managed by this SCIM source", idStr), "invalidValue")
		return
	}
	if deletionPolicy(r.Context()) == "hard" {
		WriteSCIMError(w, http.StatusConflict,
			"hard delete is unavailable for normalized identities; use an identity transition so the subject tombstone is retained",
			"mutability")
		return
	}
	active := false
	current.Active = &active
	fields := extractUserFields(current)
	if _, err = s.applySourceUser(r.Context(), externalID, fields, current.Title, id); err != nil {
		WriteSCIMError(w, s.logReducerError("scim delete user failed", err), "Failed to delete user", "")
		return
	}

	// Notify authserver to revoke sessions (best-effort), keyed on user id.
	go RevokeAuthSessions(r.Context(), s.logger, s.authServerURL, s.internalAPIKey, id)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sourceSubjectForUser(ctx context.Context, userID int64) (string, error) {
	sourceID, ok := ctx.Value(ctxSourceID).(int64)
	if !ok || sourceID <= 0 {
		return "", errors.New("SCIM token is not source-bound")
	}
	var subject string
	err := s.workerPool.QueryRow(ctx, `
		SELECT l.external_subject
		  FROM user_identity_links l
		 WHERE l.source_id = $1 AND l.user_id = $2
		   AND l.state = 'active' AND 'provision' = ANY(l.purposes)
	`, sourceID, userID).Scan(&subject)
	return subject, err
}

func (s *Server) sourceUserForPatch(ctx context.Context, userID int64) (UserResource, string, error) {
	sourceID, ok := scimSourceID(ctx)
	if !ok {
		return UserResource{}, "", errors.New("SCIM token is not source-bound")
	}
	var externalID string
	var username, email, displayName *string
	var firstName, lastName, jobTitle, phone *string
	var department *string
	var enabled *bool
	err := s.workerPool.QueryRow(ctx, `
		SELECT l.external_subject,u.username,u.email,u.display_name,
		       u.first_name,u.last_name,u.job_title,u.phone,d.path,u.enabled
		  FROM user_identity_links l
		  JOIN users u ON u.id=l.user_id
		  LEFT JOIN departments d ON d.id=u.department_id
		 WHERE l.source_id=$1 AND u.id=$2
		   AND l.state='active' AND 'provision'=ANY(l.purposes)
		   AND NOT is_guest_account(u.id)
	`, sourceID, userID).Scan(
		&externalID, &username, &email, &displayName, &firstName, &lastName,
		&jobTitle, &phone, &department, &enabled,
	)
	if err != nil {
		return UserResource{}, "", err
	}
	now := time.Now()
	resource := userRowToResource(userID, &externalID, username, email, displayName,
		firstName, lastName, jobTitle, phone, enabled, now, now)
	if department != nil {
		resource.EntExt = &EnterpriseUserExtension{Department: *department}
	}
	return resource, externalID, nil
}

// revokeTimeout bounds a single revocation call (see revokeClient).
const revokeTimeout = 10 * time.Second

// revokeClient is the dedicated egress client for RevokeAuthSessions
// (D-MAILSERVER-INTERNAL-SCIM-003): an explicit Timeout bounds every
// fire-and-forget revocation call, so an authserver stall cannot accumulate
// hung goroutines/connections per disabled user (http.DefaultClient has no
// timeout and must never carry an outbound call).
var revokeClient = &http.Client{Timeout: revokeTimeout}

// RevokeAuthSessions POSTs to the authserver's internal /auth/scim/disable
// endpoint to revoke every live session for userID. This is the ONE seam
// mailserver uses to reach that endpoint — SCIM delete/disable (above) and the
// admin-console suspend path (mailserver/internal/admin/admin_users.go) both
// call this same function rather than each rolling their own HTTP client.
// Keyed on user id (always present), never scim_external_id (only present for
// SCIM-provisioned accounts). Best-effort: a failure logs and returns — the
// caller's own DB mutation (users.enabled=FALSE) has already committed, and
// the disabled-user check on refresh (authserver/internal/token/refresh.go)
// is the structural guarantee within one access-token TTL; this call is only
// for immediacy. No-op when authServerURL/internalAPIKey are unset.
func RevokeAuthSessions(ctx context.Context, logger *slog.Logger, authServerURL, internalAPIKey string, userID int64) {
	if authServerURL == "" || internalAPIKey == "" {
		return
	}
	// WithoutCancel detaches the call from the caller's request lifetime — the
	// fire-and-forget goroutine must survive the handler returning — while
	// still carrying request-derived values; the explicit timeout alone bounds
	// the call (D-MAILSERVER-INTERNAL-SCIM-003).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		authServerURL+"/auth/scim/disable",
		jsonBody(map[string]int64{"user_id": userID}))
	if err != nil {
		logger.Warn("auth session revoke request build failed", "error", err, "user_id", userID)
		return
	}
	req.Header.Set("Authorization", "Bearer "+internalAPIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := revokeClient.Do(req)
	if err != nil {
		logger.Warn("auth session revoke failed", "error", err, "user_id", userID)
		return
	}
	resp.Body.Close()
}

func jsonBody(v interface{}) *bytes.Reader {
	data, _ := json.Marshal(v)
	return bytes.NewReader(data)
}

// ── Sync Token helpers ─────────────────────────────────────────────────────

func encodeSyncToken(sourceID int64, t time.Time) string {
	data, _ := json.Marshal(struct {
		SourceID  string `json:"sourceId"`
		UpdatedAt string `json:"updatedAt"`
	}{
		SourceID: strconv.FormatInt(sourceID, 10), UpdatedAt: t.Format(time.RFC3339Nano),
	})
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeSyncToken(token string, expectedSourceID int64) (time.Time, error) {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, err
	}
	var payload struct {
		SourceID  string `json:"sourceId"`
		UpdatedAt string `json:"updatedAt"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return time.Time{}, err
	}
	if payload.SourceID != strconv.FormatInt(expectedSourceID, 10) {
		return time.Time{}, errors.New("syncToken belongs to another SCIM source")
	}
	return time.Parse(time.RFC3339Nano, payload.UpdatedAt)
}
