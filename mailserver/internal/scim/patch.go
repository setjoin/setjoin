package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// httpError is a helper type for returning SCIM errors from patch operations.
type httpError struct {
	Status   int
	Detail   string
	ScimType string
}

func (e *httpError) Error() string {
	return e.Detail
}

type userPatchFields map[string]bool

func applyUserPatchTracked(user *UserResource, ops []PatchOperation) (userPatchFields, error) {
	touched := userPatchFields{}
	for _, op := range ops {
		switch op.Op {
		case "replace":
			if err := patchUserReplace(user, op); err != nil {
				return nil, err
			}
		case "add":
			if err := patchUserAdd(user, op); err != nil {
				return nil, err
			}
		case "remove":
			if err := patchUserRemove(user, op); err != nil {
				return nil, err
			}
		default:
			return nil, &httpError{
				Status:   400,
				Detail:   fmt.Sprintf("Unsupported PATCH operation: %s", op.Op),
				ScimType: "invalidValue",
			}
		}
		touched[canonicalUserPatchField(op.Path)] = true
	}
	return touched, nil
}

func canonicalUserPatchField(path string) string {
	path = strings.ToLower(path)
	switch {
	case path == "" || path == "active":
		return "active"
	case path == "displayname":
		return "displayName"
	case path == "title":
		return "title"
	case path == "name.givenname":
		return "givenName"
	case path == "name.familyname":
		return "familyName"
	case path == "emails":
		return "emails"
	case path == "phonenumbers" || path == "phonenumbers.value":
		return "phoneNumbers"
	case strings.HasPrefix(path, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:department"):
		return "department"
	default:
		return path
	}
}

func patchUserReplace(user *UserResource, op PatchOperation) error {
	path := strings.ToLower(op.Path)

	switch {
	case path == "" || path == "active":
		var active bool
		if err := json.Unmarshal(op.Value, &active); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for active", ScimType: "invalidValue"}
		}
		if !active {
			user.Active = &active
			return nil
		}
		user.Active = &active
		return nil

	case path == "displayname":
		var val string
		if err := json.Unmarshal(op.Value, &val); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for displayName", ScimType: "invalidValue"}
		}
		user.DisplayName = val
		return nil

	case path == "title":
		var val string
		if err := json.Unmarshal(op.Value, &val); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for title", ScimType: "invalidValue"}
		}
		user.Title = val
		return nil

	case path == "name.givenname" || path == "name.familyname":
		var val string
		if err := json.Unmarshal(op.Value, &val); err != nil {
			field := "name.givenName"
			if path == "name.familyname" {
				field = "name.familyName"
			}
			return &httpError{Status: 400, Detail: "Invalid value for " + field, ScimType: "invalidValue"}
		}
		if user.Name == nil {
			user.Name = &Name{}
		}
		if path == "name.givenname" {
			user.Name.GivenName = val
		} else {
			user.Name.FamilyName = val
		}
		return nil

	case path == "emails":
		var emails []EmailAttr
		if err := json.Unmarshal(op.Value, &emails); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for emails", ScimType: "invalidValue"}
		}
		if len(emails) > 0 && emails[0].Value != "" {
			user.Emails = emails
		}
		return nil

	case path == "phonenumbers":
		var phones []PhoneNumberAttr
		if err := json.Unmarshal(op.Value, &phones); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for phoneNumbers", ScimType: "invalidValue"}
		}
		if len(phones) > 0 {
			user.PhoneNumbers = phones
		}
		return nil

	case strings.HasPrefix(path, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user:department"):
		var val string
		if err := json.Unmarshal(op.Value, &val); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for department", ScimType: "invalidValue"}
		}
		if user.EntExt == nil {
			user.EntExt = &EnterpriseUserExtension{}
		}
		user.EntExt.Department = val
		return nil

	default:
		return &httpError{
			Status:   400,
			Detail:   fmt.Sprintf("Unsupported PATCH path: %s", op.Path),
			ScimType: "invalidPath",
		}
	}
}

func patchUserAdd(user *UserResource, op PatchOperation) error {
	// "add" on a single-valued attribute is equivalent to "replace"
	// For multi-valued, append. We treat most user attributes as single-valued.
	return patchUserReplace(user, PatchOperation{
		Op:    "replace",
		Path:  op.Path,
		Value: op.Value,
	})
}

func patchUserRemove(user *UserResource, op PatchOperation) error {
	path := strings.ToLower(op.Path)

	switch {
	case path == "" || path == "active":
		return &httpError{Status: 400, Detail: "Cannot remove required attribute: active", ScimType: "noTarget"}
	case path == "phonenumbers" || path == "phonenumbers.value":
		user.PhoneNumbers = nil
		return nil
	case path == "title":
		user.Title = ""
		return nil
	default:
		return &httpError{
			Status:   400,
			Detail:   fmt.Sprintf("Cannot remove attribute via PATCH: %s", op.Path),
			ScimType: "noTarget",
		}
	}
}

// applyGroupPatch applies PATCH operations to a Group resource.
func applyGroupPatch(
	s *Server,
	ctx context.Context,
	sourceID, sourceGeneration, groupID int64,
	extID string,
	ops []PatchOperation,
) error {
	for _, op := range ops {
		switch op.Op {
		case "replace":
			if err := patchGroupReplace(s, ctx, sourceID, sourceGeneration, groupID, extID, op); err != nil {
				return err
			}
		case "add":
			if err := patchGroupAdd(s, ctx, sourceID, sourceGeneration, extID, op); err != nil {
				return err
			}
		case "remove":
			if err := patchGroupRemove(s, ctx, sourceID, sourceGeneration, extID, op); err != nil {
				return err
			}
		default:
			return &httpError{
				Status:   400,
				Detail:   fmt.Sprintf("Unsupported PATCH operation: %s", op.Op),
				ScimType: "invalidValue",
			}
		}
	}
	return nil
}

func patchGroupReplace(
	s *Server,
	ctx context.Context,
	sourceID, sourceGeneration, groupID int64,
	extID string,
	op PatchOperation,
) error {
	path := strings.ToLower(op.Path)

	switch {
	case path == "displayname":
		var val string
		if err := json.Unmarshal(op.Value, &val); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for displayName", ScimType: "invalidValue"}
		}
		var updatedGroupID int64
		err := s.pool.QueryRow(ctx,
			`SELECT scim_upsert_group($1, $2, $3, $4)`,
			sourceID, sourceGeneration, extID, val,
		).Scan(&updatedGroupID)
		if err == nil && updatedGroupID != groupID {
			return &httpError{Status: 404, Detail: "Group is not managed by this SCIM source", ScimType: "noTarget"}
		}
		return err

	case path == "members":
		// Replace entire member list
		var members []MemberRef
		if err := json.Unmarshal(op.Value, &members); err != nil {
			return &httpError{Status: 400, Detail: "Invalid value for members", ScimType: "invalidValue"}
		}
		extIDs := make([]string, len(members))
		for i, m := range members {
			extIDs[i] = m.Value
		}
		_, err := s.pool.Exec(ctx,
			`SELECT scim_apply_group_members($1, $2, $3, $4, TRUE)`,
			sourceID, sourceGeneration, extID, extIDs)
		return err

	default:
		return &httpError{
			Status:   400,
			Detail:   fmt.Sprintf("Unsupported PATCH path: %s", op.Path),
			ScimType: "invalidPath",
		}
	}
}

func patchGroupAdd(s *Server, ctx context.Context, sourceID, sourceGeneration int64, extID string, op PatchOperation) error {
	return patchGroupMembership(s, ctx, sourceID, sourceGeneration, extID, op, false)
}

func patchGroupRemove(s *Server, ctx context.Context, sourceID, sourceGeneration int64, extID string, op PatchOperation) error {
	return patchGroupMembership(s, ctx, sourceID, sourceGeneration, extID, op, true)
}

func patchGroupMembership(
	s *Server,
	ctx context.Context,
	sourceID, sourceGeneration int64,
	extID string,
	op PatchOperation,
	remove bool,
) error {
	path := strings.ToLower(op.Path)
	if path != "members" && !strings.HasPrefix(path, "members") {
		if remove {
			return &httpError{
				Status:   400,
				Detail:   fmt.Sprintf("Cannot remove attribute: %s", op.Path),
				ScimType: "noTarget",
			}
		}
		return &httpError{
			Status:   400,
			Detail:   fmt.Sprintf("Unsupported PATCH path: %s", op.Path),
			ScimType: "invalidPath",
		}
	}

	extIDs, err := groupMemberExternalIDs(op.Value)
	if err != nil {
		return err
	}
	if remove {
		_, err = s.pool.Exec(ctx,
			`SELECT scim_remove_group_members($1, $2, $3, $4)`,
			sourceID, sourceGeneration, extID, extIDs)
		return err
	}
	_, err = s.pool.Exec(ctx,
		`SELECT scim_apply_group_members($1, $2, $3, $4, FALSE)`,
		sourceID, sourceGeneration, extID, extIDs)
	return err
}

func groupMemberExternalIDs(raw json.RawMessage) ([]string, error) {
	var members []MemberRef
	if err := json.Unmarshal(raw, &members); err != nil {
		var single MemberRef
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, &httpError{
				Status: 400, Detail: "Invalid value for members", ScimType: "invalidValue",
			}
		}
		members = []MemberRef{single}
	}
	extIDs := make([]string, len(members))
	for i, member := range members {
		extIDs[i] = member.Value
	}
	return extIDs, nil
}
