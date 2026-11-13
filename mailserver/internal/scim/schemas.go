// Package scim implements a SCIM 2.0 server (RFC 7644) for IdP-driven user and group provisioning.
package scim

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// ── SCIM Core Resource Types (RFC 7643 §4) ──────────────────────────────────

// UserResource is the SCIM User representation (RFC 7643 §4.1).
type UserResource struct {
	Schemas      []string                 `json:"schemas"`
	ID           string                   `json:"id,omitempty"`
	ExternalID   string                   `json:"externalId,omitempty"`
	UserName     string                   `json:"userName,omitempty"`
	Name         *Name                    `json:"name,omitempty"`
	DisplayName  string                   `json:"displayName,omitempty"`
	Emails       []EmailAttr              `json:"emails,omitempty"`
	PhoneNumbers []PhoneNumberAttr        `json:"phoneNumbers,omitempty"`
	Title        string                   `json:"title,omitempty"`
	Active       *bool                    `json:"active,omitempty"`
	Groups       []GroupRef               `json:"groups,omitempty"`
	Meta         *Meta                    `json:"meta,omitempty"`
	EntExt       *EnterpriseUserExtension `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// GroupResource is the SCIM Group representation (RFC 7643 §4.2).
type GroupResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Members     []MemberRef `json:"members,omitempty"`
	Meta        *Meta       `json:"meta,omitempty"`
}

// EnterpriseUserExtension is the SCIM Enterprise User extension (RFC 7643 §4.3).
type EnterpriseUserExtension struct {
	EmployeeNumber string      `json:"employeeNumber,omitempty"`
	Department     string      `json:"department,omitempty"`
	Manager        *ManagerRef `json:"manager,omitempty"`
}

// ── Sub-Types ───────────────────────────────────────────────────────────────

// Name is the SCIM name complex attribute.
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// EmailAttr is a SCIM email multi-valued attribute.
type EmailAttr struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"` // "work", "home", "other"
	Primary *bool  `json:"primary,omitempty"`
}

// PhoneNumberAttr is a SCIM phone number multi-valued attribute.
type PhoneNumberAttr struct {
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"`
}

// MemberRef is a SCIM Group member reference.
type MemberRef struct {
	Value   string `json:"value,omitempty"`   // user's scim_external_id or id
	Display string `json:"display,omitempty"` // user's display_name
	Ref     string `json:"$ref,omitempty"`    // URL to user SCIM resource
	Type    string `json:"type,omitempty"`    // "User" or "Group"
}

// GroupRef is a SCIM User group reference (groups the user belongs to).
type GroupRef struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ManagerRef is a SCIM Enterprise User manager reference.
type ManagerRef struct {
	Value       string `json:"value,omitempty"` // manager's scim_external_id or id
	DisplayName string `json:"displayName,omitempty"`
	Ref         string `json:"$ref,omitempty"`
}

// Meta is the SCIM common metadata attribute.
type Meta struct {
	ResourceType string `json:"resourceType,omitempty"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
	Version      string `json:"version,omitempty"`
}

// ── List / PATCH / Error Types (RFC 7644 §3.4.2, §3.5.2, §3.12) ────────────

// ListResponse is the SCIM list/search response.
type ListResponse struct {
	Schemas      []string        `json:"schemas"`
	TotalResults int             `json:"totalResults"`
	StartIndex   int             `json:"startIndex"`
	ItemsPerPage int             `json:"itemsPerPage"`
	Resources    json.RawMessage `json:"Resources"`
}

// PatchRequest is a SCIM PATCH request body (RFC 7644 §3.5.2).
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is a single PATCH operation.
type PatchOperation struct {
	Op    string          `json:"op"` // "add", "replace", "remove"
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// SCIMError is the standard SCIM error response (RFC 7644 §3.12).
type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   int      `json:"status,string"`
	ScimType string   `json:"scimType,omitempty"`
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// Const SCIM schemas URIs.
const (
	SchemaUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError          = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
)

// DefaultUserSchemas is the schemas array for a User resource.
var DefaultUserSchemas = []string{SchemaUser, SchemaEnterpriseUser}

// DefaultGroupSchemas is the schemas array for a Group resource.
var DefaultGroupSchemas = []string{SchemaGroup}

// ContentTypeSCIM is the SCIM content type.
const ContentTypeSCIM = "application/scim+json"

// NewSCIMError creates a SCIM error response body.
func NewSCIMError(status int, detail, scimType string) SCIMError {
	return SCIMError{
		Schemas:  []string{SchemaError},
		Detail:   detail,
		Status:   status,
		ScimType: scimType,
	}
}

// WriteSCIMError writes a SCIM-formatted error response.
func WriteSCIMError(w http.ResponseWriter, status int, detail, scimType string) {
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(NewSCIMError(status, detail, scimType))
}

// WriteSCIM writes a SCIM JSON response with the correct content type.
func WriteSCIM(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// idToStr converts an int64 ID to a string for SCIM resources.
func idToStr(id int64) string {
	return strconv.FormatInt(id, 10)
}

// strToID converts a SCIM resource ID string to int64.
func strToID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
