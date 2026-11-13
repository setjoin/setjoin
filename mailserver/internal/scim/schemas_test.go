package scim

import (
	"encoding/json"
	"testing"
)

func TestUserResource_JSONRoundTrip(t *testing.T) {
	active := true
	primary := true
	user := UserResource{
		Schemas:    DefaultUserSchemas,
		ID:         "42",
		ExternalID: "entra-id-abc123",
		UserName:   "alice@example.com",
		Name: &Name{
			Formatted:  "Alice Smith",
			FamilyName: "Smith",
			GivenName:  "Alice",
		},
		DisplayName: "Alice Smith",
		Emails: []EmailAttr{
			{Value: "alice@example.com", Type: "work", Primary: &primary},
		},
		PhoneNumbers: []PhoneNumberAttr{
			{Value: "+1555001", Type: "work"},
		},
		Title:  "Engineer",
		Active: &active,
		EntExt: &EnterpriseUserExtension{
			Department:     "Engineering",
			EmployeeNumber: "E-123",
			Manager: &ManagerRef{
				Value:       "entra-id-mgr-001",
				DisplayName: "Bob Manager",
			},
		},
		Meta: &Meta{
			ResourceType: "User",
			Location:     "/scim/v2/Users/42",
		},
	}

	// Marshal
	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("marshal UserResource: %v", err)
	}

	// Unmarshal
	var decoded UserResource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal UserResource: %v", err)
	}

	if decoded.ID != "42" {
		t.Errorf("expected id=42, got %q", decoded.ID)
	}
	if decoded.ExternalID != "entra-id-abc123" {
		t.Errorf("expected externalId=entra-id-abc123, got %q", decoded.ExternalID)
	}
	if decoded.UserName != "alice@example.com" {
		t.Errorf("expected userName=alice@example.com, got %q", decoded.UserName)
	}
	if decoded.DisplayName != "Alice Smith" {
		t.Errorf("expected displayName=Alice Smith, got %q", decoded.DisplayName)
	}
	if decoded.Name == nil {
		t.Fatal("name is nil")
	}
	if decoded.Name.FamilyName != "Smith" {
		t.Errorf("expected name.familyName=Smith, got %q", decoded.Name.FamilyName)
	}
	if decoded.Name.GivenName != "Alice" {
		t.Errorf("expected name.givenName=Alice, got %q", decoded.Name.GivenName)
	}
	if len(decoded.Emails) != 1 {
		t.Fatalf("expected 1 email, got %d", len(decoded.Emails))
	}
	if decoded.Emails[0].Value != "alice@example.com" {
		t.Errorf("expected emails[0].value=alice@example.com, got %q", decoded.Emails[0].Value)
	}
	if decoded.Title != "Engineer" {
		t.Errorf("expected title=Engineer, got %q", decoded.Title)
	}
	if decoded.Active == nil || !*decoded.Active {
		t.Error("expected active=true")
	}
	if decoded.EntExt == nil {
		t.Fatal("enterprise extension is nil")
	}
	if decoded.EntExt.Department != "Engineering" {
		t.Errorf("expected department=Engineering, got %q", decoded.EntExt.Department)
	}
	if decoded.EntExt.EmployeeNumber != "E-123" {
		t.Errorf("expected employeeNumber=E-123, got %q", decoded.EntExt.EmployeeNumber)
	}
	if decoded.EntExt.Manager == nil {
		t.Fatal("manager is nil")
	}
	if decoded.EntExt.Manager.Value != "entra-id-mgr-001" {
		t.Errorf("expected manager.value=entra-id-mgr-001, got %q", decoded.EntExt.Manager.Value)
	}
}

func TestGroupResource_JSONRoundTrip(t *testing.T) {
	group := GroupResource{
		Schemas:     DefaultGroupSchemas,
		ID:          "7",
		ExternalID:  "entra-group-xyz",
		DisplayName: "Engineering Team",
		Members: []MemberRef{
			{
				Value:   "entra-id-abc123",
				Display: "Alice Smith",
				Type:    "User",
				Ref:     "/scim/v2/Users/42",
			},
		},
		Meta: &Meta{
			ResourceType: "Group",
			Location:     "/scim/v2/Groups/7",
		},
	}

	data, err := json.Marshal(group)
	if err != nil {
		t.Fatalf("marshal GroupResource: %v", err)
	}

	var decoded GroupResource
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal GroupResource: %v", err)
	}

	if decoded.ID != "7" {
		t.Errorf("expected id=7, got %q", decoded.ID)
	}
	if decoded.DisplayName != "Engineering Team" {
		t.Errorf("expected displayName=Engineering Team, got %q", decoded.DisplayName)
	}
	if len(decoded.Members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(decoded.Members))
	}
	if decoded.Members[0].Value != "entra-id-abc123" {
		t.Errorf("expected members[0].value=entra-id-abc123, got %q", decoded.Members[0].Value)
	}
}

func TestSCIMError_Format(t *testing.T) {
	errResp := NewSCIMError(404, "User not found", "invalidValue")

	if errResp.Status != 404 {
		t.Errorf("expected status 404, got %d", errResp.Status)
	}
	if errResp.Detail != "User not found" {
		t.Errorf("expected detail='User not found', got %q", errResp.Detail)
	}
	if errResp.ScimType != "invalidValue" {
		t.Errorf("expected scimType=invalidValue, got %q", errResp.ScimType)
	}
	if len(errResp.Schemas) != 1 || errResp.Schemas[0] != SchemaError {
		t.Errorf("expected schemas containing %s, got %v", SchemaError, errResp.Schemas)
	}

	data, err := json.Marshal(errResp)
	if err != nil {
		t.Fatalf("marshal SCIMError: %v", err)
	}

	// RFC 7644 §3.12: status must be a string in JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal SCIMError: %v", err)
	}
	if _, ok := raw["status"]; !ok {
		t.Error("status field missing")
	}
	// Status should be serialized as a string per the ,string tag
	if _, ok := raw["status"].(string); !ok {
		t.Errorf("status should be a string, got %T", raw["status"])
	}
}

func TestListResponse_JSONRoundTrip(t *testing.T) {
	resources := json.RawMessage(`[{"id":"1","userName":"alice"}]`)
	list := ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: 1,
		StartIndex:   1,
		ItemsPerPage: 100,
		Resources:    resources,
	}

	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal ListResponse: %v", err)
	}

	var decoded ListResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal ListResponse: %v", err)
	}
	if decoded.TotalResults != 1 {
		t.Errorf("expected totalResults=1, got %d", decoded.TotalResults)
	}
}

func TestPatchRequest_Parse(t *testing.T) {
	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [
			{"op": "replace", "path": "active", "value": false},
			{"op": "add", "path": "phoneNumbers", "value": [{"value": "+1555001", "type": "work"}]}
		]
	}`

	var pr PatchRequest
	if err := json.Unmarshal([]byte(body), &pr); err != nil {
		t.Fatalf("unmarshal PatchRequest: %v", err)
	}
	if len(pr.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(pr.Operations))
	}
	if pr.Operations[0].Op != "replace" {
		t.Errorf("expected op=replace, got %q", pr.Operations[0].Op)
	}
	if pr.Operations[1].Op != "add" {
		t.Errorf("expected op=add, got %q", pr.Operations[1].Op)
	}
}
