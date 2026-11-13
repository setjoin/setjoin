package scim

import (
	"encoding/json"
	"errors"
	"testing"
)

func rawPatchValue(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal patch value: %v", err)
	}
	return raw
}

// TestApplyUserPatchMatrix pins the complete in-memory SCIM PATCH language.
// The persistence boundary is separately reducer-tested; this matrix makes
// every accepted mutation and every rejected operation/path explicit.
func TestApplyUserPatchMatrix(t *testing.T) {
	active := true
	base := func() UserResource {
		return UserResource{
			Active:       &active,
			Name:         &Name{GivenName: "Before", FamilyName: "Before"},
			Title:        "Before",
			PhoneNumbers: []PhoneNumberAttr{{Value: "100"}},
		}
	}
	valid := []struct {
		name  string
		op    PatchOperation
		check func(*UserResource) bool
	}{
		{"replace active false", PatchOperation{Op: "replace", Path: "active", Value: rawPatchValue(t, false)}, func(u *UserResource) bool { return u.Active != nil && !*u.Active }},
		{"replace active true via empty path", PatchOperation{Op: "replace", Value: rawPatchValue(t, true)}, func(u *UserResource) bool { return u.Active != nil && *u.Active }},
		{"replace display name", PatchOperation{Op: "replace", Path: "displayName", Value: rawPatchValue(t, "After")}, func(u *UserResource) bool { return u.DisplayName == "After" }},
		{"replace title", PatchOperation{Op: "replace", Path: "title", Value: rawPatchValue(t, "Engineer")}, func(u *UserResource) bool { return u.Title == "Engineer" }},
		{"replace given name allocates name", PatchOperation{Op: "replace", Path: "name.givenName", Value: rawPatchValue(t, "Given")}, func(u *UserResource) bool { return u.Name != nil && u.Name.GivenName == "Given" }},
		{"replace family name allocates name", PatchOperation{Op: "replace", Path: "name.familyName", Value: rawPatchValue(t, "Family")}, func(u *UserResource) bool { return u.Name != nil && u.Name.FamilyName == "Family" }},
		{"replace emails", PatchOperation{Op: "replace", Path: "emails", Value: rawPatchValue(t, []EmailAttr{{Value: "a@example.test"}})}, func(u *UserResource) bool { return len(u.Emails) == 1 && u.Emails[0].Value == "a@example.test" }},
		{"empty emails ignored", PatchOperation{Op: "replace", Path: "emails", Value: rawPatchValue(t, []EmailAttr{})}, func(u *UserResource) bool { return len(u.Emails) == 0 }},
		{"replace phones", PatchOperation{Op: "replace", Path: "phoneNumbers", Value: rawPatchValue(t, []PhoneNumberAttr{{Value: "200"}})}, func(u *UserResource) bool { return len(u.PhoneNumbers) == 1 && u.PhoneNumbers[0].Value == "200" }},
		{"empty phones ignored", PatchOperation{Op: "replace", Path: "phoneNumbers", Value: rawPatchValue(t, []PhoneNumberAttr{})}, func(u *UserResource) bool { return len(u.PhoneNumbers) == 1 }},
		{"replace enterprise department", PatchOperation{Op: "replace", Path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", Value: rawPatchValue(t, "Platform")}, func(u *UserResource) bool { return u.EntExt != nil && u.EntExt.Department == "Platform" }},
		{"add aliases replace", PatchOperation{Op: "add", Path: "title", Value: rawPatchValue(t, "Added")}, func(u *UserResource) bool { return u.Title == "Added" }},
		{"remove phones", PatchOperation{Op: "remove", Path: "phoneNumbers.value"}, func(u *UserResource) bool { return u.PhoneNumbers == nil }},
		{"remove title", PatchOperation{Op: "remove", Path: "title"}, func(u *UserResource) bool { return u.Title == "" }},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			user := base()
			if tc.name == "replace given name allocates name" || tc.name == "replace family name allocates name" {
				user.Name = nil
			}
			if tc.name == "empty emails ignored" {
				user.Emails = nil
			}
			if err := applyUserPatch(&user, []PatchOperation{tc.op}); err != nil {
				t.Fatalf("apply patch: %v", err)
			}
			if !tc.check(&user) {
				t.Fatalf("patch did not produce expected resource: %+v", user)
			}
		})
	}

	invalid := []PatchOperation{
		{Op: "move", Path: "title", Value: rawPatchValue(t, "x")},
		{Op: "replace", Path: "active", Value: json.RawMessage(`"not-bool"`)},
		{Op: "replace", Path: "displayName", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "title", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "name.givenName", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "name.familyName", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "emails", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "phoneNumbers", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", Value: json.RawMessage(`false`)},
		{Op: "replace", Path: "unknown", Value: rawPatchValue(t, "x")},
		{Op: "add", Path: "unknown", Value: rawPatchValue(t, "x")},
		{Op: "remove", Path: "active"},
		{Op: "remove", Path: "displayName"},
	}
	for i, op := range invalid {
		user := base()
		err := applyUserPatch(&user, []PatchOperation{op})
		var scimErr *httpError
		if !errors.As(err, &scimErr) || scimErr.Status != 400 {
			t.Errorf("invalid case %d returned %v, want SCIM 400", i, err)
		}
	}

	user := base()
	if err := applyUserPatch(&user, []PatchOperation{
		{Op: "replace", Path: "title", Value: rawPatchValue(t, "First")},
		{Op: "remove", Path: "displayName"},
		{Op: "replace", Path: "title", Value: rawPatchValue(t, "Never")},
	}); err == nil {
		t.Fatal("multi-operation patch must stop at the first invalid operation")
	}
	if user.Title != "First" {
		t.Fatalf("patch continued after error: title=%q", user.Title)
	}

	if got := canonicalUserPatchField("customExtension"); got != "customextension" {
		t.Fatalf("canonical unknown field=%q", got)
	}
}
