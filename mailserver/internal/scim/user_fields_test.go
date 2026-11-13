package scim

import "testing"

func TestExtractUserFields(t *testing.T) {
	tests := []struct {
		name string
		req  UserResource
		want scimUserFields
	}{
		{
			name: "displayName falls back to Name.Formatted",
			req: UserResource{
				UserName: "alice@example.com",
				Name:     &Name{Formatted: "Alice Smith", GivenName: "Alice", FamilyName: "Smith"},
			},
			want: scimUserFields{
				displayName: "Alice Smith", firstName: "Alice", lastName: "Smith",
				primaryEmail: "alice@example.com", active: true,
			},
		},
		{
			name: "displayName falls back to userName when both empty",
			req:  UserResource{UserName: "bob@example.com"},
			want: scimUserFields{
				displayName: "bob@example.com", primaryEmail: "bob@example.com", active: true,
			},
		},
		{
			name: "primaryEmail falls back to userName when Emails empty",
			req: UserResource{
				UserName:    "carol@example.com",
				DisplayName: "Carol",
			},
			want: scimUserFields{
				displayName: "Carol", primaryEmail: "carol@example.com", active: true,
			},
		},
		{
			name: "active defaults true when Active nil",
			req:  UserResource{UserName: "dave@example.com", DisplayName: "Dave"},
			want: scimUserFields{
				displayName: "Dave", primaryEmail: "dave@example.com", active: true,
			},
		},
		{
			name: "active honored when Active set false",
			req: UserResource{
				UserName:    "eve@example.com",
				DisplayName: "Eve",
				Active:      ptrBool(false),
			},
			want: scimUserFields{
				displayName: "Eve", primaryEmail: "eve@example.com", active: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUserFields(tt.req)
			if got != tt.want {
				t.Errorf("extractUserFields() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func ptrBool(b bool) *bool { return &b }
