package threat

import "testing"

func TestScopeMatchesRole(t *testing.T) {
	cases := []struct {
		name        string
		scopeTarget string
		roleGroups  []int64
		want        bool
	}{
		{"role in set", "1", []int64{1, 5}, true},
		{"role not in set", "9", []int64{1, 5}, false},
		{"empty target", "", []int64{1}, false},
		{"empty roles", "1", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeMatches("role", tc.scopeTarget, 42, []int64{99}, tc.roleGroups, false)
			if got != tc.want {
				t.Fatalf("scopeMatches(role, %q, roleGroups=%v) = %v, want %v", tc.scopeTarget, tc.roleGroups, got, tc.want)
			}
		})
	}
}
