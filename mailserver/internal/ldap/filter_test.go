package ldap

import (
	"strings"
	"testing"
)

// TestApplyFilterNestedAndPerOU is the regression for two LDAP search bugs:
//
//   - Nested boolean groups: the old hand-rolled parser only recognized &/|/!
//     at the top level, so a nested group child like (|(cn=jo*)(mail=jo*)) — the
//     common Outlook/Thunderbird GAL shape — was mis-parsed as a single bogus
//     assertion and the real OR terms were silently dropped.
//   - Flat column map applied to four different tables: attributes were mapped
//     to a single users-shaped schema, so terms referenced columns absent from
//     the target table (objectClass anywhere, the dept_name SELECT alias in a
//     WHERE, mail on contacts) and the query errored with OperationsError.
func TestApplyFilterNestedAndPerOU(t *testing.T) {
	tests := []struct {
		name            string
		filter          string
		ou              string
		wantSQLContains []string
		wantSQLAbsent   []string
		wantArgs        []interface{}
	}{
		{
			name:            "nested OR inside AND keeps BOTH leaf terms",
			filter:          "(&(objectClass=*)(|(cn=jo*)(mail=jo*)))",
			ou:              "people",
			wantSQLContains: []string{"v.display_name ILIKE $1", "v.address_blob ILIKE $2", " OR "},
			wantSQLAbsent:   []string{"object_class"},
			wantArgs:        []interface{}{"%jo%", "%jo%"},
		},
		{
			name:            "standalone nested OR",
			filter:          "(|(cn=jo*)(mail=jo*))",
			ou:              "people",
			wantSQLContains: []string{"v.display_name ILIKE $1", "v.address_blob ILIKE $2"},
			wantArgs:        []interface{}{"%jo%", "%jo%"},
		},
		{
			name:            "people department resolves d.name, not the dept_name alias",
			filter:          "(department=eng)",
			ou:              "people",
			wantSQLContains: []string{"d.name ILIKE $1"},
			wantSQLAbsent:   []string{"dept_name"},
			wantArgs:        []interface{}{"%eng%"},
		},
		{
			name:     "people objectClass term is dropped (no object_class column anywhere)",
			filter:   "(objectClass=person)",
			ou:       "people",
			wantArgs: nil,
		},
		{
			name:     "contacts mail has no scalar column -> dropped, not OperationsError",
			filter:   "(mail=foo@bar.com)",
			ou:       "contacts",
			wantArgs: nil,
		},
		{
			name:            "contacts company maps to c.company",
			filter:          "(o=acme)",
			ou:              "contacts",
			wantSQLContains: []string{"c.company ILIKE $1"},
			wantArgs:        []interface{}{"%acme%"},
		},
		{
			name:            "groups cn maps to m.display_name (group identity lives on the mailbox)",
			filter:          "(cn=sales)",
			ou:              "groups",
			wantSQLContains: []string{"m.display_name ILIKE $1"},
			wantArgs:        []interface{}{"%sales%"},
		},
		{
			name:            "NOT wraps the negated leaf",
			filter:          "(!(cn=admin))",
			ou:              "people",
			wantSQLContains: []string{"NOT (", "v.display_name ILIKE $1"},
			wantArgs:        []interface{}{"%admin%"},
		},
		{
			name:            "exact mail equality (no wildcard) stays exact",
			filter:          "(mail=jo@x.com)",
			ou:              "people",
			wantSQLContains: []string{"jsonb_array_elements(v.addresses)", "LOWER(address->>'email') = LOWER($1)"},
			wantArgs:        []interface{}{"jo@x.com"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sql, args := applyFilter(tc.filter, 0, tc.ou)
			for _, want := range tc.wantSQLContains {
				if !strings.Contains(sql, want) {
					t.Errorf("filter %q ou=%s: SQL %q missing %q", tc.filter, tc.ou, sql, want)
				}
			}
			for _, absent := range tc.wantSQLAbsent {
				if strings.Contains(sql, absent) {
					t.Errorf("filter %q ou=%s: SQL %q must not contain %q", tc.filter, tc.ou, sql, absent)
				}
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("filter %q ou=%s: got %d args %v, want %d %v",
					tc.filter, tc.ou, len(args), args, len(tc.wantArgs), tc.wantArgs)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Errorf("filter %q arg[%d] = %v, want %v", tc.filter, i, args[i], tc.wantArgs[i])
				}
			}
		})
	}
}

// TestParseFilterMalformed ensures the parser rejects unbalanced input rather
// than panicking or silently mis-parsing.
func TestParseFilterMalformed(t *testing.T) {
	for _, f := range []string{"(&(cn=a)", "(", "(|)"} {
		if _, err := parseFilter(f); err == nil {
			t.Errorf("parseFilter(%q): expected error, got nil", f)
		}
	}
}
