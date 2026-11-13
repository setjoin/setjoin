package threat

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseIDArray(t *testing.T) {
	got := parseIDArray([]byte(`[7, 9, 12]`))
	want := []int64{7, 9, 12}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseIDArray[%d] = %d, want %d", i, got[i], want[i])
		}
	}
	if l := len(parseIDArray([]byte(`[]`))); l != 0 {
		t.Fatalf("empty array len = %d, want 0", l)
	}
	if l := len(parseIDArray(nil)); l != 0 {
		t.Fatalf("nil len = %d, want 0", l)
	}
}

func TestLoadPoliciesStateExclude(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := NewPolicyStore(pool, acrTestLogger())

	// Re-run-safe seed: delete by name first.
	_, _ = pool.Exec(context.Background(),
		`DELETE FROM conditional_access_policies WHERE name IN ('t6_on','t6_report_only','t6_off')`)

	// Note: enabled defaults to TRUE in the schema; the ca_sync_enabled trigger's legacy
	// back-fill path fires when state='off' AND enabled=TRUE and flips state to 'on'.
	// We must explicitly pass enabled=false when seeding state='off' to suppress the flip.
	_, err = pool.Exec(context.Background(),
		`INSERT INTO conditional_access_policies (priority, name, scope_type, scope_target, state, enabled,
			exclude_users, exclude_groups)
		 VALUES
		   (181,'t6_on','user','42', 'on',          true,  '[7,9]'::jsonb, '[3]'::jsonb),
		   (182,'t6_report_only','user','42', 'report_only', false, '[]'::jsonb, '[]'::jsonb),
		   (183,'t6_off','user','42', 'off',         false, '[]'::jsonb, '[]'::jsonb)`)
	if err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM conditional_access_policies WHERE name IN ('t6_on','t6_report_only','t6_off')`)
	}()

	pectx := PolicyEvalContext{UserID: 42}
	rows, err := store.LoadPolicies(context.Background(), pectx)
	if err != nil {
		t.Fatal(err)
	}

	// 'off' policy must be filtered out; 'on' and 'report_only' must be present.
	var foundOn, foundReportOnly, foundOff bool
	for _, r := range rows {
		switch r.Name {
		case "t6_on":
			foundOn = true
			if r.State != "on" {
				t.Errorf("t6_on: State = %q, want 'on'", r.State)
			}
			if len(r.ExcludeUsers) != 2 || r.ExcludeUsers[0] != 7 || r.ExcludeUsers[1] != 9 {
				t.Errorf("t6_on: ExcludeUsers = %v, want [7 9]", r.ExcludeUsers)
			}
			if len(r.ExcludeGroups) != 1 || r.ExcludeGroups[0] != 3 {
				t.Errorf("t6_on: ExcludeGroups = %v, want [3]", r.ExcludeGroups)
			}
		case "t6_report_only":
			foundReportOnly = true
			if r.State != "report_only" {
				t.Errorf("t6_report_only: State = %q, want 'report_only'", r.State)
			}
		case "t6_off":
			foundOff = true
		}
	}
	if !foundOn {
		t.Error("LoadPolicies: 'on' policy not returned")
	}
	if !foundReportOnly {
		t.Error("LoadPolicies: 'report_only' policy not returned")
	}
	if foundOff {
		t.Error("LoadPolicies: 'off' policy was returned but must be filtered out")
	}
}

func TestLoadBreakGlass(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := NewPolicyStore(pool, acrTestLogger())

	// Seed the break-glass set (re-run-safe: upsert).
	_, err = pool.Exec(context.Background(),
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('ca_break_glass_user_ids', '[101,202]'::jsonb, false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	if err != nil {
		t.Fatalf("seed break-glass: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(),
			`UPDATE system_config SET value = '[]'::jsonb WHERE key = 'ca_break_glass_user_ids'`)
	}()

	ids, err := store.LoadBreakGlass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 101 || ids[1] != 202 {
		t.Fatalf("LoadBreakGlass = %v, want [101 202]", ids)
	}
}

func TestExcludeMatches(t *testing.T) {
	tests := []struct {
		name       string
		row        PolicyRow
		userID     int64
		groupIDs   []int64
		breakGlass []int64
		want       bool
	}{
		{"user-direct", PolicyRow{ExcludeUsers: []int64{7}}, 7, nil, nil, true},
		{"group-intersection", PolicyRow{ExcludeGroups: []int64{3, 9}}, 7, []int64{9}, nil, true},
		{"break-glass-set", PolicyRow{}, 7, nil, []int64{7}, true},
		{"no-match", PolicyRow{ExcludeUsers: []int64{8}, ExcludeGroups: []int64{3}}, 7, []int64{9}, []int64{8}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := excludeMatches(tt.row, tt.userID, tt.groupIDs, tt.breakGlass); got != tt.want {
				t.Fatalf("excludeMatches = %v, want %v", got, tt.want)
			}
		})
	}
}
