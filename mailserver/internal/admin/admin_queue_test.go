package admin

import "testing"

// TestMapQueueStatus pins the UI-tab → real-status translation. The webmail tabs
// label 'failed'/'held' (operator vocabulary), but outbound_queue's real statuses
// are pending/sending/delivered/bounced/deferred — the old WHERE status=$1 query
// listed nothing for those tabs. This maps them to the real query.
func TestMapQueueStatus(t *testing.T) {
	cases := []struct {
		tab        string
		wantClause string
		wantArg    bool // whether the status value is bound as $1
	}{
		{"failed", "status = 'bounced'", false},
		{"held", "attempt_count >= 10 AND status IN ('deferred','pending')", false},
		{"pending", "status = $1", true},
		{"deferred", "status = $1", true},
		{"", "", false}, // all / no filter
		{"all", "", false},
	}
	for _, c := range cases {
		clause, useArg := mapQueueStatus(c.tab)
		if clause != c.wantClause {
			t.Errorf("mapQueueStatus(%q) clause = %q, want %q", c.tab, clause, c.wantClause)
		}
		if useArg != c.wantArg {
			t.Errorf("mapQueueStatus(%q) useArg = %v, want %v", c.tab, useArg, c.wantArg)
		}
	}
}
