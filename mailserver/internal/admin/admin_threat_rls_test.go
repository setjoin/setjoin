package admin

import "testing"

// admin_threat.go builds its queries with fmt.Sprintf("... FROM %s ...",
// def.table, …) — a DYNAMIC table name the check-rls-coverage.sh literal scanner
// cannot see (native-rls plan, AUTOPLAN GAUNTLET REVIEW F4). A textual guard over
// dynamic builders is a false-positive flood ("from"/"update" are common English
// words), so instead we pin the ACTUAL risk at its source: the viewRegistry's
// table domain must never include a FORCE'd table. If it did, the fmt-built query
// would run un-wrapped on the app pool and fail-CLOSED (0 rows / 42501) at the DSN
// switch. Adding a FORCE'd-table view here must instead wrap it / route it to the
// worker pool (like the eDiscovery/monitor admin handlers) — this test makes the
// silent version un-mergeable.
func TestThreatViewRegistry_NoForcedRLSTables(t *testing.T) {
	// The native-RLS FORCE'd-table set (must match check-rls-coverage.sh RLS_TBL).
	forced := map[string]bool{
		"messages": true, "message_tags": true, "mailbox_delegates": true,
		"delivery_attempts": true, "approval_requests": true,
		"approval_policies": true, "held_inbound_messages": true,
	}
	for name, def := range viewRegistry {
		if forced[def.table] {
			t.Errorf("threat view %q targets FORCE'd table %q via a dynamic fmt.Sprintf builder — "+
				"it would fail-closed at the DSN switch; wrap it in a scoped tx or route it to workerPool "+
				"(see admin eDiscovery) instead of adding it to viewRegistry", name, def.table)
		}
	}
}
