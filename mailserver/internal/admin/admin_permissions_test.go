package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func TestPermissionsCatalogList(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewPermissionsHandler(pool, testsupport.TestLogger())

	req := httptest.NewRequest("GET", "/admin/permissions", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	var out []permissionCatalogEntry
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// scope_sets.manage is deliberately absent: v2 keeps it Super-only by
	// seeding the built-in role directly, so it must not appear in the
	// assignable role-editor catalog. Every other registered permission must.
	want := make(map[string]bool, len(permissions.AllPermissions)-1)
	for _, key := range permissions.AllPermissions {
		if key != permissions.PermScopeSetsManage {
			want[key] = true
		}
	}
	if len(out) != len(want) {
		t.Errorf("got %d assignable permissions, want %d", len(out), len(want))
	}
	for _, p := range out {
		if !want[p.Key] {
			t.Errorf("unexpected assignable permission %q", p.Key)
			continue
		}
		delete(want, p.Key)
	}
	for key := range want {
		t.Errorf("registered permission %q missing from assignable catalog", key)
	}
	// Verify ORDER BY category, permission_key from the query.
	for i := 1; i < len(out); i++ {
		prev, cur := out[i-1], out[i]
		if cur.Category < prev.Category || (cur.Category == prev.Category && cur.Key < prev.Key) {
			t.Errorf("result not sorted at index %d: (%s,%s) after (%s,%s)",
				i, cur.Category, cur.Key, prev.Category, prev.Key)
		}
	}
	// Privileged catalog additions must remain visible and sensitive.
	found := map[string]bool{"roles.manage": false, "system.recovery": false}
	for _, p := range out {
		if _, required := found[p.Key]; required {
			found[p.Key] = true
			if !p.IsSensitive {
				t.Errorf("%s should be sensitive", p.Key)
			}
		}
	}
	for key, present := range found {
		if !present {
			t.Errorf("%s missing from catalog", key)
		}
	}
}
