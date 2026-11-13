package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// ── null-vs-[] regression suite ─────────────────────────────────────────────
//
// The bug: several list handlers declared their output slice as `var out []T`
// (a nil slice) instead of `out := []T{}`. encoding/json marshals a nil slice
// as the JSON literal `null`, not `[]` — a footgun for every client that calls
// `.map`/`.forEach` on the response and gets a TypeError on an empty result.
// Fixed across 21 handlers; these tests pin representative members of that
// class so a future edit reverting `out := []T{}` back to `var out []T` fails
// loudly instead of shipping a null-vs-[] regression silently.

// TestAdminUsersList_EmptyReturnsArrayNotNull pins admin_users.go List: a
// zero-match query must respond "[]", not JSON null.
func TestAdminUsersList_EmptyReturnsArrayNotNull(t *testing.T) {
	pool := mailboxTestPool(t)
	logger := mailboxTestLogger()
	h := NewUsersHandler(pool, pgxutil.WorkerPool{Pool: pool}, logger, nil, "", "")

	suffix := mailboxRandomSuffix(t)
	q := "no-such-user-zzz-" + suffix + "@nowhere.invalid"
	req := httptest.NewRequest(http.MethodGet, "/admin/users?q="+q, nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("List: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	body := strings.TrimSpace(rec.Body.String())
	if body == "null" {
		t.Fatalf(`List with zero matches returned JSON null, want "[]"`)
	}
	var out []UserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not a JSON array: %v (body=%s)", err, body)
	}
	if len(out) != 0 {
		t.Fatalf("expected zero results for query %q, got %d", q, len(out))
	}
}

// TestAdminRolesGetRole_EmptyMembersReturnsArrayNotNull pins admin_roles.go
// fetchMembers (embedded in GetRole's "members" key — there is no standalone
// GET /admin/roles/{id}/members route, membership is nested in GetRole): a
// freshly created role with zero assignments must report "members": [], not
// JSON null.
func TestAdminRolesGetRole_EmptyMembersReturnsArrayNotNull(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewRolesHandler(pool, testsupport.TestLogger())

	suffix := rolesTestRandomSuffix(t)
	roleID := rolesTestCreateRole(t, pool, "empty-members-"+suffix)

	req := httptest.NewRequest(http.MethodGet, "/admin/roles/"+strconv.FormatInt(roleID, 10), nil)
	req.SetPathValue("id", strconv.FormatInt(roleID, 10))
	rec := httptest.NewRecorder()
	h.GetRole(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GetRole: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Members json.RawMessage `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode GetRole response: %v (body=%s)", err, rec.Body.String())
	}
	membersBody := strings.TrimSpace(string(resp.Members))
	if membersBody == "null" || membersBody == "" {
		t.Fatalf(`GetRole "members" is JSON null for a role with zero members, want "[]" (body=%s)`, rec.Body.String())
	}
	var members []roleMember
	if err := json.Unmarshal(resp.Members, &members); err != nil {
		t.Fatalf(`"members" is not a JSON array: %v (%s)`, err, membersBody)
	}
	if len(members) != 0 {
		t.Fatalf("expected zero members for a freshly created role, got %d", len(members))
	}
}
