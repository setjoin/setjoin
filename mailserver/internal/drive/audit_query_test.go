package drive

// Live (DB-backed) tests for P6 Task 11: audit query, CSV export (incl. the
// CSV-injection guard), and alarm rule CRUD.

import (
	"context"
	"encoding/csv"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/toggle"
)

func TestAuditQuery_ManagerMemberAdmin(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvauqOwner")
	viewer := driveLiveUser(t, pool, "drvauqViewer")
	admin := driveLiveUser(t, pool, "drvauqAdmin")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	rr := driveLiveDo(t, h, owner, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members",
		map[string]any{"userId": viewer, "role": "viewer"})
	if rr.Code != http.StatusOK {
		t.Fatalf("grant viewer: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, admin); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, admin) //nolint:errcheck
	})

	spaceParam := "?space=" + strconv.FormatInt(spaceID, 10)

	// manager (space owner) — own space, 200.
	rr = driveLiveDo(t, h, owner, "GET", "/drive/audit"+spaceParam, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("manager audit query: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// plain member (viewer, non-manager) — 403.
	rr = driveLiveDo(t, h, viewer, "GET", "/drive/audit"+spaceParam, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer audit query: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// drive.view admin, non-member of this space — 200.
	rr = driveLiveDo(t, h, admin, "GET", "/drive/audit"+spaceParam, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin audit query: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// no space param -> 400.
	rr = driveLiveDo(t, h, owner, "GET", "/drive/audit", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no space: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditQuery_KeysetPagination(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvauqPage")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	// Three extra chained 'view' rows on top of whatever space.create wrote.
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(context.Background(),
			`SELECT drive_access_audit($1, $2, 'view', 'node', $3, NULL, NULL, NULL, NULL)`,
			owner, spaceID, int64(i+1)); err != nil {
			t.Fatalf("seed audit row %d: %v", i, err)
		}
	}

	rr := driveLiveDo(t, h, owner, "GET", "/drive/audit?space="+strconv.FormatInt(spaceID, 10)+"&max=2", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("page 1: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var page1 struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
		HasMore bool `json:"hasMore"`
	}
	driveLiveDecode(t, rr, &page1)
	if len(page1.Items) != 2 || !page1.HasMore {
		t.Fatalf("page 1 = %+v, want 2 items + hasMore=true", page1)
	}

	lastID := page1.Items[len(page1.Items)-1].ID
	rr = driveLiveDo(t, h, owner, "GET",
		"/drive/audit?space="+strconv.FormatInt(spaceID, 10)+"&max=2&beforeId="+strconv.FormatInt(lastID, 10), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("page 2: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var page2 struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
		HasMore bool `json:"hasMore"`
	}
	driveLiveDecode(t, rr, &page2)
	for _, it := range page2.Items {
		if it.ID >= lastID {
			t.Fatalf("page 2 item %d overlaps/duplicates page 1's beforeId cursor %d", it.ID, lastID)
		}
	}
}

func TestAuditQuery_CSVExport_FormulaInjectionGuard(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvauqCsv")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	// Crafted corpus (OWASP CSV injection set) + a benign control. Each
	// crafted note must export with the neutralizing leading apostrophe
	// (csvCell → migration.EscapeCSVCell); the benign note must round-trip
	// verbatim.
	seeds := []struct{ name, note, want string }{
		{"hyperlink", `=HYPERLINK("http://evil.example","click")`, `'` + `=HYPERLINK("http://evil.example","click")`},
		{"dde", `=cmd|' /C calc'!A0`, `'` + `=cmd|' /C calc'!A0`},
		{"at-function", `@SUM(1+1)`, `'@SUM(1+1)`},
		{"leading-tab", "\t=1+1", "'\t=1+1"},
		{"benign", "plain audit note", "plain audit note"},
	}
	for i, s := range seeds {
		if _, err := pool.Exec(context.Background(),
			`SELECT drive_access_audit($1, $2, 'view', 'node', $3, NULL, NULL, NULL, $4)`,
			owner, spaceID, int64(i+1), s.note); err != nil {
			t.Fatalf("seed csv audit row %s: %v", s.name, err)
		}
	}

	rr := driveLiveDo(t, h, owner, "GET", "/drive/audit?space="+strconv.FormatInt(spaceID, 10)+"&format=csv", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("csv export: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv prefix", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "drive-audit-") {
		t.Fatalf("Content-Disposition = %q, want a drive-audit-*.csv filename", cd)
	}

	rows, err := csv.NewReader(strings.NewReader(rr.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) < 2 {
		t.Fatalf("csv rows = %v, want header + at least one data row", rows)
	}
	wantHeader := []string{"ID", "Timestamp", "User", "IP", "Action", "Target Type", "Target ID", "Notes"}
	for i, col := range wantHeader {
		if rows[0][i] != col {
			t.Fatalf("csv header[%d] = %q, want %q", i, rows[0][i], col)
		}
	}
	got := map[string]bool{}
	for _, r := range rows[1:] {
		got[r[len(r)-1]] = true
	}
	for _, s := range seeds {
		if !got[s.want] {
			t.Errorf("csv export notes: no cell %q for seed %q (formula-injection guard missing or mangling a benign cell); got %v", s.want, s.name, got)
		}
	}
}

// TestCSVCell_MatchesEscapeCSVCellAuthority pins the delegation: drive's
// writer-seam helper must stay exactly the repo's single tested formula
// neutralization (migration.EscapeCSVCell) — the OWASP crafted corpus comes
// out defused, benign cells pass through unchanged.
func TestCSVCell_MatchesEscapeCSVCellAuthority(t *testing.T) {
	corpus := []string{
		`=cmd|' /C calc'!A0`,
		`@SUM(1+1)`,
		`-2+3+cmd|' /C calc'!A0`,
		`+1+1`,
		"\t=1+1",
		"\r=cmd",
		`'already-quoted`,
		"plain audit note",
		"plain@example.com",
		"192.0.2.1",
		"",
		"delivered=ok",
	}
	for _, in := range corpus {
		if got, want := csvCell(in), migration.EscapeCSVCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want the migration.EscapeCSVCell authority result %q", in, got, want)
		}
	}
}

func TestAlarmCRUD(t *testing.T) {
	pool := driveLivePool(t)
	admin := driveLiveUser(t, pool, "drvalarmAdmin")
	member := driveLiveUser(t, pool, "drvalarmMember")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, admin); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, admin) //nolint:errcheck
	})

	// non-admin POST -> 403.
	rr := driveLiveDo(t, h, member, "POST", "/drive/audit-alarms",
		map[string]any{"actionPattern": "lock.*", "threshold": 3, "windowMinutes": 5})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-admin create: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// unrecognized action pattern -> 422.
	rr = driveLiveDo(t, h, admin, "POST", "/drive/audit-alarms",
		map[string]any{"actionPattern": "totally.bogus", "threshold": 3, "windowMinutes": 5})
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bogus action pattern: want 422, got %d: %s", rr.Code, rr.Body.String())
	}

	// admin create -> 201.
	rr = driveLiveDo(t, h, admin, "POST", "/drive/audit-alarms",
		map[string]any{"actionPattern": "lock.*", "threshold": 3, "windowMinutes": 5})
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin create: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID int64 `json:"id"`
	}
	driveLiveDecode(t, rr, &created)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM drive_audit_alarms WHERE id=$1`, created.ID) //nolint:errcheck
	})

	// list -> includes the seed export.deny rule + our new one.
	rr = driveLiveDo(t, h, admin, "GET", "/drive/audit-alarms", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list alarms: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var alarms []struct {
		ID            int64  `json:"id"`
		ActionPattern string `json:"actionPattern"`
		Enabled       bool   `json:"enabled"`
	}
	driveLiveDecode(t, rr, &alarms)
	var hasSeed, hasOurs bool
	for _, a := range alarms {
		if a.ActionPattern == "export.deny" {
			hasSeed = true
		}
		if a.ID == created.ID {
			hasOurs = true
			if !a.Enabled {
				t.Errorf("new alarm defaults to disabled, want enabled")
			}
		}
	}
	if !hasSeed {
		t.Errorf("alarm list %v missing the seeded export.deny storm detector", alarms)
	}
	if !hasOurs {
		t.Fatalf("alarm list %v missing our created rule %d", alarms, created.ID)
	}

	// non-admin list -> 403 too.
	rr = driveLiveDo(t, h, member, "GET", "/drive/audit-alarms", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-admin list: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// patch toggles enabled off.
	rr = driveLiveDo(t, h, admin, "PATCH", "/drive/audit-alarms/"+strconv.FormatInt(created.ID, 10),
		map[string]any{"enabled": false})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("patch enabled: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var got bool
	if err := pool.QueryRow(context.Background(), `SELECT enabled FROM drive_audit_alarms WHERE id=$1`, created.ID).Scan(&got); err != nil {
		t.Fatalf("verify patch: %v", err)
	}
	if got {
		t.Errorf("enabled = true after PATCH{enabled:false}, want false")
	}

	// patch unknown id -> 404.
	rr = driveLiveDo(t, h, admin, "PATCH", "/drive/audit-alarms/999999999", map[string]any{"enabled": true})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("patch unknown id: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	// delete.
	rr = driveLiveDo(t, h, admin, "DELETE", "/drive/audit-alarms/"+strconv.FormatInt(created.ID, 10), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM drive_audit_alarms WHERE id=$1`, created.ID).Scan(&count); err != nil {
		t.Fatalf("verify delete: %v", err)
	}
	if count != 0 {
		t.Errorf("alarm %d still present after delete", created.ID)
	}

	// delete again -> 404.
	rr = driveLiveDo(t, h, admin, "DELETE", "/drive/audit-alarms/"+strconv.FormatInt(created.ID, 10), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("double delete: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
