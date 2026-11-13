package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/testsupport"
)

func TestLegacyDirectorySyncLogsUseCurrentSchema(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	adHandler := NewADHandler(pool, logger, &config.Config{})
	ldapHandler := NewLDAPHandler(pool, logger)
	ctx := context.Background()
	marker := fmt.Sprintf("legacy-directory-%d", time.Now().UnixNano())

	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sync_log (
			source, users_checked, users_created, users_updated, users_disabled,
			fields_skipped, conflicts_found, duration_ms, error, details
		) VALUES
			('ad', 11, 2, 3, 4, 5, 6, 1750, NULL, jsonb_build_object('marker', $1::text)),
			('ldap', 21, 12, 13, 14, 15, 16, 2500, 'bind failed', jsonb_build_object('marker', $1::text))`, marker); err != nil {
		t.Fatalf("seed sync logs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM identity_sync_log WHERE details->>'marker' = $1`, marker)
	})

	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		want    map[string]int
	}{
		{name: "ad", handler: adHandler.GetSyncLog, want: map[string]int{"checked": 11, "created": 2, "updated": 3, "disabled": 4, "skipped": 5, "errors": 0, "durationSeconds": 1}},
		{name: "ldap", handler: ldapHandler.GetSyncLog, want: map[string]int{"checked": 21, "created": 12, "updated": 13, "disabled": 14, "skipped": 15, "errors": 1, "durationSeconds": 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/"+tc.name+"/sync-log?limit=100", nil)
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GetSyncLog: got %d body=%s, want 200", rec.Code, rec.Body.String())
			}
			var rows []map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			var found map[string]any
			for _, row := range rows {
				details, _ := row["details"].(map[string]any)
				if details["marker"] == marker {
					found = row
					break
				}
			}
			if found == nil {
				t.Fatalf("fixture row missing from %+v", rows)
			}
			for field, want := range tc.want {
				if got := int(found[field].(float64)); got != want {
					t.Fatalf("%s=%d, want %d in %+v", field, got, want, found)
				}
			}
		})
	}
}

func TestADConflictsUseTextColumnsSourceAndDomainScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var domainA, domainB, mailboxA, mailboxB, userA, userB int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, "ad-conflict-a-"+suffix+".test").Scan(&domainA); err != nil {
		t.Fatalf("seed domain A: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, "ad-conflict-b-"+suffix+".test").Scan(&domainB); err != nil {
		t.Fatalf("seed domain B: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "ad-conflict-a-"+suffix).Scan(&mailboxA); err != nil {
		t.Fatalf("seed account A: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "ad-conflict-b-"+suffix).Scan(&mailboxB); err != nil {
		t.Fatalf("seed account B: %v", err)
	}
	if err := pool.QueryRow(ctx, `UPDATE users SET domain_id=$2 WHERE id=(SELECT user_id FROM mailboxes WHERE id=$1) RETURNING id`, mailboxA, domainA).Scan(&userA); err != nil {
		t.Fatalf("scope user A: %v", err)
	}
	if err := pool.QueryRow(ctx, `UPDATE users SET domain_id=$2 WHERE id=(SELECT user_id FROM mailboxes WHERE id=$1) RETURNING id`, mailboxB, domainB).Scan(&userB); err != nil {
		t.Fatalf("scope user B: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source)
		VALUES ($1, 'display_name', 'local-a', 'remote-a', 'ad'),
		       ($1, 'title', 'ldap-local', 'ldap-remote', 'ldap'),
		       ($2, 'display_name', 'local-b', 'remote-b', 'ad')`, userA, userB); err != nil {
		t.Fatalf("seed conflicts: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id IN ($1, $2)`, domainA, domainB)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/ad/conflicts", nil)
	req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainA))
	rec := httptest.NewRecorder()
	h.Conflicts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Conflicts: got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var conflicts []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &conflicts); err != nil {
		t.Fatalf("decode conflicts: %v", err)
	}
	if len(conflicts) != 1 || conflicts[0]["localValue"] != "local-a" || conflicts[0]["remoteValue"] != "remote-a" {
		t.Fatalf("conflicts=%+v, want only domain A AD conflict", conflicts)
	}
}

func TestADConflictResolutionMapsWireValuesAndPreservesScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var domainA, domainB, mailboxA, mailboxB, userA, userB, conflictA, conflictB int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, "ad-resolve-a-"+suffix+".test").Scan(&domainA); err != nil {
		t.Fatalf("seed domain A: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, "ad-resolve-b-"+suffix+".test").Scan(&domainB); err != nil {
		t.Fatalf("seed domain B: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "ad-resolve-a-"+suffix).Scan(&mailboxA); err != nil {
		t.Fatalf("seed account A: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, "ad-resolve-b-"+suffix).Scan(&mailboxB); err != nil {
		t.Fatalf("seed account B: %v", err)
	}
	if err := pool.QueryRow(ctx, `UPDATE users SET domain_id=$2 WHERE id=(SELECT user_id FROM mailboxes WHERE id=$1) RETURNING id`, mailboxA, domainA).Scan(&userA); err != nil {
		t.Fatalf("scope user A: %v", err)
	}
	if err := pool.QueryRow(ctx, `UPDATE users SET domain_id=$2 WHERE id=(SELECT user_id FROM mailboxes WHERE id=$1) RETURNING id`, mailboxB, domainB).Scan(&userB); err != nil {
		t.Fatalf("scope user B: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'title', 'a', 'A', 'ad') RETURNING id`, userA).Scan(&conflictA); err != nil {
		t.Fatalf("seed conflict A: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'title', 'b', 'B', 'ad') RETURNING id`, userB).Scan(&conflictB); err != nil {
		t.Fatalf("seed conflict B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id IN ($1, $2)`, domainA, domainB)
	})

	resolve := func(id int64, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/ad/conflicts/%d", id), bytes.NewBufferString(body))
		req.SetPathValue("id", fmt.Sprintf("%d", id))
		req = req.WithContext(middleware.ContextWithDomainScope(req.Context(), domainA))
		rec := httptest.NewRecorder()
		h.ResolveConflict(rec, req)
		return rec
	}

	if rec := resolve(conflictA, `{"resolution":"keep_local"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("resolve local: got %d body=%s", rec.Code, rec.Body.String())
	}
	var resolution string
	if err := pool.QueryRow(ctx, `SELECT resolution FROM sync_conflicts WHERE id=$1`, conflictA).Scan(&resolution); err != nil || resolution != "kept_local" {
		t.Fatalf("stored resolution=%q err=%v, want kept_local", resolution, err)
	}
	if rec := resolve(conflictB, `{"resolution":"accept_remote"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-domain resolve: got %d body=%s, want 404", rec.Code, rec.Body.String())
	}
	var resolvedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT resolved_at FROM sync_conflicts WHERE id=$1`, conflictB).Scan(&resolvedAt); err != nil || resolvedAt != nil {
		t.Fatalf("cross-domain conflict changed: resolvedAt=%v err=%v", resolvedAt, err)
	}

	var conflictA2, ldapConflictA int64
	if err := pool.QueryRow(ctx, `INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'department', 'old', 'new', 'ad') RETURNING id`, userA).Scan(&conflictA2); err != nil {
		t.Fatalf("seed second AD conflict: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'department', 'old', 'new', 'ldap') RETURNING id`, userA).Scan(&ldapConflictA); err != nil {
		t.Fatalf("seed LDAP conflict: %v", err)
	}
	bulkReq := httptest.NewRequest(http.MethodPost, "/api/admin/ad/conflicts/resolve-all", bytes.NewBufferString(`{"resolution":"accept_remote"}`))
	bulkReq = bulkReq.WithContext(middleware.ContextWithDomainScope(bulkReq.Context(), domainA))
	bulkRec := httptest.NewRecorder()
	h.ResolveAllConflicts(bulkRec, bulkReq)
	if bulkRec.Code != http.StatusNoContent {
		t.Fatalf("bulk resolve: got %d body=%s", bulkRec.Code, bulkRec.Body.String())
	}
	var resolutionA2 string
	if err := pool.QueryRow(ctx, `SELECT resolution FROM sync_conflicts WHERE id=$1`, conflictA2).Scan(&resolutionA2); err != nil || resolutionA2 != "accepted_remote" {
		t.Fatalf("bulk stored resolution=%q err=%v, want accepted_remote", resolutionA2, err)
	}
	for _, untouched := range []int64{conflictB, ldapConflictA} {
		resolvedAt = nil
		if err := pool.QueryRow(ctx, `SELECT resolved_at FROM sync_conflicts WHERE id=$1`, untouched).Scan(&resolvedAt); err != nil || resolvedAt != nil {
			t.Fatalf("out-of-scope conflict %d changed: resolvedAt=%v err=%v", untouched, resolvedAt, err)
		}
	}
}
