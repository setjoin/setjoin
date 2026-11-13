package admin

// admin_kql_bounds_test.go — med-shard2-020: the handler-boundary half of
// the KQL resource bounds (CWE-674/CWE-405). The parser re-checks every cap
// on each application; these tests pin that the admin handlers enforce the
// same bounds where a compliance.write principal meets the parser:
//   - ContentSearchHandler.Search rejects over-bound KQL with a bounded 400;
//   - EDiscoveryHandler.StartSearch rejects over-bound KQL with a bounded
//     400 BEFORE storing it;
//   - a stored hostile query (inserted before enforcement existed) is
//     rejected identically on every application — the background
//     executeSearch run marks the search failed, and every per-fetch
//     GetSearch re-application returns the bounded 400 — and never kills
//     the process.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/kql"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// kqlBoundsSeedUser seeds a dedicated domain+user so ediscovery_searches
// rows created by these tests satisfy the created_by → users.id foreign key
// without touching another test's fixtures (997xx range is unused elsewhere).
func kqlBoundsSeedUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (99776,'kqlbounds.test',TRUE) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
			(99777,'kqlbounds_u',99776,'kqlbounds_u@kqlbounds.test','KQLBounds',TRUE) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM users WHERE id = 99777`)   //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = 99776`) //nolint:errcheck
	})
	return 99777
}

// kqlBoundsClaims builds a scoped principal for the seeded user — the same
// shape as claimsWith, but bound to a real seeded row. It carries
// compliance.write (the content-search/ediscovery write principal) and
// mail.export (GetSearch results are message content, gated by the handler's
// requireMailExportClaims re-check), so these tests exercise the KQL bounds
// behavior behind both gates without re-testing the gates themselves.
func kqlBoundsClaims(userID int64) *auth.Claims {
	return &auth.Claims{
		UserID:      userID,
		Email:       "kqlbounds_u@kqlbounds.test",
		IsAdmin:     true,
		Permissions: []string{permissions.PermComplianceWrite, permissions.PermMailExport},
		Type:        jwtutil.TypeAccess,
	}
}

// kqlBoundsHostiles returns one hostile query per bound dimension: too deep
// (within the length cap, past the depth cap), too long, too term-heavy.
func kqlBoundsHostiles() map[string]string {
	return map[string]string{
		"too_deep":       strings.Repeat("(", kql.MaxQueryLength),
		"too_long":       strings.Repeat("a", kql.MaxQueryLength+1),
		"too_many_terms": strings.Repeat("t1 ", kql.MaxTerms) + "t_final",
	}
}

func TestContentSearch_KQLResourceBoundsRejected400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	for name, hostile := range kqlBoundsHostiles() {
		body, _ := json.Marshal(map[string]any{"kql": hostile})
		req := httptest.NewRequest(http.MethodPost, "/admin/content-search/search", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.Search(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: Search status = %d, want 400 (body=%s)", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid KQL query") {
			t.Errorf("%s: detail = %s, want an invalid-KQL bounded error", name, rec.Body.String())
		}
	}
}

// TestContentSearch_KQLAtCapAccepted proves the boundary rejects only
// one-past-the-bound input: a query of exactly MaxQueryLength runes passes
// the boundary, parses, and runs the real FTS query (empty results here —
// nothing is seeded).
func TestContentSearch_KQLAtCapAccepted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{"kql": strings.Repeat("a", kql.MaxQueryLength)})
	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/search", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("at-cap query status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Results []map[string]any `json:"results"`
		Total   int              `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 0 || len(resp.Results) != 0 {
		t.Errorf("at-cap query over unseeded data returned %d results, want 0", resp.Total)
	}
}

func TestEDiscoveryStartSearch_KQLResourceBoundsRejected400(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", nil)
	userID := kqlBoundsSeedUser(t, pool)

	for name, hostile := range kqlBoundsHostiles() {
		body, _ := json.Marshal(map[string]any{"name": "kql-bounds-" + name, "kql": hostile})
		req := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/searches", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), kqlBoundsClaims(userID)))
		rec := httptest.NewRecorder()
		h.StartSearch(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: StartSearch status = %d, want 400 (body=%s)", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid KQL query") {
			t.Errorf("%s: detail = %s, want an invalid-KQL bounded error", name, rec.Body.String())
		}

		// The hostile query must never have been stored for later
		// re-application.
		var stored int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM ediscovery_searches WHERE created_by = $1 AND query->>'kql' = $2`,
			userID, hostile,
		).Scan(&stored); err != nil {
			t.Fatalf("%s: count stored rows: %v", name, err)
		}
		if stored != 0 {
			t.Errorf("%s: found %d stored hostile search rows, want 0", name, stored)
		}
	}
}

// TestEDiscoveryStartSearch_KQLAtCapAccepted proves an at-cap KQL query is
// still accepted for storage (the boundary must not over-reject). The search
// row it creates is deleted by cleanup; its background execution goroutine
// only marks row state and harmlessly no-ops once the row is gone.
func TestEDiscoveryStartSearch_KQLAtCapAccepted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", nil)

	atCap := strings.Repeat("a", kql.MaxQueryLength)
	body, _ := json.Marshal(map[string]any{"name": "kql-bounds-atcap", "kql": atCap})
	req := httptest.NewRequest(http.MethodPost, "/admin/ediscovery/searches", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), kqlBoundsClaims(kqlBoundsSeedUser(t, pool))))
	rec := httptest.NewRecorder()
	h.StartSearch(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("at-cap StartSearch status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM ediscovery_searches WHERE id = $1`, resp.ID) //nolint:errcheck
	})
}

// TestEDiscoveryStoredMaliciousQueryRejectedIdenticallyOnEveryApplication is
// the stored-query re-application contract: a hostile query that reached
// storage before enforcement existed is rejected identically on every
// application — once by the background executeSearch run (search marked
// failed) and identically on every per-fetch GetSearch re-application (the
// bounded 400) — never a 200 reporting the misleading `status: complete` a
// rejected query can never legitimately reach, and never an abort of the
// process.
func TestEDiscoveryStoredMaliciousQueryRejectedIdenticallyOnEveryApplication(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewEDiscoveryHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger(), nil, "", nil)
	userID := kqlBoundsSeedUser(t, pool)

	hostile := strings.Repeat("(", kql.MaxQueryLength)
	queryJSON, _ := json.Marshal(map[string]any{
		"keywords": "", "kql": hostile, "fromAddr": "", "dateFrom": "", "dateTo": "", "mailboxIds": nil,
	})
	var searchID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO ediscovery_searches (name, created_by, query, status, result_count)
		 VALUES ('kql-bounds-stored', $2, $1::JSONB, 'complete', 1) RETURNING id`,
		string(queryJSON), userID,
	).Scan(&searchID); err != nil {
		t.Fatalf("seed stored hostile search: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM ediscovery_searches WHERE id = $1`, searchID) //nolint:errcheck
	})

	// Application 1: the background execution path. Pre-fix this is where a
	// stored hostile query could abort the process; post-fix it must mark the
	// search failed and return.
	h.executeSearch(context.Background(), searchID)
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM ediscovery_searches WHERE id = $1`, searchID,
	).Scan(&status); err != nil {
		t.Fatalf("read status after executeSearch: %v", err)
	}
	if status != "failed" {
		t.Fatalf("executeSearch status = %q, want %q (bounded rejection)", status, "failed")
	}

	// Restore the stored row so the per-fetch path is exercised against the
	// same stored hostile query.
	if _, err := pool.Exec(context.Background(),
		`UPDATE ediscovery_searches SET status = 'complete', result_count = 1, started_at = now(), completed_at = now() WHERE id = $1`,
		searchID,
	); err != nil {
		t.Fatalf("restore stored row: %v", err)
	}

	// Applications 2..4: GetSearch re-validates the stored KQL on every fetch
	// (the per-fetch reapplication of the stored query). Each application must
	// reject identically with the bounded 400 — never a 200 reporting the
	// misleading `status: complete` the rejected query can never legitimately
	// reach.
	const fetches = 3
	var firstBody string
	for i := 0; i < fetches; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/admin/ediscovery/searches/%d", searchID), nil)
		req.SetPathValue("id", strconv.FormatInt(searchID, 10))
		req = req.WithContext(auth.ContextWithUser(req.Context(), kqlBoundsClaims(userID)))
		rec := httptest.NewRecorder()
		h.GetSearch(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("fetch %d: GetSearch status = %d, want 400 (body=%s)", i+2, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid KQL query") {
			t.Errorf("fetch %d: detail = %s, want an invalid-KQL bounded error", i+2, rec.Body.String())
		}
		if i == 0 {
			firstBody = rec.Body.String()
			continue
		}
		if rec.Body.String() != firstBody {
			t.Fatalf("fetch %d: response differs from fetch 2 — re-application must reject identically", i+2)
		}
	}

	// The rejection itself must be identical on every direct application of
	// the stored query (this is exactly what each fetch performed above).
	firstErr := ""
	for i := 0; i < fetches+1; i++ {
		_, err := kql.Parse(hostile)
		if err == nil {
			t.Fatalf("stored hostile query parsed successfully on application %d", i+1)
		}
		if i == 0 {
			firstErr = err.Error()
			continue
		}
		if err.Error() != firstErr {
			t.Fatalf("application %d error = %q, want identical %q", i+1, err.Error(), firstErr)
		}
	}
}
