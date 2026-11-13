package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/testutil"
	"setjoin.com/shared/testsupport"
)

// openThreatTestPool returns a pool connected to DB_DSN; skips if not set.
func openThreatTestPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func threatTestLogger() *slog.Logger {
	return testsupport.TestLogger()
}

// newThreatHandlerWithQuerier constructs a ThreatHandler with an injected querier
// for unit tests (no DB required).
func newThreatHandlerWithQuerier(q threatQuerier, logger *slog.Logger) *ThreatHandler {
	return &ThreatHandler{querier: q, logger: logger}
}

// ---- stub threatQuerier -------------------------------------------------------

// stubRows implements pgx.Rows and returns a fixed slice of fixture rows.
type stubRows struct {
	rows   [][]any
	idx    int
	err    error
	cmdTag pgconn.CommandTag
}

func newStubRows(rows [][]any) *stubRows { return &stubRows{rows: rows} }

func (s *stubRows) Next() bool {
	if s.idx < len(s.rows) {
		s.idx++
		return true
	}
	return false
}
func (s *stubRows) Scan(dest ...any) error {
	row := s.rows[s.idx-1]
	for i, d := range dest {
		if i >= len(row) {
			break
		}
		switch v := d.(type) {
		case *string:
			if sv, ok := row[i].(string); ok {
				*v = sv
			}
		case *int:
			if iv, ok := row[i].(int); ok {
				*v = iv
			}
		case *any:
			*v = row[i]
		}
	}
	return nil
}
func (s *stubRows) Close()                                       {}
func (s *stubRows) Err() error                                   { return s.err }
func (s *stubRows) CommandTag() pgconn.CommandTag                { return s.cmdTag }
func (s *stubRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (s *stubRows) Values() ([]any, error)                       { return nil, nil }
func (s *stubRows) RawValues() [][]byte                          { return nil }
func (s *stubRows) Conn() *pgx.Conn                              { return nil }

// stubThreatQuerier implements threatQuerier without a DB.
// capturedCount / capturedData record the last SQL + args for assertion.
type stubThreatQuerier struct {
	count         int
	rows          [][]any
	capturedCount string
	capturedData  string
	countArgs     []any
	dataArgs      []any
}

func (s *stubThreatQuerier) QueryCount(_ context.Context, sql string, args ...any) (int, error) {
	s.capturedCount = sql
	s.countArgs = args
	return s.count, nil
}

func (s *stubThreatQuerier) QueryRows(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	s.capturedData = sql
	s.dataArgs = args
	return newStubRows(s.rows), nil
}

// ---- unit tests using the stub querier ---------------------------------------

// TestNewThreatHandler confirms constructor does not panic with nil pools.
func TestNewThreatHandler(t *testing.T) {
	h := NewThreatHandler(nil, nil, nil)
	if h == nil {
		t.Fatal("NewThreatHandler returned nil")
	}
}

// TestThreatViewUnknown returns a 404 problem for an unrecognised view name.
func TestThreatViewUnknown(t *testing.T) {
	h := NewThreatHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/dragons", nil)
	req.SetPathValue("view", "dragons")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown view, got %d", w.Code)
	}
	var prob struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(w.Body).Decode(&prob); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if prob.Type != "https://setjoin.com/errors/not-found" {
		t.Errorf("unexpected problem type %q", prob.Type)
	}
}

// TestThreatViewKnownReturnsOK returns 200 for each of the four valid views
// using the stub querier (no DB needed).
func TestThreatViewKnownReturnsOK(t *testing.T) {
	views := []string{"attempts", "lockouts", "feed-blocks", "rate-counters"}
	for _, v := range views {
		t.Run(v, func(t *testing.T) {
			stub := &stubThreatQuerier{count: 0, rows: nil}
			h := newThreatHandlerWithQuerier(stub, nil)
			req := httptest.NewRequest(http.MethodGet, "/admin/threat/"+v, nil)
			req.SetPathValue("view", v)
			w := httptest.NewRecorder()
			h.View(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("view %q: expected 200, got %d — body: %s", v, w.Code, w.Body.String())
			}
		})
	}
}

// TestThreatPaginationDefaults asserts response envelope uses default limit=100, offset=0.
func TestThreatPaginationDefaults(t *testing.T) {
	stub := &stubThreatQuerier{}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/lockouts", nil)
	req.SetPathValue("view", "lockouts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Rows   []any `json:"rows"`
		Total  int   `json:"total"`
		Limit  int   `json:"limit"`
		Offset int   `json:"offset"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Limit != 100 {
		t.Errorf("default limit: expected 100, got %d", resp.Limit)
	}
	if resp.Offset != 0 {
		t.Errorf("default offset: expected 0, got %d", resp.Offset)
	}
}

// TestThreatBadLimitClamped asserts a non-numeric limit is clamped to default (no 500).
func TestThreatBadLimitClamped(t *testing.T) {
	stub := &stubThreatQuerier{}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/attempts?limit=notanumber", nil)
	req.SetPathValue("view", "attempts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with clamped limit, got %d", w.Code)
	}
}

// TestThreatLimitMaxClamped asserts a limit above 500 is clamped to 500.
func TestThreatLimitMaxClamped(t *testing.T) {
	stub := &stubThreatQuerier{}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/attempts?limit=9999", nil)
	req.SetPathValue("view", "attempts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp struct {
		Limit int `json:"limit"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Limit != 500 {
		t.Errorf("expected limit clamped to 500, got %d", resp.Limit)
	}
}

// TestThreatSortInjectionRejected asserts that an arbitrary sort column
// falls back to the default order (no SQL injection; no panic; 200 returned).
// The stub querier lets us also verify the ORDER BY clause does not contain
// the injected string.
func TestThreatSortInjectionRejected(t *testing.T) {
	stub := &stubThreatQuerier{}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/attempts?sort=1;DROP+TABLE+auth_attempts;--", nil)
	req.SetPathValue("view", "attempts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with injected sort silently ignored, got %d", w.Code)
	}
	// Verify the data SQL uses the default order, not the injected value.
	if stub.capturedData == "" {
		t.Fatal("stub did not capture the data query")
	}
	injected := "DROP"
	if containsIgnoreCase(stub.capturedData, injected) {
		t.Errorf("SQL contains injected token %q: %s", injected, stub.capturedData)
	}
}

func containsIgnoreCase(s, sub string) bool {
	return len(s) >= len(sub) &&
		(s == sub || len(s) > 0 && containsIgnoreCaseHelper(s, sub))
}

func containsIgnoreCaseHelper(s, sub string) bool {
	lower := func(r byte) byte {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	subL := make([]byte, len(sub))
	for i := range sub {
		subL[i] = lower(sub[i])
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := range sub {
			if lower(s[i+j]) != subL[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestThreatResponseShape asserts the envelope matches the M1 Table contract:
// {rows:[...], total, limit, offset}.
func TestThreatResponseShape(t *testing.T) {
	stub := &stubThreatQuerier{count: 2, rows: [][]any{
		{"1.2.3.0/24", "spamhaus", "2026-06-01T00:00:00Z"},
		{"5.6.7.0/24", "custom", "2026-06-02T00:00:00Z"},
	}}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/feed-blocks", nil)
	req.SetPathValue("view", "feed-blocks")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var env map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	for _, key := range []string{"rows", "total", "limit", "offset"} {
		if _, ok := env[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
}

// TestThreatStubFixtureRows asserts that fixture rows returned by the stub
// querier appear in the response (stub querier exercised end-to-end).
func TestThreatStubFixtureRows(t *testing.T) {
	stub := &stubThreatQuerier{
		count: 1,
		rows: [][]any{
			{"ip:192.0.2.1", 5, nil, nil}, // lockout_key, failed_count, locked_until, escalation_level, updated_at
		},
	}
	// Add the 5th column (updated_at) the lockouts scanRow expects.
	stub.rows = [][]any{
		{"ip:192.0.2.1", 5, nil, 2, nil},
	}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/lockouts", nil)
	req.SetPathValue("view", "lockouts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Rows []struct {
			LockoutKey  string `json:"lockoutKey"`
			FailedCount int    `json:"failedCount"`
		} `json:"rows"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rows) != 1 {
		t.Fatalf("expected 1 fixture row, got %d", len(resp.Rows))
	}
	if resp.Rows[0].LockoutKey != "ip:192.0.2.1" {
		t.Errorf("unexpected lockout_key: %q", resp.Rows[0].LockoutKey)
	}
	if resp.Rows[0].FailedCount != 5 {
		t.Errorf("unexpected failed_count: %d", resp.Rows[0].FailedCount)
	}
}

// TestThreatLockoutsTotalFromFullCountAccessor pins the Astra impl-r2 P2
// pagination fix: the lockouts total must come from the page-bound-free
// lockout_count accessor, NOT from counting a lockout_list page (which caps
// at the accessor's 500-row ceiling and hides every row beyond it). With 847
// matching rows, total=847 must survive — pagination can reach row 501.
func TestThreatLockoutsTotalFromFullCountAccessor(t *testing.T) {
	stub := &stubThreatQuerier{count: 847}
	h := newThreatHandlerWithQuerier(stub, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/lockouts?limit=25&offset=500", nil)
	req.SetPathValue("view", "lockouts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body=%s", w.Code, w.Body.String())
	}
	if stub.capturedCount == "" {
		t.Fatal("stub did not capture the count query")
	}
	if !strings.Contains(stub.capturedCount, "lockout_count") {
		t.Errorf("count query must read lockout_count (full filtered count, no page bound), got: %s",
			stub.capturedCount)
	}
	if strings.Contains(stub.capturedCount, "lockout_list") {
		t.Errorf("count query must not count a (page-capped) lockout_list result, got: %s",
			stub.capturedCount)
	}
	var resp struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 847 {
		t.Errorf("total must be the full filtered count (847), got %d — rows beyond 500 are unreachable", resp.Total)
	}
	if len(stub.countArgs) != 1 {
		t.Errorf("lockout_count takes exactly the q filter, got %d args: %v", len(stub.countArgs), stub.countArgs)
	}
}

// TestThreatLockoutsSortThreadedToAccessor pins the Astra impl-r2 P2 sorting
// fix: the previously supported lockouts sorting (?sort=col&dir=asc|desc)
// must reach lockout_list as validated bind parameters ($4/$5), never be
// silently dropped in favour of the accessor's default locked_until DESC.
func TestThreatLockoutsSortThreadedToAccessor(t *testing.T) {
	for _, col := range []string{"locked_until", "failed_count", "updated_at"} {
		for _, dir := range []string{"asc", "desc"} {
			name := col + "_" + dir
			t.Run(name, func(t *testing.T) {
				stub := &stubThreatQuerier{}
				h := newThreatHandlerWithQuerier(stub, nil)
				url := "/admin/threat/lockouts?sort=" + col + "&dir=" + dir
				req := httptest.NewRequest(http.MethodGet, url, nil)
				req.SetPathValue("view", "lockouts")
				w := httptest.NewRecorder()
				h.View(w, req)
				if w.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d — body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(stub.capturedData, "lockout_list($1::text, $2::int, $3::int, $4::text, $5::text)") {
					t.Errorf("data query must page through the 5-arg lockout_list, got: %s", stub.capturedData)
				}
				// dataArgs = (q, limit, offset, sortCol, sortDir).
				if len(stub.dataArgs) != 5 {
					t.Fatalf("expected 5 bound params, got %d: %v", len(stub.dataArgs), stub.dataArgs)
				}
				if got := stub.dataArgs[3]; got != col {
					t.Errorf("sort column param: expected %q, got %v", col, got)
				}
				if got := stub.dataArgs[4]; got != dir {
					t.Errorf("sort direction param: expected %q, got %v", dir, got)
				}
			})
		}
	}

	// Direction defaulting: a missing or invalid dir on a valid column binds
	// the column with the ascending default (matching resolveOrder).
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"missing dir", "/admin/threat/lockouts?sort=failed_count"},
		{"invalid dir", "/admin/threat/lockouts?sort=failed_count&dir=lateral"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubThreatQuerier{}
			h := newThreatHandlerWithQuerier(stub, nil)
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.SetPathValue("view", "lockouts")
			w := httptest.NewRecorder()
			h.View(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d — body=%s", w.Code, w.Body.String())
			}
			if len(stub.dataArgs) != 5 {
				t.Fatalf("expected 5 bound params, got %d: %v", len(stub.dataArgs), stub.dataArgs)
			}
			if got := stub.dataArgs[3]; got != "failed_count" {
				t.Errorf("sort column param: expected failed_count, got %v", got)
			}
			if got := stub.dataArgs[4]; got != "asc" {
				t.Errorf("sort direction param: expected asc default, got %v", got)
			}
		})
	}
}

// TestThreatLockoutsDefaultAndUnknownSortUseAccessorDefault asserts the other
// half of the contract: absent and non-allow-listed sorts bind empty column/
// direction parameters so the accessor falls back to its locked_until DESC
// default (and injected tokens never reach any bound value).
func TestThreatLockoutsDefaultAndUnknownSortUseAccessorDefault(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"no sort params", "/admin/threat/lockouts"},
		{"unknown column", "/admin/threat/lockouts?sort=lockout_key&dir=asc"},
		{"injected sort", "/admin/threat/lockouts?sort=1;DROP+TABLE+auth_lockouts;--&dir=asc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubThreatQuerier{}
			h := newThreatHandlerWithQuerier(stub, nil)
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			req.SetPathValue("view", "lockouts")
			w := httptest.NewRecorder()
			h.View(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d — body=%s", w.Code, w.Body.String())
			}
			if len(stub.dataArgs) != 5 {
				t.Fatalf("expected 5 bound params, got %d: %v", len(stub.dataArgs), stub.dataArgs)
			}
			if got := stub.dataArgs[3]; got != "" {
				t.Errorf("non-allow-listed sort must bind an empty column (accessor default), got %v", got)
			}
			if got := stub.dataArgs[4]; got != "" {
				t.Errorf("non-allow-listed sort must bind an empty direction (accessor default), got %v", got)
			}
		})
	}
}

// TestThreatAttemptsIntegration is a real-pool integration test.
// Inserts a dummy auth_attempt and asserts the attempts view returns it.
func TestThreatAttemptsIntegration(t *testing.T) {
	testutil.SkipIfNoEnv(t, "DB_DSN")

	pool := openThreatTestPool(t)
	h := NewThreatHandler(pool, nil, threatTestLogger())
	ctx := context.Background()

	// Insert a fixture row into the test partition (2026-05 is the only seeded partition).
	_, err := pool.Exec(ctx,
		`INSERT INTO auth_attempts (source_ip, target_username, protocol, outcome, occurred_at)
		 VALUES ('192.0.2.88'::inet, 'threattest_b6@example.com', 'http', 'failure', '2026-05-20 01:00:01+00'::timestamptz)`)
	if err != nil {
		t.Fatalf("insert fixture: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM auth_attempts WHERE target_username = 'threattest_b6@example.com'`)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/threat/attempts?limit=500", nil)
	req.SetPathValue("view", "attempts")
	w := httptest.NewRecorder()
	h.View(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var resp struct {
		Rows []struct {
			SourceIP string `json:"sourceIp"`
			Outcome  string `json:"outcome"`
		} `json:"rows"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	found := false
	for _, row := range resp.Rows {
		if row.Outcome == "failure" && row.SourceIP == "192.0.2.88" {
			found = true
		}
	}
	if !found {
		t.Errorf("fixture row not found in attempts view; total=%d rows=%+v", resp.Total, resp.Rows)
	}
}
