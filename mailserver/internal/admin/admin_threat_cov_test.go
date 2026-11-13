package admin

// Final-wave changed-lines coverage for admin_threat.go: the worker-credential
// constructor arm (NewThreatHandler with a non-nil worker pool) and the
// accessor-backed lockouts view's four failure arms — count fault, data-query
// fault, per-row scan fault (skip), and post-iteration rows.Err fault — driven
// through the stub-querier seam admin_threat_test.go established.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// covFaultQuerier is a threatQuerier whose count and data legs fault
// independently, so each failure arm of the accessor path executes in isolation.
type covFaultQuerier struct {
	count    int
	countErr error
	rows     pgx.Rows
	rowsErr  error
}

func (q *covFaultQuerier) QueryCount(context.Context, string, ...any) (int, error) {
	return q.count, q.countErr
}

func (q *covFaultQuerier) QueryRows(context.Context, string, ...any) (pgx.Rows, error) {
	return q.rows, q.rowsErr
}

// covFaultRows is a pgx.Rows whose Scan and Err fault independently: scanErr
// exercises the per-row skip arm, errErr the post-iteration arm.
type covFaultRows struct {
	scanCalled bool
	scanErr    error
	errErr     error
}

func (r *covFaultRows) Next() bool { return !r.scanCalled }

func (r *covFaultRows) Scan(...any) error {
	r.scanCalled = true
	return r.scanErr
}

func (r *covFaultRows) Close()                                       {}
func (r *covFaultRows) Err() error                                   { return r.errErr }
func (r *covFaultRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *covFaultRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *covFaultRows) Values() ([]any, error)                       { return nil, nil }
func (r *covFaultRows) RawValues() [][]byte                          { return nil }
func (r *covFaultRows) Conn() *pgx.Conn                              { return nil }

// runCovThreatLockouts drives one lockouts-view request through h (the only
// usesAccessor view, so every arm here is runAccessorQuery's).
func runCovThreatLockouts(t *testing.T, h *ThreatHandler, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/threat/lockouts"+query, nil)
	req.SetPathValue("view", "lockouts")
	rec := httptest.NewRecorder()
	h.View(rec, req)
	return rec
}

// TestThreatWorkerCredentialWiring covers the worker!=nil constructor arm: the
// lockouts view must ride the separate worker querier (BYPASSRLS accessor
// credential), never fall back to the request pool, when a worker DSN is set.
func TestThreatWorkerCredentialWiring(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewThreatHandler(pool, pool, testsupport.TestLogger())
	if h.querier == nil {
		t.Fatal("NewThreatHandler with a non-nil pool must wire querier")
	}
	if h.lockoutsQuerier == nil {
		t.Fatal("NewThreatHandler with a non-nil worker pool must wire lockoutsQuerier")
	}
}

// TestThreatLockoutsCountQueryFailure pins the count-fault arm: a lockout_count
// accessor failure surfaces as an internal problem, never as a fake empty page.
func TestThreatLockoutsCountQueryFailure(t *testing.T) {
	h := newThreatHandlerWithQuerier(&covFaultQuerier{countErr: errors.New("cov count fault")}, nil)
	rec := runCovThreatLockouts(t, h, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("count fault: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestThreatLockoutsDataQueryFailure pins the page-fault arm: a lockout_list
// accessor failure surfaces as an internal problem too.
func TestThreatLockoutsDataQueryFailure(t *testing.T) {
	h := newThreatHandlerWithQuerier(&covFaultQuerier{rowsErr: errors.New("cov data fault")}, nil)
	rec := runCovThreatLockouts(t, h, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("data fault: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestThreatLockoutsScanFailureSkipsRow pins the per-row skip arm: an
// unreadable row is dropped (200 with the remaining rows) rather than failing
// the whole page.
func TestThreatLockoutsScanFailureSkipsRow(t *testing.T) {
	h := newThreatHandlerWithQuerier(&covFaultQuerier{
		rows: &covFaultRows{scanErr: errors.New("cov scan fault")},
	}, nil)
	rec := runCovThreatLockouts(t, h, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("scan fault: want 200 (row skipped), got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"rows":[]`) {
		t.Fatalf("scan-fault row must be skipped leaving an empty page, got: %s", rec.Body.String())
	}
}

// TestThreatLockoutsRowsIterationFailure pins the post-iteration arm: a fault
// surfaced via rows.Err after iteration fails the request with an internal
// problem (no partial page can masquerade as complete).
func TestThreatLockoutsRowsIterationFailure(t *testing.T) {
	h := newThreatHandlerWithQuerier(&covFaultQuerier{
		rows: &covFaultRows{errErr: errors.New("cov iteration fault")},
	}, nil)
	rec := runCovThreatLockouts(t, h, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("iteration fault: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
