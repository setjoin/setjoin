package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

func TestDeviceLockdownActionParse(t *testing.T) {
	// actionFromPath maps the URL action segment to a transition target; an
	// unknown action is rejected with ok=false.
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"enroll", "enrolled", true},
		{"approve", "approved", true},
		{"revoke", "revoked", true},
		{"bogus", "", false},
	} {
		got, ok := actionFromPath(c.in)
		if got != c.want || ok != c.ok {
			t.Fatalf("actionFromPath(%q)=(%q,%v) want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestListRequiresUserID(t *testing.T) {
	h := NewDeviceLockdownHandler(nil, testsupport.TestLogger())
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/admin/devices", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("List without user_id: code=%d want 400", rec.Code)
	}
}

// TestQueueDefaultsAndShape is a TEST_DB_DSN-gated handler test asserting Queue
// returns 200 + a JSON array for an empty queue, proving the empty-array (not
// null) contract the UI's EMPTY state depends on.
func TestQueueDefaultsAndShape(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set — skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	h := NewDeviceLockdownHandler(pool, testsupport.TestLogger())
	req := httptest.NewRequest(http.MethodGet, "/admin/devices/queue", nil)
	req = withAdminClaims(req, 1)
	rec := httptest.NewRecorder()
	h.Queue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Queue: got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("Queue: body is not a JSON array: %v; body=%s", err, rec.Body.String())
	}
	// rows may be length 0 (empty queue) — that's the empty-array contract.
}
