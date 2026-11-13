package drive

// Shared skip-if-no-DB helpers for the white-box (package drive) live tests
// — chunks_live_test.go and content_live_test.go. Mirrors internal/audit's
// mustPool/ensureTestUser genre; drive_test's black-box equivalents
// (handler_live_test.go) duplicate a small amount of this by necessity
// (different Go package, can't import unexported test helpers across the
// package/package_test boundary).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
)

func driveLivePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// driveLiveUser creates a fresh user+mailbox via the shared mk_account
// fixture and returns the user id (drive reducers key on users.id).
func driveLiveUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var mailboxID int64
	if err := pool.QueryRow(context.Background(), `SELECT mk_account($1)`, label).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	var userID int64
	if err := pool.QueryRow(context.Background(), `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user_id: %v", err)
	}
	return userID
}

// driveLiveDo is the white-box (package drive) twin of drive_test's driveDo —
// shared by the P4 Task 9-11 live test files (branches/locks/folderadmins/
// activity), which live in this package (not drive_test) so they can reuse
// content_live_test.go's fixture helpers (driveLiveCreateFile et al.).
func driveLiveDo(t *testing.T, h *Handler, userID int64, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	// ACL receipt-backed mutations require the same UUID on both wire
	// surfaces. Mirror the first-party client when a test body declares one.
	if object, ok := body.(map[string]any); ok {
		if key, ok := object["idempotencyKey"].(string); ok {
			r.Header.Set("Idempotency-Key", key)
		}
	}
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func driveLiveDecode(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rr.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
}
