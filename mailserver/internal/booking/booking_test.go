package booking_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/booking"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func TestOwnerPagesRequiresAuthContext(t *testing.T) {
	h := booking.NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.booking_pages": true}), slog.Default())
	req := httptest.NewRequest("GET", "/api/booking/pages", nil) // no claims in ctx
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without auth claims, got %d", rr.Code)
	}
}

func TestOwnerPages404WhenToggleOff(t *testing.T) {
	h := booking.NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.booking_pages": false}), slog.Default())
	req := httptest.NewRequest("GET", "/api/booking/pages", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404 when feature.booking_pages is off, got %d", rr.Code)
	}
}

func TestOwnerUpsertPassesJSONAsJSONB(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var mailboxID, userID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, fmt.Sprintf("booking-owner-%d", time.Now().UnixNano())).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve account user: %v", err)
	}

	h := booking.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.booking_pages": true}), slog.Default())
	body := fmt.Sprintf(`{"slug":"owner-upsert-%d","title":"Owner upsert"}`, time.Now().UnixNano())
	req := httptest.NewRequest(http.MethodPut, "/api/booking/pages", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("owner upsert: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func constrainedBookingPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE setjoin_app")
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open constrained pool: %v", err)
	}
	t.Cleanup(pool.Close)
	var role string
	if err := pool.QueryRow(t.Context(), "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("read constrained role: %v", err)
	}
	if role != "setjoin_app" {
		t.Fatalf("current_user=%q, want setjoin_app", role)
	}
	return pool
}

func TestOwnerCRUDScopesConstrainedAppRole(t *testing.T) {
	adminPool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	var mailboxID, userID int64
	if err := adminPool.QueryRow(ctx, `SELECT mk_account($1)`, fmt.Sprintf("booking-rls-%d", time.Now().UnixNano())).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := adminPool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve account user: %v", err)
	}

	pool := constrainedBookingPool(t)
	h := booking.NewHandler(pool, toggle.NewTestFlags(map[string]bool{"feature.booking_pages": true}), slog.Default())
	do := func(method, target, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	slug := fmt.Sprintf("booking-rls-%d", time.Now().UnixNano())
	rr := do(http.MethodPut, "/api/booking/pages", fmt.Sprintf(`{"slug":%q,"title":"RLS scope"}`, slug))
	if rr.Code != http.StatusOK {
		t.Fatalf("constrained upsert: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&created); err != nil || created.ID == "" {
		t.Fatalf("decode created page id: id=%q err=%v", created.ID, err)
	}
	// The row now exists, but this same constrained pool cannot see it without
	// the Handler's transaction-local mailbox GUC. This is the negative control
	// proving the scoped transaction is load-bearing rather than decorative.
	var visible int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM booking_pages WHERE id = $1`, created.ID).Scan(&visible); err != nil {
		t.Fatalf("unscoped RLS negative control: %v", err)
	}
	if visible != 0 {
		t.Fatalf("unscoped setjoin_app unexpectedly sees created booking page id=%s", created.ID)
	}
	rr = do(http.MethodGet, "/api/booking/pages", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), slug) {
		t.Fatalf("constrained list: want page %q, got %d: %s", slug, rr.Code, rr.Body.String())
	}
	rr = do(http.MethodDelete, "/api/booking/pages?id="+created.ID, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("constrained delete: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
