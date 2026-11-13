package user

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestProfile_RequiresAuth(t *testing.T) {
	h := NewProfileHandler(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest("POST", "/user/profile", bytes.NewReader([]byte(`{"display_name":"x"}`)))
	rr := httptest.NewRecorder()
	h.Update(rr, req) // no auth context
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth → status %d, want 401", rr.Code)
	}
}

func TestProfile_RejectsEmptyName(t *testing.T) {
	h := NewProfileHandler(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest("POST", "/user/profile", bytes.NewReader([]byte(`{"display_name":"   "}`)))
	req = req.WithContext(auth.ContextWithUser(t.Context(), &auth.Claims{UserID: 999999}))
	rr := httptest.NewRecorder()
	h.Update(rr, req) // validation returns before the pool is touched
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty name → status %d, want 400", rr.Code)
	}
}

func TestProfile_UpdatesDisplayName(t *testing.T) {
	pool := testPool(t)
	userID := createTestUser(t, pool)
	h := NewProfileHandler(pool, slog.New(slog.NewTextHandler(io.Discard, nil)))

	req := httptest.NewRequest("POST", "/user/profile", bytes.NewReader([]byte(`{"display_name":"Alice Renamed"}`)))
	req = req.WithContext(auth.ContextWithUser(t.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.Update(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var got string
	if err := pool.QueryRow(t.Context(), `SELECT display_name FROM users WHERE id=$1`, userID).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != "Alice Renamed" {
		t.Errorf("display_name persisted = %q, want %q", got, "Alice Renamed")
	}
}
