package admin

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/auth"
)

func TestMapReducerErr(t *testing.T) {
	h := &AccessReviewsHandler{logger: slog.Default()}
	cases := []struct {
		code string
		want int
	}{
		{"BZ060", http.StatusNotFound},
		{"BZ061", http.StatusForbidden},
		{"BZ069", http.StatusForbidden},
		{"BZ062", http.StatusConflict},
		{"BZ063", http.StatusConflict},
		{"BZ997", http.StatusInternalServerError}, // unregistered BZ → 500
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/admin/access-reviews/1/close", nil)
		h.mapReducerErr(rr, req, &pgconn.PgError{Code: c.code, Message: "x"})
		if rr.Code != c.want {
			t.Errorf("code %s → %d, want %d", c.code, rr.Code, c.want)
		}
	}
}

func TestDecideRejectsBadDecision(t *testing.T) {
	h := &AccessReviewsHandler{logger: slog.Default()}
	rr := httptest.NewRecorder()
	body := strings.NewReader(`{"decision":"maybe"}`)
	req := httptest.NewRequest("PUT", "/admin/access-reviews/1/items/2", body)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	req.SetPathValue("id", "1")
	req.SetPathValue("itemId", "2")
	h.Decide(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad decision → %d, want 400", rr.Code)
	}
}
