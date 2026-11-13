package chat

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// TestRoutes404WhenChatOff pins the G5-style gate (drive's shape): OFF is
// checked BEFORE auth/mux dispatch. A sentinel 200 route (a path distinct
// from every real Task 9 route — NewHandler's own registrations would
// otherwise collide with a same-path sentinel and dispatch into a real
// handler with a nil pool) is registered on h.mux so the assertion actually
// pins the gate — without it, an empty mux's own default 404 would satisfy
// the OFF assertion even if the flags.IsEnabled check were compiled out
// entirely (mutation-verified).
func TestRoutes404WhenChatOff(t *testing.T) {
	newSentinelHandler := func(enabled bool) *Handler {
		h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.chat": enabled}), slog.Default())
		h.mux.HandleFunc("/chat/__gate_sentinel__", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return h
	}

	req := func() *http.Request {
		r := httptest.NewRequest("GET", "/chat/__gate_sentinel__", nil)
		return r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: 7}))
	}

	rrOn := httptest.NewRecorder()
	newSentinelHandler(true).ServeHTTP(rrOn, req())
	if rrOn.Code != http.StatusOK {
		t.Fatalf("want 200 from sentinel route while feature.chat ON, got %d", rrOn.Code)
	}

	rrOff := httptest.NewRecorder()
	newSentinelHandler(false).ServeHTTP(rrOff, req())
	if rrOff.Code != http.StatusNotFound {
		t.Errorf("want 404 while feature.chat OFF (same registered route as the ON case), got %d", rrOff.Code)
	}
}

// TestRoutesRequireAuthClaims pins the second gate leg: feature ON but no
// auth claims in context still 401s before mux dispatch.
func TestRoutesRequireAuthClaims(t *testing.T) {
	h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	req := httptest.NewRequest("GET", "/chat/conversations", nil) // no claims
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without claims, got %d", rr.Code)
	}
}

func pgErr(code string) error { return &pgconn.PgError{Code: code} }

// TestBZStatusMap pins the Task 8 locked table verbatim, extended for BZ171
// (Task 17 gate: found missing from the original table — the archive
// read-only guard added later): BZ160→400, BZ161/163/164/166/167/171→403,
// BZ162/165/168→422, BZ169/BZ170→404 (the anti-oracle leg — join-private and
// reaction-on-missing-message read alike). Also pins the `code`/`type`
// RFC7807 fields survive the projection for every one of these — BZ171's
// status alone was already correct via the shared reducererr.codeClass
// fallback, but its code/type fields were silently dropped before the fix.
// Extended by Chat A4a Task 8 (2026-07-12-chat-A4a-records-lifecycle.md):
// BZ192/BZ193 (no-downgrade / WORM immutability, both ClassConflict) → 409.
// Task 10 adds BZ196 (per-user chat send rate exceeded, ClassSendQuota) →
// 507 — the route-status case Task 10's red step names; this map is the
// established location for exactly that assertion (every other chat BZ
// code's status/code/type is pinned here, not in a per-route test file).
// Chat A4b Task 2 (2026-07-15-chat-A4b-oversight.md) adds BZ197 (invalid
// oversight arguments, ClassUnprocessable) → 422 and BZ198 (eDiscovery case
// not open, ClassConflict) → 409, raised by chat_case_hold_set/release.
func TestBZStatusMap(t *testing.T) {
	want := map[string]int{
		"BZ160": http.StatusBadRequest,
		"BZ161": http.StatusForbidden,
		"BZ163": http.StatusForbidden,
		"BZ164": http.StatusForbidden,
		"BZ166": http.StatusForbidden,
		"BZ167": http.StatusForbidden,
		"BZ171": http.StatusForbidden,
		"BZ194": http.StatusForbidden,
		"BZ220": http.StatusForbidden,
		"BZ162": http.StatusUnprocessableEntity,
		"BZ165": http.StatusUnprocessableEntity,
		"BZ168": http.StatusUnprocessableEntity,
		"BZ169": http.StatusNotFound,
		"BZ170": http.StatusNotFound,
		"BZ178": http.StatusUnprocessableEntity,
		"BZ191": http.StatusUnprocessableEntity,
		"BZ192": http.StatusConflict,
		"BZ193": http.StatusConflict,
		"BZ195": http.StatusUnprocessableEntity,
		"BZ196": http.StatusInsufficientStorage,
		"BZ197": http.StatusUnprocessableEntity,
		"BZ198": http.StatusConflict,
	}
	for code, status := range want {
		rr := httptest.NewRecorder()
		writeChatProblem(rr, httptest.NewRequest("GET", "/chat/conversations", nil), pgErr(code))
		if rr.Code != status {
			t.Errorf("%s: want %d got %d", code, status, rr.Code)
		}
		var p struct {
			Code string `json:"code"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
			t.Fatalf("%s: decode problem body: %v", code, err)
		}
		if p.Code != code {
			t.Errorf("%s: problem `code` field = %q, want %q", code, p.Code, code)
		}
		if p.Type == "" {
			t.Errorf("%s: problem `type` field is empty, want a chat problem URI", code)
		}
	}
}

// TestBZStatusMap_DefaultUnknownIs500 pins the default fallback: an
// unclassified/non-chat SQLSTATE never guesses a 4xx.
func TestBZStatusMap_DefaultUnknownIs500(t *testing.T) {
	rr := httptest.NewRecorder()
	writeChatProblem(rr, httptest.NewRequest("GET", "/chat/conversations", nil), pgErr("23505"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500 for an unclassified error, got %d", rr.Code)
	}
}
