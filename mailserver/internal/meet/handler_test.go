package meet

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

// configuredCfg is a fully-set Config (all three LIVEKIT_* fields non-empty)
// used by every test that needs to get past the "not configured" gate leg.
var configuredCfg = Config{APIKey: "key", APISecret: "secret", WSURL: "ws://127.0.0.1:7880"}

func authedReq(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: 7}))
}

// TestRoutes404WhenMeetOff pins the G5-style gate (drive/chat's shape): OFF
// is checked BEFORE auth/configured/mux dispatch. A sentinel route (a path
// distinct from every real route Tasks 10-13 will add) is registered on
// h.mux so the assertion actually pins the gate — without it, an empty
// mux's own default 404 would satisfy the OFF assertion even if the
// flags.IsEnabled check were compiled out entirely.
func TestRoutes404WhenMeetOff(t *testing.T) {
	newSentinelHandler := func(enabled bool) *Handler {
		h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.meet": enabled}), configuredCfg, nil, nil, nil, slog.Default())
		// GET-prefixed (Task 10 deviation): Task 10 wires real routes,
		// including "GET /meet/{id}", into NewHandler itself, so a bare
		// method-agnostic pattern here now conflicts (ServeMux panics on two
		// patterns where neither dominates: this one is a more specific path
		// but less specific method, {id} is the reverse). Matching the
		// request method the test actually sends makes the literal segment
		// strictly more specific than the wildcard, resolving the ambiguity
		// without changing what this test proves.
		h.mux.HandleFunc("GET /meet/__gate_sentinel__", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		return h
	}

	rrOn := httptest.NewRecorder()
	newSentinelHandler(true).ServeHTTP(rrOn, authedReq("GET", "/meet/__gate_sentinel__"))
	if rrOn.Code != http.StatusOK {
		t.Fatalf("want 200 from sentinel route while feature.meet ON, got %d", rrOn.Code)
	}

	rrOff := httptest.NewRecorder()
	newSentinelHandler(false).ServeHTTP(rrOff, authedReq("GET", "/meet/__gate_sentinel__"))
	if rrOff.Code != http.StatusNotFound {
		t.Errorf("want 404 while feature.meet OFF (same registered route as the ON case), got %d", rrOff.Code)
	}
}

// TestRoutesRequireAuthClaims pins the second gate leg: feature ON but no
// auth claims in context still 401s before the configured-check or mux
// dispatch.
func TestRoutesRequireAuthClaims(t *testing.T) {
	h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.meet": true}), configuredCfg, nil, nil, nil, slog.Default())
	req := httptest.NewRequest("GET", "/meet", nil) // no claims
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without claims, got %d", rr.Code)
	}
}

// TestRoutes503WhenNotConfigured pins the third gate leg: feature ON, auth
// present, but LIVEKIT_* is unset — the SFU sidecar isn't provisioned on
// this box, so every route 503s rather than panicking on a nil RoomController.
func TestRoutes503WhenNotConfigured(t *testing.T) {
	h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.meet": true}), Config{}, nil, nil, nil, slog.Default())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedReq("GET", "/meet"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 when LIVEKIT_* unset, got %d", rr.Code)
	}
}

// TestRoutesOKWhenConfigured pins the happy path: all four gate legs open
// (feature ON, auth present, cfg configured) and dispatch reaches the
// internal mux — proven with a stub route rather than a real one so this
// test stays independent of Task 10's routes. GET-prefixed for the same
// reason as TestRoutes404WhenMeetOff's sentinel above (Task 10 deviation).
func TestRoutesOKWhenConfigured(t *testing.T) {
	h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.meet": true}), configuredCfg, nil, nil, nil, slog.Default())
	h.mux.HandleFunc("GET /meet/__stub__", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authedReq("GET", "/meet/__stub__"))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 through all gates, got %d", rr.Code)
	}
	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode stub body: %v", err)
	}
	if !body.OK {
		t.Errorf("stub body ok=false, want true")
	}
}

// TestConfigHTTPURL pins the ws(s)->http(s) scheme swap the Task 9
// RoomServiceClient depends on.
func TestConfigHTTPURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ws://127.0.0.1:7880", "http://127.0.0.1:7880"},
		{"wss://sfu.example.com", "https://sfu.example.com"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := (Config{WSURL: tc.in}).HTTPURL(); got != tc.want {
			t.Errorf("HTTPURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func pgErrCode(code string) error { return &pgconn.PgError{Code: code} }

// TestBZStatusMap pins the Task 8 locked table verbatim: BZ185→404,
// BZ186/BZ187→403, BZ188/BZ189→422, BZ190→409 — extended by B2 Task 5 with
// BZ199→403 (guest⇄recording exclusion) and BZ200→409 (recording state
// conflict), and by B3 Task 4 with BZ201→422 (the breakout anti-oracle
// lump). Also pins that the
// `code`/`type` RFC7807 fields survive the projection for every one of
// these (the chat A1 BZ171 gap-class lesson: a status can be right via the
// shared codeClass fallback while code/type are silently dropped).
func TestBZStatusMap(t *testing.T) {
	want := map[string]int{
		"BZ185": http.StatusNotFound,
		"BZ186": http.StatusForbidden,
		"BZ187": http.StatusForbidden,
		"BZ188": http.StatusUnprocessableEntity,
		"BZ189": http.StatusUnprocessableEntity,
		"BZ190": http.StatusConflict,
		"BZ199": http.StatusForbidden,
		"BZ200": http.StatusConflict,
		"BZ201": http.StatusUnprocessableEntity,
	}
	for code, status := range want {
		rr := httptest.NewRecorder()
		writeMeetProblem(rr, httptest.NewRequest("GET", "/meet", nil), pgErrCode(code))
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
			t.Errorf("%s: problem `type` field is empty, want a meet problem URI", code)
		}
	}
}

// TestBZStatusMap_DefaultUnknownIs500 pins the default fallback: an
// unclassified/non-meet SQLSTATE never guesses a 4xx.
func TestBZStatusMap_DefaultUnknownIs500(t *testing.T) {
	rr := httptest.NewRecorder()
	writeMeetProblem(rr, httptest.NewRequest("GET", "/meet", nil), pgErrCode("23505"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("want 500 for an unclassified error, got %d", rr.Code)
	}
}
