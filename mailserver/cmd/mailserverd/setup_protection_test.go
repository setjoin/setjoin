package main

// Owner decision A3 — setup endpoint protection tests: the setup
// completion-state endpoint is rate limited and 404s after setup completes
// (never a "done" answer), and every control-socket setup call requires the
// one-time setup token install.sh prints (fail-closed when unset).

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/middleware"
)

// setupGateRow is a pgx.Row stub answering the user-count probe.
type setupGateRow struct {
	count int
	err   error
}

func (r setupGateRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*int)) = r.count
	return nil
}

// setupGateDB satisfies queryRower with a fixed row.
type setupGateDB struct {
	row setupGateRow
}

func (d setupGateDB) QueryRow(context.Context, string, ...any) pgx.Row { return d.row }

func setupGateLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── (b) post-completion 404 ───────────────────────────────────────────────────

func TestSetupStatusGateReturns404AfterCompletion(t *testing.T) {
	gate := setupStatusGate(setupGateDB{row: setupGateRow{count: 3}},
		func(w http.ResponseWriter, _ *http.Request) {
			t.Error("status handler must not run once setup completed")
		}, setupGateLogger())
	rec := httptest.NewRecorder()
	gate(rec, httptest.NewRequest(http.MethodGet, "/setup/status", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("post-completion status = %d, want 404", rec.Code)
	}
	// The 404 must be the plain unknown-route answer, not a "done" body that
	// still discloses state.
	if strings.Contains(rec.Body.String(), "initialized") {
		t.Fatalf("404 body discloses setup state: %q", rec.Body.String())
	}
}

func TestSetupStatusGateFailsClosedOnDBError(t *testing.T) {
	gate := setupStatusGate(setupGateDB{row: setupGateRow{err: context.DeadlineExceeded}},
		func(w http.ResponseWriter, _ *http.Request) {
			t.Error("status handler must not run when the user count failed")
		}, setupGateLogger())
	rec := httptest.NewRecorder()
	gate(rec, httptest.NewRequest(http.MethodGet, "/setup/status", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("db-failure status = %d, want 404 (fail closed)", rec.Code)
	}
}

func TestSetupStatusGateServesUninitializedSystem(t *testing.T) {
	served := false
	gate := setupStatusGate(setupGateDB{row: setupGateRow{count: 0}},
		func(w http.ResponseWriter, _ *http.Request) {
			served = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"initialized": false}`))
		}, setupGateLogger())
	rec := httptest.NewRecorder()
	gate(rec, httptest.NewRequest(http.MethodGet, "/setup/status", nil))
	if !served || rec.Code != http.StatusOK {
		t.Fatalf("uninitialized system: served=%v status=%d, want the setup wizard's status answer", served, rec.Code)
	}
}

// ── (a) rate limit fires ─────────────────────────────────────────────────────

// TestSetupStatusRouteRateLimitFires drives the same chain shape the route
// registers (RateLimit middleware wrapping the A3 gate) and requires the
// budget to exhaust into 429s. The production limiter (HybridRateLimiter,
// keyed by trusted-proxy-aware client IP) is pinned to the route by the
// route-inventory golden + TestRouteInventory_LoadBearingChains; this test
// proves the composed shape actually enforces it.
func TestSetupStatusRouteRateLimitFires(t *testing.T) {
	limiter := middleware.NewRateLimiter(3, time.Minute)
	route := middleware.RateLimit(limiter)(http.HandlerFunc(setupStatusGate(
		setupGateDB{row: setupGateRow{count: 0}},
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
		setupGateLogger())))
	server := httptest.NewServer(route)
	t.Cleanup(server.Close)

	statuses := make([]int, 0, 5)
	for i := 0; i < 5; i++ {
		resp, err := http.Get(server.URL + "/setup/status")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		statuses = append(statuses, resp.StatusCode)
	}
	for i, status := range statuses[:3] {
		if status != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 within budget", i, status)
		}
	}
	for i, status := range statuses[3:] {
		if status != http.StatusTooManyRequests {
			t.Fatalf("request %d = %d, want 429 once the setup budget is exhausted", i+3, status)
		}
	}
}

// ── (c) one-time setup token on setup calls ──────────────────────────────────

func TestSetupTokenGateValidatesToken(t *testing.T) {
	const token = "a1b2c3d4e5f6a7b8"
	next := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	gate := setupTokenGate(token, setupGateLogger(), next)

	post := func(headerValue string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/setup/preflight", nil)
		if headerValue != "" {
			req.Header.Set(setupTokenHeader, headerValue)
		}
		rec := httptest.NewRecorder()
		gate(rec, req)
		return rec
	}

	if rec := post(""); rec.Code != http.StatusForbidden {
		t.Errorf("missing token = %d, want 403", rec.Code)
	}
	if rec := post("wrong-token"); rec.Code != http.StatusForbidden {
		t.Errorf("wrong token = %d, want 403", rec.Code)
	}
	// A token that is a prefix of the real one must not pass.
	if rec := post(token[:len(token)-1]); rec.Code != http.StatusForbidden {
		t.Errorf("prefix token = %d, want 403", rec.Code)
	}
	if rec := post(token); rec.Code != http.StatusOK {
		t.Errorf("valid token = %d, want the setup call to proceed (200)", rec.Code)
	}
}

func TestSetupTokenGateFailsClosedWithoutConfiguredToken(t *testing.T) {
	gate := setupTokenGate("", setupGateLogger(), func(w http.ResponseWriter, _ *http.Request) {
		t.Error("setup call must never proceed when SETJOIN_SETUP_TOKEN is unset")
	})
	req := httptest.NewRequest(http.MethodPost, "/setup/restore", nil)
	req.Header.Set(setupTokenHeader, "anything")
	rec := httptest.NewRecorder()
	gate(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unset configured token = %d, want 503 (fail closed)", rec.Code)
	}
}

// TestSetupControlSocketEnforcesToken walks the REAL control-socket mux
// registration: with a token configured, missing/wrong tokens are refused
// before the setup handlers run; with no token configured every setup call
// fails closed 503.
func TestSetupControlSocketEnforcesToken(t *testing.T) {
	dialContext := func(socket string) *http.Client {
		return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}}
	}
	startSocket := func(t *testing.T, token string) string {
		t.Helper()
		dir, err := os.MkdirTemp("/tmp", "sj-a3-token-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		socket := filepath.Join(dir, "control.sock")
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		if err := startSetupControlSocket(ctx, socket, token, nil, setupGateLogger()); err != nil {
			t.Fatal(err)
		}
		// Wait for the socket to accept (the server goroutine races Serve).
		deadline := time.Now().Add(2 * time.Second)
		for {
			if conn, dialErr := net.DialTimeout("unix", socket, 100*time.Millisecond); dialErr == nil {
				_ = conn.Close()
				return socket
			}
			if time.Now().After(deadline) {
				t.Fatal("control socket never became ready")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	post := func(client *http.Client, headerValue string) int {
		req, err := http.NewRequest(http.MethodPost, "http://setjoin-control/setup/preflight", nil)
		if err != nil {
			t.Fatal(err)
		}
		if headerValue != "" {
			req.Header.Set(setupTokenHeader, headerValue)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	socket := startSocket(t, "real-token")
	client := dialContext(socket)
	if got := post(client, ""); got != http.StatusForbidden {
		t.Errorf("control-socket preflight without token = %d, want 403", got)
	}
	if got := post(client, "wrong"); got != http.StatusForbidden {
		t.Errorf("control-socket preflight with wrong token = %d, want 403", got)
	}

	// No configured token: fail closed 503 — the handler is never reached.
	openSocket := startSocket(t, "")
	if got := post(dialContext(openSocket), "guess"); got != http.StatusServiceUnavailable {
		t.Errorf("control-socket preflight with unset configured token = %d, want 503 (fail closed)", got)
	}
}
