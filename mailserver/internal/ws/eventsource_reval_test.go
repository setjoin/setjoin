package ws

// SSE arm of the periodic authorization re-validation (med-shard3-018): the
// EventSource stream must ride the SAME shared seam as the WS Upgrade loop —
// revalidateSessionAuthz on the authzRecheckInterval cadence (topology.go) —
// so a token whose exp passes mid-stream, or a demoted drive admin, loses the
// rail within the window. These are the SSE twins of the live-rail tests in
// authz_reval_test.go; the shared-helper decision tests there cover both
// transports and are not duplicated here.

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
)

// startRevalEventSourceServer exposes h.EventSource on a loopback httptest
// server (the SSE counterpart of startRevalUpgradeServer).
func startRevalEventSourceServer(t *testing.T, h *Handler) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(h.EventSource))
	t.Cleanup(srv.Close)
	return srv.URL
}

// openRevalSSE opens a real client SSE stream with bearer auth and pins the
// 200 + text/event-stream handshake before any frame is read.
func openRevalSSE(t *testing.T, url, token string) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		t.Fatalf("new SSE request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("open SSE stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("SSE handshake status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		resp.Body.Close()
		cancel()
		t.Fatalf("SSE Content-Type = %q, want text/event-stream", ct)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, cancel
}

// pumpSSEFrames reads the stream body in one goroutine and delivers complete
// SSE frames (blank-line terminated) on frames; the terminal read error (EOF
// after the server tears the rail down) lands on errs. Exactly one reader —
// net/http bodies forbid concurrent reads.
func pumpSSEFrames(t *testing.T, resp *http.Response) (<-chan string, <-chan error) {
	t.Helper()
	frames := make(chan string, 4)
	errs := make(chan error, 1)
	go func() {
		br := bufio.NewReader(resp.Body)
		var frame strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				errs <- err
				return
			}
			frame.WriteString(line)
			if line == "\n" {
				frames <- frame.String()
				frame.Reset()
			}
		}
	}()
	return frames, errs
}

// expectSSECloseAfter is the SSE twin of expectWSCloseAfter, in one
// single-reader flow:
//
//  1. Aliveness — the initial `event: state` frame arrives on the stream.
//  2. mutate — the authorization change under test.
//  3. The same stream must then hit its terminal read error (EOF) within the
//     window — any survival past it means the rail stayed open, which fails
//     the test.
func expectSSECloseAfter(t *testing.T, frames <-chan string, errs <-chan error, mutate func(), window time.Duration) {
	t.Helper()

	// Phase 1 — the rail must prove itself alive BEFORE the change.
	select {
	case fr := <-frames:
		if !strings.Contains(fr, "event: state") {
			t.Fatalf("first SSE frame = %q, want the initial state event", fr)
		}
	case err := <-errs:
		t.Fatalf("SSE stream failed before the authorization change: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no initial state frame within 5s — SSE push rail not alive")
	}

	// Phase 2 — apply the authorization change.
	mutate()

	// Phase 3 — teardown must land inside the window.
	select {
	case err := <-errs:
		if err == nil {
			t.Fatal("nil terminal error on a torn-down SSE rail")
		}
		// EOF / unexpected EOF / context canceled = the stream ended within
		// the window — the SSE demotion outcome.
		return
	case fr := <-frames:
		t.Fatalf("SSE rail kept streaming after the authorization change: %q", fr)
	case <-time.After(2 * window):
		t.Fatalf("SSE rail still open %vx2 after the authorization change", window)
	}
}

// TestSSEConnectionTeardownOnClaimsExpiry is the live-rail proof for the SSE
// expiry arm: a stream whose token exp passes mid-connection is closed within
// the re-validation window (SSE twin of TestWSConnectionTeardownOnClaimsExpiry).
func TestSSEConnectionTeardownOnClaimsExpiry(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live SSE push-rail teardown test")
	}
	pool := testsupport.OpenTestPool(t)
	userID, _ := provisionRevalMember(t, pool)

	h := newRevalHandler(t, pool, dsn) // shrinks authzRecheckInterval to revalInterval
	resp, cancel := openRevalSSE(t, startRevalEventSourceServer(t, h),
		mintExpiringPushAccessToken(t, userID, "sse-exp-jti", "sse-exp-family", 2*time.Second))
	defer cancel()

	// No external mutation: time itself is the change. The rail must prove
	// alive (initial state frame), then close once claims.exp passes, within
	// the window.
	frames, errs := pumpSSEFrames(t, resp)
	expectSSECloseAfter(t, frames, errs, func() {}, 5*time.Second)
}

// TestSSEConnectionTeardownOnDriveAdminDemotion is the live-rail proof for the
// SSE permission-loss arm: a connected drive admin keeps the stream open, and
// after a plain admin_role_assignments delete (the demotion with NO lifecycle
// teardown) the stream is closed within the re-validation window (SSE twin of
// TestWSConnectionTeardownOnDriveAdminDemotion).
func TestSSEConnectionTeardownOnDriveAdminDemotion(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live SSE push-rail teardown test")
	}
	pool := testsupport.OpenTestPool(t)
	userID, _ := provisionRevalMember(t, pool)
	grantRevalDriveAdmin(t, pool, userID)

	h := newRevalHandler(t, pool, dsn)
	demoteToken, _ := mintPushAccessToken(t, userID, "sse-demote-jti", "sse-demote-family")
	resp, cancel := openRevalSSE(t, startRevalEventSourceServer(t, h), demoteToken)
	defer cancel()

	frames, errs := pumpSSEFrames(t, resp)
	expectSSECloseAfter(t, frames, errs, func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM admin_role_assignments WHERE user_id = $1`, userID); err != nil {
			t.Errorf("demote: %v", err)
		}
	}, 5*time.Second)
}
