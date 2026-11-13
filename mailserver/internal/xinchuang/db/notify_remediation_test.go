//go:build xinchuang

package db

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// captureDefaultLogger swaps slog's default logger for a text handler writing
// into the returned buffer. Must be called BEFORE NewNotifier (the notifier
// captures slog.Default() at construction).
func captureDefaultLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	prevLogWriter := log.Writer()
	prevLogFlags := log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	// slog.SetDefault ALSO points the standard log package at the new handler
	// (Go's log/slog bridge). Restore that writer too: otherwise every later
	// slog record in the binary silently lands in THIS test's buffer, and the
	// degradation diagnostics from later tests never reach the test log.
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevLogWriter)
		log.SetFlags(prevLogFlags)
	})
	return &buf
}

// TestStartFallbackDegradedObservable covers XINCHUANG-DB-001: a Start that
// cannot establish native LISTEN stays non-fatal but is never silent — the
// mode reflects poll, Degraded() reports the degradation, and the log carries
// an ERROR naming the channel and reason.
func TestStartFallbackDegradedObservable(t *testing.T) {
	logs := captureDefaultLogger(t)

	// Port 1 refuses connections immediately — the native attempt fails.
	n, err := NewNotifier(context.Background(), "secevents_test_channel",
		"postgres://127.0.0.1:1/no_such_db")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start must stay non-fatal on fallback, got: %v", err)
	}
	if n.Mode() != NotifyPoll {
		t.Fatalf("mode after failed native LISTEN = %s, want poll", n.Mode())
	}
	if !n.Degraded() {
		t.Fatal("Degraded() = false after a failed native attempt — the degradation must be observable")
	}

	out := logs.String()
	if !strings.Contains(out, `level=ERROR`) {
		t.Fatalf("fallback was not logged at Error level; logs:\n%s", out)
	}
	if !strings.Contains(out, "secevents_test_channel") || !strings.Contains(out, "DEGRADED") {
		t.Fatalf("fallback log must name the channel and the degradation; logs:\n%s", out)
	}
}

// TestNativeStartNotDegraded controls the happy path: a successful native
// LISTEN leaves Degraded() false (DB-backed; skips without DB_DSN following
// the testsupport fail-closed policy).
func TestNativeStartNotDegraded(t *testing.T) {
	// Capture (and dump on failure) so a container-specific LISTEN degradation
	// shows its pgx error instead of vanishing into a swallowed slog record.
	logs := captureDefaultLogger(t)
	dsn := requireTestDSN(t)

	n, err := NewNotifier(context.Background(), "secevents_test_channel", dsn)
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if n.Mode() != NotifyNative {
		t.Fatalf("mode = %s, want native", n.Mode())
	}
	if n.Degraded() {
		t.Fatalf("Degraded() = true after a successful native LISTEN; notifier logs:\n%s", logs.String())
	}
}

// TestDropAccountingOnFullListenerBuffer covers XINCHUANG-DB-002: a payload
// aimed at a full listener buffer is dropped without blocking, but the drop
// is accounted — the counter increments and a (rate-limited) warning fires
// instead of the old silent `default:`.
func TestDropAccountingOnFullListenerBuffer(t *testing.T) {
	logs := captureDefaultLogger(t)

	n, err := NewNotifier(context.Background(), "secevents_test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	// Register a listener directly: Listen() would spawn a poll ticker that
	// writes into the same buffer and muddy the drop accounting.
	ch := make(chan string, 1)
	n.mu.Lock()
	n.listeners[ch] = struct{}{}
	n.mu.Unlock()
	t.Cleanup(func() {
		n.mu.Lock()
		delete(n.listeners, ch)
		n.mu.Unlock()
	})

	n.fanout("first") // fills the 1-slot buffer — no drop
	if got := n.DroppedTotal(); got != 0 {
		t.Fatalf("DroppedTotal = %d after a buffered delivery, want 0", got)
	}

	n.fanout("second") // dropped — buffer full
	if got := n.DroppedTotal(); got != 1 {
		t.Fatalf("DroppedTotal = %d after one full-buffer delivery, want 1", got)
	}
	out := logs.String()
	if !strings.Contains(out, `level=WARN`) || !strings.Contains(out, "dropped_total=1") {
		t.Fatalf("drop was not logged (or counter missing from the log); logs:\n%s", out)
	}

	n.fanout("third") // dropped again — but the warning is rate-limited
	if got := n.DroppedTotal(); got != 2 {
		t.Fatalf("DroppedTotal = %d after two full-buffer deliveries, want 2", got)
	}
	if warns := strings.Count(logs.String(), `level=WARN`); warns != 1 {
		t.Fatalf("drop warning fired %d times within the rate-limit window, want 1; logs:\n%s",
			warns, logs.String())
	}

	// The other listeners still receive: fanout never blocks on a full one.
	ch2 := make(chan string, 4)
	n.mu.Lock()
	n.listeners[ch2] = struct{}{}
	n.mu.Unlock()
	n.fanout("fourth")
	select {
	case got := <-ch2:
		if got != "fourth" {
			t.Fatalf("healthy listener got %q, want the payload", got)
		}
	default:
		t.Fatal("healthy listener received nothing — fanout blocked or skipped it")
	}
}

// TestWaitForNotificationsNilConnGuarded covers the conn race rider: Close()
// sets conn = nil while waitForNotifications may be about to read it. With
// the connection gone the method must return an error, never dereference nil.
func TestWaitForNotificationsNilConnGuarded(t *testing.T) {
	n, err := NewNotifier(context.Background(), "secevents_test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	n.Close() // conn was never opened — nil under the same lock the reader takes

	if err := n.waitForNotifications(); err == nil {
		t.Fatal("waitForNotifications returned nil on a closed notifier — the nil conn must be guarded")
	}
}

// TestFanoutCannotSendOnClosedListenerDuringShutdown is the L2-C4 HOLD item 1
// regression test for the supported Listen-before-Start sequence: a listener
// registered while the notifier is still in poll mode is removed and CLOSED by
// its poll goroutine's cleanup at shutdown, while the native loop (started by
// a later Start going native) may be fanning out. The pre-fix fanout
// snapshotted the listener set under RLock, released the lock, and only then
// sent — a close landing in that window panicked with "send on closed
// channel". The fix holds n.mu across the snapshot AND the sends, with
// cleanup's delete+close under the same lock, so the interleaving is
// impossible. The fanoutGate seam freezes fanout at exactly that interleaving
// (snapshot taken, sends not started), making the race deterministic instead
// of a timing-dependent hammer.
func TestFanoutCannotSendOnClosedListenerDuringShutdown(t *testing.T) {
	n, err := NewNotifier(context.Background(), "secevents_test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()
	n.dropLogEvery = time.Hour // keep the rate-limited drop warning quiet

	// The victim: a poll-mode listener about to be shut down while a fanout
	// pass holds it in a snapshot.
	ch := make(chan string, 16)
	n.mu.Lock()
	n.listeners[ch] = struct{}{}
	n.mu.Unlock()

	snapshotted := make(chan struct{})
	release := make(chan struct{})
	n.fanoutGate = func() {
		close(snapshotted)
		<-release
	}
	t.Cleanup(func() { n.fanoutGate = nil })

	done := make(chan struct{})
	go func() {
		defer close(done)
		n.fanout("shutdown-race")
	}()
	<-snapshotted // snapshot holds the victim; no send has happened yet

	closed := make(chan struct{})
	go func() {
		n.cleanup(ch) // the poll goroutine's shutdown path: remove + close
		close(closed)
	}()

	// Pre-fix: fanout holds no lock here, so cleanup closes the victim
	// immediately (`closed` fires at once) and the sends below panic. Fixed:
	// fanout still holds n.mu, so `closed` cannot fire before the gate is
	// released — the close is fenced behind the in-flight sends.
	closedEarly := false
	select {
	case <-closed:
		closedEarly = true
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-done

	// The fenced cleanup gets its turn once the lock is free.
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup never completed after the fanout released the lock")
	}
	if closedEarly {
		t.Fatal("cleanup closed a listener channel while a fanout pass was frozen between its snapshot and its sends — the close must be fenced behind the in-flight sends (L2-C4 HOLD item 1); the pre-fix code panics here with \"send on closed channel\"")
	}
}

// TestOnReconnectFiresAfterReLISTEN covers the XINCHUANG-DB-002 compensation
// hook end-to-end: the notifier's dedicated LISTEN backend is terminated, the
// loop reconnects and re-subscribes, and OnReconnect fires so the consumer can
// re-query for notifications lost during the gap. DB-backed; skips without
// DB_DSN per the testsupport fail-closed policy.
func TestOnReconnectFiresAfterReLISTEN(t *testing.T) {
	dsn := requireTestDSN(t)

	// Tag the notifier's dedicated connection so pg_stat_activity can find it.
	const appName = "xinchuang_notify_reconnect_test"
	listenerDSN := withApplicationName(t, dsn, appName)

	logs := captureDefaultLogger(t)
	n, err := NewNotifier(context.Background(), "secevents_reconnect_test_channel", listenerDSN)
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	reconnected := make(chan struct{}, 1)
	n.OnReconnect(func() { reconnected <- struct{}{} })

	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if n.Mode() != NotifyNative || n.Degraded() {
		t.Fatalf("mode=%s degraded=%v, want native/undegraded; notifier logs:\n%s", n.Mode(), n.Degraded(), logs.String())
	}
	_ = n.Listen() // starts the shared native loop

	// Terminate the notifier's LISTEN backend to simulate connection loss.
	admin, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(context.Background())

	var pid int
	if err := admin.QueryRow(context.Background(),
		`SELECT pid FROM pg_stat_activity
		  WHERE application_name = $1 AND pid <> pg_backend_pid()
		  ORDER BY backend_start LIMIT 1`, appName).Scan(&pid); err != nil {
		t.Fatalf("notifier backend not found in pg_stat_activity (application_name=%s): %v", appName, err)
	}
	if _, err := admin.Exec(context.Background(),
		`SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatalf("pg_terminate_backend(%d): %v", pid, err)
	}

	// The loop reconnects (1s initial backoff) and fires the hook.
	select {
	case <-reconnected:
		// Compensation signal delivered.
	case <-time.After(20 * time.Second):
		t.Fatal("OnReconnect never fired after a forced LISTEN-backend loss")
	}
	if n.Mode() != NotifyNative {
		t.Fatalf("mode after reconnect = %s, want native (re-LISTEN)", n.Mode())
	}
}

// requireTestDSN mirrors the shared testsupport connect-or-skip policy for a
// raw DSN (the notifier needs a connection string, not a pool): DB_DSN unset
// skips locally and fails closed when REQUIRE_DB is set (CI).
func requireTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	return dsn
}

// withApplicationName appends (or merges) an application_name parameter into a
// Postgres DSN so the connection is identifiable in pg_stat_activity.
func withApplicationName(t *testing.T, dsn, name string) string {
	t.Helper()
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "application_name=" + name
}
