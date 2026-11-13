package pgnotify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// TestListener_ConcurrentSubscribeNoConnBusy reproduces the direct-connection
// saturation flake: while Run's WaitForNotification blocks (and, in pgx, holds
// the conn lock for the whole wait), many concurrent Subscribe calls each issue
// LISTEN on the SAME conn. Before the fix that races into "conn busy"; after the
// fix every Subscribe succeeds AND its channel actually receives a notification,
// proving the LISTEN took effect on the shared conn.
func TestListener_ConcurrentSubscribeNoConnBusy(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	l := NewListener(conn, testsupport.TestLogger())
	runDone := make(chan struct{})
	go func() { defer close(runDone); l.Run(ctx) }()
	// Teardown order (defers run LIFO): stop Run, join it, THEN close the conn —
	// Run's goroutine owns the conn; closing it underneath Run is itself a race.
	defer conn.Close(context.Background()) //nolint:errcheck
	defer func() { cancel(); <-runDone }()

	// Let Run reach WaitForNotification so the conn lock is held — this is the
	// steady state in production and the condition that triggers "conn busy".
	time.Sleep(100 * time.Millisecond)

	const n = 40
	prefix := fmt.Sprintf("stress:%d:", time.Now().UnixNano())

	var got [n]atomic.Int32
	var subErr atomic.Value // error
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ch := fmt.Sprintf("%s%d", prefix, i)
			_, err := l.Subscribe(ctx, ch, func(*pgconn.Notification) {
				got[i].Add(1)
			})
			if err != nil {
				subErr.Store(err)
			}
		}(i)
	}
	wg.Wait()

	if v := subErr.Load(); v != nil {
		t.Fatalf("Subscribe failed under concurrency (direct-conn saturation): %v", v)
	}

	// Every LISTEN must be live on the shared conn: notify each channel and see it.
	notifier := testsupport.OpenTestPool(t)
	for i := 0; i < n; i++ {
		if _, err := notifier.Exec(ctx, "SELECT pg_notify($1, 'x')", fmt.Sprintf("%s%d", prefix, i)); err != nil {
			t.Fatalf("pg_notify: %v", err)
		}
	}

	deadline := time.After(5 * time.Second)
	for {
		delivered := 0
		for i := 0; i < n; i++ {
			if got[i].Load() > 0 {
				delivered++
			}
		}
		if delivered == n {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d/%d channels received a notification — a LISTEN was lost", delivered, n)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestListenerReconnectReloadsToggleChangedWhileDisconnected(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := testsupport.OpenTestPool(t)
	key := fmt.Sprintf("feature.listener-reconnect-test-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx,
		`INSERT INTO feature_toggles(key,enabled) VALUES($1,true)`, key,
	); err != nil {
		t.Fatalf("seed reconnect toggle: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM feature_toggles WHERE key=$1`, key)
	})
	flags, err := toggle.New(ctx, pool, nil)
	if err != nil {
		t.Fatalf("load feature flags: %v", err)
	}
	if !flags.IsEnabled(key) {
		t.Fatal("reconnect test toggle did not start enabled")
	}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect direct listener: %v", err)
	}
	listener := NewListener(conn, testsupport.TestLogger())
	listener.SetDSN(dsn)
	refreshed := make(chan error, 1)
	listener.OnReconnect(func(ctx context.Context) error {
		err := flags.Reload(ctx)
		refreshed <- err
		return err
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		listener.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if listener.conn != nil {
			_ = listener.conn.Close(context.Background())
		}
	})

	time.Sleep(100 * time.Millisecond)
	if err := conn.PgConn().Conn().Close(); err != nil {
		t.Fatalf("drop listener network connection: %v", err)
	}
	// Change the row during Listener.Run's reconnect backoff. No subscription
	// exists yet on the replacement connection, so this update cannot be
	// repaired by a later notification.
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled=false WHERE key=$1`, key,
	); err != nil {
		t.Fatalf("disable toggle during disconnect: %v", err)
	}

	select {
	case err := <-refreshed:
		if err != nil {
			t.Fatalf("authoritative refresh after reconnect: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("listener did not execute authoritative refresh after reconnect")
	}
	if flags.IsEnabled(key) {
		t.Fatal("toggle remained enabled after LISTEN reconnect missed its disable notification")
	}
}

func TestListenerReconnectRetriesFailedAuthoritativeRefresh(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}
	direct, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connect direct listener: %v", err)
	}
	defer direct.Close(t.Context())

	listener := NewListener(direct, testsupport.TestLogger())
	listener.SetDSN(dsn)
	var refreshes atomic.Int32
	refreshed := make(chan struct{})
	listener.OnReconnect(func(context.Context) error {
		if refreshes.Add(1) == 1 {
			return errors.New("transient authoritative refresh failure")
		}
		select {
		case <-refreshed:
		default:
			close(refreshed)
		}
		return nil
	})

	runCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go listener.Run(runCtx)

	if err := direct.PgConn().Conn().Close(); err != nil {
		t.Fatalf("force close listener socket: %v", err)
	}
	select {
	case <-refreshed:
	case <-time.After(10 * time.Second):
		t.Fatalf("authoritative refresh attempts = %d, want retry after failure", refreshes.Load())
	}
	if got := refreshes.Load(); got < 2 {
		t.Fatalf("authoritative refresh attempts = %d, want at least 2", got)
	}
}

func TestListenerDurableSubscriptionReplaysAfterInitialListenFailure(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	direct, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatalf("connect direct listener: %v", err)
	}
	listener := NewListener(direct, testsupport.TestLogger())
	listener.SetDSN(dsn)

	channel := fmt.Sprintf("durable_initial_failure_%d", time.Now().UnixNano())
	received := make(chan struct{}, 1)
	subResult := make(chan error, 1)
	go func() {
		_, err := listener.SubscribeDurable(
			t.Context(), channel, func(*pgconn.Notification) {
				select {
				case received <- struct{}{}:
				default:
				}
			},
		)
		subResult <- err
	}()

	// Inject the first LISTEN failure at the listener command boundary. The
	// durable handler must remain in the registry for reconnect replay.
	cmd := <-listener.cmds
	cmd.reply <- errors.New("injected initial LISTEN failure")
	if err := <-subResult; err == nil {
		t.Fatal("durable subscription unexpectedly hid the initial LISTEN failure")
	}

	if err := direct.PgConn().Conn().Close(); err != nil {
		t.Fatalf("force initial listener connection closed: %v", err)
	}
	runCtx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		listener.Run(runCtx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		if listener.conn != nil {
			_ = listener.conn.Close(context.Background())
		}
	})

	notifier := testsupport.OpenTestPool(t)
	deadline := time.After(12 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-received:
			return
		case <-ticker.C:
			if _, err := notifier.Exec(
				t.Context(), "SELECT pg_notify($1, 'disable')", channel,
			); err != nil {
				t.Fatalf("notify durable channel: %v", err)
			}
		case <-deadline:
			t.Fatal("durable handler did not receive notification after reconnect replay")
		}
	}
}
