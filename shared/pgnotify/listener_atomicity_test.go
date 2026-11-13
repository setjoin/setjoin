package pgnotify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/testsupport"
)

// TestListenerSubscribeUnsubscribeDrainAtomicity is the deterministic,
// barrier-controlled regression for subscribe/unsubscribe atomicity against the
// command drain. A seam pauses Unsubscribe after its handler-map emptiness
// decision and before its UNLISTEN enqueue; a concurrent Subscribe then tries to
// re-insert a handler and enqueue LISTEN while it is parked. The FIFO drain must
// never apply UNLISTEN after a later subscribe's LISTEN: once the race settles,
// the server-side subscription state (pg_listening_channels on the live listener
// session) must match the in-process handler map, and a post-race NOTIFY must
// reach the surviving handler.
//
// The test itself owns the listener connection (Run is never started): it drains
// the command queue and executes each command on the connection exactly as the
// Run goroutine would, so pg_listening_channels and WaitForNotification can run
// on the same live session. Every wait is bounded, so a repair that deadlocks
// fails the test instead of hanging; the final assertions hold in every
// interleaving and do not depend on timing.
func TestListenerSubscribeUnsubscribeDrainAtomicity(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background()) //nolint:errcheck

	listener := NewListener(conn, testsupport.TestLogger())
	channel := fmt.Sprintf("atomicity_race_%d", time.Now().UnixNano())

	// drainOne executes the next queued command on the live connection, in FIFO
	// order, and records the SQL that the server actually applied.
	var drained []string
	drainOne := func() {
		t.Helper()
		select {
		case cmd := <-listener.cmds:
			_, err := conn.Exec(ctx, cmd.sql)
			cmd.reply <- err
			if err != nil {
				t.Fatalf("drain %q: %v", cmd.sql, err)
			}
			drained = append(drained, cmd.sql)
		case <-time.After(10 * time.Second):
			t.Fatalf("no command arrived within the drain bound (drained so far: %v)", drained)
		}
	}

	// Baseline: a live first subscriber puts the channel into steady state.
	// Subscribe blocks on its command reply, so it runs on its own goroutine
	// while the test drains — the same role split as Run.
	baselineDone := make(chan error, 1)
	var idA int
	go func() {
		id, err := listener.Subscribe(ctx, channel, func(*pgconn.Notification) {})
		idA = id
		baselineDone <- err
	}()
	drainOne()
	select {
	case err := <-baselineDone:
		if err != nil {
			t.Fatalf("baseline subscribe: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("baseline subscribe never completed (deadlocked repair?)")
	}
	if last := drained[len(drained)-1]; last != `LISTEN "`+channel+`"` {
		t.Fatalf("baseline command = %q, want LISTEN %q", last, channel)
	}
	if !serverSessionListening(t, conn, ctx, channel) {
		t.Fatalf("channel %q not live on the listener session after baseline LISTEN", channel)
	}

	// Barrier 1: park Unsubscribe between its emptiness decision and its
	// UNLISTEN enqueue.
	decided := make(chan struct{})
	var releaseOnce sync.Once
	release := make(chan struct{})
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	listener.testAfterUnsubscribeDecision = func() {
		close(decided)
		<-release
	}
	unsubscribeDone := make(chan struct{})
	go func() {
		defer close(unsubscribeDone)
		listener.Unsubscribe(channel, idA)
	}()
	select {
	case <-decided:
	case <-time.After(10 * time.Second):
		t.Fatal("Unsubscribe never reached its emptiness decision (deadlocked repair?)")
	}

	// A concurrent Subscribe now tries to re-insert a handler and enqueue LISTEN
	// while Unsubscribe is parked between decision and enqueue.
	type subResult struct {
		id  int
		err error
	}
	subscribeDone := make(chan subResult, 1)
	notified := make(chan struct{}, 1)
	go func() {
		id, err := listener.Subscribe(ctx, channel, func(*pgconn.Notification) {
			select {
			case notified <- struct{}{}:
			default:
			}
		})
		subscribeDone <- subResult{id: id, err: err}
	}()

	// Barrier 2: while parked, either the racing Subscribe completes (only a
	// broken implementation can let its LISTEN jump the parked UNLISTEN) or the
	// bounded park exhausts because the atomicity guarantee serialized it. The
	// bound is only the branch selector between the two shapes; every assertion
	// below holds in both. Anything already enqueued is drained in FIFO order.
	racingSubscribeWon := false
	parkBound := time.NewTimer(3 * time.Second)
	defer parkBound.Stop()
parked:
	for {
		select {
		case <-parkBound.C:
			break parked // serialized shape: Subscribe cannot pass the critical section
		case res := <-subscribeDone:
			if res.err != nil {
				t.Fatalf("racing subscribe: %v", res.err)
			}
			racingSubscribeWon = true
			break parked
		case cmd := <-listener.cmds:
			_, err := conn.Exec(ctx, cmd.sql)
			cmd.reply <- err
			if err != nil {
				t.Fatalf("drain %q: %v", cmd.sql, err)
			}
			drained = append(drained, cmd.sql)
			select {
			case res := <-subscribeDone:
				if res.err != nil {
					t.Fatalf("racing subscribe: %v", res.err)
				}
				racingSubscribeWon = true
			case <-time.After(10 * time.Second):
				t.Fatal("racing subscribe never completed after its command drained (deadlocked repair?)")
			}
			break parked
		}
	}

	// Release the parked Unsubscribe and let both operations settle. A repair
	// that deadlocks fails these bounds instead of hanging the test.
	releaseOnce.Do(func() { close(release) })
	drainOne() // the parked Unsubscribe's UNLISTEN (or the serialized Subscribe's LISTEN)
	select {
	case <-unsubscribeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Unsubscribe never completed after release (deadlocked repair?)")
	}
	if !racingSubscribeWon {
		drainOne() // the racing Subscribe, serialized behind Unsubscribe, enqueues LISTEN now
		select {
		case res := <-subscribeDone:
			if res.err != nil {
				t.Fatalf("racing subscribe: %v", res.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("racing subscribe never completed after release (deadlocked repair?)")
		}
	}
	listener.testAfterUnsubscribeDecision = nil

	// INVARIANT 1: in-process state — exactly the racing handler survives.
	listener.mu.RLock()
	remaining := len(listener.handlers[channel])
	listener.mu.RUnlock()
	if remaining != 1 {
		t.Fatalf("handlers for %q = %d, want exactly the one racing subscriber", channel, remaining)
	}

	// INVARIANT 2: the last command the server applied for the channel must
	// agree with the surviving handler — UNLISTEN may never drain after a later
	// subscribe's LISTEN.
	if last := drained[len(drained)-1]; last != `LISTEN "`+channel+`"` {
		t.Fatalf("last drained command = %q, want LISTEN (drain order %v) — server state diverged from in-process handlers", last, drained)
	}

	// INVARIANT 3: actual server-side subscription state on the live listener
	// session must match the in-process handler map.
	if !serverSessionListening(t, conn, ctx, channel) {
		t.Fatalf("server-side subscription lost after the subscribe/unsubscribe race: pg_listening_channels has no %q (drain order %v)", channel, drained)
	}

	// INVARIANT 4: an invalidation NOTIFY sent after the race settled reaches
	// the surviving handler. The test plays runLoop's role on the conn it owns:
	// wait for the notification, then dispatch exactly as Run would.
	notifier := testsupport.OpenTestPool(t)
	if _, err := notifier.Exec(ctx, "SELECT pg_notify($1, 'post-race')", channel); err != nil {
		t.Fatalf("post-race pg_notify: %v", err)
	}
	notifyCtx, notifyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer notifyCancel()
	notification, err := conn.WaitForNotification(notifyCtx)
	if err != nil {
		t.Fatalf("no notification delivered after post-race NOTIFY (drain order %v): %v", drained, err)
	}
	if notification.Channel != channel {
		t.Fatalf("notification channel = %q, want %q", notification.Channel, channel)
	}
	listener.dispatch(notification)
	select {
	case <-notified:
	case <-time.After(10 * time.Second):
		t.Fatal("surviving handler did not receive the post-race invalidation NOTIFY")
	}

	// INVARIANT 5: nothing is left queued behind the settled race.
	select {
	case cmd := <-listener.cmds:
		t.Fatalf("unexpected queued command %q after the race settled", cmd.sql)
	default:
	}
}

// TestStalledSubscribeCannotPinOtherSubscribersOrUnsubscribe is the
// barrier-controlled lifecycle regression for cancellation-aware serialization
// acquisition. The command consumer is stopped (Run never starts and the test
// stops draining after the baseline): a subscriber enqueues LISTEN and then
// blocks indefinitely on its reply while holding the serialization semaphore.
// Against that stalled holder:
//
//  1. a second subscriber must fail at its own context deadline instead of
//     blocking unboundedly behind the stall, and
//  2. Unsubscribe must still complete within its whole-operation bound
//     (unsubBound, shrunk here from the production five seconds) instead of
//     never reaching it, abandoning with the handler left registered rather
//     than half-applied.
//
// The barrier is deterministic: receiving the stalled LISTEN out of the queue
// proves the holder is inside its critical section, and every wait is bounded,
// so a repair that re-introduces uncancellable acquisition fails the test
// instead of hanging.
func TestStalledSubscribeCannotPinOtherSubscribersOrUnsubscribe(t *testing.T) {
	listener := NewListener(nil, nil)
	listener.unsubBound = 300 * time.Millisecond

	// Establish one removable subscription while the consumer still replies
	// (the test plays the Run role by hand, then stops consuming).
	baseDone := make(chan error, 1)
	var baseID int
	go func() {
		id, err := listener.Subscribe(context.Background(), "bounded_channel", func(*pgconn.Notification) {})
		baseID = id
		baseDone <- err
	}()
	baseCmd := <-listener.cmds
	if baseCmd.sql != `LISTEN "bounded_channel"` {
		t.Fatalf("baseline command = %q", baseCmd.sql)
	}
	baseCmd.reply <- nil
	if err := <-baseDone; err != nil {
		t.Fatal(err)
	}

	// The stall: this LISTEN is never served or replied to, so its Subscribe
	// holds the serialization for the rest of the test. Cleanup replies to it
	// so the goroutine exits deterministically instead of leaking.
	stalledDone := make(chan struct{})
	var stalledCmd command
	go func() {
		defer close(stalledDone)
		_, _ = listener.Subscribe(context.Background(), "stalled_channel", func(*pgconn.Notification) {})
	}()
	stalledCmd = <-listener.cmds
	if stalledCmd.sql != `LISTEN "stalled_channel"` {
		t.Fatalf("stall command = %q", stalledCmd.sql)
	}
	t.Cleanup(func() {
		stalledCmd.reply <- nil
		<-stalledDone
	})

	// 1. A second subscriber must honor its own deadline: acquisition of the
	// serialization is cancellation-aware, so it fails instead of parking
	// behind the stalled holder.
	secondCtx, cancelSecond := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancelSecond()
	secondDone := make(chan error, 1)
	go func() {
		_, err := listener.Subscribe(secondCtx, "other_channel", func(*pgconn.Notification) {})
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("second subscriber error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stalled subscribe pinned a second subscriber past its deadline")
	}

	// 2. Unsubscribe must reach and honor its whole-operation bound instead of
	// blocking forever on acquisition.
	start := time.Now()
	listener.Unsubscribe("bounded_channel", baseID)
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("Unsubscribe exceeded its whole-operation bound: %v", elapsed)
	}
	listener.mu.RLock()
	_, retained := listener.handlers["bounded_channel"][baseID]
	listener.mu.RUnlock()
	if !retained {
		t.Fatal("abandoned unsubscribe half-applied: handler was removed without its serialized UNLISTEN")
	}
}

// serverSessionListening reports whether channel is in pg_listening_channels on
// the given live listener session. The caller must solely own the connection.
func serverSessionListening(t *testing.T, conn *pgx.Conn, ctx context.Context, channel string) bool {
	t.Helper()
	rows, err := conn.Query(ctx, `SELECT pg_listening_channels()`)
	if err != nil {
		t.Fatalf("pg_listening_channels: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan pg_listening_channels: %v", err)
		}
		if name == channel {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("pg_listening_channels rows: %v", err)
	}
	return found
}
