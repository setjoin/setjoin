package pgnotify

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidChannelRE(t *testing.T) {
	cases := []struct {
		channel string
		valid   bool
	}{
		{"tag:42", true},
		{"email_state", true},
		{"calendar.event.1", true},
		{"task-updates", true},
		{"", false},
		{"has space", false},
		{"has!bang", false},
		{"has@at", false},
		{"has#hash", false},
		{"normal_123:.-", true},
	}
	for _, tc := range cases {
		got := validChannelRE.MatchString(tc.channel)
		if got != tc.valid {
			t.Errorf("validChannelRE.MatchString(%q) = %v, want %v", tc.channel, got, tc.valid)
		}
	}
}

func TestRefreshAfterReconnectRunsEveryAuthoritativeRefresh(t *testing.T) {
	listener := NewListener(nil, nil)
	wantErr := errors.New("refresh failed")
	calls := 0
	listener.OnReconnect(func(context.Context) error {
		calls++
		return wantErr
	})
	listener.OnReconnect(func(context.Context) error {
		calls++
		return nil
	})

	err := listener.refreshAfterReconnect(context.Background())
	if calls != 2 {
		t.Fatalf("reconnect refresh calls = %d, want 2", calls)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("reconnect refresh error = %v, want %v", err, wantErr)
	}
}

func TestRegisterReconnectRemovalPreservesRemainingOrder(t *testing.T) {
	listener := NewListener(nil, nil)
	var calls []int
	removeFirst := listener.RegisterReconnect(func(context.Context) error {
		calls = append(calls, 1)
		return nil
	})
	listener.RegisterReconnect(func(context.Context) error {
		calls = append(calls, 2)
		return nil
	})
	removeFirst()
	removeFirst()
	if err := listener.refreshAfterReconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != 2 {
		t.Fatalf("reconnect calls=%v, want [2]", calls)
	}
}

func TestSubscribeDurableRetainsHandlerAfterInitialListenFailure(t *testing.T) {
	listener := NewListener(nil, nil)
	injected := errors.New("initial LISTEN failed")
	type result struct {
		id  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		id, err := listener.SubscribeDurable(
			context.Background(), "config_changed", func(*pgconn.Notification) {},
		)
		done <- result{id: id, err: err}
	}()

	cmd := <-listener.cmds
	cmd.reply <- injected
	got := <-done
	if !errors.Is(got.err, injected) {
		t.Fatalf("durable subscription error = %v, want %v", got.err, injected)
	}
	listener.mu.RLock()
	_, retained := listener.handlers["config_changed"][got.id]
	listener.mu.RUnlock()
	if !retained {
		t.Fatal("durable subscription handler was removed after initial LISTEN failure")
	}
}

func TestSubscribeRemovesRequestScopedHandlerAfterInitialListenFailure(t *testing.T) {
	listener := NewListener(nil, nil)
	injected := errors.New("initial LISTEN failed")
	done := make(chan error, 1)
	go func() {
		_, err := listener.Subscribe(
			context.Background(), "request_channel", func(*pgconn.Notification) {},
		)
		done <- err
	}()

	cmd := <-listener.cmds
	cmd.reply <- injected
	if err := <-done; !errors.Is(err, injected) {
		t.Fatalf("request-scoped subscription error = %v, want %v", err, injected)
	}
	listener.mu.RLock()
	_, retained := listener.handlers["request_channel"]
	listener.mu.RUnlock()
	if retained {
		t.Fatal("request-scoped handler leaked after initial LISTEN failure")
	}
}

func TestListenerSubscriptionLifecycleSerializesUnlistenAndDispatch(t *testing.T) {
	listener := NewListener(nil, nil)
	listener.OnReconnect(nil)
	if len(listener.reconnect) != 0 {
		t.Fatal("nil reconnect callback was retained")
	}
	if _, err := listener.Subscribe(
		context.Background(), "bad channel", func(*pgconn.Notification) {},
	); err == nil {
		t.Fatal("invalid LISTEN channel was accepted")
	}

	type subscription struct {
		id  int
		err error
	}
	firstDone := make(chan subscription, 1)
	calls := 0
	go func() {
		id, err := listener.Subscribe(
			context.Background(), "identity_changed",
			func(*pgconn.Notification) { calls++ },
		)
		firstDone <- subscription{id: id, err: err}
	}()
	listen := <-listener.cmds
	if listen.sql != `LISTEN "identity_changed"` {
		t.Fatalf("first command = %q", listen.sql)
	}
	listen.reply <- nil
	first := <-firstDone
	if first.err != nil {
		t.Fatal(first.err)
	}
	secondID, err := listener.Subscribe(
		context.Background(), "identity_changed",
		func(*pgconn.Notification) { calls++ },
	)
	if err != nil {
		t.Fatal(err)
	}
	listener.dispatch(&pgconn.Notification{Channel: "identity_changed"})
	if calls != 2 {
		t.Fatalf("notification dispatch calls = %d, want 2", calls)
	}

	listener.Unsubscribe("identity_changed", first.id)
	select {
	case command := <-listener.cmds:
		t.Fatalf("non-final unsubscribe issued %q", command.sql)
	default:
	}
	unsubscribeDone := make(chan struct{})
	go func() {
		listener.Unsubscribe("identity_changed", secondID)
		close(unsubscribeDone)
	}()
	unlisten := <-listener.cmds
	if unlisten.sql != `UNLISTEN "identity_changed"` {
		t.Fatalf("last command = %q", unlisten.sql)
	}
	unlisten.reply <- nil
	<-unsubscribeDone
}

func TestListenerExecHonorsCancellationBeforeAndAfterEnqueue(t *testing.T) {
	listener := NewListener(nil, nil)
	for index := 0; index < cap(listener.cmds); index++ {
		listener.cmds <- command{sql: "queued", reply: make(chan error, 1)}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := listener.exec(cancelled, "LISTEN never"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-enqueue cancellation = %v", err)
	}

	listener = NewListener(nil, nil)
	waiting, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- listener.exec(waiting, "LISTEN waiting")
	}()
	<-listener.cmds
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("post-enqueue cancellation = %v", err)
	}
}

func TestRetryDurableListenConvergesAfterFailure(t *testing.T) {
	listener := NewListener(nil, nil)
	listener.handlers["retry_channel"] = map[int]NotifyHandler{1: func(*pgconn.Notification) {}}

	done := make(chan struct{})
	go func() {
		listener.retryDurableListen("retry_channel")
		close(done)
	}()

	// First attempt fails, second succeeds: the retry loop must exit after
	// the success.
	cmd := <-listener.cmds
	if cmd.sql != `LISTEN "retry_channel"` {
		t.Fatalf("retry sql = %q", cmd.sql)
	}
	cmd.reply <- errors.New("still down")

	cmd2 := <-listener.cmds
	cmd2.reply <- nil // success

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop did not exit after successful LISTEN")
	}
}

func TestRetryDurableListenStopsWhenHandlersRemoved(t *testing.T) {
	listener := NewListener(nil, nil)
	listener.handlers["gone_channel"] = map[int]NotifyHandler{1: func(*pgconn.Notification) {}}

	done := make(chan struct{})
	go func() {
		// The handler disappears before the first retry tick: the loop must
		// exit without issuing any LISTEN.
		listener.mu.Lock()
		delete(listener.handlers, "gone_channel")
		listener.mu.Unlock()
		listener.retryDurableListen("gone_channel")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retry loop did not exit after handler removal")
	}
	select {
	case cmd := <-listener.cmds:
		t.Fatalf("unexpected command after handler removal: %q", cmd.sql)
	default:
	}
}

func TestUnsubscribeRejectsInvalidChannel(t *testing.T) {
	listener := NewListener(nil, nil)
	// Must not panic and must not enqueue an UNLISTEN for an identifier that
	// could never have been subscribed.
	listener.Unsubscribe("bad channel!", 1)
	select {
	case cmd := <-listener.cmds:
		t.Fatalf("invalid channel produced command %q", cmd.sql)
	default:
	}
}
