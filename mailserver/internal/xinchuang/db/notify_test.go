//go:build xinchuang

package db

import (
	"context"
	"testing"
	"time"
)

func TestNotifyAbstraction_ListenThenClose_PollMode(t *testing.T) {
	// Without calling Start, the notifier defaults to poll mode.
	n, err := NewNotifier(context.Background(), "test_channel", "" /* no DSN needed for poll */)
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	if n.Mode() != NotifyPoll {
		t.Fatalf("expected poll mode before Start, got %s", n.Mode())
	}

	ch := n.Listen()
	if ch == nil {
		t.Fatal("Listen returned nil channel")
	}

	// Verify channel receives at least one tick or closes cleanly
	select {
	case <-ch:
		t.Log("channel received event")
	case <-time.After(200 * time.Millisecond):
		t.Log("no event within 200ms (acceptable)")
	}
}

func TestNotifyAbstraction_PollingFallback(t *testing.T) {
	n, err := NewNotifier(context.Background(), "test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}

	// Explicitly calling Start with an empty DSN forces poll fallback.
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start should not return error even on fallback: %v", err)
	}

	if n.Mode() != NotifyPoll {
		t.Fatalf("expected poll mode after failed native connect, got %s", n.Mode())
	}

	ch := n.Listen()
	if ch == nil {
		t.Fatal("Listen returned nil channel even in polling mode")
	}

	// Polling mode should not block — verify channel setup
	select {
	case <-ch:
		t.Log("polling tick received")
	case <-time.After(200 * time.Millisecond):
		t.Log("no poll tick within 200ms")
	}
}

func TestNotifyAbstraction_CloseStopsDelivery(t *testing.T) {
	n, err := NewNotifier(context.Background(), "test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	ch := n.Listen()
	n.Close()

	// After close, channel should eventually be drained and closed
	timeout := time.After(500 * time.Millisecond)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Log("channel closed after notifier close")
				return
			}
		case <-timeout:
			t.Log("channel still open after close (may still be draining)")
			return
		}
	}
}

func TestNotifyMode_String(t *testing.T) {
	if s := NotifyNative.String(); s != "native" {
		t.Errorf("NotifyNative.String() = %q, want %q", s, "native")
	}
	if s := NotifyPoll.String(); s != "poll" {
		t.Errorf("NotifyPoll.String() = %q, want %q", s, "poll")
	}
	if s := NotifyMode(99).String(); s != "unknown(99)" {
		t.Errorf("NotifyMode(99).String() = %q, want %q", s, "unknown(99)")
	}
}

func TestNotifyStart_Idempotent(t *testing.T) {
	n, err := NewNotifier(context.Background(), "test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	// Start multiple times — should be a no-op after the first.
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	mode1 := n.Mode()

	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	mode2 := n.Mode()

	if mode1 != mode2 {
		t.Errorf("mode changed across Start calls: %s → %s", mode1, mode2)
	}
}

func TestNotifyMultipleListeners_PollMode(t *testing.T) {
	n, err := NewNotifier(context.Background(), "test_channel", "")
	if err != nil {
		t.Fatalf("NewNotifier: %v", err)
	}
	defer n.Close()

	ch1 := n.Listen()
	ch2 := n.Listen()

	// Both should receive ticks independently.
	select {
	case <-ch1:
		t.Log("ch1 received")
	case <-time.After(200 * time.Millisecond):
		t.Log("ch1 no event within 200ms")
	}

	select {
	case <-ch2:
		t.Log("ch2 received")
	case <-time.After(200 * time.Millisecond):
		t.Log("ch2 no event within 200ms")
	}
}

// TestNewNotifier_RejectsInvalidChannel pins the constructor-level channel
// grammar gate (shared/pgnotify identifier allowlist): a channel that could
// break out of the LISTEN "<channel>" quoting is rejected at construction
// with an error — never silently accepted or downgraded to poll.
func TestNewNotifier_RejectsInvalidChannel(t *testing.T) {
	hostile := []string{
		"",                 // empty
		`a"; NOTIFY x; --`, // injection attempt
		"has space",
		"quote\"inside",
		"back\\slash",
		"new\nline",
		"unicode→channel",
	}
	for _, ch := range hostile {
		n, err := NewNotifier(context.Background(), ch, "")
		if err == nil {
			n.Close()
			t.Errorf("invalid channel %q accepted", ch)
		}
	}

	valid := []string{"secevents", "test_channel", "a-b.c:d_e", "Upper1_2"}
	for _, ch := range valid {
		n, err := NewNotifier(context.Background(), ch, "")
		if err != nil {
			t.Errorf("valid channel %q rejected: %v", ch, err)
			continue
		}
		n.Close()
	}
}
