package main

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectorySyncTriggerSerializesAndCoalesces(t *testing.T) {
	t.Parallel()
	started := make(chan int32, 4)
	release := make(chan struct{}, 4)
	var active atomic.Int32
	var maxActive atomic.Int32
	var runs atomic.Int32
	trigger := newDirectorySyncTrigger(
		context.Background(),
		"ldap",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(context.Context) error {
			run := runs.Add(1)
			now := active.Add(1)
			for {
				max := maxActive.Load()
				if now <= max || maxActive.CompareAndSwap(max, now) {
					break
				}
			}
			started <- run
			<-release
			active.Add(-1)
			return nil
		},
	)

	trigger.Trigger("ldap_sync_host")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first sync did not start")
	}
	for i := 0; i < 64; i++ {
		trigger.Trigger("ldap_sync_changed")
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("concurrent runs = %d, want 1", got)
	}

	release <- struct{}{}
	select {
	case got := <-started:
		if got != 2 {
			t.Fatalf("coalesced run number = %d, want 2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced rerun did not start")
	}
	release <- struct{}{}

	deadline := time.Now().Add(2 * time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("runs = %d, want exactly 2", got)
	}
	if got := maxActive.Load(); got != 1 {
		t.Fatalf("maximum concurrent syncs = %d, want 1", got)
	}
}

func TestDirectorySyncTriggerStopsPendingWorkOnCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var runs atomic.Int32
	trigger := newDirectorySyncTrigger(
		ctx,
		"ad",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(context.Context) error {
			runs.Add(1)
			started <- struct{}{}
			<-release
			return nil
		},
	)
	trigger.Trigger("ad_sync_host")
	<-started
	trigger.Trigger("ad_sync_base_dn")
	cancel()
	close(release)

	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("runs after cancellation = %d, want 1", got)
	}
}
