package main

import (
	"context"
	"log/slog"
	"sync"
)

// directorySyncTrigger serializes one directory source's config-change syncs.
// ConfigStore hooks fire once per changed key, so a batch can call Trigger many
// times. While a sync is running those calls collapse into one pending rerun:
// there is never more than one goroutine or one sync in flight per source.
type directorySyncTrigger struct {
	ctx    context.Context
	source string
	logger *slog.Logger
	run    func(context.Context) error

	mu      sync.Mutex
	running bool
	pending bool
}

func newDirectorySyncTrigger(
	ctx context.Context,
	source string,
	logger *slog.Logger,
	run func(context.Context) error,
) *directorySyncTrigger {
	return &directorySyncTrigger{
		ctx: ctx, source: source, logger: logger, run: run,
	}
}

func (t *directorySyncTrigger) Trigger(key string) {
	t.mu.Lock()
	if t.running {
		t.pending = true
		t.mu.Unlock()
		t.logger.Info(t.source+" config change coalesced", "key", key)
		return
	}
	t.running = true
	t.mu.Unlock()

	t.logger.Info(t.source+" config changed; triggering background sync", "key", key)
	go t.loop()
}

func (t *directorySyncTrigger) loop() {
	for {
		if err := t.run(t.ctx); err != nil && t.ctx.Err() == nil {
			t.logger.Error(t.source+" config-change sync failed", "error", err)
		}

		t.mu.Lock()
		if t.pending && t.ctx.Err() == nil {
			t.pending = false
			t.mu.Unlock()
			continue
		}
		t.running = false
		t.pending = false
		t.mu.Unlock()
		return
	}
}
