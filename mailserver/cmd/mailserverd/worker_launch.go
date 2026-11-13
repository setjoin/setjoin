package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// launchWorker adds lifecycle identity to an already-constructed void-returning
// worker without changing its policy. The method value is evaluated by the
// caller before this function runs, preserving synchronous construction. This
// wrapper intentionally does not recover panics, add retries, create a child
// context, cancel peers, or wait during shutdown.
func launchWorker(ctx context.Context, logger *slog.Logger, name string, run func(context.Context)) {
	if !workerEnabled(name) {
		return
	}
	go func() {
		logger.Info("background worker started", "worker", name)
		defer logger.Info("background worker returned", "worker", name)
		run(ctx)
	}()
}

// startWorker gates a helper that owns its goroutines. Startup remains
// synchronous, including any first claim or controller reconciliation.
func startWorker(ctx context.Context, name string, start func(context.Context)) {
	if workerEnabled(name) {
		start(ctx)
	}
}

func workerEnabled(name string) bool {
	for _, disabled := range strings.Split(os.Getenv("GO_WORKERS_OFF"), ",") {
		if name != "" && strings.TrimSpace(disabled) == name {
			return false
		}
	}
	return true
}
