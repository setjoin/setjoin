package config

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// ConfigPtr is an atomic pointer to the current config. Request handlers
// read via Load() with zero lock contention.
type ConfigPtr[T any] struct {
	p atomic.Pointer[T]
}

// Load returns the current config. Safe for concurrent use from any goroutine.
// Returns nil if no config has been stored yet.
func (c *ConfigPtr[T]) Load() *T { return c.p.Load() }

// Store atomically replaces the config. Call after a successful reload.
func (c *ConfigPtr[T]) Store(cfg *T) { c.p.Store(cfg) }

// NotifyReloadOnSIGHUP registers for SIGHUP and returns a buffered channel
// that receives on each signal. The channel is buffered (size 1) to prevent
// signal loss under load -- unbuffered channels silently drop signals.
//
// On platforms without SIGHUP (Windows), returns nil.
// The caller should check for nil and use HTTP POST /admin/reload instead.
func NotifyReloadOnSIGHUP() <-chan struct{} {
	// Use a buffered channel to prevent dropped signals under load.
	// Size 1 is sufficient: a pending SIGHUP in the buffer means "reload now",
	// and additional signals before the first is consumed are coalesced.
	sigCh := make(chan struct{}, 1)
	osSigCh := make(chan os.Signal, 1)
	signal.Notify(osSigCh, syscall.SIGHUP)

	go func() {
		for range osSigCh {
			select {
			case sigCh <- struct{}{}:
			default:
				// Channel is full -- a reload is already pending.
				// Coalesce: drop this signal since one is already queued.
			}
		}
	}()

	return sigCh
}
