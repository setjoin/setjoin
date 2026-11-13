package identitysource

import (
	"context"
	"reflect"
	"sync"
)

// Controller owns one compatibility worker slot. It is used by the legacy
// AD/LDAP admin adapters while the catalog Supervisor handles multi-source
// workers. Replace always cancels and joins before starting the new worker.
type Controller struct {
	mu     sync.Mutex
	parent context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

func (c *Controller) Start(parent context.Context, worker Runnable) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parent = parent
	c.replaceLocked(worker)
}

func (c *Controller) Replace(worker Runnable) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.parent == nil {
		return
	}
	c.replaceLocked(worker)
}

func (c *Controller) replaceLocked(worker Runnable) {
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
		c.done = nil
	}
	if isNilRunnable(worker) {
		return
	}
	ctx, cancel := context.WithCancel(c.parent)
	done := make(chan struct{})
	c.cancel, c.done = cancel, done
	go func() {
		defer close(done)
		worker.Run(ctx)
	}()
}

// isNilRunnable closes Go's typed-nil interface trap: callers naturally pass
// a *SyncWorker that may be nil, and assigning that pointer to Runnable makes
// the interface itself non-nil. Starting it would launch a goroutine that
// panics on the first method dereference.
func isNilRunnable(worker Runnable) bool {
	if worker == nil {
		return true
	}
	value := reflect.ValueOf(worker)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (c *Controller) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parent = nil
	if c.cancel != nil {
		c.cancel()
		<-c.done
		c.cancel = nil
		c.done = nil
	}
}
