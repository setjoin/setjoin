package toggle

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// ConfigChangedChannel is the shared feature/config invalidation channel.
const ConfigChangedChannel = "config_changed"

// reloadDebounceInterval coalesces config_changed bursts into one authoritative
// reload per window: short enough that a legitimate single flip propagates
// promptly, long enough that reducer bursts (bulk flips, registry migrations)
// cost one reload instead of one per notification. Tests may shorten it before
// binding; production code must not.
var reloadDebounceInterval = 50 * time.Millisecond

// Notification is the decoded config_changed envelope. Key and Enabled are
// decoded for process-specific observers only; the toggle lifecycle itself
// never consumes payload content (see notificationFlags). Payload is retained
// for adapters that need a domain key such as identity.source.N.
type Notification struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	Reload  bool   `json:"reload"`
	Payload string `json:"-"`
}

// Observer receives a notification only after the toggle snapshot has been
// updated or authoritatively reconciled. Implementations must be bounded; a
// listener dispatch loop invokes observers synchronously.
type Observer interface {
	ObserveNotification(context.Context, Notification)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(context.Context, Notification)

func (f ObserverFunc) ObserveNotification(ctx context.Context, notification Notification) {
	f(ctx, notification)
}

// NotificationListener is the listener lifecycle surface required by
// BindNotifications. Concrete direct-connection ownership remains in each
// binary's composition root.
type NotificationListener interface {
	RegisterReconnect(func(context.Context) error) func()
	SubscribeDurable(context.Context, string, func(*pgconn.Notification)) (int, error)
	Unsubscribe(string, int)
}

// notificationFlags is the authoritative snapshot surface the notification
// protocol needs. Payload content is never applied point-wise: a runtime value
// changes only through a full Reload that re-reads feature_toggles (the
// reducer-authoritative store). A forged, stale, foreign, or
// forged-higher-version notification can therefore never materialize a
// transient cache value the authoritative store does not hold, and
// protected-key (BZ263) changes stay reachable only through the audited
// reducer path.
type notificationFlags interface {
	Reload(context.Context) error
}

// debouncedReloader coalesces notification bursts into a single reload per
// fixed window. The first notification arms the window; later notifications
// replace the pending payload (last wins) without extending it, so sustained
// load still reloads once per interval. When the window closes, the pending
// notification is handed to run exactly once. A failed reload does not retry
// on its own; the next notification re-arms the window.
type debouncedReloader struct {
	interval time.Duration
	mu       sync.Mutex
	timer    *time.Timer
	pending  Notification
}

func newDebouncedReloader(interval time.Duration) *debouncedReloader {
	return &debouncedReloader{interval: interval}
}

func (d *debouncedReloader) schedule(notification Notification, run func(Notification)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer == nil {
		d.timer = time.AfterFunc(d.interval, func() {
			d.mu.Lock()
			pending := d.pending
			d.pending = Notification{}
			d.timer = nil
			d.mu.Unlock()
			run(pending)
		})
	}
	d.pending = notification
}

func (d *debouncedReloader) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.pending = Notification{}
}

func decodeNotification(message *pgconn.Notification) (Notification, string) {
	notification := Notification{}
	if message != nil {
		notification.Payload = message.Payload
	}
	if message == nil || json.Unmarshal([]byte(notification.Payload), &notification) != nil {
		notification.Reload = true
		return notification, "feature-toggle notification malformed; reconciling authoritative snapshot"
	}
	if notification.Key == "" && !notification.Reload {
		notification.Reload = true
		return notification, "feature-toggle notification has empty key; reconciling authoritative snapshot"
	}
	return notification, ""
}

// BindNotifications owns the feature-toggle notification protocol: register a
// reconnect reconciler, establish durable LISTEN, close the startup snapshot
// window with a post-LISTEN reload, treat every notification as a debounced
// reload hint (reload-only propagation: payload content is never applied to
// the snapshot), and unregister on cancellation. Connection creation, Run, and
// process-specific observers remain composition-root responsibilities. Startup
// and reconnect reloads run immediately; only notification-triggered reloads
// are debounced.
func BindNotifications(
	ctx context.Context,
	listener NotificationListener,
	flags notificationFlags,
	observer Observer,
	logger *slog.Logger,
) error {
	if logger == nil {
		logger = slog.Default()
	}
	var lifecycleMu sync.Mutex
	active := true

	observe := func(observeCtx context.Context, notification Notification) {
		if active && ctx.Err() == nil && observer != nil {
			observer.ObserveNotification(observeCtx, notification)
		}
	}
	reloadLocked := func(reloadCtx context.Context, notification Notification) error {
		if !active || ctx.Err() != nil {
			return nil
		}
		if err := flags.Reload(reloadCtx); err != nil {
			return err
		}
		observe(reloadCtx, notification)
		return nil
	}
	applyReload := func(reloadCtx context.Context, notification Notification) error {
		lifecycleMu.Lock()
		defer lifecycleMu.Unlock()
		return reloadLocked(reloadCtx, notification)
	}

	removeReconnect := listener.RegisterReconnect(func(reconnectCtx context.Context) error {
		return applyReload(reconnectCtx, Notification{Reload: true})
	})
	notifyReloads := newDebouncedReloader(reloadDebounceInterval)
	var (
		subscriptionID int
		cleanupOnce    sync.Once
	)
	cleanup := func() {
		cleanupOnce.Do(func() {
			lifecycleMu.Lock()
			active = false
			notifyReloads.stop()
			lifecycleMu.Unlock()
			removeReconnect()
			listener.Unsubscribe(ConfigChangedChannel, subscriptionID)
		})
	}

	subscriptionID, err := listener.SubscribeDurable(ctx, ConfigChangedChannel, func(message *pgconn.Notification) {
		lifecycleMu.Lock()
		defer lifecycleMu.Unlock()
		if !active || ctx.Err() != nil {
			return
		}
		notification, warning := decodeNotification(message)
		if warning != "" {
			logger.Warn(warning)
		}
		// Reload-only propagation: every notification is at most a reload
		// hint. Key/Enabled are decoded only for observers below; the runtime
		// snapshot changes exclusively through flags.Reload re-reading
		// feature_toggles, so no unauthenticated or forged payload can produce
		// a transient unauthorized value between the notification and the
		// reload.
		notifyReloads.schedule(notification, func(pending Notification) {
			lifecycleMu.Lock()
			defer lifecycleMu.Unlock()
			if err := reloadLocked(ctx, pending); err != nil {
				logger.Error("feature-toggle notification reload failed", "error", err)
			}
		})
	})
	if err != nil {
		cleanup()
		return err
	}
	if err := applyReload(ctx, Notification{Reload: true}); err != nil {
		cleanup()
		return err
	}
	if err := ctx.Err(); err != nil {
		cleanup()
		return err
	}
	go func() {
		<-ctx.Done()
		cleanup()
	}()
	return nil
}
