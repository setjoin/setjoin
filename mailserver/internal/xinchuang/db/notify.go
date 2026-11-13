//go:build xinchuang

package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyMode indicates whether the notifier is using native LISTEN or polling.
type NotifyMode int

const (
	// NotifyNative uses PostgreSQL LISTEN/NOTIFY via a dedicated pgx connection.
	// Supported by PostgreSQL and PolarDB for PostgreSQL.
	NotifyNative NotifyMode = iota

	// NotifyPoll uses configurable-interval polling as a fallback for
	// databases without LISTEN/NOTIFY support.
	NotifyPoll
)

// String returns a human-readable mode name.
func (m NotifyMode) String() string {
	switch m {
	case NotifyNative:
		return "native"
	case NotifyPoll:
		return "poll"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// Notifier provides LISTEN/NOTIFY functionality with automatic fallback
// to polling for databases that do not support native PostgreSQL NOTIFY.
//
// DELIVERY GUARANTEE (XINCHUANG-DB-002): LISTEN/NOTIFY here is LOSSY by
// design and must never be treated as a delivery mechanism. Notifications
// emitted while the native connection is down (or while a slow listener's
// buffer is full — drops are counted and logged, never blocking) are gone.
// A notification is a wakeup meaning "go re-query", never "here is the
// event"; anything that must not be lost belongs in a durable substrate
// (e.g. the security_event_outbox drained by internal/secevents), with this
// notifier as a latency optimization only.
//
// DEGRADATION IS OBSERVABLE (XINCHUANG-DB-001): if Start cannot establish
// native LISTEN it stays non-fatal and falls back to payload-less polling,
// but the degradation is never silent — it is logged at Error level with the
// channel and reason, reflected in Mode(), and reported by Degraded() so a
// caller can gate on it. There is no success-shaped silence.
//
// Lifecycle:
//
//  1. NewNotifier(ctx, channel, dsn) — create the notifier
//  2. Start(ctx)                      — attempt native LISTEN; fall back to poll on error
//  3. Listen()                        — subscribe to notifications
//  4. Close()                         — stop all listeners and release the connection
//
// If Listen is called before Start, poll mode is used automatically (that is
// a caller choice, not a degradation — Degraded() stays false until a Start
// attempt actually failed over).
type Notifier struct {
	ctx    context.Context
	cancel context.CancelFunc

	channel string
	mode    NotifyMode
	// degraded records that a Start attempt tried native LISTEN and had to
	// fall back to poll (XINCHUANG-DB-001). False until such an attempt.
	degraded     bool
	conn         *pgx.Conn // dedicated connection for native LISTEN (not from pool)
	dsn          string
	logger       *slog.Logger
	listeners    map[chan string]struct{}
	mu           sync.RWMutex
	pollInterval time.Duration

	// drops counts payloads discarded because a listener buffer was full
	// (XINCHUANG-DB-002: the previously silent `default:` drop).
	drops atomic.Uint64
	// dropLogLast rate-limits the drop warning to one per dropLogEvery.
	dropLogLast  time.Time
	dropLogEvery time.Duration

	// onReconnect is the consumer-compensation hook (XINCHUANG-DB-002): it
	// fires after a successful re-LISTEN so the consumer can re-query for
	// notifications lost during the connection gap.
	onReconnect func()

	startOnce sync.Once
	loopOnce  sync.Once // ensures a single native listen-loop goroutine

	// loopWG tracks the native listen-loop goroutine. Close waits for it
	// before closing the dedicated connection: the loop reads the connection
	// inside pgx's WaitForNotification outside n.mu, so closing the conn under
	// an in-flight receive is a data race (observed by -race on the reconnect
	// acceptance test), not a coordinated shutdown.
	loopWG sync.WaitGroup

	// fanoutGate is a test-only seam (nil in production): the L2-C4 HOLD item
	// 1 regression test freezes fanout between the listener snapshot and the
	// sends — the exact interleaving where the pre-fix code had already
	// released n.mu and a concurrent cleanup could close a snapshotted
	// channel. On the fixed code the gate runs while fanout still holds n.mu,
	// so cleanup's delete+close stays fenced behind the in-flight sends.
	fanoutGate func()
}

// validChannel mirrors shared/pgnotify's channel grammar (identifier allowlist
// `^[a-zA-Z0-9_:.-]+$`). pgnotify's helper is unexported, so the grammar is
// restated here — this sink cannot drift into accepting what the shared
// listener would reject. Any LISTEN/UNLISTEN interpolation is gated on it.
const validChannelPattern = `^[a-zA-Z0-9_:.-]+$`

var validChannelRE = regexp.MustCompile(validChannelPattern)

// NewNotifier creates a Notifier for the given channel.
// dsn is the database connection string used to open a dedicated
// pgx connection for native LISTEN/NOTIFY.
//
// The channel is validated against the shared/pgnotify identifier grammar
// here, at the constructor — before it can ever reach `LISTEN "<channel>"`
// interpolation (SQL-INJECTION-IDENTIFIER-CONCATENATION hardening). An
// invalid channel fails fast with an error instead of falling back to poll,
// so a typo or hostile name can never silently downgrade delivery semantics.
func NewNotifier(ctx context.Context, channel string, dsn string) (*Notifier, error) {
	if !validChannelRE.MatchString(channel) {
		return nil, fmt.Errorf("xinchuang notifier: invalid channel %q (must match %s)", channel, validChannelPattern)
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Notifier{
		ctx:          ctx,
		cancel:       cancel,
		channel:      channel,
		mode:         NotifyPoll, // safe default until Start is called
		dsn:          dsn,
		logger:       slog.Default().With("component", "xinchuang_notifier", "channel", channel),
		listeners:    make(map[chan string]struct{}),
		pollInterval: 5 * time.Second,
		dropLogEvery: 5 * time.Second, // drop-warning rate limit; tests may shorten
	}, nil
}

// Mode returns which notification strategy is currently active.
func (n *Notifier) Mode() NotifyMode {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.mode
}

// Degraded reports whether a Start attempt tried to establish native LISTEN
// and had to fall back to payload-less polling (XINCHUANG-DB-001). Callers
// can gate on it to surface the latency degradation. False before Start and
// after a successful native LISTEN.
func (n *Notifier) Degraded() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.degraded
}

// DroppedTotal returns how many listener deliveries have been discarded
// because a listener's buffer was full (XINCHUANG-DB-002 drop accounting).
func (n *Notifier) DroppedTotal() uint64 {
	return n.drops.Load()
}

// OnReconnect registers fn to be invoked after the native LISTEN connection
// is re-established following a loss. Notifications emitted during the gap
// were dropped by PostgreSQL (LISTEN is not durable), so the hook is the
// consumer's signal to re-query its source — the notifier compensates for
// nothing by itself. fn runs on the notifier's internal loop goroutine and
// MUST NOT block; a panic in fn is recovered and logged so it cannot kill
// the loop.
func (n *Notifier) OnReconnect(fn func()) {
	n.mu.Lock()
	n.onReconnect = fn
	n.mu.Unlock()
}

// Start attempts to establish native LISTEN/NOTIFY on a dedicated pgx
// connection. If the database or driver does not support LISTEN (returns
// an error), it falls back to polling. The fallback stays non-fatal — Start
// still returns nil — but it is never silent: it logs at Error level with
// the channel and reason, Mode() reflects poll, and Degraded() turns true
// (XINCHUANG-DB-001).
//
// Start is idempotent — subsequent calls are no-ops.
func (n *Notifier) Start(ctx context.Context) error {
	var startErr error
	n.startOnce.Do(func() {
		startErr = n.start(ctx)
	})
	return startErr
}

func (n *Notifier) start(ctx context.Context) error {
	// Attempt native LISTEN via a dedicated pgx connection.
	conn, err := pgx.Connect(ctx, n.dsn)
	if err != nil {
		// XINCHUANG-DB-001: degradation is observable, never success-shaped
		// silence. Poll keeps working; delivery guarantees live in the
		// durable outbox, so this costs latency, not events.
		n.logger.Error("native LISTEN connection failed — falling back to payload-less polling (DEGRADED)",
			"error", err)
		n.mu.Lock()
		n.mode = NotifyPoll
		n.degraded = true
		n.mu.Unlock()
		return nil // poll is always available
	}

	// Issue LISTEN on the dedicated connection.
	if _, err := conn.Exec(ctx, `LISTEN "`+n.channel+`"`); err != nil {
		n.logger.Error("LISTEN command failed — falling back to payload-less polling (DEGRADED)",
			"error", err)
		conn.Close(ctx)
		n.mu.Lock()
		n.mode = NotifyPoll
		n.degraded = true
		n.mu.Unlock()
		return nil // poll is always available
	}

	n.mu.Lock()
	n.conn = conn
	n.mode = NotifyNative
	n.mu.Unlock()

	n.logger.Info("native LISTEN established")
	return nil
}

// Listen returns a channel that receives notification payloads.
//
// Native mode (PostgreSQL / PolarDB for PostgreSQL):
//   - Payloads are delivered in real time as PostgreSQL NOTIFY events.
//   - A single dedicated goroutine fans out to all subscribers.
//   - Delivery is LOSSY: if this listener's buffer (16) is full, the payload
//     is dropped for this listener (counted; see DroppedTotal), and payloads
//     emitted during a connection gap never arrive (see OnReconnect).
//
// Poll mode (databases without native LISTEN/NOTIFY):
//   - The channel receives an empty string on each poll tick.
//   - Callers must re-query to detect changes.
//
// If Start has not been called, poll mode is used automatically.
func (n *Notifier) Listen() <-chan string {
	ch := make(chan string, 16)

	n.mu.Lock()
	n.listeners[ch] = struct{}{}
	mode := n.mode
	n.mu.Unlock()

	if mode == NotifyNative {
		// Ensure the native listen loop runs exactly once, shared by all
		// subscribers.
		n.loopOnce.Do(func() {
			n.loopWG.Add(1)
			go n.runNativeLoop()
		})
	} else {
		go n.poll(ch)
	}
	return ch
}

// runNativeLoop is the single goroutine that reads notifications from the
// dedicated pgx connection and fans them out to all registered listeners.
// On connection failure it attempts reconnection with exponential backoff
// and fires the OnReconnect hook after a successful re-LISTEN (XINCHUANG-
// DB-002: notifications emitted during the gap are lost; the hook is the
// consumer's compensation signal).
func (n *Notifier) runNativeLoop() {
	defer n.loopWG.Done()
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		err := n.waitForNotifications()
		if n.ctx.Err() != nil {
			return // clean shutdown
		}

		n.logger.Error("native LISTEN connection lost, reconnecting",
			"error", err, "backoff", backoff)

		select {
		case <-n.ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Reconnect and re-issue LISTEN.
		conn, dialErr := pgx.Connect(n.ctx, n.dsn)
		if dialErr != nil {
			n.logger.Error("native LISTEN reconnect failed", "error", dialErr)
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		if _, execErr := conn.Exec(n.ctx, `LISTEN "`+n.channel+`"`); execErr != nil {
			n.logger.Error("native LISTEN re-subscribe failed", "error", execErr)
			conn.Close(n.ctx)
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		n.mu.Lock()
		if n.conn != nil {
			n.conn.Close(n.ctx)
		}
		n.conn = conn
		n.mu.Unlock()

		backoff = time.Second // reset on successful reconnect
		n.logger.Info("native LISTEN re-established after connection loss — payloads emitted during the gap were lost; consumers must re-query")
		n.fireReconnect()
	}
}

// waitForNotifications blocks on WaitForNotification and fans out payloads
// to all registered listener channels. It returns on context cancellation,
// connection error, or when the connection is gone (nil-guarded against a
// concurrent Close setting conn to nil).
func (n *Notifier) waitForNotifications() error {
	for {
		n.mu.RLock()
		conn := n.conn
		n.mu.RUnlock()
		if conn == nil {
			// Close() ran between iterations (or Start never went native):
			// return instead of dereferencing nil (XINCHUANG-DB-002 rider).
			return errors.New("xinchuang notifier: connection closed")
		}

		notification, err := conn.WaitForNotification(n.ctx)
		if err != nil {
			return err
		}

		n.fanout(notification.Payload)
	}
}

// fanout delivers one payload to every registered listener without ever
// blocking. A full listener buffer drops the payload for that listener only
// — a slow consumer can never block the others — but the drop is accounted
// (XINCHUANG-DB-002): an atomic counter plus a rate-limited warning stating
// that LISTEN is lossy and re-querying is the delivery guarantee.
//
// Synchronization (L2-C4 HOLD item 1): the write lock is held across BOTH the
// listener snapshot and the nonblocking sends, and cleanup removes+closes a
// channel under that same lock. The old shape (RLock snapshot, release, then
// send) let the supported Listen-before-Start sequence panic at shutdown: a
// poll-mode listener registered before Start is removed and CLOSED by its poll
// goroutine's cleanup when the notifier stops, and a native-loop fanout
// holding only a stale snapshot could then execute `ch <- payload` on the
// closed channel ("send on closed channel"). With the lock held through the
// sends, every send either completes before cleanup takes the lock or its
// channel was already gone from the snapshot — the interleaving is gone. The
// sends stay nonblocking, so holding the lock never lets a slow listener
// stall Listen registration or Close.
func (n *Notifier) fanout(payload string) {
	n.mu.Lock()
	if n.fanoutGate != nil {
		n.fanoutGate()
	}
	dropped := 0
	for ch := range n.listeners {
		select {
		case ch <- payload:
		default:
			dropped++
		}
	}
	if dropped == 0 {
		n.mu.Unlock()
		return
	}

	total := n.drops.Add(uint64(dropped))
	logIt := time.Since(n.dropLogLast) >= n.dropLogEvery
	if logIt {
		n.dropLogLast = time.Now()
	}
	n.mu.Unlock()
	if logIt {
		n.logger.Warn("notification payload dropped for a slow listener (LISTEN is lossy — consumers must re-query; durable events belong in the outbox)",
			"dropped_now", dropped, "dropped_total", total)
	}
}

// fireReconnect invokes the OnReconnect hook after a successful re-LISTEN.
func (n *Notifier) fireReconnect() {
	n.mu.RLock()
	hook := n.onReconnect
	n.mu.RUnlock()
	if hook == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			n.logger.Error("OnReconnect hook panicked (recovered — listen loop stays alive)", "panic", r)
		}
	}()
	hook()
}

// poll sends an empty string on each tick so callers know to re-query.
// Used when the database does not support native LISTEN/NOTIFY.
func (n *Notifier) poll(ch chan string) {
	defer n.cleanup(ch)
	ticker := time.NewTicker(n.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			select {
			case ch <- "":
			default:
			}
		}
	}
}

// Close stops all listeners and releases the dedicated connection (if any).
// Cancellation comes first; the native loop is then joined BEFORE the
// connection is closed — the loop reads the conn inside pgx's
// WaitForNotification outside n.mu, so the close must never land under an
// in-flight receive (run with -race on the reconnect acceptance test to
// police this).
func (n *Notifier) Close() {
	n.cancel()
	n.loopWG.Wait()
	n.mu.Lock()
	if n.conn != nil {
		n.conn.Close(context.Background())
		n.conn = nil
	}
	n.mu.Unlock()
}

func (n *Notifier) cleanup(ch chan string) {
	n.mu.Lock()
	delete(n.listeners, ch)
	close(ch)
	n.mu.Unlock()
}
