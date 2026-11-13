// Package pgnotify provides reconnecting PostgreSQL LISTEN/NOTIFY delivery for
// process-local caches and other subscribers that require direct connections.
package pgnotify

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var validChannelRE = regexp.MustCompile(`^[a-zA-Z0-9_:.-]+$`)

// validateChannel enforces the identifier grammar at EVERY SQL-adjacent sink,
// not only Subscribe: UNLISTEN (Unsubscribe) and the post-reconnect replay
// (reSubscribe) interpolate the channel into LISTEN/UNLISTEN statements, so
// the same allowlist must gate all three. Defense-in-depth: current callers
// are map-derived or operator-configured, but the sink never trusts that.
func validateChannel(channel string) bool {
	return validChannelRE.MatchString(channel)
}

// NotifyHandler is called with each PostgreSQL notification on a subscribed channel.
// It is an alias so listener-agnostic lifecycle interfaces can name the plain
// function signature without importing pgnotify.
type NotifyHandler = func(msg *pgconn.Notification)

// command is a LISTEN/UNLISTEN executed on the Run goroutine — the sole owner of
// the pgx conn. pgx.Conn is NOT concurrent-safe: WaitForNotification locks the
// conn for its whole (blocking) duration, so a LISTEN Exec from a subscriber
// goroutine returns "conn busy". Funnelling every conn statement through one
// goroutine removes that race.
type command struct {
	sql   string
	reply chan error
}

type reconnectRegistration struct {
	id      int
	refresh func(context.Context) error
}

// Listener manages LISTEN/NOTIFY subscriptions on a dedicated direct connection.
// PgBouncer in transaction mode cannot be used for LISTEN — use a raw pgx.Conn.
//
// Subscribe returns an integer ID used to Unsubscribe. Multiple callers may
// subscribe to the same PostgreSQL channel; LISTEN is issued only once per channel
// and UNLISTEN is issued only when the last subscriber unsubscribes.
//
// The conn is owned exclusively by the Run goroutine. Subscribe/Unsubscribe do
// not touch it — they enqueue a command and wake the Run loop out of
// WaitForNotification to run it, then wait for the result.
type Listener struct {
	conn     *pgx.Conn
	dsn      string
	mu       sync.RWMutex
	nextID   int
	handlers map[string]map[int]NotifyHandler // channel → {subID → handler}
	logger   *slog.Logger

	cmds            chan command
	interruptMu     sync.Mutex
	interrupt       context.CancelFunc // cancels the in-flight WaitForNotification; nil when Run isn't waiting
	reconnect       []reconnectRegistration
	nextReconnectID int

	// subMu is a capacity-1 semaphore serializing each subscribe/Unsubscribe
	// decide-and-enqueue critical section. The command queue is FIFO, so enqueue
	// order must match handler-map decision order: without subMu, Unsubscribe can
	// decide the channel empty and release mu before enqueueing UNLISTEN, a
	// concurrent Subscribe then re-inserts a handler and enqueues LISTEN first,
	// and the drain executes LISTEN,UNLISTEN — leaving the server unsubscribed
	// while an in-process handler stays live, with no error and no log on the
	// invalidation substrate. The critical section spans exec's blocking reply
	// wait, which cannot deadlock: drainCommands on the Run goroutine replies
	// without taking any listener lock, and nothing that holds mu or subMu
	// blocks on Run for any other reason. Unlike a sync.Mutex, the semaphore is
	// acquired through lockSub's context-aware select, so a caller stalled in
	// its own reply wait cannot pin later callers past their deadlines: other
	// Subscribes fail at their own ctx deadlines instead of blocking
	// unboundedly, and Unsubscribe bounds its entire operation — acquisition
	// included — by unsubBound. Callers need no external serialization.
	subMu chan struct{}

	// unsubBound bounds an entire Unsubscribe — serialization acquisition,
	// emptiness decision and UNLISTEN wait. When the budget lapses the
	// unsubscribe is abandoned with the handler left registered rather than
	// half-removed. The production value is five seconds; in-package tests
	// shrink it so stalled-holder bounds stay fast.
	unsubBound time.Duration

	// testAfterUnsubscribeDecision is nil in production. In-package tests set
	// it to pause Unsubscribe between the handler-map emptiness decision and
	// the UNLISTEN enqueue, deterministically forcing the interleaving that the
	// subMu atomicity guarantee excludes.
	testAfterUnsubscribeDecision func()

	// done is closed when Run exits (listener shutdown). The durable-LISTEN
	// retry goroutine watches it so a failed durable subscription's retry
	// loop cannot outlive the listener.
	done     chan struct{}
	doneOnce sync.Once
}

func NewListener(conn *pgx.Conn, logger *slog.Logger) *Listener {
	return &Listener{
		conn:     conn,
		handlers: make(map[string]map[int]NotifyHandler),
		logger:   logger,
		done:     make(chan struct{}),
		// ponytail: buffered so an enqueue doesn't need the loop to be actively
		// receiving; 1024 >> realistic in-flight subscribes. If it ever fills,
		// exec blocks on send (backpressure), never deadlocks — every prior
		// enqueue already fired an interrupt, so the loop is draining.
		cmds:       make(chan command, 1024),
		subMu:      make(chan struct{}, 1),
		unsubBound: 5 * time.Second,
	}
}

// SetDSN stores the DSN for reconnection.
func (l *Listener) SetDSN(dsn string) {
	l.dsn = dsn
}

// OnReconnect registers an authoritative-state refresh to run after every
// successful reconnect and LISTEN replay. Notifications missed while the
// connection was down are not replayed by PostgreSQL.
func (l *Listener) OnReconnect(refresh func(context.Context) error) {
	_ = l.RegisterReconnect(refresh)
}

// RegisterReconnect registers an authoritative-state refresh and returns an
// idempotent remover. Process-lifetime callers may keep using OnReconnect;
// context-bound lifecycle modules use the remover so a canceled binding cannot
// retain or invoke stale callbacks.
func (l *Listener) RegisterReconnect(refresh func(context.Context) error) func() {
	if refresh == nil {
		return func() {}
	}
	l.mu.Lock()
	id := l.nextReconnectID
	l.nextReconnectID++
	l.reconnect = append(l.reconnect, reconnectRegistration{id: id, refresh: refresh})
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			for i := range l.reconnect {
				if l.reconnect[i].id == id {
					l.reconnect = append(l.reconnect[:i], l.reconnect[i+1:]...)
					break
				}
			}
			l.mu.Unlock()
		})
	}
}

// exec enqueues a statement for the Run goroutine to run on the conn and blocks
// until it completes. This is the ONLY path by which LISTEN/UNLISTEN reach the
// conn during normal operation, guaranteeing serial access.
func (l *Listener) exec(ctx context.Context, sql string) error {
	cmd := command{sql: sql, reply: make(chan error, 1)}
	select {
	case l.cmds <- cmd:
	case <-ctx.Done():
		return ctx.Err()
	}
	// Wake the Run loop out of WaitForNotification so it drains the queue.
	l.interruptMu.Lock()
	if l.interrupt != nil {
		l.interrupt()
	}
	l.interruptMu.Unlock()
	select {
	case err := <-cmd.reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// lockSub acquires the subscribe serialization semaphore. A free semaphore is
// taken even when ctx is already done, preserving immediate acquisition for
// callers whose critical section needs no conn round trip; otherwise the wait
// for the current holder shares ctx's deadline, so one caller stalled inside
// its own decision-and-reply critical section cannot pin this one past it.
func (l *Listener) lockSub(ctx context.Context) error {
	select {
	case l.subMu <- struct{}{}:
		return nil
	default:
	}
	select {
	case l.subMu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// unlockSub releases the subscribe serialization semaphore.
func (l *Listener) unlockSub() { <-l.subMu }

// Subscribe registers h on channel and returns a subscription ID.
// Issues LISTEN to PostgreSQL if this is the first handler for the channel.
// A failed initial LISTEN removes the handler, preserving the ordinary
// request-scoped subscription contract.
// Concurrent Subscribe/Unsubscribe calls are atomic against the command drain:
// see the subMu field comment. Waiting behind another subscribe/Unsubscribe
// critical section is cancellation-aware and shares ctx's deadline.
func (l *Listener) Subscribe(ctx context.Context, channel string, h NotifyHandler) (int, error) {
	return l.subscribe(ctx, channel, h, false)
}

// SubscribeDurable registers a process-lifetime handler. If the initial LISTEN
// fails, the handler remains registered so Run can replay the channel after its
// next successful reconnect. The returned ID is valid even when err is non-nil
// and may be passed to Unsubscribe by callers that abandon the subscription.
func (l *Listener) SubscribeDurable(ctx context.Context, channel string, h NotifyHandler) (int, error) {
	return l.subscribe(ctx, channel, h, true)
}

func (l *Listener) subscribe(ctx context.Context, channel string, h NotifyHandler, durable bool) (int, error) {
	if !validateChannel(channel) {
		return 0, &pgconn.PgError{Message: "invalid channel name: " + channel}
	}

	// subMu keeps the handler-map decision and the LISTEN enqueue one atomic
	// step, so the FIFO drain order always matches the decision order. ctx
	// bounds the acquisition wait behind any other critical section, so a
	// stalled subscription elsewhere cannot block this caller past its own
	// deadline.
	if err := l.lockSub(ctx); err != nil {
		return 0, err
	}
	defer l.unlockSub()

	l.mu.Lock()
	firstForChannel := len(l.handlers[channel]) == 0
	if l.handlers[channel] == nil {
		l.handlers[channel] = make(map[int]NotifyHandler)
	}
	id := l.nextID
	l.nextID++
	l.handlers[channel][id] = h
	l.mu.Unlock()

	if firstForChannel {
		if err := l.exec(ctx, `LISTEN "`+channel+`"`); err != nil {
			if !durable {
				l.mu.Lock()
				delete(l.handlers[channel], id)
				if len(l.handlers[channel]) == 0 {
					delete(l.handlers, channel)
				}
				l.mu.Unlock()
				return 0, err
			}
			// Durable contract: the handler stays registered (the reconnect
			// replay will re-issue LISTEN), but a reconnect is only delivered
			// after a connection LOSS — on a connection that stays up, a
			// failed initial LISTEN would otherwise wait forever. Retry the
			// LISTEN from a background goroutine so the subscription still
			// converges; the error is returned synchronously either way, so
			// a caller that fails closed at boot is unaffected.
			if l.logger != nil {
				l.logger.Warn("pgnotify: durable LISTEN failed; retrying in background until it succeeds",
					"channel", channel, "error", err)
			}
			go l.retryDurableListen(channel)
			return id, err
		}
	}
	return id, nil
}

// durableListenRetryBounds tune the background retry for a failed durable
// initial LISTEN: each attempt is bounded (exec's reply wait cannot outlive
// it) and the between-attempt backoff doubles to a 30s ceiling, matching
// Run's reconnect backoff shape.
const (
	durableListenAttemptBound = 5 * time.Second
	durableListenMaxBackoff   = 30 * time.Second
)

// retryDurableListen re-issues the failed initial LISTEN for a retained
// durable handler until it succeeds, the channel loses its last handler
// (Unsubscribe), or the listener shuts down (Run exits). It runs on its own
// goroutine and only touches the conn through exec (the Run-goroutine
// command queue), never directly.
func (l *Listener) retryDurableListen(channel string) {
	backoff := time.Second
	for {
		select {
		case <-l.done:
			return
		case <-time.After(backoff):
		}

		l.mu.RLock()
		alive := len(l.handlers[channel]) > 0
		l.mu.RUnlock()
		if !alive {
			return
		}

		attemptCtx, cancel := context.WithTimeout(context.Background(), durableListenAttemptBound)
		err := l.exec(attemptCtx, `LISTEN "`+channel+`"`)
		cancel()
		if err == nil {
			if l.logger != nil {
				l.logger.Info("pgnotify: durable LISTEN retry succeeded", "channel", channel)
			}
			return
		}
		if l.logger != nil {
			l.logger.Warn("pgnotify: durable LISTEN retry failed; will retry",
				"channel", channel, "error", err, "retry_in", backoff)
		}
		backoff = min(backoff*2, durableListenMaxBackoff)
	}
}

// Unsubscribe removes the handler with the given subscription ID.
// Issues UNLISTEN when no handlers remain for the channel.
// Atomic against concurrent Subscribe calls: see the subMu field comment.
// The entire operation — serialization acquisition included — is bounded by
// unsubBound: if a stalled subscription pins the serialization, the
// unsubscribe is abandoned with the handler left registered rather than
// blocking unboundedly or being half-applied.
func (l *Listener) Unsubscribe(channel string, id int) {
	// Sink-side identifier enforcement: UNLISTEN interpolates the channel, so
	// the same grammar that gated Subscribe gates the unsubscribe path. A
	// channel that could never have been subscribed (subscribe rejects it)
	// can hold no handler; drop the request before building the statement.
	if !validateChannel(channel) {
		if l.logger != nil {
			l.logger.Warn("pgnotify: unsubscribe rejected invalid channel name", "channel", channel)
		}
		return
	}
	// One budget bounds acquisition, the emptiness decision and the UNLISTEN
	// wait together, so Unsubscribe always reaches its bound even when another
	// subscribe is stalled inside the critical section. subMu keeps the
	// emptiness decision and the UNLISTEN enqueue one atomic step. Releasing mu
	// between them would let a concurrent Subscribe re-insert a handler and
	// enqueue LISTEN ahead of this UNLISTEN, and the FIFO drain would then
	// unsubscribe the server while that handler stays live. The blocking reply
	// wait stays deadlock-free under subMu — see the subMu field comment.
	ctx, cancel := context.WithTimeout(context.Background(), l.unsubBound)
	defer cancel()
	if err := l.lockSub(ctx); err != nil {
		// Bounded abandonment. The handler stays registered: removing it
		// outside the serialization would break the decision/enqueue invariant
		// subMu guards, and a half-applied unsubscribe is worse than a
		// deferred one.
		if l.logger != nil {
			l.logger.Warn("pgnotify: unsubscribe abandoned; subscribe serialization stayed held",
				"channel", channel, "bound", l.unsubBound, "error", err)
		}
		return
	}
	defer l.unlockSub()

	l.mu.Lock()
	delete(l.handlers[channel], id)
	empty := len(l.handlers[channel]) == 0
	if empty {
		delete(l.handlers, channel)
	}
	l.mu.Unlock()

	if empty {
		if l.testAfterUnsubscribeDecision != nil {
			l.testAfterUnsubscribeDecision()
		}
		// Best-effort. The remaining budget of the shared bound applies, so it
		// can't wedge forever if Run has stopped.
		l.exec(ctx, `UNLISTEN "`+channel+`"`) //nolint:errcheck
	}
}

// Run blocks dispatching notifications to registered handlers until ctx is cancelled.
// On connection error, it reconnects with exponential backoff.
// Call in a dedicated goroutine. This goroutine is the sole owner of the conn.
func (l *Listener) Run(ctx context.Context) {
	defer func() {
		if l.conn != nil {
			_ = l.conn.Close(context.Background())
		}
		l.doneOnce.Do(func() { close(l.done) })
	}()

	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		err := l.runLoop(ctx)
		if ctx.Err() != nil {
			return // clean shutdown
		}
		l.logger.Error("LISTEN connection lost", "error", err, "retry_in", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Reconnect
		if l.dsn != "" {
			newConn, err := pgx.Connect(ctx, l.dsn)
			if err != nil {
				l.logger.Error("LISTEN reconnect failed", "error", err)
				backoff = min(backoff*2, maxBackoff)
				continue
			}
			if l.conn != nil {
				l.conn.Close(ctx)
			}
			l.conn = newConn
			// Re-issue LISTEN for all registered channels. Safe to touch the conn
			// directly here: runLoop has exited, so nothing else uses it.
			l.mu.RLock()
			channels := make([]string, 0, len(l.handlers))
			for ch := range l.handlers {
				channels = append(channels, ch)
			}
			l.mu.RUnlock()
			if err := l.reSubscribe(ctx, channels); err != nil {
				l.logger.Error("LISTEN re-subscribe failed", "error", err)
				_ = newConn.Close(ctx)
				backoff = min(backoff*2, maxBackoff)
				continue
			}
			if err := l.refreshAfterReconnect(ctx); err != nil {
				// A consumer could not reconstruct authoritative state missed
				// during the outage. Do not resume notification service with a
				// partially refreshed process: close this connection and retry
				// the whole reconnect sequence. Security caches invalidate
				// themselves before returning the error.
				l.logger.Error("LISTEN reconnect state refresh failed", "error", err)
				_ = newConn.Close(ctx)
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		} else {
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second
	}
}

// reSubscribe re-issues LISTEN for all registered channels after a reconnect.
// Called only from Run while runLoop is not active, so direct conn use is safe.
func (l *Listener) reSubscribe(ctx context.Context, channels []string) error {
	var errs []error
	for _, ch := range channels {
		if !validateChannel(ch) {
			// Every entry is map-derived and was validated at Subscribe;
			// a violation is a programming defect, so fail the replay loudly
			// rather than interpolate an unvalidated identifier.
			errs = append(errs, errors.New(ch+": invalid channel name"))
			continue
		}
		if _, err := l.conn.Exec(ctx, `LISTEN "`+ch+`"`); err != nil {
			errs = append(errs, errors.New(ch+": "+err.Error()))
		}
	}
	return errors.Join(errs...)
}

func (l *Listener) refreshAfterReconnect(ctx context.Context) error {
	l.mu.RLock()
	refreshers := make([]func(context.Context) error, 0, len(l.reconnect))
	for _, registration := range l.reconnect {
		refreshers = append(refreshers, registration.refresh)
	}
	l.mu.RUnlock()
	var errs []error
	for _, refresh := range refreshers {
		if err := refresh(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (l *Listener) runLoop(ctx context.Context) error {
	for {
		// Run any pending LISTEN/UNLISTEN before blocking — we own the conn here.
		if err := l.drainCommands(ctx); err != nil {
			return err
		}

		waitCtx, cancel := context.WithCancel(ctx)
		l.interruptMu.Lock()
		l.interrupt = cancel
		// A command enqueued between drainCommands and this point would otherwise
		// wait until the next NOTIFY; cancel now so we loop straight back to drain.
		if len(l.cmds) > 0 {
			cancel()
		}
		l.interruptMu.Unlock()

		n, err := l.conn.WaitForNotification(waitCtx)
		// Capture whether a command/parent actually interrupted the wait before
		// calling cancel below. Checking waitCtx.Err after our own cancel would
		// misclassify every real socket failure as an intentional interrupt and
		// spin forever on the dead connection instead of reconnecting.
		interrupted := waitCtx.Err() != nil

		l.interruptMu.Lock()
		l.interrupt = nil
		l.interruptMu.Unlock()
		cancel()

		if err != nil {
			if ctx.Err() != nil {
				return err // parent cancelled → shutdown
			}
			if interrupted {
				continue // interrupted to process a command
			}
			return err // real connection error → Run reconnects
		}
		l.dispatch(n)
	}
}

// drainCommands runs every queued LISTEN/UNLISTEN on the conn. A real conn error
// is returned so Run can reconnect; the command still gets that error as its reply.
func (l *Listener) drainCommands(ctx context.Context) error {
	for {
		select {
		case cmd := <-l.cmds:
			_, err := l.conn.Exec(ctx, cmd.sql)
			cmd.reply <- err
			if err != nil && ctx.Err() == nil && l.conn.IsClosed() {
				return err
			}
		default:
			return nil
		}
	}
}

func (l *Listener) dispatch(n *pgconn.Notification) {
	l.mu.RLock()
	hs := make([]NotifyHandler, 0, len(l.handlers[n.Channel]))
	for _, h := range l.handlers[n.Channel] {
		hs = append(hs, h)
	}
	l.mu.RUnlock()

	for _, h := range hs {
		h(n)
	}
}
