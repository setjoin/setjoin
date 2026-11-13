package notify

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/db"
)

// pgChannelGrammar is the in-package fail-closed allowlist of NOTIFY channels
// the dispatcher will LISTEN on (D-MAILSERVER-INTERNAL-NOTIFY-001,
// notification-channel-authorization): the exact channel universe the
// reducers emit (mailserver/sql/AGENTS.md → NOTIFY channel contract) and the
// ws session topology subscribes to — state-change channels tag:/calendar:/
// contact:/task:{mailbox}, session_revoke, drive-alarm, and the self-scoped
// drive-watch:/chat:/meet:{uid} channels. A channel outside this grammar is
// refused at Subscribe: transport callers still derive channel names
// server-side, and this gate makes a future drift fail loudly instead of
// silently binding fan-out to an attacker-chosen channel.
var (
	pgScopedChannelRe = regexp.MustCompile(`^(tag|calendar|contact|task):[1-9][0-9]*$`)
	pgUserChannelRe   = regexp.MustCompile(`^(drive-watch|chat|meet):[1-9][0-9]*$`)
)

// validPgChannel reports whether channel is in the known NOTIFY universe.
func validPgChannel(channel string) bool {
	switch channel {
	case "session_revoke", "drive-alarm":
		return true
	}
	return pgScopedChannelRe.MatchString(channel) || pgUserChannelRe.MatchString(channel)
}

// Dispatcher routes PostgreSQL NOTIFY messages to WebSocket clients.
//
// Design:
//   - One db.Listener handler is registered per PostgreSQL channel (fan-out handler).
//   - Many WebSocket clients can subscribe to the same channel.
//   - Each client gets a unique integer subscription ID for clean unsubscribe.
//   - The db.Listener subscription is released when the last client unsubscribes.
//
// This is the mechanism behind JMAP Push (RFC 8887). The channel id is always
// a mailbox id (ADR-003 account-scope currency), never a user id:
//
//	deliver() → pg_notify("tag:{mailbox_id}", {...}) → Dispatcher → WebSocket clients
type Dispatcher struct {
	listener      *db.Listener
	mu            sync.RWMutex
	clients       map[string]map[int]chan<- string // pgChannel → {subID → clientCh}
	listenerIDs   map[string]int                   // pgChannel → db.Listener subID
	subs          map[int]string                   // subID → registered pgChannel (teardown authority)
	nextSubID     int
	logger        *slog.Logger
	maxPerChannel int // hard limit to prevent memory exhaustion
}

func NewDispatcher(listener *db.Listener, logger *slog.Logger) *Dispatcher {
	return &Dispatcher{
		listener:      listener,
		clients:       make(map[string]map[int]chan<- string),
		listenerIDs:   make(map[string]int),
		subs:          make(map[int]string),
		logger:        logger,
		maxPerChannel: 1000, // 1000 concurrent WS clients per mailbox channel
	}
}

// Subscribe registers clientCh for notifications on pgChannel.
// Returns a subscription ID that must be passed to Unsubscribe when done.
// The channel must be inside the known NOTIFY universe (validPgChannel): an
// unknown channel is refused (fail closed), never silently LISTENed.
func (d *Dispatcher) Subscribe(ctx context.Context, pgChannel string, clientCh chan<- string) (int, error) {
	if !validPgChannel(pgChannel) {
		return 0, fmt.Errorf("channel %q is not in the dispatcher's NOTIFY channel grammar", pgChannel)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Assign a dispatcher-level subscription ID for this client.
	subID := d.nextSubID
	d.nextSubID++

	if d.clients[pgChannel] == nil {
		// First client for this channel — register a fan-out handler with the listener.
		handler := d.fanoutHandler(pgChannel)
		listenerID, err := d.listener.Subscribe(ctx, pgChannel, handler)
		if err != nil {
			return 0, err
		}
		d.listenerIDs[pgChannel] = listenerID
		d.clients[pgChannel] = make(map[int]chan<- string)
	}

	if len(d.clients[pgChannel]) >= d.maxPerChannel {
		return 0, fmt.Errorf("channel %s has reached max subscriber limit (%d)", pgChannel, d.maxPerChannel)
	}

	d.clients[pgChannel][subID] = clientCh
	d.subs[subID] = pgChannel
	return subID, nil
}

// Unsubscribe removes the subscription with the given ID from pgChannel.
// When no clients remain for the channel, the db.Listener subscription is released.
//
// The CHANNEL RESOLVED FROM THE STORED REGISTRATION governs teardown
// (D-MAILSERVER-INTERNAL-NOTIFY-001): a caller-supplied name that no longer
// matches the registration cannot strand the LISTEN by deleting against a
// different channel key — the subID is the subscription's identity, the
// stored channel its authority.
func (d *Dispatcher) Unsubscribe(pgChannel string, subID int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	registered, ok := d.subs[subID]
	if !ok {
		return
	}
	if registered != pgChannel && d.logger != nil {
		d.logger.Warn("notify unsubscribe channel mismatch; using registered channel",
			"sub_id", subID, "registered", registered, "supplied", pgChannel)
	}
	channel := registered
	delete(d.subs, subID)
	delete(d.clients[channel], subID)
	empty := len(d.clients[channel]) == 0
	if empty {
		listenerID := d.listenerIDs[channel]
		delete(d.clients, channel)
		delete(d.listenerIDs, channel)
		// Hold lock through Unsubscribe to prevent a concurrent Subscribe
		// from re-registering the channel between our cleanup and the UNLISTEN.
		d.listener.Unsubscribe(channel, listenerID)
	}
}

// fanoutHandler returns the single NotifyHandler registered with db.Listener for pgChannel.
// It reads the current client set on each notification to handle subscribe/unsubscribe races.
func (d *Dispatcher) fanoutHandler(pgChannel string) db.NotifyHandler {
	return func(n *pgconn.Notification) {
		d.mu.RLock()
		ch := d.clients[n.Channel]
		targets := make([]chan<- string, 0, len(ch))
		for _, clientCh := range ch {
			targets = append(targets, clientCh)
		}
		d.mu.RUnlock()

		for _, clientCh := range targets {
			select {
			case clientCh <- n.Payload:
			default:
				// Channel full — skip. Client will resync via JMAP state token mismatch.
				d.logger.Warn("notify channel full, dropping payload", "channel", n.Channel)
			}
		}
	}
}
