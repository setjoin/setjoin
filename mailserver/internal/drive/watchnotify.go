// watchnotify.go — the live-push half of spec §5.6 (plan Task 11). Subscribes
// to the 'drive' NOTIFY channel (bumped by drive_notify_change on every
// journal-worthy mutation, and by the P4 lock reducers' presence nudge — see
// drive_notify_change.sql / drive_file_lock.sql / drive_file_unlock.sql) and
// fans each event out to every interested watcher's own drive-watch:<uid>
// channel. The human/inbox fan-out (deliver()-based emails to watchers +
// folder admins + the branch creator) is drive_notify_event (P4 Task 8, SQL);
// this layer ONLY drives the live UI + P6's subscription inbox, so it
// consults drive_watches directly, respects its ops filter (NULL = all;
// a lock-kind event maps to the synthetic 'lock' class — drive_watches.ops
// documents "+ 'branch','lock' event classes", V114), and re-derives the
// watcher's current read capability per event (see watchersOf — a removed
// member's watch row can outlive their membership on legacy-mode spaces,
// where drive_member_revoke prunes bound artifacts only via the acl-mode
// drive_acl_bump path).
//
// Runs on workerPool (BYPASSRLS, deploy-gate RLS classification: a system
// fan-out with no single acting user — the approval_created/device_policy
// precedent): watcher resolution walks node ancestors across users, and
// drive_watches' own RLS is own-rows-only (same reasoning as
// drive_event_recipients, Task 8) — an invoker-rights read would see nothing
// but the caller's own watch row.
package drive

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// driveWatchRows is the read seam WatchNotifier needs. *pgxpool.Pool
// satisfies this directly (its Query method has this exact signature) —
// production wiring passes it unwrapped; watchnotify_test.go injects a fake
// with canned rows, no live DB/LISTEN required.
type driveWatchRows interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// WatchNotifier fans 'drive' NOTIFY payloads out to per-user drive-watch:<uid>
// pushes.
type WatchNotifier struct {
	pool   driveWatchRows
	notify func(ctx context.Context, channel, payload string) error
	logger *slog.Logger

	mu     sync.Mutex
	recent map[string]time.Time // "user:node:op" -> last-sent
}

// NewWatchNotifier builds a WatchNotifier. notify is the pg_notify seam
// (production: SELECT pg_notify($1,$2) on the given pool) — injected so unit
// tests can assert the exact (channel, payload) set without a live listener.
func NewWatchNotifier(pool driveWatchRows, notify func(ctx context.Context, channel, payload string) error, logger *slog.Logger) *WatchNotifier {
	return &WatchNotifier{pool: pool, notify: notify, logger: logger, recent: make(map[string]time.Time)}
}

// drivePayload is the union of the two shapes ever written to the 'drive'
// channel (verified against every app_notify('drive', …) call site):
// drive_notify_change writes {spaceId,seq}; the P4 lock reducers write
// {spaceId,kind:"lock",nodeId} (no seq — presence is never journaled, §5.4).
type drivePayload struct {
	SpaceID int64  `json:"spaceId"`
	Seq     *int64 `json:"seq"`
	Kind    string `json:"kind"`
	NodeID  *int64 `json:"nodeId"`
}

// dedupeWindow is the per-(user,node,op) live-push dedupe window.
// ponytail: in-memory per process (single-gateway deployments) — move to a
// table if a multi-gateway deployment ever needs cross-process dedupe.
const dedupeWindow = 60 * time.Second

// Handle resolves one 'drive' NOTIFY payload to its (nodeId, op), finds every
// watcher up the node's ancestor chain whose ops filter admits that op,
// dedupes per (user,node,op) within dedupeWindow, and pushes drive-watch:<uid>
// to each. Errors are logged and dropped — this is a best-effort live layer;
// drive_changes is the durable truth a client can always resync from.
func (w *WatchNotifier) Handle(ctx context.Context, payload string) {
	var p drivePayload
	if err := json.Unmarshal([]byte(payload), &p); err != nil {
		w.logger.Warn("drive: watchnotify malformed payload", "error", err, "payload", payload)
		return
	}

	var nodeID int64
	var op string
	switch {
	case p.Seq != nil:
		var found bool
		var err error
		nodeID, op, found, err = w.resolveChange(ctx, p.SpaceID, *p.Seq)
		if err != nil {
			w.logger.Warn("drive: watchnotify change lookup failed", "error", err)
			return
		}
		if !found {
			return // journal row already pruned/raced — nothing to fan out
		}
	case p.Kind == "lock" && p.NodeID != nil:
		nodeID, op = *p.NodeID, "lock"
	default:
		return // unrecognized shape — never emitted by a real reducer, drop defensively
	}

	users, err := w.watchersOf(ctx, nodeID, op)
	if err != nil {
		w.logger.Warn("drive: watchnotify watcher lookup failed", "error", err)
		return
	}
	if len(users) == 0 {
		return
	}

	out, err := json.Marshal(map[string]any{"nodeId": nodeID, "op": op, "spaceId": p.SpaceID})
	if err != nil {
		w.logger.Warn("drive: watchnotify payload marshal failed", "error", err)
		return
	}
	for _, uid := range users {
		if !w.shouldSend(uid, nodeID, op) {
			continue
		}
		channel := "drive-watch:" + strconv.FormatInt(uid, 10)
		if err := w.notify(ctx, channel, string(out)); err != nil {
			w.logger.Warn("drive: watchnotify push failed", "user_id", uid, "error", err)
		}
	}
}

func (w *WatchNotifier) resolveChange(ctx context.Context, spaceID, seq int64) (nodeID int64, op string, found bool, err error) {
	rows, err := w.pool.Query(ctx, `SELECT node_id, op FROM drive_changes WHERE space_id = $1 AND seq = $2`, spaceID, seq)
	if err != nil {
		return 0, "", false, err
	}
	defer rows.Close()
	if rows.Next() {
		if err := rows.Scan(&nodeID, &op); err != nil {
			return 0, "", false, err
		}
		found = true
	}
	return nodeID, op, found, rows.Err()
}

// watchersOf reads the V184 closure authority and returns every user watching
// that node or an ancestor whose ops filter admits op AND who still holds
// read_metadata on the EVENT node at fan-out time — the same
// drive_runtime_has_node_capability authority drive_watch_set gates watch
// creation with and drive_acl_revoke_bound_artifacts prunes stale watches
// with. Without this per-event re-derivation, a removed member's un-pruned
// legacy-mode drive_watches row would keep receiving nodeId/op/spaceId pushes
// as a near-real-time activity oracle (the capability check targets the event
// node, not the watched ancestor, because the event node is what the push
// discloses). The worker pool bypasses RLS, but using closure here still keeps
// notification ancestry identical to move/trash/auth facts and removes a
// second recursive implementation.
func (w *WatchNotifier) watchersOf(ctx context.Context, nodeID int64, op string) ([]int64, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT DISTINCT wa.user_id
		  FROM drive_nodes n
		  JOIN drive_node_closure c
		    ON c.space_id = n.space_id AND c.descendant_id = n.id
		  JOIN drive_watches wa ON wa.node_id = c.ancestor_id
		 WHERE n.id = $1
		   AND (wa.ops IS NULL OR $2 = ANY(wa.ops))
		   AND public.drive_runtime_has_node_capability(wa.user_id, n.id, 'read_metadata')`, nodeID, op)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		out = append(out, uid)
	}
	return out, rows.Err()
}

// shouldSend applies the dedupeWindow gate per (user,node,op).
func (w *WatchNotifier) shouldSend(userID, nodeID int64, op string) bool {
	key := strconv.FormatInt(userID, 10) + ":" + strconv.FormatInt(nodeID, 10) + ":" + op
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.recent[key]; ok && now.Sub(t) < dedupeWindow {
		return false
	}
	w.recent[key] = now
	return true
}
