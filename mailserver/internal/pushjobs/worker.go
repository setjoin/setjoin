// Package pushjobs drains push-intent queues: the mail-push worker (V107, QoL
// #9) plus, since Chat A3.5, a second drain leg for chat_push_intents.
// deliver() enqueues one push_intents row per delivered, non-spam, non-muted
// message when feature.mail_push is ON; chat_message_send enqueues one
// chat_push_intents row per sent message when feature.chat_push is ON. This
// worker claims each queue independently, re-checks the relevant policy gate
// (push_should_notify for mail; chat_push_should_notify per member for chat),
// resolves the recipient's non-revoked push devices, and dispatches via
// shared/push.
//
// Lifecycle mirrors approvaljobs/notifyjobs: started once at startup on the
// workerPool (BYPASSRLS — both queues + push_devices are cross-tenant), exits on
// ctx cancel. Claim + retry semantics are copied from scheduled_actions (FOR
// UPDATE SKIP LOCKED + attempts + capped exponential backoff), implemented in Go
// and shared across both legs via claimOn/markDoneOn/retryOrFailOn (table name
// is always a fixed Go string constant at the call site, never request-derived).
package pushjobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/pgxutil"
	sharedpush "setjoin.com/shared/push"
)

const (
	workerInterval = 3 * time.Second
	maxAttempts    = 5
	leaseWindow    = 2 * time.Minute

	guestDigestSendTimeout = 30 * time.Second

	pushIntentsTable = "push_intents"
	chatIntentsTable = "chat_push_intents"

	// chatReapAfter is how long a terminal (done/failed) chat_push_intents row
	// survives before the chat drain leg deletes it. Nothing reaps V107's
	// push_intents either (a pre-existing gap — noted here as a backport
	// candidate, not fixed in this rider). The 7-day interval is the A4 seam:
	// if the conversation audit chain grows to record push emissions, that
	// decision changes this retention.
	chatReapAfter = 7 * 24 * time.Hour
)

// Worker drains push_intents and dispatches mail push notifications.
type Worker struct {
	pool           pgxutil.WorkerPool
	providers      *sharedpush.Set
	logger         *slog.Logger
	guestDigestCfg *GuestDigestConfig
}

// GuestDigestConfig holds the non-database dependencies for the guest digest
// drain. Database work always uses Worker.pool (the BYPASSRLS worker pool).
type GuestDigestConfig struct {
	MC         *minio.Client
	Bucket     string
	FromAddr   string
	FromName   string
	WebmailURL string
}

// SetGuestDigestConfig enables the guest digest drain without changing the
// established NewWorker signature. A nil object-store client leaves it inert.
func (w *Worker) SetGuestDigestConfig(cfg GuestDigestConfig) {
	w.guestDigestCfg = &cfg
}

// NewWorker creates a push worker. providers is the built dispatcher set (may be
// empty — the worker still drains, marking intents done when no device matches).
func NewWorker(pool pgxutil.WorkerPool, providers *sharedpush.Set, logger *slog.Logger) *Worker {
	return &Worker{pool: pool, providers: providers, logger: logger}
}

// Run starts the ticker loop. It exits cleanly when ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	w.logger.Info("push worker started", "interval", workerInterval, "providers", w.providers.Any())
	ticker := time.NewTicker(workerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("push worker stopped")
			return
		case <-ticker.C:
			for {
				claimed, err := w.processOne(ctx)
				if err != nil {
					if ctx.Err() == nil {
						w.logger.Warn("pushjobs: process failed", "error", err)
					}
					break
				}
				if !claimed {
					break
				}
			}
			// Second drain leg (Chat A3.5): chat_push_intents, same
			// lease/backoff shape as the mail leg above. Runs unconditionally
			// (like the drive worker) — feature.chat_push only gates the
			// enqueue in chat_message_send, never this drain. Chat draining
			// after mail within one tick means a mail backlog can delay chat
			// by one tick; accepted for a rider phase.
			for {
				claimed, err := w.processOneChat(ctx)
				if err != nil {
					if ctx.Err() == nil {
						w.logger.Warn("pushjobs(chat): process failed", "error", err)
					}
					break
				}
				if !claimed {
					break
				}
			}
			w.reapChatIntents(ctx)

			// Third drain leg (Guest G1): durable offline notification digests.
			// D11: feature.guest_accounts gates enqueue only; residue drains even
			// after the toggle is switched off.
			for {
				drained, err := w.DrainGuestDigests(ctx)
				if err != nil {
					if ctx.Err() == nil {
						w.logger.Warn("pushjobs(guest-digest): drain failed", "error", err)
					}
					break
				}
				if !drained {
					break
				}
			}
			w.reapGuestIntents(ctx)
		}
	}
}

type guestDigestIntent struct {
	id   int64
	kind string
	ref  string
}

// DrainGuestDigests processes at most one guest batch. true means a batch was
// sent or terminalized and another pass may help; active/throttled/locked
// guests are no progress and therefore cannot spin Run's drain loop.
func (w *Worker) DrainGuestDigests(ctx context.Context) (bool, error) {
	if w.guestDigestCfg == nil || w.guestDigestCfg.MC == nil {
		return false, nil
	}
	windowMinutes, err := w.guestDigestWindow(ctx)
	if err != nil {
		return false, err
	}

	rows, err := w.pool.Query(ctx,
		`SELECT DISTINCT user_id FROM guest_notification_intents
		  WHERE sent_at IS NULL ORDER BY user_id`)
	if err != nil {
		return false, fmt.Errorf("guest-digest: list pending guests: %w", err)
	}
	var guestIDs []int64
	for rows.Next() {
		var guestID int64
		if err := rows.Scan(&guestID); err != nil {
			rows.Close()
			return false, fmt.Errorf("guest-digest: scan pending guest: %w", err)
		}
		guestIDs = append(guestIDs, guestID)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return false, fmt.Errorf("guest-digest: list pending guests: %w", rowsErr)
	}

	for _, guestID := range guestIDs {
		progress, err := w.processGuestDigest(ctx, guestID, windowMinutes)
		if err != nil {
			return false, err
		}
		if progress {
			return true, nil
		}
	}
	return false, nil
}

func (w *Worker) guestDigestWindow(ctx context.Context) (int, error) {
	const defaultMinutes = 15
	var raw string
	err := w.pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key='guest.digest_window_minutes'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultMinutes, nil
	}
	if err != nil {
		return 0, fmt.Errorf("guest-digest: read digest window: %w", err)
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || minutes <= 0 {
		return 0, fmt.Errorf("guest-digest: invalid digest window")
	}
	return minutes, nil
}

// processGuestDigest holds a transaction-scoped advisory lock from status
// lookup through render, queue, and final stamp. The transaction deliberately
// spans the object-store write so the outbound_queue insert and intent stamp
// commit atomically; guestDigestSendTimeout bounds that network-I/O tradeoff.
func (w *Worker) processGuestDigest(ctx context.Context, guestID int64, windowMinutes int) (progress bool, err error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("guest-digest: begin guest transaction: %w", err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rollbackErr := tx.Rollback(rollbackCtx)
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) && err == nil {
			progress = false
			err = fmt.Errorf("guest-digest: rollback guest transaction: %w", rollbackErr)
		}
	}()

	var locked bool
	if err := tx.QueryRow(ctx,
		`SELECT pg_try_advisory_xact_lock(hashtextextended('setjoin.pushjobs.guest_digest:' || ($1::bigint)::text, 0))`,
		guestID).Scan(&locked); err != nil {
		return false, fmt.Errorf("guest-digest: acquire guest lock: %w", err)
	}
	if !locked {
		return false, nil
	}

	var status, invitedEmail string
	var enabled bool
	err = tx.QueryRow(ctx, `
		SELECT ga.status, ga.invited_email, u.enabled
		  FROM guest_accounts ga JOIN users u ON u.id=ga.user_id
		 WHERE ga.user_id=$1`, guestID).Scan(&status, &invitedEmail, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		progress, err = w.tombstoneGuestBatch(ctx, tx, guestID)
		if err != nil {
			return false, err
		}
		return commitGuestDigest(ctx, tx, progress)
	}
	if err != nil {
		return false, fmt.Errorf("guest-digest: read guest status: %w", err)
	}
	if status != "active" || !enabled {
		progress, err = w.tombstoneGuestBatch(ctx, tx, guestID)
		if err != nil {
			return false, err
		}
		return commitGuestDigest(ctx, tx, progress)
	}

	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM sessions
		 WHERE user_id=$1 AND last_seen_at > now()-interval '1 hour')`, guestID,
	).Scan(&active); err != nil {
		return false, fmt.Errorf("guest-digest: check active session: %w", err)
	}
	if active {
		return false, nil
	}
	var throttled bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM guest_notification_intents
		 WHERE user_id=$1 AND sent_at > now()-make_interval(mins => $2))`,
		guestID, windowMinutes).Scan(&throttled); err != nil {
		return false, fmt.Errorf("guest-digest: check throttle: %w", err)
	}
	if throttled {
		return false, nil
	}

	intents, err := loadGuestDigestBatch(ctx, tx, guestID)
	if err != nil {
		return false, err
	}
	if len(intents) == 0 {
		return false, nil
	}

	var orgName string
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key='org.name'),''),
		                'your organization')`).Scan(&orgName); err != nil {
		return false, fmt.Errorf("guest-digest: read organization name: %w", err)
	}
	lines := make([]string, 0, len(intents))
	for _, intent := range intents {
		line, err := w.renderIntentLine(ctx, tx, guestID, intent.kind, intent.ref)
		if err != nil {
			return false, err
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		progress, err = w.stampGuestBatch(ctx, tx, guestID, intents)
		if err != nil {
			return false, err
		}
		return commitGuestDigest(ctx, tx, progress)
	}

	subject := fmt.Sprintf("New activity in %s", orgName)
	if len(lines) > 1 {
		subject = fmt.Sprintf("%d new items in %s", len(lines), orgName)
	}
	body := strings.Join(lines, "\n") + fmt.Sprintf(
		"\n\nThis message was sent because you have a guest account in %s.\nLog in to view full content: %s\n",
		orgName, w.guestDigestCfg.WebmailURL)
	sendCtx, cancel := context.WithTimeout(ctx, guestDigestSendTimeout)
	defer cancel()
	if err := notify.SendSystemMail(sendCtx, tx, w.guestDigestCfg.MC,
		w.guestDigestCfg.Bucket, "digest/", w.guestDigestCfg.FromAddr,
		w.guestDigestCfg.FromName, invitedEmail, subject, body); err != nil {
		// The sender error may contain message content. Run logs this sanitized
		// result only; the batch remains pending for a later retry.
		return false, errors.New("guest-digest: send failed")
	}
	progress, err = w.stampGuestBatch(sendCtx, tx, guestID, intents)
	if err != nil {
		return false, err
	}
	return commitGuestDigest(sendCtx, tx, progress)
}

func commitGuestDigest(ctx context.Context, tx pgx.Tx, progress bool) (bool, error) {
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("guest-digest: commit guest transaction: %w", err)
	}
	return progress, nil
}

func loadGuestDigestBatch(ctx context.Context, q pgx.Tx, guestID int64) ([]guestDigestIntent, error) {
	rows, err := q.Query(ctx, `
		SELECT id,kind,ref FROM guest_notification_intents
		 WHERE user_id=$1 AND sent_at IS NULL
		 ORDER BY created_at,id LIMIT 50`, guestID)
	if err != nil {
		return nil, fmt.Errorf("guest-digest: load batch: %w", err)
	}
	defer rows.Close()
	var intents []guestDigestIntent
	for rows.Next() {
		var intent guestDigestIntent
		if err := rows.Scan(&intent.id, &intent.kind, &intent.ref); err != nil {
			return nil, fmt.Errorf("guest-digest: scan batch: %w", err)
		}
		intents = append(intents, intent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("guest-digest: load batch: %w", err)
	}
	return intents, nil
}

func (w *Worker) tombstoneGuestBatch(ctx context.Context, q pgx.Tx, guestID int64) (bool, error) {
	tag, err := q.Exec(ctx, `
		WITH batch AS (
		  SELECT id FROM guest_notification_intents
		   WHERE user_id=$1 AND sent_at IS NULL ORDER BY created_at,id LIMIT 50
		)
		UPDATE guest_notification_intents SET sent_at=now()
		 WHERE user_id=$1 AND sent_at IS NULL AND id IN (SELECT id FROM batch)`, guestID)
	if err != nil {
		return false, fmt.Errorf("guest-digest: tombstone batch: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (w *Worker) stampGuestBatch(ctx context.Context, q pgx.Tx, guestID int64, intents []guestDigestIntent) (bool, error) {
	ids := make([]int64, len(intents))
	for i := range intents {
		ids[i] = intents[i].id
	}
	tag, err := q.Exec(ctx, `
		UPDATE guest_notification_intents SET sent_at=now()
		 WHERE user_id=$1 AND sent_at IS NULL AND id=ANY($2)`, guestID, ids)
	if err != nil {
		return false, fmt.Errorf("guest-digest: stamp batch: %w", err)
	}
	if tag.RowsAffected() != int64(len(ids)) {
		return false, fmt.Errorf("guest-digest: stamp batch changed %d of %d rows", tag.RowsAffected(), len(ids))
	}
	return len(ids) > 0, nil
}

func parseGuestChatRef(ref string) (channelID, messageID int64, ok bool) {
	channel, message, found := strings.Cut(ref, ":")
	if !found {
		return 0, 0, false
	}
	channelID, err := strconv.ParseInt(channel, 10, 64)
	if err != nil || channelID <= 0 {
		return 0, 0, false
	}
	messageID, err = strconv.ParseInt(message, 10, 64)
	if err != nil || messageID <= 0 {
		return 0, 0, false
	}
	return channelID, messageID, true
}

// renderIntentLine returns no line for malformed/deleted/foreign refs. A real
// database error is distinct and fails the batch closed.
func (w *Worker) renderIntentLine(ctx context.Context, q pgx.Tx, guestID int64, kind, ref string) (string, error) {
	switch kind {
	case "mention":
		channelID, messageID, ok := parseGuestChatRef(ref)
		if !ok {
			return "", nil
		}
		var channelName, senderName, excerpt string
		err := q.QueryRow(ctx, `
			SELECT COALESCE(c.name,'conversation'),u.display_name,left(m.body,100)
			  FROM chat_messages m
			  JOIN chat_channels c ON c.id=m.channel_id
			  JOIN users u ON u.id=m.author_id
			  JOIN chat_mentions cm ON cm.message_id=m.id AND cm.mentioned_user_id=$3
			  JOIN chat_channel_members member ON member.channel_id=m.channel_id AND member.user_id=$3
			 WHERE m.id=$2 AND m.channel_id=$1 AND m.deleted_at IS NULL`,
			channelID, messageID, guestID).Scan(&channelName, &senderName, &excerpt)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("guest-digest: render mention: %w", err)
		}
		return fmt.Sprintf("You were mentioned in #%s by %s: %q", channelName, senderName, excerpt), nil
	case "dm":
		channelID, messageID, ok := parseGuestChatRef(ref)
		if !ok {
			return "", nil
		}
		var senderName, excerpt string
		err := q.QueryRow(ctx, `
			SELECT u.display_name,left(m.body,100)
			  FROM chat_messages m
			  JOIN chat_channels c ON c.id=m.channel_id AND c.kind='dm'
			  JOIN users u ON u.id=m.author_id
			  JOIN chat_channel_members member ON member.channel_id=m.channel_id AND member.user_id=$3
			 WHERE m.id=$2 AND m.channel_id=$1 AND m.deleted_at IS NULL`,
			channelID, messageID, guestID).Scan(&senderName, &excerpt)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("guest-digest: render dm: %w", err)
		}
		return fmt.Sprintf("New message from %s: %q", senderName, excerpt), nil
	case "meeting_invite":
		meetingID, err := strconv.ParseInt(ref, 10, 64)
		if err != nil || meetingID <= 0 {
			return "", nil
		}
		var title, start string
		err = q.QueryRow(ctx, `
			SELECT m.title,COALESCE(to_char(m.scheduled_start AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI UTC'),'time not set')
			  FROM meetings m
			  JOIN chat_channel_members member ON member.channel_id=m.chat_channel_id AND member.user_id=$2
			 WHERE m.id=$1`, meetingID, guestID).Scan(&title, &start)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("guest-digest: render meeting: %w", err)
		}
		return fmt.Sprintf("New meeting: %s (%s)", title, start), nil
	default:
		return "", nil
	}
}

// reapGuestIntents removes old terminal rows and tombstones old unsent rows.
func (w *Worker) reapGuestIntents(ctx context.Context) {
	if w.guestDigestCfg == nil {
		return
	}
	if _, err := w.pool.Exec(ctx, `
		DELETE FROM guest_notification_intents
		 WHERE sent_at IS NOT NULL AND created_at < now()-interval '7 days'`); err != nil {
		w.logger.Warn("pushjobs(guest-digest): reap sent failed", "error", err)
	}
	if _, err := w.pool.Exec(ctx, `
		UPDATE guest_notification_intents SET sent_at=now()
		 WHERE sent_at IS NULL AND created_at < now()-interval '7 days'`); err != nil {
		w.logger.Warn("pushjobs(guest-digest): reap stale failed", "error", err)
	}
}

// claimOn leases one due pending row from table, returning it via QueryRow so
// each caller Scans its own column set — mail's and chat's intents share the
// id/status/attempts/next_attempt_at/last_error reliability shape but carry
// different payload columns, so RETURNING is the one part left per-caller
// rather than forced into a common struct. table/returning are both fixed Go
// string constants at every call site, never request-derived.
func (w *Worker) claimOn(ctx context.Context, table, returning string) pgx.Row {
	return w.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE %s
		   SET attempts = attempts + 1,
		       next_attempt_at = now() + make_interval(secs => $1)
		 WHERE id = (
		   SELECT id FROM %s
		    WHERE status = 'pending' AND next_attempt_at <= now()
		    ORDER BY next_attempt_at
		    FOR UPDATE SKIP LOCKED
		    LIMIT 1
		 )
		 RETURNING %s`, table, table, returning),
		leaseWindow.Seconds(),
	)
}

// markDoneOn finalizes a row on table as done — shared by both drain legs.
func (w *Worker) markDoneOn(ctx context.Context, table string, id int64) error {
	_, err := w.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE %s SET status='done', next_attempt_at=now(), last_error=NULL WHERE id=$1`, table), id)
	return err
}

// retryOrFailOn re-queues with capped exponential backoff, or marks failed
// once attempts are exhausted — shared by both drain legs. attempts is the
// value already incremented by claimOn's UPDATE.
func (w *Worker) retryOrFailOn(ctx context.Context, table string, id int64, attempts int, errMsg string) error {
	if attempts >= maxAttempts {
		_, err := w.pool.Exec(ctx,
			fmt.Sprintf(`UPDATE %s SET status='failed', last_error=$2, next_attempt_at=now() WHERE id=$1`, table),
			id, errMsg)
		return err
	}
	backoff := backoffFor(attempts)
	_, err := w.pool.Exec(ctx,
		fmt.Sprintf(`UPDATE %s SET status='pending', next_attempt_at=now()+make_interval(secs => $2), last_error=$3 WHERE id=$1`, table),
		id, backoff.Seconds(), errMsg)
	return err
}

// reapChatIntents deletes terminal chat_push_intents rows past chatReapAfter.
// Ticks alongside the chat drain leg; a delete-failure just logs (there is
// always a next tick).
func (w *Worker) reapChatIntents(ctx context.Context) {
	if _, err := w.pool.Exec(ctx,
		`DELETE FROM chat_push_intents WHERE status IN ('done','failed') AND created_at < now() - make_interval(secs => $1)`,
		chatReapAfter.Seconds(),
	); err != nil {
		w.logger.Warn("pushjobs(chat): reap failed", "error", err)
	}
}

// intent is a claimed push_intents row.
type intent struct {
	id         int64
	mailboxID  int64
	messageID  int64
	receivedAt time.Time
	attempts   int
}

// processOne claims one due intent (lease via next_attempt_at, so no 'processing'
// status is needed and the claim commits before any network I/O), evaluates the
// gate, dispatches, and records the outcome. Returns (true,nil) when one was
// processed, (false,nil) when the queue is empty/idle.
func (w *Worker) processOne(ctx context.Context) (bool, error) {
	var it intent
	err := w.claimOn(ctx, pushIntentsTable, "id, mailbox_id, message_id, received_at, attempts").
		Scan(&it.id, &it.mailboxID, &it.messageID, &it.receivedAt, &it.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// Policy gate: prefs / VIP / DND / mute. A FALSE verdict is terminal-done
	// (the message simply shouldn't push), never a retry.
	var notify bool
	if err := w.pool.QueryRow(ctx, `SELECT push_should_notify($1,$2,$3)`,
		it.mailboxID, it.messageID, it.receivedAt).Scan(&notify); err != nil {
		return true, w.retryOrFail(ctx, it, "gate: "+err.Error())
	}
	if !notify {
		return true, w.markDone(ctx, it.id)
	}

	// Build the rich payload from the delivered message + owning mailbox/user.
	payload, userID, ok, err := w.buildPayload(ctx, it)
	if err != nil {
		return true, w.retryOrFail(ctx, it, "payload: "+err.Error())
	}
	if !ok {
		// Message/mailbox vanished (deleted before we ran) — nothing to send.
		return true, w.markDone(ctx, it.id)
	}

	devices, err := sharedpush.ResolveDevices(ctx, w.pool, userID)
	if err != nil {
		return true, w.retryOrFail(ctx, it, "devices: "+err.Error())
	}
	if len(devices) == 0 {
		return true, w.markDone(ctx, it.id)
	}

	out := evalSends(ctx, w.providers.Get, devices, payload)

	// Prune dead tokens so we stop trying them.
	for _, id := range out.pruneIDs {
		if _, e := w.pool.Exec(ctx,
			`UPDATE push_devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id); e != nil {
			w.logger.Warn("pushjobs: prune failed", "device_id", id, "error", e)
		} else {
			w.logger.Info("pushjobs: pruned unregistered device", "device_id", id)
		}
	}
	if out.retryable {
		w.logger.Warn("pushjobs: send failed", "intent_id", it.id, "error", out.lastErr)
	}

	// A single successful delivery (or an all-pruned/all-unmatched outcome) is
	// terminal-done. Only an all-failed-with-retryable-errors intent retries.
	if out.anySuccess || !out.retryable {
		return true, w.markDone(ctx, it.id)
	}
	return true, w.retryOrFail(ctx, it, out.lastErr)
}

// sendOutcome summarises one intent's fan-out across a user's devices.
type sendOutcome struct {
	anySuccess bool
	retryable  bool    // ≥1 device failed with a retryable (non-unregistered) error
	lastErr    string  // text of the last retryable error
	pruneIDs   []int64 // devices the provider reported dead (prune → revoke)
}

// evalSends dispatches payload to each device via the provider looked up by get,
// classifying each result. Pure (no DB) so the gate/prune/backoff decision is unit
// tested with a fake dispatcher. A device whose provider isn't configured here is
// skipped (not an error).
func evalSends(ctx context.Context, get func(sharedpush.ProviderKind) (sharedpush.Dispatcher, bool), devices []sharedpush.Device, payload []byte) sendOutcome {
	var o sendOutcome
	for _, d := range devices {
		disp, ok := get(d.Provider)
		if !ok {
			continue
		}
		err := disp.Send(ctx, d.Token, payload)
		switch {
		case err == nil:
			o.anySuccess = true
		case errors.Is(err, sharedpush.ErrUnregistered):
			o.pruneIDs = append(o.pruneIDs, d.ID)
		default:
			o.retryable = true
			o.lastErr = err.Error()
		}
	}
	return o
}

// buildPayload assembles the rich mail-push JSON and returns the recipient user id.
// ok=false means the message/mailbox no longer exists.
func (w *Worker) buildPayload(ctx context.Context, it intent) (payload []byte, userID int64, ok bool, err error) {
	var fromAddr, fromName, subject, rfcID, mailboxEmail string
	var uid *int64
	scanErr := w.pool.QueryRow(ctx, `
		SELECT COALESCE(m.from_addr,''), COALESCE(m.from_name,''), COALESCE(m.subject,''),
		       COALESCE(m.message_id,''), mb.email, mb.user_id
		  FROM messages m
		  JOIN mailboxes mb ON mb.id = m.mailbox_id
		 WHERE m.id = $1 AND m.received_at = $2 AND m.mailbox_id = $3`,
		it.messageID, it.receivedAt, it.mailboxID,
	).Scan(&fromAddr, &fromName, &subject, &rfcID, &mailboxEmail, &uid)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		return nil, 0, false, nil
	}
	if scanErr != nil {
		return nil, 0, false, scanErr
	}
	if uid == nil {
		return nil, 0, false, nil
	}

	// decided 2026-07-07: rich payload on all providers.
	b, mErr := json.Marshal(map[string]any{
		"type":      "mail",
		"sender":    map[string]string{"name": fromName, "email": fromAddr},
		"subject":   subject,
		"messageId": rfcID,
		"mailbox":   mailboxEmail,
		"actions":   []string{"archive", "reply"},
	})
	if mErr != nil {
		return nil, 0, false, mErr
	}
	return b, *uid, true, nil
}

func (w *Worker) markDone(ctx context.Context, id int64) error {
	return w.markDoneOn(ctx, pushIntentsTable, id)
}

// retryOrFail re-queues with capped exponential backoff, or marks failed once
// attempts are exhausted. attempts was already incremented by the claim.
// backoff = LEAST(1 minute * 2^attempts, 1 hour) — copied from scheduled_actions.
func (w *Worker) retryOrFail(ctx context.Context, it intent, errMsg string) error {
	return w.retryOrFailOn(ctx, pushIntentsTable, it.id, it.attempts, errMsg)
}

// backoffFor returns min(1min * 2^attempts, 1h).
func backoffFor(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 6 {
		attempts = 6 // 2^6 min = 64 min → capped to 1h anyway; guards the shift
	}
	d := time.Duration(1<<uint(attempts)) * time.Minute
	if d > time.Hour {
		d = time.Hour
	}
	return d
}
