package pushjobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	sharedpush "setjoin.com/shared/push"
)

// chatIntent is a claimed chat_push_intents row (Chat A3.5 Task 3).
type chatIntent struct {
	id           int64
	channelID    int64
	messageID    int64
	senderUserID int64
	attempts     int
}

// chatMsgMeta is the per-message shape the chat drain leg needs to decide
// coalescing and build payloads. hasMentions is ANY chat_mentions row on the
// message (any recipient) — the coalesce-safety check; mentioned is the
// PER-RECIPIENT set used for each member's payload "mention" flag.
type chatMsgMeta struct {
	channelID  int64
	messageID  int64
	seq        int64
	senderName string
	broadcast  bool
	kind       string // chat_channels.kind: channel/dm/group_dm
	chanName   string // chat_channels.name, "" when NULL (dm/group_dm)
	mentioned  map[int64]bool
}

// hasMentions reports whether ANY recipient was personally @mentioned on this
// message — the mention-safety input to shouldCoalesce.
func (m chatMsgMeta) hasMentions() bool { return len(m.mentioned) > 0 }

// shouldCoalesce decides whether this (older) intent should be dropped —
// marked done, never dispatched — because a newer pending intent already
// exists for the same channel. A message the coalesce would drop must carry
// no personal @mention and not be a broadcast: otherwise a 'mentions'-level
// member's push dies silently along with the skipped intent (mention-safe
// tag-replace has no equivalent across APNs/FCM/HMS/webpush).
func shouldCoalesce(msg chatMsgMeta, newerPendingExists bool) bool {
	return newerPendingExists && !msg.broadcast && !msg.hasMentions()
}

// chatFanoutMember is one channel member's ALREADY-RESOLVED (DB-read)
// gate verdict, devices, and per-recipient payload shape — the pure
// planChatFanout input (the evalSends precedent: no DB, no I/O inside).
type chatFanoutMember struct {
	userID      int64
	notify      bool // chat_push_should_notify verdict for this member
	mention     bool // this member's own mention/broadcast qualifier
	channelName string
	devices     []sharedpush.Device
}

// chatSend is one planned dispatch: a member's resolved devices plus their
// fully-built payload (never shared across members — DM/group-DM channelName
// differs per recipient, so payloads can't be built once per intent the way
// mail's buildPayload builds once per intent).
type chatSend struct {
	userID  int64
	devices []sharedpush.Device
	payload []byte
}

// planChatFanout is the pure decision core of the chat drain leg: given
// members with their gate verdict + devices already resolved, decide who
// gets a dispatch and build each payload. No DB, no I/O — every DB read
// (the gate, ResolveDevices, the coalesce EXISTS check) happens in
// processOneChat before this is called.
//
// Payload carries NO message body (payload-privacy posture, A3.5 Global
// Constraints): {type,channelId,messageId,seq,sender,channelName,mention,
// dedupeTag}. dedupeTag is per-CHANNEL (not per-message) so a second chat
// notification replaces the first on a platform that honors tag-replace.
func planChatFanout(msg chatMsgMeta, members []chatFanoutMember) []chatSend {
	var sends []chatSend
	for _, m := range members {
		if !m.notify || len(m.devices) == 0 {
			continue
		}
		payload, err := json.Marshal(map[string]any{
			"type":        "chat",
			"channelId":   msg.channelID,
			"messageId":   msg.messageID,
			"seq":         msg.seq,
			"sender":      msg.senderName,
			"channelName": m.channelName,
			"mention":     m.mention,
			"dedupeTag":   fmt.Sprintf("chat-%d", msg.channelID),
		})
		if err != nil {
			continue // unreachable: every field above is a primitive/string
		}
		sends = append(sends, chatSend{userID: m.userID, devices: m.devices, payload: payload})
	}
	return sends
}

// chatChannelName resolves the payload's channelName for one recipient:
//   - kind 'channel'  -> the channel's own name.
//   - kind 'dm'       -> "" — the client renders the i18n "Direct message"
//     string itself (chat_channels.name is NULL for a plain DM).
//   - kind 'group_dm' -> the OTHER members' display names, comma-joined
//     (built per-recipient: "other" excludes the recipient, not the sender).
func chatChannelName(msg chatMsgMeta, roster []chatRosterMember, recipientID int64) string {
	if msg.kind == "channel" {
		return msg.chanName
	}
	if msg.kind == "dm" {
		return ""
	}
	var names []string
	for _, r := range roster {
		if r.userID == recipientID {
			continue
		}
		if r.displayName != "" {
			names = append(names, r.displayName)
		}
	}
	joined := ""
	for i, n := range names {
		if i > 0 {
			joined += ", "
		}
		joined += n
	}
	return joined
}

// chatRosterMember is one row of a channel's membership + display name.
type chatRosterMember struct {
	userID      int64
	displayName string
}

// loadChatRoster reads every current member of a channel with their display
// name — used both to build the notify-candidate list (exclude the sender)
// and, for group_dm, each recipient's "other members" channelName.
func (w *Worker) loadChatRoster(ctx context.Context, channelID int64) ([]chatRosterMember, error) {
	rows, err := w.pool.Query(ctx, `
		SELECT ccm.user_id, COALESCE(u.display_name, '')
		  FROM chat_channel_members ccm
		  JOIN users u ON u.id = ccm.user_id
		 WHERE ccm.channel_id = $1
		 ORDER BY ccm.user_id`, channelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []chatRosterMember
	for rows.Next() {
		var r chatRosterMember
		if err := rows.Scan(&r.userID, &r.displayName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// loadChatMessage reads the message + owning channel shape once, plus the
// full per-message mention set. ok=false means the message no longer exists
// (channel/message hard-delete via FK CASCADE — the intent itself would have
// cascaded too, so this is defensive, not a path this repo's reducers take
// today).
func (w *Worker) loadChatMessage(ctx context.Context, messageID, channelID int64) (chatMsgMeta, bool, error) {
	var meta chatMsgMeta
	meta.messageID = messageID
	meta.channelID = channelID
	var chanName *string
	err := w.pool.QueryRow(ctx, `
		SELECT m.seq, (m.broadcast IS NOT NULL), c.kind, c.name
		  FROM chat_messages m
		  JOIN chat_channels c ON c.id = m.channel_id
		 WHERE m.id = $1 AND m.channel_id = $2`,
		messageID, channelID,
	).Scan(&meta.seq, &meta.broadcast, &meta.kind, &chanName)
	if errors.Is(err, pgx.ErrNoRows) {
		return meta, false, nil
	}
	if err != nil {
		return meta, false, err
	}
	if chanName != nil {
		meta.chanName = *chanName
	}

	rows, err := w.pool.Query(ctx, `SELECT mentioned_user_id FROM chat_mentions WHERE message_id = $1`, messageID)
	if err != nil {
		return meta, false, err
	}
	defer rows.Close()
	meta.mentioned = make(map[int64]bool)
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			return meta, false, err
		}
		meta.mentioned[uid] = true
	}
	if err := rows.Err(); err != nil {
		return meta, false, err
	}

	return meta, true, nil
}

// chatShouldNotify calls the chat_push_should_notify reducer for one member.
func (w *Worker) chatShouldNotify(ctx context.Context, userID, channelID, messageID int64) (bool, error) {
	var notify bool
	err := w.pool.QueryRow(ctx, `SELECT chat_push_should_notify($1,$2,$3)`,
		userID, channelID, messageID).Scan(&notify)
	return notify, err
}

// processOneChat claims one due chat_push_intents row and fans it out to
// every notify-eligible channel member. Returns (true,nil) when one was
// processed, (false,nil) when the queue is empty/idle.
//
// Retry policy (multi-recipient intent, unlike mail's single-recipient
// push_intents row): a claim/load/coalesce-check failure BEFORE fan-out
// begins retries normally (real infra trouble, no member has been touched
// yet). Once the per-member loop starts, the intent is ALWAYS terminal-done
// regardless of any individual send outcome — re-fanning on one flaky device
// would re-push every member who already succeeded (no cross-provider
// tag-replace-on-retry). Push is a best-effort wake hint (guomi §11).
func (w *Worker) processOneChat(ctx context.Context) (bool, error) {
	var ci chatIntent
	err := w.claimOn(ctx, chatIntentsTable, "id, channel_id, message_id, sender_user_id, attempts").
		Scan(&ci.id, &ci.channelID, &ci.messageID, &ci.senderUserID, &ci.attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	msg, ok, err := w.loadChatMessage(ctx, ci.messageID, ci.channelID)
	if err != nil {
		return true, w.retryOrFailOn(ctx, chatIntentsTable, ci.id, ci.attempts, "load: "+err.Error())
	}
	if !ok {
		return true, w.markDoneOn(ctx, chatIntentsTable, ci.id)
	}

	var newerPending bool
	if err := w.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM chat_push_intents WHERE channel_id=$1 AND status='pending' AND id>$2)`,
		ci.channelID, ci.id,
	).Scan(&newerPending); err != nil {
		return true, w.retryOrFailOn(ctx, chatIntentsTable, ci.id, ci.attempts, "coalesce: "+err.Error())
	}
	if shouldCoalesce(msg, newerPending) {
		return true, w.markDoneOn(ctx, chatIntentsTable, ci.id)
	}

	roster, err := w.loadChatRoster(ctx, ci.channelID)
	if err != nil {
		return true, w.retryOrFailOn(ctx, chatIntentsTable, ci.id, ci.attempts, "roster: "+err.Error())
	}
	for _, r := range roster {
		if r.userID == ci.senderUserID {
			msg.senderName = r.displayName
			break
		}
	}

	// Fan-out begins here: from this point the intent is ALWAYS
	// terminal-done (see doc above) — no more retryOrFailOn on this path.
	var members []chatFanoutMember
	for _, r := range roster {
		if r.userID == ci.senderUserID {
			// The intent's sender_user_id already excludes the sender at
			// member-load — a deliberate cheap belt alongside
			// chat_push_should_notify's own author_id self-check.
			continue
		}
		notify, gerr := w.chatShouldNotify(ctx, r.userID, ci.channelID, ci.messageID)
		if gerr != nil {
			w.logger.Warn("pushjobs(chat): gate failed", "user_id", r.userID, "error", gerr)
			continue
		}
		if !notify {
			continue
		}
		devices, derr := sharedpush.ResolveDevices(ctx, w.pool, r.userID)
		if derr != nil {
			w.logger.Warn("pushjobs(chat): resolve devices failed", "user_id", r.userID, "error", derr)
			continue
		}
		members = append(members, chatFanoutMember{
			userID:      r.userID,
			notify:      true,
			mention:     msg.broadcast || msg.mentioned[r.userID],
			channelName: chatChannelName(msg, roster, r.userID),
			devices:     devices,
		})
	}

	for _, s := range planChatFanout(msg, members) {
		out := evalSends(ctx, w.providers.Get, s.devices, s.payload)
		if len(out.pruneIDs) > 0 {
			// One batched revoke per fanout instead of one UPDATE per device
			// (the tombstoneGuestBatch pattern from worker.go).
			if _, e := w.pool.Exec(ctx,
				`UPDATE push_devices SET revoked_at = now()
				 WHERE id = ANY($1::bigint[]) AND revoked_at IS NULL`, out.pruneIDs); e != nil {
				w.logger.Warn("pushjobs(chat): prune failed", "devices", len(out.pruneIDs), "error", e)
			}
		}
		if out.retryable {
			w.logger.Warn("pushjobs(chat): send failed", "user_id", s.userID, "error", out.lastErr)
		}
	}

	return true, w.markDoneOn(ctx, chatIntentsTable, ci.id)
}
