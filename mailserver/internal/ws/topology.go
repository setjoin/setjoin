package ws

import (
	"context"
	"fmt"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
)

// This file single-homes the session push-channel topology (arch review #A2):
// ws/handler.go (WS Upgrade) and ws/eventsource.go (SSE EventSource) each used
// to hand-roll the identical set of per-session NOTIFY subscriptions —
// mailbox tag:/calendar:/contact:/task:{mbox}, session_revoke, drive-watch:
// {uid}, perm-gated drive-alarm, chat:{uid} (+ Presence.Connect side effect),
// meet:{uid} — with no guard pinning that the two lists stayed in sync. Every
// program that added a channel had to remember to edit both files.
//
// sessionChannels is now the ONE place a session-scoped push channel is
// declared: both handlers range over it to subscribe (permission gate,
// buffer size, connect/disconnect side effects all travel with the entry).
// Each transport keeps its own WIRE mechanics — WS forwards a verbatim
// channel via forwardRawEvents' {"@type":...} frame; SSE writes its own
// "event: ...\ndata: ..." frames from the same channel inside its single
// select loop (a dynamic-length select requires reflect.Select, not worth it
// for four fixed channels) — kind identifies which named variable in
// EventSource's select the subscribed channel feeds.

// subKind classifies how a session channel's payloads are consumed. The
// first two kinds have transport-specific dispatch mechanics (batched JMAP
// StateChange / close-on-match); the rest are forwarded to the client
// verbatim, tagged by wsAtType (WS) / sseEvent (SSE).
type subKind int

const (
	// subStateChange channels feed the batched JMAP StateChange pipeline
	// (tag/calendar/contact/task, see mailserver/sql/AGENTS.md → "NOTIFY
	// channel contract"). REQUIRED: a subscribe failure aborts the connection.
	subStateChange subKind = iota
	// subRevoke is session_revoke — emits the best-effort client signal when
	// this exact all/JTI/family scope targets the connection. The process-wide
	// ProtocolSessionRegistry remains the authoritative close path.
	subRevoke
	// subDriveWatch is drive-watch:<uid> (Drive P4 §5.6 live push).
	subDriveWatch
	// subDriveAlarm is drive-alarm (Drive P6 Task 12), perm-gated on
	// drive.view/drive.manage — the only channel not self-scoped to the
	// caller's own uid.
	subDriveAlarm
	// subChat is chat:<uid> (Chat A1 Task 9), which also drives the
	// in-memory presence registry (chat.Presence) for the life of the
	// connection.
	subChat
	// subMeet is meet:<uid> (Meet B1 Task 13).
	subMeet
)

// subscription is one session-scoped NOTIFY channel a push connection
// (WS or SSE) subscribes to.
type subscription struct {
	channel string
	kind    subKind
	buf     int    // channel buffer size for kind's own chan string; 0 => 16
	app     string // guest-only user-id entitlement gate; members retain existing topology

	// permGate, when non-nil, must return true for the subscription to be
	// attempted. A nil gate is unconditional (self-scoped to the caller's
	// own uid, so there is nothing to authorize beyond "is this the caller").
	permGate func(ctx context.Context, h *Handler, claims *auth.Claims) bool

	// onConnect/onDisconnect carry a side effect that must fire exactly once
	// per successful subscription (currently only chat.Presence). Called by
	// the caller's own goroutine at subscribe time / via defer at teardown —
	// NOT deferred inside a shared helper, since that would fire at the
	// helper's return instead of connection teardown.
	onConnect    func(userID int64)
	onDisconnect func(userID int64)

	wsAtType string // WS forwardRawEvents "@type" (verbatim kinds only)
	sseEvent string // SSE "event:" name (verbatim kinds only)
}

// driveAdminPermGate gates a subscription on drive.view or drive.manage —
// shared by both transports' drive-alarm entry.
func driveAdminPermGate(ctx context.Context, h *Handler, claims *auth.Claims) bool {
	return h.jmap.HasDriveAdminPerm(ctx, claims.UserID, "drive.view") ||
		h.jmap.HasDriveAdminPerm(ctx, claims.UserID, "drive.manage")
}

// sessionChannels returns every NOTIFY channel this session subscribes to.
// Add a new session-scoped push channel HERE — it goes live on both WS and
// SSE with no second edit (each transport's dispatch loop already handles
// its kind generically; a genuinely new verbatim kind needs one switch case
// added to EventSource's select, since Go can't select over a dynamic
// channel list without reflect).
func sessionChannels(claims *auth.Claims, mailboxID int64) []subscription {
	return []subscription{
		{channel: fmt.Sprintf("tag:%d", mailboxID), kind: subStateChange},
		{channel: fmt.Sprintf("calendar:%d", mailboxID), kind: subStateChange},
		{channel: fmt.Sprintf("contact:%d", mailboxID), kind: subStateChange},
		{channel: fmt.Sprintf("task:%d", mailboxID), kind: subStateChange},
		{channel: "session_revoke", kind: subRevoke},
		{
			channel: fmt.Sprintf("drive-watch:%d", claims.UserID), kind: subDriveWatch,
			buf: 16, app: "drive", wsAtType: "DriveWatch", sseEvent: "drive-watch",
		},
		{
			channel: "drive-alarm", kind: subDriveAlarm,
			buf: 8, app: "drive", permGate: driveAdminPermGate, wsAtType: "DriveAlarm", sseEvent: "drive-alarm",
		},
		{
			channel: fmt.Sprintf("chat:%d", claims.UserID), kind: subChat,
			buf: 16, app: "chat", wsAtType: "ChatEvent", sseEvent: "chat",
			onConnect: chat.Presence.Connect, onDisconnect: chat.Presence.Disconnect,
		},
		{
			channel: fmt.Sprintf("meet:%d", claims.UserID), kind: subMeet,
			buf: 16, app: "meet", wsAtType: "MeetEvent", sseEvent: "meet",
		},
	}
}

// subscriptionAllowed applies only the additional belts carried by a topology
// entry. Guest app subscriptions are checked first so a denied guest never
// reaches a broader permission lookup (notably drive-alarm). Members preserve
// the pre-G2 topology exactly, including explicit app-deny rows; changing member
// push behavior is outside this guest hardening lane.
func subscriptionAllowed(ctx context.Context, h *Handler, claims *auth.Claims, sub subscription) bool {
	if claims.IsGuest() && sub.app != "" {
		if h.jmap == nil || !h.jmap.HasAppEntitlement(ctx, claims.UserID, sub.app) {
			return false
		}
	}
	return sub.permGate == nil || sub.permGate(ctx, h, claims)
}

// defaultWSAuthzRecheckInterval is the default periodic authorization
// re-validation window for a live push connection (ops tunable — override via
// Handler.authzRecheckInterval). It balances NOTIFY/DB load (each tick runs at
// most a handful of permission/entitlement lookups per connection) against
// staleness: a claims.exp expiry or an entitlement/permission demotion with no
// other teardown path closes the rail within this window, with no reconnect.
const defaultWSAuthzRecheckInterval = 5 * time.Minute

// revalidateSessionAuthz reports whether a live push connection's
// authorization still holds. It re-checks exactly the two authorization
// changes that today have NO other teardown path:
//
//   - claims.exp passing mid-connection — time-based, nothing NOTIFies for it;
//   - entitlement/permission changes behind a channel's connect-time gate
//     (guest app entitlements, drive-admin drive.view/drive.manage) — a
//     demoted drive admin or an entitlement-withdrawn guest loses the rail
//     within the re-validation window without reconnecting.
//
// Out of scope BY DESIGN and preserved unchanged: session revocation (the
// session_revoke NOTIFY + denylist + ProtocolSessionRegistry rail), device
// revocation (per-message gate), and the guest lifecycle teardown
// (revoke_user_sessions, guest_account.sql) — withdrawn guests are already
// revoked at the source by that path; this never duplicates or replaces it.
//
// The check is deliberately fail-closed: HasDriveAdminPerm/HasAppEntitlement
// return false on any lookup error, so an unavailable DB tears connections
// down within the window — the same posture as the denylist gate.
func revalidateSessionAuthz(ctx context.Context, h *Handler, claims *auth.Claims, admitted []subscription) bool {
	if claims == nil {
		return true
	}
	if claims.ExpiresAt != nil && !time.Now().Before(claims.ExpiresAt.Time) {
		return false
	}
	for _, sub := range admitted {
		if !subscriptionAllowed(ctx, h, claims, sub) {
			return false
		}
	}
	return true
}

func (s subscription) bufSize() int {
	if s.buf > 0 {
		return s.buf
	}
	return 16
}
