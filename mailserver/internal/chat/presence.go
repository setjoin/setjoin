// presence.go — Task 10 breadth: read watermark, typing signal, and online
// presence. Presence itself (grill Q2) is deliberately NOT reducer-backed:
// "no table — ephemeral notify, capped + throttled" governs typing, and
// presence goes further — no DB row, no push at all. It's a process-wide
// in-memory connect-count registry that ws/handler.go's WS Upgrade and
// ws/eventsource.go's SSE handler maintain (Connect on subscribe, Disconnect
// deferred on teardown), read here by a plain GET. Clients poll (<=1/60s,
// visible users only) — there is nothing to push.
package chat

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/federation"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
)

// PresenceRegistry counts live connections per user. Multiple tabs/devices
// for the same user each Connect/Disconnect independently — a user reads
// online as long as at least one connection is open. No DB, no push;
// process-local (a multi-node deployment would need this centralized, not
// built here — single mailserverd process per the current architecture).
type PresenceRegistry struct {
	mu     sync.Mutex
	counts map[int64]int
}

// Presence is the process-wide registry. ws/handler.go and ws/eventsource.go
// both call Connect/Disconnect around their existing chat:{uid} subscribe
// blocks; GET /chat/presence below is the only reader.
var Presence = &PresenceRegistry{counts: make(map[int64]int)}

// Connect increments the caller's connection count.
func (r *PresenceRegistry) Connect(userID int64) {
	r.mu.Lock()
	r.counts[userID]++
	r.mu.Unlock()
}

// Disconnect decrements the caller's connection count, clearing the entry
// once it reaches zero rather than letting it go negative.
func (r *PresenceRegistry) Disconnect(userID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counts[userID] <= 1 {
		delete(r.counts, userID)
		return
	}
	r.counts[userID]--
}

// IsOnline reports whether userID has at least one live connection.
func (r *PresenceRegistry) IsOnline(userID int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts[userID] > 0
}

// registerPresenceRoutes registers the read/typing/presence routes on h.mux.
func (h *Handler) registerPresenceRoutes(mux router) {
	mux.HandleFunc("POST /chat/channels/{id}/read", h.markRead)
	mux.HandleFunc("POST /chat/channels/{id}/typing", h.typingSignal)
	mux.HandleFunc("GET /chat/presence", h.getPresence)
	// A3 QoL Task 4: read-receipt watermark projection (ADR DES-010) — no
	// new write path, just a membership-scoped view over the last_read_seq
	// column chat_mark_read already maintains.
	mux.HandleFunc("GET /chat/channels/{id}/readers", h.getChannelReaders)
}

type markReadBody struct {
	Seq int64 `json:"seq"`
}

// markRead serves POST /chat/channels/{id}/read {seq}. chat_mark_read clamps
// to the channel's current change_seq server-side (F7) — this handler passes
// the client's value through verbatim, unclamped, by design.
func (h *Handler) markRead(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, body, ok := chatIDBody[markReadBody](w, r, "id")
	if !ok {
		return
	}
	h.execChat(w, r, claims.UserID, `SELECT chat_mark_read($1, $2, $3)`, claims.UserID, channelID, body.Seq)
}

// typingDebounceFloor matches the local typing cadence (~1s) — the Q5-
// ratified "debounce BEFORE any local DB work" gate on the outbound
// federated-typing hook below.
const typingDebounceFloor = time.Second

// typingDebounceCap bounds h.typingDebounce's size (Task 6 review, MAJOR 2):
// httputil.ParseIDPath admits ANY int64 as a channel id — it never checks
// the channel exists — so a client hammering distinct/bogus ids grows this
// map forever; nothing ever deletes an entry otherwise. ponytail: a lazy
// sweep at the cap (below) is a few lines and amortizes to O(1) per insert;
// a proper LRU/TTL cache is unwarranted for a debounce floor this short-lived.
const typingDebounceCap = 4096

// federationTypingDebounced reports whether channelID is still inside its
// debounce floor, and — if not — marks it as freshly signaled. Consulted
// BEFORE h.federationTyping's nil-check, BEFORE the RLS SELECT below, and
// BEFORE any goroutine is spawned (the codex-hardened Q5 ordering: a noisy
// client must not create local DB load even while wire frames would end up
// dropped anyway). Per-channel, not per-user — see the Handler.typingDebounce
// field's own doc comment for why that coarseness is an accepted v1 shape.
func (h *Handler) federationTypingDebounced(channelID int64) bool {
	h.typingDebounceMu.Lock()
	defer h.typingDebounceMu.Unlock()
	now := time.Now()
	if last, ok := h.typingDebounce[channelID]; ok && now.Sub(last) < typingDebounceFloor {
		return true
	}
	if len(h.typingDebounce) >= typingDebounceCap {
		// ponytail: lazy sweep under the same lock — every entry past the
		// debounce floor is stale for debounce purposes (its channel would be
		// re-admitted anyway), so this is a safe O(n) prune amortized across
		// the next typingDebounceCap inserts — bounds the growth without a
		// background goroutine/ticker for a map this cheap.
		for id, t := range h.typingDebounce {
			if now.Sub(t) >= typingDebounceFloor {
				delete(h.typingDebounce, id)
			}
		}
	}
	h.typingDebounce[channelID] = now
	return false
}

// typingSignal serves POST /chat/channels/{id}/typing. chat_typing_signal
// itself no-ops (no error, no notify) above the 32-member cap — this
// handler doesn't special-case that; the client just never sees an event.
//
// Pillar C2 Task 6 (federated typing, Q5): after chat_typing_signal
// succeeds, a channel bound to a federation peer/room ALSO gets a
// best-effort SendTyping call — debounced FIRST (above, before this
// function even reads federated_peer_domain), fire-and-forget (a short-
// lived detached context, not r.Context(), so the outbound wire send
// outlives this HTTP response), and entirely non-blocking for the client:
// a federation hiccup never affects the 204 this handler already wrote for
// the local (always-authoritative) typing signal.
//
// Task 6 review (MAJOR 1): the federation hook fires ONLY when
// chat_typing_signal itself SUCCEEDED (execChat's return value) — "only an
// admitted signal proceeds" per the plan. This app-level gate is PRIMARY
// (ARCH-006): the RLS read inside sendFederationTyping is a backstop only,
// and doesn't even hold for a PUBLIC channel — DES-008's discovery arm lets
// any org user SELECT a public channel's federation columns whether or not
// they're a member, so a non-member's REFUSED signal (BZ163) would still
// have federated without this success gate.
func (h *Handler) typingSignal(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	// MINOR 8 (Task 6 review): the debounce stamp is taken BEFORE we know
	// whether chat_typing_signal will even succeed — deliberately: the
	// Q5-ratified ordering requires the debounce decision before any local
	// DB work, so it can't wait on this call's outcome. The cost is a stale
	// debounce entry (≤1s) on an occasional refused request, which self-heals
	// on the next admitted signal — negligible next to the ordering law.
	debounced := h.federationTypingDebounced(channelID)
	admitted := h.execChat(w, r, claims.UserID, `SELECT chat_typing_signal($1, $2)`, claims.UserID, channelID)

	if !admitted || debounced || h.federationTyping == nil {
		return
	}
	// context.WithoutCancel(r.Context()) — the webhook/dispatcher.go +
	// booking/public.go idiom for a detached-but-bounded background send:
	// keeps any request-scoped values, drops the cancellation-on-response-
	// return that a bare context.Background() would lose (gosec G118), so a
	// slow/aborted HTTP response never cuts off an already-admitted send.
	go h.sendFederationTyping(context.WithoutCancel(r.Context()), claims.UserID, channelID, claims.Email)
}

// sendFederationTyping runs the one cheap RLS-visible SELECT of a channel's
// federation columns (W4-scoped, dbscope.RunUserScoped — every user-request-
// path table read in this package runs inside it, scripts/check-rls-scope-
// wrap.sh's own invariant; this goroutine is no exception just because it
// outlives the HTTP response) and, if the channel is federated (DM or
// room-bound), calls h.federationTyping non-blocking. parent is already
// detached from request cancellation (context.WithoutCancel, above) — bound
// here with its own short timeout so an admitted send can't hang forever;
// Service.SendTyping's own peer-scoped token bucket is the real throttle
// from here on.
func (h *Handler) sendFederationTyping(parent context.Context, userID, channelID int64, localEmail string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	var peerDomain, roomID, remoteID *string
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT federated_peer_domain, federated_room_id, federated_remote_id
			   FROM chat_channels WHERE id = $1`, channelID,
		).Scan(&peerDomain, &roomID, &remoteID)
	})
	if err != nil {
		return // channel gone, or not visible — nothing to federate
	}
	if peerDomain == nil && roomID == nil {
		return // an ordinary, non-federated channel — the common case
	}

	ch := federation.TypingChannel{ChannelID: channelID, LocalUserEmail: localEmail}
	if peerDomain != nil {
		ch.PeerDomain = *peerDomain
	}
	if roomID != nil {
		ch.RoomID = *roomID
	}
	if remoteID != nil {
		ch.RemoteID = *remoteID
	}
	h.federationTyping(ctx, ch)
}

// getChannelReaders serves GET /chat/channels/{id}/readers -> [{userId,
// lastReadSeq}, ...] — chat_channel_readers is membership-scoped (BZ163);
// this handler is a pure pass-through, same shape as listPins/listSaves.
func (h *Handler) getChannelReaders(w http.ResponseWriter, r *http.Request) {
	claims := auth.UserFromContext(r.Context())
	channelID, ok := httputil.ParseIDPath(w, r, "id", "invalid channel id")
	if !ok {
		return
	}
	h.queryChatJSON(w, r, claims.UserID, `SELECT chat_channel_readers($1, $2)`, claims.UserID, channelID)
}

// getPresence serves GET /chat/presence?userIds=1,2,3 -> {"1":true,"2":false}.
// No membership/ownership check on WHICH userIds are asked about (grill Q2:
// presence is a coarse online/offline signal, not a private fact scoped to
// shared channels) — matches chat_channel_roster's directory-lookup posture
// elsewhere in this package. A malformed id 400s rather than being skipped
// silently, so a client bug surfaces immediately instead of reading everyone
// as offline.
//
// Guest Accounts G0 Task 13 (spec P2, read-oracle scoping): a GUEST caller
// does NOT get the unscoped read above — that would be both an org-wide
// online/offline oracle and an existence oracle (any id, member or not,
// answers truthfully) for an account that's supposed to see only its own
// channels. A guest's answers are restricted to users who share a channel
// with the guest; every other id (non-co-member or nonexistent) is
// uniformly false. Member behavior is unchanged (this branch is gated on
// claims.IsGuest()).
func (h *Handler) getPresence(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("userIds")
	ids := []int64{}
	keys := []string{} // raw (trimmed) id text, same order as ids — preserves the
	// original byte-for-byte response keying (e.g. "007") instead of a
	// strconv.FormatInt-normalized key, for both branches below.
	if raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			id, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid userIds"})
				return
			}
			ids = append(ids, id)
			keys = append(keys, s)
		}
	}

	claims := auth.UserFromContext(r.Context())
	if claims != nil && claims.IsGuest() && len(ids) > 0 {
		// R1: the co-membership predicate keys on the CALLER's id from
		// validated claims (never a request field). D-m1: chat_channel_members
		// is FORCE-RLS — a raw h.pool read carries no app.current_user_id GUC
		// and returns ZERO rows (uniform-false even for real co-members), so
		// the query runs under dbscope.RunUserScoped, the caller's own scope:
		// a caller's co-memberships are by definition visible to the caller
		// (the same rail every other chat handler in this package rides).
		coMember := map[int64]bool{}
		err := dbscope.RunUserScoped(r.Context(), h.pool, claims.UserID, func(tx pgx.Tx) error {
			rows, err := tx.Query(r.Context(),
				`SELECT DISTINCT m2.user_id
				   FROM chat_channel_members m1
				   JOIN chat_channel_members m2 ON m2.channel_id = m1.channel_id
				  WHERE m1.user_id = $1 AND m2.user_id = ANY($2)`,
				claims.UserID, ids)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					return err
				}
				coMember[id] = true
			}
			return rows.Err()
		})
		if err != nil {
			httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "presence scope lookup failed"})
			return // fail CLOSED — never fall through to the unscoped read
		}
		scoped := map[string]bool{}
		for i, id := range ids {
			scoped[keys[i]] = coMember[id] && Presence.IsOnline(id)
		}
		httputil.WriteJSON(w, http.StatusOK, scoped)
		return
	}

	out := map[string]bool{}
	for i, id := range ids {
		out[keys[i]] = Presence.IsOnline(id)
	}
	httputil.WriteJSON(w, http.StatusOK, out)
}
