package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type cancelCloser func()

func (f cancelCloser) Close() error {
	f()
	return nil
}

// EventSource serves GET /jmap/eventsource — the JMAP push channel over
// Server-Sent Events (RFC 8620 §7.3). It is the WebSocket-fallback for
// deployments whose proxies block WS upgrades; the session object
// (`jmap/handler.go` `eventSourceUrl`) advertises it, so it MUST be served or a
// client that picks SSE gets a 404 (the bug this closes).
//
// It reuses the same NOTIFY subscription + StateChange machinery as the WS
// handler; the only difference is the wire format (text/event-stream frames
// instead of WS messages) and the RFC 8620 query params:
//   - types=*         comma-separated JMAP type names to restrict pushes, or "*"
//   - closeafter=state close the connection right after the first StateChange
//     (a one-shot "give me current state" fetch); "no" = stream
//   - ping=N          send a `ping` event every N seconds (0 = never); also
//     doubles as the keepalive through buffering proxies
func (h *Handler) EventSource(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Auth: Authorization: Bearer <jwt> (non-browser clients) OR the access_token
	// cookie (browser EventSource with withCredentials). When the token comes
	// from the ambient cookie we ALSO enforce the same-origin check the WS path
	// uses — a cookie is a CSRF/CSWSH vector; a bearer header set by the caller
	// is not, so header-authed clients skip the origin pin.
	var tokenStr string
	fromCookie := false
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tokenStr = strings.TrimPrefix(ah, "Bearer ")
	} else if c, err := r.Cookie("access_token"); err == nil {
		tokenStr = c.Value
		fromCookie = true
	}
	if tokenStr == "" {
		http.Error(w, "missing access_token", http.StatusUnauthorized)
		return
	}
	if fromCookie && !h.checkOrigin(r) {
		h.logger.Warn("eventsource origin rejected", "origin", r.Header.Get("Origin"))
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	// The ONE push-acceptance seam (shared with the WS handshake): rejects
	// non-access tokens AND any scoped mirror token (Drive P1 native-token
	// bridge). This endpoint can't route through chain.AuthenticateRequest, so
	// the seam re-enforces scope containment — else a drive-scoped token would
	// open a mailbox push stream. See auth.AuthenticatePushToken.
	claims, err := h.chain.AuthenticatePushToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if deny, _ := denylistDecision(h.denylist, claims); deny {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Connection cap — share the WS push-connection budget (both are long-lived).
	max := h.maxClients
	if max <= 0 {
		max = 1000
	}
	if h.incClients() > max {
		h.decClients()
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	defer h.decClients()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Register before successful streaming headers. A concurrent or previously
	// reconciled revocation cancels this context, and the second denylist check
	// closes the narrow gate-to-register race for targeted JTI/family rows.
	releaseSession := h.sessionRegistry.RegisterTokenSession(
		claims.UserID,
		pushIssuedAt(claims),
		claims.JTI,
		claims.FamilyID,
		cancelCloser(cancel),
	)
	defer releaseSession()
	if ctx.Err() != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if deny, _ := denylistDecision(h.denylist, claims); deny {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	accountID := "0"
	var mailboxID int64
	hasMailbox := !claims.IsGuest()
	if hasMailbox {
		accountID = h.jmap.GetAccountID(ctx, claims.UserID)
		mailboxID, _ = strconv.ParseInt(accountID, 10, 64)
		if mailboxID <= 0 {
			http.Error(w, "no primary mailbox", http.StatusForbidden)
			return
		}
	}

	typeFilter := parseTypeFilter(r.URL.Query().Get("types"))
	closeAfterState := r.URL.Query().Get("closeafter") == "state"
	pingSecs, _ := strconv.Atoi(r.URL.Query().Get("ping"))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	// Defeat reverse-proxy response buffering (nginx) that would otherwise hold
	// SSE frames until the connection closes.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe to every session-scoped NOTIFY channel (topology.go, #A2) —
	// the WS handler's SSE twin: mailbox tag:/calendar:/contact:/task: feed
	// the batched JMAP StateChange pipeline; session_revoke ends the stream on
	// match; the rest (drive-watch, perm-gated drive-alarm, chat + its
	// Presence side effect, meet) are forwarded verbatim as their own SSE
	// event once assigned to a named channel below — Go's select can't range
	// over a dynamic channel list without reflect, so each verbatim kind
	// still needs its own case in the select loop further down.
	// admitted records every channel that passed its connect-time gate so the
	// periodic re-validation below re-checks exactly those gates (same seam as
	// the WS Upgrade loop in handler.go).
	notifyCh := make(chan string, 64)
	revokeCh := make(chan string, 4)
	var admitted []subscription
	var driveWatchCh, driveAlarmCh, chatCh, meetCh chan string
	for _, sub := range sessionChannels(claims, mailboxID) {
		// Guest G2 users are intentionally mailbox-less. They still need the
		// self-scoped Chat/Drive/Meet/revocation rails, but have no JMAP state
		// channels or state tokens to subscribe to.
		if !hasMailbox && sub.kind == subStateChange {
			continue
		}
		if !subscriptionAllowed(ctx, h, claims, sub) {
			continue
		}
		admitted = append(admitted, sub)
		switch sub.kind {
		case subStateChange:
			subID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, notifyCh)
			if subErr != nil {
				h.logger.Error("eventsource notify subscribe failed", "channel", sub.channel, "error", subErr)
				return
			}
			defer h.dispatcher.Unsubscribe(sub.channel, subID)
		case subRevoke:
			if revSubID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, revokeCh); subErr == nil {
				defer h.dispatcher.Unsubscribe(sub.channel, revSubID)
			}
		default: // verbatim kinds: subDriveWatch / subDriveAlarm / subChat / subMeet
			ch := make(chan string, sub.bufSize())
			subID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, ch)
			if subErr != nil {
				continue
			}
			defer h.dispatcher.Unsubscribe(sub.channel, subID)
			if sub.onConnect != nil {
				sub.onConnect(claims.UserID)
			}
			if sub.onDisconnect != nil {
				defer sub.onDisconnect(claims.UserID)
			}
			switch sub.kind {
			case subDriveWatch:
				driveWatchCh = ch
			case subDriveAlarm:
				driveAlarmCh = ch
			case subChat:
				chatCh = ch
			case subMeet:
				meetCh = ch
			}
		}
	}

	// Initial sync: emit the current state once on connect (all requested types)
	// so a fresh client — especially a closeafter=state one-shot — gets the
	// baseline without waiting for the next mutation.
	if hasMailbox {
		changed := filterTypes(h.buildChangedTokens(mailboxID, true, true, true), typeFilter)
		if err := writeStateChange(w, flusher, accountID, changed); err != nil {
			return
		}
		if closeAfterState {
			return
		}
	} else if closeAfterState {
		return
	}

	var pingTicker *time.Ticker
	var pingC <-chan time.Time
	if pingSecs > 0 {
		pingTicker = time.NewTicker(time.Duration(pingSecs) * time.Second)
		defer pingTicker.Stop()
		pingC = pingTicker.C
	}

	// Periodic authorization re-validation — the SSE twin of the WS arm
	// (WS-PERMESSAGE-AUTHZ, CWE-613; handler.go). Connect-time
	// subscriptionAllowed evaluated entitlements/admin perms exactly once and
	// nothing re-checked claims.exp for the stream lifetime. Every
	// authzRecheckInterval, revalidateSessionAuthz re-checks the token expiry
	// and the gates of the channels admitted above; a failure ends the SSE
	// stream inside the window (the WS close-frame outcome on the SSE wire).
	// The session_revoke / denylist / ProtocolSessionRegistry teardown rails
	// are unchanged and stay authoritative for revocation.
	revalInterval := h.authzRecheckInterval
	if revalInterval <= 0 {
		revalInterval = defaultWSAuthzRecheckInterval
	}
	revalTicker := time.NewTicker(revalInterval)
	defer revalTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-revokeCh:
			if shouldPushSessionRevoked([]byte(payload), claims) {
				return
			}
		case <-revalTicker.C:
			if !revalidateSessionAuthz(ctx, h, claims, admitted) {
				h.logger.Warn("eventsource: authorization re-validation failed — closing push rail",
					"user_id", claims.UserID, "jti", claims.JTI)
				return
			}
		case <-pingC:
			if _, err := io.WriteString(w, fmt.Sprintf("event: ping\ndata: {\"interval\":%d}\n\n", pingSecs)); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-driveWatchCh:
			var event json.RawMessage
			if json.Unmarshal([]byte(payload), &event) != nil {
				continue // malformed payload — drop, never crash the connection
			}
			if _, err := io.WriteString(w, "event: drive-watch\ndata: "+string(event)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-driveAlarmCh:
			var event json.RawMessage
			if json.Unmarshal([]byte(payload), &event) != nil {
				continue // malformed payload — drop, never crash the connection
			}
			if _, err := io.WriteString(w, "event: drive-alarm\ndata: "+string(event)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-chatCh:
			var event json.RawMessage
			if json.Unmarshal([]byte(payload), &event) != nil {
				continue // malformed payload — drop, never crash the connection
			}
			if _, err := io.WriteString(w, "event: chat\ndata: "+string(event)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-meetCh:
			var event json.RawMessage
			if json.Unmarshal([]byte(payload), &event) != nil {
				continue // malformed payload — drop, never crash the connection
			}
			if _, err := io.WriteString(w, "event: meet\ndata: "+string(event)+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case first := <-notifyCh:
			// Coalesce a burst (20ms window) into one StateChange, matching the WS path.
			batch := []string{first}
			drain := time.NewTimer(20 * time.Millisecond)
		drainLoop:
			for {
				select {
				case p := <-notifyCh:
					batch = append(batch, p)
				case <-drain.C:
					break drainLoop
				case <-ctx.Done():
					drain.Stop()
					return
				}
			}
			drain.Stop()

			anyValid, calChanged, contactChanged, taskChanged, _ := classifyBatch(batch)
			if !anyValid {
				continue
			}
			changed := filterTypes(h.buildChangedTokens(mailboxID, calChanged, contactChanged, taskChanged), typeFilter)
			if len(changed) == 0 {
				continue // nothing the client asked for
			}
			if err := writeStateChange(w, flusher, accountID, changed); err != nil {
				return
			}
			if closeAfterState {
				return
			}
		}
	}
}

// incClients / decClients wrap the shared push-connection counter (also used by
// the WS Upgrade path) so SSE and WS share one connection budget.
func (h *Handler) incClients() int32 { return atomic.AddInt32(&h.clientCount, 1) }
func (h *Handler) decClients()       { atomic.AddInt32(&h.clientCount, -1) }

// parseTypeFilter turns the `types` query param into a set. Empty or "*" means
// "all types" (nil set = no filtering).
func parseTypeFilter(raw string) map[string]bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" {
		return nil
	}
	set := make(map[string]bool)
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			set[t] = true
		}
	}
	return set
}

// filterTypes drops keys the client didn't request. A nil filter passes everything.
func filterTypes(changed map[string]string, filter map[string]bool) map[string]string {
	if filter == nil {
		return changed
	}
	out := make(map[string]string, len(changed))
	for k, v := range changed {
		if filter[k] {
			out[k] = v
		}
	}
	return out
}

// writeStateChange emits one RFC 8620 §7.3 StateChange as an SSE `state` event.
func writeStateChange(w io.Writer, f http.Flusher, accountID string, changed map[string]string) error {
	if len(changed) == 0 {
		return nil
	}
	msg := map[string]any{
		"@type":   "StateChange",
		"changed": map[string]any{accountID: changed},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, "event: state\ndata: "); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "\n\n"); err != nil {
		return err
	}
	f.Flush()
	return nil
}
