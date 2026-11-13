package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/jmap"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/threat"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// CheckOrigin is set per-handler in NewWSHandler.
}

const maxWSMessageSize = 10 * 1024 * 1024 // 10 MiB

// msgCounts bounding (WS-LIFECYCLE-RESOURCE-LIMIT, CWE-770). The counters are
// keyed by client-frame @type; without a closed vocabulary the key space was
// bounded only by the 10 MiB read limit, so any authenticated principal could
// grow the shared heap without bound. Both knobs below are ops tunables:
// raise/lower them via Handler.frameTypeCap / Handler.frameTypeTTL if a
// deployment needs different bounds.
const (
	// defaultWSFrameTypeCap is the max number of distinct @type keys msgCounts
	// retains. With the closed wsClientFrameTypes vocabulary the live key count
	// is 3; the cap is the hard backstop (least-recently-seen eviction).
	defaultWSFrameTypeCap = 64
	// defaultWSFrameTypeTTL is the age at which an untouched msgCounts entry is
	// evicted on the next insert.
	defaultWSFrameTypeTTL = time.Hour
)

// wsClientFrameTypes is the CLOSED vocabulary of client→server @type values
// RFC 8887 defines. Anything else is answered with an unknownType error and
// never counted, so the msgCounts key space is fixed by construction.
var wsClientFrameTypes = map[string]bool{
	"Request":              true,
	"WebSocketPushEnable":  true,
	"WebSocketPushDisable": true,
}

// unknownTypeProblem is the JMAP error type carried in the "error" frame
// answering an @type outside wsClientFrameTypes (RFC 8887 §3.3).
const unknownTypeProblem = "urn:ietf:params:jmap:error:unknownType"

// wsFrameCount is one msgCounts entry: the running per-@type frame counter
// plus the last time that key was seen (TTL + LRU eviction currency).
type wsFrameCount struct {
	count    int64
	lastSeen time.Time
}

// Handler manages JMAP WebSocket connections (RFC 8887).
//
// Each connected client gets:
//   - A subscription to their mailbox's LISTEN/NOTIFY channel.
//   - A bidirectional channel for sending JMAP requests and receiving responses.
//   - Automatic push of StateChange messages when mail is delivered or sent.
//
// Auth: JWT passed as ?access_token= query param. Browsers cannot set the
// Authorization header for WebSocket connections, so query param is standard.
type Handler struct {
	dispatcher *notify.Dispatcher
	chain      *auth.Chain
	jmap       *jmap.JMAPHandler
	logger     *slog.Logger
	production bool
	// allowedHost, when set, is the configured public hostname (cfg.Hostname)
	// the WS origin is pinned to in production. Empty in dev (pure request-host
	// same-origin). Bare host, no scheme/port.
	allowedHost string
	// msgCounts is the per-@type frame counter (3.3.1), bounded by the closed
	// wsClientFrameTypes vocabulary plus the frameTypeCap/frameTypeTTL knobs.
	// countMu guards it (it is written per message, read by tests/monitoring).
	msgCounts map[string]*wsFrameCount
	countMu   sync.Mutex
	// frameTypeCap / frameTypeTTL bound msgCounts. Zero/negative falls back to
	// defaultWSFrameTypeCap / defaultWSFrameTypeTTL. Ops tunables.
	frameTypeCap int
	frameTypeTTL time.Duration
	// authzRecheckInterval is the periodic authorization re-validation window
	// for live connections (see revalidateSessionAuthz). Zero/negative falls
	// back to defaultWSAuthzRecheckInterval. Ops tunable.
	authzRecheckInterval time.Duration
	maxClients           int32
	clientCount          int32

	// denylist gates JMAP dispatch for revoked sessions (CA-3a finding 2).
	// Nil = no check (pre-wiring). Set via SetDenylist after construction.
	denylist *threat.SessionDenylist

	// sessionRegistry closes established long-lived push transports when a
	// session_revoke NOTIFY or durable reconcile covers their access token.
	sessionRegistry *threat.ProtocolSessionRegistry

	// deviceRevCheck gates JMAP dispatch for revoked/wiped devices (offline #2b).
	// Called as fn(ctx, deviceFP); true = deny. Nil = no check (pre-wiring).
	// ponytail: func type avoids importing middleware from ws.
	deviceRevCheck func(context.Context, string) bool

	// Profiling counters — monitor WebSocket write amplification.
	// If wsWritesPerSecond exceeds threshold or wsWriteLatencyUs p99 > 20ms,
	// implement per-connection batching in the notify goroutine.
	wsWriteTotal     atomic.Int64
	wsWriteLatencyUs atomic.Int64 // cumulative microseconds
}

func NewHandler(dispatcher *notify.Dispatcher, chain *auth.Chain, jh *jmap.JMAPHandler, logger *slog.Logger, production bool) *Handler {
	return &Handler{
		dispatcher:           dispatcher,
		chain:                chain,
		jmap:                 jh,
		logger:               logger,
		production:           production,
		msgCounts:            make(map[string]*wsFrameCount),
		frameTypeCap:         defaultWSFrameTypeCap,
		frameTypeTTL:         defaultWSFrameTypeTTL,
		authzRecheckInterval: defaultWSAuthzRecheckInterval,
	}
}

// SetAllowedOrigin pins the WebSocket origin check to a configured public
// hostname (bare host, e.g. "mail.corp.com" — no scheme/port). Set in
// production; leave unset in dev to keep pure request-host same-origin.
func (h *Handler) SetAllowedOrigin(host string) {
	h.allowedHost = host
}

// SetDenylist wires the session-revocation denylist so handleMessage can
// gate JMAP dispatch for revoked sessions (CA-3a finding 2).
func (h *Handler) SetDenylist(d *threat.SessionDenylist) { h.denylist = d }

// SetSessionRegistry wires the process-wide runtime-session registry shared by
// IMAP, SMTP, WebSocket, and SSE.
func (h *Handler) SetSessionRegistry(r *threat.ProtocolSessionRegistry) {
	h.sessionRegistry = r
}

// SetDeviceRevocationCheck wires the device-revocation check for the WS path
// (offline #2b finding). fn is called with (ctx, deviceFP); true = deny (close the socket).
// Share the DeviceRevocationChecker from DeviceRevocationGate so both HTTP and WS paths
// use the same loaded cache.
func (h *Handler) SetDeviceRevocationCheck(fn func(context.Context, string) bool) {
	h.deviceRevCheck = fn
}

// wsEnvelope is the top-level wrapper for all JMAP WebSocket messages.
type wsEnvelope struct {
	Type string `json:"@type"`
	// Request fields
	Using       []string          `json:"using,omitempty"`
	MethodCalls []jmap.MethodCall `json:"methodCalls,omitempty"`
	ID          string            `json:"id,omitempty"`
	// Response fields
	SessionState    string            `json:"sessionState,omitempty"`
	MethodResponses []jmap.MethodCall `json:"methodResponses,omitempty"`
	CreatedIDs      map[string]string `json:"createdIds,omitempty"`
	RequestID       string            `json:"requestId,omitempty"`
	ProblemType     string            `json:"type,omitempty"`
	Status          int               `json:"status,omitempty"`
	Detail          string            `json:"detail,omitempty"`
	// Push control
	DataTypes []string `json:"dataTypes,omitempty"`
	PushState string   `json:"pushState,omitempty"`
	// StateChange
	Changed map[string]map[string]string `json:"changed,omitempty"`
}

// Upgrade upgrades GET /jmap/ws to a WebSocket connection.
func (h *Handler) Upgrade(w http.ResponseWriter, r *http.Request) {
	// Origin check
	if !h.checkOrigin(r) {
		h.logger.Warn("websocket origin rejected", "origin", r.Header.Get("Origin"))
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}

	// Connection limit
	max := h.maxClients
	if max <= 0 {
		max = 1000
	}
	if atomic.LoadInt32(&h.clientCount) >= max {
		h.logger.Warn("websocket: max clients reached", "max", max)
		http.Error(w, "too many connections", http.StatusServiceUnavailable)
		return
	}
	atomic.AddInt32(&h.clientCount, 1)
	defer atomic.AddInt32(&h.clientCount, -1)

	// Authenticate via cookie (HttpOnly — sent automatically by browser WS).
	// Browsers cannot set custom headers on WebSocket handshake, so cookies
	// are the only secure transport for tokens.
	var tokenStr string
	if c, err := r.Cookie("access_token"); err == nil {
		tokenStr = c.Value
	}
	if tokenStr == "" {
		http.Error(w, "missing access_token", http.StatusUnauthorized)
		return
	}
	// Subprotocol validation (3.3.2) — reject unknown WebSocket subprotocols
	if sp := r.Header.Get("Sec-WebSocket-Protocol"); sp != "" {
		h.logger.Warn("websocket subprotocol rejected", "subprotocol", sp)
	}

	// The ONE push-acceptance seam: rejects non-access tokens AND any scoped
	// mirror token (Drive P1 native-token bridge) in one place, so this handshake
	// — which can't route through chain.AuthenticateRequest (no Authorization
	// header) — still enforces scope containment. See auth.AuthenticatePushToken.
	claims, err := h.chain.AuthenticatePushToken(r.Context(), tokenStr)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if deny, _ := denylistDecision(h.denylist, claims); deny {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.Close()

	// Write mutex: gorilla/websocket requires no more than one concurrent writer.
	var writeMu sync.Mutex

	conn.SetReadLimit(maxWSMessageSize)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Register after upgrade but before any subscription. The registry's
	// all-session watermark and targeted token sets reject a revocation that
	// races between the handshake denylist check and registration.
	releaseSession := h.sessionRegistry.RegisterTokenSession(
		claims.UserID,
		pushIssuedAt(claims),
		claims.JTI,
		claims.FamilyID,
		conn,
	)
	defer releaseSession()
	if deny, _ := denylistDecision(h.denylist, claims); deny {
		return
	}

	// Resolve the caller's PRIMARY MAILBOX id the same way parseAccountID does
	// (SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary). This is the
	// account-scope currency (ADR-003): users.id and mailboxes.id are
	// independent BIGSERIAL sequences, and every reducer emits its push on
	// "tag:{mailbox_id}" (notify_state_change), NEVER "tag:{user_id}". Keying
	// the subscription on claims.UserID — as this handler historically did —
	// silently matched zero notifications in production (where user_id !=
	// mailbox_id) so the webmail received NO state-change pushes.
	accountID := h.jmap.GetAccountID(ctx, claims.UserID)
	mailboxID, _ := strconv.ParseInt(accountID, 10, 64)
	if mailboxID <= 0 {
		// The connection is already upgraded (hijacked) at this point, so we
		// cannot write an http.Error — just log and return; the deferred
		// conn.Close() tears the socket down.
		h.logger.Error("websocket: could not resolve primary mailbox", "user_id", claims.UserID)
		return
	}

	// Subscribe to every session-scoped NOTIFY channel (topology.go, #A2):
	// mailbox tag:/calendar:/contact:/task: feed the batched JMAP StateChange
	// pipeline; session_revoke tears the connection down on match; the rest
	// (drive-watch, perm-gated drive-alarm, chat + its Presence side effect,
	// meet) are forwarded to the client verbatim via forwardRawEvents.
	// admitted records every channel that passed its connect-time gate so the
	// periodic re-validation below re-checks exactly those gates.
	notifyCh := make(chan string, 64)
	revokeCh := make(chan string, 4) // ponytail: buffered 4 — one revoke per user burst; goroutine exits on first match.
	var admitted []subscription
	for _, sub := range sessionChannels(claims, mailboxID) {
		if !subscriptionAllowed(ctx, h, claims, sub) {
			continue
		}
		admitted = append(admitted, sub)
		switch sub.kind {
		case subStateChange:
			subID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, notifyCh)
			if subErr != nil {
				h.logger.Error("notify subscribe failed", "channel", sub.channel, "error", subErr)
				return
			}
			defer h.dispatcher.Unsubscribe(sub.channel, subID)
		case subRevoke:
			if revSubID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, revokeCh); subErr == nil {
				defer h.dispatcher.Unsubscribe(sub.channel, revSubID)
				go func() {
					for {
						select {
						case <-ctx.Done():
							return
						case payload := <-revokeCh:
							if shouldPushSessionRevoked([]byte(payload), claims) {
								writeMu.Lock()
								_ = conn.WriteJSON(map[string]string{"@type": "SessionRevoked"})
								writeMu.Unlock()
								cancel() // tear the socket down
								return
							}
						}
					}
				}()
			}
		default: // verbatim kinds: subDriveWatch / subDriveAlarm / subChat / subMeet
			ch := make(chan string, sub.bufSize())
			if subID, subErr := h.dispatcher.Subscribe(ctx, sub.channel, ch); subErr == nil {
				defer h.dispatcher.Unsubscribe(sub.channel, subID)
				go forwardRawEvents(ctx, conn, &writeMu, ch, sub.wsAtType)
				if sub.onConnect != nil {
					sub.onConnect(claims.UserID)
				}
				if sub.onDisconnect != nil {
					defer sub.onDisconnect(claims.UserID)
				}
			}
		}
	}

	// Per-connection goroutine — forwards NOTIFY payloads to WebSocket.
	// Uses ctx derived from context.WithCancel(r.Context()); cancelled on disconnect.
	go func() {
		for {
			// Block until the first notification arrives.
			var first string
			select {
			case first = <-notifyCh:
			case <-ctx.Done():
				return
			}

			// Drain any additional notifications that arrive within 20ms.
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

			start := time.Now()
			writeMu.Lock()
			h.pushStateChangeBatchLocked(conn, accountID, mailboxID, batch)
			writeMu.Unlock()
			h.wsWriteTotal.Add(1)
			h.wsWriteLatencyUs.Add(time.Since(start).Microseconds())
		}
	}()

	// Keepalive pings.
	conn.SetReadDeadline(time.Now().Add(70 * time.Second))
	conn.SetPongHandler(func(_ string) error {
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})
	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()

	// Periodic authorization re-validation (WS-PERMESSAGE-AUTHZ, CWE-613).
	// Connect-time subscriptionAllowed evaluated entitlements/admin perms
	// exactly once and nothing re-checked claims.exp for the connection
	// lifetime. Every authzRecheckInterval, revalidateSessionAuthz re-checks
	// the token expiry and the gates of the channels admitted above; a failure
	// tears the whole push rail down inside the window. The session_revoke /
	// denylist / device-revocation teardown rails are unchanged and stay
	// authoritative for revocation; this closes only the gaps they never
	// covered (claims.exp passing mid-connection, entitlement/permission
	// changes with no lifecycle teardown).
	revalInterval := h.authzRecheckInterval
	if revalInterval <= 0 {
		revalInterval = defaultWSAuthzRecheckInterval
	}
	revalTicker := time.NewTicker(revalInterval)
	defer revalTicker.Stop()

	// Per-connection goroutine — reads JMAP requests over WebSocket.
	// Uses ctx derived from context.WithCancel(r.Context()); cancelled on disconnect.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		defer func() {
			if rec := recover(); rec != nil {
				h.logger.Error("websocket read loop panic", "panic", rec)
				cancel()
			}
		}()
		panicCount := 0
		const maxPanics = 5
		for {
			_, msgBytes, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
			panicCount += h.handleMessage(ctx, conn, &writeMu, claims, msgBytes)
			if panicCount >= maxPanics {
				h.logger.Error("websocket too many handleMessage panics, closing", "count", panicCount)
				cancel()
				return
			}
		}
	}()

	for {
		select {
		case <-pingTicker.C:
			writeMu.Lock()
			err := conn.WriteMessage(websocket.PingMessage, nil)
			writeMu.Unlock()
			if err != nil {
				return
			}
		case <-revalTicker.C:
			if !revalidateSessionAuthz(ctx, h, claims, admitted) {
				h.logger.Warn("websocket: authorization re-validation failed — closing push rail",
					"user_id", claims.UserID, "jti", claims.JTI)
				writeMu.Lock()
				_ = conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "authorization changed"))
				writeMu.Unlock()
				return
			}
		case <-readDone:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (h *Handler) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Browsers ALWAYS send Origin on a WS handshake (RFC 6454). An empty
		// Origin is a non-browser client or a proxy/header-stripping
		// intermediary: accept only in dev. h.production is derived from a real
		// TLS/proxy deployment signal (cmd/mailserverd/main.go), NOT just the
		// static-cert path — so autocert/Lego and reverse-proxy deployments
		// reject empty Origin too (CSWSH backstop).
		return !h.production
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if h.allowedHost != "" {
		// Production: pin to the configured public hostname (robust when r.Host
		// is rewritten by a reverse proxy). Also accept an exact request-host
		// match so multi-domain (autocert) front-ends keep working — a genuine
		// cross-site WS carries the attacker's Origin host with the victim's
		// real Host, so neither branch passes it.
		return strings.EqualFold(u.Host, h.allowedHost) || u.Host == r.Host
	}
	// Dev / no configured host: require same origin as the request host.
	return u.Host == r.Host
}

// handleMessage processes a single WebSocket message from the client.
func (h *Handler) handleMessage(ctx context.Context, conn *websocket.Conn, writeMu *sync.Mutex, claims *auth.Claims, data []byte) (errCount int) {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("websocket handleMessage panic", "panic", rec)
			errCount++ // returned via named return; caller tracks panic count
		}
	}()

	// Denylist gate (CA-3a): revoked sessions must not dispatch JMAP.
	// Fail-CLOSED when denylist is non-nil but not loaded — matches RequireRuntimeAccess contract.
	// (Previously fail-open on !Loaded; asymmetric with the HTTP path, now corrected.)
	if deny, shouldClose := denylistDecision(h.denylist, claims); deny {
		if shouldClose {
			h.logger.Warn("ws: denylist not loaded — closing connection (fail-closed)")
			writeMu.Lock()
			_ = conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseServiceRestart, "session verification unavailable"))
			writeMu.Unlock()
			_ = conn.Close()
		} else {
			h.logger.Info("ws: revoked session attempted JMAP dispatch — rejected",
				"user_id", claims.UserID, "jti", claims.JTI)
		}
		return 0
	}

	// Device-revocation gate (offline #2b): a revoked/wiped device must not read JMAP
	// over WS even with a valid JWT — HTTP is DeviceRevocationGate-protected; without
	// this check the WS path was an unguarded bypass. Fail-CLOSED when the denylist is
	// unloaded (deviceRevocationDecision returns true). Shares the DeviceRevocationChecker
	// loaded by DeviceRevocationGate — no separate cache or NOTIFY subscription needed.
	if deviceRevocationDecision(ctx, h.deviceRevCheck, claims) {
		h.logger.Warn("ws: revoked device attempted JMAP dispatch — closing",
			"user_id", claims.UserID)
		writeMu.Lock()
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "device access revoked"))
		writeMu.Unlock()
		_ = conn.Close()
		return 0
	}

	var env wsEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return
	}

	// Closed @type vocabulary (RFC 8887 §3.3): a client frame outside
	// wsClientFrameTypes is answered with an unknownType error and NEVER enters
	// msgCounts, so the counter key space is fixed by construction. The
	// cap/TTL bound in recordFrameType is the belt-and-suspenders hard limit
	// (WS-LIFECYCLE-RESOURCE-LIMIT): the key length and count of distinct
	// unauthenticated values can no longer grow the shared heap.
	if !wsClientFrameTypes[env.Type] {
		errMsg := wsEnvelope{
			Type:        "error",
			ProblemType: unknownTypeProblem,
			Status:      http.StatusBadRequest,
			Detail:      "unknown @type",
		}
		if data, mErr := json.Marshal(errMsg); mErr == nil {
			writeMu.Lock()
			// Best-effort control reply, same as the CloseMessage writes
			// above: a failed error frame cannot be retried meaningfully and
			// the caller's own error accounting (errCount) already covers it.
			_ = conn.WriteMessage(websocket.TextMessage, data)
			writeMu.Unlock()
		}
		return 0
	}

	// Per-message type frame counting (3.3.1) — bounded (cap + TTL eviction).
	h.recordFrameType(env.Type, time.Now())

	switch env.Type {
	case "Request":
		resp := h.executeRequest(ctx, claims, env)
		data, _ := json.Marshal(resp)
		writeMu.Lock()
		conn.WriteMessage(websocket.TextMessage, data)
		writeMu.Unlock()

	case "WebSocketPushEnable":
		// Client explicitly enables push (optional per RFC 8887).
		// We push all state changes by default — nothing extra needed here.

	case "WebSocketPushDisable":
		// Client opts out of push for this connection — not supported in Phase 2.
		// Respond with an error per RFC 8887.
		errMsg := wsEnvelope{Type: "error"}
		data, _ := json.Marshal(errMsg)
		writeMu.Lock()
		conn.WriteMessage(websocket.TextMessage, data)
		writeMu.Unlock()
	}
	return 0
}

// recordFrameType bumps the bounded per-@type frame counter. Callers must pass
// a type already admitted by wsClientFrameTypes — the counting path rejects
// everything else — but the cap/TTL eviction below holds even if that changes:
// at cap, expired entries are evicted first, then the least-recently-seen key,
// so len(msgCounts) can never exceed frameTypeCap.
func (h *Handler) recordFrameType(typ string, now time.Time) {
	h.countMu.Lock()
	defer h.countMu.Unlock()
	if fc, ok := h.msgCounts[typ]; ok {
		fc.count++
		fc.lastSeen = now
		return
	}
	maxTypes := h.frameTypeCap
	if maxTypes <= 0 {
		maxTypes = defaultWSFrameTypeCap
	}
	ttl := h.frameTypeTTL
	if ttl <= 0 {
		ttl = defaultWSFrameTypeTTL
	}
	for key, fc := range h.msgCounts {
		if now.Sub(fc.lastSeen) > ttl {
			delete(h.msgCounts, key)
		}
	}
	if len(h.msgCounts) >= maxTypes {
		oldestKey := ""
		var oldest time.Time
		first := true
		for key, fc := range h.msgCounts {
			if first || fc.lastSeen.Before(oldest) {
				oldestKey, oldest, first = key, fc.lastSeen, false
			}
		}
		if oldestKey != "" {
			delete(h.msgCounts, oldestKey)
		}
	}
	h.msgCounts[typ] = &wsFrameCount{count: 1, lastSeen: now}
}

// executeRequest is the RFC 8887 transport projection over JMAPHandler's
// transport-neutral batch authority. It never resolves, gates, dispatches, or
// accumulates method calls itself.
func (h *Handler) executeRequest(ctx context.Context, claims *auth.Claims, env wsEnvelope) wsEnvelope {
	result := h.jmap.ExecuteBatch(ctx, claims, jmap.BatchRequest{
		Using: env.Using, MethodCalls: env.MethodCalls, CreatedIDs: env.CreatedIDs,
	})
	if result.Problem != nil {
		return wsEnvelope{
			Type:        "RequestError",
			RequestID:   env.ID,
			ProblemType: result.Problem.Type,
			Status:      result.Problem.Status,
			Detail:      result.Problem.Detail,
		}
	}
	return wsEnvelope{
		Type:            "Response",
		RequestID:       env.ID,
		SessionState:    result.Response.SessionState,
		MethodResponses: result.Response.MethodResponses,
		CreatedIDs:      result.Response.CreatedIDs,
	}
}

// pushStateChangeBatchLocked sends a single JMAP StateChange message (RFC 8887 §3.2)
// per batch of pg_notify payloads.
//
// State tokens are read from the database per capability (jmap_email_state,
// jmap_mailbox_state, jmap_thread_state) so that each type carries its own
// monotonic counter rather than a single shared value. accountID is the
// caller's primary-mailbox id as a string (the JMAP accountId wire value);
// mailboxID is the same value as an int and is what the per-capability state
// tokens are keyed on (mailboxes.id, NOT users.id — ADR-003).
//
// Payloads carry either a "state" field (email/tag channels via
// notify_state_change) or a calendar "event" field (the "calendar:{mailbox_id}"
// channel). A calendar notification adds the Calendar/CalendarEvent keys so the
// webmail's `changes.Calendar || changes.CalendarEvent` push handler fires.
// classifyBatch inspects a batch of pg_notify payloads and reports whether the
// batch carries any state change worth pushing (anyValid) and which domains
// changed (calendar/CalendarEvent, contact, task). Pure (no I/O) so the
// classification contract — including the iTIP/RSVP family that historically
// slipped through — is unit-testable (see handler_test.go).
//
// Discrimination is keyed on the PRESENCE of the channel's id field, NOT on
// fragile event-string matching (Decision F): contact:{mailbox_id} payloads carry
// a "contact_id" key, task:{mailbox_id} payloads carry a "task_id" key, mirroring
// the calendar "calendar_id"/"event_id" catch-all. A "contact_id"/"task_id" key is
// always present (JSON null for a domain-wide change), so its presence — not its
// value — is the discriminator.
//
// Channel payload shapes:
//   - email/tag (tag:{mailbox_id}, notify_state_change): carries "state".
//   - calendar (calendar:{mailbox_id}): carries an "event" string discriminator,
//     and optionally a "calendar_id" or "event_id".
//   - contact (contact:{mailbox_id}, notify_contact_state): carries a "contact_id".
//   - task (task:{mailbox_id}, notify_task_state): carries a "task_id".
//
// controlPayloadTypes is the set of top-level "type" values the WS layer forwards
// verbatim to the live socket (NOT as a StateChange token map). These carry no
// state/calendar/contact/task discriminator, so without this set classifyBatch
// would drop them (the F1 bug: offline.wipe/capsChanged were silently lost).
var controlPayloadTypes = map[string]bool{
	"offline.wipe":  true,
	"capsChanged":   true,
	"MailWorkEvent": true,
}

func classifyBatch(payloads []string) (anyValid, calendarChanged, contactChanged, taskChanged bool, controlPayloads []json.RawMessage) {
	for _, payload := range payloads {
		var notif map[string]any
		if err := json.Unmarshal([]byte(payload), &notif); err != nil {
			continue
		}
		// Control payloads: a top-level "type" string in the control set is
		// forwarded verbatim, bypassing the StateChange token path entirely.
		if t, ok := notif["type"].(string); ok && controlPayloadTypes[t] {
			controlPayloads = append(controlPayloads, json.RawMessage(payload))
			continue
		}
		if _, ok := notif["state"]; ok {
			anyValid = true
		}
		// Calendar/CalendarEvent classification. The calendar:{mailbox_id} channel
		// carries an "event" string discriminator. Match three families:
		//   1. *event* substring (event_created/updated/destroyed) — Calendar/set,
		//      recurrence edits, calendar_send_invite.
		//   2. "calendar" prefix (calendar_updated) — Calendar metadata changes.
		//   3. iTIP / RSVP events (rsvp, itip_reply, itip_cancel) — calendar_itip.sql
		//      emits these with an event_id but NO calendar_id, so the substring/prefix
		//      rules above miss them and the push was dead at the calendar UI.
		if ev, ok := notif["event"].(string); ok &&
			(strings.Contains(ev, "event") || strings.HasPrefix(ev, "calendar") ||
				ev == "rsvp" || ev == "itip_reply" || ev == "itip_cancel") {
			calendarChanged = true
			anyValid = true
		}
		// Any calendar payload that carries a calendar_id or an event_id is a
		// calendar change (catch-all for iTIP/RSVP payloads keyed by event_id only).
		if _, ok := notif["calendar_id"]; ok {
			calendarChanged = true
			anyValid = true
		}
		if _, ok := notif["event_id"]; ok {
			calendarChanged = true
			anyValid = true
		}
		// Contact / Task classification — keyed on id-presence (Decision F), NOT on
		// the event string (which overlaps the calendar "event" key).
		if _, ok := notif["contact_id"]; ok {
			contactChanged = true
			anyValid = true
		}
		if _, ok := notif["task_id"]; ok {
			taskChanged = true
			anyValid = true
		}
	}
	return anyValid, calendarChanged, contactChanged, taskChanged, controlPayloads
}

// forwardRawEvents drains a NOTIFY channel and writes each payload verbatim to
// the socket as a distinct {"@type": atType, "event": <payload>} wire message,
// dropping malformed JSON rather than tearing the connection down. Shared by the
// drive-watch and drive-alarm push loops (identical fan-out, different channel
// and wire type). Returns when ctx is cancelled (connection closed).
func forwardRawEvents(ctx context.Context, conn *websocket.Conn, writeMu *sync.Mutex, ch <-chan string, atType string) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-ch:
			var event json.RawMessage
			if json.Unmarshal([]byte(payload), &event) != nil {
				continue // malformed payload — drop, never crash the connection
			}
			writeMu.Lock()
			_ = conn.WriteJSON(map[string]any{"@type": atType, "event": event})
			writeMu.Unlock()
		}
	}
}

// shouldPushSessionRevoked is the best-effort client-message twin of the
// process-wide ProtocolSessionRegistry. It must use the same scope semantics:
// all compares the access-token iat to the revocation watermark, while JTI and
// family scopes match only the exact token identity.
func shouldPushSessionRevoked(payload []byte, claims *auth.Claims) bool {
	if claims == nil {
		return false
	}
	var p struct {
		UserID    int64  `json:"user_id"`
		Scope     string `json:"scope"`
		NotBefore string `json:"not_before"`
		JTI       string `json:"jti"`
		FamilyID  string `json:"family_id"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return false
	}
	if p.UserID != claims.UserID {
		return false
	}
	switch p.Scope {
	case threat.ScopeAll:
		if claims.IssuedAt == nil {
			return true
		}
		notBefore, err := time.Parse(time.RFC3339Nano, p.NotBefore)
		return err == nil && !claims.IssuedAt.Time.After(notBefore)
	case threat.ScopeJTI:
		return p.JTI != "" && p.JTI == claims.JTI
	case threat.ScopeFamily:
		return p.FamilyID != "" && p.FamilyID == claims.FamilyID
	default:
		return false
	}
}

// buildChangedTokens builds the per-type state-token map for a JMAP StateChange,
// given which domains a batch of pg_notify payloads touched. Shared by the WS
// (pushStateChangeBatchLocked) and EventSource (SSE) push paths so both emit the
// identical token set. Email/Mailbox/Thread always ride along (the common case);
// calendar/contact/task keys are added only when their domain changed.
func (h *Handler) buildChangedTokens(mailboxID int64, calendarChanged, contactChanged, taskChanged bool) map[string]string {
	tokens := h.jmap.GetStateTokensByMailbox(context.Background(), mailboxID)
	changed := map[string]string{
		"Email":   tokens.Email,
		"Mailbox": tokens.Mailbox,
		"Thread":  tokens.Thread,
	}
	if calendarChanged {
		// The webmail re-fetches on any Calendar/CalendarEvent key; the token
		// value is the mailbox-wide max calendar jmap_state.
		changed["Calendar"] = tokens.Calendar
		changed["CalendarEvent"] = tokens.Calendar
	}
	if contactChanged {
		changed["Contact"] = tokens.Contact
	}
	if taskChanged {
		changed["Task"] = tokens.Task
	}
	return changed
}

func (h *Handler) pushStateChangeBatchLocked(conn *websocket.Conn, accountID string, mailboxID int64, payloads []string) {
	anyValid, calendarChanged, contactChanged, taskChanged, controlPayloads := classifyBatch(payloads)

	// Forward control payloads verbatim FIRST (independent of accountID gating and
	// of GetStateTokensByMailbox). A revoked device must get its offline.wipe even
	// when no state token changed.
	for _, ctrl := range controlPayloads {
		conn.WriteMessage(websocket.TextMessage, ctrl) //nolint:errcheck
	}

	if !anyValid || accountID == "" || accountID == "0" {
		return
	}

	changed := h.buildChangedTokens(mailboxID, calendarChanged, contactChanged, taskChanged)

	msg := map[string]any{
		"@type": "StateChange",
		"changed": map[string]any{
			accountID: changed,
		},
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	conn.WriteMessage(websocket.TextMessage, data)
}

// deviceRevocationDecision returns true when JMAP dispatch must be denied due to
// device revocation (offline #2b). Extracted as a pure helper for unit-testability
// (mirrors denylistDecision — no *websocket.Conn dependency).
//
//   - false: gate passes; proceed normally.
//   - true: device is revoked or denylist is unloaded (fail-CLOSED) — caller closes the socket.
func deviceRevocationDecision(ctx context.Context, fn func(context.Context, string) bool, claims *auth.Claims) bool {
	if fn == nil {
		return false // not wired — no check
	}
	if claims.Device == nil || claims.Device.ID == "" {
		return false // legacy/unenrolled device — pass (same as HTTP gate posture)
	}
	return fn(ctx, claims.Device.ID)
}

// denylistDecision returns (deny, shouldClose) for the given denylist and claims.
//
//   - deny=false: gate passes; proceed normally.
//   - deny=true, shouldClose=false: session is known-revoked (close the race window; the
//     session_revoke NOTIFY goroutine will also tear down the socket).
//   - deny=true, shouldClose=true: denylist is non-nil but not yet loaded (fail-CLOSED to
//     match RequireRuntimeAccess — caller must write a close frame and close the connection).
//
// Extracted as a pure helper for unit-testability (no *websocket.Conn dependency).
func denylistDecision(dl *threat.SessionDenylist, claims *auth.Claims) (deny, shouldClose bool) {
	if dl == nil {
		return false, false
	}
	if !dl.Loaded() {
		return true, true // fail-CLOSED: cannot verify revocation state
	}
	var iat time.Time
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Time
	}
	if dl.IsRevoked(claims.UserID, claims.JTI, claims.FamilyID, iat) {
		return true, false
	}
	return false, false
}

func pushIssuedAt(claims *auth.Claims) time.Time {
	if claims != nil && claims.IssuedAt != nil {
		return claims.IssuedAt.Time
	}
	return time.Time{}
}
