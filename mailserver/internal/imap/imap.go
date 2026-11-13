package imap

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
	wh "setjoin.com/shared/webhook"
)

// Server is a minimal IMAP4rev2 bridge to the PostgreSQL mail store.
type Server struct {
	pool              *pgxpool.Pool
	logger            *slog.Logger
	addr              string
	listener          net.Listener
	tlsCert           string
	tlsKey            string
	implicitTLS       bool
	requireTLS        bool
	dispatcher        *notify.Dispatcher
	webhookDispatcher *webhook.Dispatcher
	threatInterceptor *threat.ThreatInterceptor
	sessionRegistry   *threat.ProtocolSessionRegistry
	maxConns          int
	userTracker       tlsutil.ConnTracker
}

// NewServer creates an IMAP server.
func NewServer(pool *pgxpool.Pool, addr string, dispatcher *notify.Dispatcher, logger *slog.Logger, webhookDispatcher *webhook.Dispatcher, threatInterceptor *threat.ThreatInterceptor) *Server {
	return &Server{pool: pool, addr: addr, dispatcher: dispatcher, logger: logger, webhookDispatcher: webhookDispatcher, threatInterceptor: threatInterceptor}
}

// SetTLS enables implicit TLS for this server.
func (s *Server) SetTLS(certFile, keyFile string) {
	s.tlsCert = certFile
	s.tlsKey = keyFile
	s.implicitTLS = true
	s.requireTLS = true
}

// SetSTARTTLS enables an explicit TLS upgrade on the plaintext IMAP listener.
// Authentication is rejected until the upgrade succeeds.
func (s *Server) SetSTARTTLS(certFile, keyFile string) {
	s.tlsCert = certFile
	s.tlsKey = keyFile
	s.implicitTLS = false
	s.requireTLS = true
}

// SetMaxConns caps the number of simultaneous connections. 0 = unlimited.
func (s *Server) SetMaxConns(n int) { s.maxConns = n }

// SetPerUserMaxConns caps connections per authenticated user. 0 = unlimited.
func (s *Server) SetPerUserMaxConns(n int) { s.userTracker.SetMaxConns(n) }

// SetSessionRegistry enables immediate closure of authenticated protocol
// connections when revoke_user_sessions commits.
func (s *Server) SetSessionRegistry(registry *threat.ProtocolSessionRegistry) {
	s.sessionRegistry = registry
}

// Start begins accepting IMAP connections.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("imap listen %s: %w", s.addr, err)
	}

	if s.tlsCert != "" && s.tlsKey != "" {
		// Validate the configured pair before accepting connections. STARTTLS
		// listeners use the same pair later during the per-connection upgrade.
		if _, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey); err != nil {
			s.logger.Error("failed to load TLS certificate", "cert", s.tlsCert, "key", s.tlsKey, "error", err)
			ln.Close()
			return fmt.Errorf("imap TLS cert load: %w", err)
		}
	}

	if s.implicitTLS {
		tlsConfig := &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     tlsutil.DefaultCipherSuites,
			CurvePreferences: tlsutil.DefaultCurves,
		}
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			s.logger.Error("failed to load TLS certificate", "cert", s.tlsCert, "key", s.tlsKey, "error", err)
			ln.Close()
			return fmt.Errorf("imap TLS cert load: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		ln = tls.NewListener(ln, tlsConfig)
		s.logger.Info("IMAP TLS server started", "addr", s.addr)
	} else {
		s.logger.Info("IMAP server started", "addr", s.addr)
	}

	if s.maxConns > 0 {
		ln = tlsutil.LimitListener(ln, s.maxConns)
		s.logger.Info("IMAP connection limit applied", "max_conns", s.maxConns)
	}
	s.listener = ln

	// Server-lifetime goroutine — uses server-level shutdown context.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Server-lifetime goroutine — uses server-level shutdown context.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.logger.Warn("imap accept error", "error", err)
				continue
			}
			go s.handleConn(ctx, conn)
		}
	}()

	return nil
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// ponytail: recover so one malformed connection can never crash the process.
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("imap: panic in handleConn (recovered)", "panic", r)
		}
	}()

	c := &connState{
		srv:    s,
		conn:   conn,
		reader: bufio.NewReader(conn),
		secure: s.implicitTLS,
		authed: false,
		userID: 0,
	}

	// Release per-user connection slot on disconnect
	defer func() {
		if c.release != nil {
			c.release()
		}
		if c.sessionRelease != nil {
			c.sessionRelease()
		}
	}()

	c.reply("*", "OK [CAPABILITY "+c.capabilities()+"] mailserver ready")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := c.readCommandLine()
		if err != nil {
			if err == errIMAPLineTooLong {
				c.reply("*", "BAD line too long")
			}
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			c.reply(parts[0], "BAD Command not understood")
			continue
		}

		tag := parts[0]
		cmd := strings.ToUpper(parts[1])
		args := strings.Join(parts[2:], " ")

		switch cmd {
		case "CAPABILITY":
			c.reply("*", "CAPABILITY "+c.capabilities())
			c.reply(tag, "OK CAPABILITY completed")
		case "NOOP":
			c.reply(tag, "OK NOOP completed")
		case "LOGOUT":
			c.reply("*", "BYE Logging out")
			c.reply(tag, "OK LOGOUT completed")
			return
		case "LOGIN":
			c.handleLogin(ctx, tag, args)
		case "SELECT", "EXAMINE":
			c.handleSelect(ctx, tag, cmd, args)
		case "LIST":
			c.handleList(ctx, tag)
		case "LSUB":
			c.reply(tag, "OK LSUB completed")
		case "STATUS":
			c.handleStatus(ctx, tag, args)
		case "FETCH":
			c.handleFetch(ctx, tag, args, false)
		case "SEARCH":
			c.handleSearch(ctx, tag, false, args)
		case "STORE":
			c.handleStore(ctx, tag, false, args)
		case "EXPUNGE":
			c.handleExpunge(ctx, tag)
		case "UID":
			c.handleUID(ctx, tag, args)
		case "IDLE":
			c.handleIdle(ctx, tag)
		case "APPEND":
			c.handleAppend(ctx, tag, args)
		case "CREATE":
			c.handleCreate(ctx, tag, args)
		case "DELETE":
			c.handleDelete(ctx, tag, args)
		case "RENAME":
			c.handleRename(ctx, tag, args)
		case "MOVE":
			c.handleMove(ctx, tag, args, false)
		case "COPY":
			c.handleCopy(ctx, tag, args, false)
		case "CLOSE":
			c.handleClose(ctx, tag)
		case "UNSELECT":
			c.handleUnselect(tag)
		case "NAMESPACE":
			c.reply("*", "NAMESPACE ((\"\" \"/\")) NIL NIL")
			c.reply(tag, "OK NAMESPACE completed")
		case "STARTTLS":
			c.handleStartTLS(ctx, tag)
		case "AUTHENTICATE":
			c.handleAuthenticate(ctx, tag, args)
		case "SUBSCRIBE", "UNSUBSCRIBE":
			c.reply(tag, "OK "+cmd+" completed")
		case "ID":
			c.reply(tag, "OK ID completed")
		case "ENABLE":
			c.reply(tag, "OK ENABLE completed")
		default:
			c.reply(tag, "BAD Command not implemented")
		}
	}
}

func (c *connState) auditLog(ctx context.Context, action string, msgID *int64) {
	if c.mailboxID > 0 {
		c.srv.pool.Exec(ctx,
			`INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id)
			 VALUES ($1, $2, $3, $4)`,
			c.mailboxID, c.userID, action, msgID)
	}
}

type connState struct {
	srv            *Server
	conn           net.Conn
	reader         *bufio.Reader
	secure         bool
	authed         bool
	userID         int64
	release        func()
	sessionRelease func()
	selected       string // folder name
	mailboxID      int64  // set during SELECT (legacy, for backward compat)
	tagID          int64  // tag ID for tag-aware SELECT/STATUS/FETCH
	readOnly       bool
	// Pinned at SELECT. A runtime flag flip affects only later selections, so
	// every command in one selected session uses one UID authority.
	useMembershipUID bool
}

// canonicalMailboxLookupName implements RFC 9051's one case-insensitive
// mailbox-name exception. User-created mailbox names remain case-sensitive;
// only every spelling of the reserved INBOX name maps to Setjoin's fixed
// system tag name.
func canonicalMailboxLookupName(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "Inbox"
	}
	return name
}

// imapUIDColumn returns one of two compile-time SQL identifiers. It never
// accepts request text; the selected-session flag is the only input.
func imapUIDColumn(useMembership bool) string {
	if useMembership {
		return "mt.imap_uid"
	}
	return "m.imap_uid"
}

func formatUIDSet(uids []int64) string {
	parts := make([]string, 0, len(uids))
	for _, uid := range uids {
		parts = append(parts, strconv.FormatInt(uid, 10))
	}
	return strings.Join(parts, ",")
}

func (c *connState) capabilities() string {
	capabilities := "IMAP4rev2 LOGIN-REFERRALS ID ENABLE"
	if !c.secure && c.srv.tlsCert != "" {
		capabilities += " STARTTLS"
	}
	if !c.secure && c.srv.requireTLS {
		capabilities += " LOGINDISABLED"
	}
	return capabilities
}

func (c *connState) rejectPlaintextAuth(tag string) bool {
	if c.srv.requireTLS && !c.secure {
		c.reply(tag, "NO [PRIVACYREQUIRED] Must issue STARTTLS first")
		return true
	}
	return false
}

func (c *connState) reply(tag, msg string) {
	fmt.Fprintf(c.conn, "%s %s\r\n", tag, msg)
}

func (c *connState) trackProtocolSession(userID int64, authenticatedAt time.Time) {
	if c.sessionRelease != nil {
		c.sessionRelease()
		c.sessionRelease = nil
	}
	if c.srv.sessionRegistry != nil {
		c.sessionRelease = c.srv.sessionRegistry.Register(
			userID, authenticatedAt, c.conn,
		)
	}
}

// releaseUserSlot releases the per-user connection-tracker slot this connection
// holds, if any. Auth flows MUST run this before installing a new c.release
// (release-then-acquire): overwriting the callback without running it orphans
// the original user's slot, which then stays consumed beyond disconnect because
// only the final c.release runs when the connection exits (handleConn).
func (c *connState) releaseUserSlot() {
	if c.release != nil {
		c.release()
		c.release = nil
	}
}

// resetSelectedMailboxState clears the selected-mailbox data-plane handle.
// Every identity transition runs this BEFORE the new identity is installed, so
// FETCH/STORE/EXPUNGE can never keep operating on the previous identity's
// mailbox: c.tagID/c.mailboxID are resolved by SELECT under one c.userID and
// must never outlive it.
func (c *connState) resetSelectedMailboxState() {
	c.selected = ""
	c.mailboxID = 0
	c.tagID = 0
	c.readOnly = false
	c.useMembershipUID = false
}

// withScope is the native-RLS per-command tx wrapper (W5 / plan
// 2026-06-18-native-rls-backstop.md, fork 3 resolved: PER-OP wrap, NOT a
// pinned connection). It runs fn inside an explicit transaction that first sets
// the transaction-scoped GUC app.current_mailbox_id to the session's selected
// mailbox (c.mailboxID), so the eventual messages/message_tags RLS policies
// (W6 FORCE flip) see the right tenant. Shape mirrors reducercall.PoolCaller's
// CallScoped, used from internal/jmap/handler.go:
//
//	BEGIN
//	  SELECT set_config('app.current_mailbox_id', c.mailboxID::text, true)  -- is_local=TRUE
//	  fn(tx)   -- ALL of this command's messages/message_tags statements
//	COMMIT     (ROLLBACK on any error)
//
// Because the set is transaction-scoped (true), the GUC auto-clears at COMMIT/
// ROLLBACK — there is NO session-pinned connection, NO AfterRelease reset, and
// NO separate IMAP pool. (The separate-pool isolation optimization the W5 plan
// mentions is an isolation-only nicety and is DEFERRED; it is not required for
// correctness because per-op tx-scoped GUC never leaks to the next pooled
// request, the DATABASE_SECURITY.md:149 trap that session scope would hit.)
//
// INERT until W6: RLS is not enabled in production, so the GUC is set but
// unused — the wrapped commands behave byte-identically today; the wrapper only
// guarantees the GUC is in place so the W6 flip does not silently break IMAP.
//
// CRITICAL for streaming commands (FETCH/SEARCH/STORE/EXPUNGE): fn MUST fully
// consume and Close() its pgx.Rows BEFORE returning — never hold an open Rows
// across Commit (pgx errors/deadlocks). Read rows into an in-memory slice inside
// fn, close them, then format/stream to the client after withScope returns (or
// stream inside fn before returning).
//
// c.mailboxID is 0 until handleSelect resolves a folder. A messages-command
// issued before SELECT sets GUC=0, which under FORCE yields a clean empty result
// (correct: nothing selected). Every messages/message_tags handler already
// guards on c.selected != "" before doing DB work, so in practice mailboxID > 0
// whenever fn runs.
func (c *connState) withScope(ctx context.Context, fn func(tx pgx.Tx) error) error {
	// The Begin → set_config → fn → Commit dance is the shared dbscope seam
	// (WP6 follow-up after the WP4 integration handoff): same transaction
	// boundary, same transaction-local app.current_mailbox_id, rollback on
	// any error, fn's error returned verbatim. See shared/dbscope's package
	// doc — the last inline copy retired.
	return dbscope.RunScoped(ctx, c.srv.pool, c.mailboxID, fn)
}

// postAuthDenied maps the post-auth conditional-access result to a deny decision.
func postAuthDenied(reject bool) bool { return reject }

// imapDenied is the per-user IMAP kill switch: when user_imap_settings.imap_enabled
// is false (an admin lockdown can force this), LOGIN is denied independently of any
// CA policy row — a fast local deny consulted at LOGIN.
func imapDenied(imapEnabled bool) bool { return !imapEnabled }

// denyIfImapDisabled checks user_imap_settings.imap_enabled for userID.
// Fail-open only on pgx.ErrNoRows (no row = default enabled); fail-closed on
// real DB errors (pool exhaustion, cancellation, etc.) — deny and return true.
// Returns true and replies NO if access is denied; caller must return immediately.
func (c *connState) denyIfImapDisabled(ctx context.Context, tag string, userID int64) bool {
	var imapEnabled bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT COALESCE(imap_enabled, TRUE) FROM user_imap_settings WHERE user_id = $1`,
		userID).Scan(&imapEnabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false // ponytail: no row = default-enabled, intentional fail-open
		}
		c.authed = false
		c.userID = 0
		c.reply(tag, "NO internal error")
		return true
	}
	if imapDenied(imapEnabled) {
		c.authed = false
		c.userID = 0
		c.reply(tag, "NO IMAP access disabled for this account by policy")
		return true
	}
	return false
}

// denyIfMailboxLifecycleBlocked is the protocol admission seam for explicit
// mailbox suspension/detachment. It fails closed on missing state or database
// errors; the OFF-gated reducer preserves the legacy mailboxes.enabled rule.
func (c *connState) denyIfMailboxLifecycleBlocked(ctx context.Context, tag string, userID int64) bool {
	mailboxID, err := identity.ResolvePrimaryMailbox(ctx, c.srv.pool, userID)
	if err != nil {
		c.authed = false
		c.userID = 0
		c.reply(tag, "NO Mailbox access unavailable")
		return true
	}
	var allowed bool
	if err := c.srv.pool.QueryRow(ctx, `SELECT mailbox_lifecycle_access_allowed($1)`, mailboxID).Scan(&allowed); err != nil || !allowed {
		c.authed = false
		c.userID = 0
		c.reply(tag, "NO Mailbox access suspended")
		return true
	}
	return false
}

func (c *connState) handleLogin(ctx context.Context, tag, args string) {
	if c.authed {
		c.reply(tag, "NO Already authenticated")
		return
	}
	if c.rejectPlaintextAuth(tag) {
		return
	}

	parts := splitIMAPArgs(args)
	if len(parts) < 2 {
		c.reply(tag, "BAD Missing arguments")
		return
	}

	email := strings.Trim(parts[0], `"`)
	password := strings.Trim(parts[1], `"`)
	authenticatedAt := time.Now().UTC()

	clientIP := "unknown"
	if addr, ok := c.conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	var meta threat.ConnectionMeta
	if c.srv.threatInterceptor != nil {
		meta = threat.ConnectionMeta{
			SourceIP:  clientIP,
			Username:  email,
			Protocol:  threat.ProtocolIMAP,
			UserAgent: "", // not available for IMAP
		}
		result, _, delay := c.srv.threatInterceptor.Intercept(ctx, &meta)
		switch result {
		case threat.ActionReject:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Authentication temporarily unavailable")
			return
		case threat.ActionTarpitted:
			if delay > 0 {
				time.Sleep(delay)
			}
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Authentication temporarily unavailable")
			return
		case threat.ActionRateLimited:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "rate_limit", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Too many authentication attempts — try again later")
			return
		}
	}

	// Try app password first
	if user, err := pwhash.CheckAppPassword(ctx, c.srv.pool, email, password); err == nil {
		c.resetSelectedMailboxState() // identity change: drop the selected-mailbox handle first
		c.authed = true
		c.userID = user.ID
		if c.srv.threatInterceptor != nil {
			meta.AppPassword = true
			c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
			meta.UserID = user.ID
			meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
			meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
			if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); postAuthDenied(res == threat.ActionReject) {
				pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
					UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
					Email: email, IPAddress: clientIP,
				}, nil)
				c.authed = false
				c.userID = 0
				c.reply(tag, "NO ["+reason+"] Access blocked by policy")
				return
			}
		}
		c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
			"email":    email,
			"provider": "app_password",
			"ip":       clientIP,
		}))
		if c.denyIfImapDisabled(ctx, tag, user.ID) || c.denyIfMailboxLifecycleBlocked(ctx, tag, user.ID) {
			return
		}
		meta.DeviceBound = false // IMAP cannot present a device proof header
		// Release-then-acquire: hand back any tracker slot this connection still
		// holds BEFORE taking the new identity's slot. Overwriting c.release
		// without running it orphans the original user's slot beyond disconnect
		// (only the final c.release runs in handleConn).
		c.releaseUserSlot()
		// RFC 9051 §6.2.2 — send tagged OK with per-user connection check
		release, err := c.srv.userTracker.TryAcquire(user.ID)
		if err != nil {
			c.reply(tag, "NO Too many connections from this account")
			c.authed = false
			c.userID = 0
			return
		}
		c.release = release
		c.trackProtocolSession(user.ID, authenticatedAt)
		c.reply(tag, "OK [CAPABILITY "+c.capabilities()+"] LOGIN completed")
		return
	}

	user, err := auth.CheckPassword(ctx, c.srv.pool, email, password)
	if err != nil {
		if c.srv.threatInterceptor != nil {
			c.srv.threatInterceptor.RecordResult(ctx, &meta, false, 0)
		}
		pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "bcrypt", Email: email,
			IPAddress: c.conn.RemoteAddr().String(),
		}, nil)
		c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLoginFailed, map[string]interface{}{
			"email":    email,
			"provider": "bcrypt",
			"ip":       clientIP,
		}))
		c.reply(tag, "NO Authentication failed")
		return
	}
	pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "bcrypt", Email: email,
		IPAddress: c.conn.RemoteAddr().String(),
	}, nil)
	c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
		"email":    email,
		"provider": "bcrypt",
		"ip":       clientIP,
	}))

	c.resetSelectedMailboxState() // identity change: drop the selected-mailbox handle first
	c.authed = true
	c.userID = user.ID
	if c.srv.threatInterceptor != nil {
		c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
		meta.UserID = user.ID
		meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
		meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
		if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); postAuthDenied(res == threat.ActionReject) {
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
				Email: email, IPAddress: clientIP,
			}, nil)
			c.authed = false
			c.userID = 0
			c.reply(tag, "NO ["+reason+"] Access blocked by policy")
			return
		}
	}

	if c.denyIfImapDisabled(ctx, tag, user.ID) || c.denyIfMailboxLifecycleBlocked(ctx, tag, user.ID) {
		return
	}
	meta.DeviceBound = false // IMAP cannot present a device proof header

	// Check per-user connection limit. Release-then-acquire: hand back any
	// tracker slot this connection still holds BEFORE taking the new identity's
	// slot (an overwrite without release orphans the original user's slot
	// beyond disconnect).
	c.releaseUserSlot()
	release, err := c.srv.userTracker.TryAcquire(user.ID)
	if err != nil {
		c.reply(tag, "NO Too many connections from this account")
		c.authed = false
		c.userID = 0
		return
	}
	c.release = release
	c.trackProtocolSession(user.ID, authenticatedAt)
	c.reply(tag, "OK [CAPABILITY "+c.capabilities()+"] LOGIN completed")
}

func (c *connState) handleSelect(ctx context.Context, tag, cmd, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}

	if c.selected != "" {
		c.reply("*", "OK [CLOSED] Previous mailbox closed")
	}

	// RFC 9051 §6.3.2: a failed SELECT/EXAMINE leaves no mailbox selected.
	// Reset the whole handle BEFORE the lookup so a failed re-select can never
	// keep the previous selection's c.tagID/c.mailboxID serving data-plane
	// commands (FETCH/STORE/EXPUNGE guard only on c.selected being non-empty
	// and then query by c.tagID with GUC=c.mailboxID).
	c.resetSelectedMailboxState()
	folder := canonicalMailboxLookupName(strings.Trim(args, `"`))
	c.selected = folder
	c.readOnly = (cmd == "EXAMINE")

	// Look up tag by name (using imap_name fallback for remapped names)
	var tagID, total, unseen int64
	var mbID, uidValidity, nextUID int64
	var useMembershipUID bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT t.id, t.mailbox_id, COALESCE(t.total_count, 0), COALESCE(t.unread_count, 0),
		        COALESCE(t.imap_uid_validity, 0), COALESCE(t.imap_uid_next, 1),
		        COALESCE((SELECT enabled FROM feature_toggles
		                  WHERE key='feature.imap_membership_uid'),FALSE)
		        AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE)
		 FROM tags t
		 JOIN mailboxes m ON m.id = t.mailbox_id
		 WHERE m.user_id = $1
		   AND (t.name = $2 OR t.imap_name = $2)
		   AND t.imap_expose = TRUE
		 LIMIT 1`,
		c.userID, folder,
	).Scan(&tagID, &mbID, &total, &unseen, &uidValidity, &nextUID, &useMembershipUID)
	if err != nil {
		c.selected = "" // failed select leaves no mailbox selected (RFC 9051 §6.3.2)
		c.reply(tag, "NO No such mailbox")
		return
	}

	c.mailboxID = mbID
	c.tagID = tagID
	c.useMembershipUID = useMembershipUID
	if uidValidity == 0 {
		//nolint:gosec // G404: non-security jitter for IMAP UID-validity seed, not a secret
		uidValidity = time.Now().UnixMicro() + int64(rand.Intn(1000000))
	}
	if nextUID < 1 {
		// native-RLS (W5): this fallback reads messages + message_tags, so wrap
		// it with app.current_mailbox_id = c.mailboxID (just set above to mbID).
		// The tag-resolution query above touches only tags/mailboxes (W6-safe),
		// so only this messages-touching read needs the scope.
		var maxUID int64
		_ = c.withScope(ctx, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx,
				`SELECT COALESCE(MAX(`+imapUIDColumn(c.useMembershipUID)+`), 0) + 1 FROM messages m
				 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
				 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE`,
				tagID,
			).Scan(&maxUID)
		})
		if maxUID > 0 {
			nextUID = maxUID
		}
	}
	c.tagID = tagID

	c.reply("*", "FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen)")
	c.reply(fmt.Sprintf("* %d EXISTS", total), "")
	c.reply(fmt.Sprintf("* OK [UIDVALIDITY %d] UIDs valid", uidValidity), "")
	c.reply(fmt.Sprintf("* OK [UIDNEXT %d] Predicted next UID", nextUID), "")
	c.reply("*", "OK [PERMANENTFLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen)] Flags permitted")

	if c.readOnly {
		c.reply(tag, "OK [READ-ONLY] EXAMINE completed")
	} else {
		c.reply(tag, "OK [READ-WRITE] SELECT completed")
	}
}

func (c *connState) handleList(ctx context.Context, tag string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}

	// Read user IMAP settings
	var exposeAll, subOnly bool
	var exposedIDs []int64
	var separator string
	_ = c.srv.pool.QueryRow(ctx,
		`SELECT COALESCE(expose_all, FALSE), COALESCE(show_subscribed_only, TRUE),
		        COALESCE(exposed_tag_ids, '{}'), COALESCE(folder_separator, '/')
		 FROM user_imap_settings WHERE user_id = $1`,
		c.userID,
	).Scan(&exposeAll, &subOnly, &exposedIDs, &separator)
	if separator == "" {
		separator = "/"
	}

	// Query tags visible over IMAP
	rows, err := c.srv.pool.Query(ctx,
		`SELECT t.id, COALESCE(t.imap_name, t.name) AS name, t.parent_id,
		        COALESCE(t.total_count, 0), COALESCE(t.unread_count, 0),
		        COALESCE((SELECT COUNT(*) FROM tags child WHERE child.parent_id = t.id AND child.imap_expose = TRUE), 0) AS child_count,
		        t.tag_type
		 FROM tags t
		 JOIN mailboxes m ON m.id = t.mailbox_id
		 WHERE m.user_id = $1 AND t.imap_expose = TRUE
		 ORDER BY t.sort_order, t.name`,
		c.userID,
	)
	if err != nil {
		c.reply(tag, "NO Server error")
		return
	}
	defer rows.Close()

	// Build parent path map for hierarchical LIST
	parentMap := map[int64]string{}

	for rows.Next() {
		var id, parentID, total, unread, childCount int64
		var name, tagType string
		rows.Scan(&id, &name, &parentID, &total, &unread, &childCount, &tagType)

		// Apply user_imap_settings filters
		if subOnly && !exposeAll {
			found := false
			for _, eid := range exposedIDs {
				if eid == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Build full path from parent_id chain
		fullPath := buildTagPath(id, parentID, name, parentMap, separator)
		parentMap[id] = fullPath

		// Determine flags
		flags := `\HasNoChildren`
		if childCount > 0 {
			flags = `\HasChildren`
		}

		// Add special-use flags
		if tagType == "system" {
			switch strings.ToLower(name) {
			case "inbox":
				flags += ` \Inbox`
			case "sent":
				flags += ` \Sent`
			case "drafts":
				flags += ` \Drafts`
			case "trash":
				flags += ` \Trash`
			case "spam", "junk":
				flags += ` \Junk`
			}
		}

		c.reply(fmt.Sprintf(`* LIST (%s) "%s" "%s"`, flags, separator, fullPath), "")
	}
	if err := rows.Err(); err != nil {
		c.reply(tag, "NO Server error")
		return
	}
	c.reply(tag, "OK LIST completed")
}

// buildTagPath constructs the full hierarchical path for a tag by walking parent_id chain.
func buildTagPath(tagID, parentID int64, name string, parentMap map[int64]string, sep string) string {
	if parentID == 0 {
		return name
	}
	if parentPath, ok := parentMap[parentID]; ok {
		return parentPath + sep + name
	}
	return name
}

func (c *connState) handleStatus(ctx context.Context, tag, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}

	parts := strings.SplitN(args, " ", 2)
	if len(parts) < 1 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	folder := canonicalMailboxLookupName(strings.Trim(parts[0], `"`))

	var total, unread int64
	var uidValidity, nextUID int64
	err := c.srv.pool.QueryRow(ctx,
		`SELECT COALESCE(t.total_count, 0), COALESCE(t.unread_count, 0),
		        COALESCE(t.imap_uid_validity, 0), COALESCE(t.imap_uid_next, 1)
		 FROM tags t
		 JOIN mailboxes m ON m.id = t.mailbox_id
		 WHERE m.user_id = $1
		   AND (t.name = $2 OR t.imap_name = $2)
		   AND t.imap_expose = TRUE
		 LIMIT 1`,
		c.userID, folder,
	).Scan(&total, &unread, &uidValidity, &nextUID)
	if err != nil {
		c.reply(tag, "NO No such mailbox")
		return
	}
	if uidValidity == 0 {
		uidValidity = 1
	}
	if nextUID < 1 {
		nextUID = 1
	}

	c.reply(fmt.Sprintf(`* STATUS "%s" (MESSAGES %d UNSEEN %d UIDVALIDITY %d UIDNEXT %d)`, folder, total, unread, uidValidity, nextUID), "")
	c.reply(tag, "OK STATUS completed")
}

// handleFetch implements FETCH and UID FETCH. When isUID is true the
// sequence-set in args is resolved against imap_uid values (not positional
// offsets) — mirroring the BUG-2 fix in handleStore.
func (c *connState) handleFetch(ctx context.Context, tag, args string, isUID bool) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}

	// Parse the sequence-set from the first token.  parseSeqSet strips any
	// trailing parenthesised data-item list so "1:5 (FLAGS UID)" works.
	// ponytail: loads all mailbox rows for UID-resolution correctness; a
	// paginated path can be added if large-mailbox latency matters.
	seqStr := strings.Fields(args)
	if len(seqStr) == 0 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	ranges := parseSeqSet(seqStr[0])
	if len(ranges) == 0 {
		c.reply(tag, "BAD Invalid sequence number")
		return
	}

	// fetchMsg is the in-memory view of one FETCH row. native-RLS (W5): the
	// messages+message_tags read runs inside withScope (GUC = c.mailboxID); the
	// rows MUST be fully drained + closed INSIDE the tx (never held across
	// Commit), so we read into this slice, then format/stream to the client
	// after withScope returns.
	// SP1 P5 (C3): body serving (BODY[]/RFC822) is not yet implemented —
	// raw_ref is excluded from this SELECT until the blob-streaming path is
	// wired in. The imap package must never call the smime decrypt primitives
	// (locked by TestIMAP_NoDecryptImported).
	type fetchMsg struct {
		ID         int64
		IMAPUID    int64
		Subject    string
		From       string
		To         []string
		Cc         []string
		IsRead     bool
		IsFlagged  bool
		IsAnswered bool
		IsDraft    bool
		IsDeleted  bool
		SizeBytes  int64
		ReceivedAt interface{}
		seq        int64 // 1-based position in UID-ordered list, set in Go
	}
	var msgs []fetchMsg
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT m.id, `+imapUIDColumn(c.useMembershipUID)+`, m.subject, m.from_addr, m.to_addrs, m.cc_addrs,
			        m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted,
			        m.size_bytes, m.received_at
			 FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE
			 ORDER BY `+imapUIDColumn(c.useMembershipUID),
			c.tagID,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		seqN := int64(0)
		for rows.Next() {
			var msg fetchMsg
			if err := rows.Scan(
				&msg.ID, &msg.IMAPUID, &msg.Subject, &msg.From, &msg.To, &msg.Cc,
				&msg.IsRead, &msg.IsFlagged, &msg.IsAnswered, &msg.IsDraft, &msg.IsDeleted,
				&msg.SizeBytes, &msg.ReceivedAt,
			); err != nil {
				continue
			}
			seqN++
			msg.seq = seqN
			msgs = append(msgs, msg)
		}
		return rows.Err()
	})
	if scopeErr != nil {
		c.reply(tag, "NO Server error")
		return
	}

	// Resolve the sequence-set honoring UID vs. positional mode.  Build a
	// storeMsg view (id/imapUID/seq only — resolveSeqSet needs nothing more)
	// from the full fetchMsg slice, resolve, then look up the full data.
	allStore := make([]storeMsg, len(msgs))
	for i, m := range msgs {
		allStore[i] = storeMsg{id: m.ID, imapUID: m.IMAPUID, seq: m.seq}
	}
	targets := resolveSeqSet(ranges, allStore, isUID)

	byID := make(map[int64]*fetchMsg, len(msgs))
	for i := range msgs {
		byID[msgs[i].ID] = &msgs[i]
	}

	for _, sm := range targets {
		msg := byID[sm.id]
		if msg == nil {
			continue
		}
		flags := []string{}
		if msg.IsRead {
			flags = append(flags, `\Seen`)
		}
		if msg.IsFlagged {
			flags = append(flags, `\Flagged`)
		}
		if msg.IsAnswered {
			flags = append(flags, `\Answered`)
		}
		if msg.IsDraft {
			flags = append(flags, `\Draft`)
		}
		if msg.IsDeleted {
			flags = append(flags, `\Deleted`)
		}

		dateStr := "NIL"
		if t, ok := msg.ReceivedAt.(time.Time); ok && !t.IsZero() {
			dateStr = quoteIMAP(t.Format("Mon, 02 Jan 2006 15:04:05 -0700"))
		}
		fromTuple := parseAddrTuple(msg.From)
		toTuples := formatAddrTuples(msg.To)
		if toTuples == "NIL" {
			toTuples = "((NIL NIL \"\" \"\"))"
		}
		ccTuples := formatAddrTuples(msg.Cc)
		// RFC 9051 §7.5.5: the outer FETCH tuple must be properly closed.
		c.reply(fmt.Sprintf("* %d FETCH (UID %d FLAGS (%s) RFC822.SIZE %d ENVELOPE (%s %s %s %s %s %s %s NIL NIL NIL))",
			sm.seq, msg.IMAPUID, strings.Join(flags, " "), msg.SizeBytes,
			dateStr,                // date
			quoteIMAP(msg.Subject), // subject
			fromTuple,              // from
			fromTuple,              // sender
			fromTuple,              // reply-to
			toTuples,               // to
			ccTuples,               // cc
		), "")
	}
	c.reply(tag, "OK FETCH completed")
	c.auditLog(ctx, "imap_fetch", nil)
}

func (c *connState) handleSearch(ctx context.Context, tag string, isUID bool, args string) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// BUG-1 fix: match the selected mailbox via the tag-aware message_tags model
	// (c.tagID, resolved in handleSelect), NOT the legacy `folders` table — the
	// old `JOIN folders f ON f.id = m.folder_id` joined a TAG id against the
	// wrong table. buildSearchClause now numbers its placeholders from $2 (only
	// $1=tagID is consumed by the message_tags WHERE). Ordered by imap_uid so the
	// derived sequence numbers match SELECT/FETCH.
	where, whereArgs := buildSearchClause(args)
	allArgs := []any{c.tagID}
	allArgs = append(allArgs, whereArgs...)

	// native-RLS (W5): the messages+message_tags read runs inside withScope
	// (GUC = c.mailboxID). Drain + close the rows INSIDE the tx (collect the
	// matched UIDs into a slice), then build the response after withScope returns.
	var uids []int64
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+imapUIDColumn(c.useMembershipUID)+` FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND NOT m.is_deleted`+where+` ORDER BY `+imapUIDColumn(c.useMembershipUID),
			allArgs...,
		)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var uid int64
			if err := rows.Scan(&uid); err != nil {
				continue
			}
			uids = append(uids, uid)
		}
		return rows.Err()
	})
	if scopeErr != nil {
		c.reply(tag, "NO Server error")
		return
	}

	var nums []string
	seqNum := 0
	for _, uid := range uids {
		seqNum++
		if isUID {
			nums = append(nums, fmt.Sprintf("%d", uid))
		} else {
			nums = append(nums, fmt.Sprintf("%d", seqNum))
		}
	}
	// RFC 9051 §6.4.4: correlate to the actual command tag and encode results
	// under the required ALL return item as one sequence-set. The prior fixed
	// "searchUids" tag and bare space-delimited numbers were not valid ESEARCH.
	response := fmt.Sprintf(`ESEARCH (TAG %q)`, tag)
	if isUID {
		response += " UID"
	}
	if len(nums) > 0 {
		response += " ALL " + strings.Join(nums, ",")
	}
	c.reply("*", response)
	c.reply(tag, "OK SEARCH completed")
}

// buildSearchClause builds a SQL WHERE clause (+ args) from IMAP search keys.
// Placeholders start at $2; the caller consumes $1 (the selected tag id).
func buildSearchClause(args string) (string, []any) {
	if args == "" {
		return "", nil
	}
	keys := splitIMAPArgs(args)
	var clauses []string
	var params []any
	argN := 2 // $1 is the tag id used by the caller

	for i := 0; i < len(keys); i++ {
		k := strings.ToUpper(keys[i])
		switch k {
		case "ALL":
			// no filter
		case "SEEN":
			clauses = append(clauses, fmt.Sprintf("m.is_read = TRUE"))
		case "UNSEEN":
			clauses = append(clauses, fmt.Sprintf("m.is_read = FALSE"))
		case "DELETED":
			clauses = append(clauses, fmt.Sprintf("m.is_deleted = TRUE"))
		case "UNDELETED":
			clauses = append(clauses, fmt.Sprintf("m.is_deleted = FALSE"))
		case "ANSWERED":
			clauses = append(clauses, fmt.Sprintf("m.is_answered = TRUE"))
		case "UNANSWERED":
			clauses = append(clauses, fmt.Sprintf("m.is_answered = FALSE"))
		case "FLAGGED":
			clauses = append(clauses, fmt.Sprintf("m.is_flagged = TRUE"))
		case "UNFLAGGED":
			clauses = append(clauses, fmt.Sprintf("m.is_flagged = FALSE"))
		case "DRAFT":
			clauses = append(clauses, fmt.Sprintf("m.is_draft = TRUE"))
		case "UNDRAFT":
			clauses = append(clauses, fmt.Sprintf("m.is_draft = FALSE"))
		case "FROM":
			if i+1 < len(keys) {
				clauses = append(clauses, fmt.Sprintf("m.from_addr ILIKE $%d", argN))
				val := strings.Trim(keys[i+1], "\"")
				params = append(params, "%"+val+"%")
				argN++
				i++
			}
		case "SUBJECT":
			if i+1 < len(keys) {
				clauses = append(clauses, fmt.Sprintf("m.subject ILIKE $%d", argN))
				val := strings.Trim(keys[i+1], "\"")
				params = append(params, "%"+val+"%")
				argN++
				i++
			}
		case "TEXT", "BODY":
			if i+1 < len(keys) {
				clauses = append(clauses, fmt.Sprintf("(m.subject ILIKE $%d OR m.body_text ILIKE $%d)", argN, argN))
				val := strings.Trim(keys[i+1], "\"")
				params = append(params, "%"+val+"%")
				argN++
				i++
			}
		case "HEADER":
			if i+2 < len(keys) {
				field := strings.ToUpper(strings.Trim(keys[i+1], `"`))
				value := strings.Trim(keys[i+2], `"`)
				switch field {
				case "MESSAGE-ID":
					clauses = append(clauses, fmt.Sprintf("m.message_id = $%d", argN))
					params = append(params, value)
					argN++
				default:
					// An unsupported header cannot safely mean ALL.
					clauses = append(clauses, "FALSE")
				}
				i += 2
			}
		case "KEYWORD":
			if i+1 < len(keys) {
				clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM message_tags mt JOIN tags t ON t.id = mt.tag_id WHERE mt.message_id = m.id AND t.name = $%d)", argN))
				params = append(params, keys[i+1])
				argN++
				i++
			}
		case "NEW":
			clauses = append(clauses, "m.is_read = FALSE")
			// NEW = RECENT + UNSEEN. We don't track RECENT, so match UNSEEN.
		case "RECENT":
			// Not tracked; match nothing
			clauses = append(clauses, "FALSE")
		}
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(clauses, " AND "), params
}

// storeMsg is the ordered, tag-aware view of one message in the selected
// mailbox: its DB id, its IMAP UID, its 1-based sequence number (position in the
// UID-ordered list), and its current flag state. resolveSeqSet matches against
// it; the flag state is the basis for the untagged FETCH FLAGS response.
type storeMsg struct {
	id, imapUID, seq                                  int64
	isRead, isFlagged, isAnswered, isDraft, isDeleted bool
	// recv is messages.received_at — needed by MOVE/COPY (message_tags is
	// partitioned by received_at and keyed on it) but not by FETCH/STORE, which
	// leave it zero-valued.
	recv time.Time
}

// storeFlagDelta is the parsed protocol intent of a STORE command, independent
// of any particular message. `replace` is the RFC 9051 §6.4.6 `FLAGS (...)`
// form: it sets the whole flag set, clearing the UNMENTIONED flags — distinct
// from `+FLAGS`/`-FLAGS` which only touch the mentioned flags.
type storeFlagDelta struct {
	add, remove, replace bool
	// which IMAP flags were mentioned in the command (\Seen → seen, etc.)
	seen, flagged, answered, draft, deleted bool
}

// parseStoreFlags parses `<+FLAGS|-FLAGS|FLAGS>[.SILENT] (<flag-list>)` into a
// storeFlagDelta. The `.SILENT` suffix (suppress the untagged FETCH responses)
// is recognised and recorded by the caller via the returned silent bool.
func parseStoreFlags(op, flagStr string) (storeFlagDelta, bool) {
	op = strings.ToUpper(op)
	silent := strings.HasSuffix(op, ".SILENT")
	op = strings.TrimSuffix(op, ".SILENT")

	var d storeFlagDelta
	switch op {
	case "+FLAGS":
		d.add = true
	case "-FLAGS":
		d.remove = true
	case "FLAGS":
		d.replace = true
	}

	flagStr = strings.Trim(flagStr, "()")
	for _, f := range strings.Fields(flagStr) {
		switch strings.ToUpper(f) {
		case "\\SEEN":
			d.seen = true
		case "\\FLAGGED":
			d.flagged = true
		case "\\ANSWERED":
			d.answered = true
		case "\\DRAFT":
			d.draft = true
		case "\\DELETED":
			d.deleted = true
		}
	}
	return d, silent
}

// seqRange is a single component of an IMAP sequence-set: lo..hi inclusive.
// hi == seqStar means "*" (the highest message). For a bare number lo == hi.
type seqRange struct{ lo, hi int64 }

const seqStar = int64(-1)

// parseSeqSet parses a full IMAP sequence-set ("1", "2:4", "1,3,5", "2:*",
// "*:4") into its component ranges, honoring commas, ranges, and "*". It does
// NOT collapse to start+count (unlike parseSeqRange), so gaps and enumerations
// survive. Invalid tokens are skipped. A "*" endpoint becomes seqStar; the
// caller resolves it against the live message list.
func parseSeqSet(seqStr string) []seqRange {
	// Strip any trailing parenthesised arg the caller may have left attached.
	if idx := strings.Index(seqStr, "("); idx >= 0 {
		seqStr = strings.TrimSpace(seqStr[:idx])
	}
	var out []seqRange
	for _, part := range strings.Split(seqStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		atoms := strings.SplitN(part, ":", 2)
		parseAtom := func(s string) (int64, bool) {
			s = strings.TrimSpace(s)
			if s == "*" {
				return seqStar, true
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n < 1 {
				return 0, false
			}
			return n, true
		}
		if len(atoms) == 1 {
			if n, ok := parseAtom(atoms[0]); ok {
				out = append(out, seqRange{lo: n, hi: n})
			}
			continue
		}
		lo, okLo := parseAtom(atoms[0])
		hi, okHi := parseAtom(atoms[1])
		if okLo && okHi {
			out = append(out, seqRange{lo: lo, hi: hi})
		}
	}
	return out
}

// resolveSeqSet maps an IMAP sequence-set onto concrete messages. `msgs` MUST be
// ordered by IMAP UID ascending (so index i has sequence number i+1, already
// filled into msg.seq). When isUID is true the set is matched against imap_uid;
// otherwise against the 1-based sequence number. "*" (seqStar) resolves to the
// highest sequence number / highest UID present. A range is normalised so lo<=hi
// (RFC 9051 §9: "n:m" and "m:n" are equivalent). De-duplicates and preserves
// ascending order so the FETCH responses come out in sequence order.
func resolveSeqSet(ranges []seqRange, msgs []storeMsg, isUID bool) []storeMsg {
	if len(msgs) == 0 {
		return nil
	}
	maxSeq := int64(len(msgs))
	maxUID := msgs[len(msgs)-1].imapUID // last is highest (UID-ordered)

	star := maxSeq
	if isUID {
		star = maxUID
	}
	resolve := func(v int64) int64 {
		if v == seqStar {
			return star
		}
		return v
	}

	seen := make(map[int64]bool, len(msgs))
	var out []storeMsg
	for _, m := range msgs {
		key := m.seq
		if isUID {
			key = m.imapUID
		}
		for _, r := range ranges {
			lo, hi := resolve(r.lo), resolve(r.hi)
			if lo > hi {
				lo, hi = hi, lo
			}
			if key >= lo && key <= hi {
				if !seen[m.id] {
					seen[m.id] = true
					out = append(out, m)
				}
				break
			}
		}
	}
	return out
}

// applyStoreDelta computes the post-STORE flag state of one message from its
// current state + the parsed delta. For +FLAGS only the mentioned flags are
// set true; for -FLAGS only the mentioned flags are set false; for FLAGS
// (replace) the WHOLE set is rewritten — mentioned flags true, unmentioned
// flags false (RFC 9051 §6.4.6).
func applyStoreDelta(m storeMsg, d storeFlagDelta) storeMsg {
	set := func(cur, mentioned bool) bool {
		switch {
		case d.replace:
			return mentioned // mentioned→true, unmentioned→false
		case d.add:
			if mentioned {
				return true
			}
			return cur
		case d.remove:
			if mentioned {
				return false
			}
			return cur
		}
		return cur
	}
	m.isRead = set(m.isRead, d.seen)
	m.isFlagged = set(m.isFlagged, d.flagged)
	m.isAnswered = set(m.isAnswered, d.answered)
	m.isDraft = set(m.isDraft, d.draft)
	m.isDeleted = set(m.isDeleted, d.deleted)
	return m
}

func (c *connState) handleStore(ctx context.Context, tag string, isUID bool, args string) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// RFC 9051 §6.3.2 — EXAMINE opens mailbox read-only
	if c.readOnly {
		c.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only")
		return
	}

	// Parse: <sequence-set> <+FLAGS|-FLAGS|FLAGS>[.SILENT] (<flag-list>)
	parts := strings.Fields(args)
	if len(parts) < 3 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	ranges := parseSeqSet(parts[0])
	if len(ranges) == 0 {
		c.reply(tag, "BAD Invalid sequence number")
		return
	}
	delta, silent := parseStoreFlags(parts[1], strings.Join(parts[2:], " "))

	// native-RLS (W5): the ordered-view read (messages+message_tags) AND the
	// flag writes (jmap_email_set_update + the \Deleted UPDATEs on messages) all
	// run inside ONE per-command tx with app.current_mailbox_id = c.mailboxID, so
	// they survive the W6 FORCE flip. The read feeds the Go-side seq math which
	// feeds the writes, so the whole unit is one scoped tx. The streaming read
	// rows are drained + closed INSIDE the tx before any write (never held across
	// Commit). `post` is captured for the post-tx client FETCH-FLAGS stream.
	var post []storeMsg
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		// Load the ordered, TAG-AWARE view of the selected mailbox — the same
		// message_tags/tagID model FETCH uses. Sequence numbers are derived in Go
		// (UID-ascending position) — the reducer must not do seq-set math, it
		// needs this live ordered view.
		rows, err := tx.Query(ctx,
			`SELECT m.id, `+imapUIDColumn(c.useMembershipUID)+`, m.is_read, m.is_flagged, m.is_answered, m.is_draft, m.is_deleted
			 FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE
			 ORDER BY `+imapUIDColumn(c.useMembershipUID),
			c.tagID,
		)
		if err != nil {
			return err
		}
		var msgs []storeMsg
		seqNum := int64(0)
		for rows.Next() {
			seqNum++
			var m storeMsg
			if err := rows.Scan(&m.id, &m.imapUID, &m.isRead, &m.isFlagged, &m.isAnswered, &m.isDraft, &m.isDeleted); err != nil {
				continue
			}
			m.seq = seqNum
			msgs = append(msgs, m)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// BUG-2 fix: resolve the set to message ids honoring UID-vs-sequence,
		// ranges, gaps and "*". The old handler treated a UID STORE's set as a
		// positional sequence offset (parseSeqRange → LIMIT/OFFSET).
		targets := resolveSeqSet(ranges, msgs, isUID)
		if len(targets) == 0 {
			return nil
		}

		// Build the jmap_email_set_update keyword patch (the reducer does the
		// atomic write + unread-count adjust across all tags + notify_state_change).
		// \Seen/\Flagged/\Answered/\Draft map to the keyword columns; \Deleted is
		// the IMAP expunge-mark flag (messages.is_deleted), which the keyword path
		// does NOT own — applied separately below, scoped to the session mailbox.
		patch := map[string]any{}
		var deletedTrueIDs, deletedFalseIDs []int64
		post = make([]storeMsg, len(targets))
		for i, m := range targets {
			np := applyStoreDelta(m, delta)
			post[i] = np

			// keyword sub-patch: only include a key when the resulting boolean
			// differs from current (relative ops) or when replacing (always emit
			// so an unmentioned-true flag is cleared).
			kw := map[string]any{}
			if delta.replace || np.isRead != m.isRead {
				kw["$seen"] = np.isRead
			}
			if delta.replace || np.isFlagged != m.isFlagged {
				kw["$flagged"] = np.isFlagged
			}
			if delta.replace || np.isAnswered != m.isAnswered {
				kw["$answered"] = np.isAnswered
			}
			if delta.replace || np.isDraft != m.isDraft {
				kw["$draft"] = np.isDraft
			}
			if len(kw) > 0 {
				patch[strconv.FormatInt(m.id, 10)] = map[string]any{"keywords": kw}
			}

			if np.isDeleted != m.isDeleted {
				if np.isDeleted {
					deletedTrueIDs = append(deletedTrueIDs, m.id)
				} else {
					deletedFalseIDs = append(deletedFalseIDs, m.id)
				}
			}
		}

		if len(patch) > 0 {
			patchJSON, mErr := json.Marshal(patch)
			if mErr != nil {
				return mErr
			}
			if _, err := tx.Exec(ctx,
				`SELECT jmap_email_set_update($1, $2::jsonb)`,
				c.mailboxID, string(patchJSON),
			); err != nil {
				return err
			}
		}

		// Apply the \Deleted IMAP flag (expunge-mark). Scoped to the session
		// mailbox (DATABASE_SECURITY R3): the ids were resolved from a
		// tag_id-scoped SELECT above, and the WHERE re-asserts mailbox_id so a
		// future refactor can't write a foreign mailbox.
		if len(deletedTrueIDs) > 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE messages SET is_deleted = TRUE WHERE id = ANY($1) AND mailbox_id = $2`,
				deletedTrueIDs, c.mailboxID,
			); err != nil {
				return err
			}
			// arch A8: is_deleted hides the message from JMAP (Email/query & get all
			// filter NOT is_deleted), so setting \Deleted removes it from the client's
			// view — push a 'destroyed' delta per id (the raw UPDATE fired no trigger
			// and no notify, so a JMAP/second-IMAP client never saw it vanish).
			for _, id := range deletedTrueIDs {
				if _, err := tx.Exec(ctx,
					`SELECT notify_state_change($1, NULL::BIGINT, $2, 'destroyed')`,
					c.mailboxID, id); err != nil {
					return err
				}
			}
		}
		if len(deletedFalseIDs) > 0 {
			if _, err := tx.Exec(ctx,
				`UPDATE messages SET is_deleted = FALSE WHERE id = ANY($1) AND mailbox_id = $2`,
				deletedFalseIDs, c.mailboxID,
			); err != nil {
				return err
			}
			// Clearing \Deleted makes the message queryable again → it reappears in
			// the client's view: push a 'created' delta per id.
			for _, id := range deletedFalseIDs {
				if _, err := tx.Exec(ctx,
					`SELECT notify_state_change($1, NULL::BIGINT, $2, 'created')`,
					c.mailboxID, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if scopeErr != nil {
		c.reply(tag, "NO Store failed")
		return
	}
	if len(post) == 0 {
		// No matched targets — nothing written.
		c.reply(tag, "OK STORE completed")
		c.auditLog(ctx, "imap_store", nil)
		return
	}

	// Untagged FETCH FLAGS responses from the now-applied state (suppressed for
	// the .SILENT form, RFC 9051 §6.4.6).
	if !silent {
		for _, m := range post {
			fmt.Fprintf(c.conn, "* %d FETCH (UID %d FLAGS %s)\r\n", m.seq, m.imapUID, formatFlagList(m))
		}
	}
	c.reply(tag, "OK STORE completed")
	c.auditLog(ctx, "imap_store", nil)
}

// formatFlagList renders a message's flag set in IMAP FLAGS-list syntax, e.g.
// "(\Seen \Flagged)" or "()". Order matches the legacy STORE response.
func formatFlagList(m storeMsg) string {
	var flagList []string
	if m.isRead {
		flagList = append(flagList, `\Seen`)
	}
	if m.isFlagged {
		flagList = append(flagList, `\Flagged`)
	}
	if m.isAnswered {
		flagList = append(flagList, `\Answered`)
	}
	if m.isDraft {
		flagList = append(flagList, `\Draft`)
	}
	if m.isDeleted {
		flagList = append(flagList, `\Deleted`)
	}
	return "(" + strings.Join(flagList, " ") + ")"
}

func (c *connState) handleExpunge(ctx context.Context, tag string) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// RFC 9051 §6.3.2 — EXAMINE opens mailbox read-only
	if c.readOnly {
		c.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only")
		return
	}

	// native-RLS (W5): the ordered-view read (messages+message_tags) AND the
	// deletes (message_tags + messages) all run inside ONE per-command tx with
	// app.current_mailbox_id = c.mailboxID, so they survive the W6 FORCE flip.
	// The streaming read rows are drained + closed INSIDE the tx before any
	// write; the untagged EXPUNGE responses are streamed to the client from
	// inside fn (after the rows are closed, before the deletes).
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		// Load all messages in the selected mailbox (deleted and non-deleted)
		// ordered by imap_uid. Sequence numbers are derived in Go — eliminates
		// O(D) per-row COUNT queries. Match via the tag-aware message_tags model
		// (c.tagID). Ordered by imap_uid so the derived sequence numbers match
		// SELECT/FETCH/STORE.
		rows, err := tx.Query(ctx,
			`SELECT m.id, m.is_deleted FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE
			 ORDER BY `+imapUIDColumn(c.useMembershipUID),
			c.tagID,
		)
		if err != nil {
			return err
		}
		type msgRow struct {
			id        int64
			isDeleted bool
		}
		var all []msgRow
		for rows.Next() {
			var m msgRow
			if err := rows.Scan(&m.id, &m.isDeleted); err == nil {
				all = append(all, m)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Walk the ordered list to derive IMAP sequence numbers (RFC 9051
		// §7.4.1). Each EXPUNGE shifts subsequent sequence numbers down by 1;
		// processing in ascending order means seq = currentSeq - alreadyGone.
		var deleteIDs []int64
		currentSeq := 0
		alreadyGone := 0
		for _, m := range all {
			currentSeq++
			if m.isDeleted {
				seq := currentSeq - alreadyGone
				if seq < 1 {
					seq = 1
				}
				fmt.Fprintf(c.conn, "* %d EXPUNGE\r\n", seq)
				deleteIDs = append(deleteIDs, m.id)
				alreadyGone++
			}
		}

		if len(deleteIDs) > 0 {
			// arch A8: purge through the reducer so the raw_ref BLOB is dedup-checked
			// and queued for GC (orphaned_message_blobs) — the raw `DELETE messages`
			// here leaked every expunged message's body blob. jmap_email_purge only
			// hard-deletes is_deleted rows (which these all are), R3-scopes to
			// p_mailbox_id, and cascade-drops message_tags (FK ON DELETE CASCADE).
			// p_notify=FALSE: the \Deleted STORE already pushed the 'destroyed' delta,
			// so a second resync-forcing notify would needlessly invalidate clients.
			if _, err := tx.Exec(ctx,
				`SELECT jmap_email_purge($2, $1, FALSE)`,
				deleteIDs, c.mailboxID); err != nil {
				return err
			}
		}
		return nil
	})
	if scopeErr != nil {
		c.reply(tag, "NO Server error")
		return
	}

	c.reply(tag, "OK EXPUNGE completed")
	c.auditLog(ctx, "imap_expunge", nil)
}

func (c *connState) handleUID(ctx context.Context, tag, args string) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// For now, treat UID commands same as regular
	parts := strings.Fields(args)
	if len(parts) < 2 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	subcmd := strings.ToUpper(parts[0])
	subargs := strings.Join(parts[1:], " ")

	switch subcmd {
	case "FETCH":
		c.handleFetch(ctx, tag, subargs, true)
	case "SEARCH":
		c.handleSearch(ctx, tag, true, subargs)
	case "STORE":
		c.handleStore(ctx, tag, true, subargs)
	case "COPY":
		// Route to the real COPY path (it actually adds the dest tag now). Was a
		// success-replying no-op — never reply OK without doing the work.
		c.handleCopy(ctx, tag, subargs, true)
	case "MOVE":
		// Route to the real MOVE path. Was a success-replying no-op.
		c.handleMove(ctx, tag, subargs, true)
	default:
		c.reply(tag, "BAD Unknown UID command")
	}
}

func (c *connState) handleUnselect(tag string) {
	c.reply("*", "OK [CLOSED] Previous mailbox closed")
	c.selected = ""
	c.mailboxID = 0
	c.reply(tag, "OK UNSELECT completed")
}

func (c *connState) handleClose(ctx context.Context, tag string) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// native-RLS (W5): the \Deleted-id read AND the deletes (message_tags +
	// messages) all run inside ONE per-command tx with app.current_mailbox_id =
	// c.mailboxID, so they survive the W6 FORCE flip.
	_ = c.withScope(ctx, func(tx pgx.Tx) error {
		// Resolve the selected folder's \Deleted messages via the tag-aware
		// message_tags model (c.tagID, resolved in handleSelect) — NOT the legacy
		// `folders` join (`JOIN folders f ON f.id = m.folder_id` joined a TAG id
		// against the wrong table → matched nothing, so CLOSE silently expunged
		// nothing). Mirrors handleExpunge's pattern.
		rows, err := tx.Query(ctx,
			`SELECT m.id FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND m.is_deleted = TRUE`,
			c.tagID,
		)
		if err != nil {
			return err
		}
		var deleteIDs []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err == nil {
				deleteIDs = append(deleteIDs, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		if len(deleteIDs) > 0 {
			// arch A8: purge through the reducer (blob dedup + GC queue) instead of a
			// raw DELETE that leaked the body blob. Same contract as handleExpunge:
			// is_deleted-only, R3-scoped, FK-cascades message_tags, p_notify=FALSE
			// (the \Deleted STORE already pushed the 'destroyed' delta).
			if _, err := tx.Exec(ctx,
				`SELECT jmap_email_purge($2, $1, FALSE)`,
				deleteIDs, c.mailboxID); err != nil {
				return err
			}
		}
		return nil
	})
	// CLOSE always succeeds at the protocol level (RFC 9051 §6.4.2) regardless of
	// the expunge outcome; the scope error is swallowed exactly as the legacy
	// fire-and-forget Execs swallowed their errors.
	c.reply("*", "OK [CLOSED] Previous mailbox closed")
	c.selected = ""
	c.mailboxID = 0
	c.reply(tag, "OK CLOSE completed")
}

func (c *connState) handleCreate(ctx context.Context, tag, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}
	name := canonicalMailboxLookupName(strings.Trim(args, `"`))
	if name == "" {
		c.reply(tag, "BAD Missing mailbox name")
		return
	}
	// Guard: prevent recreating system tags
	lower := strings.ToLower(name)
	if lower == "inbox" || lower == "sent" || lower == "drafts" || lower == "trash" || lower == "spam" {
		c.reply(tag, "NO Cannot create system mailbox")
		return
	}
	// Get mailbox_id for this user
	mbID, err := identity.ResolvePrimaryMailbox(ctx, c.srv.pool, c.userID)
	if err != nil {
		c.reply(tag, "NO Cannot find mailbox")
		return
	}
	_, err = c.srv.pool.Exec(ctx,
		`INSERT INTO tags (mailbox_id, name, tag_type, sort_order, imap_expose)
		 VALUES ($1, $2, 'user', 999, TRUE) ON CONFLICT (mailbox_id, name) DO NOTHING`,
		mbID, name)
	if err != nil {
		c.reply(tag, "NO CREATE failed")
		return
	}
	c.reply(tag, "OK CREATE completed")
}

func (c *connState) handleDelete(ctx context.Context, tag, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}
	name := canonicalMailboxLookupName(strings.Trim(args, `"`))
	if name == "" {
		c.reply(tag, "BAD Missing mailbox name")
		return
	}
	// Find the mailbox for this user
	mbID, _ := identity.ResolvePrimaryMailbox(ctx, c.srv.pool, c.userID)
	if mbID == 0 {
		c.reply(tag, "NO Cannot find mailbox")
		return
	}
	// Check tag type before deleting
	var tagType string
	err := c.srv.pool.QueryRow(ctx,
		`SELECT tag_type FROM tags WHERE mailbox_id = $1 AND name = $2`, mbID, name,
	).Scan(&tagType)
	if err != nil {
		c.reply(tag, "NO No such mailbox")
		return
	}
	if tagType == "system" {
		c.reply(tag, "NO Cannot delete system mailbox")
		return
	}
	_, err = c.srv.pool.Exec(ctx,
		`DELETE FROM tags WHERE mailbox_id = $1 AND name = $2 AND tag_type = 'user'`,
		mbID, name)
	if err != nil {
		c.reply(tag, "NO DELETE failed")
		return
	}
	// If this was the selected mailbox, deselect
	if strings.EqualFold(name, c.selected) {
		c.reply("*", "OK [CLOSED] Previous mailbox closed")
		c.selected = ""
		c.mailboxID = 0
	}
	c.reply(tag, "OK DELETE completed")
}

func (c *connState) handleRename(ctx context.Context, tag, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}
	parts := splitIMAPArgs(args)
	if len(parts) < 2 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	oldName := strings.Trim(parts[0], `"`)
	newName := strings.Trim(parts[1], `"`)
	if oldName == "" || newName == "" {
		c.reply(tag, "BAD Invalid mailbox names")
		return
	}
	// Guard: prevent renaming system tags
	lowerOld := strings.ToLower(oldName)
	if lowerOld == "inbox" || lowerOld == "sent" || lowerOld == "drafts" || lowerOld == "trash" || lowerOld == "spam" {
		c.reply(tag, "NO Cannot rename system mailbox")
		return
	}
	mbID, _ := identity.ResolvePrimaryMailbox(ctx, c.srv.pool, c.userID)
	if mbID == 0 {
		c.reply(tag, "NO Cannot find mailbox")
		return
	}
	_, err := c.srv.pool.Exec(ctx,
		`UPDATE tags SET name = $1 WHERE mailbox_id = $2 AND name = $3 AND tag_type = 'user'`,
		newName, mbID, oldName)
	if err != nil {
		c.reply(tag, "NO RENAME failed")
		return
	}
	// Update selected state if renamed mailbox was selected
	if strings.EqualFold(oldName, c.selected) {
		c.selected = newName
	}
	c.reply(tag, "OK RENAME completed")
}

func (c *connState) handleMove(ctx context.Context, tag, args string, isUID bool) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// RFC 9051 §6.3.2 — EXAMINE opens mailbox read-only
	if c.readOnly {
		c.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only")
		return
	}
	parts := splitIMAPArgs(args)
	if len(parts) < 2 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	seqStr := parts[0]
	targetName := canonicalMailboxLookupName(strings.Trim(strings.Join(parts[1:], " "), `"`))
	// C3 fix (2026-07-11 codebase review): resolve the sequence-set honoring
	// UID vs. positional mode via parseSeqSet+resolveSeqSet — same as
	// FETCH/STORE — instead of parseSeqRange's positional start+count, which
	// treated a UID MOVE operand as an array index into the UID-ordered view
	// and moved the WRONG message (or none) whenever the mailbox's UIDs are
	// non-contiguous (any prior delete/expunge leaves a gap).
	ranges := parseSeqSet(seqStr)
	if len(ranges) == 0 {
		c.reply(tag, "BAD Invalid sequence number")
		return
	}

	// native-RLS (W5): the batched source load (messages+message_tags) + the
	// batched tag swap all run inside ONE per-command tx with
	// app.current_mailbox_id = c.mailboxID, so they survive the W6 FORCE flip.
	// The command boundary is unchanged from the per-row loop it replaces: ONE
	// Begin→scope→callback→Commit per MOVE, and any row's failure returns an
	// error from the callback and rolls back ALL earlier rows (no per-row
	// commits, no savepoints, no partial success).
	movedCount := 0
	var sourceUIDs, destinationUIDs []int64
	var destinationUIDValidity int64
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		// Resolve the destination tag in the SELECTED mailbox (a folder is a tag).
		// MOVE within a mailbox: the target tag must belong to c.mailboxID (R3 —
		// ownership in the resolution, so a foreign/unknown name resolves nothing).
		var destTagID int64
		var destTagGroup *string
		if err := tx.QueryRow(ctx,
			`SELECT id,exclusive_group,imap_uid_validity FROM tags
			 WHERE mailbox_id = $1 AND (name = $2 OR imap_name = $2)`,
			c.mailboxID, targetName,
		).Scan(&destTagID, &destTagGroup, &destinationUIDValidity); err != nil {
			// Unknown target tag → no move (MOVE completes with zero moved).
			return nil
		}

		// Batch-load the source folder's ordered view via the message_tags model
		// (c.tagID, resolved in handleSelect) — NOT the legacy `folders` join (the
		// old `folder_id = (SELECT id FROM folders …)` joined a TAG id against the
		// wrong table and matched nothing). Capture each message's ORIGINAL
		// received_at so the dest tag row lands in the SAME partition (message_tags
		// is partitioned by received_at; PK is message_id+received_at+tag_id, and
		// the exclusive-group trigger matches on received_at). One query kills the
		// per-sequence N+1. imap_uid+seq are what resolveSeqSet needs.
		rows, err := tx.Query(ctx,
			`SELECT m.id, `+imapUIDColumn(c.useMembershipUID)+`, m.received_at FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND NOT m.is_deleted
			 ORDER BY `+imapUIDColumn(c.useMembershipUID),
			c.tagID,
		)
		if err != nil {
			return err
		}
		var all []storeMsg
		seqN := int64(0)
		for rows.Next() {
			var s storeMsg
			if err := rows.Scan(&s.id, &s.imapUID, &s.recv); err == nil {
				seqN++
				s.seq = seqN
				all = append(all, s)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Resolve the set against imap_uid (isUID) or 1-based position — NOT a
		// positional array slice — so non-contiguous UIDs (gaps from prior
		// deletes) resolve to the CORRECT message, or to none if the named UID
		// doesn't exist. resolveSeqSet preserves the UID-ascending order of
		// `all`, so targets[0]/targets[len-1] are the lowest/highest matched UID.
		targets := resolveSeqSet(ranges, all, isUID)
		if len(targets) == 0 {
			return nil
		}
		in := newImapBatchInput(targets)
		sourceUIDs = in.sourceUIDs

		// IMAP MOVE = remove from source folder, add to dest. Remove ALL source
		// tag memberships first (same received_at) in ONE set-based statement so
		// every message leaves the source folder regardless of whether source/dest
		// share an exclusive group.
		if err := deleteSourceMemberships(ctx, tx, in, c.mailboxID, c.tagID); err != nil {
			return err
		}

		if destTagGroup != nil && *destTagGroup == "location" {
			// Location-group dest → the batch front door imap_batch_move_location:
			// one round trip that loops transition_message_location PER MESSAGE, in
			// input-ordinal order — the invariant guard, the exclusive swap and the
			// reducer-owned notify stay per message (no second notify here, no bulk
			// reducer) — and returns each message's destination membership UID.
			destUIDs, err := moveLocationBatch(ctx, tx, in, targetName, c.mailboxID)
			if err != nil {
				return err
			}
			if destinationUIDs, err = in.destinationUIDs(c.useMembershipUID, destUIDs); err != nil {
				return err
			}
		} else {
			// Non-location dest (user/custom label) → set-based INSERT as primary
			// so the messages are visible in the dest folder (FETCH keys on
			// is_primary). The BEFORE-INSERT exclusive trigger is a no-op for a
			// NULL group; the membership-UID allocator trigger fires per row in
			// input-ordinal order.
			destUIDs, err := addDestMemberships(ctx, tx, in, c.mailboxID, destTagID)
			if err != nil {
				return err
			}
			if destinationUIDs, err = in.destinationUIDs(c.useMembershipUID, destUIDs); err != nil {
				return err
			}
			// arch A8: the raw tag swap above bypassed the jmap state bump + push
			// (unlike the location branch's transition_message_location), so a
			// JMAP or second-IMAP client never saw this move until a full resync.
			// Push a precise message-level 'updated' delta per message, in source
			// ordinal order, through the single owner. tag_id NULL: we hold the dest
			// name, not its id — the mailbox-wide email-state bump + journal row are
			// what the client needs. Deliberately per-row (not bulk/coalesced):
			// in-transaction pg_notify and state journals have per-message meaning.
			if err := notifyUpdatedBatch(ctx, tx, in, c.mailboxID, nil); err != nil {
				return err
			}
		}
		movedCount = len(in.ids)
		return nil
	})
	if scopeErr != nil {
		c.reply(tag, "NO MOVE failed")
		return
	}
	if movedCount > 0 {
		c.reply(fmt.Sprintf("* OK [COPYUID %d %s %s] MOVE completed",
			destinationUIDValidity, formatUIDSet(sourceUIDs), formatUIDSet(destinationUIDs)), "")
	}
	c.reply(tag, "OK MOVE completed")
	c.auditLog(ctx, "imap_move", nil)
}

func (c *connState) handleCopy(ctx context.Context, tag, args string, isUID bool) {
	if !c.authed || c.selected == "" {
		c.reply(tag, "NO No mailbox selected")
		return
	}
	// RFC 9051 §6.3.2 — EXAMINE opens mailbox read-only
	if c.readOnly {
		c.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only")
		return
	}
	parts := splitIMAPArgs(args)
	if len(parts) < 2 {
		c.reply(tag, "BAD Missing arguments")
		return
	}
	seqStr := parts[0]
	targetName := canonicalMailboxLookupName(strings.Trim(strings.Join(parts[1:], " "), `"`))
	// C3 fix (2026-07-11 codebase review): resolve the sequence-set honoring
	// UID vs. positional mode via parseSeqSet+resolveSeqSet — same as
	// FETCH/STORE/MOVE — instead of parseSeqRange's positional start+count,
	// which treated a UID COPY operand as an array index into the UID-ordered
	// view and copied the WRONG message (or none) whenever the mailbox's UIDs
	// are non-contiguous (any prior delete/expunge leaves a gap).
	ranges := parseSeqSet(seqStr)
	if len(ranges) == 0 {
		c.reply(tag, "BAD Invalid sequence number")
		return
	}

	// native-RLS (W5): the batched source load (messages+message_tags) + the
	// batched dest-tag add run inside ONE per-command tx with
	// app.current_mailbox_id = c.mailboxID, so they survive the W6 FORCE flip.
	// The command boundary is unchanged from the per-row loop it replaces: ONE
	// Begin→scope→callback→Commit per COPY, and any row's failure returns an
	// error from the callback and rolls back ALL earlier rows (no per-row
	// commits, no savepoints, no partial success).
	copiedCount := 0
	var sourceUIDs, destinationUIDs []int64
	var destinationUIDValidity int64
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		// Resolve the destination tag id in the SELECTED mailbox (a folder is a
		// tag). Ownership in the resolution (R3) — a foreign/unknown name resolves
		// nothing and COPY completes with zero copied.
		var destTagID int64
		if err := tx.QueryRow(ctx,
			`SELECT id,imap_uid_validity FROM tags WHERE mailbox_id = $1 AND (name = $2 OR imap_name = $2)`,
			c.mailboxID, targetName,
		).Scan(&destTagID, &destinationUIDValidity); err != nil {
			return nil
		}

		// Batch-load the source folder's ordered view via the message_tags model
		// (c.tagID) — NOT the legacy `folders` join (`folder_id = (SELECT id FROM
		// folders …)` joined a TAG id against the wrong table → matched nothing).
		// Capture the ORIGINAL received_at so the copy's message_tags row lands in
		// the SAME partition. One query kills the per-sequence N+1. imap_uid+seq
		// are what resolveSeqSet needs.
		rows, err := tx.Query(ctx,
			`SELECT m.id, `+imapUIDColumn(c.useMembershipUID)+`, m.received_at FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND NOT m.is_deleted
			 ORDER BY `+imapUIDColumn(c.useMembershipUID),
			c.tagID,
		)
		if err != nil {
			return err
		}
		var all []storeMsg
		seqN := int64(0)
		for rows.Next() {
			var s storeMsg
			if err := rows.Scan(&s.id, &s.imapUID, &s.recv); err == nil {
				seqN++
				s.seq = seqN
				all = append(all, s)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		// Resolve the set against imap_uid (isUID) or 1-based position — NOT a
		// positional array slice — so non-contiguous UIDs (gaps from prior
		// deletes) resolve to the CORRECT message, or to none if the named UID
		// doesn't exist. resolveSeqSet preserves the UID-ascending order of
		// `all`, so targets[0]/targets[len-1] are the lowest/highest matched UID.
		targets := resolveSeqSet(ranges, all, isUID)
		if len(targets) == 0 {
			return nil
		}
		in := newImapBatchInput(targets)
		sourceUIDs = in.sourceUIDs

		// COPY = ADD the dest tag membership WITHOUT removing the source (IMAP
		// COPY semantics; confirmed against the legacy INSERT which added a dest
		// tag and left the source). One set-based INSERT ... SELECT over the
		// aligned input relation, ordered by input ordinal. is_primary = TRUE so
		// the copies are visible in the dest folder (FETCH/SEARCH key on
		// is_primary = TRUE). The current data model cannot materialize a second
		// independent JMAP Email object, so a repeated COPY fails explicitly
		// instead of returning a false COPYUID success: duplicate detection is the
		// message_tags PRIMARY KEY at MUTATION time — the old per-row EXISTS
		// precheck (a separate read, and a TOCTOU window under a racing writer) is
		// gone; a conflict aborts this statement and the whole tx, and is mapped
		// to errCopyAlreadyPresent for the [CANNOT] reply (copyConflictOrErr
		// discriminates the message_tags PK from the allocator-ledger PK — both
		// are 23505 here). The BEFORE-INSERT exclusive-group trigger still owns
		// any location-group enforcement on insert, per row, exactly as before.
		destUIDs, err := addDestMemberships(ctx, tx, in, c.mailboxID, destTagID)
		if err != nil {
			return copyConflictOrErr(err)
		}
		var dupErr error
		if destinationUIDs, dupErr = in.destinationUIDs(c.useMembershipUID, destUIDs); dupErr != nil {
			return dupErr
		}
		// arch A8: the raw dest-tag INSERT bypassed the jmap state bump + push,
		// so a JMAP or second-IMAP client never saw the copied messages appear in
		// the dest folder. Push a precise message-level 'updated' delta per
		// message, in source ordinal order, through the single owner (destTagID is
		// known here, so bump its tag state too). Deliberately per-row (not
		// bulk/coalesced): in-transaction pg_notify and state journals have
		// per-message meaning.
		if err := notifyUpdatedBatch(ctx, tx, in, c.mailboxID, &destTagID); err != nil {
			return err
		}
		copiedCount = len(in.ids)
		return nil
	})
	if errors.Is(scopeErr, errCopyAlreadyPresent) {
		c.reply(tag, "NO [CANNOT] Destination already contains one or more messages")
		return
	}
	if scopeErr != nil {
		c.reply(tag, "NO COPY failed")
		return
	}
	if copiedCount > 0 {
		c.reply(fmt.Sprintf("* OK [COPYUID %d %s %s] COPY completed",
			destinationUIDValidity, formatUIDSet(sourceUIDs), formatUIDSet(destinationUIDs)), "")
	}
	c.reply(tag, "OK COPY completed")
	c.auditLog(ctx, "imap_copy", nil)
}

var errCopyAlreadyPresent = errors.New("imap: copy destination membership already exists")

// pgErrUniqueViolation is the SQLSTATE for a unique/PK violation (23505). The
// batched COPY dest INSERT relies on message_tags' PRIMARY KEY
// (message_id, received_at, tag_id) as the mutation-time duplicate arbiter.
const pgErrUniqueViolation = "23505"

// copyConflictOrErr maps the set-based dest INSERT's mutation-time unique
// violation on the message_tags PK to errCopyAlreadyPresent (→ the RFC
// "[CANNOT]" NO reply) and passes every other error through untouched. 23505
// here can also come from the imap_membership_uid_ledger PK inside the
// allocator trigger — an allocator race, not "destination already contains one
// of the messages" — so the constraint name discriminates; the whole statement
// aborted either way, so the caller's tx rollback makes the rejection
// transactional.
func copyConflictOrErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
		// 23505 fires from TWO constraints reachable in this statement: the
		// message_tags PK (the genuine duplicate-COPY signal) and the
		// imap_membership_uid_ledger PK inside the allocator trigger (an
		// allocator race — a server error, not a client "already present").
		// Discriminate by constraint name; the ledger collision falls through
		// as the raw error so the client sees a serverFail, not [CANNOT].
		if strings.Contains(pgErr.ConstraintName, "message_tags") {
			return errCopyAlreadyPresent
		}
	}
	return err
}

// imapMembershipKey identifies one message_tags membership row by its PK pair.
// The received_at is carried as UnixNano so keys stay comparable across the
// timestamptz encode/decode round trip through the batch statements.
type imapMembershipKey struct {
	messageID int64
	recvAt    int64
}

// imapBatchInput is the ONE aligned input relation the batched MOVE/COPY
// statements consume: index i describes the i-th target in the source view's
// ascending effective-UID order (membership UID when the session pinned it at
// SELECT, legacy message UID otherwise). That order — resolveSeqSet's output —
// is the input ordinal for destination UID allocation, for the per-message
// notify loop and for the COPYUID pairing; ids/recvs/sourceUIDs are carried as
// one aligned relation (never separate uncorrelated ANY predicates), so the SQL
// statements can't cross-match a message id with a foreign received_at.
type imapBatchInput struct {
	ids        []int64
	recvs      []time.Time
	sourceUIDs []int64
}

// newImapBatchInput slices resolveSeqSet's targets (already ordered and
// deduplicated) into the aligned input relation.
func newImapBatchInput(targets []storeMsg) imapBatchInput {
	in := imapBatchInput{
		ids:        make([]int64, len(targets)),
		recvs:      make([]time.Time, len(targets)),
		sourceUIDs: make([]int64, len(targets)),
	}
	for i, s := range targets {
		in.ids[i] = s.id
		in.recvs[i] = s.recv
		in.sourceUIDs[i] = s.imapUID
	}
	return in
}

// destinationUIDs pairs every input ordinal with its destination UID. Legacy
// mode (useMembershipUID false) keeps the long-standing rule destination UID =
// source message UID. Membership mode matches the inserted memberships on
// (message_id, received_at) and reorders by input ordinal — NEVER by message
// ID, timestamp alone, destination UID sort or incidental RETURNING order — and
// fails the command rather than emit a misaligned COPYUID when a membership is
// missing.
func (in imapBatchInput) destinationUIDs(useMembershipUID bool, inserted map[imapMembershipKey]int64) ([]int64, error) {
	if !useMembershipUID {
		return append([]int64(nil), in.sourceUIDs...), nil
	}
	out := make([]int64, len(in.ids))
	for i := range in.ids {
		uid, ok := inserted[imapMembershipKey{in.ids[i], in.recvs[i].UnixNano()}]
		if !ok {
			return nil, fmt.Errorf("imap: no destination membership for message %d (COPYUID pairing would misalign)", in.ids[i])
		}
		out[i] = uid
	}
	return out, nil
}

// deleteSourceMemberships removes the source-tag primary membership for the
// whole aligned input in ONE statement (the per-message DELETE round trips this
// replaces fired the identical AFTER DELETE counter/ledger-retire triggers, per
// row). DATABASE_SECURITY R1: ownership is re-asserted IN the statement via the
// messages join (m.mailbox_id), and mt.tag_id + mt.is_primary re-assert the
// source-read predicate, so a stale/forged id cannot delete another mailbox's
// membership. Input arrays travel as one correlated unnest relation.
func deleteSourceMemberships(ctx context.Context, tx pgx.Tx, in imapBatchInput, mailboxID, sourceTagID int64) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM message_tags mt
		  USING messages m,
		       unnest($1::bigint[], $2::timestamptz[]) WITH ORDINALITY AS u(mid, rat, ord)
		  WHERE mt.message_id = m.id AND mt.received_at = m.received_at
		    AND m.mailbox_id = $3
		    AND mt.tag_id = $4
		    AND mt.is_primary = TRUE
		    AND mt.message_id = u.mid AND mt.received_at = u.rat`,
		in.ids, in.recvs, mailboxID, sourceTagID)
	return err
}

// addDestMemberships INSERTs the destination primary membership for the whole
// aligned input in ONE set-based statement (this is tag_message's insert —
// (message_id, received_at, tag_id, 'imap', is_primary=TRUE) — minus the
// redundant per-row name resolution, which the caller already did
// ownership-scoped). Rows are fed to the INSERT in input-ordinal order
// (ORDER BY u.ord), so the BEFORE-INSERT triggers fire per row in that order:
// exclusive-group enforcement, then the membership-UID allocator — the ordered
// input reaches imap_membership_uid_allocate BEFORE UID assignment, which is
// what pins destination UID allocation to the source view's ascending effective
// UID order. DATABASE_SECURITY R1: ownership via the messages join in the same
// statement. RETURNING is matched back to the input ordinal on
// (message_id, received_at) in Go; the statement's output order is never
// trusted.
func addDestMemberships(ctx context.Context, tx pgx.Tx, in imapBatchInput, mailboxID, destTagID int64) (map[imapMembershipKey]int64, error) {
	rows, err := tx.Query(ctx,
		`WITH input AS (
		   SELECT u.mid, u.rat, u.ord
		     FROM unnest($1::bigint[], $2::timestamptz[]) WITH ORDINALITY AS u(mid, rat, ord)
		 ), inserted AS (
		   INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary)
		   SELECT i.mid, i.rat, $3, 'imap', TRUE
		     FROM input i
		     JOIN messages m ON m.id = i.mid AND m.received_at = i.rat
		     WHERE m.mailbox_id = $4
		     ORDER BY i.ord
		     RETURNING message_id, received_at, imap_uid
		 )
		 SELECT ins.message_id, ins.received_at, ins.imap_uid
		   FROM inserted ins
		   JOIN input i ON i.mid = ins.message_id AND i.rat = ins.received_at
		  ORDER BY i.ord`,
		in.ids, in.recvs, destTagID, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[imapMembershipKey]int64, len(in.ids))
	for rows.Next() {
		var mid, uid int64
		var rat time.Time
		if err := rows.Scan(&mid, &rat, &uid); err != nil {
			return nil, err
		}
		out[imapMembershipKey{messageID: mid, recvAt: rat.UnixNano()}] = uid
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// moveLocationBatch dispatches a location-group MOVE dest through the SQL batch
// front door imap_batch_move_location: ONE round trip that loops the existing
// per-message seam transition_message_location in input-ordinal order — the
// location invariant guard, the exclusive swap and the reducer-owned notify
// stay per message inside it (no second notify from Go here, no bulk/coalesced
// reducer) — and returns each message's destination membership UID, allocated
// by the same trigger the per-row loop used.
func moveLocationBatch(ctx context.Context, tx pgx.Tx, in imapBatchInput, destTagName string, mailboxID int64) (map[imapMembershipKey]int64, error) {
	rows, err := tx.Query(ctx,
		`SELECT out_message_id, out_received_at, out_imap_uid
		   FROM imap_batch_move_location($1::bigint[], $2::timestamptz[], $3, $4, 'imap')`,
		in.ids, in.recvs, destTagName, mailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[imapMembershipKey]int64, len(in.ids))
	for rows.Next() {
		var mid, uid int64
		var rat time.Time
		if err := rows.Scan(&mid, &rat, &uid); err != nil {
			return nil, err
		}
		out[imapMembershipKey{messageID: mid, recvAt: rat.UnixNano()}] = uid
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// notifyUpdatedBatch emits the per-message 'updated' state deltas for the whole
// aligned input, ONE notify_state_change call per message in source ordinal
// order, inside the caller's scoped transaction. Deliberately NOT bulk and NOT
// coalesced (WP4 contract): in-transaction pg_notify and the jmap state journal
// carry per-message meaning, so the O(N) notification calls stay while the
// mutation/UID-read statements around them become set-based. tagID nil keeps
// the mailbox-wide bump the non-location MOVE branch has always used; a
// non-nil tagID bumps that tag's state too (COPY's existing shape).
func notifyUpdatedBatch(ctx context.Context, tx pgx.Tx, in imapBatchInput, mailboxID int64, tagID *int64) error {
	for i := range in.ids {
		if _, err := tx.Exec(ctx,
			`SELECT notify_state_change($1, $2, $3, 'updated')`,
			mailboxID, tagID, in.ids[i]); err != nil {
			return err
		}
	}
	return nil
}

func (c *connState) handleStartTLS(ctx context.Context, tag string) {
	if c.secure {
		c.reply(tag, "BAD TLS is already active")
		return
	}
	if c.authed {
		c.reply(tag, "BAD STARTTLS is not permitted after authentication")
		return
	}
	if c.srv.tlsCert == "" {
		c.reply(tag, "NO STARTTLS not available")
		return
	}
	c.reply(tag, "OK Begin TLS negotiation now")
	cert, err := tls.LoadX509KeyPair(c.srv.tlsCert, c.srv.tlsKey)
	if err != nil {
		c.srv.logger.Error("imap STARTTLS cert load failed", "error", err)
		return
	}
	tlsConfig := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     tlsutil.DefaultCipherSuites,
		CurvePreferences: tlsutil.DefaultCurves,
	}
	tlsConn := tls.Server(c.conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		c.srv.logger.Error("imap STARTTLS handshake failed", "error", err)
		return
	}
	c.conn = tlsConn
	c.reader = bufio.NewReader(tlsConn)
	c.secure = true
}

func (c *connState) handleAuthenticate(ctx context.Context, tag, args string) {
	if c.authed {
		// RFC 9051 §6.2.2: AUTHENTICATE in the authenticated state is a command
		// error. Rejecting here (mirroring handleLogin) also closes the
		// identity-rebind hole: a re-AUTHENTICATE used to move c.userID and the
		// protocol-session registry entry to a second account while c.tagID /
		// c.mailboxID kept serving the FIRST account's selected mailbox, and
		// overwrote c.release without running it (leaking the first account's
		// per-user connection slot beyond disconnect).
		c.reply(tag, "BAD Already authenticated")
		return
	}
	if c.rejectPlaintextAuth(tag) {
		return
	}
	f := strings.Fields(args)
	if len(f) == 0 {
		c.reply(tag, "BAD mechanism required")
		return
	}
	if !strings.EqualFold(f[0], "PLAIN") {
		c.reply(tag, "NO Only AUTH=PLAIN supported")
		return
	}
	// SASL PLAIN: client sends empty response, server sends "+", client sends base64("\0user\0pass")
	c.reply("+", "Ready for additional data")
	line, err := readLineLimited(c.reader)
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "*" {
		c.reply(tag, "BAD Authentication cancelled")
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		c.reply(tag, "BAD Invalid base64")
		return
	}
	parts := strings.SplitN(string(decoded), "\x00", 3)
	if len(parts) < 3 {
		c.reply(tag, "BAD Invalid PLAIN credentials")
		return
	}
	email := parts[1]
	password := parts[2]
	authenticatedAt := time.Now().UTC()

	clientIP := "unknown"
	if addr, ok := c.conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	var meta threat.ConnectionMeta
	if c.srv.threatInterceptor != nil {
		meta = threat.ConnectionMeta{
			SourceIP:  clientIP,
			Username:  email,
			Protocol:  threat.ProtocolIMAP,
			UserAgent: "",
		}
		result, _, delay := c.srv.threatInterceptor.Intercept(ctx, &meta)
		switch result {
		case threat.ActionReject:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Authentication temporarily unavailable")
			return
		case threat.ActionTarpitted:
			if delay > 0 {
				time.Sleep(delay)
			}
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Authentication temporarily unavailable")
			return
		case threat.ActionRateLimited:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "rate_limit", Email: email,
				IPAddress: clientIP,
			}, nil)
			c.reply(tag, "NO Too many authentication attempts — try again later")
			return
		}
	}

	// Try app password first
	if user, err := pwhash.CheckAppPassword(ctx, c.srv.pool, email, password); err == nil {
		c.resetSelectedMailboxState() // identity change: drop the selected-mailbox handle first
		c.authed = true
		c.userID = user.ID
		if c.srv.threatInterceptor != nil {
			meta.AppPassword = true
			c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
			meta.UserID = user.ID
			meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
			meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
			if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); postAuthDenied(res == threat.ActionReject) {
				pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
					UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
					Email: email, IPAddress: clientIP,
				}, nil)
				c.authed = false
				c.userID = 0
				c.reply(tag, "NO ["+reason+"] Access blocked by policy")
				return
			}
		}
		c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
			"email":    email,
			"provider": "app_password",
			"ip":       clientIP,
		}))
		if c.denyIfImapDisabled(ctx, tag, user.ID) || c.denyIfMailboxLifecycleBlocked(ctx, tag, user.ID) {
			return
		}
		meta.DeviceBound = false // IMAP cannot present a device proof header
		// Release-then-acquire: hand back any tracker slot this connection still
		// holds BEFORE taking the new identity's slot. Overwriting c.release
		// without running it orphans the original user's slot beyond disconnect
		// (only the final c.release runs in handleConn).
		c.releaseUserSlot()
		// RFC 9051 §6.2.2 — send tagged OK with per-user connection check
		release, err := c.srv.userTracker.TryAcquire(user.ID)
		if err != nil {
			c.reply(tag, "NO Too many connections from this account")
			c.authed = false
			c.userID = 0
			return
		}
		c.release = release
		c.trackProtocolSession(user.ID, authenticatedAt)
		c.reply(tag, "OK AUTHENTICATE completed")
		return
	}

	user, err := auth.CheckPassword(ctx, c.srv.pool, email, password)
	if err != nil {
		if c.srv.threatInterceptor != nil {
			c.srv.threatInterceptor.RecordResult(ctx, &meta, false, 0)
		}
		pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "bcrypt", Email: email,
			IPAddress: c.conn.RemoteAddr().String(),
		}, nil)
		c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLoginFailed, map[string]interface{}{
			"email":    email,
			"provider": "bcrypt",
			"ip":       clientIP,
		}))
		c.reply(tag, "NO Authentication failed")
		return
	}
	pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "bcrypt", Email: email,
		IPAddress: c.conn.RemoteAddr().String(),
	}, nil)
	c.srv.webhookDispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
		"email":    email,
		"provider": "bcrypt",
		"ip":       clientIP,
	}))
	c.resetSelectedMailboxState() // identity change: drop the selected-mailbox handle first
	c.authed = true
	c.userID = user.ID
	if c.srv.threatInterceptor != nil {
		c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
		meta.UserID = user.ID
		meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
		meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
		if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); postAuthDenied(res == threat.ActionReject) {
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
				Email: email, IPAddress: clientIP,
			}, nil)
			c.authed = false
			c.userID = 0
			c.reply(tag, "NO ["+reason+"] Access blocked by policy")
			return
		}
	}

	if c.denyIfImapDisabled(ctx, tag, user.ID) || c.denyIfMailboxLifecycleBlocked(ctx, tag, user.ID) {
		return
	}
	meta.DeviceBound = false // IMAP cannot present a device proof header

	// Check per-user connection limit. Release-then-acquire: hand back any
	// tracker slot this connection still holds BEFORE taking the new identity's
	// slot (an overwrite without release orphans the original user's slot
	// beyond disconnect).
	c.releaseUserSlot()
	release, err := c.srv.userTracker.TryAcquire(user.ID)
	if err != nil {
		c.reply(tag, "NO Too many connections from this account")
		c.authed = false
		c.userID = 0
		return
	}
	c.release = release
	c.trackProtocolSession(user.ID, authenticatedAt)
	c.reply(tag, "OK AUTHENTICATE completed")
}

// errAppendOverQuota is returned from the APPEND scope when the message would
// push the mailbox past its quota; the caller maps it to a NO [OVERQUOTA] reply.
var errAppendOverQuota = errors.New("imap: append exceeds mailbox quota")

func (c *connState) handleAppend(ctx context.Context, tag, args string) {
	if !c.authed {
		c.reply(tag, "NO Authentication required")
		return
	}
	// RFC 9051 §6.3.2 — EXAMINE opens mailbox read-only
	if c.readOnly {
		c.reply(tag, "NO [READ-ONLY] Mailbox selected as read-only")
		return
	}
	// Parse: APPEND <mailbox> [flags] [date-time] <literal>
	// Read literal size: {size}
	if !strings.HasSuffix(args, "}") {
		c.reply(tag, "BAD Expected literal size")
		return
	}
	braceIdx := strings.LastIndex(args, "{")
	sizeStr := args[braceIdx+1 : len(args)-1]
	size, err := strconv.Atoi(sizeStr)
	if err != nil || size <= 0 || size > 50_000_000 {
		c.reply(tag, "BAD Invalid literal size")
		return
	}

	// Extract mailbox name (before flags/literal)
	prefix := strings.TrimSpace(args[:braceIdx])
	pf := strings.Fields(prefix)
	if len(pf) == 0 {
		c.reply(tag, "BAD mailbox required")
		return
	}
	mailboxName := canonicalMailboxLookupName(strings.Trim(pf[0], `"`))

	// Read literal data
	fmt.Fprintf(c.conn, "+ Ready for literal data\r\n")
	buf := make([]byte, size)
	n, err := io.ReadFull(c.reader, buf)
	if err != nil || n != size {
		c.reply(tag, "NO Failed to read message data")
		return
	}
	// Read trailing CRLF after literal
	_, _ = readLineLimited(c.reader)

	// Parse flags from prefix
	var isRead, isFlagged, isAnswered, isDraft bool
	if strings.Contains(prefix, "(") && strings.Contains(prefix, ")") {
		flagStr := prefix[strings.Index(prefix, "(")+1 : strings.Index(prefix, ")")]
		for _, f := range strings.Fields(flagStr) {
			switch strings.ToUpper(f) {
			case "\\SEEN":
				isRead = true
			case "\\FLAGGED":
				isFlagged = true
			case "\\ANSWERED":
				isAnswered = true
			case "\\DRAFT":
				isDraft = true
			}
		}
	}

	// Resolve the target folder as a TAG (a folder IS a tag — CONTEXT.md), not via
	// the legacy `folders` table. `messages.folder_id` is set by the message_tags
	// primary-sync trigger to a TAG id, and FETCH/SEARCH/EXPUNGE select on
	// message_tags+tag_id — so APPEND must land the message under the destination
	// TAG (resolved by name + mailbox_id from `tags`), with a primary message_tags
	// row, or the appended message is invisible (the silent data-loss bug).
	var destTagID, destMailbox, destUIDValidity int64
	var destUseMembershipUID bool
	var destTagName string
	err = c.srv.pool.QueryRow(ctx,
		`SELECT t.id, t.mailbox_id, t.name, t.imap_uid_validity,
		        COALESCE((SELECT enabled FROM feature_toggles
		                  WHERE key='feature.imap_membership_uid'),FALSE)
		        AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE)
		 FROM tags t
		 WHERE t.mailbox_id = $1 AND (t.name = $2 OR t.imap_name = $2)`,
		c.mailboxID, mailboxName,
	).Scan(&destTagID, &destMailbox, &destTagName, &destUIDValidity, &destUseMembershipUID)
	if err != nil {
		// Fall back to resolving the tag by the connection's user (covers an
		// APPEND issued before SELECT bound c.mailboxID).
		err = c.srv.pool.QueryRow(ctx,
			`SELECT t.id, t.mailbox_id, t.name, t.imap_uid_validity,
			        COALESCE((SELECT enabled FROM feature_toggles
			                  WHERE key='feature.imap_membership_uid'),FALSE)
			        AND COALESCE((imap_membership_uid_readiness(t.id)->>'ready')::boolean,FALSE)
			 FROM tags t
			 JOIN mailboxes mb ON mb.id = t.mailbox_id
			 WHERE mb.user_id = $1 AND (t.name = $2 OR t.imap_name = $2)
			 ORDER BY mb.is_primary DESC LIMIT 1`,
			c.userID, mailboxName,
		).Scan(&destTagID, &destMailbox, &destTagName, &destUIDValidity, &destUseMembershipUID)
		if err != nil {
			c.reply(tag, "NO No such mailbox")
			return
		}
	}

	// native-RLS (W5): the next-UID read + the INSERT INTO messages + the
	// tag_message membership write all run inside ONE per-command tx with
	// app.current_mailbox_id = destMailbox, so they survive the W6 FORCE flip. The
	// GUC equals the INSERT's mailbox_id (destMailbox), which is the message's RLS
	// key — its WITH CHECK under FORCE then passes. The tag lookup above touches
	// only tags/mailboxes (W6-safe), so only this messages-touching region is
	// scoped. The GUC must be destMailbox (not c.mailboxID, which may be 0 or a
	// different selected mailbox), so override it for this scope.
	msg := string(buf)
	prevMailbox := c.mailboxID
	c.mailboxID = destMailbox
	var appendedUID int64
	scopeErr := c.withScope(ctx, func(tx pgx.Tx) error {
		// arch A8: gate the append on quota BEFORE inserting — the canonical create
		// (jmap_email_set_create) does, but the open-coded APPEND did not, so an IMAP
		// client could push the mailbox past its limit. check_quota FOR UPDATE-locks
		// the mailbox row, so the check + the used_bytes bump below are consistent.
		var withinQuota bool
		if err := tx.QueryRow(ctx,
			`SELECT check_quota($1, $2)`, destMailbox, size,
		).Scan(&withinQuota); err != nil {
			return err
		}
		if !withinQuota {
			return errAppendOverQuota
		}

		// Next IMAP UID for the destination tag (mirrors import_message — UID is
		// per-tag, advanced atomically by next_imap_uid_for_tag).
		var nextUID int64
		if err := tx.QueryRow(ctx,
			`SELECT next_imap_uid_for_tag($1)`, destTagID,
		).Scan(&nextUID); err != nil {
			return err
		}

		// Insert the message. folder_id = destTagID (the message_tags primary-sync
		// trigger keeps folder_id == the primary tag id). message_id, thread_id and
		// raw_ref are NOT NULL with no default, so they MUST be supplied — the old
		// INSERT omitted all three and would have failed the constraint outright.
		// received_at is captured (RETURNING) so the message_tags row lands in the
		// SAME partition (message_tags is partitioned by received_at; PK is
		// message_id+received_at+tag_id).
		var msgID int64
		var recv time.Time
		if err := tx.QueryRow(ctx,
			`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject,
			 from_addr, to_addrs, thread_id, raw_ref,
			 is_read, is_flagged, is_answered, is_draft, body_text, size_bytes, received_at)
			 VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
			 RETURNING id, received_at`,
			destMailbox, destTagID, nextUID,
			fmt.Sprintf("<append-%d@setjoin.local>", nextUID), "(appended)", "",
			fmt.Sprintf("append-%d", nextUID), fmt.Sprintf("append-%d", nextUID),
			isRead, isFlagged, isAnswered, isDraft, msg, size,
		).Scan(&msgID, &recv); err != nil {
			return err
		}

		// Create the primary message_tags row so the message is visible to
		// FETCH/SEARCH/EXPUNGE (which join message_tags WHERE is_primary = TRUE).
		// tag_message resolves the tag by name + mailbox (BZ019 if unknown — also
		// fails a foreign mailbox) and is the same primitive import_message uses;
		// the counter + primary-sync triggers fire on the insert.
		if _, err := tx.Exec(ctx,
			`SELECT tag_message($1, $2, $3, $4, 'imap', TRUE)`,
			msgID, recv, destTagName, destMailbox,
		); err != nil {
			return err
		}
		if destUseMembershipUID {
			if err := tx.QueryRow(ctx, `SELECT imap_uid FROM message_tags
				WHERE message_id=$1 AND received_at=$2 AND tag_id=$3`,
				msgID, recv, destTagID).Scan(&appendedUID); err != nil {
				return err
			}
		} else {
			appendedUID = nextUID
		}
		// arch A8: maintain the mailbox quota counter (the append now counts) and
		// push a 'created' delta so a JMAP/second-IMAP client sees the new message —
		// the open-coded APPEND did neither.
		if _, err := tx.Exec(ctx,
			`UPDATE mailboxes SET used_bytes = used_bytes + $1 WHERE id = $2`,
			size, destMailbox,
		); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`SELECT notify_state_change($1, $2, $3, 'created')`,
			destMailbox, destTagID, msgID,
		); err != nil {
			return err
		}
		return nil
	})
	c.mailboxID = prevMailbox
	if errors.Is(scopeErr, errAppendOverQuota) {
		c.reply(tag, "NO [OVERQUOTA] APPEND exceeds mailbox quota")
		return
	}
	if scopeErr != nil {
		c.reply(tag, "NO APPEND failed")
		return
	}

	c.reply(fmt.Sprintf("* %d EXISTS", 0), "") // EXISTS count emitted by SELECT handler
	c.reply(tag, fmt.Sprintf("OK [APPENDUID %d %d] APPEND completed", destUIDValidity, appendedUID))
}

// handleIdle gates IDLE to authenticated connections, then chooses the
// notification-backed or simple idle loop. IDLE is an authenticated-state
// command (RFC 9051 §6.3.13), and both idle loops drop the command-loop read
// deadline so a quiet client is not disconnected mid-idle. Reachable
// pre-authentication (D-MAILSERVER-INTERNAL-IMAP-F-002, CWE-770
// imap/preauth-idle-no-deadline), that deadline drop let an unauthenticated
// socket hold a tlsutil.LimitListener accept slot indefinitely — ~maxConns
// silent sockets deny the whole listener. The guard therefore rejects pre-auth
// IDLE with RFC 5530's [AUTHENTICATIONREQUIRED] code BEFORE any deadline is
// dropped, leaving unauthenticated connections bounded by the ordinary
// readCommandLine slowloris deadline like every other pre-auth command.
// Authenticated long-lived IDLE (the deliberate deadline-clear accommodation)
// is unchanged.
func (c *connState) handleIdle(ctx context.Context, tag string) {
	if !c.authed {
		c.reply(tag, "NO [AUTHENTICATIONREQUIRED] Authenticate before IDLE")
		return
	}
	if c.srv.dispatcher != nil && c.mailboxID > 0 {
		c.idleWithNotify(ctx, tag)
	} else {
		c.idleSimple(tag)
	}
}

func (c *connState) idleSimple(tag string) {
	c.reply(tag, "+ idling")
	// IDLE may legitimately last up to the RFC autologout window; drop the
	// command-loop read deadline so a quiet client is not disconnected. The
	// line cap still bounds memory.
	c.clearReadDeadline()
	for {
		line, err := readLineLimited(c.reader)
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "DONE" {
			c.reply(tag, "OK IDLE completed")
			return
		}
	}
}

func (c *connState) idleWithNotify(ctx context.Context, tag string) {
	c.reply(tag, "+ idling")
	// Drop the command-loop read deadline for the duration of IDLE so the
	// notification poll is not starved by a stale timeout (re-armed on the next
	// command via readCommandLine).
	c.clearReadDeadline()
	pgChannel := fmt.Sprintf("tag:%d", c.mailboxID)
	notifyCh := make(chan string, 16)
	subID, err := c.srv.dispatcher.Subscribe(ctx, pgChannel, notifyCh)
	if err != nil {
		c.srv.logger.Warn("imap idle subscribe failed", "error", err)
		c.idleSimple(tag)
		return
	}
	defer c.srv.dispatcher.Unsubscribe(pgChannel, subID)

	// Track current state for detecting changes. native-RLS (W5): the EXISTS
	// count reads messages, so wrap with app.current_mailbox_id = c.mailboxID
	// (idleWithNotify is only entered when c.mailboxID > 0, see handleConn).
	var lastExists int64
	_ = c.withScope(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM messages m
			 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
			 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND NOT m.is_deleted`,
			c.tagID,
		).Scan(&lastExists)
	})

	for {
		select {
		case payload := <-notifyCh:
			// Parse notification payload for state changes
			var notif struct {
				Event string `json:"event"`
				State int64  `json:"state"`
			}
			if json.Unmarshal([]byte(payload), &notif) != nil {
				continue
			}
			// Query for new message count (reads messages → scoped, W5).
			var currentExists int64
			_ = c.withScope(ctx, func(tx pgx.Tx) error {
				return tx.QueryRow(ctx,
					`SELECT COUNT(*) FROM messages m
					 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
					 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE AND NOT m.is_deleted`,
					c.tagID,
				).Scan(&currentExists)
			})
			if currentExists > lastExists {
				fmt.Fprintf(c.conn, "* %d EXISTS\r\n", currentExists)
			}
			if currentExists < lastExists {
				fmt.Fprintf(c.conn, "* %d EXPUNGE\r\n", 1) // approximate
			}
			lastExists = currentExists

		default:
			// Non-blocking read from the client
			line, err := readNonBlocking(c.reader)
			if err != nil {
				return
			}
			if line != "" && strings.TrimSpace(line) == "DONE" {
				c.reply(tag, "OK IDLE completed")
				return
			}
			// Small sleep to avoid busy-looping
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func readNonBlocking(r *bufio.Reader) (string, error) {
	// Check if data is available without blocking
	// bufio.Reader doesn't support non-blocking reads natively,
	// so we use Peek(1) to test availability
	_, err := r.Peek(1)
	if err != nil {
		return "", nil
	}
	line, err := readLineLimited(r)
	return line, err
}

// Helpers

func quoteIMAP(s string) string {
	if s == "" {
		return "NIL"
	}
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return fmt.Sprintf(`"%s"`, s)
}

// parseAddrTuple parses an email address into an IMAP address tuple.
// Returns "((name NIL local-part host))" or "NIL" if empty.
func parseAddrTuple(addr string) string {
	if addr == "" {
		return "NIL"
	}
	name := ""
	local := addr
	host := ""
	if idx := strings.LastIndex(addr, "@"); idx >= 0 {
		local = addr[:idx]
		host = addr[idx+1:]
	}
	return fmt.Sprintf("((%s NIL %s %s))", quoteIMAP(name), quoteIMAP(local), quoteIMAP(host))
}

// formatAddrTuples formats a list of email addresses as IMAP address tuples.
// Returns "NIL" for empty list, or "((name NIL local host) ...)".
func formatAddrTuples(addrs []string) string {
	if len(addrs) == 0 {
		return "NIL"
	}
	var parts []string
	for _, a := range addrs {
		local := a
		host := ""
		if idx := strings.LastIndex(a, "@"); idx >= 0 {
			local = a[:idx]
			host = a[idx+1:]
		}
		parts = append(parts, fmt.Sprintf("(NIL NIL %s %s)", quoteIMAP(local), quoteIMAP(host)))
	}
	return "(" + strings.Join(parts, " ") + ")"
}

// splitIMAPArgs splits IMAP command arguments respecting quoted strings.
// Unlike strings.Fields, this keeps quoted strings intact as single tokens,
// so passwords with spaces like "my secret password" are preserved.
func splitIMAPArgs(args string) []string {
	var out []string
	i := 0
	for i < len(args) {
		// Skip whitespace
		for i < len(args) && (args[i] == ' ' || args[i] == '\t') {
			i++
		}
		if i >= len(args) {
			break
		}
		if args[i] == '"' {
			// Quoted string — find matching close quote
			j := i + 1
			for j < len(args) && args[j] != '"' {
				j++
			}
			if j < len(args) {
				j++ // include closing quote
			}
			out = append(out, args[i:j])
			i = j
		} else {
			// Atom — until next whitespace
			j := i
			for j < len(args) && args[j] != ' ' && args[j] != '\t' {
				j++
			}
			out = append(out, args[i:j])
			i = j
		}
	}
	return out
}
