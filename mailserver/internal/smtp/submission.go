package smtp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"

	"setjoin.com/shared/pwhash"
	wh "setjoin.com/shared/webhook"
)

// SubmissionServer is the MSA (port 587) with AUTH support.
type SubmissionServer struct {
	pool              *pgxpool.Pool
	logger            *slog.Logger
	addr              string
	listener          net.Listener
	tlsCert           string
	tlsKey            string
	toggles           *toggle.FeatureFlags
	maxConns          int
	userTracker       tlsutil.ConnTracker
	dispatcher        *webhook.Dispatcher
	threatInterceptor *threat.ThreatInterceptor
	sessionRegistry   *threat.ProtocolSessionRegistry
	putBlob           func(ctx context.Context, key string, data []byte) error // raw-blob store seam (SetBlobStore)
	commitTx          func(context.Context, pgx.Tx) error                      // nil = tx.Commit; narrow failure-boundary test seam
}

func (s *SubmissionServer) commit(ctx context.Context, tx pgx.Tx) error {
	if s.commitTx != nil {
		return s.commitTx(ctx, tx)
	}
	return tx.Commit(ctx)
}

func NewSubmissionServer(pool pgxutil.WorkerPool, addr string, logger *slog.Logger, toggles *toggle.FeatureFlags, dispatcher *webhook.Dispatcher, threatInterceptor *threat.ThreatInterceptor) *SubmissionServer {
	return &SubmissionServer{pool: pool.Pool, addr: addr, logger: logger, toggles: toggles, dispatcher: dispatcher, threatInterceptor: threatInterceptor}
}

// SetTLS enables STARTTLS for this server (stores cert file paths).
func (s *SubmissionServer) SetTLS(certFile, keyFile string) {
	s.tlsCert = certFile
	s.tlsKey = keyFile
}

// SetMaxConns caps the number of simultaneous connections. 0 = unlimited.
func (s *SubmissionServer) SetMaxConns(n int) { s.maxConns = n }

// SetPerUserMaxConns caps connections per authenticated user. 0 = unlimited.
func (s *SubmissionServer) SetPerUserMaxConns(n int) { s.userTracker.SetMaxConns(n) }

// SetSessionRegistry enables immediate closure of authenticated submission
// connections when revoke_user_sessions commits.
func (s *SubmissionServer) SetSessionRegistry(registry *threat.ProtocolSessionRegistry) {
	s.sessionRegistry = registry
}

// Start begins accepting submission connections.
func (s *SubmissionServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("submission listen %s: %w", s.addr, err)
	}
	if s.maxConns > 0 {
		ln = tlsutil.LimitListener(ln, s.maxConns)
	}
	s.listener = ln
	s.logger.Info("SMTP submission server started", "addr", s.addr, "max_conns", s.maxConns)

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
				s.logger.Warn("submission accept error", "error", err)
				continue
			}
			go s.handleConn(ctx, conn)
		}
	}()

	return nil
}

func (s *SubmissionServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	c := &subConnState{
		srv:    s,
		conn:   conn,
		tp:     textproto.NewConn(conn),
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

	c.serveCommands(ctx)
}

// serveCommands runs the RFC 5321 command loop on an established submission
// connection: greeting, bounded command-line reads, and per-command dispatch.
// Extracted from handleConn so the intake bounds are testable without a DB
// pool (per-user slot/session release stays with handleConn).
func (c *subConnState) serveCommands(ctx context.Context) {
	c.reply(220, "mailserver ESMTP submission ready")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// RFC 5321 §4.5.3.2.6: 5-minute command timeout
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		// Bounded command/AUTH intake (resource-exhaustion.smtp-auth-line):
		// textproto.ReadLine carries no per-line cap on this toolchain, so an
		// unauthenticated sender could previously park an arbitrarily large
		// line (a giant AUTH PLAIN argument included) in connection memory.
		// The cap is enforced here: overlong lines are answered 500 5.5.2 and
		// skipped with the stream left in sync.
		line, err := readBoundedLine(c.tp.R, smtpMaxCommandLineBytes)
		if err != nil {
			if errors.Is(err, errCommandLineTooLong) {
				c.reply(500, "5.5.2 Line too long")
				continue
			}
			if os.IsTimeout(err) {
				c.reply(421, "4.4.2 Connection timed out")
			}
			return
		}

		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)

		switch cmd {
		case "EHLO":
			fmt.Fprintf(c.conn, "250-%s\r\n", "mailserver")
			fmt.Fprintf(c.conn, "250-%s\r\n", "PIPELINING")
			fmt.Fprintf(c.conn, "250-%s\r\n", "8BITMIME")
			fmt.Fprintf(c.conn, "250-ENHANCEDSTATUSCODES\r\n")
			if c.srv.tlsCert != "" && c.tlsMode == tlsNone {
				fmt.Fprintf(c.conn, "250-STARTTLS\r\n")
			}
			// AUTH is advertised ONLY on an active TLS session: a cert-less MSA
			// (no STARTTLS available) must never advertise plaintext AUTH, and a
			// cert-capable MSA must not invite AUTH before the upgrade.
			if c.tlsMode == tlsStartTLS {
				fmt.Fprintf(c.conn, "250-%s\r\n", "AUTH LOGIN PLAIN")
			}
			fmt.Fprintf(c.conn, "250 %s\r\n", "SIZE 157286400")
		case "STARTTLS":
			if c.tlsMode == tlsStartTLS {
				c.reply(503, "TLS already active")
				return
			}
			if c.srv.tlsCert == "" {
				c.reply(503, "STARTTLS not available")
				return
			}
			c.reply(220, "Ready to start TLS")
			cert, err := tls.LoadX509KeyPair(c.srv.tlsCert, c.srv.tlsKey)
			if err != nil {
				c.srv.logger.Error("submission STARTTLS cert load failed", "error", err)
				c.reply(454, "TLS not available due to server error")
				return
			}
			tlsConn := tls.Server(c.conn, &tls.Config{
				Certificates:     []tls.Certificate{cert},
				MinVersion:       tls.VersionTLS12,
				CipherSuites:     tlsutil.DefaultCipherSuites,
				CurvePreferences: tlsutil.DefaultCurves,
			})
			if err := tlsConn.Handshake(); err != nil {
				c.srv.logger.Error("submission STARTTLS handshake failed", "error", err)
				return
			}
			c.conn = tlsConn
			c.tp = textproto.NewConn(tlsConn)
			c.tlsMode = tlsStartTLS
			c.reset()
		case "AUTH":
			// Keyed on ACTIVE TLS state, never on tlsCert presence: a cert-less
			// MSA can never upgrade, so plaintext AUTH must be refused there too
			// (credentials would otherwise cross the wire in the clear).
			if c.tlsMode != tlsStartTLS {
				c.reply(530, "Must issue STARTTLS first")
				return
			}
			c.handleAuth(ctx, arg)
		case "MAIL":
			c.handleMail(arg)
		case "RCPT":
			c.handleRcpt(arg)
		case "DATA":
			if !c.handleData(ctx) {
				return
			}
		case "RSET":
			c.reset()
			c.reply(250, "OK")
		case "QUIT":
			c.reply(221, "Bye")
			return
		case "NOOP":
			c.reply(250, "OK")
		default:
			c.reply(500, "Command not recognized")
		}
	}
}

type subConnState struct {
	srv            *SubmissionServer
	conn           net.Conn
	tp             *textproto.Conn
	authed         bool
	userID         int64
	userEmail      string
	release        func()
	sessionRelease func()
	from           string
	to             []string
	data           []byte
	tlsMode        tlsMode
}

func (c *subConnState) reply(code int, msg string) {
	fmt.Fprintf(c.conn, "%d %s\r\n", code, msg)
}

func (c *subConnState) trackProtocolSession(userID int64, authenticatedAt time.Time) {
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

func (c *subConnState) reset() {
	c.from = ""
	c.to = nil
	c.data = nil
}

func (c *subConnState) handleAuth(ctx context.Context, arg string) {
	parts := strings.Fields(arg)
	if len(parts) == 0 {
		c.reply(501, "Syntax error")
		return
	}

	mech := strings.ToUpper(parts[0])
	switch mech {
	case "PLAIN":
		c.authPlain(ctx, strings.TrimPrefix(arg, "PLAIN "))
	case "LOGIN":
		c.authLogin(ctx)
	default:
		c.reply(504, "Mechanism not supported")
	}
}

func (c *subConnState) authPlain(ctx context.Context, b64 string) {
	if b64 == "" {
		c.reply(334, " ")
		line, _ := c.tp.ReadLine()
		b64 = line
	}
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		c.reply(501, "Invalid base64")
		return
	}
	// RFC 4616 §2: authzid\0authcid\0passwd
	parts := strings.Split(string(data), "\x00")
	if len(parts) != 3 {
		c.reply(501, "Invalid PLAIN format")
		return
	}
	// RFC 4616 §2: If authzid is non-empty and differs from authcid,
	// the server must reject (delegation not supported for SMTP AUTH).
	if parts[0] != "" && parts[0] != parts[1] {
		c.reply(501, "Authorization identity not supported")
		return
	}
	c.checkPassword(ctx, parts[1], parts[2])
}

func (c *subConnState) authLogin(ctx context.Context) {
	c.reply(334, base64.StdEncoding.EncodeToString([]byte("Username:")))
	userB64, _ := c.tp.ReadLine()
	username, _ := base64.StdEncoding.DecodeString(userB64)

	c.reply(334, base64.StdEncoding.EncodeToString([]byte("Password:")))
	passB64, _ := c.tp.ReadLine()
	password, _ := base64.StdEncoding.DecodeString(passB64)

	c.checkPassword(ctx, string(username), string(password))
}

func (c *subConnState) checkPassword(ctx context.Context, email, password string) {
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
			Protocol:  threat.ProtocolSMTP,
			UserAgent: "",
		}
		result, _, delay := c.srv.threatInterceptor.Intercept(ctx, &meta)
		switch result {
		case threat.ActionReject:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, c.srv.toggles)
			c.reply(421, "Authentication temporarily unavailable")
			return
		case threat.ActionTarpitted:
			if delay > 0 {
				time.Sleep(delay)
			}
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: email,
				IPAddress: clientIP,
			}, c.srv.toggles)
			c.reply(421, "Authentication temporarily unavailable")
			return
		case threat.ActionRateLimited:
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "rate_limit", Email: email,
				IPAddress: clientIP,
			}, c.srv.toggles)
			c.reply(421, "Too many authentication attempts — try again later")
			return
		}
	}
	// ---- END NEW ----

	// NOTE: The ad-hoc rate_limit_check calls below are superseded by the unified
	// threat interceptor above. They remain as defense-in-depth until the interceptor
	// is confirmed active in production.
	// Rate limit by IP
	var allowed bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT rate_limit_check('ip:' || $1, 10, 5, 30)`,
		clientIP,
	).Scan(&allowed)
	if err == nil && !allowed {
		c.reply(421, "Too many authentication attempts — try again later")
		return
	}

	// Rate limit by account
	err = c.srv.pool.QueryRow(ctx,
		`SELECT rate_limit_check('acct:' || lower($1), 5, 15, 60)`,
		email,
	).Scan(&allowed)
	if err == nil && !allowed {
		c.reply(421, "Too many authentication attempts — try again later")
		return
	}

	// Try app password first
	if user, err := pwhash.CheckAppPassword(ctx, c.srv.pool, email, password); err == nil {
		c.authed = true
		c.userID = user.ID
		c.userEmail = user.Email
		if c.srv.threatInterceptor != nil {
			meta.AppPassword = true
			c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
			meta.UserID = user.ID
			meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
			meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
			if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); res == threat.ActionReject {
				pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
					UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
					Email: email, IPAddress: clientIP,
				}, c.srv.toggles)
				c.authed = false
				c.userID = 0
				c.userEmail = ""
				c.reply(535, "5.7.0 Access blocked by policy: "+reason)
				return
			}
		}

		c.srv.dispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
			"email":    email,
			"provider": "app_password",
			"ip":       clientIP,
		}))

		meta.DeviceBound = false // ponytail: SMTP cannot present a device proof header; CA DeviceBound=false → legacy path
		// Check per-user connection limit
		release, err := c.srv.userTracker.TryAcquire(user.ID)
		if err != nil {
			c.reply(550, "Too many connections from this account")
			c.authed = false
			c.userID = 0
			c.userEmail = ""
			return
		}
		c.release = release
		c.trackProtocolSession(user.ID, authenticatedAt)
		c.reply(235, "Authentication successful")
		return
	}

	user, err := auth.CheckPassword(ctx, c.srv.pool, email, password)
	if err != nil {
		pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "bcrypt", Email: email,
			IPAddress: clientIP,
		}, c.srv.toggles)
		c.srv.dispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLoginFailed, map[string]interface{}{
			"email":    email,
			"provider": "bcrypt",
			"ip":       clientIP,
		}))
		if c.srv.threatInterceptor != nil {
			c.srv.threatInterceptor.RecordResult(ctx, &meta, false, 0)
		}
		c.reply(535, "Authentication failed")
		return
	}
	pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "bcrypt", Email: email,
		IPAddress: clientIP,
	}, c.srv.toggles)
	c.srv.dispatcher.Dispatch(ctx, wh.NewCloudEvent("mailserver/auth", wh.EventAuthLogin, map[string]interface{}{
		"email":    email,
		"provider": "bcrypt",
		"ip":       clientIP,
	}))
	c.authed = true
	c.userID = user.ID
	if c.srv.threatInterceptor != nil {
		c.srv.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
		meta.UserID = user.ID
		meta.GroupIDs = threat.ResolveUserGroups(ctx, c.srv.pool, user.ID)
		meta.RoleGroupIDs = threat.ResolveRoleGroups(ctx, c.srv.pool, user.ID)
		if res, reason := c.srv.threatInterceptor.EvaluatePostAuth(ctx, &meta); res == threat.ActionReject {
			pwhash.LogAuthEvent(ctx, c.srv.pool, pwhash.AuthEvent{
				UserID: &user.ID, Event: "login_failed", Provider: "conditional_access",
				Email: email, IPAddress: clientIP,
			}, c.srv.toggles)
			c.authed = false
			c.userID = 0
			c.reply(535, "5.7.0 Access blocked by policy: "+reason)
			return
		}
	}

	meta.DeviceBound = false // ponytail: SMTP cannot present a device proof header; CA DeviceBound=false → legacy path

	// Check per-user connection limit
	release, err := c.srv.userTracker.TryAcquire(user.ID)
	if err != nil {
		c.reply(550, "Too many connections from this account")
		c.authed = false
		c.userID = 0
		return
	}
	c.release = release
	c.trackProtocolSession(user.ID, authenticatedAt)
	c.reply(235, "Authentication successful")
}

func (c *subConnState) handleMail(arg string) {
	if !c.authed {
		c.reply(530, "Authentication required")
		return
	}
	if !strings.HasPrefix(strings.ToUpper(arg), "FROM:") {
		c.reply(501, "Syntax error")
		return
	}
	c.from = extractAddr(arg[5:])

	// Verify the envelope-from address belongs to the authenticated user.
	var allowed bool
	err := c.srv.pool.QueryRow(context.Background(),
		`SELECT EXISTS(
			SELECT 1 FROM mailboxes mb
			LEFT JOIN aliases a ON a.mailbox_id = mb.id AND lower(a.email) = lower($1)
			WHERE mb.user_id = $2 AND mailbox_lifecycle_access_allowed(mb.id)
			  AND (lower(mb.email) = lower($1) OR a.id IS NOT NULL)
		)`,
		c.from, c.userID,
	).Scan(&allowed)
	if err != nil || !allowed {
		c.reply(553, "Envelope-from address not authorized for this user")
		c.from = ""
		return
	}

	c.reply(250, "OK")
}

func (c *subConnState) handleRcpt(arg string) {
	if !c.authed {
		c.reply(530, "Authentication required")
		return
	}
	if !strings.HasPrefix(strings.ToUpper(arg), "TO:") {
		c.reply(501, "Syntax error")
		return
	}
	if c.from == "" {
		c.reply(503, "Need MAIL before RCPT")
		return
	}
	addr := extractAddr(arg[3:])
	if len(c.to) >= maxRecipients {
		c.reply(452, "Too many recipients")
		return
	}
	c.to = append(c.to, addr)
	c.reply(250, "OK")
}

func (c *subConnState) handleData(ctx context.Context) bool {
	if !c.authed {
		c.reply(530, "Authentication required")
		return true
	}
	if c.from == "" || len(c.to) == 0 {
		c.reply(503, "Need MAIL and RCPT before DATA")
		return true
	}

	c.reply(354, "Start mail input; end with <CRLF>.<CRLF>")

	// Strict CRLF dot framing (same intake rule as the inbound server — see
	// strictDotReader): a bare ".\n" never terminates DATA; the frame is
	// refused 5xx and the connection closed because the sender controls the
	// remaining stream and the frame cannot resynchronize.
	reader := &strictDotReader{br: c.tp.R}
	const maxSize = 157286400 // 150 MiB, matches EHLO SIZE advertisement
	data, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		code, msg, terminate := dataReadFailure(err)
		c.reply(code, msg)
		return !terminate
	}
	if len(data) > maxSize {
		c.reply(552, "Message size exceeds fixed maximum message size")
		return true
	}
	if err := validateLineLengths(data); err != nil {
		c.reply(550, fmt.Sprintf("Line too long: %s", err.Error()))
		return true
	}

	c.data = data
	// submit() owns every non-success reply (precise 5xx/4xx); only acknowledge 250
	// when it actually queued the message. An unconditional 250 here corrupted the
	// wire: the mailbox-resolve failure path returned with no reply (250 → silent mail
	// loss), and every 5xx failure path got a stray trailing 250 (two responses for
	// one DATA, desyncing the protocol and masking the T9 quota/DLP/send-as 5xx).
	ok := c.submit(ctx)
	c.reset()
	if ok {
		c.reply(250, "OK")
	}
	return true
}

// submit attempts to queue the buffered message. It returns true only when the
// send reducer committed; on any failure it sends the appropriate 4xx/5xx reply
// itself and returns false (so handleData must NOT add its own reply).
func (c *subConnState) submit(ctx context.Context) bool {
	msg := string(c.data)
	subject := extractHeader(msg, "Subject")
	messageID := extractHeader(msg, "Message-Id")
	if messageID == "" {
		hostname, _ := getLocalHostname()
		messageID = fmt.Sprintf("<%s@%s>", randomID(), hostname)
	}
	// Add Date: header if missing (RFC 5322 §3.6.1)
	if extractHeader(msg, "Date") == "" {
		msg = "Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" + msg
	}
	// Add Sender: header if From differs from authenticated identity (RFC 5322 §3.6.2)
	if c.userID > 0 {
		_, fromAddr := parseFrom(extractHeader(msg, "From"))
		var authEmail string
		if err := c.srv.pool.QueryRow(ctx,
			`SELECT email FROM users WHERE id = $1`, c.userID,
		).Scan(&authEmail); err == nil && authEmail != "" {
			if !strings.EqualFold(fromAddr, authEmail) && extractHeader(msg, "Sender") == "" {
				msg = "Sender: <" + authEmail + ">\r\n" + msg
			}
		}
	}
	inReplyTo := extractHeader(msg, "In-Reply-To")
	references := extractHeader(msg, "References")

	toAddrs := parseAddressList(extractHeader(msg, "To"))
	ccAddrs := parseAddressList(extractHeader(msg, "Cc"))
	bccAddrs := parseAddressList(extractHeader(msg, "Bcc"))
	hasAttachments := strings.Contains(msg, "Content-Disposition: attachment")

	// Content-addressed raw_ref over the FIXED-UP wire (msg carries the
	// prepended Date/Sender headers; hashing c.data would break key==sha(content)).
	hash := sha256.Sum256([]byte(msg))
	rawRef := "blobs/" + hex.EncodeToString(hash[:])

	// Get primary mailbox for the user
	mailboxID, err := identity.ResolvePrimaryMailbox(ctx, c.srv.pool, c.userID)
	if err != nil {
		c.srv.logger.Error("primary mailbox lookup failed", "user_id", c.userID, "error", err)
		// 451 (transient): a DB blip is retryable, and a genuinely missing primary
		// mailbox surfaces as a delivery warning to the user — either is correct mail
		// handling. The old silent return let handleData reply 250 and drop the mail.
		c.reply(451, "4.3.0 Mailbox temporarily unavailable")
		return false
	}

	fromName, fromAddr := parseFrom(extractHeader(msg, "From"))
	if fromAddr == "" {
		// Use user's email as From
		if err := c.srv.pool.QueryRow(ctx,
			`SELECT email, display_name FROM users WHERE id = $1`,
			c.userID,
		).Scan(&fromAddr, &fromName); err != nil {
			c.reply(554, "5.3.0 Failed to resolve sender address")
			return false
		}
	}

	// Store the raw wire under rawRef BEFORE send() writes any row referencing
	// it. Pre-fix nothing was ever stored: the outbound drain GetObject'ed a
	// nonexistent key (every MSA external send bounced) and the Sent copy's
	// raw_ref dangled for .eml download / trainer / ediscovery. Fail closed on
	// a store error — a 451 retry beats enqueueing an undeliverable message.
	if c.srv.putBlob != nil {
		if err := c.srv.putBlob(ctx, rawRef, []byte(msg)); err != nil {
			c.srv.logger.Error("raw blob store failed", "key", rawRef, "error", err)
			c.reply(451, "4.3.0 Temporary storage failure")
			return false
		}
	}

	tx, err := c.srv.pool.Begin(ctx)
	if err != nil {
		c.srv.logger.Error("send transaction begin failed", "error", err)
		c.reply(554, "5.3.0 Internal error")
		return false
	}
	defer tx.Rollback(ctx)

	setIfDisabled := func(key, varName string) {
		if !c.srv.toggles.IsEnabled(key) {
			tx.Exec(ctx, "SET LOCAL "+varName+" = 'true'")
		}
	}
	setIfDisabled(toggle.FeatureRulesEngine, "app.skip_rules")
	setIfDisabled(toggle.FeatureDLP, "app.skip_dlp")
	setIfDisabled(toggle.FeatureJournaling, "app.skip_journaling")
	setIfDisabled(toggle.FeatureRetention, "app.skip_retention")
	// Explicitly set app.skip_fts in both directions so the trigger
	// always has a known value (PostgreSQL defaults to 'true' when unset).
	if c.srv.toggles.IsEnabled(toggle.FeatureFullTextSearch) {
		tx.Exec(ctx, "SET LOCAL app.skip_fts = 'false'")
	} else {
		tx.Exec(ctx, "SET LOCAL app.skip_fts = 'true'")
	}
	setIfDisabled(toggle.FeatureMailboxAuditLog, "app.skip_audit")

	envelopeRecipients, err := json.Marshal(c.to)
	if err != nil {
		c.srv.logger.Error("submission envelope encode failed", "error", err)
		c.reply(554, "5.3.0 Internal error")
		return false
	}
	var sentID, subjectUserID, subjectMailboxID *int64
	var publicationEnrolled bool
	err = tx.QueryRow(ctx,
		`SELECT message_id,subject_user_id,subject_mailbox_id,publication_enrolled
		   FROM smtp_submission_send($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		c.userID, mailboxID, rawRef, messageID, fromAddr,
		toAddrs, ccAddrs, bccAddrs,
		subject, inReplyTo, references,
		extractBodyText(msg), extractBodyHTML(msg),
		int64(len(msg)), hasAttachments, nil, envelopeRecipients,
	).Scan(&sentID, &subjectUserID, &subjectMailboxID, &publicationEnrolled)
	if err != nil {
		c.srv.logger.Error("send failed", "error", err)
		// T9: classify the reducer BZ code so a permanent failure (sending-quota
		// reached, DLP/policy block, send-as unauthorized) returns a precise 5xx
		// the submitting client can surface to the user, instead of the old
		// blanket 554 that hid which condition fired. A non-BZ error (an infra
		// blip with no BZ code) preserves the existing generic 554 reply.
		if reply, ok := classifyReducerReply(err); ok {
			c.reply(reply.code, reply.msg)
			return false
		}
		c.reply(554, "5.3.0 Failed to send message")
		return false
	}
	if err := c.srv.commit(ctx, tx); err != nil {
		c.srv.logger.Error("send commit failed", "error", err)
		c.reply(554, "5.3.0 Internal error")
		return false
	}
	// A NULL send result is accepted-and-held, not committed mail.sent.  The old
	// Exec path discarded that distinction and emitted a false event.  OFF-mode
	// compatibility is now scoped to the reducer-derived mailbox after commit.
	if sentID != nil && !publicationEnrolled && subjectUserID != nil && subjectMailboxID != nil && c.srv.dispatcher != nil {
		for _, rcptAddr := range c.to {
			c.srv.dispatcher.DispatchForMailbox(ctx, *subjectUserID, *subjectMailboxID,
				wh.NewCloudEvent("mailserver/gateway", wh.EventMailSent, map[string]interface{}{
					"from": fromAddr,
					"to":   rcptAddr,
				}))
		}
	}
	return true
}
