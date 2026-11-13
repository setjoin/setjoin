package ldap

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	ldapserver "github.com/vjeantet/ldapserver"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
)

// Server is a read-only LDAP GAL backed by PostgreSQL.
type Server struct {
	pool              *pgxpool.Pool
	logger            *slog.Logger
	addr              string
	baseDN            string
	domain            string
	tlsConfig         *tls.Config
	startTLS          bool // true = TLS via STARTTLS upgrade; false = implicit TLS or plaintext
	maxConns          int
	baseCtx           context.Context
	threatInterceptor *threat.ThreatInterceptor

	// Admission control (see admission.go): per-connection and pool-wide caps
	// on concurrent in-flight LDAP work, applied before the dependency's
	// per-request goroutine is allocated (per-connection read-path grants) and
	// before handler work runs (pool-wide). SetMaxInflightPerConn/
	// SetMaxInflightTotal override the defaults and must be called before
	// Start. admission is built in NewServer, installed in Start, and exposed
	// for monitoring/test observation only.
	maxInflightPerConn int
	maxInflightTotal   int
	admission          *admissionLimiter

	// innerHandler, when non-nil, replaces the route mux as the handler behind
	// the admission gate. Test-only seam; always nil in production.
	innerHandler ldapserver.Handler
}

// BoundPrincipal is the authenticated identity carried by one LDAP connection.
// A successful password check is the only minting path; directory handlers use
// the user ID to derive the canonical caller mailbox themselves.
type BoundPrincipal struct {
	UserID int64
}

// NewServer creates an LDAP GAL server.
func NewServer(pool *pgxpool.Pool, addr, domain string, logger *slog.Logger, threatInterceptor *threat.ThreatInterceptor) *Server {
	return &Server{
		pool:               pool,
		logger:             logger,
		addr:               addr,
		baseDN:             buildBaseDN(domain),
		domain:             domain,
		threatInterceptor:  threatInterceptor,
		maxInflightPerConn: DefaultMaxInflightPerConn,
		maxInflightTotal:   DefaultMaxInflightTotal,
		admission:          newAdmissionLimiter(DefaultMaxInflightPerConn, DefaultMaxInflightTotal),
	}
}

// SetTLS enables implicit TLS (LDAPS). Returns error if cert loading fails.
func (s *Server) SetTLS(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		s.logger.Warn("ldap tls load failed", "error", err)
		return err
	}
	s.tlsConfig = &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     tlsutil.DefaultCipherSuites,
		CurvePreferences: tlsutil.DefaultCurves,
	}
	return nil
}

// EnableStartTLS loads TLS certificates and enables STARTTLS upgrade on plaintext connections.
// Unlike SetTLS (implicit LDAPS), this keeps the listener plaintext and upgrades per-connection.
func (s *Server) EnableStartTLS(certFile, keyFile string) error {
	if err := s.SetTLS(certFile, keyFile); err != nil {
		return err
	}
	s.startTLS = true
	return nil
}

// SetMaxConns caps the number of simultaneous connections. 0 = unlimited.
func (s *Server) SetMaxConns(n int) { s.maxConns = n }

// SetMaxInflightPerConn caps concurrent in-flight LDAP operations per
// connection; excess pipelined requests are shed with LDAPResultBusy at the
// server boundary. 0 restores the DefaultMaxInflightPerConn default. Must be
// called before Start: the caps are baked into the admission limiter's slot
// channels, which the setter rebuilds.
func (s *Server) SetMaxInflightPerConn(n int) {
	if n <= 0 {
		n = DefaultMaxInflightPerConn
	}
	s.maxInflightPerConn = n
	s.admission = newAdmissionLimiter(s.maxInflightPerConn, s.maxInflightTotal)
}

// SetMaxInflightTotal caps concurrent in-flight LDAP operations across all
// connections, protecting the request pool shared with JMAP/IMAP/SMTP.
// 0 restores the DefaultMaxInflightTotal default. Must be called before
// Start: the caps are baked into the admission limiter's slot channels, which
// the setter rebuilds.
func (s *Server) SetMaxInflightTotal(n int) {
	if n <= 0 {
		n = DefaultMaxInflightTotal
	}
	s.maxInflightTotal = n
	s.admission = newAdmissionLimiter(s.maxInflightPerConn, s.maxInflightTotal)
}

// Start runs the LDAP server.
func (s *Server) Start(ctx context.Context) error {
	s.baseCtx = ctx
	routes := ldapserver.NewRouteMux()

	routes.Bind(s.handleBind)
	routes.Search(s.handleSearch)
	routes.Extended(s.handleExtended)
	routes.Abandon(s.handleAbandon)
	routes.Add(s.handleReadOnly)
	routes.Delete(s.handleReadOnly)
	routes.Modify(s.handleReadOnly)
	routes.Compare(s.handleCompare)

	// Admission control wraps the whole route mux at the server boundary:
	// every request (all operations, including unrouted ones) is admitted or
	// shed before any route handler runs. The gate is minted per connection by
	// the library's HandlerSource hook, so per-connection slot state is
	// reclaimed with the connection. server.Handle must NOT be called —
	// NewServerWithHandlerSource panics on a dual registration.
	inner := ldapserver.Handler(routes)
	if s.innerHandler != nil {
		inner = s.innerHandler
	}
	s.admission.base = inner
	server := ldapserver.NewServerWithHandlerSource(s.admission)

	// Server-lifetime goroutine — uses server-level shutdown context.
	go func() {
		<-ctx.Done()
		server.Stop()
	}()

	// Build listener-option chain: TLS wrapping, then connection limiting.
	// The library calls ListenAndServe(addr, opts...) where opts receive the
	// server and can set server.Listener before serve() is called.
	wrap := func(srv *ldapserver.Server) {
		if s.maxConns > 0 {
			srv.Listener = tlsutil.LimitListener(srv.Listener, s.maxConns)
		}
		if s.tlsConfig != nil && !s.startTLS {
			srv.Listener = tls.NewListener(srv.Listener, s.tlsConfig)
		}
		// Admission wraps OUTERMOST (see admission.go): the framing wrapper
		// must see the plaintext BER stream the library reads, so grants land
		// before the library parses and allocates each request goroutine.
		srv.Listener = newAdmissionListener(srv.Listener, s.admission)
	}
	s.logger.Info("ldap starting", "addr", s.addr, "max_conns", s.maxConns, "tls", s.tlsConfig != nil && !s.startTLS, "start_tls", s.startTLS)
	return server.ListenAndServe(s.addr, wrap)
}

// handleBind verifies credentials against PostgreSQL.
func (s *Server) handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	username := string(r.Name())
	password := string(r.AuthenticationSimple())

	// Anonymous bind — not supported for security reasons.
	if username == "" && password == "" {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInappropriateAuthentication)
		w.Write(res)
		return
	}

	// Reject non-TLS binds to prevent credential leakage. The credential must
	// travel over an actual TLS connection — either implicit LDAPS (the listener
	// is TLS-wrapped) or a completed STARTTLS upgrade (handleExtended swaps in a
	// *tls.Conn). Checking server config alone is not enough: in STARTTLS mode a
	// client that never issued the STARTTLS op still has a plaintext conn, so we
	// must assert the connection state, not just that TLS is configured. The
	// assertion targets the transport under the admission framing wrapper.
	if _, ok := transportConn(m.Client.GetConn()).(*tls.Conn); !ok {
		s.logger.Warn("ldap bind rejected: bind attempted over a non-TLS connection", "user", username)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInappropriateAuthentication)
		w.Write(res)
		return
	}

	// Extract email from DN or use directly
	email := username
	if strings.Contains(username, "=") {
		parts := strings.Split(username, ",")
		if len(parts) > 0 && strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
			local := strings.TrimPrefix(parts[0], "cn=")
			local = strings.TrimPrefix(local, "CN=")
			email = local + "@" + s.domain
		}
	}

	ctx, cancel := context.WithTimeout(s.baseCtx, 15*time.Second)
	defer cancel()

	var meta threat.ConnectionMeta
	if s.threatInterceptor != nil {
		clientIP := "unknown"
		if addr, ok := m.Client.GetConn().RemoteAddr().(*net.TCPAddr); ok {
			clientIP = addr.IP.String()
		}
		meta = threat.ConnectionMeta{
			SourceIP:  clientIP,
			Username:  email,
			Protocol:  "ldap",
			UserAgent: "",
		}
		result, _, delay := s.threatInterceptor.Intercept(ctx, &meta)
		switch result {
		case threat.ActionReject, threat.ActionTarpitted:
			if delay > 0 {
				time.Sleep(delay)
			}
			pwhash.LogAuthEvent(ctx, s.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "threat", Email: username,
				IPAddress: clientIP,
			}, nil)
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
			w.Write(res)
			return
		case threat.ActionRateLimited:
			pwhash.LogAuthEvent(ctx, s.pool, pwhash.AuthEvent{
				Event: "login_failed", Provider: "rate_limit", Email: username,
				IPAddress: clientIP,
			}, nil)
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
			w.Write(res)
			return
		}
	}

	user, err := auth.CheckPassword(ctx, s.pool, email, password)
	if err != nil {
		if s.threatInterceptor != nil {
			s.threatInterceptor.RecordResult(ctx, &meta, false, 0)
		}
		pwhash.LogAuthEvent(ctx, s.pool, pwhash.AuthEvent{
			Event: "login_failed", Provider: "ldap", Email: username,
			IPAddress: m.Client.GetConn().RemoteAddr().String(),
		}, nil)
		s.logger.Warn("ldap bind failed", "email", email)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		w.Write(res)
		return
	}

	if s.threatInterceptor != nil {
		s.threatInterceptor.RecordResult(ctx, &meta, true, user.ID)
	}
	pwhash.LogAuthEvent(ctx, s.pool, pwhash.AuthEvent{
		UserID: &user.ID, Event: "login", Provider: "ldap", Email: user.Email,
		IPAddress: m.Client.GetConn().RemoteAddr().String(),
	}, nil)

	// Carry the authenticated identity, not a bool-only marker: people searches
	// need the caller's canonical primary mailbox for directory_visible_users.
	m.Client.SetData(BoundPrincipal{UserID: user.ID})

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
}

// handleExtended processes LDAP Extended operations, including STARTTLS (RFC 4513 §3).
func (s *Server) handleExtended(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetExtendedRequest()
	if r.RequestName() == ldapserver.NoticeOfStartTLS {
		if s.tlsConfig == nil {
			res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultUnwillingToPerform)
			w.Write(res)
			return
		}
		// Upgrade connection to TLS BEFORE sending success response
		rawConn := m.Client.GetConn()
		// The admission framing wrapper must see plaintext BER. Flip it to raw
		// pass-through for the handshake, then re-arm a fresh wrapper around
		// the TLS transport (sharing the grant budget) via SetConn — without
		// the re-arm, STARTTLS connections would lose their pre-dispatch
		// admission bound for the rest of the session.
		admitted, isAdmitted := rawConn.(*admissionConn)
		if isAdmitted {
			admitted.beginTLSUpgrade()
		}
		tlsConn := tls.Server(rawConn, s.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			s.logger.Warn("STARTTLS handshake failed", "error", err)
			res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultOperationsError)
			w.Write(res)
			return
		}
		if isAdmitted {
			rawConn = admitted.rearmTLS(tlsConn)
		} else {
			rawConn = tlsConn
		}
		m.Client.SetConn(rawConn)
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess)
		res.SetResponseName(ldapserver.NoticeOfStartTLS)
		w.Write(res)
		return
	}
	res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultUnwillingToPerform)
	w.Write(res)
}

// handleAbandon processes LDAP Abandon requests (RFC 4511 §4.11).
// The library handles the protocol level; individual search goroutines
// must check m.Done to actually stop processing.
func (s *Server) handleAbandon(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// No-op: library calls requestToAbandon.Abandon() which signals Done channel.
	// Search loops check msg.Done to stop processing.
}

// handleReadOnly rejects write operations (Add, Delete, Modify, ModifyDN).
// The LDAP GAL is intentionally read-only; provisioning happens via the admin
// console or AD sync. Requests for unsupported ModifyDN are caught by the
// library's default NotFound handler (returns LDAPResultUnwillingToPerform).
func (s *Server) handleReadOnly(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage("LDAP GAL is read-only; use admin console or JMAP for provisioning")
	w.Write(res)
}
