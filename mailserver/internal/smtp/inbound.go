package smtp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"
	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"

	wh "setjoin.com/shared/webhook"
)

// deliveryResult holds per-recipient DMARC results from evaluateDMARC.
type deliveryResult struct {
	dmarcQuarantine bool
}

// ErrDMARCReject is returned when DMARC policy is p=reject.
var ErrDMARCReject = errors.New("smtp: message rejected per DMARC policy")

// ErrGroupModerationReject is returned by the inbound delivery seam when a sender
// is not permitted to post to a distribution group (group with
// allow_external_senders=false + an external sender). handleData maps it to a 5xx
// SMTP rejection — a hard anti-spam block, no message held.
var ErrGroupModerationReject = errors.New("smtp: sender not permitted to post to this group")

// defaultPerIPConnPerMin caps inbound MTA connections accepted from a single
// remote IP within a one-minute sliding window. The old per-server
// perIPRateLimit field was removed; this is the package-level limit.
const defaultPerIPConnPerMin = 20

// smtpMaxCommandLineBytes bounds one SMTP command line (command + arguments,
// without CRLF) at intake. The RFC 5321 §4.5.3.1.4 floor is 512 octets
// including CRLF; 4096 matches net/textproto's historical maxLineLength and
// leaves headroom for long EHLO/MAIL arguments (Postfix accepts 2048). The
// bound is load-bearing, not cosmetic: this toolchain's textproto.ReadLine
// carries NO per-line cap (readLineSlice(-1)), so an unauthenticated sender
// could previously park an arbitrarily large line in connection memory per
// pipelined command.
const smtpMaxCommandLineBytes = 4096

// errCommandLineTooLong is returned by readBoundedLine when a single command
// line exceeds smtpMaxCommandLineBytes. The physical line is fully drained
// before the error is returned, so the command stream stays in sync and the
// connection can continue with the next command.
var errCommandLineTooLong = errors.New("smtp: command line exceeds the fixed maximum length")

// readBoundedLine reads one logical line from br (bufio line semantics: both
// CRLF and bare-LF terminated) and refuses lines longer than max. Memory is
// bounded even on refusal: once the cap is exceeded no further bytes are
// retained, but the remainder of the physical line is still drained so the
// next read starts at the next command (a pipelining peer stays framed).
func readBoundedLine(br *bufio.Reader, max int) (string, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return "", err
		}
		if !tooLong {
			buf = append(buf, chunk...)
			if len(buf) > max {
				tooLong = true
				buf = nil
			}
		}
		if !isPrefix {
			break
		}
	}
	if tooLong {
		return "", errCommandLineTooLong
	}
	return string(buf), nil
}

// strictDotReader is the CRLF-strict DATA intake replacing net/textproto's
// DotReader on both SMTP servers. It reproduces the stdlib dotReader state
// machine byte for byte (leading-dot unstuffing, CRLF→LF line normalization,
// lone-CR passthrough — go/src/net/textproto/read.go) with ONE tightened
// branch: the DATA frame ends only at the RFC 5321 §4.1.1.4 terminator
// CRLF.CRLF. The stdlib reader also ends on a bare ".\n" (stateDot + '\n' →
// end), which is the SMTP-smuggling vector (CVE-2023-51764 class): a bare-LF
// terminator lets one sender frame split early and re-enter the command
// stream mid-frame, diverging from strict downstream parsers. Postfix made
// the same refusal the default with smtpd_forbid_bare_lf.
type strictDotReader struct {
	br    *bufio.Reader
	state int
	ended bool
}

const (
	sdBeginLine = iota // beginning of a line: a leading '.' is framing
	sdDot              // saw '.' at beginning of line
	sdDotCR            // saw ".\r" at beginning of line
	sdCR               // saw '\r' (possibly end of line)
	sdData             // inside line data
)

// errBareLFDataTerminator is returned when a DATA frame is terminated by a
// bare-LF "." line. The connection cannot resynchronize (the sender controls
// the remaining stream), so callers reply 5xx and close.
var errBareLFDataTerminator = errors.New("smtp: DATA terminated by bare-LF '.' (RFC 5321 requires CRLF.CRLF; SMTP smuggling refused)")

// Read implements io.Reader with the stdlib DotReader's output transformation
// and the strict terminator above.
func (d *strictDotReader) Read(p []byte) (n int, err error) {
	for n < len(p) && !d.ended {
		c, e := d.br.ReadByte()
		if e != nil {
			if e == io.EOF {
				e = io.ErrUnexpectedEOF
			}
			return n, e
		}
		switch d.state {
		case sdBeginLine:
			switch {
			case c == '.':
				d.state = sdDot
				continue
			case c == '\r':
				d.state = sdCR
				continue
			}
			d.state = sdData
		case sdDot:
			switch {
			case c == '\r':
				d.state = sdDotCR
				continue
			case c == '\n':
				// The stdlib reader ends DATA here; the strict intake refuses
				// — only CRLF.CRLF may terminate (see type comment).
				return n, errBareLFDataTerminator
			}
			d.state = sdData
		case sdDotCR:
			if c == '\n' {
				d.ended = true
				continue
			}
			// Not part of .\r\n: unstuff the leading dot, emit the saved \r.
			// UnreadByte cannot fail here (the just-read byte is buffered),
			// and mid-unstuff there is no useful error path.
			_ = d.br.UnreadByte()
			c = '\r'
			d.state = sdData
		case sdCR:
			if c == '\n' {
				d.state = sdBeginLine
				break // CRLF normalized to LF
			}
			// Not part of \r\n: emit the saved \r.
			// UnreadByte cannot fail here (the just-read byte is buffered),
			// and mid-unstuff there is no useful error path.
			_ = d.br.UnreadByte()
			c = '\r'
			d.state = sdData
		case sdData:
			if c == '\r' {
				d.state = sdCR
				continue
			}
			if c == '\n' {
				d.state = sdBeginLine
			}
		}
		p[n] = c
		n++
	}
	if d.ended {
		err = io.EOF
	}
	return n, err
}

// dataReadFailure maps a DATA-read error to its SMTP reply. terminate reports
// whether the connection must be closed: a refused bare-LF terminator leaves
// the sender in control of the remaining stream, so the frame can never
// resynchronize and the connection ends after the 5xx reply.
func dataReadFailure(err error) (code int, msg string, terminate bool) {
	switch {
	case errors.Is(err, errBareLFDataTerminator):
		return 500, "5.5.2 Bare LF not allowed", true
	case errors.Is(err, errSpoolMemorySaturated):
		return 451, "4.3.1 Mail system full, try again later", false
	default:
		return 451, "Error reading message", false
	}
}

// maxRematerializedSpoolMessages bounds how many spilled (>1 MiB) inbound
// messages may be rematerialized into process memory at once. Worst-case heap
// held by large-message intake is therefore bounded at
// maxRematerializedSpoolMessages × the 150 MiB message cap, instead of
// growing with concurrent connections (the disk spool only deferred the
// allocation before; the read-back rematerialized every spilled message in
// the heap at once).
const maxRematerializedSpoolMessages = 4

// spoolMemoryAdmission gates the spool read-back. Small (in-memory) messages
// never touch it: only messages that actually spilled acquire a slot.
var spoolMemoryAdmission = make(chan struct{}, maxRematerializedSpoolMessages)

// spoolAdmissionWait bounds how long a large message waits for a memory slot
// before it is answered 451 4.3.1 (the sending MTA retries). A var so tests
// can shrink it.
var spoolAdmissionWait = 30 * time.Second

// errSpoolMemorySaturated is returned when no rematerialization slot freed up
// within spoolAdmissionWait. It maps to 451 4.3.1 (transient) — never a
// bounce.
var errSpoolMemorySaturated = errors.New("smtp: inbound rematerialization budget saturated")

// acquireSpoolSlot takes one rematerialization slot, waiting at most
// spoolAdmissionWait before giving up.
func acquireSpoolSlot() bool {
	select {
	case spoolMemoryAdmission <- struct{}{}:
		return true
	default:
	}
	select {
	case spoolMemoryAdmission <- struct{}{}:
		return true
	case <-time.After(spoolAdmissionWait):
		return false
	}
}

// spoolMemThreshold is the message size at which spooledRead (helpers.go)
// spills to the temp file. The admission reader below must fire at exactly
// this boundary so the rematerialization slot is held from the moment a
// message is known to spill — i.e. before the disk read-back, which is the
// unbounded step.
const spoolMemThreshold = 1 << 20 // 1 MiB

// spillAdmitReader wraps the DATA stream and acquires one
// spoolMemoryAdmission slot as soon as the stream reaches spoolMemThreshold
// bytes — the point at which spooledRead spills the message to disk and will
// later rematerialize it into the heap. Small (in-memory) messages never
// touch the admission budget. On saturation the reader surfaces
// errSpoolMemorySaturated on the next Read, so the bounded-heap refusal
// propagates through spooledRead unchanged and maps to the transient
// 451 4.3.1 (dataReadFailure). release is nil until a slot is acquired and
// must be deferred by the caller so the rematerialized bytes' whole lifetime
// stays inside the admitted window.
type spillAdmitReader struct {
	r          io.Reader
	read       int
	admitted   bool
	pendingErr error
	release    func()
}

func (a *spillAdmitReader) Read(p []byte) (int, error) {
	if a.pendingErr != nil {
		return 0, a.pendingErr
	}
	n, err := a.r.Read(p)
	a.read += n
	if !a.admitted && err == nil && a.read >= spoolMemThreshold {
		if !acquireSpoolSlot() {
			a.pendingErr = errSpoolMemorySaturated
		} else {
			a.admitted = true
			released := false
			a.release = func() {
				if !released {
					released = true
					<-spoolMemoryAdmission
				}
			}
		}
	}
	return n, err
}

// rateLimitQuerier is the minimal subset of pgx the per-IP connection throttle
// needs. Satisfied by *pgxpool.Pool; narrowed so the throttle decision can be
// unit-tested with a fake row (no live DB).
type rateLimitQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// InboundServer is the MTA (port 25) that accepts mail from remote servers.
type InboundServer struct {
	pool               *pgxpool.Pool
	logger             *slog.Logger
	addr               string
	listener           net.Listener
	tlsCert            string
	tlsKey             string
	tlsConfig          *tls.Config
	clamav             *ClamAVClient
	sandbox            *AttachmentAnalysisPipeline
	toggles            *toggle.FeatureFlags
	maxConns           int32
	connCount          int32
	connSem            chan struct{}
	dispatcher         *webhook.Dispatcher
	jwtSecret          []byte                                                   // HMAC key for link-protect + approval-email tokens
	linkProtectKeys    linkprotect.TokenKeys                                    // versioned key set the rewriter signs with (SetLinkProtect seeds the version-1 default; SetLinkProtectKeys installs the configured rotation set)
	internalDomains    []string                                                 // domains skipped by link-protect rewriter
	tlsEnforce         bool                                                     // require STARTTLS before MAIL FROM
	antiPhishDetectors []PhishDetector                                          // anti-phishing pipeline detectors
	spamStore          spam.ModelSource                                         // per-user FTRL spam model store (LoadModel scoring surface)
	putBlob            func(ctx context.Context, key string, data []byte) error // raw-blob store seam (SetBlobStore)

	// imipRejected counts iMIP messages dropped because the sender failed
	// iTIP role authentication (REPLY attendee / CANCEL organizer; see
	// detectAndProcessIMip and caldav.ErrITIPUnauthenticated).
	imipRejected atomic.Int64

	// Inbound S/MIME trust pools, scoped per recipient domain. Each pool is
	// bundled Mozilla roots ∪ deployment-wide anchors (domain_id IS NULL) ∪ that
	// domain's anchors — so one tenant's imported root cannot grant trust in
	// another. Built lazily, cached per domain_id (0 = no/unknown domain), and
	// cleared on a trust-anchor change (smime_trust_changed). Guarded by smimeMu.
	smimeDomainPools map[int64]*x509.CertPool
	smimeMu          sync.RWMutex
}

// NewInboundServer creates an SMTP inbound server.
func NewInboundServer(pool pgxutil.WorkerPool, addr string, logger *slog.Logger, toggles *toggle.FeatureFlags, dispatcher *webhook.Dispatcher) *InboundServer {
	return &InboundServer{pool: pool.Pool, addr: addr, logger: logger, toggles: toggles, maxConns: 100, connSem: make(chan struct{}, 100), dispatcher: dispatcher, smimeDomainPools: make(map[int64]*x509.CertPool)}
}

// SetLinkProtect configures link protection URL rewriting. The jwtSecret is
// seeded as the VERSION-1 key set — byte-identical to the pre-rotation
// behavior — so a server wired only through this setter rotates nothing.
// SetLinkProtectKeys installs the configured rotation key set (MAILSERVERD-004).
func (s *InboundServer) SetLinkProtect(jwtSecret []byte, internalDomains []string) {
	s.jwtSecret = jwtSecret
	s.linkProtectKeys = linkprotect.TokenKeys{Secret: jwtSecret}
	s.internalDomains = internalDomains
}

// SetLinkProtectKeys installs the versioned link-protect token key set the
// inbound rewriter signs with (MAILSERVERD-004 dual-key overlap rotation):
// freshly minted redirect tokens carry the CURRENT key version, so a rotation
// never orphans tokens already delivered in live mail — the click handler and
// the outbound egress un-rewriter verify against the same configured set.
func (s *InboundServer) SetLinkProtectKeys(keys linkprotect.TokenKeys) {
	s.linkProtectKeys = keys
}

// SetMaxConns configures the maximum concurrent inbound connections (default 100).
func (s *InboundServer) SetMaxConns(n int32) {
	s.maxConns = n
	s.connSem = make(chan struct{}, n)
}

// SetClamAV enables virus scanning via clamd.
func (s *InboundServer) SetClamAV(addr string) {
	if addr != "" {
		s.clamav = NewClamAVClient(addr)
	}
}

// SetSandbox enables attachment behavioral analysis via CAPE sandbox.
func (s *InboundServer) SetSandbox(p *AttachmentAnalysisPipeline) { s.sandbox = p }

// SetTLS enables implicit TLS for this server.
func (s *InboundServer) SetTLS(certFile, keyFile string) {
	s.tlsCert = certFile
	s.tlsKey = keyFile
}

// SetTLSEnforce controls whether STARTTLS is required before MAIL FROM.
// When true, plaintext MAIL FROM is rejected with 530 5.7.0.
func (s *InboundServer) SetTLSEnforce(enforce bool) {
	s.tlsEnforce = enforce
}

// SetAntiPhish configures the anti-phishing detector pipeline.
// Pass nil or empty slice to disable all anti-phishing checks.
func (s *InboundServer) SetAntiPhish(detectors []PhishDetector) {
	s.antiPhishDetectors = detectors
}

// SetSpamStore wires the per-user FTRL spam model store for per-recipient scoring.
func (s *InboundServer) SetSpamStore(store spam.ModelSource) { s.spamStore = store }

// smimeRootsForDomain returns the inbound S/MIME trust pool for a recipient domain:
// bundled Mozilla roots ∪ deployment-wide anchors (domain_id IS NULL) ∪ that domain's
// anchors. Cached per domain; cleared on a trust-anchor change. domainID 0 ⇒ only
// bundle ∪ deployment-wide anchors. Never returns nil — a nil pool would make x509
// fall back to the system store, so on any error we return an empty pool (worst case:
// everything untrusted, delivery proceeds; fail-open).
//
// Round 6 (Astra HOLD): each stored anchor row now authorizes exactly ONE
// fingerprint — the pool loads only certs whose DER fingerprint matches its
// row's, so a multi-cert PEM whose bundle contained unfingerprinted certs (the
// pre-round-6 import stored the complete PEM under the FIRST cert's
// fingerprint) can no longer smuggle extra roots into the pool.
func (s *InboundServer) smimeRootsForDomain(ctx context.Context, domainID int64) *x509.CertPool {
	s.smimeMu.RLock()
	if p, ok := s.smimeDomainPools[domainID]; ok {
		s.smimeMu.RUnlock()
		return p
	}
	s.smimeMu.RUnlock()

	// Build: bundle ∪ deployment-wide (domain_id IS NULL) ∪ this domain's anchors.
	var anchors []smime.AnchorPEM
	rows, err := s.pool.Query(ctx,
		`SELECT cert_pem, fingerprint FROM smime_trust_anchors WHERE domain_id IS NULL OR domain_id = $1`, domainID)
	if err == nil {
		for rows.Next() {
			var p, fp string
			if rows.Scan(&p, &fp) == nil {
				anchors = append(anchors, smime.AnchorPEM{PEM: p, Fingerprint: fp})
			}
		}
		rows.Close()
	} else {
		s.logger.Warn("smime: failed to load trust anchors for domain; verify will use bundle only", "domain_id", domainID, "error", err)
	}
	pool, berr := smime.BuildTrustPool(anchors)
	if berr != nil || pool == nil {
		// BuildTrustPool only fails if even the bundle won't parse; fall back to an
		// empty (non-nil) pool so x509 never reaches the system store.
		pool = x509.NewCertPool()
	}

	s.smimeMu.Lock()
	if s.smimeDomainPools == nil {
		// Literal-constructed servers (tests) start with a nil map; assign
		// lazily instead of panicking on the cache write.
		s.smimeDomainPools = make(map[int64]*x509.CertPool)
	}
	s.smimeDomainPools[domainID] = pool
	s.smimeMu.Unlock()
	return pool
}

// InvalidateSMIMETrustCache clears the per-domain pool cache; call on
// smime_trust_changed so an imported/removed anchor takes effect without restart.
func (s *InboundServer) InvalidateSMIMETrustCache() {
	s.smimeMu.Lock()
	s.smimeDomainPools = make(map[int64]*x509.CertPool)
	s.smimeMu.Unlock()
}

// smimeRevocationOptions builds the inbound S/MIME revocation-policy inputs:
// the configured maximum-staleness ceiling for CRL freshness plus the
// DB-backed admin blocklist (smime_revocation_blocklist — the explicit
// override). No CRL fetcher is wired: the operational CRL source (and its
// caching) is an ops decision, so until one is supplied CRL evidence is
// unavailable and verification stays fail-open; the blocklist alone still
// removes badge, exemption, harvest targeting on entry.
func (s *InboundServer) smimeRevocationOptions() *smime.RevocationOptions {
	return &smime.RevocationOptions{
		MaxStaleness: smime.DefaultMaxCRLStaleness,
		Blocklist:    smime.BlocklistCheckFunc(s.pool),
	}
}

// smimeAnchorTrustScope resolves (round 5, Astra HOLD; round 6 tightens to
// fail-closed) which tenant domains the trust anchor of a VALIDATED S/MIME
// chain actually grants, by the anchor's fingerprint in smime_trust_anchors:
//
//   - SmimeTrustUnrestricted: a bundled public root (standard public S/MIME
//     trust model) or a deployment-wide anchor (domain_id IS NULL — the
//     deployment deliberately granted org-wide trust).
//   - SmimeTrustDomainScoped: a per-tenant anchor; the returned set lists the
//     tenant domains its row grants, and rule (a) requires the signer email's
//     domain to be one of them.
//   - SmimeTrustNone (fail closed): an anchor with NO trust row (removed while
//     a cached pool still held it, or a cert that was never imported), rows
//     whose domain no longer resolves, or any DB lookup ERROR. Round 5
//     degraded every one of these to unrestricted; they now authenticate
//     nothing. An empty anchorPEM (no validated chain) is likewise None.
func (s *InboundServer) smimeAnchorTrustScope(ctx context.Context, anchorPEM string) (caldav.SmimeTrustScope, []string) {
	if anchorPEM == "" {
		return caldav.SmimeTrustNone, nil
	}
	fp, _, _, _, err := smime.Fingerprint(anchorPEM)
	if err != nil || fp == "" {
		s.logger.Warn("smime: cannot fingerprint validated trust anchor; failing closed", "error", err)
		return caldav.SmimeTrustNone, nil
	}
	var deploymentWide bool
	var domains []string
	err = s.pool.QueryRow(ctx,
		`SELECT COALESCE(bool_or(t.domain_id IS NULL), FALSE),
		        COALESCE(array_agg(DISTINCT lower(d.name)) FILTER (WHERE d.name IS NOT NULL), '{}')::text[]
		 FROM smime_trust_anchors t
		 LEFT JOIN domains d ON d.id = t.domain_id
		 WHERE t.fingerprint = $1`,
		fp,
	).Scan(&deploymentWide, &domains)
	if err != nil {
		s.logger.Warn("smime: anchor trust-domain lookup failed; failing closed", "error", err)
		return caldav.SmimeTrustNone, nil
	}
	if deploymentWide {
		return caldav.SmimeTrustUnrestricted, nil
	}
	if len(domains) > 0 {
		return caldav.SmimeTrustDomainScoped, domains
	}
	if smime.IsBundledRoot(fp) {
		return caldav.SmimeTrustUnrestricted, nil
	}
	// A validated anchor with no granting row: never imported, already deleted,
	// or scoped to a domain that no longer exists. Trust nothing.
	s.logger.Warn("smime: validated anchor has no trust row; failing closed", "fingerprint", fp)
	return caldav.SmimeTrustNone, nil
}

// Start begins accepting inbound connections.
func (s *InboundServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("inbound listen %s: %w", s.addr, err)
	}

	if s.tlsCert != "" && s.tlsKey != "" {
		tlsConfig := &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     tlsutil.DefaultCipherSuites,
			CurvePreferences: tlsutil.DefaultCurves,
		}
		cert, err := tls.LoadX509KeyPair(s.tlsCert, s.tlsKey)
		if err != nil {
			s.logger.Error("failed to load TLS certificate", "cert", s.tlsCert, "key", s.tlsKey, "error", err)
			ln.Close()
			return fmt.Errorf("inbound TLS cert load: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		s.tlsConfig = tlsConfig
		ln = tls.NewListener(ln, tlsConfig)
		s.logger.Info("SMTP inbound TLS server started", "addr", s.addr)
	} else {
		s.logger.Info("SMTP inbound server started", "addr", s.addr)
	}

	s.listener = ln

	// ClamAV health check on startup
	if s.clamav != nil {
		if err := s.clamav.Ping(); err != nil {
			s.logger.Warn("clamav health check failed on startup", "error", err)
		} else {
			s.logger.Info("clamav health check passed")
		}
	}

	// Sandbox health check on startup
	if s.sandbox != nil {
		if err := s.sandbox.HealthCheck(ctx); err != nil {
			s.logger.Warn("sandbox health check failed on startup", "error", err)
		} else {
			s.logger.Info("sandbox health check passed", "analyzers", s.sandbox.Len())
		}
	}

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
				s.logger.Warn("inbound accept error", "error", err)
				continue
			}
			// Per-IP rate limit: cap connections per minute from one IP.
			remoteIP := tcpAddrIP(conn)
			if !allowPerIPConn(ctx, s.pool, s.logger, remoteIP, defaultPerIPConnPerMin) {
				fmt.Fprintf(conn, "421 Too many connections from your IP\r\n")
				conn.Close()
				continue
			}
			s.pool.Exec(ctx,
				`INSERT INTO rate_limit_counters (key, count, window_start)
				 VALUES ($1, 1, now())
				 ON CONFLICT (key) DO UPDATE
				 SET count = rate_limit_counters.count + 1,
				     window_start = CASE WHEN rate_limit_counters.window_start < now() - INTERVAL '1 minute'
				                        THEN now() ELSE rate_limit_counters.window_start END`,
				"smtp:conn:"+remoteIP)
			// Connection limit: non-blocking acquire; reject with 421 if full
			select {
			case s.connSem <- struct{}{}:
				atomic.AddInt32(&s.connCount, 1)
				go s.handleConn(ctx, conn)
			default:
				fmt.Fprintf(conn, "421 Too many connections, try again later\r\n")
				conn.Close()
			}
		}
	}()

	return nil
}

// allowPerIPConn reports whether a new inbound connection from remoteIP is
// within the per-minute limit. It reads the live counter for this IP's key and
// compares it against limitPerMin.
//
// Two placeholders: $1 is the numeric limit (compared against the integer
// count), $2 is the text key (matched against rate_limit_counters.key). Binding
// one placeholder to both — as the prior code did — compared the integer count
// against the IP-key string, so the limit never enforced.
//
// Fails OPEN: a DB error (a blip, an unreachable pool) returns true so a
// transient fault never locks out all inbound mail. The error is logged.
func allowPerIPConn(ctx context.Context, q rateLimitQuerier, logger *slog.Logger, remoteIP string, limitPerMin int) bool {
	var allowed bool
	err := q.QueryRow(ctx,
		`SELECT count < $1 FROM rate_limit_counters
		 WHERE key = $2 AND window_start > now() - INTERVAL '1 minute'
		 UNION ALL SELECT TRUE LIMIT 1`,
		limitPerMin, "smtp:conn:"+remoteIP,
	).Scan(&allowed)
	if err != nil {
		// Fail open — a DB blip must not block all inbound mail. Log so the
		// throttle silently degrading is visible.
		if logger != nil {
			logger.Warn("per-IP connection rate-limit check failed (fail-open)", "ip", remoteIP, "error", err)
		}
		return true
	}
	return allowed
}

func (s *InboundServer) handleConn(ctx context.Context, conn net.Conn) {
	defer func() {
		conn.Close()
		<-s.connSem
		atomic.AddInt32(&s.connCount, -1)
	}()

	// Record session for monitoring (unlogged table, survives crash as truncated)
	remoteIP := tcpAddrIP(conn)
	sessionID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s:%d", remoteIP, time.Now().UnixNano()))))[:16]
	s.pool.Exec(ctx,
		`INSERT INTO smtp_sessions (id, remote_ip, state, bytes_received)
		 VALUES ($1, $2, 'greeting', 0)`, sessionID, remoteIP)
	defer s.pool.Exec(context.Background(),
		`DELETE FROM smtp_sessions WHERE id = $1`, sessionID)

	c := &inConnState{
		srv:  s,
		conn: conn,
		tp:   textproto.NewConn(conn),
	}
	// Batch-load release (feature.spam_model_batch_load): returning the
	// connection hands any resident batch models back to the process-wide
	// gauge — the footprint must never outlive the connection that held it.
	defer func() {
		if c.spamBatch != nil {
			c.spamBatch.Reset()
		}
	}()

	c.serveCommands(ctx)
}

// serveCommands runs the RFC 5321 command loop on an established inbound
// connection: greeting, bounded command-line reads, and per-command dispatch.
// Extracted from handleConn so the intake bounds are testable without a DB
// pool (the session-bookkeeping INSERT stays with handleConn).
func (c *inConnState) serveCommands(ctx context.Context) {
	c.reply(220, "mailserver ESMTP")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// RFC 5321 §4.5.3.2.6: 5-minute command timeout
		c.conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		// Bounded command intake (resource-exhaustion.smtp-command-line):
		// textproto.ReadLine carries no per-line cap on this toolchain, so the
		// cap is enforced here — an overlong line is answered 500 5.5.2 and
		// skipped, the stream stays in sync, and no unbounded allocation
		// happens ahead of the check.
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
			c.state = phaseEhlo
			c.helo = arg
			fmt.Fprintf(c.conn, "250-%s\r\n", "mailserver")
			fmt.Fprintf(c.conn, "250-%s\r\n", "PIPELINING")
			fmt.Fprintf(c.conn, "250-%s\r\n", "8BITMIME")
			fmt.Fprintf(c.conn, "250-ENHANCEDSTATUSCODES\r\n")
			if c.srv.tlsConfig != nil {
				fmt.Fprintf(c.conn, "250-STARTTLS\r\n")
			}
			fmt.Fprintf(c.conn, "250 %s\r\n", "SIZE 157286400")
		case "HELO":
			c.state = phaseEhlo
			c.helo = arg
			c.reply(250, "mailserver")
		case "STARTTLS":
			if c.tlsMode == tlsStartTLS {
				c.reply(503, "TLS already active")
				return
			}
			if c.srv.tlsConfig == nil {
				c.reply(503, "STARTTLS not available")
				return
			}
			c.reply(220, "Ready to start TLS")
			tlsConn := tls.Server(c.conn, c.srv.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				c.srv.logger.Error("inbound STARTTLS handshake failed", "error", err)
				return
			}
			c.conn = tlsConn
			c.tp = textproto.NewConn(tlsConn)
			c.tlsMode = tlsStartTLS
			c.reset()
		case "MAIL":
			c.handleMail(arg)
		case "RCPT":
			c.handleRcpt(ctx, arg)
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

// smtpPhase tracks the SMTP command sequence state (RFC 5321 §4.1.4).
type smtpPhase int

const (
	phaseGreeting smtpPhase = iota
	phaseEhlo
	phaseMail
	phaseRcpt
	phaseData
)

// maxRecipients is the maximum number of RCPT TO commands per message.
// RFC 5321 §4.5.3.1.8 requires supporting at least 100 recipients.
const maxRecipients = 1000

// maxDeliveryConcurrency is the per-message cap on concurrent deliver()
// pipelines (the errgroup.SetLimit in handleData). Mirrors the outbound
// worker's delivery semaphore magnitude (outbound.go: sem cap 20) while
// staying conservative for the heavier inbound pipeline (per-recipient scans
// + DB transactions).
const maxDeliveryConcurrency = 8

// tlsMode tracks the TLS negotiation mode of a connection.
type tlsMode int

const (
	tlsNone     tlsMode = iota // plaintext connection
	tlsImplicit                // implicit TLS (port 465)
	tlsStartTLS                // upgraded via STARTTLS command
)

type inConnState struct {
	srv       *InboundServer
	conn      net.Conn
	tp        *textproto.Conn
	from      string
	to        []string
	data      []byte
	spfResult string
	helo      string // EHLO/HELO hostname for SPF null-sender fallback
	state     smtpPhase
	tlsMode   tlsMode

	// spamBatch is this connection's bounded batch scorer
	// (feature.spam_model_batch_load ON): one model load per user per
	// DefaultBatchLoadSize-scored-delivery batch, resident models released at
	// the batch boundary and when the connection closes (handleConn defer).
	// Lazily built on the first batched FTRL score; nil while the toggle is
	// OFF (the per-call path never touches it). Lazily assigned from the
	// connection's single delivery goroutine, so no lock is needed.
	spamBatch *spam.BatchScorer
}

func (c *inConnState) reply(code int, msg string) {
	_, _ = fmt.Fprintf(c.conn, "%d %s\r\n", code, msg)
}

func (c *inConnState) reset() {
	c.from = ""
	c.to = nil
	c.data = nil
	// RFC 5321 §4.1.4: RSET aborts the mail transaction but does NOT
	// invalidate the EHLO greeting.  After RSET the client may issue
	// MAIL FROM directly without re-EHLO.
	// §4.1.1.5: RSET issued before the initial EHLO is a no-op
	// (state stays at phaseGreeting).
	if c.state != phaseGreeting {
		c.state = phaseEhlo
	}
}

func (c *inConnState) handleMail(arg string) {
	if c.srv.tlsEnforce && c.tlsMode == tlsNone {
		c.reply(530, "5.7.0 Must issue STARTTLS first")
		return
	}
	if c.state != phaseEhlo {
		c.reply(503, "Send EHLO/HELO first")
		return
	}
	if !strings.HasPrefix(strings.ToUpper(arg), "FROM:") {
		c.reply(501, "Syntax error")
		return
	}
	c.from = extractAddr(arg[5:])
	c.to = nil
	c.state = phaseMail

	// SPF check — use HELO identity for null sender (RFC 7208 §2.4)
	spfDomain := ""
	if c.from == "" || c.from == "<>" {
		spfDomain = c.helo
	} else if idx := strings.LastIndex(c.from, "@"); idx >= 0 {
		spfDomain = c.from[idx+1:]
	}
	if c.srv.toggles.IsEnabled(toggle.FeatureSPF) {
		clientIP := tcpAddrIP(c.conn)
		c.spfResult = string(CheckSPF(spfDomain, clientIP, c.from, c.helo))
	} else {
		c.spfResult = string(SPFNone)
	}

	c.reply(250, "OK")
}

func (c *inConnState) handleRcpt(ctx context.Context, arg string) {
	if !strings.HasPrefix(strings.ToUpper(arg), "TO:") {
		c.reply(501, "Syntax error")
		return
	}
	// RFC 5321 §4.1.4: RCPT TO only valid after MAIL FROM (phaseMail)
	// or after a previous RCPT TO (phaseRcpt)
	if c.state != phaseMail && c.state != phaseRcpt {
		c.reply(503, "Bad sequence of commands")
		return
	}
	if c.from == "" {
		c.reply(503, "Need MAIL before RCPT")
		return
	}
	c.state = phaseRcpt
	addr := extractAddr(arg[3:])

	// Enforce per-message recipient cap before any DB round-trip.
	if len(c.to) >= maxRecipients {
		c.reply(452, "Too many recipients")
		return
	}

	// Check if recipient is valid (local domain or alias)
	var exists bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM aliases a JOIN mailboxes m ON m.id=a.mailbox_id
			 WHERE a.email=lower($1) AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting'
			UNION
			SELECT 1 FROM mailboxes m WHERE m.email=lower($1)
			 AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting'
			UNION
			SELECT 1 FROM domains d JOIN mailboxes m ON m.id=d.catch_all_mailbox_id
			 WHERE lower($1) LIKE '%@' || d.name AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting'
		)`, addr,
	).Scan(&exists)
	if err != nil || !exists {
		c.reply(550, "No such user here")
		return
	}

	// Greylist check
	if c.srv.toggles.IsEnabled(toggle.FeatureGreylisting) {
		clientIP := tcpAddrIP(c.conn)
		var greylisted bool
		err = c.srv.pool.QueryRow(ctx,
			`SELECT NOT greylist_check($1::INET, $2, $3)`,
			clientIP, c.from, addr,
		).Scan(&greylisted)
		if err == nil && greylisted {
			c.reply(450, "Greylisted — please retry in a few minutes")
			return
		}
	}

	c.to = append(c.to, addr)
	c.reply(250, "OK")
}

func (c *inConnState) handleData(ctx context.Context) bool {
	if c.state != phaseRcpt {
		c.reply(503, "Need MAIL and RCPT before DATA")
		return true
	}
	c.state = phaseData

	c.reply(354, "Start mail input; end with <CRLF>.<CRLF>")

	const maxSize = 157286400 // 150 MiB, must match EHLO SIZE advertisement
	// Strict CRLF dot framing (smtp-bare-lf-message-smuggling): a bare ".\n"
	// never terminates DATA — the frame is refused and the connection closed,
	// so a sender cannot split its DATA and re-enter the command stream
	// mid-frame (strictDotReader comment has the smuggling rationale).
	reader := &strictDotReader{br: c.tp.R}
	limitReader := io.LimitReader(reader, maxSize+1)
	// Bounded rematerialization (smtp-spool-rematerialization): the admission
	// reader acquires a memory slot the moment the stream proves it will
	// spill, so spilled messages read back under a bounded budget; the slot
	// is held for the whole delivery (the rematerialized bytes live in
	// c.data) and freed when this handler returns.
	admitted := &spillAdmitReader{r: limitReader}
	data, tmpFile, err := spooledRead(admitted, maxSize)
	if admitted.release != nil {
		defer admitted.release()
	}
	if err != nil {
		code, msg, terminate := dataReadFailure(err)
		c.reply(code, msg)
		return !terminate
	}
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()
	if len(data) > maxSize {
		c.reply(552, "Message size exceeds fixed maximum message size")
		return true
	}
	if err := validateLineLengths(data); err != nil {
		c.reply(550, fmt.Sprintf("Line too long: %s", err.Error()))
		return true
	}
	c.data = data

	// Deliver to each recipient concurrently using errgroup.
	// Each delivery opens its own DB transaction via pgxpool and is concurrency-safe.
	g, gctx := errgroup.WithContext(ctx)
	// Bounded delivery fanout (smtp-recipient-delivery-fanout): maxRecipients
	// allows 1,000 RCPT TOs per message, and the old unbounded errgroup ran up
	// to 1,000 deliver() pipelines in parallel per message (each its own DB
	// transaction + scan pipeline). SetLimit queues the fanout at
	// maxDeliveryConcurrency — the same bounded-parallelism control the
	// outbound worker applies with its delivery semaphore (outbound.go sem).
	g.SetLimit(maxDeliveryConcurrency)
	var (
		mu                   sync.Mutex
		deliverErr           error
		antiPhishRejected    bool
		dmarcRejected        bool
		groupRejected        bool
		replyDMARCQuarantine bool
	)

	for _, rcpt := range c.to {
		rcpt := rcpt
		g.Go(func() error {
			dmResult, err := c.deliver(gctx, rcpt)
			mu.Lock()
			if errors.Is(err, ErrAntiPhishReject) {
				antiPhishRejected = true
			} else if errors.Is(err, ErrDMARCReject) {
				dmarcRejected = true
			} else if errors.Is(err, ErrGroupModerationReject) {
				groupRejected = true
			} else if err != nil {
				c.srv.logger.Error("deliver failed", "rcpt", rcpt, "error", err)
				if deliverErr == nil {
					deliverErr = err
				}
			}
			if dmResult != nil && dmResult.dmarcQuarantine {
				replyDMARCQuarantine = true
			}
			mu.Unlock()
			return nil // don't cancel sibling goroutines on one failure
		})
	}
	// Ignore errgroup cancellation — we always return nil from goroutines.
	_ = g.Wait()

	c.reset()
	if dmarcRejected {
		if antiPhishRejected {
			c.reply(550, "Message rejected per anti-phishing policy")
			return true
		}
		c.reply(550, "Message rejected per DMARC policy")
		return true
	}
	if groupRejected {
		// Anti-spam hard block: a closed distribution group rejected an external
		// sender. Reject the whole message (mirrors the anti-phish/DMARC reject
		// semantics — one DATA reply covers all recipients).
		c.reply(550, "5.7.1 Message rejected: sender not permitted to post to this group")
		return true
	}
	if deliverErr != nil {
		// T9: classify the reducer BZ code to pick the SMTP reply class —
		// permanent (5xx) vs transient (451). A permanent failure (over-quota,
		// DLP/policy, unknown recipient) MUST surface as 5xx so the sending MTA
		// bounces instead of retrying forever; a non-BZ infra error stays the
		// safe transient 451 default (so a blip is retried, not bounced).
		if reply, ok := classifyReducerReply(deliverErr); ok {
			c.reply(reply.code, reply.msg)
			return true
		}
		c.reply(451, "4.3.0 Temporary failure, please try again later")
		return true
	}
	_ = replyDMARCQuarantine // tracked for parallel-safety: may suppress final reject when any rcpt is quarantine
	c.reply(250, "OK")
	return true
}

func (c *inConnState) deliver(ctx context.Context, rcpt string) (*deliveryResult, error) {
	msg := c.buildTraceMessage()
	headers := c.extractHeaders(msg)

	// External sender warning banner checks (Stage 1.6).
	// Fail open — never block delivery for a banner check error.
	if c.srv.toggles.IsEnabled(toggle.FeatureExternalSenderWarn) {
		external, _, err := c.isExternalDomain(ctx, headers.fromAddr)
		if err != nil {
			c.srv.logger.Warn("external sender check failed (fail-open)", "error", err, "from", headers.fromAddr)
		}
		headers.isExternal = external

		if external && c.srv.toggles.IsEnabled(toggle.FeatureExternalSenderNameSpoof) {
			spoof, err := c.isNameLookalike(ctx, headers.fromName)
			if err != nil {
				c.srv.logger.Warn("name lookalike check failed (fail-open)", "error", err, "from_name", headers.fromName)
			}
			headers.isNameSpoof = spoof
		}
	}

	var dkimResult DKIMResult
	var dkimDomain string
	var dkimSignedLen int64
	var dkimCanonical string
	if c.srv.toggles.IsEnabled(toggle.FeatureDKIM) {
		dkimResult, dkimDomain, dkimSignedLen, dkimCanonical = c.verifyDKIM()
	} else {
		dkimResult = DKIMNone
	}

	var fromDomain string
	var dmarcResult DMARCResult
	var dmResult *deliveryResult
	if c.srv.toggles.IsEnabled(toggle.FeatureDMARC) {
		var dmarcReject error
		fromDomain, dmarcResult, dmResult, dmarcReject = c.evaluateDMARC(ctx, headers.fromAddr, dkimResult, dkimDomain)
		if dmarcReject != nil {
			// DMARC reply now sent by handleData under mutex protection
			return dmResult, dmarcReject
		}
	} else {
		dmarcResult = DMARCNone
		dmResult = &deliveryResult{}
	}

	// Capture c.data once — subsequent steps use the local variable to avoid
	// racing on the slice header when delivery is parallelised.
	data := c.data

	if c.srv.toggles.IsEnabled(toggle.FeatureARC) {
		if sealed := c.sealARC(fromDomain, dkimResult, dkimDomain); sealed != nil {
			data = sealed
			// Rebuild trace message with ARC-sealed data (trace headers are not
			// part of the original message and must reflect the sealed content).
			msg = c.prependTrace(data)
		}
	}
	// ── Inbound S/MIME verification (P0 ordering) ──
	// A signature covers the ORIGINAL message bytes, so the verdict MUST be
	// computed here — on the pristine msg, BEFORE the anti-phish banner inject
	// and link-protect URL rewrite mutate the body below. (ARC sealing above
	// only prepends outer trace/seal headers; it never touches the signed
	// content part, so msg/data are still pristine for the signed body.)
	//
	// Only a fully-valid verdict (trusted chain + From-match) exempts a message
	// from the body mutators — so verified == stored == displayed. Every other
	// verdict (invalid / untrusted / unsigned) is STILL anti-phished and
	// link-protected: a broken or untrusted signature must NOT be a hole that
	// lets an attacker wrap malicious links to skip link-protect. The gate
	// lives in bodyMutatorsApply() (unit-tested) so this invariant is explicit.
	//
	// Fail-open: a nil verdict (not signed, or any extraction/parse failure)
	// never blocks delivery — it simply means the body mutators still run.
	var smimeRes *smime.VerifyResult
	if c.srv.toggles.IsEnabled(toggle.FeatureSmimeVerify) {
		// Per-tenant trust scoping: chain against the RECIPIENT domain's pool
		// (bundle ∪ deployment-wide anchors ∪ this domain's anchors), so an anchor
		// imported for one tenant cannot grant trust in another. recipDomainID 0 ⇒
		// unknown/foreign domain ⇒ bundle ∪ deployment-wide only. Lookup failure
		// fails open to 0 (bundle ∪ deployment-wide).
		var recipDomainID int64
		if at := strings.LastIndex(rcpt, "@"); at >= 0 {
			_ = c.srv.pool.QueryRow(ctx,
				`SELECT id FROM domains WHERE lower(name) = lower($1)`, rcpt[at+1:]).Scan(&recipDomainID)
		}
		smimeRes = verifyInboundSMIME(ctx, msg, headers.fromAddr, c.srv.smimeRootsForDomain(ctx, recipDomainID), c.srv.smimeRevocationOptions())
		if smimeRes != nil {
			c.srv.logger.Debug("smime: inbound verdict", "rcpt", rcpt, "status", smimeRes.Status, "signer", smimeRes.SignerEmail,
				"revocation", smimeRes.Revocation)
			// Harvest the verified signer's cert for the receiving user (SP1 Phase 2).
			// Best-effort + valid-only (gated inside the hook); NEVER blocks delivery.
			// Reads only the verdict, so order vs. the body mutators below is irrelevant.
			// Pass the From the cert was validated against — the hook files the cert under
			// THAT address (the SAN-matched From), not the leaf's first SAN.
			c.harvestSignerCert(ctx, rcpt, headers.fromAddr, smimeRes)
		}
	}
	applyBodyMutators := bodyMutatorsApply(smimeRes)

	// ── Anti-phishing pipeline: run after DMARC, before spam scoring ──
	var antiPhishVerdict PhishVerdict
	var antiPhishEvidence []string
	if len(c.srv.antiPhishDetectors) > 0 {
		input := &PhishInput{
			FromName:         headers.fromName,
			FromAddr:         headers.fromAddr,
			ReturnPathDomain: fromDomain,
			Recipients: []PhishRecipient{
				{Email: rcpt},
			},
		}
		antiPhishVerdict, antiPhishEvidence = RunPhishPipeline(ctx, c.srv.antiPhishDetectors, c.srv.toggles, input)
		// The reject/warn DECISION always stands (a valid-signed message can
		// still be rejected per policy). Only the body MUTATION is gated: a
		// valid-signed message keeps its bytes intact so the signature stays
		// verifiable end-to-end.
		if antiPhishVerdict == PhishReject {
			return dmResult, ErrAntiPhishReject
		}
		if antiPhishVerdict == PhishWarn && applyBodyMutators {
			data = InjectAntiPhishHeaders(data, antiPhishVerdict, antiPhishEvidence)
		}
	}

	var spamResult AntiSpamResult
	if c.srv.toggles.IsEnabled(toggle.FeatureSpamScoring) || c.srv.toggles.IsEnabled(toggle.FeatureRBL) {
		spamResult = c.scoreSpam(data)
	}

	// shared/spam detector suite (arch review #A5) — ADDITIVE signal only,
	// folded into spamResult alongside the RBL/heuristic score above and the
	// per-user FTRL score below. applyMLDetectorSignal is the sole gate on
	// toggle.FeatureSpamMLDetectors (DEFAULT OFF): a no-op today.
	msgStr := string(data)
	applyMLDetectorSignal(c.srv.toggles, &spamResult,
		c.from, headers.fromAddr, c.to,
		extractHeader(msgStr, "To"), extractHeader(msgStr, "Cc"),
		extractBodyText(msgStr), extractBodyHTML(msgStr),
		c.spfResult == string(SPFPass), dkimResult == DKIMPass,
	)

	var virusName string
	if c.srv.toggles.IsEnabled(toggle.FeatureClamAV) {
		virusName = c.scanVirus(data)
	}

	// Attachment sandbox: detonate high-risk attachments after ClamAV passes.
	// The gate is the verdict itself: virusName == "" now means ClamAV RAN and
	// returned clean — a scan error yields the non-empty clamdUnavailableVerdict,
	// which closes the sandbox ("after ClamAV passes" is then false) and
	// quarantines the message below instead (D-MAILSERVER-INTERNAL-SMTP-V003).
	var sandboxVerdictStr string
	if c.srv.sandbox != nil && virusName == "" {
		attTypes := detectAttachmentTypes(data)
		if len(attTypes) > 0 && c.domainSandboxEnabled(ctx, rcpt) {
			c.srv.logger.Info("sandbox: detonating attachments", "rcpt", rcpt, "types", attTypes)
			verdict := c.srv.sandbox.Analyze(ctx, data)
			sandboxVerdictStr = verdict.String()
			c.srv.logger.Info("sandbox: verdict", "rcpt", rcpt, "verdict", sandboxVerdictStr, "severity", verdict.Severity)
			switch verdict.Severity {
			case SandboxMalicious:
				action := c.domainSandboxAction(ctx, rcpt)
				if action == "reject" {
					return dmResult, fmt.Errorf("sandbox: %s", sandboxVerdictStr)
				}
				virusName = "Sandbox:" + verdict.VirusName
			case SandboxSuspicious:
				virusName = "Sandbox:Suspicious:" + verdict.VirusName
			case SandboxError, SandboxUnknown:
				if c.srv.sandbox.failMode == FailClosed {
					return dmResult, fmt.Errorf("sandbox unreachable (fail-closed)")
				}
			}
		}
	}

	cryptoType := string(DetectCrypto(msg))

	// Link protection: rewrite external URLs through /link-protect proxy.
	// Skipped for valid-signed mail (applyBodyMutators == false) so the signed
	// body is never altered; every other verdict is still rewritten.
	// Fail-closed (D-MAILSERVER-INTERNAL-MIMEUTIL-001): a rewrite/walker
	// failure means the body was never proven scanner-visible (attacker
	// MIME framing the reference parser cannot agree with), so the message is
	// flagged for quarantine below instead of silently delivering the
	// original.
	var mimeFailClosed bool
	if applyBodyMutators && c.srv.toggles.IsEnabled(toggle.FeatureLinkProtectRewrite) && len(c.srv.linkProtectKeys.Secret) > 0 {
		mailboxID := c.resolveMailboxID(ctx, rcpt)
		// Rotation-aware minting (MAILSERVERD-004): tokens are signed under the
		// CURRENT configured key version so the click handler and the outbound
		// egress un-rewriter — wired with the same key set — keep resolving
		// every delivered token, including after the overlap window drains.
		rewritten, count, rewriteErr := RewriteMessageBodyN(data, c.srv.linkProtectKeys, c.srv.internalDomains, headers.messageID, mailboxID)
		if rewriteErr != nil {
			mimeFailClosed = true
			c.srv.logger.Warn("link_protect: rewrite failed, quarantining fail-closed (original never reaches Inbox)", "error", rewriteErr, "rcpt", rcpt)
		} else if count > 0 {
			c.srv.logger.Debug("link_protect: URLs rewritten", "count", count, "rcpt", rcpt)
			data = rewritten
			// Rebuild trace message with rewritten data
			msg = c.prependTrace(data)
		}
	}

	// Per-user FTRL scoring at delivery time.
	// Blocked/safe/ML checks run per-recipient because user_id is known here.
	c.applyPerUserSpam(ctx, rcpt, headers.fromAddr, data, &spamResult)

	// Fail-closed condemnation resolution (D-MAILSERVER-INTERNAL-MIMEUTIL-001):
	// a detection verdict takes precedence for the audit label; the MIME
	// fail-closed degradation supplies the marker when no detection exists.
	// The condemnation is carried THROUGH the delivery transaction (atomic
	// quarantine of every delivered copy — med-shard2-002 item 1 / med-shard2-021
	// item 4), never applied post-commit: a post-commit quarantine failure was
	// only logged, and a distribution-group delivery (msgID==0) bypassed
	// quarantine entirely.
	condemned := virusName
	if mimeFailClosed && condemned == "" {
		condemned = mimeFailClosedVerdict
	}

	msgID, err := c.storeAndDeliver(ctx, rcpt, headers, dkimResult, msg, data, spamResult, dmarcResult, cryptoType, dmResult.dmarcQuarantine, smimeRes, condemned)
	if err != nil {
		return dmResult, err
	}
	// ponytail: held messages return msgID==0; skip all post-delivery side effects
	// (webhook dispatch, iMIP calendar ops) until the moderator approves and the
	// approval path replays deliver() for each member. Quarantine is NOT among
	// the skipped effects anymore: it commits inside storeAndDeliver's
	// transaction, so a held post is never delivered-and-uncondemned in the
	// first place (and a condemned post to a moderated group is deferred before
	// the hold is even parked — see ErrCondemnedDeferred).
	if msgID != 0 {
		// iMIP transport identity (security fix D-MAILSERVER-INTERNAL-CALDAV,
		// round 2): the transport evidence the per-method iTIP role checks bind
		// against. DkimAligned requires a DKIM pass whose signing domain aligns
		// (RFC 7489 relaxed, organizational domain) with the RFC 5322 From
		// header domain; SpfPass records the SPF verdict for the envelope so a
		// bare envelope match authenticates nothing. The S/MIME verdict is
		// captured inside detectAndProcessIMip, where the signature is verified.
		dkimAligned := false
		if dkimResult == DKIMPass {
			if at := strings.LastIndex(headers.fromAddr, "@"); at >= 0 {
				dkimAligned = isDMARCAligned(dkimDomain, headers.fromAddr[at+1:], DMARCRelaxed)
			}
		}
		c.detectAndProcessIMip(ctx, msg, caldav.ITIPTransportIdentity{
			EnvelopeFrom: c.from,
			FromHeader:   headers.fromAddr,
			DkimAligned:  dkimAligned,
			DkimDomain:   dkimDomain,
			SpfPass:      c.spfResult == string(SPFPass),
		}, dkimSignedLen, dkimCanonical)
	}
	return dmResult, nil
}

// buildTraceMessage prepends Received and Return-Path headers (RFC 5321 §4.4).
// prependTrace rebuilds the message with the trace headers (Received + optional
// Return-Path) prepended. The three call sites (ARC seal, link-protect rewrite,
// buildTraceMessage) must stay byte-identical in header shape.
func (c *inConnState) prependTrace(data []byte) string {
	remoteIP := tcpAddrIP(c.conn)
	received := fmt.Sprintf(
		"Received: from %s (%s [%s]) by mailserver\r\n\tvia SMTP; %s\r\n",
		c.helo, remoteIP, remoteIP, time.Now().Format(time.RFC1123Z),
	)
	returnPath := ""
	if c.from != "" && c.from != "<>" {
		returnPath = fmt.Sprintf("Return-Path: <%s>\r\n", c.from)
	}
	return received + returnPath + string(data)
}

func (c *inConnState) buildTraceMessage() string {
	return c.prependTrace(c.data)

}

// deliverHeaders groups parsed MIME headers used throughout the delivery pipeline.
type deliverHeaders struct {
	subject, messageID, inReplyTo, references string
	fromName, fromAddr                        string
	toAddrs, ccAddrs, bccAddrs                []byte
	hasAttachments                            bool
	voteResponse                              string
	isExternal                                bool
	isNameSpoof                               bool
	listUnsubscribe                           string // RFC 8058 — one-click unsubscribe URL
	isNewsletter                              bool   // true if List-Unsubscribe header present
	listID                                    string // RFC 2919 List-Id header (raw, normalized by DB)
}

// extractHeaders parses MIME headers from the trace-enriched message.
func (c *inConnState) extractHeaders(msg string) deliverHeaders {
	h := deliverHeaders{}
	h.subject = extractHeader(msg, "Subject")
	h.messageID = extractHeader(msg, "Message-Id")
	if h.messageID == "" {
		h.messageID = fmt.Sprintf("<%s@mailserver>", randomID())
	}
	h.inReplyTo = extractHeader(msg, "In-Reply-To")
	h.references = extractHeader(msg, "References")
	h.fromName, h.fromAddr = parseFrom(extractHeader(msg, "From"))
	h.toAddrs = parseAddressList(extractHeader(msg, "To"))
	h.ccAddrs = parseAddressList(extractHeader(msg, "Cc"))
	h.bccAddrs = parseAddressList(extractHeader(msg, "Bcc"))
	h.voteResponse = extractHeader(msg, "X-Mailserver-Vote-Response")
	h.listUnsubscribe = extractHeader(msg, "List-Unsubscribe")
	h.listID = extractHeader(msg, "List-Id")
	h.isNewsletter = h.listUnsubscribe != "" || h.listID != ""
	h.hasAttachments = strings.Contains(msg, "Content-Disposition: attachment")
	return h
}

// verifyDKIM performs DKIM verification. Round 3 (Astra HOLD): the signing
// domain reported for alignment is the parsed signature's d= — the EXACT
// signature VerifyDKIM verifies (parseDKIMSignature: the first DKIM-Signature
// header, duplicate tags last-wins). The old separate `strings.Index(d, "d=")`
// scan grabbed the FIRST "d=" substring of the header while the verifier used
// the LAST duplicate, so `d=victim.test; …; d=attacker.test` verified against
// attacker keys while alignment read the victim domain. Both now come from the
// same parse, so alignment can only ever follow the signature that actually
// verified: a role-matching identity requires THAT signature to pass, not
// merely a matching tag to exist.
//
// Round 4 (Astra HOLD): the third return is the signature's AUTHENTICATED body
// length — the l= tag value when the signature verified (0 = no l= tag: the
// full body is signed; 0 also on every non-pass verdict). The iMIP step uses
// it to bound content processing to the signed body prefix.
//
// Round 5 (Astra HOLD): the fourth return is the signature's c= tag so the
// iMIP fence can map the authenticated length from the CANONICALIZED byte
// space (what l= counts, RFC 6376 §3.5) back to the stored byte space — the
// CRLF→LF intake canonicalization makes the two diverge line by line.
func (c *inConnState) verifyDKIM() (DKIMResult, string, int64, string) {
	sig := parseDKIMSignature(string(c.data))
	if sig == nil {
		return DKIMNone, "", 0, ""
	}
	result, signedLen := VerifyDKIM(c.data, "")
	return result, sig.Domain, signedLen, sig.Canonical
}

// evaluateDMARC checks DMARC policy and enforces it. Returns the from domain,
// the DMARC result, a per-recipient delivery result, and a non-nil error if
// p=reject should abort delivery. This method is free of side effects — the
// caller owns the reply and state mutation.
func (c *inConnState) evaluateDMARC(ctx context.Context, fromAddr string, dkimResult DKIMResult, dkimDomain string) (fromDomain string, dmarcResult DMARCResult, dr *deliveryResult, rejectErr error) {
	dr = &deliveryResult{}
	if idx := strings.LastIndex(fromAddr, "@"); idx >= 0 {
		fromDomain = fromAddr[idx+1:]
	}
	spfDomain := ""
	if idx := strings.LastIndex(c.from, "@"); idx >= 0 {
		spfDomain = c.from[idx+1:]
	}
	msgID := extractHeader(string(c.data), "Message-Id")
	dmarcResult, dmarcRec := CheckDMARC(fromDomain, msgID, SPFResult(c.spfResult), spfDomain, dkimResult, dkimDomain)
	RecordDMARCResult(ctx, c.srv.pool, fromDomain, dmarcResult, dmarcRec)

	if dmarcRec != nil && dmarcResult == DMARCFail {
		switch dmarcRec.Policy {
		case DMARCRejectPolicy:
			return fromDomain, dmarcResult, dr, ErrDMARCReject
		case DMARCQuarantinePolicy:
			dr.dmarcQuarantine = true
		}
	}
	return fromDomain, dmarcResult, dr, nil
}

// sealARC applies ARC (RFC 8617) sealing and returns the sealed message bytes.
// Returns the sealed data (which may be unchanged if no signing key is available),
// or nil if ARC is not applicable (empty fromDomain).
// Does NOT mutate c.data — the caller owns the decision to use the returned data.
func (c *inConnState) sealARC(fromDomain string, dkimResult DKIMResult, dkimDomain string) []byte {
	if fromDomain == "" {
		return nil
	}
	spfDomain := ""
	if idx := strings.LastIndex(c.from, "@"); idx >= 0 {
		spfDomain = c.from[idx+1:]
	}
	return arcSignForInbound(c.data, fromDomain, c.srv.pool,
		c.spfResult, spfDomain,
		string(dkimResult), dkimDomain,
		string(DMARCNone),
	)
}

// scoreSpam runs anti-spam heuristics and RBL checks.
func (c *inConnState) scoreSpam(data []byte) AntiSpamResult {
	clientIP := tcpAddrIP(c.conn)
	var rblListed []string
	if c.srv.toggles.IsEnabled(toggle.FeatureRBL) {
		rblListed, _ = CheckRBL(clientIP)
	}
	if c.srv.toggles.IsEnabled(toggle.FeatureSpamScoring) {
		return ScoreMessage(data, rblListed)
	}
	return AntiSpamResult{}
}

// applyPerUserSpam applies per-user spam decisions at delivery time.
// Checks: blocked sender → junk, safe sender → inbox (skip FTRL), FTRL model → junk if score > 0.7.
// All checks are scoped to this recipient's user_id.
func (c *inConnState) applyPerUserSpam(ctx context.Context, rcpt, fromAddr string, data []byte, spamResult *AntiSpamResult) {
	mailboxID := c.resolveMailboxID(ctx, rcpt)
	if mailboxID == 0 {
		return // can't resolve mailbox, skip per-user checks
	}

	// Get user_id for this mailbox.
	var userID int64
	err := c.srv.pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID,
	).Scan(&userID)
	if err != nil {
		return
	}

	// 1. BLOCKED: user explicitly blocked this sender → Junk.
	var blocked bool
	c.srv.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_sender_list
		 WHERE user_id = $1 AND sender = $2 AND list_type = 'blocked')`,
		userID, fromAddr,
	).Scan(&blocked)
	if blocked {
		spamResult.Score = max(spamResult.Score, 10.0)
		spamResult.Symbols = append(spamResult.Symbols, "USER_BLOCKED")
		return
	}

	// 2. SAFE: user explicitly trusts this sender → Inbox, skip FTRL.
	var safe bool
	c.srv.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_sender_list
		 WHERE user_id = $1 AND sender = $2 AND list_type = 'safe')`,
		userID, fromAddr,
	).Scan(&safe)
	if safe {
		spamResult.Score = min(spamResult.Score, 1.0)
		spamResult.Symbols = append(spamResult.Symbols, "USER_SAFE")
		return
	}

	// 3. FTRL: per-user ML model decides.
	if c.srv.toggles.IsEnabled(toggle.FeatureMLSpam) && c.srv.spamStore != nil {
		ftrlScore, err := c.scoreFTRL(ctx, userID, data)
		if err != nil {
			return
		}
		spamResult.FTRLScore = ftrlScore
		if ftrlScore > 0.7 {
			spamResult.Score = max(spamResult.Score, 7.0)
			spamResult.Symbols = append(spamResult.Symbols, "FTRL_SPAM")
		}
	}
}

// scoreFTRL runs the per-user FTRL score for one delivery. The load strategy
// is toggle-selected (owner decision A6):
//
//   - feature.spam_model_batch_load OFF: exactly the historical per-call
//     behavior — LoadModel+Score per recipient per message, nothing held
//     across calls. Byte-identical to the pre-A6 path.
//   - ON: the connection's bounded BatchScorer loads each user's model once
//     per DefaultBatchLoadSize-scored-delivery batch. Memory trade (resident
//     models, bounded staleness within a batch) is declared by the toggle's
//     startup/flip warning log and surfaced on the admin spam dashboard.
//
// Error semantics are identical on both paths: any LoadModel error (including
// the ErrModelDisabled scoring opt-out) returns the error and scores nothing.
func (c *inConnState) scoreFTRL(ctx context.Context, userID int64, data []byte) (float64, error) {
	if !c.srv.toggles.IsEnabled(toggle.FeatureSpamModelBatchLoad) {
		model, err := c.srv.spamStore.LoadModel(ctx, userID)
		if err != nil {
			return 0, err
		}
		return model.Score(data), nil
	}
	if c.spamBatch == nil {
		c.spamBatch = spam.NewBatchScorer(c.srv.spamStore, spam.DefaultBatchLoadSize)
	}
	return c.spamBatch.Score(ctx, userID, data)
}

// clamdUnavailableVerdict is the DISTINCT NON-CLEAN verdict scanVirus returns
// when the clamd exchange itself fails (connect error, timeout, protocol
// error). It is deliberately non-empty so a degraded scan can never be
// mistaken for a clean one: the deliver pipeline treats any non-empty verdict
// as condemned (quarantine via quarantine_message, sandbox gate closed), so a
// scanner outage or deliberate scan starvation fails closed instead of
// delivering to Inbox (D-MAILSERVER-INTERNAL-SMTP-V003).
const clamdUnavailableVerdict = "ClamAV:unavailable"

// mimeFailClosedVerdict is the DISTINCT NON-CLEAN condemnation marker for a
// link-protect rewrite/walker failure (D-MAILSERVER-INTERNAL-MIMEUTIL-001):
// the MIME framing was ambiguous, so the body was never proven
// scanner-visible and the message is quarantined instead of delivering the
// original. Deliberately non-empty so the fail-closed degradation can never
// be mistaken for a clean pass through the atomic condemnation path
// (quarantineDeliveredTx).
const mimeFailClosedVerdict = "MIME:unparseable"

// scanVirus runs ClamAV against the message and returns the virus name (empty
// if clean). A scan ERROR is never clean: it returns clamdUnavailableVerdict,
// which downstream gating treats like a detection (quarantine, no sandbox).
func (c *inConnState) scanVirus(data []byte) string {
	if c.srv.clamav == nil {
		return ""
	}
	virus, err := c.srv.clamav.Scan(data)
	if err != nil {
		c.srv.logger.Error("clamav scan error — failing closed", "error", err)
		return clamdUnavailableVerdict
	}
	return virus
}

// storeAndDeliver writes the blob, calls the deliver() PG reducer, and returns the message ID.
//
// condemned (med-shard2-002 item 1 / med-shard2-021 item 4) carries a
// malware-gate verdict (clamAV detection, clamdUnavailableVerdict) or the
// mimeFailClosedVerdict fail-closed marker. It is applied INSIDE the delivery
// transaction — quarantine_message runs on the same tx as deliver(), before
// the commit — so delivery and quarantine are atomic: every delivered copy
// (single mailbox or distribution-group fan-out) commits already-quarantined,
// and a quarantine failure rolls the whole delivery back (the SMTP seam turns
// that into a transient 451, never a partial uncondemned delivery).
func (c *inConnState) storeAndDeliver(ctx context.Context, rcpt string,
	headers deliverHeaders, dkimResult DKIMResult, msg string, data []byte,
	spamResult AntiSpamResult, dmarcResult DMARCResult, cryptoType string,
	dmarcQuarantine bool, smimeRes *smime.VerifyResult, condemned string,
) (int64, error) {
	hash := sha256.Sum256(data)
	blobKey := "inbound/" + hex.EncodeToString(hash[:])

	// Store the raw wire under blobKey BEFORE any row references it — pre-fix
	// this function only CLAIMED to write the blob, so messages.raw_ref (and a
	// moderation hold's held_inbound_messages.raw_ref) pointed at a key that
	// never existed, breaking .eml download, spam-trainer FetchMessage, and
	// ediscovery raw export for every received message. Content-addressed by
	// sha256, so per-recipient re-deliveries of the same wire dedupe to one
	// object. Fail closed: a store error tempfails the delivery (sender
	// retries) rather than delivering a message whose raw bytes are lost.
	if c.srv.putBlob != nil {
		if err := c.srv.putBlob(ctx, blobKey, data); err != nil {
			return 0, fmt.Errorf("raw blob store %s: %w", blobKey, err)
		}
	}

	spamHeaders, _ := json.Marshal(spamResult.Symbols)

	spamScore := spamResult.Score
	dmarcRes := string(dmarcResult)
	if dmarcQuarantine {
		spamScore = max(spamScore, 10.0)
		dmarcRes = string(DKIMFail)
	}

	// Derive the 4 nullable S/MIME columns ($29..$32). A nil verdict (verify
	// disabled, not signed, or fail-open) leaves all four NULL.
	var smStatus, smSignerEmail, smSignerCN, smIssuerCN *string
	if smimeRes != nil {
		smStatus = &smimeRes.Status
		smSignerEmail = emptyToNil(smimeRes.SignerEmail)
		smSignerCN = emptyToNil(smimeRes.SignerCN)
		smIssuerCN = emptyToNil(smimeRes.IssuerCN)
	}

	tx, err := c.srv.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	c.setToggleSessionVars(ctx, tx)

	// The 32 deliver() args, in the exact positional order of deliverParamNames and
	// the deliver() signature. Built once so they feed BOTH the live call below and —
	// on a moderated-group hold — the verbatim replay packaged into held_inbound_messages.
	deliverArgs := []any{
		blobKey, headers.messageID, headers.fromAddr, headers.fromName, rcpt,
		headers.toAddrs, headers.ccAddrs, headers.bccAddrs,
		headers.subject, headers.inReplyTo, headers.references,
		extractBodyText(msg), extractBodyHTML(msg),
		int64(len(data)), headers.hasAttachments, time.Now(),
		c.spfResult, string(dkimResult), dmarcRes,
		spamScore, spamHeaders, headers.voteResponse, cryptoType,
		headers.isExternal, headers.fromName, headers.isNameSpoof,
		0, emptyToNil(headers.listID),
		smStatus, smSignerEmail, smSignerCN, smIssuerCN,
	}

	// ── Inbound distribution-group moderation + anti-spam (T8) ──
	// Before deliver() expands a distribution group to its members, consult the
	// group's live moderation settings. Engaged ONLY when the recipient resolves to
	// a distribution group AND approval.group_moderation is on. Toggle off, a
	// non-group recipient, or an internal sender to an unmoderated/open group ⇒ the
	// delivery proceeds byte-for-byte as before.
	if c.srv.toggles.IsEnabled(toggle.ApprovalGroupModeration) {
		if groupID := c.resolveDistributionGroup(ctx, tx, rcpt); groupID != 0 {
			senderExternal, _, _ := c.isExternalDomain(ctx, c.from)
			var verdict string
			if err := tx.QueryRow(ctx,
				`SELECT group_moderation_check($1, $2)`, groupID, senderExternal,
			).Scan(&verdict); err != nil {
				return 0, err
			}
			switch verdict {
			case "reject":
				return 0, ErrGroupModerationReject
			case "hold":
				if condemned != "" {
					// A condemned post must never wait behind a moderation
					// hold: the approval replay re-runs deliver() verbatim and
					// would fan the message out to every member UNCONDEMNED —
					// the exact bypass this seam exists to close. Defer before
					// delivery instead (fail closed at SMTP time; the error is
					// not a reducer BZ code, so the DATA phase answers 451).
					return 0, ErrCondemnedDeferred
				}
				params, err := deliverParamsJSON(deliverArgs)
				if err != nil {
					return 0, err
				}
				envelope, err := json.Marshal(map[string]string{"mail_from": c.from, "rcpt_to": rcpt})
				if err != nil {
					return 0, err
				}
				var reqID int64
				if err := tx.QueryRow(ctx,
					`SELECT group_moderation_hold($1, $2, $3, $4, $5)`,
					groupID, c.from, blobKey, envelope, params,
				).Scan(&reqID); err != nil {
					return 0, err
				}
				if err := tx.Commit(ctx); err != nil {
					return 0, err
				}
				c.srv.logger.Info("group moderation: inbound post held for approval",
					"rcpt", rcpt, "from", c.from, "group_id", groupID, "request_id", reqID)
				// The approve-by-email notification is dispatched centrally off the
				// approval_created NOTIFY (see approval.HandleApprovalCreatedNotify,
				// wired in main.go) — not here. That single path also reaches the
				// external-send hold, which has no Go call site with the request id.
				return 0, nil // accepted-and-held: no message row, deliver() skipped
			}
			// "deliver" falls through to the normal path below.
		}
	}

	// msgID is a pointer: deliver() RETURNs NULL for a distribution-group
	// recipient (it expands to members recursively and the group mailbox
	// itself never gets a message row — see deliver_group_vacation.sql). A
	// plain int64 destination can't accept that NULL (pgx: "cannot scan NULL
	// into *int64"), which — before this fix — surfaced as a Go error the
	// inbound SMTP server turned into a 451 for EVERY message to EVERY
	// distribution group, moderated or not (TODOS.md "451 edge"; pre-existing,
	// not introduced by T8). NULL here means the same thing msgID==0 already
	// means below: accepted, no further per-message side effects (the group
	// mailbox has no message row to dispatch/quarantine/iMIP against).
	// Package the args as jsonb keyed by parameter name and let the deliver_json
	// reducer unpack them positionally — one place owns the key->position mapping,
	// instead of a hand-numbered SELECT deliver($1..$N) string that silently drifts
	// as deliver() grows trailing DEFAULT params. deliverParamsJSON's len guard is
	// the remaining drift backstop.
	params, err := deliverParamsJSON(deliverArgs)
	if err != nil {
		return 0, err
	}
	var msgID, subjectUserID, subjectMailboxID *int64
	var publicationEnrolled bool
	err = tx.QueryRow(ctx,
		`SELECT message_id,subject_user_id,subject_mailbox_id,publication_enrolled
		   FROM smtp_inbound_deliver($1,$2,$3)`,
		params, c.from, rcpt,
	).Scan(&msgID, &subjectUserID, &subjectMailboxID, &publicationEnrolled)
	if err != nil {
		return 0, err
	}
	// Condemnation rides the SAME transaction as the delivery (med-shard2-002
	// item 1 / med-shard2-021 item 4): every copy deliver() just created —
	// the single mailbox's row, or every distribution-group member's row —
	// is quarantined before the commit, and any quarantine failure aborts the
	// whole delivery (rollback ⇒ nothing delivered ⇒ transient 451).
	if condemned != "" {
		if err := c.quarantineDeliveredTx(ctx, tx, blobKey, headers.messageID, msgID, condemned); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if msgID == nil {
		return 0, nil
	}
	// Default-OFF rolling compatibility remains post-commit, but is now typed to
	// the reducer-derived mailbox subject. Ownerless shared/group mailboxes fail
	// closed, and the ON path never double-dispatches a durable publication.
	if !publicationEnrolled && subjectUserID != nil && subjectMailboxID != nil && c.srv.dispatcher != nil {
		c.srv.dispatcher.DispatchForMailbox(ctx, *subjectUserID, *subjectMailboxID,
			wh.NewCloudEvent("mailserver/gateway", wh.EventMailReceived, map[string]interface{}{
				"from": c.from,
				"to":   rcpt,
			}))
	}
	return *msgID, nil
}

// deliverParamNames are the 32 deliver() parameter names, in the exact positional
// order of the deliverArgs slice in storeAndDeliver and the deliver() signature.
// group_moderation_hold persists the held args keyed by these names;
// group_moderation_approval_decide reads them back to replay deliver() verbatim on
// approval. ORDER IS LOAD-BEARING — keep it in lockstep with deliverArgs + deliver().
var deliverParamNames = []string{
	"p_raw_ref", "p_message_id", "p_from_addr", "p_from_name", "p_rcpt_addr",
	"p_to_addrs", "p_cc_addrs", "p_bcc_addrs",
	"p_subject", "p_in_reply_to", "p_references_hdr",
	"p_body_text", "p_body_html",
	"p_size_bytes", "p_has_attachments", "p_sent_at",
	"p_spf_result", "p_dkim_result", "p_dmarc_result",
	"p_spam_score", "p_spam_headers", "p_vote_response", "p_crypto_type",
	"p_is_external", "p_sender_display_name", "p_is_name_spoof",
	"p_depth", "p_list_id",
	"p_smime_status", "p_smime_signer_email", "p_smime_signer_cn", "p_smime_issuer_cn",
}

// deliverParamsJSON serializes the 32 positional deliver() args (matching
// deliverParamNames) into a jsonb object keyed by parameter name, for verbatim
// replay on moderator approval. The four []byte values that are already JSON
// (to/cc/bcc addrs, spam headers) are embedded as raw JSON, not base64, so the
// reducer reads them straight back as jsonb arrays.
func deliverParamsJSON(args []any) ([]byte, error) {
	if len(args) != len(deliverParamNames) {
		return nil, fmt.Errorf("deliverParamsJSON: got %d args, want %d", len(args), len(deliverParamNames))
	}
	m := make(map[string]any, len(args))
	for i, name := range deliverParamNames {
		v := args[i]
		if b, ok := v.([]byte); ok {
			v = json.RawMessage(b)
		}
		m[name] = v
	}
	return json.Marshal(m)
}

// resolveDistributionGroup returns the distribution_groups.id whose group mailbox
// the recipient resolves to (via an alias or the mailbox's own address), or 0 when
// the recipient is not a distribution group. Mirrors deliver()'s recipient
// resolution so the Go seam and the reducer agree on what "the group" is.
// Fail-open: any lookup error returns 0 (treat as a normal mailbox — never block).
func (c *inConnState) resolveDistributionGroup(ctx context.Context, tx pgx.Tx, rcpt string) int64 {
	var groupID int64
	err := tx.QueryRow(ctx,
		`SELECT dg.id
		   FROM distribution_groups dg
		   JOIN mailboxes mb ON mb.id = dg.mailbox_id
		   LEFT JOIN aliases a ON a.mailbox_id = mb.id
		  WHERE mailbox_lifecycle_delivery_mode(mb.id)<>'rejecting'
		    AND (mb.email = lower($1) OR a.email = lower($1))
		  LIMIT 1`, rcpt,
	).Scan(&groupID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			c.srv.logger.Warn("group moderation: group resolution failed (fail-open)", "rcpt", rcpt, "error", err)
		}
		return 0
	}
	return groupID
}

// setToggleSessionVars sets PostgreSQL session variables based on feature toggle state.
// These are read by PL/pgSQL reducers to skip disabled features.
func (c *inConnState) setToggleSessionVars(ctx context.Context, tx pgx.Tx) {
	setIfDisabled := func(key, varName string) {
		if !c.srv.toggles.IsEnabled(key) {
			tx.Exec(ctx, "SET LOCAL "+varName+" = 'true'")
		}
	}
	setIfDisabled(toggle.FeatureRulesEngine, "app.skip_rules")
	setIfDisabled(toggle.FeatureVacation, "app.skip_vacation")
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
	setIfDisabled(toggle.FeatureExternalSenderFirstTime, "app.skip_external_sender_first_time")
}

// isExternalDomain checks whether the sender's domain is external (not a local domain).
// Returns (isExternal, domain, error). Empty fromAddr or error defaults to external

// (fail open — never block delivery for a banner check).
func (c *inConnState) isExternalDomain(ctx context.Context, fromAddr string) (bool, string, error) {
	domain := extractDomain(fromAddr)
	if domain == "" {
		return true, "", nil // empty domain → treat as external
	}

	var isLocal bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM domains WHERE is_local = TRUE AND lower(name) = lower($1))`,
		domain,
	).Scan(&isLocal)
	if err != nil {
		c.srv.logger.Warn("external sender check: failed to query domain", "domain", domain, "error", err)
		return false, domain, err // fail open
	}
	return !isLocal, domain, nil
}

// isNameLookalike checks whether the given display name matches an internal user's display_name.
// Returns (isMatch, error). Empty displayName or error defaults to false
// (fail open — never block delivery for a banner check).
func (c *inConnState) isNameLookalike(ctx context.Context, displayName string) (bool, error) {
	if displayName == "" {
		return false, nil
	}

	var exists bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE lower(display_name) = lower($1))`,
		displayName,
	).Scan(&exists)
	if err != nil {
		c.srv.logger.Warn("name lookalike check: failed to query users", "display_name", displayName, "error", err)
		return false, err
	}
	return exists, nil
}

// ErrCondemnedDeferred is returned by storeAndDeliver when a CONDEMNED message
// (a malware detection, the clamdUnavailableVerdict fail-closed degradation, or
// the mimeFailClosedVerdict marker) reaches a moderated distribution group
// whose verdict is "hold". Parking it would let the moderator-approval replay
// fan the message out to every member UNCONDEMNED, so the message is deferred
// before delivery instead. The error carries no reducer BZ code, so the DATA
// phase keeps its safe transient default (451) and the sender retries into the
// same fail-closed refusal.
var ErrCondemnedDeferred = errors.New("smtp: condemned message deferred instead of moderation hold")

// quarantineReason maps a condemnation verdict to the quarantine audit reason.
// reason_type stays 'virus' (the CHECK-constrained bucket for malware-gate
// condemnation); the reason text distinguishes scanner degradation so an
// operator can tell a fail-closed quarantine from a detection.
func quarantineReason(virusName string) string {
	switch virusName {
	case clamdUnavailableVerdict:
		return "Malware scan unavailable — quarantined fail-closed (message never verified clean)"
	case mimeFailClosedVerdict:
		return "MIME structure failed safe parsing — quarantined fail-closed (body never link-protect rewritten)"
	}
	return "Virus detected: " + virusName
}

// quarantineDeliveredTx quarantines EVERY message row the CURRENT delivery
// transaction created, on that same transaction — the atomic condemnation path
// that replaces the old post-commit processQuarantine (med-shard2-002 item 1 /
// med-shard2-021 item 4). Two shapes:
//
//   - Single-recipient delivery (msgID != nil): the quarantine target is the
//     AUTHORITATIVE delivered mailbox identity — messages.mailbox_id of the
//     row deliver() itself created (med-shard2-002 item 2). The old code
//     re-resolved the recipient with a `UNION … LIMIT 1` over aliases ∪
//     canonical ∪ catch-all, which does not preserve deliver()'s alias →
//     canonical → catch-all precedence: a configured catch-all could win for
//     an existing recipient, quarantining (failing over) the WRONG mailbox and
//     leaving the malware in the real one.
//
//   - Distribution-group delivery (msgID == nil): deliver() returned NULL
//     because it expanded the group to member mailboxes recursively inside the
//     reducer, so the gateway never saw a message id. The copies are selected
//     by their insertion xact status — a row VISIBLE to this transaction whose
//     xmin is not yet committed can only have been written by this
//     transaction (deliver() inserts each member copy from a per-member
//     subtransaction, so xmin is a SUBxid and cannot be compared against
//     pg_current_xact_id()), scoped to the wire's blob ref and Message-Id.
//     Each copy is quarantined in ITS OWN mailbox.
//
// Any failure propagates: the caller returns the error and its deferred
// rollback undelivers every copy — a quarantine failure can never again leave
// condemned mail in Inbox behind a committed delivery.
func (c *inConnState) quarantineDeliveredTx(ctx context.Context, tx pgx.Tx, blobKey, messageID string, msgID *int64, condemned string) error {
	reason := quarantineReason(condemned)
	if msgID != nil {
		var mailboxID int64
		if err := tx.QueryRow(ctx,
			`SELECT mailbox_id FROM messages WHERE id = $1`, *msgID,
		).Scan(&mailboxID); err != nil {
			return fmt.Errorf("condemnation: delivered message %d not found: %w", *msgID, err)
		}
		return quarantineOneTx(ctx, tx, *msgID, mailboxID, reason, condemned)
	}

	rows, err := tx.Query(ctx,
		`SELECT id, mailbox_id FROM messages
		  WHERE raw_ref = $1 AND message_id = $2
		    AND pg_xact_status(xmin::text::xid8) IN ('in progress', 'subcommitted')`,
		blobKey, messageID,
	)
	if err != nil {
		return fmt.Errorf("condemnation: group fan-out copy lookup: %w", err)
	}
	defer rows.Close()
	type copyRow struct {
		id, mailboxID int64
	}
	var copies []copyRow
	for rows.Next() {
		var cr copyRow
		if err := rows.Scan(&cr.id, &cr.mailboxID); err != nil {
			return fmt.Errorf("condemnation: group fan-out copy scan: %w", err)
		}
		copies = append(copies, cr)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("condemnation: group fan-out copy iteration: %w", err)
	}
	for _, cr := range copies {
		if err := quarantineOneTx(ctx, tx, cr.id, cr.mailboxID, reason, condemned); err != nil {
			return err
		}
	}
	return nil
}

// quarantineOneTx runs the quarantine_message reducer for one delivered copy
// on the delivery transaction. quarantine_message() owns the whole transition
// atomically: it seeds the mailbox's Quarantined system tag (conflict-safe),
// removes the message's real location-group tag(s), adds the Quarantined tag,
// writes one quarantined_messages audit row (with the REAL original location),
// and pushes notify_state_change — all inside this transaction's commit.
// R3-scoped on the copy's own mailbox (BZ074 on a foreign mailbox / missing
// message — and that error now ABORTS the delivery instead of being logged).
func quarantineOneTx(ctx context.Context, tx pgx.Tx, msgID, mailboxID int64, reason, condemned string) error {
	if _, err := tx.Exec(ctx,
		`SELECT quarantine_message($1, $2, $3, $4, $5)`,
		msgID, mailboxID, reason, "virus", condemned,
	); err != nil {
		return fmt.Errorf("condemnation: quarantine_message failed for message %d mailbox %d: %w", msgID, mailboxID, err)
	}
	return nil
}

// domainSandboxEnabled checks whether sandbox analysis is enabled for the
// recipient's domain (from the domains table).
func (c *inConnState) domainSandboxEnabled(ctx context.Context, rcpt string) bool {
	domain := extractDomain(rcpt)
	if domain == "" {
		return false
	}
	var enabled bool
	err := c.srv.pool.QueryRow(ctx,
		`SELECT sandbox_enabled FROM domains WHERE name = $1`, domain,
	).Scan(&enabled)
	return err == nil && enabled
}

// domainSandboxAction returns the sandbox action for the recipient's domain
// (reject or quarantine).
func (c *inConnState) domainSandboxAction(ctx context.Context, rcpt string) string {
	domain := extractDomain(rcpt)
	if domain == "" {
		return "quarantine"
	}
	var action string
	err := c.srv.pool.QueryRow(ctx,
		`SELECT sandbox_action FROM domains WHERE name = $1`, domain,
	).Scan(&action)
	if err != nil {
		return "quarantine"
	}
	return action
}

// detectAndProcessIMip detects an iMIP text/calendar payload in a delivered
// message, extracts it from the MIME scope whose authenticity was established,
// and hands it to caldav.ProcessITIP with the transport identity.
//
// dkimSignedLen (round 4, Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-003): when
// the verified DKIM signature carried an l= tag, this is the number of body
// bytes the signature actually authenticates (RFC 6376 §3.5). Content appended
// beyond that prefix — new MIME parts, METHOD lines, event properties — is
// UNAUTHENTICATED and must never reach ParseITIP, so the UNSIGNED path first
// cuts the body to the signed prefix before calendar extraction. 0 means "no
// l= tag / no verified signature": the full body is treated as the extraction
// scope, and the per-method role authentication inside ProcessITIP still gates
// every mutation.
//
// dkimCanonical (round 5, Astra HOLD): the verified signature's c= tag. l= is
// counted against the CANONICALIZED body (RFC 6376 §3.5) while the stored
// message body is the CRLF→LF intake canonicalization — canonical and stored
// lengths diverge by one byte per line break (plus relaxed WSP collapsing), so
// indexing the stored bytes with the raw l= value let an appended unsigned
// CANCEL inside that gap escape truncation entirely. dkimSignedBodyCut maps
// the authenticated length through the SAME canonicalization the bh= hash was
// verified with, so content processed == content signed under one
// transformation.
//
// Round 8 (Astra HOLD r15, mixed-evidence l= bypass): the DKIM-covered byte
// boundary is computed ONCE here, in c.data space, and carried alongside the
// extracted calendar in BOTH branches — DKIM evidence is CONTENT-BOUND and is
// eligible transport identity only when the verified signature covers the
// calendar actually processed. The unsigned branch proves coverage by
// construction (its extraction scope is truncated to the covered prefix). The
// S/MIME branch — whose calendar is authenticated by the S/MIME signature over
// the full content part, not by DKIM — anchors the verified content part's
// bytes inside c.data and clears DkimAligned when the processed calendar
// extends beyond the covered prefix; otherwise a replayed positive-l= DKIM
// prefix (preserved as MIME preamble) plus an appended tenant-trusted S/MIME
// CANCEL let the DKIM leg authorize cancellations the signature never covered.
// SPF evidence (rule (c)) is envelope-only with no content binding and stays
// untouched; scoped S/MIME evidence keeps its own per-mailbox trust policy.
func (c *inConnState) detectAndProcessIMip(ctx context.Context, msg string, identity caldav.ITIPTransportIdentity, dkimSignedLen int64, dkimCanonical string) {
	if !strings.Contains(strings.ToLower(msg), "text/calendar") {
		return
	}
	if !strings.Contains(strings.ToLower(msg), "method=") {
		return
	}

	// Round 8: the covered boundary, computed once, over c.data — the RAW
	// bytes the actual net/textproto DotReader canonicalized at DATA intake
	// and the exact input VerifyDKIM hashed, never on the trace-enriched,
	// ARC-sealed or link-protect-rewritten msg copy. dkimCoveredEnd is the
	// exclusive end offset of the authenticated body prefix (l= mapped onto
	// the stored bytes through the c= canonicalization); -1 when no bound
	// exists (no l= tag / no verified signature, or the canonical full body
	// fits within l=: every body byte is signed).
	dkimCoveredEnd := int64(-1)
	var cutScope string
	if dkimSignedLen > 0 && len(c.data) > 0 {
		if headers, body := splitHeadersBody(c.data); len(body) > 0 {
			if cut := dkimSignedBodyCut(body, dkimCanonical, dkimSignedLen); cut < int64(len(body)) {
				dkimCoveredEnd = int64(len(c.data)-len(body)) + cut
				cutScope = string(headers) + "\r\n" + string(body[:cut])
				c.srv.logger.Debug("iMIP: body cut to the DKIM l= signed prefix",
					"signed_len", dkimSignedLen, "body_len", len(body), "cut", cut)
			}
		}
	}

	// Round 3 (Astra HOLD): the iCalendar fed to ParseITIP must be exactly the
	// MIME part whose authenticity was established.
	//
	// S/MIME-signed message: the detached signature is graded with the FULL
	// trust policy — trusted chain against the recipient domain's pool (bundled
	// roots ∪ deployment-wide ∪ per-domain anchors), EmailProtection EKU,
	// validity window, and signer-email == From-header binding. The old
	// smime.Verify call checked signature math only, so an attacker's
	// self-signed "victim email" certificate authenticated the sender. Any
	// non-valid verdict (invalid/untrusted/unextractable) is fail-closed:
	// the message is dropped, never re-processed through the unsigned path.
	// The calendar is then extracted from the VERIFIED content part alone, so
	// an unsigned trailing METHOD:CANCEL part can no longer override signed
	// content (the old whole-message scan let it do exactly that).
	//
	// Unsigned message: extract from the message as before; the per-method role
	// authentication inside ProcessITIP (rules (a)/(b)/(c)) still applies.
	var ical string
	// Round 8: the processed calendar's absolute byte offsets in c.data space
	// (meaningful only when dkimCoveredEnd >= 0) and the per-branch coverage
	// verdict. The unsigned branch proves coverage by construction; the
	// S/MIME branch proves it positionally.
	var calStart, calEnd int64
	dkimCoversProcessed := true
	if isSMIMESigned(msg) {
		content, sigDER, err := extractSignedParts(msg)
		if err != nil {
			c.srv.logger.Warn("iMIP: S/MIME signed but failed to extract signature parts",
				"error", err, "from", c.from)
			return
		}
		res := smime.VerifyDetached(content, sigDER, identity.FromHeader,
			c.srv.smimeRootsForDomain(ctx, c.imipRecipientDomainID(ctx)))
		if res.Status != smime.StatusValid {
			c.srv.logger.Warn("iMIP: S/MIME signature not trusted — dropping calendar",
				"status", res.Status, "signer", res.SignerEmail, "from", c.from)
			return
		}
		identity.SmimeValid = true
		identity.SmimeSignerEmail = res.SignerEmail
		// Round 5/6 (Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-004): the signer
		// email's domain must be covered by the trust that VALIDATED the chain.
		// Round 6 resolves the anchor into a TRI-STATE scope — unrestricted
		// (bundled root / deployment-wide anchor), domain-scoped (per-tenant
		// anchor rows), or NONE (unknown/removed/unresolvable anchor or lookup
		// error) — and None fails rule (a) closed inside the identity instead
		// of degrading to unrestricted.
		identity.SmimeTrust, identity.SmimeTrustDomains = c.srv.smimeAnchorTrustScope(ctx, res.TrustAnchorPEM)
		c.srv.logger.Info("iMIP: S/MIME signature verified against trusted chain",
			"from", c.from, "signer_email", identity.SmimeSignerEmail,
			"trust_scope", int(identity.SmimeTrust), "trust_domains", identity.SmimeTrustDomains)

		partIdx, icalBody, calStart, calEnd, xerr := extractICalPart(string(content))
		if xerr != nil || icalBody == "" {
			c.srv.logger.Warn("iMIP: verified S/MIME content carries no text/calendar part",
				"error", xerr, "from", c.from)
			return
		}
		c.srv.logger.Debug("iMIP: calendar taken from verified content part", "part_index", partIdx)
		ical = icalBody
		if dkimCoveredEnd >= 0 {
			// Round 8: bind the DKIM evidence to the calendar actually
			// processed. The offsets above are relative to the verified
			// content part; anchor them in c.data space by locating the
			// content part's exact bytes (extraction is pure slicing, so the
			// bytes appear verbatim unless the msg copy was rewritten after
			// intake). If they cannot be located, no positional proof of DKIM
			// coverage can exist — fail closed for the DKIM evidence class.
			//
			// Round 10 (Astra r17 item 3): canonicalSignedContent now hands
			// CMS verification the RFC 8551 CRLF-canonical RECONSTRUCTION of
			// the part, so for an SMTP-intaked message those bytes no longer
			// appear verbatim inside the LF-stored c.data. The fence keeps
			// measuring the STORED bytes DKIM actually hashed: locate the
			// part's stored form (the DATA-intake LF canonicalization of the
			// same content — LF(CRLF(x)) == the stored x) and recompute the
			// calendar offsets in that same space. Neither mapping weakens the
			// fence — both are exact bijections between the verified content
			// and the stored bytes; an unlocatable content still fails the
			// DKIM evidence class closed.
			base := strings.Index(string(c.data), string(content))
			if base < 0 {
				storedContent := strings.ReplaceAll(string(content), "\r\n", "\n")
				if storedBase := strings.Index(string(c.data), storedContent); storedBase >= 0 {
					if _, _, s, e, serr := extractICalPart(storedContent); serr == nil {
						base = storedBase
						calStart, calEnd = s, e
					}
				}
			}
			if base < 0 {
				dkimCoversProcessed = false
			} else {
				calStart += int64(base)
				calEnd += int64(base)
				dkimCoversProcessed = calEnd <= dkimCoveredEnd
			}
		}
	} else {
		// Round 4/5/6 (Astra HOLD): an l=-carrying DKIM signature authenticates
		// only the first dkimSignedLen CANONICALIZED body bytes; appended
		// content beyond that is unauthenticated and must not extend the
		// calendar text fed to parsing. Round 6 computes AND applies the cut
		// on c.data — the RAW bytes the actual net/textproto DotReader
		// canonicalized at DATA intake and the exact input VerifyDKIM hashed —
		// never on the trace-enriched, ARC-sealed or link-protect-rewritten
		// msg copy, so the fence and the bh= hash always operate on one byte
		// string. dkimSignedBodyCut maps the canonical length back onto the
		// stored (LF) body through the same c= canonicalization, so the cut is
		// exact or strictly shorter — never looser. splitHeadersBody separates
		// at (and drops) the blank line, so the reconstruction re-adds it after
		// the header block; the extraction scope is the CUT RAW message.
		// Round 8: when that cut applied, the scope below IS
		// c.data[:dkimCoveredEnd] — DKIM coverage of whatever calendar it
		// yields holds by construction (dkimCoversProcessed stays true). The
		// truncation deliberately stays inside the UNSIGNED branch: the
		// S/MIME branch must still see the full message so its appended,
		// separately-signed parts can be verified and then judged against
		// the covered boundary positionally.
		if cutScope != "" {
			msg = cutScope
		}
		partIdx, icalBody, _, _, err := extractICalPart(msg)
		if err != nil || icalBody == "" {
			c.srv.logger.Debug("iMIP detected but failed to extract iCal part",
				"error", err, "part_index", partIdx)
			return
		}
		ical = icalBody
	}

	// Round 8 (Astra HOLD r15, mixed-evidence l= bypass): DNS (DKIM)
	// acceptance must not trust DkimAligned when the verified signature does
	// not cover the calendar actually processed. When an l= bound exists and
	// the processed calendar extends beyond it — e.g. the covered prefix was
	// replayed as MIME preamble and a separately trusted S/MIME CANCEL was
	// appended — the DKIM verdict remains a delivery signal but is NOT
	// eligible iTIP transport evidence: clearing DkimAligned removes rule (b)
	// everywhere (AuthenticatedAs, AuthenticatedSignerDomain, and the round-7
	// per-mailbox cancel-evidence OR) while SPF rule (c) and the S/MIME rule
	// (a) trust policy stay exactly as they are.
	if identity.DkimAligned && !dkimCoversProcessed {
		c.srv.logger.Warn("iMIP: DKIM pass does not cover the processed calendar — DKIM transport evidence ineligible",
			"dkim_domain", identity.DkimDomain,
			"covered_end", dkimCoveredEnd, "calendar_start", calStart, "calendar_end", calEnd)
		identity.DkimAligned = false
	}

	itipMsg, err := caldav.ParseITIP(ical)
	if err != nil {
		c.srv.logger.Debug("iMIP iTIP parse failed", "error", err)
		return
	}

	// iTIP role authentication (RFC 6047; security fix
	// D-MAILSERVER-INTERNAL-CALDAV-001/002, round 2) is ENFORCED in exactly one
	// place: inside ProcessITIP — REPLY requires AuthenticatedAs(claimed
	// attendee), CANCEL AuthenticatedAs(DB organizer) — using the full identity
	// above (S/MIME, DKIM-aligned From, envelope+SPF). The old intake-side
	// CANCEL envelope-vs-body-ORGANIZER drop lived here and was removed: it
	// wrongly rejected a DKIM-aligned organizer From whose envelope differs
	// (legitimate relayed iMIP, rule (b)) while accepting a bare spoofed
	// envelope that no longer authenticates under rule (c). The
	// body-vs-DB organizer comparison inside processCancel stays as the
	// target-selection guard. Envelope-vs-body-ORGANIZER mismatch remains a
	// Warn-only signal for the other methods (a REPLY's sender legitimately
	// differs from the body ORGANIZER).
	envFrom := strings.Trim(c.from, "<> ")
	if itipMsg.Method != caldav.MethodCancel &&
		itipMsg.Event.Organizer.Email != "" &&
		!strings.EqualFold(envFrom, itipMsg.Event.Organizer.Email) {
		c.srv.logger.Warn("iMIP sender mismatch",
			"envelope", c.from, "organizer", itipMsg.Event.Organizer.Email)
	}

	// Resolve accountID from the first local recipient mailbox
	var accountID int64
	for _, rcpt := range c.to {
		if err := c.srv.pool.QueryRow(ctx,
			`SELECT m.id FROM mailboxes m
			 JOIN aliases a ON a.mailbox_id = m.id
			 WHERE a.email = lower($1) AND mailbox_lifecycle_delivery_mode(m.id)<>'rejecting'`,
			rcpt,
		).Scan(&accountID); err == nil {
			break
		}
	}

	c.srv.logger.Info("iMIP iTIP message detected",
		"method", string(itipMsg.Method),
		"uid", itipMsg.Event.UID,
		"title", itipMsg.Event.Title,
	)

	if err := caldav.ProcessITIP(ctx, c.srv.pool, c.srv.logger, itipMsg, accountID, identity); err != nil {
		if errors.Is(err, caldav.ErrITIPUnauthenticated) {
			// Unsigned/unaligned senders are dropped here, after the role check
			// but before any reducer mutation — count and log, don't process.
			dropped := c.srv.imipRejected.Add(1)
			c.srv.logger.Warn("iMIP dropped: sender not authenticated for the claimed iTIP role",
				"method", string(itipMsg.Method), "uid", itipMsg.Event.UID,
				"envelope", c.from, "dropped_total", dropped)
		} else {
			c.srv.logger.Error("iMIP processing failed", "method", string(itipMsg.Method), "error", err)
		}
	}
}

func tcpAddrIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return "0.0.0.0"
}

// isSMIMESigned checks whether a MIME message is multipart/signed with S/MIME.
// Only inspects the top-level headers to avoid false positives from the message body.
// The header block is located line-ending-agnostically (indexHeaderBodySeparator):
// the production msg copy is CRLF trace headers ahead of LF-stored DotReader
// bytes and has no pure-CRLF blank line.
func isSMIMESigned(msg string) bool {
	headerEnd := indexHeaderBodySeparator(msg)
	if headerEnd < 0 {
		return false
	}
	headers := msg[:headerEnd]
	return strings.Contains(headers, `protocol="application/pkcs7-signature"`) ||
		strings.Contains(headers, `protocol="application/x-pkcs7-signature"`)
}

// imipRecipientDomainID resolves the recipient domain id used to scope the
// per-tenant S/MIME trust pool for iMIP verification (same policy as the
// message-level verdict in deliver(): bundle ∪ deployment-wide ∪ this domain's
// anchors). Best effort — 0 (bundle ∪ deployment-wide) when no recipient
// resolves, mirroring the fail-open domain lookup there.
func (c *inConnState) imipRecipientDomainID(ctx context.Context) int64 {
	for _, rcpt := range c.to {
		at := strings.LastIndex(rcpt, "@")
		if at < 0 {
			continue
		}
		var id int64
		if err := c.srv.pool.QueryRow(ctx,
			`SELECT id FROM domains WHERE lower(name) = lower($1)`, rcpt[at+1:]).Scan(&id); err == nil {
			return id
		}
		return 0
	}
	return 0
}

// extractSMIMEBoundary extracts the boundary value from a multipart/signed Content-Type header.
// Header lines may end in CRLF or LF (the stored DotReader form is LF-only).
func extractSMIMEBoundary(headers string) string {
	for _, raw := range strings.Split(headers, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "Content-Type:") {
			for _, part := range strings.Split(line, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "boundary=") {
					b := strings.TrimPrefix(part, "boundary=")
					return strings.Trim(b, `"`)
				}
			}
		}
	}
	return ""
}

// resolveMailboxID looks up the mailbox ID for a recipient email address.
// Returns 0 if the mailbox cannot be resolved (best-effort for audit trail).
func (c *inConnState) resolveMailboxID(ctx context.Context, rcpt string) int64 {
	var mailboxID int64
	err := c.srv.pool.QueryRow(ctx,
		`SELECT m.id FROM mailboxes m
		 JOIN aliases a ON a.mailbox_id = m.id
		 WHERE a.email = lower($1) AND m.enabled = TRUE
		 LIMIT 1`, rcpt,
	).Scan(&mailboxID)
	if err != nil {
		return 0
	}
	return mailboxID
}

// emptyToNil converts an empty string to nil (for pgx NULL parameter binding).
// A non-empty string is returned as a *string so pgx maps it to a non-NULL SQL value.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// bodyMutatorsApply reports whether link-protect/anti-phish body rewriting should run.
// Only a fully-valid S/MIME signature exempts a message (so verified==stored); everything
// else (invalid/untrusted/unsigned) is still mutated — a broken sig cannot bypass link-protect.
func bodyMutatorsApply(smimeRes *smime.VerifyResult) bool {
	return smimeRes == nil || smimeRes.Status != smime.StatusValid
}
