package federation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// Anchor pins the trust root for one peer domain — sourced from
// federation_allowlist.peer_anchor at allow-listing time (Global
// Constraints: exchanged human-to-human, never auto-trusted, never derived
// from the wire). This spike implements the CA-certificate form only,
// matching testharness/gen-certs.sh's one-CA-per-domain shape; a leaf SPKI
// pin is a named C1 alternative, not built here.
type Anchor struct {
	CACert *x509.Certificate
}

// pool returns a CertPool containing ONLY this anchor's CA — deliberately
// never a shared/multi-peer RootCAs bundle, so a cert issued by peer B's CA
// can never validate against peer A's pinned anchor (R1: anchors are
// per-peer, not a flat trust bundle).
func (a Anchor) pool() *x509.CertPool {
	p := x509.NewCertPool()
	if a.CACert != nil {
		p.AddCert(a.CACert)
	}
	return p
}

var (
	// ErrPeerAnchorMismatch is returned when a peer's presented certificate
	// does not chain to the anchor pinned on the local allow-list row for
	// that domain.
	ErrPeerAnchorMismatch = errors.New("federation: peer certificate does not chain to the pinned trust anchor")
	// ErrPeerDomainMismatch is returned when the asserted domain (Hello.FromDomain,
	// or the Dial caller's expected domain) does not match the peer
	// certificate's SAN, or the peer hello disagrees with what was expected.
	ErrPeerDomainMismatch = errors.New("federation: peer domain does not match the asserted/expected identity")
	// ErrFederationDisabled is returned by Dial/Listen/AcceptStream when
	// toggle.FeatureFederation is OFF (D11) — a no-op, not a wire-level
	// failure.
	ErrFederationDisabled = errors.New("federation: feature.federation is OFF")
	// ErrPeerNotAuthorized is returned by AcceptStream when
	// federation_peer_authorize refuses the dialer (BZ203 — Task 3/E4): no
	// local enabled allow-list row for the dialer's domain, or the row's
	// scope does not cover the requested scope. Distinct from
	// ErrPeerAnchorMismatch — the anchor check answers "is this really who it
	// claims to be" (R1); this answers "have WE chosen to talk to them at
	// all" (R4, mutual opt-in).
	ErrPeerNotAuthorized = errors.New("federation: peer not locally allow-listed/enabled for the requested scope")
)

// Accept-loop resource bounds. The s2s listener shares its process with the
// webmail/HTTP listeners, so unauthenticated federation work must never grow
// without bound. Each value below is an ops tunable, not derived policy: the
// defaults are conservative starting points for ops review, no production
// flag gates them, and they are vars (not consts) ONLY so the bounded tests
// in stream_accept_bounds_test.go can shrink them deterministically —
// production code never writes them.
var (
	// handshakeTimeout bounds the TLS handshake of an inbound connection: a
	// client that opens a socket but stalls (slowloris) is dropped when it
	// fires instead of holding a connection and goroutine forever.
	handshakeTimeout = 10 * time.Second
	// helloReadTimeout bounds the post-handshake hello read AND the anchor
	// lookup / federation_peer_authorize round-trips between hello and the
	// outbound hello write (fail-closed: a slow local dependency drops the
	// inbound connection rather than extending the unauthenticated window).
	helloReadTimeout = 10 * time.Second
	// lookupAuthorizeTimeout bounds the post-TLS anchor lookup /
	// federation_peer_authorize window by CONTEXT, not socket deadline: those
	// steps are local database calls that never touch conn I/O, so a stalled
	// pool acquisition would otherwise hold a handshake slot forever no matter
	// what deadlines the socket carries (all slots held ⇒ federation ingress
	// stalls indefinitely). The derived context is cancelled at this bound,
	// pgx honors it on acquire and query, and AcceptStream unwinds — dropping
	// the peer instead of occupying admission capacity indefinitely.
	lookupAuthorizeTimeout = 10 * time.Second
	// acceptRetryBackoff pauses the accept loop after a transient Accept
	// error (e.g. EMFILE) so a pathological error storm cannot busy-spin.
	acceptRetryBackoff = 100 * time.Millisecond
	// maxInFlightHandshakes caps connections inside the UNAUTHENTICATED
	// window (TLS handshake + hello + authorization). Excess connections are
	// closed at accept, never queued — a queued unauthenticated connection is
	// exactly the resource hold these bounds exist to prevent.
	maxInFlightHandshakes = 64
	// maxConcurrentStreams caps ALL live inbound s2s connections, accepted
	// streams included (one slot per connection from accept until its close).
	maxConcurrentStreams = 256
)

// PeerStream is one live, mutually cert-authenticated s2s connection to a
// peer domain. It is a dumb transport (DES-011) — no authority lives here.
type PeerStream struct {
	conn   net.Conn
	Domain string // the peer's asserted+verified domain
	Hello  Hello  // the peer's hello frame
}

func (s *PeerStream) WriteFrame(f Frame) error  { return WriteFrame(s.conn, f) }
func (s *PeerStream) ReadFrame() (Frame, error) { return ReadFrame(s.conn) }
func (s *PeerStream) Close() error              { return s.conn.Close() }

// leafSANMatches reports whether cert's DNS SANs include domain.
func leafSANMatches(cert *x509.Certificate, domain string) bool {
	for _, san := range cert.DNSNames {
		if san == domain {
			return true
		}
	}
	return false
}

// verifyAgainstAnchor is the ONE anchor-validation routine shared by both
// Dial (validating the server leaf inside tls.Config.VerifyConnection)
// and AcceptStream (validating the client leaf after ConnectionState(),
// post-hello) — R1's real question ("does anchor-on-allowlist bind identity
// for two strangers with no shared CA") is answered by this one code path,
// exercised from both directions.
func verifyAgainstAnchor(rawCerts [][]byte, anchor Anchor, expectDomain string) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, fmt.Errorf("federation: peer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("federation: parse presented certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		if c, err := x509.ParseCertificate(raw); err == nil {
			intermediates.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         anchor.pool(),
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPeerAnchorMismatch, err)
	}
	if expectDomain != "" && !leafSANMatches(leaf, expectDomain) {
		return nil, fmt.Errorf("%w: leaf SAN does not include %s", ErrPeerDomainMismatch, expectDomain)
	}
	return leaf, nil
}

// Dial establishes an outbound s2s stream to endpoint.Domain (already
// resolved via ResolvePeer). Anchor validation happens INSIDE
// tls.Config.VerifyConnection — the dialer knows the target's anchor
// upfront, so it validates the server leaf against it directly rather than
// via a shared RootCAs bundle (InsecureSkipVerify is set deliberately;
// VerifyConnection below IS the real, per-peer-anchor check, and unlike
// VerifyPeerCertificate it also runs on a resumed session). After
// the handshake, Dial sends its own hello, reads the peer's hello, and
// asserts hello.FromDomain == endpoint.Domain.
func Dial(ctx context.Context, flags *toggle.FeatureFlags, endpoint PeerEndpoint, clientCert tls.Certificate, anchor Anchor, hello Hello) (*PeerStream, error) {
	if !flags.IsEnabled(toggle.FeatureFederation) {
		return nil, ErrFederationDisabled
	}

	addr := net.JoinHostPort(endpoint.Target, strconv.Itoa(int(endpoint.Port)))
	cfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		// #nosec G402 -- InsecureSkipVerify is deliberate: per-peer anchor pinning replaces chain-to-RootCAs; VerifyConnection below IS the real anchor check (runs on resumed sessions too). See the Dial doc comment.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		// VerifyConnection (not VerifyPeerCertificate) so the per-peer-anchor
		// check ALSO runs on a resumed TLS 1.3 session — a resumed handshake
		// skips VerifyPeerCertificate, which would silently bypass anchor
		// validation (gosec G123). Session resumption is disabled belt-and-
		// suspenders (no benefit for one long-lived stream per peer anyway).
		SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			_, err := verifyAgainstAnchor(raw, anchor, endpoint.Domain)
			return err
		},
	}

	var dialer tls.Dialer
	dialer.Config = cfg
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err // may wrap ErrPeerAnchorMismatch/ErrPeerDomainMismatch straight from VerifyPeerCertificate
	}

	if err := WriteFrame(conn, Frame{Kind: KindHello, Payload: mustJSON(hello)}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("federation: dial: send hello: %w", err)
	}
	peerHello, err := readHello(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("federation: dial: %w", err)
	}
	if peerHello.FromDomain != endpoint.Domain {
		conn.Close()
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrPeerDomainMismatch, endpoint.Domain, peerHello.FromDomain)
	}

	return &PeerStream{conn: conn, Domain: endpoint.Domain, Hello: peerHello}, nil
}

// AnchorLookup resolves a peer domain's pinned trust anchor — the
// Listen-side analog of the anchor a Dial caller already holds. Production
// wiring (Task 3) backs this with a federation_allowlist read on
// DB_WORKER_DSN (the table is FORCE RLS deny-all — Global Constraints);
// tests inject a map-backed stub.
type AnchorLookup func(ctx context.Context, domain string) (anchor Anchor, ok bool, err error)

// authorizePeer calls federation_peer_authorize (Task 3/E4) — the LOCAL
// refusal gate, distinct from and run AFTER anchor validation. A refusal
// (BZ203: no local enabled allow-list row, or a scope mismatch) surfaces as
// ErrPeerNotAuthorized; any other error is a genuine infra failure.
func authorizePeer(ctx context.Context, pool pgxutil.WorkerPool, peerDomain, scope string) error {
	var ok bool
	err := pool.QueryRow(ctx, `SELECT federation_peer_authorize($1,$2)`, peerDomain, scope).Scan(&ok)
	if err != nil {
		if reducererr.IsCode(err, "BZ203") {
			return fmt.Errorf("%w: %s (scope %s)", ErrPeerNotAuthorized, peerDomain, scope)
		}
		return fmt.Errorf("federation: authorize peer %s: %w", peerDomain, err)
	}
	return nil
}

// AcceptStream performs the Listen-side handshake + anchor validation +
// LOCAL authorization for one already-accepted net.Conn. TLS requires ANY
// client certificate (tls.RequireAnyClientCert) — unlike Dial, the listener
// cannot know the per-peer anchor until it reads hello.FromDomain, which
// only arrives AFTER the TLS handshake completes. So the client cert is
// accepted unconditionally at the TLS layer, and validated against the
// allow-list row's anchor (via lookup) only after the hello frame is read.
// AFTER the anchor validates, authorizePeer (federation_peer_authorize,
// Task 3/E4 — the LOCAL enabled-allow-list + scope gate) runs — and only
// once THAT passes does AcceptStream send its own hello back and return the
// stream: before that point, no non-hello frame can ever flow, because the
// stream does not exist yet from the caller's perspective.
func AcceptStream(ctx context.Context, conn net.Conn, tlsCfg *tls.Config, lookup AnchorLookup, hello Hello, pool pgxutil.WorkerPool, scope string) (*PeerStream, error) {
	cfg := tlsCfg.Clone()
	cfg.ClientAuth = tls.RequireAnyClientCert
	cfg.MinVersion = tls.VersionTLS13

	// Arm the handshake deadline BEFORE the TLS handshake. HandshakeContext
	// alone bounds nothing here — callers pass a long-lived, undedlined ctx —
	// so a client that opens a socket and stalls (slowloris) would otherwise
	// hold its connection and goroutine forever.
	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("federation: listen: arm handshake deadline: %w", err)
	}

	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: TLS handshake: %w", err)
	}

	// Re-arm for the hello read plus the local anchor lookup / authorization
	// round-trips below: a client that completes TLS but never sends hello is
	// dropped by this deadline instead of extending the unauthenticated
	// window. The deadline stays armed through the outbound hello write.
	if err := tlsConn.SetDeadline(time.Now().Add(helloReadTimeout)); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: arm hello deadline: %w", err)
	}

	// The socket deadline bounds only conn I/O — lookup and authorizePeer are
	// local database calls that never touch it, so both run under a
	// lookupAuthorizeTimeout-derived context instead of the caller's
	// (service-lifetime, undedlined) ctx. A stalled pool acquisition cancels
	// at the bound, AcceptStream unwinds, and the handshake slot is freed
	// rather than held indefinitely.
	authCtx, cancel := context.WithTimeout(ctx, lookupAuthorizeTimeout)
	defer cancel()

	dialerHello, err := readHello(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: %w", err)
	}

	anchor, ok, err := lookup(authCtx, dialerHello.FromDomain)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: anchor lookup for %s: %w", dialerHello.FromDomain, err)
	}
	if !ok {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("%w: no allow-list row for %s", ErrPeerAnchorMismatch, dialerHello.FromDomain)
	}

	state := tlsConn.ConnectionState()
	rawCerts := make([][]byte, len(state.PeerCertificates))
	for i, c := range state.PeerCertificates {
		rawCerts[i] = c.Raw
	}
	if _, err := verifyAgainstAnchor(rawCerts, anchor, dialerHello.FromDomain); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	if err := authorizePeer(authCtx, pool, dialerHello.FromDomain, scope); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	if err := WriteFrame(tlsConn, Frame{Kind: KindHello, Payload: mustJSON(hello)}); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: send hello: %w", err)
	}

	// The deadlines bound only the unauthenticated window; the returned
	// stream is long-lived and must not inherit them.
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("federation: listen: clear deadlines: %w", err)
	}

	return &PeerStream{conn: tlsConn, Domain: dialerHello.FromDomain, Hello: dialerHello}, nil
}

// Listen accepts s2s connections on ln until ctx is done, handshaking each
// via AcceptStream (anchor validation + federation_peer_authorize, both
// against pool) and invoking onStream for every successfully authenticated
// AND authorized PeerStream. A connection that fails handshake, anchor
// validation, or authorization is closed and logged — it is never handed to
// onStream (DES-011: a stream only exists once fully authenticated AND
// locally authorized).
//
// Resource bounds (this listener shares the process with the webmail/HTTP
// listeners, so unauthenticated s2s work must never grow without bound):
//   - every inbound connection is deadline-bounded by AcceptStream;
//   - at most maxInFlightHandshakes connections are inside the
//     unauthenticated window and at most maxConcurrentStreams connections
//     exist at once; excess connections are closed at accept, never queued;
//   - a transient Accept error (EINTR/EAGAIN/ECONNABORTED/EMFILE/ENFILE, or
//     an accept timeout) is logged and retried after acceptRetryBackoff, so
//     one bad accept does not kill federation ingress; any other error exits
//     loudly to the caller, whose operator-facing log records it.
func Listen(ctx context.Context, flags *toggle.FeatureFlags, ln net.Listener, tlsCfg *tls.Config, lookup AnchorLookup, hello Hello, pool pgxutil.WorkerPool, scope string, logger *slog.Logger, onStream func(*PeerStream)) error {
	if !flags.IsEnabled(toggle.FeatureFederation) {
		return ErrFederationDisabled
	}
	handshakeSlots := make(chan struct{}, maxInFlightHandshakes)
	connSlots := make(chan struct{}, maxConcurrentStreams)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			if isTransientAcceptError(err) {
				logger.Warn("federation: transient accept error — retrying", "error", err)
				if !sleepAcceptBackoff(ctx, acceptRetryBackoff) {
					return nil // cancelled mid-backoff: clean shutdown
				}
				continue
			}
			return fmt.Errorf("federation: accept: %w", err)
		}

		// Admission control: drop (never queue) connections that would exceed
		// a bound — a queued unauthenticated connection is exactly the
		// slowloris resource hold these bounds exist to prevent, and the
		// kernel listen backlog already bounds pending dials meanwhile.
		select {
		case handshakeSlots <- struct{}{}:
		default:
			_ = conn.Close()
			logger.Warn("federation: in-flight handshake bound reached — dropping connection")
			continue
		}
		select {
		case connSlots <- struct{}{}:
		default:
			<-handshakeSlots
			_ = conn.Close()
			logger.Warn("federation: concurrent connection bound reached — dropping connection")
			continue
		}

		// Tie the connection slot to the connection's real lifetime: released
		// on the FIRST close, whether that is AcceptStream closing a rejected
		// handshake or the onStream owner eventually closing an accepted
		// PeerStream (the production onStream hands the stream to a separate
		// goroutine, so the slot must not depend on that callback returning).
		conn = &slotReleaseConn{Conn: conn, release: func() { <-connSlots }}
		go func() {
			defer func() { <-handshakeSlots }()
			stream, err := AcceptStream(ctx, conn, tlsCfg, lookup, hello, pool, scope)
			if err != nil {
				logger.Warn("federation: inbound stream rejected", "error", err)
				return
			}
			onStream(stream)
		}()
	}
}

// slotReleaseConn releases its Listen-loop connection slot exactly once, on
// the first Close of the wrapped connection.
type slotReleaseConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *slotReleaseConn) Close() error {
	var err error
	c.once.Do(func() {
		err = c.Conn.Close()
		c.release()
	})
	return err
}

// transientAcceptErrnos are the errno-carrying Accept failures that are
// known-transient conditions rather than a broken listener: an interrupted
// call, a connection reset between ESTABLISHED and Accept (ECONNABORTED,
// routine under load), and fd exhaustion (EMFILE/ENFILE, which the bounded
// backoff rides out until fds free up).
var transientAcceptErrnos = []error{
	syscall.EINTR,
	syscall.EAGAIN,
	syscall.ECONNABORTED,
	syscall.EMFILE,
	syscall.ENFILE,
}

// isTransientAcceptError classifies an Accept error. Transient conditions are
// logged and retried; anything else — including a closed listener outside
// shutdown and unrecoverable listener-state errors — must exit loudly so the
// operator sees federation ingress is down.
func isTransientAcceptError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	for _, transient := range transientAcceptErrnos {
		if errors.Is(err, transient) {
			return true
		}
	}
	return false
}

// sleepAcceptBackoff pauses d before the next Accept retry, aborting early on
// shutdown. It reports whether the full backoff elapsed (false = ctx done).
func sleepAcceptBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// readHello reads the next frame from r, requiring it to be a hello, and
// decodes its payload.
func readHello(r io.Reader) (Hello, error) {
	f, err := ReadFrame(r)
	if err != nil {
		return Hello{}, fmt.Errorf("read hello: %w", err)
	}
	if f.Kind != KindHello {
		return Hello{}, fmt.Errorf("expected hello frame, got %q", f.Kind)
	}
	var h Hello
	if err := json.Unmarshal(f.Payload, &h); err != nil {
		return Hello{}, fmt.Errorf("unmarshal hello: %w", err)
	}
	return h, nil
}
