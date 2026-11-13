package federation

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// These tests exercise Listen/AcceptStream's resource bounds: handshake and
// hello deadlines (slowloris), the in-flight-handshake and concurrent-
// connection caps, and transient-vs-permanent accept-error classification.
// All listeners are in-process loopback listeners; no external network.

// shrinkBounds installs small accept-loop bounds for a deterministic test and
// restores the production values via t.Cleanup. Tests must call it BEFORE
// starting Listen (the bounds are read at loop start), and its cleanup runs
// after startBoundedListen's cleanup has joined the loop goroutine (LIFO).
func shrinkBounds(t *testing.T, set func()) {
	t.Helper()
	origHandshake, origHello, origBackoff := handshakeTimeout, helloReadTimeout, acceptRetryBackoff
	origLookupAuth := lookupAuthorizeTimeout
	origHandshakes, origStreams := maxInFlightHandshakes, maxConcurrentStreams
	t.Cleanup(func() {
		handshakeTimeout, helloReadTimeout, acceptRetryBackoff = origHandshake, origHello, origBackoff
		lookupAuthorizeTimeout = origLookupAuth
		maxInFlightHandshakes, maxConcurrentStreams = origHandshakes, origStreams
	})
	set()
}

// syncBuffer is a concurrency-safe buffer for log assertions — Listen logs
// from its loop goroutine and from per-connection goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startBoundedListen runs Listen against ln with a capturing logger and a
// stop cleanup that cancels the ctx, closes the listener, and FAILS the test
// if Listen does not return within 5s (a stuck accept loop must never leak).
func startBoundedListen(t *testing.T, ln net.Listener, tlsCfg *tls.Config, helloDomain string, lookup AnchorLookup, pool pgxutil.WorkerPool, onStream func(*PeerStream)) *syncBuffer {
	t.Helper()
	logBuf := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Listen(ctx, onFlags(), ln, tlsCfg, lookup, Hello{FromDomain: helloDomain, Ver: 1}, pool, "dm",
			slog.New(slog.NewTextHandler(logBuf, nil)), onStream)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("Listen did not return within 5s of shutdown")
		}
	})
	return logBuf
}

// serverClosedWithin reports whether the server closed c within d. Bytes a
// failing TLS handshake may push mid-close are discarded; the test's own read
// deadline is the guard, so false means "server still holding c open".
func serverClosedWithin(t *testing.T, c net.Conn, d time.Duration) bool {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("arm test guard deadline: %v", err)
	}
	buf := make([]byte, 1)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		return !errors.Is(err, os.ErrDeadlineExceeded) // guard fired = still open
	}
}

// scriptedAccept is one scripted Accept result.
type scriptedAccept struct {
	conn net.Conn
	err  error
}

// scriptedListener serves a fixed script of Accept results, then delegates to
// the embedded live listener — the seam for injecting accept errors into
// Listen's real loop without touching production code.
type scriptedListener struct {
	net.Listener
	scriptMu sync.Mutex
	script   []scriptedAccept
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.scriptMu.Lock()
	if len(l.script) > 0 {
		next := l.script[0]
		l.script = l.script[1:]
		l.scriptMu.Unlock()
		return next.conn, next.err
	}
	l.scriptMu.Unlock()
	return l.Listener.Accept()
}

// injectedNetError is a net.Error-flavoured accept failure with
// Timeout()=true, standing in for a deadline-class transient accept error.
type injectedNetError struct{ msg string }

func (e *injectedNetError) Error() string   { return e.msg }
func (e *injectedNetError) Timeout() bool   { return true }
func (e *injectedNetError) Temporary() bool { return true }

// boundsTLSCfg builds a server-side TLS config for the listener tests (client
// certs are asserted at hello time by these bounds tests, not at the TLS
// layer's identity checks).
func boundsTLSCfg(t *testing.T) *tls.Config {
	t.Helper()
	return &tls.Config{
		Certificates: []tls.Certificate{issueLeaf(t, newCA(t, "stream-bounds-CA"), "bounds.test")},
		MinVersion:   tls.VersionTLS13,
	}
}

// TestListenSlowlorisDroppedByDeadlineWithoutStarving: raw clients that open
// a socket and send nothing (slowloris) are dropped by the handshake
// deadline — and while they sit stalled, a dialer that makes real progress
// is still served promptly, so stalled clients cannot starve the listener
// that shares the process with the webmail/HTTP listeners.
func TestListenSlowlorisDroppedByDeadlineWithoutStarving(t *testing.T) {
	shrinkBounds(t, func() {
		handshakeTimeout = 500 * time.Millisecond
		helloReadTimeout = 500 * time.Millisecond
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	logBuf := startBoundedListen(t, ln, boundsTLSCfg(t),
		"bounds.test",
		func(context.Context, string) (Anchor, bool, error) { return Anchor{}, false, nil },
		pgxutil.WorkerPool{}, func(*PeerStream) {})

	// Slowloris dials: complete the TCP handshake, then send nothing.
	const stalled = 3
	stalledConns := make([]net.Conn, 0, stalled)
	for i := 0; i < stalled; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("slowloris dial %d: %v", i, err)
		}
		defer func() { _ = c.Close() }() // Go 1.22+ per-iteration loop var
		stalledConns = append(stalledConns, c)
	}
	// Let the accept loop accept every stalled conn before proceeding.
	time.Sleep(500 * time.Millisecond)

	// While the stalled conns hold their slots, a dialer that makes real
	// progress must still be served promptly. RequireAnyClientCert rejects
	// this certless dialer right after the handshake — a fast, non-timeout
	// outcome is the progress proof.
	progress := make(chan error, 1)
	go func() {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true, // test-only dial to our own listener; identity checks are the R1 tests' job
			MinVersion:         tls.VersionTLS13,
		})
		if err != nil {
			progress <- err
			return
		}
		_ = c.Close()
		progress <- nil
	}()
	select {
	case err := <-progress:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("concurrent dialer was starved by stalled slowloris connections: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent dialer made no progress within 3s — listener starved")
	}

	// Each stalled client must be dropped BY THE DEADLINE (not held forever,
	// not dropped earlier by some other path): well inside the 4s guard.
	for i, c := range stalledConns {
		if !serverClosedWithin(t, c, 4*time.Second) {
			t.Fatalf("stalled slowloris conn %d was not closed by the handshake deadline", i)
		}
	}

	if !strings.Contains(logBuf.String(), "inbound stream rejected") {
		t.Fatalf("deadline drops were not logged as rejections; log:\n%s", logBuf.String())
	}
}

// TestListenHandshakeBoundDropsExcessAndRecovers: with the in-flight
// handshake bound full of stalled clients, the next connection is dropped at
// accept (never queued) and the drop is logged; once the stalled clients
// release their slots, admission recovers.
func TestListenHandshakeBoundDropsExcessAndRecovers(t *testing.T) {
	shrinkBounds(t, func() {
		maxInFlightHandshakes = 2
		maxConcurrentStreams = 8 // not the binding constraint here
		handshakeTimeout = 10 * time.Second
		helloReadTimeout = 10 * time.Second // the cap, not a deadline, must do the dropping
		acceptRetryBackoff = 10 * time.Millisecond
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	logBuf := startBoundedListen(t, ln, boundsTLSCfg(t),
		"bounds.test",
		func(context.Context, string) (Anchor, bool, error) { return Anchor{}, false, nil },
		pgxutil.WorkerPool{}, func(*PeerStream) {})

	// Hold every handshake slot with a stalled raw client; extra probes that
	// slip in before the first two are accepted simply occupy a slot too.
	var holders []net.Conn
	defer func() {
		for _, c := range holders {
			_ = c.Close()
		}
	}()
	dropped := false
	for attempt := 0; attempt < 6 && !dropped; attempt++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("probe dial %d: %v", attempt, err)
		}
		// A bound-exceeded drop happens immediately at accept, so a short
		// guard suffices; a probe that is admitted burns the whole guard and
		// then joins the holders.
		if serverClosedWithin(t, c, 1*time.Second) {
			dropped = true // dropped at accept because the bound was full
			_ = c.Close()
			break
		}
		holders = append(holders, c) // admitted — it now helps fill the bound
		time.Sleep(100 * time.Millisecond)
	}
	if !dropped {
		t.Fatal("no connection was dropped while the in-flight handshake bound was full")
	}
	logContains(t, logBuf, "in-flight handshake bound reached", 10*time.Second)

	// Release every slot; admission must recover. Closing each holder
	// unblocks its server-side handshake read, which ends AcceptStream and
	// frees the slot via the loop's defer.
	for _, c := range holders {
		_ = c.Close()
	}
	if !eventuallyAdmitted(t, ln) {
		t.Fatal("no connection was admitted after the handshake bound freed — slots leaked")
	}
}

// TestListenConcurrentStreamBoundTracksStreamLifetime (DB-backed — the one
// bound that needs a fully authorized stream): a live stream occupies the
// entire concurrent-connection bound even though its handshake slot was
// freed at AcceptStream's return; the bound is released only when the stream
// OWNER closes it — long after Listen's per-connection goroutine returned —
// and admission then recovers.
func TestListenConcurrentStreamBoundTracksStreamLifetime(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx0 := context.Background()
	if _, err := pool.Exec(ctx0,
		`INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		 VALUES ('alpha.test', 'stream_accept_bounds_test.go fixture', 'dm', true)
		 ON CONFLICT (peer_domain) DO UPDATE SET scope='dm', enabled=true`); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx0, `DELETE FROM federation_allowlist WHERE peer_domain = 'alpha.test'`) //nolint:errcheck
	})
	workerPool := pgxutil.WorkerPool{Pool: pool}

	shrinkBounds(t, func() {
		maxInFlightHandshakes = 8 // not the binding constraint here
		maxConcurrentStreams = 1  // the live stream occupies the entire bound
		handshakeTimeout = 10 * time.Second
		helloReadTimeout = 10 * time.Second
	})

	alphaCA := newCA(t, "alpha.test-CA")
	bravoCA := newCA(t, "bravo.test-CA")
	alphaLeaf := issueLeaf(t, alphaCA, "alpha.test")
	bravoLeaf := issueLeaf(t, bravoCA, "bravo.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Own accepted streams like production's onStream does: it hands each to
	// a long-lived owner that closes it much later than Listen's per-conn
	// goroutine (which returns immediately after onStream).
	var streamsMu sync.Mutex
	var serverStreams []*PeerStream
	logBuf := startBoundedListen(t, ln, &tls.Config{Certificates: []tls.Certificate{bravoLeaf}, MinVersion: tls.VersionTLS13},
		"bravo.test",
		func(_ context.Context, domain string) (Anchor, bool, error) {
			if domain == "alpha.test" {
				return Anchor{CACert: alphaCA.cert}, true, nil
			}
			return Anchor{}, false, nil
		},
		workerPool, func(s *PeerStream) {
			streamsMu.Lock()
			serverStreams = append(serverStreams, s)
			streamsMu.Unlock()
		})

	endpoint := PeerEndpoint{Domain: "bravo.test", Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := Dial(ctx, onFlags(), endpoint, alphaLeaf, Anchor{CACert: bravoCA.cert}, Hello{FromDomain: "alpha.test", Ver: 1})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = stream.Close() }()

	// The one live stream fills the concurrent-connection bound even though
	// no handshake is in flight anymore: a fresh raw dial must be dropped at
	// accept, not queued.
	probe, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	if !serverClosedWithin(t, probe, 3*time.Second) {
		_ = probe.Close()
		t.Fatal("excess connection was not dropped while the concurrent-connection bound was full")
	}
	_ = probe.Close()
	logContains(t, logBuf, "concurrent connection bound reached", 10*time.Second)

	// The owner closing the accepted stream — the production disconnect shape
	// — must release the bound.
	streamsMu.Lock()
	if len(serverStreams) != 1 {
		streamsMu.Unlock()
		t.Fatalf("onStream saw %d streams, want 1", len(serverStreams))
	}
	accepted := serverStreams[0]
	streamsMu.Unlock()
	if err := accepted.Close(); err != nil {
		t.Fatalf("server-side stream close: %v", err)
	}

	if !eventuallyAdmitted(t, ln) {
		t.Fatal("no connection was admitted after the accepted stream was closed — the connection slot leaked")
	}
}

// TestListenSurvivesTransientAcceptErrors: injected transient accept errors
// are logged and survived; the loop then still serves a real dial.
func TestListenSurvivesTransientAcceptErrors(t *testing.T) {
	shrinkBounds(t, func() {
		acceptRetryBackoff = 20 * time.Millisecond
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	scripted := &scriptedListener{
		Listener: ln,
		script: []scriptedAccept{
			{err: &injectedNetError{msg: "injected transient accept failure one"}},
			{err: &injectedNetError{msg: "injected transient accept failure two"}},
		},
	}
	logBuf := startBoundedListen(t, scripted, boundsTLSCfg(t),
		"bounds.test",
		func(context.Context, string) (Anchor, bool, error) { return Anchor{}, false, nil },
		pgxutil.WorkerPool{}, func(*PeerStream) {})

	if !eventuallyAdmitted(t, ln) {
		t.Fatal("Listen did not serve a real dial after transient accept errors")
	}
	logContains(t, logBuf, "transient accept error", 10*time.Second)
	logContains(t, logBuf, "injected transient accept failure one", 10*time.Second)
}

// TestListenPermanentAcceptErrorExitsLoudly: a permanent accept error with a
// live ctx is surfaced to the caller (whose operator-facing log records it),
// not swallowed.
func TestListenPermanentAcceptErrorExitsLoudly(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	permanent := errors.New("injected permanent listener failure")
	scripted := &scriptedListener{
		Listener: ln,
		script:   []scriptedAccept{{err: permanent}},
	}
	err = Listen(context.Background(), onFlags(), scripted, &tls.Config{}, nil, Hello{},
		pgxutil.WorkerPool{}, "dm", testLogger(), func(*PeerStream) {})
	if !errors.Is(err, permanent) {
		t.Fatalf("Listen error = %v, want the injected permanent error surfaced", err)
	}
}

// TestIsTransientAcceptErrorClassification pins the classification table:
// deadline-flavoured errors and the known errno set retry; a closed listener
// and anything unrecognised exit loudly.
func TestIsTransientAcceptErrorClassification(t *testing.T) {
	transient := []error{
		&injectedNetError{msg: "deadline-class accept error"},
		fmt.Errorf("wrapped: %w", syscall.EINTR),
		fmt.Errorf("wrapped: %w", syscall.EAGAIN),
		fmt.Errorf("wrapped: %w", syscall.ECONNABORTED),
		fmt.Errorf("wrapped: %w", syscall.EMFILE),
		fmt.Errorf("wrapped: %w", syscall.ENFILE),
	}
	for _, err := range transient {
		if !isTransientAcceptError(err) {
			t.Errorf("isTransientAcceptError(%v) = false, want true", err)
		}
	}

	permanent := []error{
		errors.New("unrecognised listener failure"),
		net.ErrClosed,
		fmt.Errorf("wrapped: %w", net.ErrClosed),
		fmt.Errorf("wrapped: %w", syscall.EACCES),
	}
	for _, err := range permanent {
		if isTransientAcceptError(err) {
			t.Errorf("isTransientAcceptError(%v) = true, want false", err)
		}
	}
}

// eventuallyAdmitted dials ln until a connection is admitted (the server
// holds it open instead of closing it at accept), closing each attempt.
func eventuallyAdmitted(t *testing.T, ln net.Listener) bool {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial attempt %d: %v", attempt, err)
		}
		admitted := !serverClosedWithin(t, c, 400*time.Millisecond)
		_ = c.Close()
		if admitted {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// logContains fails the test if the expected substring has not appeared in
// the captured Listen log within d.
func logContains(t *testing.T, logBuf *syncBuffer, want string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(logBuf.String(), want) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("log did not contain %q within %s; log:\n%s", want, d, logBuf.String())
}

// stalledAuthClient completes the TLS handshake against ln (presenting a
// client leaf, since RequireAnyClientCert demands one) and writes a
// well-formed hello — landing the server inside the post-TLS anchor lookup,
// the stall point the authorization-window tests hold. The dial is test-only
// to our own listener (InsecureSkipVerify); identity validation is the R1
// tests' job.
func stalledAuthClient(t *testing.T, ln net.Listener, ca genCA, domain string) net.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{issueLeaf(t, ca, domain)},
		InsecureSkipVerify: true, // test-only dial to our own listener; identity checks are the R1 tests' job
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	hello := Frame{Kind: KindHello, Payload: mustJSON(Hello{FromDomain: domain, Ver: 1})}
	if err := WriteFrame(c, hello); err != nil {
		_ = c.Close()
		t.Fatalf("send hello: %v", err)
	}
	return c
}

// stalledLookup builds an AnchorLookup that signals its first entry on the
// returned channel and then blocks until stall is closed or ctx is cancelled
// (the pgx acquisition/query shape: ctx cancellation is honored). After the
// stall clears it answers via answer, so tests control exactly when the
// window un-sticks.
func stalledLookup(stall, entered chan struct{}, answer func(string) (Anchor, bool, error)) AnchorLookup {
	var enterOnce sync.Once
	return AnchorLookup(func(ctx context.Context, domain string) (Anchor, bool, error) {
		enterOnce.Do(func() {
			if entered != nil {
				close(entered)
			}
		})
		select {
		case <-stall:
		case <-ctx.Done():
			return Anchor{}, false, ctx.Err()
		}
		return answer(domain)
	})
}

// TestListenStalledLookupDroppedByAuthContextDeadline (no DB): a peer that
// completes TLS and sends hello lands the server in the anchor lookup; a
// lookup stalled there must not hold a handshake slot past
// lookupAuthorizeTimeout. The socket deadlines cannot provide that bound
// (they are pinned far beyond the guard, and local DB calls never touch conn
// I/O anyway) — only the authorization-window CONTEXT can. The test proves
// the slot is genuinely occupied while stalled, that the context bound closes
// the connection and frees the slot (a fresh dial is admitted while the stall
// is still held), and that the rejection names the context deadline.
func TestListenStalledLookupDroppedByAuthContextDeadline(t *testing.T) {
	shrinkBounds(t, func() {
		maxInFlightHandshakes = 1 // the stalled lookup must occupy the only slot
		maxConcurrentStreams = 8  // not the binding constraint here
		handshakeTimeout = 10 * time.Second
		helloReadTimeout = 10 * time.Second // non-binding: the CONTEXT bound must do the dropping
		lookupAuthorizeTimeout = 300 * time.Millisecond
	})

	stall := make(chan struct{})
	entered := make(chan struct{})
	lookup := stalledLookup(stall, entered, func(string) (Anchor, bool, error) {
		return Anchor{}, false, nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ca := newCA(t, "auth-window-CA")
	logBuf := startBoundedListen(t, ln, boundsTLSCfg(t), "bounds.test", lookup,
		pgxutil.WorkerPool{}, func(*PeerStream) {})

	stalled := stalledAuthClient(t, ln, ca, "alpha.test")
	defer func() { _ = stalled.Close() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("server never reached the anchor lookup")
	}

	// The stalled lookup holds the only handshake slot: a fresh dial is
	// dropped at accept (immediate close), never queued.
	probe, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	if !serverClosedWithin(t, probe, 1*time.Second) {
		_ = probe.Close()
		t.Fatal("connection was admitted while a stalled lookup held the only handshake slot")
	}
	_ = probe.Close()

	// The context bound — not a socket deadline (both are 10s here) — closes
	// the stalled connection within lookupAuthorizeTimeout.
	if !serverClosedWithin(t, stalled, 3*time.Second) {
		t.Fatal("stalled lookup was not dropped by the authorization-window context bound")
	}
	logContains(t, logBuf, "inbound stream rejected", 5*time.Second)
	logContains(t, logBuf, "context deadline exceeded", 5*time.Second)

	// The slot is freed while the stall is STILL held: a fresh dial is
	// admitted (the server holds it into the TLS handshake instead of
	// dropping it at accept). The guard is shorter than
	// lookupAuthorizeTimeout, so an admitted connection provably outlives it.
	recovered, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("post-expiry dial: %v", err)
	}
	defer func() { _ = recovered.Close() }()
	if serverClosedWithin(t, recovered, 150*time.Millisecond) {
		t.Fatal("connection was still dropped after the stalled handshake expired — the slot leaked")
	}
}

// TestListenAdmissionRecoversAfterLookupStallClears (DB-backed): after the
// authorization-window context bound dropped a stalled peer, clearing the
// stall must fully recover admission — a real dial completes the ENTIRE
// handshake (anchor lookup, anchor validation, federation_peer_authorize,
// hello exchange, onStream delivery) through the same window that was
// previously stuck.
func TestListenAdmissionRecoversAfterLookupStallClears(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx0 := context.Background()
	if _, err := pool.Exec(ctx0,
		`INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		 VALUES ('alpha.test', 'stream_accept_bounds_test.go auth-window fixture', 'dm', true)
		 ON CONFLICT (peer_domain) DO UPDATE SET scope='dm', enabled=true`); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx0, `DELETE FROM federation_allowlist WHERE peer_domain = 'alpha.test'`) //nolint:errcheck
	})
	workerPool := pgxutil.WorkerPool{Pool: pool}

	shrinkBounds(t, func() {
		maxInFlightHandshakes = 1
		maxConcurrentStreams = 8
		handshakeTimeout = 10 * time.Second
		helloReadTimeout = 10 * time.Second // non-binding: the CONTEXT bound must do the dropping
		lookupAuthorizeTimeout = 300 * time.Millisecond
	})

	alphaCA := newCA(t, "alpha.test-CA")
	bravoCA := newCA(t, "bravo.test-CA")
	alphaLeaf := issueLeaf(t, alphaCA, "alpha.test")
	bravoLeaf := issueLeaf(t, bravoCA, "bravo.test")

	stall := make(chan struct{})
	entered := make(chan struct{})
	lookup := stalledLookup(stall, entered, func(domain string) (Anchor, bool, error) {
		if domain == "alpha.test" {
			return Anchor{CACert: alphaCA.cert}, true, nil
		}
		return Anchor{}, false, nil
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	streamCh := make(chan *PeerStream, 1)
	logBuf := startBoundedListen(t, ln,
		&tls.Config{Certificates: []tls.Certificate{bravoLeaf}, MinVersion: tls.VersionTLS13},
		"bravo.test", lookup, workerPool, func(s *PeerStream) { streamCh <- s })

	// A peer whose lookup stalls: the context bound — not a socket deadline
	// (both are 10s here) — must drop it within lookupAuthorizeTimeout.
	stalled := stalledAuthClient(t, ln, alphaCA, "alpha.test")
	defer func() { _ = stalled.Close() }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("server never reached the anchor lookup")
	}
	if !serverClosedWithin(t, stalled, 3*time.Second) {
		t.Fatal("stalled lookup was not dropped by the authorization-window context bound")
	}
	logContains(t, logBuf, "context deadline exceeded", 5*time.Second)

	// The stall clears: admission must fully recover — a real dial completes
	// the whole handshake through the previously-stuck window.
	close(stall)
	endpoint := PeerEndpoint{Domain: "bravo.test", Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStream, err := Dial(dialCtx, onFlags(), endpoint, alphaLeaf, Anchor{CACert: bravoCA.cert}, Hello{FromDomain: "alpha.test", Ver: 1})
	if err != nil {
		t.Fatalf("Dial after stall cleared: %v", err)
	}
	defer func() { _ = clientStream.Close() }()

	select {
	case serverStream := <-streamCh:
		if serverStream.Domain != "alpha.test" {
			t.Fatalf("recovered stream domain = %q, want alpha.test", serverStream.Domain)
		}
		_ = serverStream.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("onStream never saw the recovered stream — admission did not recover")
	}
}
