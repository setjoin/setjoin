package ldap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	ldapserver "github.com/vjeantet/ldapserver"
)

// LDAP admission control.
//
// The pinned vjeantet/ldapserver dependency (mailserver/go.mod) reads one BER
// message per loop iteration in client.serve() and spawns a goroutine per
// pipelined request before invoking the connection's handler; its own source
// flags the missing limit ("TODO: Use an implementation to limit runnuning
// request by client ... THEN send a BusyLdapMessage"). A gate inside the
// handler would therefore run AFTER the dependency has already allocated the
// request goroutine, Message and requestList entry, and a shed request's Busy
// response can block forever on the library's unbuffered response channel
// when the pipelining client never reads — the exact resource spike the
// approved remediation bounds.
//
// Admission therefore runs BEFORE dispatch allocation, in the connection's
// read path, which is the only code this package owns that executes before
// the library's `go c.ProcessRequestMessage(...)`:
//
//   - admissionListener (installed in Server.Start, outermost so it always
//     sees the plaintext BER stream after TLS decryption) wraps every
//     accepted connection in an admissionConn minting a fresh connAdmission
//     grant budget.
//   - admissionConn frames each LDAPMessage out of the byte stream (BER
//     tag/length scan mirroring the library's readTagAndLength) and grants
//     one per-connection slot BEFORE the frame is handed to the library —
//     blocking the read loop at the per-connection cap. A blocked read loop
//     parses and dispatches nothing: no goroutine, no Message, no response
//     work exists beyond the outstanding grants, and TCP backpressure holds
//     the pipelining client instead of an unbounded queue.
//   - admissionGate (the per-connection Handler from GetHandler) releases
//     the grant when the dispatched request finishes, and applies the
//     pool-wide budget as a try-acquire before any handler work runs, sheds
//     excess with LDAPResultBusy. Abandon and Unbind carry no grant: Abandon
//     is the cancellation signal for in-flight work and Unbind is never
//     dispatched by the library.
//
// Response writes are bounded too: admissionConn.Write enforces a write
// deadline so a nonreading client can stall a response only for that
// deadline, after which the connection is closed. Without it, held grants
// (and the pool-wide slots behind them) could park forever in the library's
// unbuffered chanOut once the client's socket buffer fills.
//
// Failure posture is fail-closed: a stream that cannot be framed (wrong tag,
// oversized declared length, truncated message) is rejected and the
// connection closed rather than passed through unadmitted. A frame that is
// granted but never dispatched (the library's parser rejects it after the
// grant) wedges that connection's remaining grant slots — the connection
// stops being served and its budget is reclaimed at teardown; it can never
// leak into the pool-wide budget, which only gates dispatched work.
//
// The gate is installed per connection via the library's HandlerSource hook
// (NewServerWithHandlerSource → newClient → GetHandler); per-connection
// grant state lives on the connection itself, so it is reclaimed by the
// garbage collector at teardown — no connection registry to leak.

// Admission caps are surfaced ops tunables (not pinned by the remediation
// row). Defaults are sized so documented sequential LDAP clients (Outlook /
// Thunderbird GAL lookups) never shed: the production connection ceiling
// (LDAPMaxConns, default 100) at one in-flight request per documented client
// stays under DefaultMaxInflightTotal, and a single connection cannot hold
// more than DefaultMaxInflightPerConn slots of the pool-wide budget.
const (
	DefaultMaxInflightPerConn = 16
	DefaultMaxInflightTotal   = 128

	// maxLDAPFrameBytes bounds the framed message the read path buffers
	// before handing it to the library. The library's readBytes allocates the
	// attacker-declared BER length up front, so the cap here (well above any
	// legitimate message: the search path pre-validates filters at 8 KiB)
	// keeps that allocation ours to refuse.
	maxLDAPFrameBytes = 1 << 20

	// defaultClientWriteTimeout bounds each response write against a
	// nonreading peer; see admissionConn.Write.
	defaultClientWriteTimeout = 30 * time.Second
)

// BER application tags this package must recognise at the frame boundary.
// LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE, ... } —
// the protocol op tag follows the messageID TLV inside the frame body.
const (
	opUnbindRequest  byte = 0x42 // [APPLICATION 2] primitive — never dispatched
	opAbandonRequest byte = 0x70 // [APPLICATION 16] primitive — cancellation signal
)

var errAdmissionConnDead = errors.New("ldap admission: connection closed after unbounded response write")

// LDAPMessage SEQUENCE tag; anything else is not an LDAP plaintext stream.
const berSequenceTag byte = 0x30

// admissionStats are the pool-wide admission counters shared by every
// connection's gate. They are monitoring hooks and deterministic test
// observation points, not authority.
type admissionStats struct {
	inFlight         atomic.Int64 // requests currently executing handler work
	rejectedPoolWide atomic.Int64 // shed at the pool-wide limit
	readBlocks       atomic.Int64 // frames held at the per-connection read gate
}

// connAdmission is one connection's outstanding-dispatch grant budget. The
// read path grants (blocking while the connection is at cap) before a frame
// reaches the library's dispatcher; the admissionGate releases when the
// dispatched request finishes. Grants never outlive the connection: the
// budget dies with it.
type connAdmission struct {
	slots chan struct{}
	stats *admissionStats
}

// grant blocks until a per-connection dispatch slot is free. This is the
// pre-allocation admission point: while it blocks, the library's read loop
// is parked here — inside our Read — and has parsed and allocated nothing.
func (s *connAdmission) grant() {
	select {
	case s.slots <- struct{}{}:
		return
	default:
	}
	s.stats.readBlocks.Add(1)
	s.slots <- struct{}{} // blocks until a release frees a slot
}

// release returns one grant; called by the admissionGate when the dispatched
// request's handler work finishes.
func (s *connAdmission) release() { <-s.slots }

// admissionLimiter implements ldapserver.HandlerSource. Start installs it via
// NewServerWithHandlerSource so the library mints one admissionGate per
// accepted connection. It is constructed in NewServer — before any server
// goroutine exists — so the poolSlots budget and stats are safe to observe
// from the moment the Server value is handed out; Start only assigns base
// (the route mux) before the listener begins accepting.
type admissionLimiter struct {
	base      ldapserver.Handler // route mux (or test override) behind the gate
	poolSlots chan struct{}      // pool-wide in-flight work budget
	perConn   int                // per-connection grant capacity
	stats     *admissionStats
}

func newAdmissionLimiter(perConn, total int) *admissionLimiter {
	return &admissionLimiter{
		poolSlots: make(chan struct{}, total),
		perConn:   perConn,
		stats:     &admissionStats{},
	}
}

// newConnState mints the per-connection dispatch budget used by the
// admissionListener's connection wrapper.
func (l *admissionLimiter) newConnState() *connAdmission {
	return &connAdmission{slots: make(chan struct{}, l.perConn), stats: l.stats}
}

// GetHandler returns the per-connection admission gate. Called by the library
// exactly once per accepted connection. Per-connection grant state is not
// wired here: the gate resolves it from the request's own connection, so the
// grant (read path) and release (handler path) always pair on the same
// budget regardless of dispatch order.
func (l *admissionLimiter) GetHandler() ldapserver.Handler {
	return &admissionGate{
		inner:     l.base,
		poolSlots: l.poolSlots,
		stats:     l.stats,
	}
}

// admissionGate is the per-connection outermost ldapserver.Handler. The
// per-connection cap has already been applied by the read path (no request
// beyond it was ever dispatched); this gate releases that grant at request
// end and caps pool-wide in-flight work before any handler work runs,
// shedding excess with LDAPResultBusy.
type admissionGate struct {
	inner     ldapserver.Handler
	poolSlots chan struct{}
	stats     *admissionStats
}

// ServeLDAP admits or sheds one dispatched request. The per-connection grant
// was taken by the connection's read path BEFORE the dependency allocated
// this goroutine; it is released here when the request finishes. The
// pool-wide budget is a try-acquire so a shed request never queues.
func (g *admissionGate) ServeLDAP(w ldapserver.ResponseWriter, r *ldapserver.Message) {
	// Abandon carries the cancellation signal that releases in-flight work;
	// it holds no grant (exempted at the read boundary) and must never wait.
	if r.ProtocolOpName() == ldapserver.ABANDON {
		g.inner.ServeLDAP(w, r)
		return
	}

	if ac, ok := r.Client.GetConn().(*admissionConn); ok {
		defer ac.state.release()
	}

	select {
	case g.poolSlots <- struct{}{}:
	default:
		g.stats.rejectedPoolWide.Add(1)
		writeBusyResponse(w, r, "server busy: pool-wide in-flight limit")
		return
	}

	g.stats.inFlight.Add(1)
	defer g.stats.inFlight.Add(-1)
	defer func() { <-g.poolSlots }()

	g.inner.ServeLDAP(w, r)
}

// admissionListener is the outermost listener installed by Server.Start. It
// sits after TLS wrapping so every accepted connection carries plaintext BER
// regardless of implicit-TLS, STARTTLS, or plaintext mode, and wraps each
// connection in an admissionConn with its own grant budget.
type admissionListener struct {
	inner   net.Listener
	limiter *admissionLimiter
}

func newAdmissionListener(inner net.Listener, limiter *admissionLimiter) *admissionListener {
	return &admissionListener{inner: inner, limiter: limiter}
}

func (l *admissionListener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &admissionConn{Conn: c, state: l.limiter.newConnState(), writeTimeout: defaultClientWriteTimeout}, nil
}

func (l *admissionListener) Close() error   { return l.inner.Close() }
func (l *admissionListener) Addr() net.Addr { return l.inner.Addr() }

// admissionConn frames the client's BER stream and applies admission before
// the library can parse and dispatch. Goroutine confinement:
//
//   - Read, frameNext, beginTLSUpgrade and rearmTLS run only on the
//     connection's read-loop goroutine (the library calls Read from
//     client.serve; STARTTLS handling is dispatched synchronously on that
//     same goroutine), so the framing fields need no lock.
//   - Write runs only on the library's per-connection response pump, so the
//     dead flag is single-writer.
type admissionConn struct {
	net.Conn
	state        *connAdmission
	writeTimeout time.Duration

	// framing state (read-loop goroutine only)
	pending [][]byte // frames ready for delivery: header segment, then body
	raw     bool     // pass-through mode during a STARTTLS upgrade

	// dead is set by Write when a response write fails its deadline; the
	// connection is closed so the read loop exits instead of granting more.
	dead bool
}

// Read serves previously framed bytes, then frames the next message —
// including its pre-dispatch admission grant — before it is delivered.
func (c *admissionConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.raw {
		return c.Conn.Read(b)
	}
	if len(c.pending) == 0 {
		if err := c.frameNext(); err != nil {
			return 0, err
		}
	}
	seg := c.pending[0]
	n := copy(b, seg)
	if n == len(seg) {
		c.pending = c.pending[1:]
	} else {
		c.pending[0] = seg[n:]
	}
	return n, nil
}

// frameNext reads one complete LDAPMessage from the wire, mirroring the
// library's readTagAndLength BER length rules (and rejecting what it would
// mis-handle), grants the pre-dispatch admission slot, and queues the frame
// for delivery. The frame is delivered as a header segment followed by the
// body segment so the library's bufio reads (1 tag byte, 1 length byte, then
// the body) drain the buffer exactly at the body boundary — large bodies
// then take bufio's direct-read path and arrive in one read, which the
// library's exact-length readBytes requires.
func (c *admissionConn) frameNext() error {
	var hdr []byte
	readByte := func() (byte, error) {
		var one [1]byte
		if _, err := io.ReadFull(c.Conn, one[:]); err != nil {
			return 0, err
		}
		hdr = append(hdr, one[0])
		return one[0], nil
	}

	tag, err := readByte()
	if err != nil {
		return err
	}
	if tag != berSequenceTag {
		return fmt.Errorf("ldap admission: expecting 0x30 as first byte, got %#x", tag)
	}
	l0, err := readByte()
	if err != nil {
		return err
	}
	length := 0
	if l0&0x80 == 0 {
		length = int(l0 & 0x7f)
	} else {
		n := int(l0 & 0x7f)
		if n == 0 || n > 4 {
			return fmt.Errorf("ldap admission: unsupported BER length form (%#x)", l0)
		}
		for i := 0; i < n; i++ {
			b, err := readByte()
			if err != nil {
				return err
			}
			length = length<<8 | int(b)
		}
	}
	if length < 0 || length > maxLDAPFrameBytes {
		return fmt.Errorf("ldap admission: declared message length out of range (%d)", length)
	}

	body := make([]byte, length) // bounded by maxLDAPFrameBytes
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return err
	}

	// Pre-dispatch admission: hold the frame until the connection's
	// outstanding work is under the per-connection cap. While this blocks,
	// nothing of this frame exists beyond the bounded buffer: no parse, no
	// goroutine, no Message — and the unread socket applies TCP backpressure
	// to the pipelining client. Unbind is never dispatched by the library and
	// Abandon releases in-flight work, so neither may consume a grant.
	if len(body) > 0 {
		opTag, err := ldapProtocolOpTag(body)
		if err != nil {
			return err
		}
		if opTag != opUnbindRequest && opTag != opAbandonRequest {
			c.state.grant()
		}
	}

	c.pending = append(c.pending, hdr)
	if len(body) > 0 {
		c.pending = append(c.pending, body) // never queue an empty segment
	}
	return nil
}

// ldapProtocolOpTag returns the protocol op tag that follows the messageID
// INTEGER TLV at the start of an LDAPMessage body.
func ldapProtocolOpTag(body []byte) (byte, error) {
	if len(body) < 2 || body[0] != 0x02 {
		return 0, fmt.Errorf("ldap admission: messageID TLV missing (first byte %#x)", body[0])
	}
	idLen := int(body[1])
	off := 2
	if body[1]&0x80 != 0 {
		n := int(body[1] & 0x7f)
		if n == 0 || n > 4 || len(body) < 2+n {
			return 0, fmt.Errorf("ldap admission: unsupported messageID length form (%#x)", body[1])
		}
		idLen = 0
		for i := 0; i < n; i++ {
			idLen = idLen<<8 | int(body[2+i])
		}
		off = 2 + n
	}
	if idLen < 0 || off+idLen >= len(body) {
		return 0, fmt.Errorf("ldap admission: protocol op tag out of bounds")
	}
	return body[off+idLen], nil
}

// Write bounds every response write against a nonreading peer. The library's
// response pump serialises writes per connection; without a deadline, one
// stalled Flush parks the pump and every dispatched request's response write
// behind it forever, holding admission slots pool-wide. A write that exceeds
// the deadline marks the connection dead and closes it: the pump drains
// (failing fast), grants release, and the read loop stops granting a
// connection that can no longer receive answers.
func (c *admissionConn) Write(p []byte) (int, error) {
	if c.dead {
		return 0, errAdmissionConnDead
	}
	// A failure to set the deadline still leaves the underlying write
	// bounded by connection close on error below.
	_ = c.Conn.SetWriteDeadline(time.Now().Add(c.writeTimeout))
	n, err := c.Conn.Write(p)
	if err != nil {
		c.dead = true
		_ = c.Conn.Close()
		return n, err
	}
	return n, nil
}

// beginTLSUpgrade switches the connection to raw pass-through so the TLS
// handshake bytes flow unframed. Called from handleExtended — on the read
// loop's own goroutine, before tls.Server wraps this connection.
func (c *admissionConn) beginTLSUpgrade() {
	c.raw = true
	c.pending = nil
}

// rearmTLS returns a fresh framing wrapper around the upgraded TLS
// connection, sharing the grant budget, so admission still precedes dispatch
// on STARTTLS connections after the library swapped the connection out from
// under the original wrapper via SetConn.
func (c *admissionConn) rearmTLS(tlsConn net.Conn) *admissionConn {
	return &admissionConn{Conn: tlsConn, state: c.state, writeTimeout: c.writeTimeout}
}

// transportConn unwraps admission framing layers to expose the underlying
// transport connection for TLS-state checks (handleBind must see the
// *tls.Conn, not the wrapper around it).
func transportConn(c net.Conn) net.Conn {
	for {
		ac, ok := c.(*admissionConn)
		if !ok {
			return c
		}
		c = ac.Conn
	}
}

// writeBusyResponse emits a protocol-appropriate LDAPResultBusy for the shed
// operation so clients receive a retryable busy signal instead of silence.
// The write itself is bounded by the admissionConn write deadline.
func writeBusyResponse(w ldapserver.ResponseWriter, r *ldapserver.Message, reason string) {
	const code = ldapserver.LDAPResultBusy
	switch r.ProtocolOpName() {
	case ldapserver.BIND:
		res := ldapserver.NewBindResponse(code)
		res.SetDiagnosticMessage(reason)
		w.Write(res)
	case ldapserver.SEARCH:
		res := ldapserver.NewSearchResultDoneResponse(code)
		res.SetDiagnosticMessage(reason)
		w.Write(res)
	case ldapserver.COMPARE:
		// message.CompareResponse is a conversion type exposing only
		// SetResultCode — no diagnostic field is settable, and the busy code
		// itself is the client-visible contract.
		res := ldapserver.NewCompareResponse(code)
		w.Write(res)
	case ldapserver.EXTENDED:
		res := ldapserver.NewExtendedResponse(code)
		res.SetDiagnosticMessage(reason)
		w.Write(res)
	default:
		res := ldapserver.NewResponse(code)
		res.SetDiagnosticMessage(reason)
		w.Write(res)
	}
}
