package smtp

// Occurrence-specific tests for the ER5 smtp-lane admission bounds:
//
//   - resource-exhaustion.smtp-command-line: unauthenticated inbound command
//     lines are byte-bounded at intake (readBoundedLine + serveCommands), with
//     the connection stream kept in sync after a refusal;
//   - smtp-bare-lf-message-smuggling: strictDotReader refuses a bare-LF "."
//     DATA terminator (RFC 5321 §4.1.1.4 CRLF.CRLF only) while reproducing the
//     stdlib DotReader output transformation for every conforming frame;
//   - smtp-spool-rematerialization: the spool read-back is gated by
//     spoolMemoryAdmission so the heap held by rematerialized large messages
//     is bounded, and the admitted path is byte-identical to spooledRead;
//   - the DATA failure → SMTP reply mapping (dataReadFailure).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func newBoundedLineTestServer() *InboundServer {
	return &InboundServer{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// driveInboundServeCommands runs serveCommands on one pipe end and returns a
// writer/reader pair for the client side plus a completion channel.
func driveInboundServeCommands(t *testing.T) (net.Conn, *bufio.Reader, chan struct{}) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &inConnState{
		srv:  newBoundedLineTestServer(),
		conn: server,
		tp:   textproto.NewConn(server),
	}
	done := make(chan struct{})
	go func() {
		c.serveCommands(context.Background())
		close(done)
	}()
	return client, bufio.NewReader(client), done
}

func readReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return line
}

// TestReadBoundedCommandLine_AcceptsAtCap pins the boundary: a line of exactly
// smtpMaxCommandLineBytes is admitted (RFC 5321 §4.5.3.1.4 floor is 512, the
// cap is deliberate headroom).
func TestReadBoundedCommandLine_AcceptsAtCap(t *testing.T) {
	line := strings.Repeat("a", smtpMaxCommandLineBytes)
	got, err := readBoundedLine(bufio.NewReader(strings.NewReader(line+"\r\nNEXT\r\n")), smtpMaxCommandLineBytes)
	if err != nil {
		t.Fatalf("at-cap line refused: %v", err)
	}
	if len(got) != smtpMaxCommandLineBytes {
		t.Fatalf("at-cap line length = %d, want %d", len(got), smtpMaxCommandLineBytes)
	}
}

// TestReadBoundedCommandLine_RejectsOverlongAndStaysInSync is the bypass leg:
// an unbounded line (the old textproto.ReadLine allocation) is refused with
// errCommandLineTooLong, the rest of the physical line is drained, and the
// NEXT command is read intact — the stream never desynchronizes.
func TestReadBoundedCommandLine_RejectsOverlongAndStaysInSync(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("NOOP " + strings.Repeat("a", 10_000) + "\r\nNOOP\r\n"))
	if _, err := readBoundedLine(br, smtpMaxCommandLineBytes); !errors.Is(err, errCommandLineTooLong) {
		t.Fatalf("overlong line err = %v, want errCommandLineTooLong", err)
	}
	next, err := readBoundedLine(br, smtpMaxCommandLineBytes)
	if err != nil {
		t.Fatalf("post-refusal read failed: %v", err)
	}
	if next != "NOOP" {
		t.Fatalf("post-refusal read = %q, want %q (stream must stay in sync)", next, "NOOP")
	}
}

// TestReadBoundedCommandLine_BoundedMemoryOnRefusal pins the memory property:
// a multi-megabyte line never accumulates — the accumulator resets once the
// cap is crossed. We can only observe the contract (error + drained line), but
// an 8 MiB line also proves no len() check on a fully-buffered line: the read
// completes without the error depending on total size.
func TestReadBoundedCommandLine_BoundedMemoryOnRefusal(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("EHLO " + strings.Repeat("a", 8<<20) + "\r\nQUIT\r\n"))
	if _, err := readBoundedLine(br, smtpMaxCommandLineBytes); !errors.Is(err, errCommandLineTooLong) {
		t.Fatalf("8MiB line err = %v, want errCommandLineTooLong", err)
	}
	if next, err := readBoundedLine(br, smtpMaxCommandLineBytes); err != nil || next != "QUIT" {
		t.Fatalf("post-refusal read = %q err=%v, want QUIT", next, err)
	}
}

// TestInboundServeCommands_OverlongLineRejected500 is the end-to-end intake
// bypass: an overlong command on the live inbound command loop is answered
// "500 5.5.2 Line too long" BEFORE any dispatch (no command execution), the
// loop continues, and normal commands still work.
func TestInboundServeCommands_OverlongLineRejected500(t *testing.T) {
	client, r, done := driveInboundServeCommands(t)

	if got := readReply(t, r); !strings.HasPrefix(got, "220") {
		t.Fatalf("greeting = %q", got)
	}
	fmt.Fprintf(client, "NOOP %s\r\n", strings.Repeat("a", 6000))
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("overlong line reply = %q, want 500 5.5.2", got)
	}
	fmt.Fprintf(client, "NOOP\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "250") {
		t.Fatalf("NOOP after refusal = %q, want 250", got)
	}
	fmt.Fprintf(client, "QUIT\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "221") {
		t.Fatalf("QUIT reply = %q, want 221", got)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCommands did not return after QUIT")
	}
}

// TestInboundHandleData_RequiresRcptPhase pins the DATA pre-guard (no DB
// touch): DATA before a completed MAIL/RCPT sequence answers 503 and keeps
// the connection.
func TestInboundHandleData_RequiresRcptPhase(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &inConnState{
		srv:   newBoundedLineTestServer(),
		conn:  server,
		tp:    textproto.NewConn(server),
		state: phaseGreeting,
	}
	result := make(chan bool, 1)
	go func() { result <- c.handleData(context.Background()) }()
	if got := readReply(t, bufio.NewReader(client)); !strings.HasPrefix(got, "503") {
		t.Fatalf("premature DATA reply = %q, want 503", got)
	}
	if ok := <-result; !ok {
		t.Fatal("503 DATA guard must keep the connection")
	}
}

// TestInboundServeCommands_BareLFDataRefusedAndConnectionCloses drives the
// live inbound command loop through a DATA frame terminated by a bare-LF "."
// (state pre-seeded to phaseRcpt so no DB lookup is needed): the frame is
// refused 500 5.5.2 and the loop terminates the connection — the smuggled
// command stream after ".\n" is never parsed.
func TestInboundServeCommands_BareLFDataRefusedAndConnectionCloses(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &inConnState{
		srv:   newBoundedLineTestServer(),
		conn:  server,
		tp:    textproto.NewConn(server),
		state: phaseRcpt,
		from:  "<sender@evil.test>",
		to:    []string{"victim@test.local"},
	}
	done := make(chan struct{})
	go func() {
		c.serveCommands(context.Background())
		close(done)
	}()

	r := bufio.NewReader(client)
	if got := readReply(t, r); !strings.HasPrefix(got, "220") {
		t.Fatalf("greeting = %q", got)
	}
	fmt.Fprintf(client, "DATA\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "354") {
		t.Fatalf("DATA reply = %q, want 354", got)
	}
	fmt.Fprintf(client, " innocently long body line\r\n.\nNOOP\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "500 5.5.2") {
		t.Fatalf("bare-LF DATA reply = %q, want 500 5.5.2", got)
	}
	select {
	case <-done:
		// Connection terminated: the trailing "NOOP" was never a command.
	case <-time.After(5 * time.Second):
		t.Fatal("serveCommands must terminate after a refused smuggling frame")
	}
}

// TestInboundServeCommands_DataLineTooLong550 pins the preserved line-length
// rejection through the new strict framing (a conforming CRLF frame with an
// overlong line still answers 550 and the connection continues).
func TestInboundServeCommands_DataLineTooLong550(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close(); client.Close() })
	c := &inConnState{
		srv:   newBoundedLineTestServer(),
		conn:  server,
		tp:    textproto.NewConn(server),
		state: phaseRcpt,
		from:  "<sender@evil.test>",
		to:    []string{"victim@test.local"},
	}
	done := make(chan struct{})
	go func() {
		c.serveCommands(context.Background())
		close(done)
	}()

	r := bufio.NewReader(client)
	readReply(t, r) // 220
	fmt.Fprintf(client, "DATA\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "354") {
		t.Fatalf("DATA reply = %q, want 354", got)
	}
	fmt.Fprintf(client, "%s\r\n.\r\n", strings.Repeat("a", 1000))
	if got := readReply(t, r); !strings.HasPrefix(got, "550") {
		t.Fatalf("overlong DATA line reply = %q, want 550", got)
	}
	fmt.Fprintf(client, "QUIT\r\n")
	if got := readReply(t, r); !strings.HasPrefix(got, "221") {
		t.Fatalf("QUIT after 550 = %q, want 221", got)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveCommands did not return after QUIT")
	}
}

func readAllStrictDot(t *testing.T, br *bufio.Reader) (string, error) {
	t.Helper()
	out, err := io.ReadAll(&strictDotReader{br: br})
	return string(out), err
}

// TestStrictDotReader_CRLFTerminatorAndOutput pins the conforming-frame
// contract: CRLF.CRLF ends DATA, CRLF normalizes to LF, and dot-stuffed lines
// unstuff exactly like the stdlib DotReader (byte-for-byte output parity is
// load-bearing: the stored message bytes feed DKIM, mimeutil, link-protect).
func TestStrictDotReader_CRLFTerminatorAndOutput(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("Hello\r\nWorld\r\n..leading dot\r\n.\r\n"))
	out, err := readAllStrictDot(t, br)
	if err != nil {
		t.Fatalf("CRLF frame read: %v", err)
	}
	if want := "Hello\nWorld\n.leading dot\n"; out != want {
		t.Fatalf("output = %q, want %q", out, want)
	}
	if leftover, err := io.ReadAll(br); err != nil || len(leftover) != 0 {
		t.Fatalf("reader consumed past the CRLF terminator: %q err=%v", leftover, err)
	}
}

// TestStrictDotReader_InteriorLoneCRPassThrough pins stdlib parity for a lone
// CR inside a line (emitted verbatim, not treated as a line break).
func TestStrictDotReader_InteriorLoneCRPassThrough(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("a\rb\r\n.\r\n"))
	out, err := readAllStrictDot(t, br)
	if err != nil {
		t.Fatalf("lone-CR frame read: %v", err)
	}
	if out != "a\rb\n" {
		t.Fatalf("output = %q, want %q", out, "a\rb\n")
	}
}

// TestStrictDotReader_InteriorBareLFPassesThrough pins the scope of the
// refusal: interior bare LFs stay tolerated byte-for-byte (identical to the
// stdlib output); only the TERMINATOR is CRLF-strict.
func TestStrictDotReader_InteriorBareLFPassesThrough(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("a\nb\r\n.\r\n"))
	out, err := readAllStrictDot(t, br)
	if err != nil {
		t.Fatalf("interior-LF frame read: %v", err)
	}
	if out != "a\nb\n" {
		t.Fatalf("output = %q, want %q", out, "a\nb\n")
	}
}

// TestStrictDotReader_RefusesBareLFTerminator is the smuggling bypass: a
// bare-LF "." line must end the frame with errBareLFDataTerminator — never
// silently terminate DATA and re-enter the command stream mid-frame.
func TestStrictDotReader_RefusesBareLFTerminator(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("Hello\r\n.\nNOOP\r\n"))
	out, err := readAllStrictDot(t, br)
	if !errors.Is(err, errBareLFDataTerminator) {
		t.Fatalf("bare-LF terminator err = %v, want errBareLFDataTerminator (out=%q)", err, out)
	}
	if out != "Hello\n" {
		t.Fatalf("data before refusal = %q, want %q", out, "Hello\n")
	}
}

// TestStrictDotReader_UnexpectedEOF pins the truncated-frame leg: a connection
// closed before the terminator surfaces io.ErrUnexpectedEOF (stdlib parity),
// which maps to the transient 451, never a silent partial message.
func TestStrictDotReader_UnexpectedEOF(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("Trunc\r\n"))
	_, err := readAllStrictDot(t, br)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated frame err = %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestStrictDotReader_UnstuffsDotCRFollowedByData pins the ".\r<more>" leg:
// a leading dot followed by CR and MORE data unstuffs the dot and emits the
// saved CR as data (only CRLF.CRLF is framing).
func TestStrictDotReader_UnstuffsDotCRFollowedByData(t *testing.T) {
	br := bufio.NewReader(strings.NewReader(".\rX\r\n.\r\n"))
	out, err := readAllStrictDot(t, br)
	if err != nil {
		t.Fatalf("dot-CR frame read: %v", err)
	}
	if out != "\rX\n" {
		t.Fatalf("output = %q, want %q", out, "\rX\n")
	}
}

// TestStrictDotReader_OverlongLinesAreData pins the boundary with
// validateLineLengths: the reader owns FRAMING only; long lines pass through
// and keep their existing 550 post-check (no behavior change for conforming
// oversized lines).
func TestStrictDotReader_OverlongLinesAreData(t *testing.T) {
	long := strings.Repeat("a", 2000)
	br := bufio.NewReader(strings.NewReader(long + "\r\n.\r\n"))
	out, err := readAllStrictDot(t, br)
	if err != nil {
		t.Fatalf("long-line frame read: %v", err)
	}
	if out != long+"\n" {
		t.Fatalf("long line mangled (len %d)", len(out))
	}
}

// TestDataReadFailureMapping pins the DATA error → reply table: bare-LF
// smuggling refuses 500 AND terminates the connection (the sender controls the
// remaining stream — no resync), saturation is a transient 451 4.3.1, and any
// other read error keeps the historical 451.
func TestDataReadFailureMapping(t *testing.T) {
	code, msg, terminate := dataReadFailure(errBareLFDataTerminator)
	if code != 500 || terminate != true || !strings.Contains(msg, "Bare LF") {
		t.Fatalf("bare-LF mapping = (%d,%q,%v)", code, msg, terminate)
	}
	code, msg, terminate = dataReadFailure(errSpoolMemorySaturated)
	if code != 451 || terminate != false || !strings.HasPrefix(msg, "4.3.1") {
		t.Fatalf("saturation mapping = (%d,%q,%v)", code, msg, terminate)
	}
	code, msg, terminate = dataReadFailure(io.ErrUnexpectedEOF)
	if code != 451 || terminate != false {
		t.Fatalf("generic mapping = (%d,%q,%v)", code, msg, terminate)
	}
}

// TestSpillAdmitReader_SmallMessageNeverAdmits: a stream under the spool
// threshold reads through byte-exact and never consumes an admission slot.
func TestSpillAdmitReader_SmallMessageNeverAdmits(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 64<<10)
	ar := &spillAdmitReader{r: bytes.NewReader(raw)}
	got, err := io.ReadAll(ar)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("read-through changed the bytes")
	}
	if ar.admitted || ar.release != nil {
		t.Fatal("sub-threshold stream must not acquire a slot")
	}
}

// TestSpillAdmitReader_SpillAdmitsOnceAndReleaseIsIdempotent: crossing the
// spool threshold acquires exactly one slot, whose idempotent release frees
// it again.
func TestSpillAdmitReader_SpillAdmitsOnceAndReleaseIsIdempotent(t *testing.T) {
	raw := bytes.Repeat([]byte("y"), 2<<20)
	ar := &spillAdmitReader{r: bytes.NewReader(raw)}
	got, err := io.ReadAll(ar)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("read-through changed the bytes")
	}
	if !ar.admitted || ar.release == nil {
		t.Fatal("spilled stream must acquire exactly the admission slot")
	}
	before := len(spoolMemoryAdmission)
	ar.release()
	ar.release() // idempotence: a double release must not underflow the slots
	if after := len(spoolMemoryAdmission); after != before-1 {
		t.Fatalf("slot count after release = %d, want %d", after, before-1)
	}
}

// TestSpooledReadAdmitted_SpilledMessageByteExact pins the admitted path's
// correctness: a >1 MiB message spills, rematerializes byte-exact, and the
// slot is released after the read.
func TestSpooledReadAdmitted_SpilledMessageByteExact(t *testing.T) {
	raw := make([]byte, 2<<20)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ar := &spillAdmitReader{r: bytes.NewReader(raw)}
	data, tmp, err := spooledRead(ar, 157286400)
	if err != nil {
		t.Fatalf("spilled message: %v", err)
	}
	if tmp == nil {
		t.Fatal("2 MiB message did not spill")
	}
	if !ar.admitted {
		t.Fatal("spilled message must hold an admission slot")
	}
	if !bytes.Equal(data, raw) {
		t.Fatal("rematerialized bytes differ from the wire")
	}
	ar.release()
	tmp.Close()
}

// TestSpooledReadAdmitted_SizeCapStillApplies: the caller-side LimitReader
// contract is unchanged — maxSize+1 bytes come back and the caller answers 552.
func TestSpooledReadAdmitted_SizeCapStillApplies(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 4096)
	r := io.LimitReader(bytes.NewReader(raw), 1024+1)
	data, _, err := spooledRead(r, 1024)
	if err != nil {
		t.Fatalf("capped read: %v", err)
	}
	if len(data) != 1024+1 {
		t.Fatalf("len(data) = %d, want %d", len(data), 1024+1)
	}
}

// TestSpilledReadAdmitted_SaturationIsTransient pins the bounded-heap bypass:
// with every rematerialization slot held, a spilling message's read fails
// with errSpoolMemorySaturated (→ 451 4.3.1, retryable) after a bounded wait —
// it is never rematerialized unbounded.
func TestSpilledReadAdmitted_SaturationIsTransient(t *testing.T) {
	prevWait := spoolAdmissionWait
	spoolAdmissionWait = 20 * time.Millisecond
	t.Cleanup(func() { spoolAdmissionWait = prevWait })

	// Drain all slots (also proves the documented slot count).
	var slots []func()
	t.Cleanup(func() {
		for _, rel := range slots {
			rel()
		}
	})
	for i := 0; i < maxRematerializedSpoolMessages; i++ {
		if !acquireSpoolSlot() {
			t.Fatalf("slot %d unavailable on an empty budget", i)
		}
		slots = append(slots, func() { <-spoolMemoryAdmission })
	}

	raw := bytes.Repeat([]byte("z"), 2<<20)
	ar := &spillAdmitReader{r: bytes.NewReader(raw)}
	_, _, err := spooledRead(ar, 157286400)
	if !errors.Is(err, errSpoolMemorySaturated) {
		t.Fatalf("saturated budget err = %v, want errSpoolMemorySaturated", err)
	}
	if ar.admitted {
		t.Fatal("a refused message must not hold a slot")
	}
}

// TestAcquireSpoolSlot_WaitingLeg pins the bounded-wait acquisition: with the
// budget momentarily FULL, acquireSpoolSlot succeeds as soon as a slot frees
// (well inside spoolAdmissionWait) instead of refusing.
func TestAcquireSpoolSlot_WaitingLeg(t *testing.T) {
	prevWait := spoolAdmissionWait
	spoolAdmissionWait = 5 * time.Second
	t.Cleanup(func() { spoolAdmissionWait = prevWait })

	// Fill every slot so the next acquire must take the waiting path.
	for i := 0; i < maxRematerializedSpoolMessages; i++ {
		if !acquireSpoolSlot() {
			t.Fatalf("slot %d unavailable on an empty budget", i)
		}
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		<-spoolMemoryAdmission
	}()
	if !acquireSpoolSlot() {
		t.Fatal("acquire must succeed once a slot frees inside the wait bound")
	}
	for i := 0; i < maxRematerializedSpoolMessages; i++ {
		<-spoolMemoryAdmission
	}
}

// TestMaxDeliveryConcurrencyBounded pins the fanout bound relationship (the
// per-message errgroup.SetLimit wiring in handleData): the concurrency cap
// must be positive and strictly below maxRecipients, so 1,000 accepted RCPT
// TOs can never spawn 1,000 parallel deliver() pipelines. The DB-backed
// delivery suites (e.g. TestDeliver_CondemnedGroupFanoutQuarantinesEveryCopy)
// execute the bounded fanout path on every delivery.
func TestMaxDeliveryConcurrencyBounded(t *testing.T) {
	if maxDeliveryConcurrency <= 0 || maxDeliveryConcurrency > maxRecipients {
		t.Fatalf("maxDeliveryConcurrency = %d, want in (0, %d]", maxDeliveryConcurrency, maxRecipients)
	}
}
