package ldap

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ldapclient "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	goldapmessage "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"

	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
)

// cleanupLDAPFixtureUser removes a test-provisioned account together with
// every login-bound row that would otherwise block the user delete: claims on
// the user's mailboxes, the mailboxes themselves, auth_event_log rows written
// by the successful bind, and the mailbox_lifecycle binding.
//
// The mailbox delete needs the table's triggers disabled; that disable is
// transactional with the delete and the re-enable (see
// deleteLDAPFixtureMailboxes), so a failed teardown rolls the global trigger
// state back instead of stranding mailboxes triggers disabled for every other
// test against the shared database. Every cleanup statement's error is
// surfaced through t.Errorf — none are ignored. Register AFTER the domain
// cleanup so it runs first (t.Cleanup is LIFO) while the domain still exists.
func cleanupLDAPFixtureUser(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $1)`, userID); err != nil {
			t.Errorf("cleanup mailbox_address_claims: %v", err)
		}
		if err := deleteLDAPFixtureMailboxes(ctx, pool, userID); err != nil {
			t.Errorf("cleanup mailboxes: %v", err)
		}
		for _, stmt := range []struct{ what, query string }{
			{"auth_event_log", `DELETE FROM auth_event_log WHERE user_id = $1`},
			{"mailbox_lifecycle", `DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`},
			{"users", `DELETE FROM users WHERE id = $1`},
		} {
			if _, err := pool.Exec(ctx, stmt.query, userID); err != nil {
				t.Errorf("cleanup %s: %v", stmt.what, err)
			}
		}
	})
}

// deleteLDAPFixtureMailboxes deletes a fixture user's mailboxes with the
// table's triggers disabled for the delete alone. The disable, the delete and
// the re-enable share one transaction: PostgreSQL rolls DDL back with the
// transaction, so a failure can never leave mailboxes triggers globally
// disabled. lock_timeout bounds the wait so cleanup cannot hang behind a
// concurrent writer holding row locks on the table.
func deleteLDAPFixtureMailboxes(ctx context.Context, pool *pgxpool.Pool, userID int64) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		return fmt.Errorf("set lock_timeout: %w", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`); err != nil {
		return fmt.Errorf("disable triggers: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete mailboxes: %w", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`); err != nil {
		return fmt.Errorf("re-enable triggers: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mailboxesDisabledTriggerCount returns how many non-internal triggers on the
// shared mailboxes table are currently in a non-default (disabled/
// replica/always) state; fixture teardown must always drive it to zero.
func mailboxesDisabledTriggerCount(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_trigger WHERE tgrelid = 'mailboxes'::regclass AND NOT tgisinternal AND tgenabled <> 'O'`,
	).Scan(&n); err != nil {
		t.Fatalf("count disabled mailboxes triggers: %v", err)
	}
	return n
}

// admissionWorkTracker observes stub handler dispatch: entered counts
// dispatches (the resource admission must bound before allocation),
// maxConcurrent is the high-water mark of actual outstanding work.
type admissionWorkTracker struct {
	entered       atomic.Int64
	concurrent    atomic.Int64
	maxConcurrent atomic.Int64
	release       chan struct{}
}

func newAdmissionWorkTracker() *admissionWorkTracker {
	return &admissionWorkTracker{release: make(chan struct{})}
}

func (w *admissionWorkTracker) serve(_ ldapserver.ResponseWriter, _ *ldapserver.Message) {
	w.entered.Add(1)
	cur := w.concurrent.Add(1)
	for {
		old := w.maxConcurrent.Load()
		if cur <= old || w.maxConcurrent.CompareAndSwap(old, cur) {
			break
		}
	}
	<-w.release
	w.concurrent.Add(-1)
}

// releaseOne lets exactly one held request finish, freeing one admission slot.
func (w *admissionWorkTracker) releaseOne() {
	w.release <- struct{}{}
}

// admissionState reports the counters tracked in these tests, for failure
// output from waitForAdmission.
func admissionState(tracker *admissionWorkTracker, stats *admissionStats) func() string {
	return func() string {
		return fmt.Sprintf("entered=%d inFlight=%d maxConcurrent=%d rejectedPoolWide=%d readBlocks=%d",
			tracker.entered.Load(), stats.inFlight.Load(), tracker.maxConcurrent.Load(),
			stats.rejectedPoolWide.Load(), stats.readBlocks.Load())
	}
}

// admissionStubHandler adapts a function to ldapserver.Handler. The library's
// own HandlerFunc does not implement Handler (no ServeLDAP method), so tests
// carry this two-line adapter.
type admissionStubHandler struct {
	fn func(ldapserver.ResponseWriter, *ldapserver.Message)
}

func (h admissionStubHandler) ServeLDAP(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	h.fn(w, m)
}

// startStubAdmissionServer starts an in-process plaintext LDAP server whose
// route handlers are replaced by `inner` behind the real admission path (the
// same production NewServerWithHandlerSource path). The pool is nil because
// the stub never reaches the DB-backed handlers; Start does not touch it.
// The returned server is stopped by t.Cleanup.
func startStubAdmissionServer(t *testing.T, perConn, total int, inner func(ldapserver.ResponseWriter, *ldapserver.Message)) *Server {
	t.Helper()
	return startStubAdmissionServerTLS(t, perConn, total, inner, false)
}

// startStubStartTLSServer is the STARTTLS variant: plaintext listener with
// per-connection TLS upgrade, the mode whose admission wrapper must survive
// the library's SetConn swap inside handleExtended.
func startStubStartTLSServer(t *testing.T, perConn, total int, inner func(ldapserver.ResponseWriter, *ldapserver.Message)) *Server {
	t.Helper()
	return startStubAdmissionServerTLS(t, perConn, total, inner, true)
}

func startStubAdmissionServerTLS(t *testing.T, perConn, total int, inner func(ldapserver.ResponseWriter, *ldapserver.Message), startTLS bool) *Server {
	t.Helper()
	logger := testsupport.TestLogger()
	addr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	srv := NewServer(nil, addr, "admission-stub.internal", logger, nil)
	srv.SetMaxInflightPerConn(perConn)
	srv.SetMaxInflightTotal(total)
	if startTLS {
		certFile, keyFile := genSelfSignedCert(t)
		if err := srv.EnableStartTLS(certFile, keyFile); err != nil {
			t.Fatalf("EnableStartTLS: %v", err)
		}
	}
	srv.innerHandler = admissionStubHandler{inner}

	srvCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(10 * time.Second):
			t.Error("admission stub ldap server did not stop after context cancel")
		}
	})
	return srv
}

// dialRawAdmissionConn dials the stub server with a short retry, tolerating
// the asynchronous net.Listen inside srv.Start's goroutine.
func dialRawAdmissionConn(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			t.Cleanup(func() { conn.Close() }) //nolint:errcheck // best-effort teardown
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("admission stub server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// admissionBERSearchRequest hand-crafts one minimal, well-formed LDAP
// SearchRequest message (RFC 4511 §4.5.1). goldap's SearchRequest fields are
// unexported, so the BER is built directly; the library parses it through the
// same readMessagePacket path as any client traffic. messageID must be < 128
// (short-form BER INTEGER).
func admissionBERSearchRequest(t *testing.T, messageID int) []byte {
	t.Helper()
	berInt := []byte{0x02, 0x01, byte(messageID)}
	enumerated := []byte{0x0A, 0x01, 0x00}                          // scope/derefAliases = 0
	boolean := []byte{0x01, 0x01, 0x00}                             // typesOnly = FALSE
	dn := []byte{0x04, 0x00}                                        // baseObject "" (LDAPString)
	present := append([]byte{0x87, 0x0B}, []byte("objectClass")...) // present filter
	attrs := []byte{0x30, 0x00}                                     // empty attribute selection

	op := append([]byte{}, dn...)
	op = append(op, enumerated...)
	op = append(op, enumerated...)
	op = append(op, berInt...)
	op = append(op, berInt...)
	op = append(op, boolean...)
	op = append(op, present...)
	op = append(op, attrs...)
	op = append([]byte{0x63, byte(len(op))}, op...) // [APPLICATION 3] SEQUENCE
	body := append(berInt, op...)
	return append([]byte{0x30, byte(len(body))}, body...) // LDAPMessage SEQUENCE
}

// admissionBERStartTLSRequest hand-crafts the StartTLS extended request
// (RFC 4511 §4.14): [APPLICATION 23] SEQUENCE { requestName [0] primitive }.
func admissionBERStartTLSRequest(t *testing.T, messageID int) []byte {
	t.Helper()
	const startTLSOID = "1.3.6.1.4.1.1466.20037"
	berInt := []byte{0x02, 0x01, byte(messageID)}
	name := append([]byte{0x80, byte(len(startTLSOID))}, startTLSOID...)
	op := append([]byte{0x77, byte(len(name))}, name...)
	body := append(berInt, op...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// readBERProtocolOpTag reads one complete LDAPMessage from conn (minimal BER
// framing mirroring the library's readTagAndLength) and returns the protocol
// op tag, so tests can verify which response crossed the wire without
// importing a full LDAP client.
func readBERProtocolOpTag(t *testing.T, conn net.Conn) byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("read BER header: %v", err)
	}
	if hdr[0] != 0x30 {
		t.Fatalf("read BER header: expected SEQUENCE tag 0x30, got %#x", hdr[0])
	}
	length := 0
	if hdr[1]&0x80 == 0 {
		length = int(hdr[1] & 0x7f)
	} else {
		n := int(hdr[1] & 0x7f)
		ext := make([]byte, n)
		if _, err := io.ReadFull(conn, ext); err != nil {
			t.Fatalf("read BER extended length: %v", err)
		}
		length = int(binary.BigEndian.Uint64(append(make([]byte, 8-n), ext...)))
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read BER body: %v", err)
	}
	tag, err := ldapProtocolOpTag(body)
	if err != nil {
		t.Fatalf("parse BER response op tag: %v", err)
	}
	return tag
}

// waitForAdmission polls cond until true or the timeout elapses (fail, not
// skip: a settled admission state is the assertion itself). The state
// function is reported verbatim on timeout so failures show which admission
// counter did not settle.
func waitForAdmission(t *testing.T, timeout time.Duration, what string, cond func() bool, state func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("admission state never settled: %s — %s", what, state())
}

// TestAdmissionGate_PipelinedNonreadingClientBound is the row's core bound
// test: one connection pipelines more requests than its per-connection
// in-flight cap and NEVER READS responses. Admission must precede the
// dependency's dispatch allocation, so requests beyond the cap are held in
// the connection's read path — no request goroutine, Message, or handler work
// may exist for them — and actual outstanding work never exceeds the cap.
func TestAdmissionGate_PipelinedNonreadingClientBound(t *testing.T) {
	const (
		perConn  = 3
		total    = 64
		floodLen = 10
	)

	tracker := newAdmissionWorkTracker()
	srv := startStubAdmissionServer(t, perConn, total, tracker.serve)

	// Pipelined flood from a nonreading client: every frame is written
	// back-to-back, no response is ever consumed.
	conn := dialRawAdmissionConn(t, srv.addr)
	for id := 1; id <= floodLen; id++ {
		if _, err := conn.Write(admissionBERSearchRequest(t, id)); err != nil {
			t.Fatalf("pipeline message %d: %v", id, err)
		}
	}

	stats := srv.admission.stats
	state := admissionState(tracker, stats)
	waitForAdmission(t, 5*time.Second, "per-connection bound reached", func() bool {
		return tracker.entered.Load() == perConn &&
			stats.inFlight.Load() == perConn &&
			stats.readBlocks.Load() > 0
	}, state)

	// The bound holds BEFORE dispatch allocation: after a settle window the
	// excess pipelined frames must still be buffered in the connection's read
	// path — under post-allocation admission they would already all be
	// dispatched (entered = floodLen).
	time.Sleep(200 * time.Millisecond)
	if got := tracker.entered.Load(); got != perConn {
		t.Fatalf("dispatch allocated %d requests while the per-connection cap is %d — admission ran after dispatch allocation (%s)", got, perConn, state())
	}
	if got := stats.inFlight.Load(); got != perConn {
		t.Fatalf("in-flight = %d, want %d", got, perConn)
	}

	// Completing exactly one unit of work admits exactly one more dispatch.
	tracker.releaseOne()
	waitForAdmission(t, 5*time.Second, "one released request admits one dispatch", func() bool {
		return tracker.entered.Load() == perConn+1 && stats.inFlight.Load() == perConn
	}, state)

	// Drain: every pipelined request is eventually served, and the
	// high-water mark of actual outstanding work never crossed the cap.
	close(tracker.release)
	waitForAdmission(t, 5*time.Second, "flood drained", func() bool {
		return tracker.entered.Load() == floodLen
	}, state)
	if max := tracker.maxConcurrent.Load(); max != perConn {
		t.Errorf("max concurrent outstanding work = %d, want exactly %d", max, perConn)
	}
	if got := stats.inFlight.Load(); got != 0 {
		t.Errorf("in-flight leaked: %d grants still held after drain", got)
	}
}

// TestAdmissionGate_PipelinedBusyShedDoesNotBlockBound proves the shed path
// cannot hang on a nonreading client: with the pool-wide budget exhausted, a
// pipelining client that never reads is shed with LDAPResultBusy, the shed
// requests' goroutines exit (their grants release), and the bound stays
// exactly at the caps.
func TestAdmissionGate_PipelinedBusyShedDoesNotBlockBound(t *testing.T) {
	const (
		perConn = 8
		total   = 2
		shedLen = 6
	)

	tracker := newAdmissionWorkTracker()
	srv := startStubAdmissionServer(t, perConn, total, tracker.serve)

	// Two connections hold the entire pool-wide budget.
	for i := 0; i < total; i++ {
		conn := dialRawAdmissionConn(t, srv.addr)
		if _, err := conn.Write(admissionBERSearchRequest(t, i+1)); err != nil {
			t.Fatalf("holder connection %d: write: %v", i, err)
		}
	}
	stats := srv.admission.stats
	state := admissionState(tracker, stats)
	waitForAdmission(t, 5*time.Second, "pool budget held", func() bool {
		return tracker.entered.Load() == total && stats.inFlight.Load() == total
	}, state)

	// A fresh connection pipelines six requests and never reads: each is
	// granted at the per-connection boundary, then shed pool-wide with Busy.
	flood := dialRawAdmissionConn(t, srv.addr)
	for id := 1; id <= shedLen; id++ {
		if _, err := flood.Write(admissionBERSearchRequest(t, id)); err != nil {
			t.Fatalf("shed pipeline message %d: %v", id, err)
		}
	}
	waitForAdmission(t, 5*time.Second, "pool-wide shed", func() bool {
		return stats.rejectedPoolWide.Load() == shedLen
	}, state)

	// The Busy responses were written to a nonreading peer without hanging:
	// the shed goroutines finished (counter stable, bound untouched).
	time.Sleep(150 * time.Millisecond)
	if got := stats.rejectedPoolWide.Load(); got != shedLen {
		t.Errorf("pool-wide rejections drifted to %d, want %d", got, shedLen)
	}
	if got := stats.inFlight.Load(); got != total {
		t.Errorf("in-flight = %d, want %d (shed requests must not hold work slots)", got, total)
	}

	// Releasing the budget restores full service on the same connection.
	close(tracker.release)
	if _, err := flood.Write(admissionBERSearchRequest(t, 100)); err != nil {
		t.Fatalf("post-drain pipeline write: %v", err)
	}
	waitForAdmission(t, 5*time.Second, "service restored after shed", func() bool {
		return tracker.entered.Load() == total+1
	}, state)
}

// TestAdmissionGate_PoolWideCapHoldsAcrossConnections is the row's pool-wide
// cap test: many connections each holding one request cannot push total
// in-flight LDAP work past the pool-wide budget.
func TestAdmissionGate_PoolWideCapHoldsAcrossConnections(t *testing.T) {
	const (
		perConn = 8 // per-connection never sheds or blocks in this scenario
		total   = 4
		conns   = 6
	)

	tracker := newAdmissionWorkTracker()
	srv := startStubAdmissionServer(t, perConn, total, tracker.serve)

	connsList := make([]net.Conn, 0, conns)
	for i := 0; i < conns; i++ {
		conn := dialRawAdmissionConn(t, srv.addr)
		connsList = append(connsList, conn)
		if _, err := conn.Write(admissionBERSearchRequest(t, 1)); err != nil {
			t.Fatalf("connection %d: write: %v", i, err)
		}
	}

	stats := srv.admission.stats
	state := admissionState(tracker, stats)
	waitForAdmission(t, 5*time.Second, "pool-wide cap held", func() bool {
		return tracker.entered.Load() == total &&
			stats.inFlight.Load() == total &&
			stats.rejectedPoolWide.Load() == conns-total
	}, state)

	if got := stats.inFlight.Load(); got != total {
		t.Errorf("in-flight = %d, want %d (pool-wide cap exceeded)", got, total)
	}
	if got := stats.rejectedPoolWide.Load(); got != conns-total {
		t.Errorf("pool-wide rejections = %d, want %d", got, conns-total)
	}
	if max := tracker.maxConcurrent.Load(); max != total {
		t.Errorf("max concurrent outstanding work = %d, want exactly %d", max, total)
	}

	close(tracker.release)
}

// TestAdmissionConn_WriteDeadlineBoundsNonreadingPeer unit-tests the bounded
// write path: a response write against a peer that never reads must fail at
// the write deadline instead of parking the library's response pump (and
// every admission slot behind it) forever, and the connection must be closed
// so no further work is granted.
func TestAdmissionConn_WriteDeadlineBoundsNonreadingPeer(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	t.Cleanup(func() { _ = server.Close() })
	conn := &admissionConn{Conn: server, writeTimeout: 100 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(make([]byte, 4096))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("write to a nonreading peer completed without any bound")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("write to a nonreading peer blocked past its write deadline")
	}

	// The deadline breach must have closed the connection: later writes fail
	// immediately and the read loop sees an error instead of granting more.
	start := time.Now()
	if _, err := conn.Write([]byte{'x'}); err == nil {
		t.Error("write after the deadline breach succeeded; connection should be dead")
	} else if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("dead-connection write took %v, want fast failure", d)
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("read on a connection closed for unbounded writes should error")
	}
}

// TestAdmissionGate_StartTLSPostUpgradePipelinedBound proves the admission
// bound survives the STARTTLS connection swap: handleExtended replaces the
// connection (SetConn) mid-session, and the re-armed wrapper must keep
// holding pre-dispatch admission for everything pipelined after the upgrade.
func TestAdmissionGate_StartTLSPostUpgradePipelinedBound(t *testing.T) {
	const (
		perConn  = 2
		total    = 64
		floodLen = 5
	)

	tracker := newAdmissionWorkTracker()
	// Route extended operations to the real handleExtended (the STARTTLS path
	// under test) and everything else to the tracker holding search work.
	var srv *Server
	srv = startStubStartTLSServer(t, perConn, total, func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		if m.ProtocolOpName() == ldapserver.EXTENDED {
			srv.handleExtended(w, m)
			return
		}
		tracker.serve(w, m)
	})

	raw := dialRawAdmissionConn(t, srv.addr)
	if _, err := raw.Write(admissionBERStartTLSRequest(t, 1)); err != nil {
		t.Fatalf("write StartTLS request: %v", err)
	}
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only, self-signed
	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set handshake deadline: %v", err)
	}
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("STARTTLS handshake: %v", err)
	}
	if tag := readBERProtocolOpTag(t, tlsConn); tag != 0x78 {
		t.Fatalf("post-upgrade response op tag = %#x, want 0x78 (ExtendedResponse)", tag)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear handshake deadline: %v", err)
	}
	t.Cleanup(func() { _ = tlsConn.Close() })

	// Pipelined flood over the upgraded connection; the client never reads.
	for id := 1; id <= floodLen; id++ {
		if _, err := tlsConn.Write(admissionBERSearchRequest(t, id)); err != nil {
			t.Fatalf("pipeline message %d over STARTTLS: %v", id, err)
		}
	}

	stats := srv.admission.stats
	state := admissionState(tracker, stats)
	waitForAdmission(t, 5*time.Second, "post-STARTTLS per-connection bound", func() bool {
		return tracker.entered.Load() == perConn &&
			stats.inFlight.Load() == perConn &&
			stats.readBlocks.Load() > 0
	}, state)
	time.Sleep(200 * time.Millisecond)
	if got := tracker.entered.Load(); got != perConn {
		t.Fatalf("post-upgrade dispatch allocated %d requests while the per-connection cap is %d — the STARTTLS re-arm lost the bound (%s)", got, perConn, state())
	}

	close(tracker.release)
	waitForAdmission(t, 5*time.Second, "post-STARTTLS flood drained", func() bool {
		return tracker.entered.Load() == floodLen
	}, state)
	if max := tracker.maxConcurrent.Load(); max > perConn {
		t.Errorf("post-upgrade max concurrent outstanding work = %d, want <= %d", max, perConn)
	}
}

// TestAdmissionGate_SequentialDocumentedClientsUnaffected is the row's
// regression for documented LDAP clients (Outlook/Thunderbird GAL): a real
// client doing a real bind then sequential searches under the default caps
// never sees LDAPResultBusy and never trips a rejection counter.
func TestAdmissionGate_SequentialDocumentedClientsUnaffected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapadm-" + suffix + ".internal"
	email := "admseq-" + suffix + "@" + domainName
	const password = "correct-horse-battery-staple-1!"
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"admseq-"+suffix, email, "Admission Seq", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// Login-bound teardown (claims, auth events, lifecycle binding) handled by
	// the shared helper; registered after the domain cleanup so it runs before
	// it (LIFO) while the domain still exists.
	cleanupLDAPFixtureUser(t, pool, userID)
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)

	certFile, keyFile := genSelfSignedCert(t)
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := NewServer(pool, addr, domainName, logger, nil)
	if err := srv.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	deadline := time.Now().Add(5 * time.Second)
	var conn *ldapclient.Conn
	for {
		conn, err = ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldapclient.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only, self-signed
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	base := "ou=People"
	for _, part := range strings.Split(domainName, ".") {
		base += ",dc=" + part
	}

	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// cn-filtered search: the shared test DB directory exceeds the RFC size
	// limit for a wildcard subtree scan, and this test asserts admission
	// behavior, not result volume.
	searchFilter := "(cn=Admission Seq)"
	for i := 0; i < 3; i++ {
		req := ldapclient.NewSearchRequest(base, ldapclient.ScopeWholeSubtree,
			ldapclient.NeverDerefAliases, 0, 0, false, searchFilter,
			[]string{"mail", "cn"}, nil)
		if _, err := conn.Search(req); err != nil {
			t.Fatalf("sequential search %d under default caps: %v", i, err)
		}
	}

	stats := srv.admission.stats
	if got := stats.rejectedPoolWide.Load(); got != 0 {
		t.Errorf("documented sequential client shed %d times, want 0", got)
	}
	if got := stats.inFlight.Load(); got != 0 {
		t.Errorf("in-flight leaked: %d grants still held after sequential traffic", got)
	}

	cancel()
	<-errCh
}

// TestAdmissionGate_BusyShedCrossesTheWire proves the shed response is
// protocol-visible: with the pool-wide budget exhausted, a real go-ldap client
// search comes back as LDAPResultBusy (51), and draining the budget restores
// normal service without restart.
func TestAdmissionGate_BusyShedCrossesTheWire(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldapbusy-" + suffix + ".internal"
	email := "admbusy-" + suffix + "@" + domainName
	const password = "correct-horse-battery-staple-1!"
	hash, err := pwhash.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"admbusy-"+suffix, email, "Admission Busy", domainID, hash,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	cleanupLDAPFixtureUser(t, pool, userID)
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, email)

	certFile, keyFile := genSelfSignedCert(t)
	port := freeTCPPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	srv := NewServer(pool, addr, domainName, logger, nil)
	if err := srv.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("SetTLS: %v", err)
	}
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	deadline := time.Now().Add(5 * time.Second)
	var conn *ldapclient.Conn
	for {
		conn, err = ldapclient.DialURL(fmt.Sprintf("ldaps://%s", addr),
			ldapclient.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // test-only, self-signed
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never accepted connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer conn.Close()

	base := "ou=People"
	for _, part := range strings.Split(domainName, ".") {
		base += ",dc=" + part
	}
	req := ldapclient.NewSearchRequest(base, ldapclient.ScopeWholeSubtree,
		ldapclient.NeverDerefAliases, 0, 0, false, "(cn=Admission Busy)",
		[]string{"mail", "cn"}, nil)

	if err := conn.Bind(email, password); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Exhaust the pool-wide budget out from under the live connection, then
	// search: the gate must shed with LDAPResultBusy on the wire.
	for i := 0; i < cap(srv.admission.poolSlots); i++ {
		srv.admission.poolSlots <- struct{}{}
	}
	if _, err := conn.Search(req); !ldapclient.IsErrorWithCode(err, ldapclient.LDAPResultBusy) {
		t.Errorf("search under exhausted pool-wide budget: got %v, want LDAPResultBusy", err)
	}
	stats := srv.admission.stats
	if got := stats.rejectedPoolWide.Load(); got != 1 {
		t.Errorf("pool-wide rejections = %d, want 1", got)
	}

	// Release the budget: the same connection keeps working — shedding is
	// per-request, never a connection ban.
	for {
		select {
		case <-srv.admission.poolSlots:
			continue
		default:
		}
		break
	}
	if _, err := conn.Search(req); err != nil {
		t.Errorf("search after budget release: %v", err)
	}

	cancel()
	<-errCh
}

// TestAdmission_RequestContextReleasedOnConnectionTeardown is the row's
// cancellation test: work derived from requestContext must abort at connection
// teardown, NOT at its own context timeout. The stub runs a 30s pg_sleep
// under a 60s requestContext the same way handleSearch derives its query
// context; tearing down the client connection must abort the query within
// seconds. If the SQL context timeout were the only bound this would take
// 30s and fail.
func TestAdmission_RequestContextReleasedOnConnectionTeardown(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()

	srv := NewServer(pool, fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t)), "admintear.internal", logger, nil)

	started := make(chan struct{})
	queryDone := make(chan time.Duration, 1)
	srv.innerHandler = admissionStubHandler{func(_ ldapserver.ResponseWriter, m *ldapserver.Message) {
		ctx, cancel := requestContext(srv.baseCtx, m, time.Minute)
		defer cancel()
		close(started)
		t0 := time.Now()
		rows, err := pool.Query(ctx, "SELECT pg_sleep(30)")
		if err != nil {
			queryDone <- time.Since(t0)
			return
		}
		for rows.Next() { // blocks until pg_sleep returns or ctx cancels
		}
		rows.Err()
		rows.Close()
		queryDone <- time.Since(t0)
	}}

	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(srvCtx) }()

	conn := dialRawAdmissionConn(t, srv.addr)
	if _, err := conn.Write(admissionBERSearchRequest(t, 1)); err != nil {
		t.Fatalf("write search: %v", err)
	}
	<-started // query in flight

	t0 := time.Now()
	conn.Close() // connection teardown — the row's release trigger
	// The stub reports the pg_sleep duration. The query started just before
	// t0, so its total runtime is the cancellation latency: a 30s sleep under
	// a 60s requestContext must abort within seconds of teardown. If the SQL
	// context timeout were the only bound, this would take 30s and fail.
	elapsed := <-queryDone
	sinceClose := time.Since(t0)
	if elapsed > 8*time.Second || sinceClose > 10*time.Second {
		t.Fatalf("query ran %v (closed conn %v ago) — cancellation did not release it at teardown; the SQL timeout must not be the bound", elapsed, sinceClose)
	}

	cancel()
	<-errCh
}

// TestRequestContext_CancelledOnTeardownAndExpiry unit-checks the
// requestContext wiring: an Abandon/teardown signal (msg.Done, exactly what
// the library sends from client.close) cancels the derived context, and the
// operation timeout still bounds it without any signal.
func TestRequestContext_CancelledOnTeardownAndExpiry(t *testing.T) {
	msg := &ldapserver.Message{
		LDAPMessage: goldapmessage.NewLDAPMessageWithProtocolOp(goldapmessage.SearchRequest{}),
		Done:        make(chan bool, 2),
	}

	ctx, cancel := requestContext(context.Background(), msg, time.Hour)
	msg.Abandon() // library teardown/abandon signal: Done <- true
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("requestContext not released by teardown (msg.Done) within 2s")
	}
	cancel() // must stay callable

	ctx2, cancel2 := requestContext(context.Background(), msg, 30*time.Millisecond)
	defer cancel2()
	select {
	case <-ctx2.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("requestContext not bounded by its operation timeout")
	}
}

// TestCleanupLDAPFixtureMailboxes_RollbackSafeTeardown proves the fixture
// teardown's trigger guard is rollback-safe: a failed cleanup must never
// strand mailboxes triggers disabled on the shared test database, and a
// successful cleanup must leave every trigger enabled.
func TestCleanupLDAPFixtureMailboxes_RollbackSafeTeardown(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	domainName := "ldaprb-" + suffix + ".internal"

	var domainID, userID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"admrb-"+suffix, "admrb-"+suffix+"@"+domainName, "Admission Rollback", domainID, "stub-hash",
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) }) //nolint:errcheck
	createLDAPTestPrimaryMailbox(t, pool, ctx, userID, domainID, "admrb-"+suffix+"@"+domainName)
	if _, err := pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', FALSE)`,
		userID, domainID, "admrb2-"+suffix+"@"+domainName,
	); err != nil {
		t.Fatalf("insert second mailbox: %v", err)
	}

	if n := mailboxesDisabledTriggerCount(t, pool); n != 0 {
		t.Fatalf("%d mailboxes triggers already disabled before the fixture ran", n)
	}

	// Force the teardown to fail: row locks held on the mailboxes rows make
	// the trigger-guard transaction hit its lock_timeout. The helper must
	// return the error AND the database must keep every trigger enabled — the
	// disable/enable pair lives in one transaction, so nothing leaks.
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker tx: %v", err)
	}
	if _, err := blocker.Exec(ctx, `SELECT id FROM mailboxes WHERE user_id = $1 ORDER BY id FOR UPDATE`, userID); err != nil {
		t.Fatalf("lock mailboxes rows: %v", err)
	}
	helperErr := deleteLDAPFixtureMailboxes(ctx, pool, userID)
	if helperErr == nil {
		t.Fatal("teardown against locked mailboxes rows succeeded; the failure path was not exercised")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatalf("rollback blocker tx: %v", err)
	}
	var alive int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE user_id = $1`, userID).Scan(&alive); err != nil {
		t.Fatalf("count mailboxes after failed teardown: %v", err)
	}
	if alive != 2 {
		t.Errorf("mailboxes count after failed teardown = %d, want 2", alive)
	}
	if n := mailboxesDisabledTriggerCount(t, pool); n != 0 {
		t.Errorf("%d mailboxes triggers left disabled by the failed teardown — teardown is not rollback-safe", n)
	}

	// Success path: the disable is undone in-transaction and mailboxes go.
	if err := deleteLDAPFixtureMailboxes(ctx, pool, userID); err != nil {
		t.Fatalf("teardown after blocker release: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM mailboxes WHERE user_id = $1`, userID).Scan(&alive); err != nil {
		t.Fatalf("count mailboxes after teardown: %v", err)
	}
	if alive != 0 {
		t.Errorf("mailboxes count after teardown = %d, want 0", alive)
	}
	if n := mailboxesDisabledTriggerCount(t, pool); n != 0 {
		t.Errorf("%d mailboxes triggers left disabled after successful teardown", n)
	}
}
