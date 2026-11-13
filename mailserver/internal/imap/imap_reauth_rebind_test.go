package imap

// Identity-rebind remediation tests (work package imap-reauth-identity-rebind,
// finding D-MAILSERVER-INTERNAL-IMAP-F-001).
//
// Pre-fix hole: AUTHENTICATE had no c.authed guard, so an already-authenticated
// client could re-AUTHENTICATE as a second account. The data plane (c.tagID /
// c.mailboxID, resolved by SELECT under the FIRST identity) kept serving
// FETCH/STORE/EXPUNGE for the original mailbox while c.userID and the
// protocol-session registry entry moved to the second account — and the first
// account's per-user connection-tracker slot was orphaned because c.release was
// overwritten without being run (only the final c.release runs at disconnect),
// so the slot stayed consumed BEYOND disconnect and only explicit tracker
// reconciliation or tracker restart could recover it.
//
// Post-fix contract pinned here:
//   - AUTHENTICATE in the authenticated state is rejected with BAD (RFC 9051
//     §6.2.2) and LOGIN with the pre-existing NO, BEFORE any identity,
//     selected-mailbox, tracker-slot, or session-registry state moves.
//   - Repeated rejected auth attempts cannot accumulate or leak tracker slots;
//     after the connection disconnects, the per-user count is restored exactly
//     (zero leak; the pre-fix leak-beyond-disconnect state is unreachable).
//   - SELECT/re-select handle ownership: a failed re-select leaves NO mailbox
//     selected (RFC 9051 §6.3.2) instead of keeping the previous selection's
//     c.tagID/c.mailboxID serving data-plane commands.
//   - Recorded post-fix decision: because re-binding is impossible, every
//     connection is bound to exactly one identity, so revoking that (sole)
//     owner closes the connection. No "re-bound connection" state exists to
//     recover, so the legacy drain/rebind reconciliation path is not needed for
//     connections created after this fix; leaks that predate it (if any) still
//     require explicit tracker reconciliation or tracker restart after draining
//     affected connections.

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/shared/threat"
)

// rebindConnState builds an authenticated connState holding a selected-mailbox
// handle owned by userID, as a real connection looks after LOGIN + SELECT.
func rebindConnState(srv *Server, conn net.Conn, userID int64) *connState {
	return &connState{
		srv:              srv,
		conn:             conn,
		authed:           true,
		userID:           userID,
		selected:         "Inbox",
		mailboxID:        11,
		tagID:            22,
		readOnly:         true,
		useMembershipUID: true,
	}
}

// assertRebindStateUnchanged verifies the full identity + data-plane state
// survived untouched and the tracker slot was not released.
func assertRebindStateUnchanged(t *testing.T, c *connState, userID int64, slotReleases *atomic.Int32) {
	t.Helper()
	if !c.authed || c.userID != userID {
		t.Fatalf("identity moved: authed=%v userID=%d want userID=%d", c.authed, c.userID, userID)
	}
	if c.selected != "Inbox" || c.mailboxID != 11 || c.tagID != 22 || !c.readOnly || !c.useMembershipUID {
		t.Fatalf("selected state moved: selected=%q mailboxID=%d tagID=%d readOnly=%v membershipUID=%v",
			c.selected, c.mailboxID, c.tagID, c.readOnly, c.useMembershipUID)
	}
	if slotReleases != nil && slotReleases.Load() != 0 {
		t.Fatalf("rejected auth attempt released the tracker slot %d time(s)", slotReleases.Load())
	}
}

func TestAuthenticateAlreadyAuthenticatedRejectedWithoutIdentityChange(t *testing.T) {
	var slotReleases atomic.Int32
	conn := &bufConn{}
	c := rebindConnState(&Server{logger: slog.Default()}, conn, 7)
	c.release = func() { slotReleases.Add(1) }

	c.handleAuthenticate(context.Background(), "R1", "PLAIN")

	if got := conn.String(); !strings.Contains(got, "R1 BAD") {
		t.Fatalf("AUTHENTICATE in authenticated state replied %q, want BAD", got)
	}
	assertRebindStateUnchanged(t, c, 7, &slotReleases)
}

func TestLoginAlreadyAuthenticatedRejectedWithoutIdentityChange(t *testing.T) {
	var slotReleases atomic.Int32
	conn := &bufConn{}
	c := rebindConnState(&Server{logger: slog.Default()}, conn, 7)
	c.release = func() { slotReleases.Add(1) }

	c.handleLogin(context.Background(), "R1", `"second@example.com" "password"`)

	if got := conn.String(); !strings.Contains(got, "R1 NO") {
		t.Fatalf("LOGIN in authenticated state replied %q, want NO", got)
	}
	assertRebindStateUnchanged(t, c, 7, &slotReleases)
}

func TestRepeatedAuthAttemptsLeakNoTrackerSlotBeyondDisconnect(t *testing.T) {
	srv := &Server{logger: slog.Default()}
	srv.userTracker.SetMaxConns(1)

	conn := &bufConn{}
	c := rebindConnState(srv, conn, 101)

	// The slot a successful LOGIN installed for user 101.
	release, err := srv.userTracker.TryAcquire(101)
	if err != nil {
		t.Fatalf("initial TryAcquire(101): %v", err)
	}
	c.release = release

	// Repeated auth attempts are rejected and must move nothing.
	for i := 0; i < 5; i++ {
		c.handleAuthenticate(context.Background(), "R1", "PLAIN")
		c.handleLogin(context.Background(), "R2", `"second@example.com" "pass"`)
	}
	transcript := conn.String()
	if !strings.Contains(transcript, "R1 BAD") || !strings.Contains(transcript, "R2 NO") {
		t.Fatalf("repeated auth attempts not rejected: %q", transcript)
	}
	assertRebindStateUnchanged(t, c, 101, nil)

	// While the connection lives, exactly one slot is held: user 101 is at the
	// limit (the rejected attempts accumulated nothing), user 102 is untouched.
	if _, err := srv.userTracker.TryAcquire(101); !errors.Is(err, tlsutil.ErrLimitExceeded) {
		t.Fatalf("TryAcquire(101) after 5 rejected re-auths = %v, want ErrLimitExceeded", err)
	}
	other, err := srv.userTracker.TryAcquire(102)
	if err != nil {
		t.Fatalf("TryAcquire(102) while 101 held: %v", err)
	}
	other()

	// Disconnect (handleConn's deferred release path): per-user accounting must
	// recover exactly. The pre-fix bug orphaned the ORIGINAL user's slot here —
	// this acquire would have failed with ErrLimitExceeded forever after.
	c.releaseUserSlot()
	after, err := srv.userTracker.TryAcquire(101)
	if err != nil {
		t.Fatalf("TryAcquire(101) after disconnect = %v, want success (slot leaked beyond disconnect)", err)
	}
	after()
}

func TestRevokingOriginalOwnerClosesConnectionWithRebindRejected(t *testing.T) {
	registry := threat.NewProtocolSessionRegistry()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})
	now := time.Now().UTC()
	c := rebindConnState(&Server{logger: slog.Default(), sessionRegistry: registry}, serverConn, 42)
	c.trackProtocolSession(42, now)

	// Rebind is rejected before any registry state moves.
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.handleAuthenticate(context.Background(), "R1", "PLAIN")
	}()
	reader := bufio.NewReader(clientConn)
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "R1 BAD") {
		t.Fatalf("rebind reply = %q err=%v, want R1 BAD", line, err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleAuthenticate did not return after the BAD reply")
	}
	assertRebindStateUnchanged(t, c, 42, nil)

	// Recorded post-fix decision: a connection carries exactly one identity, so
	// revoking the (sole) original owner closes it. There is no re-bound
	// connection whose recovery would need tracker reconciliation.
	registry.Apply(threat.RevocationRow{
		UserID: 42, Scope: threat.ScopeAll, NotBefore: now.Add(time.Second),
	})
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := clientConn.Read(one[:]); err == nil {
		t.Fatal("revocation of the sole owner did not close the connection")
	}
}

// TestFailedReselectLeavesNoMailboxSelected pins the SELECT/re-select handle
// ownership reset: a failed re-select must leave NO mailbox selected instead of
// keeping the previous selection's c.tagID/c.mailboxID reachable from the
// data-plane commands (they query by c.tagID with GUC=c.mailboxID and guard
// only on c.selected being non-empty). Needs a loaded test DB for the SELECT
// lookup; skips cleanly without one (same gate as the RLS isolation suite).
func TestFailedReselectLeavesNoMailboxSelected(t *testing.T) {
	sDSN := superDSN()
	if sDSN == "" {
		t.Skip("neither TEST_DB_DSN nor DB_DSN set — skipping IMAP re-select handle-reset test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, sDSN)
	if err != nil {
		t.Skipf("cannot connect test pool (%s): %v", sDSN, err)
	}
	// NOTE: no deferred pool.Close() here — defers run before t.Cleanup, so the
	// teardown below must own closing the pool (same as the RLS isolation suite).

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('imapRebindReselect')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID, tagID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("resolve account owner: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT get_tag_id('Inbox', $1)`, mbID).Scan(&tagID); err != nil {
		t.Fatalf("get_tag_id: %v", err)
	}
	t.Cleanup(func() {
		// Same teardown idiom as the RLS isolation suite: mk_account COMMITs
		// real rows into the shared test DB, and the primary-mailbox/user
		// delete guards need trigger suspension on ONE superuser connection.
		if conn, err := pool.Acquire(ctx); err == nil {
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
			_, _ = conn.Exec(ctx, `DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = ANY($1))`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM messages WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM mailbox_audit_log WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM tags WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM mailboxes WHERE id = ANY($1)`, []int64{mbID})
			_, _ = conn.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, []int64{userID})
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
			conn.Release()
		}
		pool.Close()
	})

	// State exactly as a real connection holds it after LOGIN + SELECT INBOX.
	conn := &bufConn{}
	c := &connState{
		srv:       &Server{pool: pool, logger: slog.Default()},
		conn:      conn,
		authed:    true,
		userID:    userID,
		selected:  "Inbox",
		mailboxID: mbID,
		tagID:     tagID,
	}

	// A failed re-select must leave NOTHING selected — not the new name and no
	// residue of the previous handle.
	c.handleSelect(ctx, "S2", "SELECT", "Definitely-Missing-Mailbox")
	if got := conn.String(); !strings.Contains(got, "S2 NO") {
		t.Fatalf("failed re-select replied %q, want NO", got)
	}
	if c.selected != "" || c.mailboxID != 0 || c.tagID != 0 || c.useMembershipUID {
		t.Fatalf("failed re-select left a selected handle: selected=%q mailboxID=%d tagID=%d membershipUID=%v",
			c.selected, c.mailboxID, c.tagID, c.useMembershipUID)
	}

	// The data plane refuses to serve afterwards (guard fails without touching
	// the stale c.tagID).
	refused := &bufConn{}
	c.conn = refused
	c.handleFetch(ctx, "F1", "1 (UID)", false)
	if got := refused.String(); !strings.Contains(got, "F1 NO") {
		t.Fatalf("FETCH after failed re-select replied %q, want NO", got)
	}
}
