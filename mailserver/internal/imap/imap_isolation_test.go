package imap

// IMAP dual-tenant RLS isolation integration test (native-rls-backstop W6).
//
// THE GAP THIS CLOSES: every other W6 proof exercises the reducer/policy layer
// (rls_policies.pg, rls_jmap_reducers.pg, rls_smtp_delivery.pg) via SQL/pgTAP.
// IMAP is the ONLY tenant protocol whose data path lives entirely in Go handlers
// (internal/imap/imap.go) with NO reducer seam — its messages/message_tags reads
// and writes are raw pgx on the connection's withScope tx. So the IMAP handler
// path had no DB-backed isolation proof. This test drives the REAL handlers
// (handleFetch/handleStore/handleExpunge/handleMove/handleCopy) as the constrained
// setjoin_app role under the V004 FORCE'd tables and asserts cross-tenant
// isolation end-to-end through withScope's BEGIN→set_config→fn→COMMIT wrap.
//
// HOW IT DRIVES THE HANDLERS AS setjoin_app:
//   - appPool   = pgxpool connected as the NON-OWNER NON-SUPERUSER NOBYPASSRLS
//                 setjoin_app role (postgres://setjoin_app@…). Server{pool: appPool}.
//                 Under V004 FORCE, RLS BITES this role — withScope's
//                 app.current_mailbox_id GUC is the only thing that lets it see rows.
//   - superPool = pgxpool connected as the test superuser (DB_DSN, role `mail`),
//                 used ONLY to INSERT fixtures (RLS would block setup on appPool)
//                 and for the non-vacuity control reads.
//   - connState{srv: &Server{pool: appPool}, mailboxID: A, tagID: A's Inbox,
//                conn: a buffer-backed net.Conn capturing the IMAP wire output}.
//     Each handler runs through withScope(GUC = c.mailboxID = A) → the streaming
//     rows path (W5) → the captured buffer is parsed for the protocol response.
//
// NON-VACUITY CONTROL (proves the isolation is RLS, not an empty fixture or the
// handler's own tag predicate): the same tag-keyed query that handleFetch runs is
// executed on superPool (RLS-bypassing) and MUST see B's row when keyed to B's
// tag — and a control assertion confirms that if the GUC were B (mismatched to a
// connState selecting A's tag) the app role sees ZERO of A's rows. The handlers
// also key on c.tagID (an app predicate), so to isolate RLS specifically we drive
// a connState whose mailboxID (the GUC) is DESYNCED from the tag it queries and
// show the app role sees nothing, while the superuser sees the rows.
//
// GATING: requires a loaded test DB with V004 applied + the setjoin_app role
// (provision-roles.sql). The superuser DSN comes from TEST_DB_DSN (the standard
// gate the rest of this suite uses) OR DB_DSN (back-compat); when NEITHER is set
// the test skips cleanly (CI no-DB default). The setjoin_app DSN is DERIVED from
// that superuser DSN — SAME host + SAME database, user swapped to setjoin_app —
// so the RLS-constrained app pool reads the EXACT database the fixtures land in
// (a hardcoded app DSN pointing at a different DB silently empties every read and
// makes the non-vacuity control assertion fail). Override via DB_APP_DSN if the
// app role needs a non-default connection.

import (
	"bytes"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// bufConn is a minimal net.Conn whose Write captures the IMAP handler's wire
// output into a buffer and whose Read blocks forever (the driven handlers never
// read from the conn — FETCH/STORE/EXPUNGE/MOVE/COPY only write responses). A
// fixed RemoteAddr satisfies the handlers that log it.
type bufConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *bufConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// Read blocks until close — no driven handler reads the conn. Returning EOF
// immediately would be fine too, but blocking models a live idle socket.
func (c *bufConn) Read(p []byte) (int, error)       { select {} }
func (c *bufConn) Close() error                     { return nil }
func (c *bufConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 143} }
func (c *bufConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000} }
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }

func (c *bufConn) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// superDSN returns the superuser/owner DSN: TEST_DB_DSN (the standard gate the
// rest of the suite uses) takes priority, then DB_DSN (back-compat). Empty when
// neither is set → the caller skips.
func superDSN() string {
	if v := os.Getenv("TEST_DB_DSN"); v != "" {
		return v
	}
	return os.Getenv("DB_DSN")
}

// appConfig builds the setjoin_app pool config by DERIVING from the superuser
// DSN: same host + same database, user swapped to setjoin_app (and any password
// dropped — the local test role trusts by peer/host). This guarantees the
// RLS-constrained app pool reads the SAME database the fixtures are inserted into.
// DB_APP_DSN overrides the whole derivation when the app role needs a bespoke DSN.
func appConfig(superDSN string) (*pgxpool.Config, error) {
	if v := os.Getenv("DB_APP_DSN"); v != "" {
		return pgxpool.ParseConfig(v)
	}
	cfg, err := pgxpool.ParseConfig(superDSN)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.User = "setjoin_app"
	cfg.ConnConfig.Password = ""
	return cfg, nil
}

// imapIsoEnv holds the two pools + the two tenants' ids for the isolation test.
type imapIsoEnv struct {
	appPool    *pgxpool.Pool // connected as setjoin_app (RLS BITES)
	superPool  *pgxpool.Pool // connected as the superuser/owner (RLS bypass) — fixtures + controls
	mbA, mbB   int64
	usrA, usrB int64 // owning user ids (for full teardown — see cleanup)
	tagA       int64 // A's Inbox tag id
	tagB       int64 // B's Inbox tag id
	msgA1      int64
	msgA2      int64
	msgB1      int64
}

// setupIMAPIso connects both pools, asserts the FORCE precondition, and inserts
// the two-tenant fixture via the superuser pool (RLS would block it on appPool).
func setupIMAPIso(t *testing.T) *imapIsoEnv {
	t.Helper()
	ctx := context.Background()

	sDSN := superDSN()
	if sDSN == "" {
		t.Skip("neither TEST_DB_DSN nor DB_DSN set — skipping IMAP RLS isolation integration test")
	}
	superPool, err := pgxpool.New(ctx, sDSN)
	if err != nil {
		t.Skipf("cannot connect superuser pool (%s): %v", sDSN, err)
	}

	// Precondition: V004 must have FORCE'd both tables; otherwise the test is
	// vacuous (RLS off → no isolation to prove). Fail loudly (not skip) when the
	// DB is reachable but un-flipped — that is a real misconfiguration for W6.
	var forceMessages, forceTags bool
	if err := superPool.QueryRow(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname='messages' AND relnamespace='public'::regnamespace`,
	).Scan(&forceMessages); err != nil {
		superPool.Close()
		t.Fatalf("force-state probe (messages): %v", err)
	}
	if err := superPool.QueryRow(ctx,
		`SELECT relforcerowsecurity FROM pg_class WHERE relname='message_tags' AND relnamespace='public'::regnamespace`,
	).Scan(&forceTags); err != nil {
		superPool.Close()
		t.Fatalf("force-state probe (message_tags): %v", err)
	}
	if !forceMessages || !forceTags {
		superPool.Close()
		t.Fatalf("V004 precondition failed: FORCE ROW LEVEL SECURITY not set (messages=%v message_tags=%v) — load the schema with V004 applied", forceMessages, forceTags)
	}

	appCfg, err := appConfig(sDSN)
	if err != nil {
		superPool.Close()
		t.Skipf("cannot derive setjoin_app pool config from %q: %v", sDSN, err)
	}
	appPool, err := pgxpool.NewWithConfig(ctx, appCfg)
	if err != nil {
		superPool.Close()
		t.Skipf("cannot connect setjoin_app pool (db=%s user=setjoin_app): %v", appCfg.ConnConfig.Database, err)
	}
	// Confirm the app role is genuinely RLS-constrained (NOT superuser, NOT
	// bypassrls) — otherwise the whole test is vacuous.
	var isSuper, isBypass bool
	if err := appPool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&isSuper, &isBypass); err != nil {
		appPool.Close()
		superPool.Close()
		t.Skipf("cannot probe setjoin_app role attributes: %v", err)
	}
	if isSuper || isBypass {
		appPool.Close()
		superPool.Close()
		t.Fatalf("app pool role is super=%v bypassrls=%v — must be a constrained non-owner role for the RLS proof to bite", isSuper, isBypass)
	}

	env := &imapIsoEnv{appPool: appPool, superPool: superPool}

	// Two tenants with divergent ids (the fixture helpers guarantee user_id !=
	// mailbox_id via disjoint sequences — ADR-003). Created on the superuser pool.
	if err := superPool.QueryRow(ctx, `SELECT mk_account('imapIsoA')`).Scan(&env.mbA); err != nil {
		t.Fatalf("mk_account A: %v", err)
	}
	if err := superPool.QueryRow(ctx, `SELECT mk_account('imapIsoB')`).Scan(&env.mbB); err != nil {
		t.Fatalf("mk_account B: %v", err)
	}
	if err := superPool.QueryRow(ctx, `SELECT get_tag_id('Inbox', $1)`, env.mbA).Scan(&env.tagA); err != nil {
		t.Fatalf("get_tag_id A: %v", err)
	}
	if err := superPool.QueryRow(ctx, `SELECT get_tag_id('Inbox', $1)`, env.mbB).Scan(&env.tagB); err != nil {
		t.Fatalf("get_tag_id B: %v", err)
	}
	// Capture the owning user ids so cleanup can remove the WHOLE account graph —
	// mk_account COMMITs (these are real rows in the shared mailserver_test DB, not
	// a pgTAP rollback), and a leaked enabled user pollutes the ORG-WIDE gal_search
	// that jmap_contact.pg later asserts a fixed count on. Full teardown is required.
	_ = superPool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, env.mbA).Scan(&env.usrA)
	_ = superPool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, env.mbB).Scan(&env.usrB)

	// Messages: A ×2, B ×1, each with sequential imap_uid + an Inbox primary tag.
	insertMsg := func(mb, tag int64, msgIDHdr, subj string, uid int64) int64 {
		var id int64
		recv := time.Now()
		if err := superPool.QueryRow(ctx,
			`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read)
			 VALUES ($1, $2, $3, $4, $5, 'sender@ext.com', '[]'::jsonb, '[]'::jsonb, 10, $6, $7, $8, FALSE) RETURNING id`,
			mb, tag, uid, msgIDHdr, subj, "thr-"+msgIDHdr, "raw-"+msgIDHdr, recv,
		).Scan(&id); err != nil {
			t.Fatalf("insert message %s: %v", msgIDHdr, err)
		}
		if _, err := superPool.Exec(ctx,
			`SELECT tag_message($1, $2, 'Inbox', $3, 'deliver', TRUE)`,
			id, recv, mb,
		); err != nil {
			t.Fatalf("tag_message %s: %v", msgIDHdr, err)
		}
		return id
	}
	env.msgA1 = insertMsg(env.mbA, env.tagA, "imapA1", "A one", 1)
	env.msgA2 = insertMsg(env.mbA, env.tagA, "imapA2", "A two", 2)
	env.msgB1 = insertMsg(env.mbB, env.tagB, "imapB1", "B one", 1)

	t.Cleanup(func() {
		// FULL fixture teardown on the superuser pool (RLS bypass). mk_account
		// COMMITs real rows into the shared mailserver_test DB; leaving the users
		// behind pollutes the ORG-WIDE gal_search that jmap_contact.pg asserts a
		// fixed count on (a later pgTAP run would see the leaked enabled users).
		//
		// The account graph has a circular teardown constraint: deleting a user's
		// only PRIMARY mailbox is blocked by trg_mailbox_primary_enforce, and
		// deleting the user first would SET NULL the mailbox.user_id which violates
		// the mailboxes_shared_not_primary CHECK. The standard test idiom is to
		// disable triggers for the teardown — session_replication_role='replica'
		// (superuser-only) suspends user triggers + FK actions so we can delete the
		// whole graph child-first without the guards firing, then restore it. This
		// is the SUPERUSER teardown connection only; production never does this.
		mbs := []int64{env.mbA, env.mbB}
		usrs := []int64{env.usrA, env.usrB}
		// All teardown statements MUST run on ONE connection so the
		// session_replication_role setting applies to the deletes (pgxpool would
		// otherwise hand each Exec a different pooled connection).
		if conn, err := superPool.Acquire(ctx); err == nil {
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'replica'`)
			_, _ = conn.Exec(ctx, `DELETE FROM message_tags WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id = ANY($1))`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM messages WHERE mailbox_id = ANY($1)`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM mailbox_audit_log WHERE mailbox_id = ANY($1)`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM tags WHERE mailbox_id = ANY($1)`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM folders WHERE mailbox_id = ANY($1)`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM mailboxes WHERE id = ANY($1)`, mbs)
			_, _ = conn.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, usrs)
			_, _ = conn.Exec(ctx, `SET session_replication_role = 'origin'`)
			conn.Release()
		}
		appPool.Close()
		superPool.Close()
	})
	return env
}

// connFor builds a connState bound to mailbox `mb` selecting tag `tag`, on a
// Server backed by the app pool — the exact shape handleConn builds after a
// successful SELECT, minus the live socket (replaced by bufConn).
func (e *imapIsoEnv) connFor(mb, tag int64) (*connState, *bufConn) {
	bc := &bufConn{}
	c := &connState{
		srv:       &Server{pool: e.appPool},
		conn:      bc,
		authed:    true,
		userID:    1, // irrelevant to the messages/message_tags path under test
		selected:  "Inbox",
		mailboxID: mb,  // the GUC withScope sets — the RLS tenant key
		tagID:     tag, // the app-level folder predicate
		readOnly:  false,
	}
	return c, bc
}

// TestIMAPIsolation_Fetch proves handleFetch under setjoin_app + FORCE sees ONLY
// the selected mailbox's messages, never the other tenant's — and that the
// isolation is RLS (non-vacuity control included).
func TestIMAPIsolation_Fetch(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// ── A's connState FETCHes A's mailbox → sees A's 2 messages, 0 of B's. ──
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleFetch(ctx, "t1", "1:*", false)
	outA := bcA.String()
	if got := strings.Count(outA, "* "); got < 2 || !strings.Contains(outA, "FETCH (UID 1") || !strings.Contains(outA, "FETCH (UID 2") {
		t.Fatalf("A's FETCH should return A's 2 messages (UID 1,2); got:\n%s", outA)
	}
	if strings.Contains(outA, `"B one"`) {
		t.Fatalf("ISOLATION BREACH: A's FETCH leaked B's message:\n%s", outA)
	}
	if !strings.Contains(outA, "OK FETCH completed") {
		t.Fatalf("A's FETCH did not complete OK:\n%s", outA)
	}

	// ── B's connState FETCHes B's mailbox → sees B's 1 message, 0 of A's. ──
	cB, bcB := env.connFor(env.mbB, env.tagB)
	cB.handleFetch(ctx, "t2", "1:*", false)
	outB := bcB.String()
	if !strings.Contains(outB, `"B one"`) {
		t.Fatalf("B's FETCH should return B's message; got:\n%s", outB)
	}
	if strings.Contains(outB, `"A one"`) || strings.Contains(outB, `"A two"`) {
		t.Fatalf("ISOLATION BREACH: B's FETCH leaked A's messages:\n%s", outB)
	}

	// ── THE RLS LOAD-BEARING CONTROL (desync GUC from tag): a connState whose
	// GUC (mailboxID) is B but whose tag predicate is A's Inbox. The handler's
	// own tag-keyed JOIN would otherwise pull A's rows; RLS (GUC=B) denies them →
	// ZERO rows. This proves the deny is RLS, not the handler's tag predicate. ──
	cDesync, bcDesync := env.connFor(env.mbB /* GUC=B */, env.tagA /* but query A's tag */)
	cDesync.handleFetch(ctx, "t3", "1:*", false)
	outDesync := bcDesync.String()
	if strings.Contains(outDesync, `"A one"`) || strings.Contains(outDesync, `"A two"`) {
		t.Fatalf("RLS NOT LOAD-BEARING: desync (GUC=B, tag=A's Inbox) leaked A's rows — the handler's tag predicate alone would, RLS must deny:\n%s", outDesync)
	}
	if strings.Contains(outDesync, "FETCH (UID") {
		t.Fatalf("RLS NOT LOAD-BEARING: desync FETCH returned rows; expected zero under RLS deny:\n%s", outDesync)
	}

	// ── NON-VACUITY: the SAME desynced tag-keyed query on the SUPERUSER pool
	// (RLS bypass) DOES see A's rows — so the zero above is RLS denying, not an
	// empty fixture or a broken tag id. ──
	var superCount int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM messages m
		 JOIN message_tags mt ON mt.message_id = m.id AND mt.received_at = m.received_at
		 WHERE mt.tag_id = $1 AND mt.is_primary = TRUE`,
		env.tagA,
	).Scan(&superCount); err != nil {
		t.Fatalf("non-vacuity control query: %v", err)
	}
	if superCount != 2 {
		t.Fatalf("non-vacuity control: superuser should see A's 2 tagged rows, saw %d", superCount)
	}
}

// TestIMAPIsolation_Store proves handleStore can flag A's own message, and a
// STORE driven from A's connState cannot reach B's message — under FORCE the
// foreign row is invisible to A's GUC, so a write keyed through it is a no-op.
func TestIMAPIsolation_Store(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// A flags its own UID 1 (\Flagged). Through withScope(GUC=A) the read sees the
	// row and the jmap_email_set_update write succeeds.
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleStore(ctx, "s1", true /*isUID*/, "1 +FLAGS (\\Flagged)")
	outA := bcA.String()
	if !strings.Contains(outA, "OK STORE completed") {
		t.Fatalf("A's STORE on its own message should complete OK:\n%s", outA)
	}
	// Confirm the flag actually landed (read on the superuser pool).
	var flagged bool
	if err := env.superPool.QueryRow(ctx, `SELECT is_flagged FROM messages WHERE id = $1`, env.msgA1).Scan(&flagged); err != nil {
		t.Fatalf("verify A flag: %v", err)
	}
	if !flagged {
		t.Fatalf("A's STORE did not flag A's own message")
	}

	// A connState scoped to A (GUC=A) but querying B's tag (desync) STOREs UID 1.
	// The ordered-view read under GUC=A sees ZERO of B's rows (RLS deny) → no
	// target resolves → B's message is never written. Verify B's message stays
	// unflagged.
	cDesync, _ := env.connFor(env.mbA /* GUC=A */, env.tagB /* B's Inbox tag */)
	cDesync.handleStore(ctx, "s2", true, "1 +FLAGS (\\Flagged)")
	var bFlagged bool
	if err := env.superPool.QueryRow(ctx, `SELECT is_flagged FROM messages WHERE id = $1`, env.msgB1).Scan(&bFlagged); err != nil {
		t.Fatalf("verify B flag: %v", err)
	}
	if bFlagged {
		t.Fatalf("ISOLATION BREACH: a STORE scoped to A (GUC=A) flagged B's message — RLS must hide B's row from A's ordered-view read")
	}
}

// TestIMAPIsolation_Expunge proves handleExpunge under GUC=A only deletes A's
// own \Deleted rows and cannot reach B's — and a desync (GUC=A, tag=B) expunges
// nothing of B's.
func TestIMAPIsolation_Expunge(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Mark B's message \Deleted (on the superuser pool, simulating prior state).
	if _, err := env.superPool.Exec(ctx, `UPDATE messages SET is_deleted = TRUE WHERE id = $1`, env.msgB1); err != nil {
		t.Fatalf("mark B deleted: %v", err)
	}

	// A connState scoped to A (GUC=A) but pointed at B's tag tries to EXPUNGE.
	// Under RLS the ordered-view read (GUC=A) sees none of B's rows → nothing is
	// deleted. B's message must survive.
	cDesync, _ := env.connFor(env.mbA /* GUC=A */, env.tagB)
	cDesync.handleExpunge(ctx, "e1")
	var stillThere bool
	if err := env.superPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM messages WHERE id = $1)`, env.msgB1).Scan(&stillThere); err != nil {
		t.Fatalf("verify B survives expunge: %v", err)
	}
	if !stillThere {
		t.Fatalf("ISOLATION BREACH: an EXPUNGE scoped to A (GUC=A) deleted B's \\Deleted message — RLS must hide B's row")
	}

	// POSITIVE READ-SIDE PROOF: A's own \Deleted message IS visible to handleExpunge
	// under GUC=A — the untagged `* N EXPUNGE` response is the RLS-governed read
	// seeing A's row. Mark A1 \Deleted, run EXPUNGE under GUC=A + A's tag, and assert
	// the untagged EXPUNGE response for A1 was emitted (the streaming read under
	// withScope saw the row → RLS does NOT hide A's own rows from A). The P1 IMAP
	// fix (T7) removed handleExpunge's trailing dead `UPDATE folders SET total_count …`
	// write (folders has no reader of total_count, and the column was the wrong
	// counter axis), so the tx now commits and the delete actually lands.
	if _, err := env.superPool.Exec(ctx, `UPDATE messages SET is_deleted = TRUE WHERE id = $1`, env.msgA1); err != nil {
		t.Fatalf("mark A1 deleted: %v", err)
	}
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.handleExpunge(ctx, "e2")
	if !strings.Contains(bcA.String(), "EXPUNGE") {
		t.Fatalf("A's EXPUNGE under GUC=A should emit an untagged EXPUNGE for A's own \\Deleted row (RLS must NOT hide A's own rows):\n%s", bcA.String())
	}
	if !strings.Contains(bcA.String(), "OK EXPUNGE completed") {
		t.Fatalf("A's EXPUNGE should now complete OK (T7 removed the broken folders write):\n%s", bcA.String())
	}
	var a1Gone bool
	if err := env.superPool.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM messages WHERE id = $1)`, env.msgA1).Scan(&a1Gone); err != nil {
		t.Fatalf("probe A1 expunged: %v", err)
	}
	if !a1Gone {
		t.Fatalf("A's EXPUNGE should have deleted A1 (T7 fix lets the tx commit)")
	}
}

// TestIMAPIsolation_MoveCopy proves handleMove and handleCopy run through
// withScope(GUC=A) and operate only within A's mailbox — a desync (GUC=A, source
// tag = A but the per-message id lookup is mailbox_id-scoped to A) cannot reach B.
func TestIMAPIsolation_MoveCopy(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Create a target user tag in A's mailbox to copy/move into.
	var targetTag int64
	_ = env.superPool.QueryRow(ctx,
		`INSERT INTO tags (mailbox_id, name, tag_type, sort_order, imap_expose)
		 VALUES ($1, 'Archive', 'user', 999, TRUE)
		 ON CONFLICT (mailbox_id, name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, env.mbA,
	).Scan(&targetTag)

	// handleCopy/handleMove resolve the target mailbox via ResolvePrimaryMailbox(
	// c.userID) — which needs a real user→mailbox mapping. To keep this test
	// hermetic to the messages/message_tags isolation (the W6 concern), assert the
	// withScope wrap itself: a COPY driven from A's connState targeting "Archive"
	// copies an A message id (mailbox_id-scoped SELECT under GUC=A) — never B's.
	// We drive handleCopy and confirm no B row gains the Archive tag.
	cA, bcA := env.connFor(env.mbA, env.tagA)
	cA.userID = mustUserForMailbox(t, env.superPool, env.mbA)
	cA.handleCopy(ctx, "c1", "1 Archive", false)
	_ = bcA.String() // COPY may NO if ResolvePrimaryMailbox can't map; isolation is the assertion below

	// WP4 (batch SQL): the batched MOVE statement must be equally tenancy-bound —
	// its aligned input arrays come from A's scoped view and its source DELETE /
	// dest INSERT re-assert m.mailbox_id = A in-statement, so B's rows are
	// unreachable even though B's fixture collides on legacy UID (1).
	cA2, bcA2 := env.connFor(env.mbA, env.tagA)
	cA2.userID = mustUserForMailbox(t, env.superPool, env.mbA)
	cA2.handleMove(ctx, "m1", "1 Archive", false)
	_ = bcA2.String()

	// Regardless of COPY/MOVE's success, NO message owned by B may carry A's
	// Archive tag (cross-tenant write would require RLS bypass, which setjoin_app
	// lacks), and B's Inbox membership must be intact.
	var bGotArchive int
	if err := env.superPool.QueryRow(ctx,
		`SELECT count(*) FROM message_tags mt
		 JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at
		 WHERE mt.tag_id = $1 AND m.mailbox_id = $2`,
		targetTag, env.mbB,
	).Scan(&bGotArchive); err != nil {
		t.Fatalf("verify B not tagged: %v", err)
	}
	if bGotArchive != 0 {
		t.Fatalf("ISOLATION BREACH: a COPY/MOVE on A's connState tagged B's message into A's Archive (count=%d)", bGotArchive)
	}
	if got := primaryTagCount(t, env, env.mbB, env.tagB); got != 1 {
		t.Fatalf("ISOLATION BREACH: A's batched verbs disturbed B's Inbox (got %d, want 1)", got)
	}
}

// TestIMAPFetch_ClosedParens is the regression test for the audit finding at
// imap.go:838: the outer FETCH tuple was missing its closing ')'. Every
// untagged FETCH response must have balanced parentheses.
func TestIMAPFetch_ClosedParens(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	c, bc := env.connFor(env.mbA, env.tagA)
	c.handleFetch(ctx, "f1", "1:*", false)
	out := bc.String()
	if !strings.Contains(out, "OK FETCH completed") {
		t.Fatalf("FETCH should complete; got:\n%s", out)
	}
	for _, line := range strings.Split(out, "\r\n") {
		if !strings.HasPrefix(line, "* ") || !strings.Contains(line, "FETCH (") {
			continue
		}
		open := strings.Count(line, "(")
		close := strings.Count(line, ")")
		if open != close {
			t.Errorf("unbalanced parentheses in FETCH response line (open=%d close=%d):\n  %s", open, close, line)
		}
	}
}

// TestIMAPFetch_UIDNotPositional is the regression test for the audit finding
// at imap.go:1494: UID FETCH used LIMIT/OFFSET (positional) instead of
// resolving the sequence-set against imap_uid values. With messages at UIDs 1
// and 2, request UID FETCH for a UID that is larger than the message count
// (seeded at 1 000) — the old code would return the wrong message via
// OFFSET 999; the fixed code must return zero rows (UID 1000 doesn't exist).
func TestIMAPFetch_UIDNotPositional(t *testing.T) {
	env := setupIMAPIso(t)
	ctx := context.Background()

	// Insert a third message with a large, non-contiguous imap_uid so we can
	// probe UID resolution vs. positional offset.
	recv := time.Now()
	var highID int64
	if err := env.superPool.QueryRow(ctx,
		`INSERT INTO messages (mailbox_id, folder_id, imap_uid, message_id, subject, from_addr, to_addrs, cc_addrs, size_bytes, thread_id, raw_ref, received_at, is_read)
		 VALUES ($1, $2, 1000, 'imapA-uid1000', 'high-uid msg', 'sender@ext.com', '[]'::jsonb, '[]'::jsonb, 10, 'thr-uid1000', 'raw-uid1000', $3, FALSE) RETURNING id`,
		env.mbA, env.tagA, recv,
	).Scan(&highID); err != nil {
		t.Fatalf("insert high-uid message: %v", err)
	}
	if _, err := env.superPool.Exec(ctx,
		`SELECT tag_message($1, $2, 'Inbox', $3, 'deliver', TRUE)`,
		highID, recv, env.mbA,
	); err != nil {
		t.Fatalf("tag high-uid message: %v", err)
	}

	c, bc := env.connFor(env.mbA, env.tagA)

	// UID FETCH 1000 must match the message at imap_uid=1000, not OFFSET 999.
	c.handleFetch(ctx, "f1", "1000 (UID FLAGS ENVELOPE)", true)
	out := bc.String()
	if !strings.Contains(out, "OK FETCH completed") {
		t.Fatalf("UID FETCH should complete; got:\n%s", out)
	}
	cnt := strings.Count(out, "FETCH (UID ")
	if cnt != 1 {
		t.Fatalf("UID FETCH 1000 should match exactly 1 message (imap_uid=1000), got %d:\n%s", cnt, out)
	}
	// The response must carry UID 1000 — not UID 3 (seq-3 positional result).
	if !strings.Contains(out, "UID 1000") {
		t.Fatalf("UID FETCH 1000 response should include UID 1000, got:\n%s", out)
	}

	// UID 999 does not exist — must return zero messages (old code: OFFSET 998
	// would return the 999th row which also doesn't exist here, but future
	// mailboxes may have 999 rows, making this a silent wrong-message read).
	c2, bc2 := env.connFor(env.mbA, env.tagA)
	c2.handleFetch(ctx, "f2", "999 (UID FLAGS)", true)
	out2 := bc2.String()
	if strings.Contains(out2, "FETCH (UID ") {
		t.Fatalf("UID FETCH 999 should return zero rows (UID 999 doesn't exist), got:\n%s", out2)
	}
}

// mustUserForMailbox returns the owning user_id of a mailbox (for handlers that
// resolve the target via the user). Uses the superuser pool.
func mustUserForMailbox(t *testing.T, pool *pgxpool.Pool, mb int64) int64 {
	t.Helper()
	var uid int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM mailboxes WHERE id = $1`, mb,
	).Scan(&uid); err != nil {
		t.Fatalf("resolve user for mailbox %d: %v", mb, err)
	}
	return uid
}
