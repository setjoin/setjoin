package connector

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool opens a pool against TEST_DB_DSN (or DB_DSN) or skips. Mirrors
// connector/local/local_test.go's skip so the pure-unit suite stays green
// without a database.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN / DB_DSN not set; skipping ResolveIdentitySQL DB test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("DSN set but pool open failed (%v); skipping", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// seededFixture is one local domain with two persons, each holding a primary
// mailbox: the minimal stage for anchor-faithful resolution and for a
// cross-person overlap.
type seededFixture struct {
	domainID int64
	userAID  int64 // alice — the lower-id person in the overlap arm
	userBID  int64 // bob
	emailA   string
	upnA     string
	aliasA   string
	emailB   string
}

// seedFixture inserts the domain + both persons + alice's mailbox/sister alias.
// The UPN is set separately (the anchor test sets it as same-person overlap; the
// fail-closed test injects a cross-person UPN by hand).
func seedFixture(t *testing.T, pool *pgxpool.Pool) *seededFixture {
	t.Helper()
	ctx := context.Background()
	uniq := randSuffix(t)
	f := &seededFixture{
		emailA: "alice@" + uniq + ".test",
		upnA:   "alice.upn@" + uniq + ".corp.local",
		aliasA: "alice@sis-" + uniq + ".test",
		emailB: "bob@" + uniq + ".test",
	}
	var err error
	if err = pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		uniq+"-residtest.test",
	).Scan(&f.domainID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	if err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, enabled)
		 VALUES ($1, $2, 'Alice', $3, TRUE) RETURNING id`,
		"alice-"+uniq, f.emailA, f.domainID,
	).Scan(&f.userAID); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, enabled)
		 VALUES ($1, $2, 'Bob', $3, TRUE) RETURNING id`,
		"bob-"+uniq, f.emailB, f.domainID,
	).Scan(&f.userBID); err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	if _, err = pool.Exec(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, 'Alice', 'personal', TRUE)`,
		f.userAID, f.domainID, f.emailA,
	); err != nil {
		t.Fatalf("seed alice mailbox: %v", err)
	}
	if _, err = pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary)
		 SELECT m.id, $1, $2, FALSE FROM mailboxes m WHERE m.user_id = $3 AND m.is_primary`,
		f.aliasA, f.domainID, f.userAID,
	); err != nil {
		t.Fatalf("seed alice sister alias: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM aliases WHERE domain_id = $1`, f.domainID)
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE domain_id = $1`, f.domainID)
		pool.Exec(ctx, `DELETE FROM users WHERE domain_id = $1`, f.domainID)
		pool.Exec(ctx, `DELETE FROM identity_address_quarantine WHERE address = ANY($1)`,
			[]string{f.emailA, f.emailB, f.upnA, f.aliasA})
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, f.domainID)
	})
	return f
}

// querier is the minimal SQL surface shared by *pgxpool.Pool (the test/owner
// identity) and *pgxpool.Conn (a connection re-roled to the runtime identity).
type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// resolveID runs the one canonical resolution fragment with a caller-appended
// projection, exactly as every consumer does (local + AD connector + the
// SP-mode handler).
func resolveID(t *testing.T, q querier, address string) (int64, error) {
	t.Helper()
	var id int64
	err := q.QueryRow(context.Background(),
		`SELECT u.id`+ResolveIdentitySQL, address).Scan(&id)
	return id, err
}

// wantNoResolution asserts the explicit no-resolution outcome: ZERO rows (the
// unknown/disabled/ambiguous/quarantined classes all look identical to the
// consumer — never a row).
func wantNoResolution(t *testing.T, q querier, address, why string) {
	t.Helper()
	if _, err := resolveID(t, q, address); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("resolve(%q) %s: got err=%v, want zero rows (pgx.ErrNoRows)", address, why, err)
	}
}

// suspendAdmissionTrigger suspends the users admission trigger so a test can
// inject a legacy-shape overlap the way pre-contract data could exist (only by
// bypassing admission), re-arming it on cleanup. Skips when the connection
// cannot (the operation needs table-owner rights).
func suspendAdmissionTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`ALTER TABLE users DISABLE TRIGGER trg_identity_address_admission_users`); err != nil {
		t.Skipf("cannot suspend admission trigger (needs table owner): %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx,
			`ALTER TABLE users ENABLE TRIGGER trg_identity_address_admission_users`); err != nil {
			t.Errorf("re-enable admission trigger: %v", err)
		}
	})
}

// appConn acquires a dedicated pool connection re-roled to setjoin_app — the
// tenant-facing runtime role (NOSUPERUSER, NOBYPASSRLS). Every assertion made on
// it runs under exactly the privileges the live resolver twin sees after the
// native-RLS flip, not under the test identity's owner bypass. Skips when the
// role is missing or cannot be assumed (provision-roles.sql not applied).
// The cleanup RESETs the role BEFORE releasing: pgxpool does not reset session
// state on release, and a returned still-setjoin_app connection would poison
// every later pool.Exec (e.g. the owner-only admission-trigger re-arm) with
// SQLSTATE 42501.
func appConn(t *testing.T, pool *pgxpool.Pool) *pgxpool.Conn {
	t.Helper()
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Skipf("cannot acquire connection: %v", err)
	}
	if _, err := conn.Exec(context.Background(), `SET ROLE setjoin_app`); err != nil {
		conn.Release()
		t.Skipf("cannot assume setjoin_app (provision-roles.sql not applied?): %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), `RESET ROLE`)
		conn.Release()
	})
	return conn
}

// TestResolveIdentitySQL_ResolvesAnchorFromEveryAddress proves the same-person
// fixture (distinct primary + UPN + sister-domain alias, all on ONE users row)
// resolves to that single anchor row from every admitted address — the
// legitimate overlap the admission contract must preserve.
func TestResolveIdentitySQL_ResolvesAnchorFromEveryAddress(t *testing.T) {
	pool := testPool(t)
	f := seedFixture(t, pool)
	ctx := context.Background()

	if _, err := pool.Exec(ctx,
		`UPDATE users SET ad_upn = $1 WHERE id = $2`, f.upnA, f.userAID); err != nil {
		t.Fatalf("seed alice UPN (same-person admission): %v", err)
	}

	for _, addr := range []string{f.emailA, f.upnA, f.aliasA, strings.ToUpper(f.upnA)} {
		id, err := resolveID(t, pool, addr)
		if err != nil {
			t.Fatalf("resolve(%q): %v", addr, err)
		}
		if id != f.userAID {
			t.Fatalf("resolve(%q) = %d, want anchor user %d", addr, id, f.userAID)
		}
	}

	// An unknown address still resolves to zero rows.
	wantNoResolution(t, pool, "nobody@nowhere-"+randSuffix(t)+".test", "is unknown")
}

// TestResolveIdentitySQL_FailClosedOnCrossPersonOverlap proves the V249
// admission contract: a cross-person duplicate injected by BYPASSING the
// admission triggers (the legacy-data class) returns the explicit no-resolution
// outcome (zero rows), never a lowest-id pick — and a quarantined address stays
// dead even after only one claimant remains, until an operator releases it.
func TestResolveIdentitySQL_FailClosedOnCrossPersonOverlap(t *testing.T) {
	pool := testPool(t)
	f := seedFixture(t, pool)
	ctx := context.Background()

	// Inject the overlap (B's UPN = A's primary email) the way pre-contract
	// data could exist: with the admission trigger suspended.
	suspendAdmissionTrigger(t, pool)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET ad_upn = $1 WHERE id = $2`, f.emailA, f.userBID); err != nil {
		t.Fatalf("inject overlap: %v", err)
	}

	// The address matches BOTH enabled persons. It must resolve to NO ONE —
	// notably not to the lower-id person a bare LIMIT 1 could return on plan
	// order.
	wantNoResolution(t, pool, f.emailA, "is claimed by two enabled persons")

	// The one-time backfill quarantines the overlap with an operator-visible
	// report naming both claimants.
	var qAddress string
	var qOwners []int64
	if err := pool.QueryRow(ctx,
		`SELECT quarantined_address, owner_ids FROM identity_address_overlap_backfill()`,
	).Scan(&qAddress, &qOwners); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if qAddress != f.emailA {
		t.Fatalf("backfill quarantined %q, want %q", qAddress, f.emailA)
	}
	if len(qOwners) != 2 || qOwners[0] != f.userAID || qOwners[1] != f.userBID {
		t.Fatalf("backfill owners = %v, want [%d %d]", qOwners, f.userAID, f.userBID)
	}
	// Empty second run: convergence.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM identity_address_overlap_backfill()`).Scan(&n); err != nil {
		t.Fatalf("second backfill run: %v", err)
	}
	if n != 0 {
		t.Fatalf("second backfill run quarantined %d more addresses; want 0", n)
	}

	// Remove the overlap source: exactly ONE claimant remains — but the
	// quarantined address still resolves for no one.
	if _, err := pool.Exec(ctx,
		`UPDATE users SET ad_upn = NULL WHERE id = $1`, f.userBID); err != nil {
		t.Fatalf("clear overlap source: %v", err)
	}
	wantNoResolution(t, pool, f.emailA, "is quarantined with a single claimant")

	// Operator release (fix + delete the quarantine row) restores
	// anchor-faithful resolution to the one legitimate owner.
	if _, err := pool.Exec(ctx,
		`DELETE FROM identity_address_quarantine WHERE address = $1`, f.emailA); err != nil {
		t.Fatalf("release quarantine: %v", err)
	}
	id, err := resolveID(t, pool, f.emailA)
	if err != nil {
		t.Fatalf("resolve after release: %v", err)
	}
	if id != f.userAID {
		t.Fatalf("resolve after release = %d, want anchor %d", id, f.userAID)
	}
}

// TestResolveIdentitySQL_QuarantineBindsUnderRuntimeRole proves the quarantine
// exclusion under the RUNTIME role (setjoin_app — NOSUPERUSER, NOBYPASSRLS),
// not just under the test identity's owner bypass. The ledger is FORCE RLS
// with zero policies, so it is INVISIBLE to setjoin_app; a twin that probed it
// directly (NOT EXISTS … FROM identity_address_quarantine) would find the
// exclusion vacuously satisfied and silently RESUME resolution once one
// competing claim is removed — without any operator release. With the
// quarantine RETAINED, resolution must stay denied under setjoin_app until the
// owner deletes the row; the fact itself flows through the SECURITY DEFINER
// helper (identity_address_quarantined) both twins call.
func TestResolveIdentitySQL_QuarantineBindsUnderRuntimeRole(t *testing.T) {
	pool := testPool(t)
	f := seedFixture(t, pool)
	ctx := context.Background()

	// Legacy-shape overlap (B's UPN = A's primary email), quarantined through
	// the operator backfill, then the overlap source removed: exactly ONE
	// enabled claimant remains, quarantine RETAINED.
	suspendAdmissionTrigger(t, pool)
	if _, err := pool.Exec(ctx,
		`UPDATE users SET ad_upn = $1 WHERE id = $2`, f.emailA, f.userBID); err != nil {
		t.Fatalf("inject overlap: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`SELECT count(*) FROM identity_address_overlap_backfill()`); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var owners []int64
	if err := pool.QueryRow(ctx,
		`SELECT owners FROM identity_address_quarantine WHERE address = $1`,
		f.emailA).Scan(&owners); err != nil {
		t.Fatalf("quarantine row missing after backfill: %v", err)
	}
	if len(owners) != 2 || owners[0] != f.userAID || owners[1] != f.userBID {
		t.Fatalf("quarantine owners = %v, want [%d %d]", owners, f.userAID, f.userBID)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET ad_upn = NULL WHERE id = $1`, f.userBID); err != nil {
		t.Fatalf("clear overlap source: %v", err)
	}

	// Runtime role: the ledger row exists but stays invisible (FORCE RLS,
	// zero policies) — while its FACT still binds the resolver shut.
	ac := appConn(t, pool)
	var appSees int
	if err := ac.QueryRow(ctx,
		`SELECT count(*)::int FROM identity_address_quarantine`).Scan(&appSees); err != nil {
		t.Fatalf("app-role ledger probe: %v", err)
	}
	if appSees != 0 {
		t.Fatalf("setjoin_app sees %d quarantine rows; want 0 (FORCE RLS, zero policies)", appSees)
	}
	var quarantined bool
	if err := ac.QueryRow(ctx,
		`SELECT identity_address_quarantined($1)`, f.emailA).Scan(&quarantined); err != nil {
		t.Fatalf("app-role quarantine helper: %v", err)
	}
	if !quarantined {
		t.Fatal("setjoin_app must read the quarantine FACT through the SECURITY DEFINER helper")
	}
	wantNoResolution(t, ac, f.emailA,
		"is quarantined with a single claimant under the RUNTIME role (setjoin_app)")

	// Non-vacuity: the same runtime connection still resolves an unquarantined
	// address — the denial above is the quarantine binding, not app-role
	// blindness.
	id, err := resolveID(t, ac, f.emailB)
	if err != nil {
		t.Fatalf("app-role resolve of unquarantined address: %v", err)
	}
	if id != f.userBID {
		t.Fatalf("app-role resolve(%q) = %d, want %d", f.emailB, id, f.userBID)
	}

	// Operator release (the owner fixes + deletes the ledger row) restores
	// anchor-faithful resolution under the SAME runtime connection.
	if _, err := pool.Exec(ctx,
		`DELETE FROM identity_address_quarantine WHERE address = $1`, f.emailA); err != nil {
		t.Fatalf("release quarantine: %v", err)
	}
	id, err = resolveID(t, ac, f.emailA)
	if err != nil {
		t.Fatalf("app-role resolve after release: %v", err)
	}
	if id != f.userAID {
		t.Fatalf("app-role resolve after release = %d, want anchor %d", id, f.userAID)
	}
}
