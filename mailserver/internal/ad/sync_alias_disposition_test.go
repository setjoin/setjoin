package ad

// L2-C3 (astra-proposal-c234 r2-C3-1 + r3-C3-1) — legacy proxyAddress alias
// writer disposition tests against V249's authoritative admission contract.
//
// The aliases BEFORE-row trigger trg_identity_address_admission_aliases is the
// SOLE admission authority: another ENABLED person claiming the address
// (users.email ∪ users.ad_upn ∪ their aliases — via identity_address_claims)
// raises BZ328; a row that instead reaches the unconditional
// aliases_email_lower_idx and lands on ON CONFLICT DO NOTHING has no enabled
// claimant (e.g. a disabled holder). These tests pin what syncProxyAliases
// DOES with those outcomes — classified skip + continued safe-alias processing
// + uSN cursor advancement, never transfer/reassignment and never a
// writer-side gate — using real legacy INSERTs against a test Postgres with
// V249 installed (identity_address_admission.pg owns trigger-denial coverage;
// we do not re-prove it).
//
// Also here: the Item-4 mailserver reachability guard (source-bound routing to
// the normalized engine, never the legacy path), the Item-5 reserved-name seam
// pin (med-shard2-008 covers the AD mint; no second gate), the r2-C3-2
// builder key-set pin for buildSyncAttrs, and the delta-r2 retained-mailbox
// regression (a NULL mailboxes.user_id alias classifies as OCCUPIED with
// Skipped accounting, never as an unclassifiable readback).
//
// delta-r3 fixture ownership: every row these tests create — including
// persons provisioned BY the sync under test (a later page entry) and the
// identity_sync_log rows a SyncNow run appends — is tracked and removed by
// fixture cleanup, every cleanup statement's error is checked, and cleanup
// verifies no owned residue survives. Leaked fixture rows fail the test
// instead of silently poisoning the shared test database.
//
// delta-r4 failure-path ownership: a SyncNow can provision a later page entry
// and THEN fail (sync.go returns the uSN cursor-update error only after the
// page's users are stored), so the page tests' immediate t.Fatalf fires
// before their adoptSyncedUser call. Cleanup therefore no longer relies on
// pre-registered ids alone: it DISCOVERS fixture rows at teardown — adopting
// expectations registered before SyncNow plus a domain-wide scan for anything
// else the sync created — and a dedicated failure arm injects that cursor
// failure and pins that cleanup leaves zero residue.
//
// delta-r5 fixture-failure cleanup round 2: the cursor-block injection creates
// a function and then a trigger, and a failed CREATE TRIGGER reaches t.Fatalf
// before any cleanup was registered — stranding the function. Each object's
// cleanup is now registered IMMEDIATELY after its own creation succeeds, and a
// dedicated arm forces the trigger creation to fail and proves the function
// leaves no residue.
//
// delta-r8 exact sync-log ownership (D-3, Astra r2): the fixture's
// identity_sync_log teardown twice retired interference-prone capture. The
// original global watermark deleted every source='ad' row above the highest
// id at fixture creation; its r7 replacement bracketed each run (`id > mark`
// read after the run returned) but STILL adopted any concurrent insert DURING
// SyncNow — that row's id also sits above the mark. Ownership now comes FROM
// THE WRITER: sync() RETURNs the id of each identity_sync_log row it inserts
// and the runSyncNow bracket adopts exactly those ids, so a foreign row —
// before, during, or after the run — can never enter the captured set. The
// dedicated interference arm proves all three placements survive cleanup.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	ldap "github.com/go-ldap/ldap/v3"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldaputil"
)

// ── fixtures ───────────────────────────────────────────────────────────────

// requireAdmissionTrigger fails the test when V249's alias admission trigger is
// absent: every disposition pin below is meaningless (or silently vacuous)
// without the DB contract these tests exist to exercise, so a mis-provisioned
// test database must fail loudly rather than skip.
func requireAdmissionTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_trigger
		  WHERE tgrelid = 'aliases'::regclass AND tgname = 'trg_identity_address_admission_aliases'`,
	).Scan(&count); err != nil || count != 1 {
		t.Fatalf("V249 alias admission trigger not installed in the test database (count=%d err=%v) — the L2-C3 disposition tests require it", count, err)
	}
}

type aliasFixture struct {
	pool     *pgxpool.Pool
	domain   string
	domainID int64

	userIDs    []int64
	mailboxIDs []int64

	// pendingSyncedEmails are persons the sync under test is PREDICTED to
	// create, registered before SyncNow runs. Cleanup adopts whatever was
	// actually created for them — including when the test aborted on a
	// SyncNow error before reaching its own adoption assertion.
	pendingSyncedEmails []string

	// syncLogIDs are the identity_sync_log ids the fixture's OWN SyncNow runs
	// appended, reported BY THE WRITER: sync() RETURNs each inserted row's id
	// and the runSyncNow bracket hands it to recordSyncLogID. There is no
	// id-range capture left — a concurrent run's rows can never enter the
	// fixture's ownership, because the fixture never looks at any row the
	// writer did not report (delta r8, D-3).
	syncLogIDs []int64
}

func newAliasFixture(t *testing.T, pool *pgxpool.Pool) *aliasFixture {
	t.Helper()
	requireAliasSchema(t, pool)
	requireAdmissionTrigger(t, pool)
	f := &aliasFixture{pool: pool}
	suffix := randSuffix(t)
	f.domain = "admdisp-" + suffix + ".local"
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, f.domain,
	).Scan(&f.domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { f.cleanup(t) })
	return f
}

// recordSyncLogID adopts one identity_sync_log id handed over by the writer
// itself: while a runSyncNow bracket is active, sync() reports each appended
// row's RETURNING id through the worker's syncLogAppended hook. Deduplicated,
// because the fixture's cleanup may run more than once.
func (f *aliasFixture) recordSyncLogID(id int64) {
	for _, existing := range f.syncLogIDs {
		if existing == id {
			return
		}
	}
	f.syncLogIDs = append(f.syncLogIDs, id)
}

// runSyncNow brackets a SyncNow with WRITER-SIDE id capture (delta r8, D-3).
// The retired shape — a pre-run watermark plus a post-run `id > mark` SELECT
// — captured at CREATION TIME but still let a concurrent run's insert DURING
// SyncNow enter the captured set (its id also sits above the mark), so cleanup
// deleted foreign rows. Ownership now comes from the actual writer: sync()
// RETURNs the id of each identity_sync_log row it inserts and only those ids
// are adopted. Cleanup deletes exactly the reported ids, and only them.
func (f *aliasFixture) runSyncNow(t *testing.T, w *SyncWorker) (SyncResult, error) {
	t.Helper()
	prev := w.syncLogAppended
	w.syncLogAppended = f.recordSyncLogID
	defer func() { w.syncLogAppended = prev }()
	return w.SyncNow(context.Background())
}

// cleanup removes every row the fixture (and any sync the tests ran through
// it) owns: aliases, mailboxes, users, the fixture domain, and the
// identity_sync_log rows captured from its own SyncNow runs. Every statement's
// error is checked, and the deletions are followed by a no-residue
// verification — leaked rows fail the test rather than persisting silently.
//
// Ownership is DISCOVERED at teardown time (delta r4), not taken from
// pre-registered ids alone: a SyncNow can provision a page entry and THEN
// fail (sync.go's cursor write), so a test can die via t.Fatalf before its
// adoptSyncedUser call. Cleanup runs on that Fatalf and must adopt the rows
// itself — see adoptFixtureOwnedRows.
//
// Each person's teardown runs in one transaction with mailboxes deleted
// BEFORE the users row, matching the admin user-delete cascade: the deferred
// BZ013 "must keep a primary mailbox" check passes because the user is gone
// at commit, and the FK's ON DELETE SET NULL never runs (so a primary mailbox
// can never violate mailboxes_shared_not_primary mid-teardown).
func (f *aliasFixture) cleanup(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	f.adoptFixtureOwnedRows(t)

	// Aliases travel with the fixture domain; the per-mailbox sweep below
	// additionally covers an alias row parked on an owned mailbox under some
	// other domain id (no current writer produces one — cleanup owns rows,
	// not writers' promises).
	if _, err := f.pool.Exec(ctx, `DELETE FROM aliases WHERE domain_id = $1`, f.domainID); err != nil {
		t.Errorf("fixture cleanup: delete aliases in fixture domain: %v", err)
	}
	for _, mb := range f.mailboxIDs {
		if _, err := f.pool.Exec(ctx, `DELETE FROM aliases WHERE mailbox_id = $1`, mb); err != nil {
			t.Errorf("fixture cleanup: delete aliases for mailbox %d: %v", mb, err)
		}
	}
	for _, uid := range f.userIDs {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Errorf("fixture cleanup: begin teardown tx for user %d: %v", uid, err)
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, uid); err != nil {
			t.Errorf("fixture cleanup: delete mailboxes for user %d: %v", uid, err)
			_ = tx.Rollback(ctx)
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, uid); err != nil {
			t.Errorf("fixture cleanup: delete user %d: %v", uid, err)
			_ = tx.Rollback(ctx)
			continue
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("fixture cleanup: commit teardown for user %d: %v", uid, err)
		}
	}
	if len(f.syncLogIDs) > 0 {
		if _, err := f.pool.Exec(ctx,
			`DELETE FROM identity_sync_log WHERE id = ANY($1)`, f.syncLogIDs,
		); err != nil {
			t.Errorf("fixture cleanup: delete %d owned sync-log rows: %v", len(f.syncLogIDs), err)
		}
	}

	// No residue: every owned row class must be gone before the domain goes.
	for _, check := range []struct {
		name  string
		query string
	}{
		{"users", `SELECT count(*) FROM users WHERE domain_id = $1`},
		{"mailboxes", `SELECT count(*) FROM mailboxes WHERE domain_id = $1`},
		{"aliases", `SELECT count(*) FROM aliases WHERE domain_id = $1`},
	} {
		var n int
		if err := f.pool.QueryRow(ctx, check.query, f.domainID).Scan(&n); err != nil {
			t.Errorf("fixture cleanup: count %s residue: %v", check.name, err)
			continue
		}
		if n != 0 {
			t.Errorf("fixture cleanup: %d %s row(s) remain for domain %q — fixture leaked rows", n, check.name, f.domain)
		}
	}
	// Owned ids only: a foreign sync-log row inserted after fixture creation
	// must survive us, so it must never appear in (or fail) this check.
	if len(f.syncLogIDs) > 0 {
		var logResidue int
		if err := f.pool.QueryRow(ctx,
			`SELECT count(*) FROM identity_sync_log WHERE id = ANY($1)`, f.syncLogIDs,
		).Scan(&logResidue); err != nil {
			t.Errorf("fixture cleanup: count owned sync-log residue: %v", err)
		} else if logResidue != 0 {
			t.Errorf("fixture cleanup: %d owned identity_sync_log row(s) survived deletion — fixture leaked sync-log rows", logResidue)
		}
	}

	if _, err := f.pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, f.domainID); err != nil {
		t.Errorf("fixture cleanup: delete domain %d: %v", f.domainID, err)
	}
}

type personOpts struct {
	enabled bool
	guid    string
	adUPN   string
	// noMailbox skips the primary mailbox: the person then holds only their
	// users.email/ad_upn claims (no mailbox_address_claims substrate row on
	// the address — the V199 'mailbox reservation' contract maps a primary
	// mailbox address to exactly one mailbox unconditionally, enabled or not).
	noMailbox bool
}

type person struct {
	userID    int64
	mailboxID int64
	email     string
}

// seedPerson creates a person (+ primary mailbox unless noMailbox) in the
// fixture domain. The V249 users admission trigger runs on this INSERT, so
// seeding a person whose address is already claimed by an enabled person fails
// loudly — fixtures only ever claim free addresses.
func (f *aliasFixture) seedPerson(t *testing.T, localPart string, opts personOpts) person {
	t.Helper()
	ctx := context.Background()
	var guid any
	if opts.guid != "" {
		guid = opts.guid
	}
	var upn any
	if opts.adUPN != "" {
		upn = opts.adUPN
	}
	var userID int64
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled, ad_object_guid, ad_upn)
		 VALUES ($1, lower($2), $3, $4, '$2a$10$placeholder', $5, $6, $7)
		 RETURNING id`,
		localPart, localPart+"@"+f.domain, "Fixture "+localPart, f.domainID, opts.enabled, guid, upn,
	).Scan(&userID); err != nil {
		t.Fatalf("insert person %s: %v", localPart, err)
	}
	f.userIDs = append(f.userIDs, userID)
	if opts.noMailbox {
		return person{userID: userID, email: localPart + "@" + f.domain}
	}
	var mailboxID int64
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', TRUE)
		 RETURNING id`,
		userID, f.domainID, localPart+"@"+f.domain,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert primary mailbox for %s: %v", localPart, err)
	}
	f.mailboxIDs = append(f.mailboxIDs, mailboxID)
	return person{userID: userID, mailboxID: mailboxID, email: localPart + "@" + f.domain}
}

// seedAlias inserts an alias row directly on a person's mailbox (through the
// same V249 admission trigger the writer faces).
func (f *aliasFixture) seedAlias(t *testing.T, mailboxID int64, addr string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1, $2, $3)`,
		mailboxID, addr, f.domainID,
	); err != nil {
		t.Fatalf("seed alias %s: %v", addr, err)
	}
	f.registerAliasMailbox(mailboxID)
}

func (f *aliasFixture) registerAliasMailbox(mailboxID int64) {
	for _, id := range f.mailboxIDs {
		if id == mailboxID {
			return
		}
	}
	f.mailboxIDs = append(f.mailboxIDs, mailboxID)
}

// expectSyncedUser registers a person the sync under test is predicted to
// create (e.g. a later page entry) BEFORE SyncNow runs, so teardown owns the
// creation even when the test aborts on the sync's error before reaching its
// own adoption assertion.
func (f *aliasFixture) expectSyncedUser(email string) {
	f.pendingSyncedEmails = append(f.pendingSyncedEmails, email)
}

// adoptFixtureOwnedRows is the teardown discovery pass (delta r4): cleanup
// runs on t.Fatalf too, so it must find rows the sync created after the test
// stopped executing — the post-provision cursor-failure shape where Bob is
// stored but unadopted. Two nets, both safe because the fixture domain is
// random-suffixed and owned by this fixture alone:
//   - every pending expectation (registered before SyncNow) is adopted by
//     email, tolerantly: a failed sync may never have provisioned it;
//   - a domain-wide scan adopts any other user row in the fixture domain —
//     the catch-all for sync-created rows no test predicted.
func (f *aliasFixture) adoptFixtureOwnedRows(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	for _, email := range f.pendingSyncedEmails {
		var userID int64
		var mailboxID *int64
		err := f.pool.QueryRow(ctx,
			`SELECT u.id, (SELECT m.id FROM mailboxes m
			   WHERE m.user_id = u.id AND m.is_primary = TRUE LIMIT 1)
			 FROM users u WHERE lower(u.email) = lower($1)`, email,
		).Scan(&userID, &mailboxID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				continue // the sync never provisioned this expectation
			}
			t.Errorf("fixture cleanup: adopt expected synced user %s: %v", email, err)
			continue
		}
		f.adoptUser(userID)
		if mailboxID != nil {
			f.registerAliasMailbox(*mailboxID)
		}
	}

	rows, err := f.pool.Query(ctx, `SELECT id FROM users WHERE domain_id = $1`, f.domainID)
	if err != nil {
		t.Errorf("fixture cleanup: discover users in fixture domain: %v", err)
		return
	}
	defer rows.Close()
	var discovered []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Errorf("fixture cleanup: scan discovered user: %v", err)
			continue
		}
		discovered = append(discovered, id)
	}
	if err := rows.Err(); err != nil {
		t.Errorf("fixture cleanup: iterate discovered users: %v", err)
		return
	}
	for _, id := range discovered {
		f.adoptUser(id)
	}
}

// adoptUser registers a user id for teardown, deduplicating (a seeded person
// is also found by the domain-wide scan).
func (f *aliasFixture) adoptUser(userID int64) {
	for _, uid := range f.userIDs {
		if uid == userID {
			return
		}
	}
	f.userIDs = append(f.userIDs, userID)
}

// adoptSyncedUser registers a person created BY the sync under test (not by
// seedPerson — e.g. a later page entry provisioned through ProvisionAccount)
// so fixture cleanup owns and removes their user + primary mailbox. The lookup
// doubles as the continuation assertion: a page entry that failed to sync
// fails the test here rather than passing vacuously.
func (f *aliasFixture) adoptSyncedUser(t *testing.T, email string) person {
	t.Helper()
	var p person
	if err := f.pool.QueryRow(context.Background(),
		`SELECT u.id, m.id FROM users u JOIN mailboxes m ON m.user_id = u.id
		  WHERE lower(u.email) = lower($1) AND m.is_primary = TRUE`, email,
	).Scan(&p.userID, &p.mailboxID); err != nil {
		t.Fatalf("adopt synced user %s (page entry did not sync): %v", email, err)
	}
	p.email = email
	f.userIDs = append(f.userIDs, p.userID)
	f.registerAliasMailbox(p.mailboxID)
	return p
}

// aliasesOnMailbox returns the alias addresses hanging off one mailbox.
func (f *aliasFixture) aliasesOnMailbox(t *testing.T, mailboxID int64) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(),
		`SELECT email FROM aliases WHERE mailbox_id = $1 ORDER BY email`, mailboxID)
	if err != nil {
		t.Fatalf("query aliases: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan alias: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// aliasOwnerMailbox returns the mailbox_id of the surviving alias row for an
// address (0 if none).
func (f *aliasFixture) aliasOwnerMailbox(t *testing.T, addr string) int64 {
	t.Helper()
	var mbID int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT mailbox_id FROM aliases WHERE lower(email) = lower($1)`, addr,
	).Scan(&mbID); err != nil {
		return 0
	}
	return mbID
}

func captureLogs(t *testing.T) (*bytes.Buffer, *slog.Logger) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	return &buf, logger
}

// setSystemConfigForTest pins a system_config key for the test, restoring the
// prior value (or deleting the row it created) afterwards.
func setSystemConfigForTest(t *testing.T, pool *pgxpool.Pool, key, value string) {
	t.Helper()
	ctx := context.Background()
	var previous *string
	prevErr := pool.QueryRow(ctx,
		`SELECT value::TEXT FROM system_config WHERE key = $1`, key,
	).Scan(&previous)
	if prevErr != nil && !errors.Is(prevErr, pgx.ErrNoRows) {
		t.Fatalf("read system_config %s: %v", key, prevErr)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, description) VALUES ($1, $2, 'set by L2-C3 disposition test')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, value,
	); err != nil {
		t.Fatalf("set system_config %s=%s: %v", key, value, err)
	}
	t.Cleanup(func() {
		c := context.Background()
		if previous == nil {
			if _, err := pool.Exec(c, `DELETE FROM system_config WHERE key = $1`, key); err != nil {
				t.Errorf("cleanup system_config %s: %v", key, err)
			}
			return
		}
		if _, err := pool.Exec(c,
			`UPDATE system_config SET value = $2::jsonb, updated_at = now() WHERE key = $1`, key, *previous); err != nil {
			t.Errorf("restore system_config %s: %v", key, err)
		}
	})
}

// ── classification unit test ───────────────────────────────────────────────

// TestAdmissionConflictClassification pins the BZ328 / hint classifier against
// non-admission DB errors: the rejection warn must be distinguishable from any
// other insert failure.
func TestAdmissionConflictClassification(t *testing.T) {
	bz := &pgconn.PgError{Code: "BZ328", Hint: `{"type":"identity_address_admission_conflict"}`}
	hintOnly := &pgconn.PgError{Code: "XX999", Hint: `{"type":"identity_address_admission_conflict"}`}
	wrapped := fmt.Errorf("insert alias: %w", bz)
	otherCode := &pgconn.PgError{Code: "23505", Hint: `{"type":"something_else"}`}
	otherHint := &pgconn.PgError{Code: "XX999", Hint: `{"type":"unrelated"}`}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"BZ328 with hint", bz, true},
		{"hint alone classifies", hintOnly, true},
		{"wrapped BZ328 classifies", wrapped, true},
		{"unique violation is not admission", otherCode, false},
		{"other hint type is not admission", otherHint, false},
		{"plain error is not admission", errors.New("boom"), false},
		{"nil is not admission", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kind, ok := admissionConflictKind(tc.err)
			if ok != tc.want {
				t.Fatalf("admissionConflictKind(%v) ok=%v, want %v", tc.err, ok, tc.want)
			}
			if ok && kind != "identity_address_admission_conflict" {
				t.Errorf("kind = %q, want identity_address_admission_conflict", kind)
			}
		})
	}
}

// ── classified rejections (BZ328): enabled competing claimant ──────────────

// runSyncProxyAliases is the shared writer harness: a SyncWorker against the
// fixture pool with a captured log buffer.
func runSyncProxyAliases(t *testing.T, f *aliasFixture) (*bytes.Buffer, *SyncWorker) {
	t.Helper()
	buf, logger := captureLogs(t)
	return buf, &SyncWorker{pool: f.pool, logger: logger}
}

func assertRejectedByAdmission(t *testing.T, logs *bytes.Buffer, user, alias string) {
	t.Helper()
	got := logs.String()
	if !strings.Contains(got, "rejected by identity address admission") {
		t.Errorf("logs missing the rejected-by-admission warn: %q", got)
	}
	if !strings.Contains(got, alias) {
		t.Errorf("rejection warn does not carry the alias %q: %q", alias, got)
	}
	if !strings.Contains(got, "identity_address_admission_conflict") {
		t.Errorf("rejection warn does not carry the rejection kind: %q", got)
	}
	if !strings.Contains(got, user) {
		t.Errorf("rejection warn does not carry the user %q: %q", user, got)
	}
	if strings.Contains(got, "failed to upsert proxy alias") {
		t.Errorf("admission rejection landed in the generic failure warn — classification broken: %q", got)
	}
}

func assertNoAdmissionWarns(t *testing.T, logs *bytes.Buffer) {
	t.Helper()
	got := logs.String()
	for _, unwanted := range []string{
		"rejected by identity address admission",
		"already held by another owner",
		"failed to upsert proxy alias",
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("logs unexpectedly contain %q: %q", unwanted, got)
		}
	}
}

// TestSyncProxyAliases_EmailCollisionRejectedByAdmission (r2): a directory
// proxyAddress equal to another ENABLED user's users.email is rejected BZ328 by
// the DB trigger — logged rejected-by-admission, counted Skipped not Errors,
// and the safe alias after it still lands.
func TestSyncProxyAliases_EmailCollisionRejectedByAdmission(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: true}) // holds holder@<domain> through users.email
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{
		Email:          syncing.email,
		ProxyAddresses: []string{"smtp:" + holder.email, "smtp:safe@" + f.domain},
	}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (the colliding alias) — counted as Errors would stall the uSN cursor", res.Skipped)
	}
	if got := f.aliasesOnMailbox(t, syncing.mailboxID); len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("aliases on syncing person = %v, want exactly [safe@…] — the safe alias after the collision must land", got)
	}
	if owner := f.aliasOwnerMailbox(t, holder.email); owner != 0 {
		t.Errorf("address %q resolved to alias mailbox %d, want no alias row — the holder keeps it through users.email (no transfer)", holder.email, owner)
	}
	assertRejectedByAdmission(t, buf, syncing.email, holder.email)
}

// TestSyncProxyAliases_UPNCollisionRejectedByAdmission (r2): same disposition
// when the competing enabled claim holds the address through users.ad_upn.
func TestSyncProxyAliases_UPNCollisionRejectedByAdmission(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	f.seedPerson(t, "holder", personOpts{enabled: true, adUPN: "held@" + f.domain})
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{Email: syncing.email, ProxyAddresses: []string{"smtp:held@" + f.domain}}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", res.Skipped)
	}
	if got := f.aliasesOnMailbox(t, syncing.mailboxID); len(got) != 0 {
		t.Errorf("aliases on syncing person = %v, want none (UPN claimant is enabled → BZ328)", got)
	}
	assertRejectedByAdmission(t, buf, syncing.email, "held@"+f.domain)
}

// TestSyncProxyAliases_AliasVsAliasCollisionRejectedByAdmission (r2): same
// disposition when the address is another enabled person's existing alias.
func TestSyncProxyAliases_AliasVsAliasCollisionRejectedByAdmission(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: true})
	f.seedAlias(t, holder.mailboxID, "held@"+f.domain)
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{Email: syncing.email, ProxyAddresses: []string{"smtp:held@" + f.domain}}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", res.Skipped)
	}
	if owner := f.aliasOwnerMailbox(t, "held@"+f.domain); owner != holder.mailboxID {
		t.Errorf("held alias mailbox = %d, want the holder's %d (no transfer, no reassignment)", owner, holder.mailboxID)
	}
	assertRejectedByAdmission(t, buf, syncing.email, "held@"+f.domain)
}

// ── Case B (r3): occupied alias row, no enabled claimant → classified no-op ─

// TestSyncProxyAliases_OccupiedAliasRowClassifiedNoOp (r3 Case B): the address
// sits on a DISABLED person's alias row — no enabled claimant, so BZ328 does
// not fire and the INSERT lands on ON CONFLICT DO NOTHING. The writer must
// classify the no-op from the command tag + owner readback: occupied-alias
// warn, counted Skipped, the existing row unchanged (same mailbox — NO
// transfer, NO reassignment), nothing created for the syncing person, and the
// safe alias after it still inserted.
func TestSyncProxyAliases_OccupiedAliasRowClassifiedNoOp(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: false})
	f.seedAlias(t, holder.mailboxID, "held@"+f.domain)
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{
		Email:          syncing.email,
		ProxyAddresses: []string{"smtp:held@" + f.domain, "smtp:safe@" + f.domain},
	}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 1 || res.Errors != 0 {
		t.Errorf("result = %+v, want Skipped=1 Errors=0 (occupied no-op is skip-shaped)", res)
	}
	if owner := f.aliasOwnerMailbox(t, "held@"+f.domain); owner != holder.mailboxID {
		t.Errorf("held alias mailbox = %d, want the disabled holder's %d — the occupied row must be left untouched (no transfer, no reassignment)", owner, holder.mailboxID)
	}
	if got := f.aliasesOnMailbox(t, syncing.mailboxID); len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("aliases on syncing person = %v, want exactly [safe@…] — the safe alias after the occupied one must land", got)
	}
	got := buf.String()
	if !strings.Contains(got, "already held by another owner") {
		t.Errorf("logs missing the occupied-alias no-op warn: %q", got)
	}
	if !strings.Contains(got, "holder_user_id") {
		t.Errorf("occupied-alias warn does not carry the holder: %q", got)
	}
	if strings.Contains(got, "rejected by identity address admission") {
		t.Errorf("occupied no-op misclassified as an admission rejection: %q", got)
	}
	if strings.Contains(got, "failed to upsert proxy alias") {
		t.Errorf("occupied no-op landed in the generic failure warn: %q", got)
	}
}

// TestSyncProxyAliases_RetainedMailboxNullBindingOccupied (L2-C3 delta r2
// regression): a retained mailbox keeps its aliases after the lifecycle detach
// clears mailboxes.user_id (mailbox_lifecycle_retention.pg pins that SQL
// contract). The alias collision reaches DO NOTHING like any other unclaimed
// row, but the readback previously scanned that NULL into int64, failed as
// "could not be classified", and escaped Skipped accounting — violating the
// occupied-row disposition. The NULL binding must classify as OCCUPIED: warn +
// Skipped (Errors stays 0, so the uSN cursor keeps advancing), the alias stays
// on the retained mailbox (no transfer, no reassignment), and the safe alias
// after it still lands.
func TestSyncProxyAliases_RetainedMailboxNullBindingOccupied(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: false})
	f.seedAlias(t, holder.mailboxID, "retained@"+f.domain)

	// Construct the retained-mailbox shape: the user binding is cleared while
	// the alias survives. (The pgTAP retention suite owns the reducer path
	// that produces this state in production; here it only needs to pin the
	// Go writer's classification of the resulting NULL mailboxes.user_id.)
	// The binding is cleared together with primacy/enabled exactly as
	// detach_retain does — mailboxes_shared_not_primary forbids a shared
	// primary mailbox.
	if _, err := pool.Exec(context.Background(),
		`UPDATE mailboxes SET user_id = NULL, is_primary = false, enabled = false WHERE id = $1`,
		holder.mailboxID,
	); err != nil {
		t.Fatalf("clear holder binding: %v", err)
	}
	t.Cleanup(func() {
		// Re-bind so the fixture's by-user_id mailbox cleanup still finds it,
		// restoring the seeded shape in full (primacy included — a live user
		// must keep a primary mailbox, BZ014).
		if _, err := pool.Exec(context.Background(),
			`UPDATE mailboxes SET user_id = $2, is_primary = TRUE WHERE id = $1`, holder.mailboxID, holder.userID); err != nil {
			t.Errorf("re-bind retained mailbox %d for cleanup: %v", holder.mailboxID, err)
		}
	})
	var binding any
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM mailboxes WHERE id = $1`, holder.mailboxID,
	).Scan(&binding); err != nil || binding != nil {
		t.Fatalf("precondition: retained mailbox binding = %v (err %v), want NULL", binding, err)
	}

	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{
		Email:          syncing.email,
		ProxyAddresses: []string{"smtp:retained@" + f.domain, "smtp:safe@" + f.domain},
	}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 1 || res.Errors != 0 {
		t.Errorf("result = %+v, want Skipped=1 Errors=0 — the NULL-binding occupied row must not escape Skipped accounting", res)
	}
	if owner := f.aliasOwnerMailbox(t, "retained@"+f.domain); owner != holder.mailboxID {
		t.Errorf("retained alias mailbox = %d, want the retained mailbox %d — no transfer, no reassignment", owner, holder.mailboxID)
	}
	if got := f.aliasesOnMailbox(t, syncing.mailboxID); len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("aliases on syncing person = %v, want exactly [safe@…] — the safe alias after the occupied one must land", got)
	}
	got := buf.String()
	if !strings.Contains(got, "already held by another owner") {
		t.Errorf("logs missing the occupied-alias no-op warn: %q", got)
	}
	if strings.Contains(got, "could not be classified") {
		t.Errorf("NULL-binding readback must classify as occupied, not fail the readback: %q", got)
	}
	if strings.Contains(got, "failed to upsert proxy alias") {
		t.Errorf("occupied no-op landed in the generic failure warn: %q", got)
	}
}

// ── Case A (r3): disabled email/UPN claim → admitted, no writer gate ───────

// TestSyncProxyAliases_DisabledEmailClaimAdmitted (r3 Case A): the address is
// held only through a DISABLED person's users.email — identity_address_claims
// filters enabled=TRUE, so BZ328 does not fire and the alias is ADMITTED for
// the syncing person. The holder is seeded mailbox-less: an address carried by
// another person's PRIMARY MAILBOX is reserved by the V199
// mailbox_address_claims substrate (BZ315) regardless of enabledness — that
// occupied shape is pinned separately below. The writer adds no enabledness
// gate of its own; the surviving re-enable arm is pinned after this test.
func TestSyncProxyAliases_DisabledEmailClaimAdmitted(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: false, noMailbox: true})
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{Email: syncing.email, ProxyAddresses: []string{"smtp:" + holder.email}}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 0 || res.Errors != 0 {
		t.Errorf("result = %+v, want zero counters — a disabled email claim must not skip or error the writer", res)
	}
	if owner := f.aliasOwnerMailbox(t, holder.email); owner != syncing.mailboxID {
		t.Errorf("alias mailbox = %d, want the syncing person's %d — the alias must be admitted and resolve to the syncing person", owner, syncing.mailboxID)
	}
	assertNoAdmissionWarns(t, buf)
}

// TestSyncProxyAliases_MailboxReservedAddressKeepsGenericFailureShape pins the
// NON-BZ328 arm of the disposition: an address carried by another person's
// primary mailbox (here a disabled holder's — mailbox reservations are
// unconditional, V199) is rejected BZ315 by the mailbox-address-claims
// substrate, which is NOT an admission conflict. The writer keeps today's
// generic shape — logged warn, NOT counted (neither Skipped nor Errors), sync
// continues — and the safe alias after it still lands.
func TestSyncProxyAliases_MailboxReservedAddressKeepsGenericFailureShape(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: false}) // primary mailbox reserves holder@<domain>
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{
		Email:          syncing.email,
		ProxyAddresses: []string{"smtp:" + holder.email, "smtp:safe@" + f.domain},
	}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)

	if res.Skipped != 0 || res.Errors != 0 {
		t.Errorf("result = %+v, want zero counters — general alias-failure accounting is not redefined by this packet", res)
	}
	if got := f.aliasesOnMailbox(t, syncing.mailboxID); len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("aliases on syncing person = %v, want exactly [safe@…] — sync must continue past the failure", got)
	}
	got := buf.String()
	if !strings.Contains(got, "failed to upsert proxy alias") {
		t.Errorf("logs missing the generic failure warn for the BZ315 shape: %q", got)
	}
	if strings.Contains(got, "rejected by identity address admission") {
		t.Errorf("a non-admission error was misclassified as an admission rejection: %q", got)
	}
	if strings.Contains(got, "already held by another owner") {
		t.Errorf("a failed insert was misclassified as an occupied-row no-op: %q", got)
	}
}

// TestDisabledHolderReenableIntoClaimFiresBZ328 is r3's surviving re-enable
// arm (scoped to Case A): after the writer admitted the syncing person's alias
// over a disabled email claim, re-enabling that holder raises BZ328 via the
// users trigger — the DB contract keeps custody; the writer surfaces nothing
// extra (asserted by the absence of warns in the writer test above).
func TestDisabledHolderReenableIntoClaimFiresBZ328(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	holder := f.seedPerson(t, "holder", personOpts{enabled: false, noMailbox: true})
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	_, w := runSyncProxyAliases(t, f)
	u := ADUser{Email: syncing.email, ProxyAddresses: []string{"smtp:" + holder.email}}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)
	if res.Skipped != 0 {
		t.Fatalf("Case A admission failed: %+v", res)
	}

	_, err := pool.Exec(context.Background(),
		`UPDATE users SET enabled = TRUE WHERE id = $1`, holder.userID)
	if err == nil {
		t.Fatal("re-enabling the disabled holder into the claimed address must raise BZ328 (V249 users trigger)")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ328" {
		t.Errorf("err = %v, want BZ328", err)
	}
}

// ── same-person idempotency (r2 point 3) ───────────────────────────────────

// TestSyncProxyAliases_SamePersonIdempotencyNoWarns: re-running the sync
// inserts nothing new and emits NO admission/occupied warn — the DO NOTHING
// readback classifies the surviving row as the syncing person's own (through
// mailboxes.user_id, so an alias on any of their mailboxes counts).
func TestSyncProxyAliases_SamePersonIdempotencyNoWarns(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	syncing := f.seedPerson(t, "syncer", personOpts{enabled: true})

	buf, w := runSyncProxyAliases(t, f)
	u := ADUser{
		Email:          syncing.email,
		ProxyAddresses: []string{"smtp:alpha@" + f.domain, "smtp:beta@" + f.domain},
	}
	var res SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res)
	first := f.aliasesOnMailbox(t, syncing.mailboxID)
	if len(first) != 2 {
		t.Fatalf("first pass aliases = %v, want both", first)
	}

	var res2 SyncResult
	w.syncProxyAliases(context.Background(), syncing.userID, u, &res2)
	second := f.aliasesOnMailbox(t, syncing.mailboxID)

	if len(second) != 2 || !equalStrings(first, second) {
		t.Errorf("re-sync changed aliases: first=%v second=%v", first, second)
	}
	if res2.Skipped != 0 {
		t.Errorf("re-sync Skipped = %d, want 0 (same-person DO NOTHING is silent idempotency)", res2.Skipped)
	}
	assertNoAdmissionWarns(t, buf)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── full-page continuation + cursor (r2 + r3 Case B binding) ───────────────

// recordingFakeDirectory watches for legacy-path dialing so the routing guard
// and the page tests can assert which engine ran.
type recordingFakeDirectory struct {
	fakeADDirectory
	connectCalled bool
}

func (f *recordingFakeDirectory) connect() (*ldap.Conn, error) {
	f.connectCalled = true
	return f.fakeADDirectory.connect()
}

// TestLegacySyncPage_CollisionSkipsContinueAndCursorAdvances (r2
// continuation): a colliding alias inside a full legacy sync page is a
// classified skip — the user's attribute sync (ApplyUserUpdate) is unaffected,
// aliases after the colliding one land, the next user in the page still syncs,
// and the uSN cursor still advances because Errors stays 0.
func TestLegacySyncPage_CollisionSkipsContinueAndCursorAdvances(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	setSystemConfigForTest(t, pool, "ad_sync_proxy_as_aliases", "true")
	setSystemConfigForTest(t, pool, "ad_sync_last_usn", "0")

	f.seedPerson(t, "holder", personOpts{enabled: true}) // users.email = holder@<domain>

	// Alice pre-exists with her GUID → the matched-GUID path (ApplyUserUpdate).
	guidA := uuid.NewString()
	alice := f.seedPerson(t, "alice", personOpts{enabled: true, guid: guidA})

	buf, logger := captureLogs(t)
	users := []ADUser{
		{
			ObjectGUID: guidA, Email: alice.email, DisplayName: "Alice Updated",
			ProxyAddresses: []string{"smtp:holder@" + f.domain, "smtp:safe@" + f.domain},
			USNChanged:     7,
		},
		{
			ObjectGUID: uuid.NewString(), Email: "bob@" + f.domain, DisplayName: "Bob",
			USNChanged: 9,
		},
	}
	w := &SyncWorker{
		client: &fakeADDirectory{users: users, maxUSN: 9},
		pool:   pool, logger: logger,
	}
	// Bob's creation is owned before SyncNow runs (delta r4): if the sync
	// provisioned him and THEN failed, the t.Fatalf below fires before the
	// adoption assertion and teardown-time discovery becomes his owner.
	f.expectSyncedUser("bob@" + f.domain)
	res, err := f.runSyncNow(t, w)
	if err != nil {
		t.Fatalf("SyncNow: %v", err)
	}
	if res.Errors != 0 {
		t.Errorf("Errors = %d, want 0 — the admission rejection must never error the entry", res.Errors)
	}
	if res.Skipped < 1 {
		t.Errorf("Skipped = %d, want >= 1 (the classified rejection)", res.Skipped)
	}
	if res.Updated < 1 {
		t.Errorf("Updated = %d, want >= 1 — Alice's attribute sync is unaffected by her alias rejection", res.Updated)
	}

	var cursor int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((value #>> '{}')::BIGINT, 0) FROM system_config WHERE key = 'ad_sync_last_usn'`,
	).Scan(&cursor); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	if cursor != 9 {
		t.Errorf("uSN cursor = %d, want 9 — Errors==0 must keep the cursor advancing past expected rejections", cursor)
	}

	var aliceName string
	if err := pool.QueryRow(context.Background(),
		`SELECT display_name FROM users WHERE ad_object_guid = $1`, guidA,
	).Scan(&aliceName); err != nil {
		t.Fatalf("read alice: %v", err)
	}
	if aliceName != "Alice Updated" {
		t.Errorf("alice display_name = %q, want %q", aliceName, "Alice Updated")
	}

	var aliceMailboxID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE`, alice.userID,
	).Scan(&aliceMailboxID); err != nil {
		t.Fatalf("read alice mailbox: %v", err)
	}
	got := f.aliasesOnMailbox(t, aliceMailboxID)
	if len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("alice aliases = %v, want exactly [safe@…]", got)
	}

	// Bob — the entry AFTER Alice — must have synced (the page continued), and
	// his sync-created rows are adopted into the fixture so cleanup owns them.
	f.adoptSyncedUser(t, "bob@"+f.domain)

	if !strings.Contains(buf.String(), "rejected by identity address admission") {
		t.Errorf("page run did not log the classified rejection: %q", buf.String())
	}
}

// TestLegacySyncPage_OccupiedAliasNoOpContinues (r3 Case B full-page shape):
// an occupied alias row (disabled holder) inside the page no-ops with
// classified accounting — safe aliases after it land, the next user syncs, the
// cursor advances.
func TestLegacySyncPage_OccupiedAliasNoOpContinues(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	setSystemConfigForTest(t, pool, "ad_sync_proxy_as_aliases", "true")
	setSystemConfigForTest(t, pool, "ad_sync_last_usn", "0")

	// The disabled holder's alias row occupies the address.
	holder := f.seedPerson(t, "holder", personOpts{enabled: false})
	f.seedAlias(t, holder.mailboxID, "occupied@"+f.domain)

	guidA := uuid.NewString()
	alice := f.seedPerson(t, "alice", personOpts{enabled: true, guid: guidA})

	buf, logger := captureLogs(t)
	users := []ADUser{
		{
			ObjectGUID: guidA, Email: alice.email, DisplayName: "Alice Updated",
			ProxyAddresses: []string{"smtp:occupied@" + f.domain, "smtp:safe@" + f.domain},
			USNChanged:     7,
		},
		{
			ObjectGUID: uuid.NewString(), Email: "bob@" + f.domain, DisplayName: "Bob",
			USNChanged: 9,
		},
	}
	w := &SyncWorker{
		client: &fakeADDirectory{users: users, maxUSN: 9},
		pool:   pool, logger: logger,
	}
	// Bob's creation is owned before SyncNow runs (delta r4): if the sync
	// provisioned him and THEN failed, the t.Fatalf below fires before the
	// adoption assertion and teardown-time discovery becomes his owner.
	f.expectSyncedUser("bob@" + f.domain)
	res, err := f.runSyncNow(t, w)
	if err != nil {
		t.Fatalf("SyncNow: %v", err)
	}
	if res.Errors != 0 {
		t.Errorf("Errors = %d, want 0 — the occupied no-op is Skipped-shaped", res.Errors)
	}
	if res.Skipped < 1 {
		t.Errorf("Skipped = %d, want >= 1 (the occupied-alias no-op)", res.Skipped)
	}

	var cursor int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE((value #>> '{}')::BIGINT, 0) FROM system_config WHERE key = 'ad_sync_last_usn'`,
	).Scan(&cursor); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	if cursor != 9 {
		t.Errorf("uSN cursor = %d, want 9", cursor)
	}

	if owner := f.aliasOwnerMailbox(t, "occupied@"+f.domain); owner != holder.mailboxID {
		t.Errorf("occupied alias mailbox = %d, want the disabled holder's %d — no transfer, no reassignment", owner, holder.mailboxID)
	}
	var aliceMailboxID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE`, alice.userID,
	).Scan(&aliceMailboxID); err != nil {
		t.Fatalf("read alice mailbox: %v", err)
	}
	got := f.aliasesOnMailbox(t, aliceMailboxID)
	if len(got) != 1 || got[0] != "safe@"+f.domain {
		t.Errorf("alice aliases = %v, want exactly [safe@…] — the safe alias after the occupied one must land", got)
	}
	// Bob — the entry AFTER Alice's occupied-alias page — must have synced too
	// (continued processing), and his sync-created rows are adopted into the
	// fixture so cleanup owns them.
	f.adoptSyncedUser(t, "bob@"+f.domain)
	if !strings.Contains(buf.String(), "already held by another owner") {
		t.Errorf("page run did not log the occupied-alias no-op: %q", buf.String())
	}
}

// createCursorBlocker injects the cursor-update failure the failure arms need:
// a BEFORE INSERT OR UPDATE trigger on system_config, scoped by WHEN to the AD
// cursor key, executing a raise-only plpgsql function. The caller passes the
// name suffix so an arm can pre-occupy the generated trigger name and force
// the CREATE TRIGGER itself to fail.
//
// delta r5 — closes the leak Astra flagged in round 4: cleanup used to be
// registered in one block AFTER the trigger creation, so a failed CREATE
// TRIGGER reached t.Fatalf while the already-created function had no cleanup
// and survived the test. Each object's cleanup is now registered immediately
// after its own creation succeeds — the function drop right after CREATE
// FUNCTION, the trigger drop right after CREATE TRIGGER — so no failure later
// in the helper can strand either object, and t.Cleanup LIFO still drops the
// trigger before the function.
func createCursorBlocker(t testing.TB, pool *pgxpool.Pool, suffix string) {
	t.Helper()
	raiseFn := "admdisp_" + suffix + "_cursor_raise"
	blockTrg := "admdisp_" + suffix + "_cursor_block"
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`CREATE FUNCTION `+raiseFn+`() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
			 RAISE EXCEPTION 'admdisp fixture: AD cursor update blocked';
		 END;
		 $fn$`,
	); err != nil {
		t.Fatalf("create cursor-block function: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+raiseFn+`()`); err != nil {
			t.Errorf("drop cursor-block function: %v", err)
		}
	})
	if _, err := pool.Exec(ctx,
		`CREATE TRIGGER `+blockTrg+` BEFORE INSERT OR UPDATE ON system_config
		 FOR EACH ROW WHEN (NEW.key = 'ad_sync_last_usn')
		 EXECUTE FUNCTION `+raiseFn+`()`,
	); err != nil {
		t.Fatalf("create cursor-block trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+blockTrg+` ON system_config`); err != nil {
			t.Errorf("drop cursor-block trigger: %v", err)
		}
	})
}

// fatalTrapTB adapts the real test for arms that must drive createCursorBlocker
// THROUGH its t.Fatalf failure path and keep running afterwards: Fatalf records
// the message and panics (the arm recovers) instead of runtime.Goexit, while
// every other TB method — crucially Cleanup, whose registrations must still run
// at teardown — delegates to the embedded *testing.T.
type fatalTrapTB struct {
	*testing.T
	fatalMsg string
}

func (ft *fatalTrapTB) Fatalf(format string, args ...any) {
	ft.fatalMsg = fmt.Sprintf(format, args...)
	panic(ft)
}

// TestLegacySyncPage_CursorFailureAfterProvisionLeavesNoResidue (delta r4
// failure arm): SyncNow can provision the later page entry (Bob) and THEN
// fail — sync.go returns the uSN cursor-update error only after the page's
// users are stored — and the page tests' immediate t.Fatalf("SyncNow: %v",
// err) then fires BEFORE adoptSyncedUser. This arm injects exactly that
// failure and pins that fixture cleanup leaves zero residue: a BEFORE trigger
// on system_config raises only for the AD cursor key, SyncNow errors after
// provisioning Bob, and the test mirrors the Fatalf shape by ending with Bob
// deliberately unadopted. Cleanup — registered long before SyncNow — must
// then discover and remove Bob, his mailbox and every other fixture row; any
// leak fails this test through cleanup's own no-residue assertions and the
// FK-guarded domain delete.
func TestLegacySyncPage_CursorFailureAfterProvisionLeavesNoResidue(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	setSystemConfigForTest(t, pool, "ad_sync_proxy_as_aliases", "true")
	setSystemConfigForTest(t, pool, "ad_sync_last_usn", "0")

	// Ownership registered BEFORE SyncNow: Bob is a predicted sync creation,
	// so teardown owns him even if the test dies before its own adoption
	// assertion. The ghost is never provisioned — discovery must tolerate an
	// expectation the failed sync did not fulfil, never fail on its absence.
	f.expectSyncedUser("bob@" + f.domain)
	f.expectSyncedUser("ghost@" + f.domain)

	guidA := uuid.NewString()
	alice := f.seedPerson(t, "alice", personOpts{enabled: true, guid: guidA})

	// Inject the cursor-update failure. The trigger is created after the
	// config seeds above and dropped before their restores (t.Cleanup LIFO),
	// so the only statement it ever sees is sync.go's cursor write. delta r5:
	// each object's cleanup registers immediately after its own creation, so
	// a failed CREATE TRIGGER cannot strand the function.
	createCursorBlocker(t, pool, randSuffix(t))

	_, logger := captureLogs(t)
	users := []ADUser{
		{ObjectGUID: guidA, Email: alice.email, DisplayName: "Alice Updated", USNChanged: 7},
		{ObjectGUID: uuid.NewString(), Email: "bob@" + f.domain, DisplayName: "Bob", USNChanged: 9},
	}
	w := &SyncWorker{
		client: &fakeADDirectory{users: users, maxUSN: 9},
		pool:   pool, logger: logger,
	}
	res, err := f.runSyncNow(t, w)
	if err == nil {
		t.Fatal("SyncNow succeeded — the cursor-block trigger did not engage and the failure arm is vacuous")
	}
	if !strings.Contains(err.Error(), "update cursor") {
		t.Errorf("err = %v, want the sync's cursor-update failure", err)
	}
	if res.Created != 1 {
		t.Errorf("Created = %d, want 1 — the failure must land AFTER the page's provision", res.Created)
	}

	// The post-provision state the page tests would t.Fatalf in: Bob is fully
	// stored (with his primary mailbox) yet registered nowhere — the exact
	// ownership gap flagged in review. This test now ends without adopting
	// him; teardown-time discovery is his only remaining owner, and its
	// no-residue assertions are the verdict.
	ctx := context.Background()
	var bobID, bobMailboxID int64
	if err := pool.QueryRow(ctx,
		`SELECT u.id, m.id FROM users u
		 JOIN mailboxes m ON m.user_id = u.id AND m.is_primary = TRUE
		 WHERE lower(u.email) = $1`, "bob@"+f.domain,
	).Scan(&bobID, &bobMailboxID); err != nil {
		t.Fatalf("Bob was not provisioned (with primary mailbox) before the cursor failure — post-provision state not reached: %v", err)
	}
	for _, uid := range f.userIDs {
		if uid == bobID {
			t.Fatal("Bob is already registered — the unadopted residue shape this arm must exercise was not reached")
		}
	}
}

// TestAliasFixtureCleanupSparesForeignSyncLogRows (delta r8, D-3 interference
// proof): both retired capture shapes adopted foreign rows — the original
// watermark deleted EVERY source='ad' sync-log row above a fixture-creation
// watermark, and its r7 bracket still captured a concurrent insert DURING
// SyncNow (the row's id also sits above the mark). Ownership is now reported
// BY THE WRITER (sync() RETURNs each inserted id; runSyncNow adopts exactly
// those). The proof: foreign AD sync-log rows inserted BEFORE the run, INSIDE
// the run (from the directory stub — the exact window the `id > mark` capture
// owned), and AFTER the run must all survive cleanup intact and never appear
// in the captured set, while every owned row is gone.
func TestAliasFixtureCleanupSparesForeignSyncLogRows(t *testing.T) {
	pool := testPool(t)
	f := newAliasFixture(t, pool)
	ctx := context.Background()

	// Foreign rows resembling a concurrent run. Each row's own cleanup is
	// registered immediately after its successful insert so this test never
	// strands what it creates; LIFO runs those cleanups BEFORE the fixture's
	// (registered earlier in newAliasFixture), which is exactly why the
	// survival verdict is asserted in the body, between the explicit fixture
	// cleanup below and the test's return.
	insertForeign := func(marker string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO identity_sync_log (source, users_checked, details)
			 VALUES ('ad', 1, jsonb_build_object('imp_debt_d3_foreign', $1::text)) RETURNING id`, marker,
		).Scan(&id); err != nil {
			t.Fatalf("insert foreign sync-log row %s: %v", marker, err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(),
				`DELETE FROM identity_sync_log WHERE id = $1 AND details->>'imp_debt_d3_foreign' = $2`, id, marker,
			); err != nil {
				t.Errorf("cleanup foreign sync-log row %d (%s): %v", id, marker, err)
			}
		})
		return id
	}
	foreignBeforeRun := insertForeign("before-run")

	// A real SyncNow through the fixture: one page entry updated, one owned
	// sync-log row appended (the cursor config is pinned, so the run reaches
	// the cursor write and the log insert after it). The directory stub
	// inserts a foreign row MID-RUN — inside the capture window the retired
	// `id > mark` bracket owned, i.e. exactly the row the old capture deleted.
	setSystemConfigForTest(t, pool, "ad_sync_proxy_as_aliases", "true")
	setSystemConfigForTest(t, pool, "ad_sync_last_usn", "0")
	guidA := uuid.NewString()
	alice := f.seedPerson(t, "alice", personOpts{enabled: true, guid: guidA})
	var midRunForeign int64
	w := &SyncWorker{
		client: &midRunForeignLogInserter{
			fakeADDirectory: fakeADDirectory{
				users:  []ADUser{{ObjectGUID: guidA, Email: alice.email, DisplayName: "Alice Updated", USNChanged: 7}},
				maxUSN: 7,
			},
			insert: func() { midRunForeign = insertForeign("mid-run") },
		},
		pool: pool, logger: testLogger(),
	}
	res, err := f.runSyncNow(t, w)
	if err != nil {
		t.Fatalf("SyncNow: %v", err)
	}
	if res.Updated != 1 || res.Errors != 0 {
		t.Fatalf("result = %+v, want Updated=1 Errors=0", res)
	}
	if len(f.syncLogIDs) == 0 {
		t.Fatal("runSyncNow captured no owned sync-log ids — the run appended no row and the ownership proof is vacuous")
	}
	if midRunForeign == 0 {
		t.Fatal("the mid-run foreign insert never fired — the interference arm is vacuous (the stub did not insert inside SyncNow)")
	}
	foreignAfterRun := insertForeign("after-run")

	// The captured set must hold ONLY the writer-reported ids: none of the
	// foreign rows — the mid-run one above all — may have been adopted.
	for _, probe := range []struct {
		id     int64
		marker string
	}{{foreignBeforeRun, "before-run"}, {midRunForeign, "mid-run"}, {foreignAfterRun, "after-run"}} {
		for _, adopted := range f.syncLogIDs {
			if adopted == probe.id {
				t.Errorf("foreign sync-log row %d (%s) was captured as owned — capture must adopt only the writer's RETURNING ids (D-3)",
					probe.id, probe.marker)
			}
		}
	}

	// Teardown now (the fixture's own t.Cleanup re-runs it harmlessly), then
	// the verdict: foreign rows survive, owned rows are gone.
	f.cleanup(t)

	for _, probe := range []struct {
		id     int64
		marker string
	}{{foreignBeforeRun, "before-run"}, {midRunForeign, "mid-run"}, {foreignAfterRun, "after-run"}} {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM identity_sync_log
			 WHERE id = $1 AND source = 'ad' AND details->>'imp_debt_d3_foreign' = $2`,
			probe.id, probe.marker,
		).Scan(&n); err != nil {
			t.Fatalf("probe foreign sync-log row %d: %v", probe.id, err)
		}
		if n != 1 {
			t.Errorf("foreign sync-log row %d (%s) did not survive fixture cleanup — admdisp fixture ownership must never extend to other runs' rows",
				probe.id, probe.marker)
		}
	}
	var owned int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM identity_sync_log WHERE id = ANY($1)`, f.syncLogIDs,
	).Scan(&owned); err != nil {
		t.Fatalf("count owned sync-log residue: %v", err)
	}
	if owned != 0 {
		t.Errorf("%d owned sync-log row(s) survived cleanup", owned)
	}
}

// midRunForeignLogInserter wraps the fake directory and inserts a foreign AD
// sync-log row DURING SyncNow (from SearchUsers — inside the run, before the
// worker reaches its identity_sync_log INSERT), then delegates unchanged.
type midRunForeignLogInserter struct {
	fakeADDirectory
	insert func()
}

func (m *midRunForeignLogInserter) SearchUsers(ctx context.Context, conn *ldap.Conn, cursor int64) ([]ADUser, int64, error) {
	if m.insert != nil {
		m.insert()
	}
	return m.fakeADDirectory.SearchUsers(ctx, conn, cursor)
}

// TestCursorBlockTriggerFailureLeavesNoFunctionResidue (delta r5 failure arm):
// the round-4 leak — a failed CREATE TRIGGER used to reach t.Fatalf BEFORE any
// cleanup was registered, stranding the already-created cursor-block function.
// This arm forces the real CREATE TRIGGER inside createCursorBlocker to fail
// (the trigger name is pre-occupied, duplicate_object) and drives the helper
// through exactly that path under a fatalTrapTB, then pins the fix: a
// teardown-time residue check — registered before the helper's cleanups, so
// t.Cleanup LIFO runs it after the function drop — must find the function
// gone. Under the r4 shape (function drop registered only after the trigger)
// the function survives and this arm fails.
//
// delta r6 (Astra r5): this arm's own setup used to recreate the same leak —
// the pre-occupied trigger function raiseFnPre was created, the pre-occupied
// trigger created, and only THEN one combined cleanup registered — so a
// failed pre-occupy CREATE TRIGGER would have stranded raiseFnPre while the
// then-raiseFn-only residue verdict looked the other way. The setup now
// registers each object's cleanup immediately after its own creation
// (function drop after CREATE FUNCTION, trigger drop after CREATE TRIGGER;
// LIFO keeps trigger-before-function teardown) and the verdict counts both
// raise functions.
func TestCursorBlockTriggerFailureLeavesNoFunctionResidue(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := "dup" + randSuffix(t)
	raiseFn := "admdisp_" + suffix + "_cursor_raise"
	blockTrg := "admdisp_" + suffix + "_cursor_block"
	raiseFnPre := raiseFn + "_pre"

	// The verdict, registered FIRST: LIFO runs it after the helper's function
	// drop and after this arm's own pre-occupied-object drops, so it observes
	// the post-teardown state of every setup object. delta r6: it counts BOTH
	// raise functions — the r5 verdict saw only raiseFn and could not catch
	// this arm's own setup leaking raiseFnPre.
	t.Cleanup(func() {
		for _, probe := range []struct{ role, name string }{
			{"cursor-block", raiseFn},
			{"pre-occupied", raiseFnPre},
		} {
			var n int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM pg_proc WHERE proname = $1`, probe.name,
			).Scan(&n); err != nil {
				t.Errorf("probe %s function residue: %v", probe.role, err)
				continue
			}
			if n != 0 {
				t.Errorf("%s function %s survived the arm — its cleanup was not registered immediately after its CREATE FUNCTION", probe.role, probe.name)
			}
		}
	})

	// Force the real CREATE TRIGGER to fail: pre-occupy the trigger name the
	// helper will generate. The collision is inert (scoped to a key nothing
	// writes), so it can never engage during the arm. delta r6: the setup no
	// longer recreates the leak it exercises — each object's cleanup is
	// registered immediately after its own successful creation, so a failed
	// CREATE TRIGGER below can no longer strand raiseFnPre under a cleanup
	// that was never reached.
	if _, err := pool.Exec(ctx,
		`CREATE FUNCTION `+raiseFnPre+`() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN RETURN NEW; END;
		 $fn$`,
	); err != nil {
		t.Fatalf("create pre-occupied trigger function: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+raiseFnPre+`()`); err != nil {
			t.Errorf("drop pre-occupied trigger function: %v", err)
		}
	})
	if _, err := pool.Exec(ctx,
		`CREATE TRIGGER `+blockTrg+` BEFORE INSERT ON system_config
		 FOR EACH ROW WHEN (NEW.key = 'admdisp_preoccupied_guard')
		 EXECUTE FUNCTION `+raiseFnPre+`()`,
	); err != nil {
		t.Fatalf("pre-occupy cursor-block trigger name: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+blockTrg+` ON system_config`); err != nil {
			t.Errorf("drop pre-occupied trigger: %v", err)
		}
	})

	// Drive the real helper under a Fatalf-trapping TB and survive its failure
	// path; the trapped message must be the trigger-creation one, proving the
	// arm actually reached the CREATE TRIGGER failure.
	ft := &fatalTrapTB{T: t}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(*fatalTrapTB); !ok {
					panic(r)
				}
			}
		}()
		createCursorBlocker(ft, pool, suffix)
	}()
	if !strings.Contains(ft.fatalMsg, "create cursor-block trigger") {
		t.Fatalf("createCursorBlocker did not die on CREATE TRIGGER (trapped message %q) — the trigger-failure arm is vacuous", ft.fatalMsg)
	}
}

// ── Item 4 (mailserver arm): source-bound routing guard ────────────────────

// TestSyncWithBoundSourceRoutesNormalizedNeverLegacy pins the shipped wiring
// premise: with an identity source store bound, SyncWorker.sync routes to the
// normalized engine and NEVER the legacy upsert path — so the legacy alias
// writer cannot be silently resurrected by a wiring change (mirrors C1's
// mount-absence-guard pattern).
func TestSyncWithBoundSourceRoutesNormalizedNeverLegacy(t *testing.T) {
	pool := testPool(t)
	fake := &recordingFakeDirectory{fakeADDirectory: fakeADDirectory{
		users: []ADUser{{ObjectGUID: uuid.NewString(), Email: "x@" + randSuffix(t) + ".local", USNChanged: 1}},
	}}
	w := NewSyncWorker(nil, pool, testLogger(), 15)
	w.SetIdentitySource(identitysource.NewStore(pool), "ad:guard-"+randSuffix(t))
	w.client = fake

	_, err := w.SyncNow(context.Background())
	if err == nil {
		t.Fatal("expected the normalized engine to error on the unknown source key — silence would mean neither path ran")
	}
	if !strings.Contains(err.Error(), "identity source") {
		t.Errorf("err = %v, want the normalized engine's source-load failure", err)
	}
	if fake.connectCalled {
		t.Error("legacy path dialed the directory while an identity source was bound — routing guard violated")
	}
}

// ── Item 5: reserved-name seam pin (med-shard2-008, no re-fix) ─────────────

// TestUpsertUserReservedNameCreateSurfacesSyncError asserts the RFC 2142 gate
// already covers directory-trust mints: an AD-minted create of
// postmaster@<local> fails in ProvisionAccount and surfaces as a sync-entry
// error. No second gate is added here — the seam is shared/identity's.
func TestUpsertUserReservedNameCreateSurfacesSyncError(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adrn-" + suffix + ".local"
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		if _, err := pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID); err != nil {
			t.Errorf("cleanup reserved-name domain %d: %v", domainID, err)
		}
	})

	guid := uuid.NewString()
	w := &SyncWorker{pool: pool, logger: testLogger()}
	u := ADUser{
		ObjectGUID:  guid,
		Email:       "postmaster@" + domain,
		DisplayName: "Postmaster",
		USNChanged:  1,
	}
	var res SyncResult
	err := w.upsertUser(ctx, u, false, false, &res)
	if err == nil {
		t.Fatal("AD-minted create of a reserved local-part must fail through ProvisionAccount's RFC 2142 gate")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Errorf("err = %v, want the RESERVED_NAME rejection", err)
	}
	var created int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE ad_object_guid = $1`, guid,
	).Scan(&created); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if created != 0 {
		t.Errorf("reserved-name create landed %d user row(s), want 0", created)
	}
}

// ── r2-C3-2: real builder pinned to the writer allowlist ───────────────────

// TestBuildSyncAttrsKeysWithinWriterAllowlist asserts the real AD map builder
// (not a hand-built map) stays inside the writer's accepted input keys, so
// builder drift fails this test instead of the writer erroring on live traffic
// — or worse, the writer silently accepting a new key.
func TestBuildSyncAttrsKeysWithinWriterAllowlist(t *testing.T) {
	u := ADUser{
		Email: "u@corp.local", DisplayName: "U", FirstName: "F", LastName: "L",
		Title: "T", Phone: "P", UPN: "u@CORP.LOCAL",
	}
	attrs := buildSyncAttrs(u)
	accepted := ldaputil.AcceptedSyncAttrsKeys()
	if len(attrs) != len(accepted) {
		t.Errorf("buildSyncAttrs produced %d keys, want the fixed table of %d", len(attrs), len(accepted))
	}
	for k := range attrs {
		if !accepted[k] {
			t.Errorf("buildSyncAttrs key %q is outside the writer's accepted input keys", k)
		}
	}
}
