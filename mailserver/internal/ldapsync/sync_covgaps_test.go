package ldapsync

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The tests in this file cover the fail-closed error arms of the sync engine:
// every arm surfaces a database fault instead of degrading to a permissive
// outcome. Faults are injected at real seams — canceled/expired contexts and
// row/table locks held by an uncommitted test transaction — so the arms run
// against the genuine pgx failure paths.

// releaseLock releases a fault-injection lock and lets the canceled
// statement settle before fixture teardown transactions run: the deferred
// release executes at test-body exit, BEFORE any t.Cleanup hook, and the
// short sleep keeps a just-canceled statement from racing those cleanups.
func releaseLock(tx pgx.Tx) {
	_ = tx.Rollback(context.Background())
	time.Sleep(300 * time.Millisecond)
}

// holdRowLock opens a transaction that holds FOR UPDATE on one system_config
// key until released. MVCC reads of the row stay unblocked; only writers
// (INSERT .. ON CONFLICT DO UPDATE) wait on it.
func holdRowLock(t *testing.T, pool *pgxpool.Pool, key string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`SELECT value FROM system_config WHERE key = $1 FOR UPDATE`, key,
	); err != nil {
		t.Fatalf("lock system_config key %s: %v", key, err)
	}
	return tx
}

// holdTableLock opens a transaction holding ACCESS EXCLUSIVE on one table
// until released, blocking every subsequent statement that touches it.
func holdTableLock(t *testing.T, pool *pgxpool.Pool, table string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE "+table+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock %s: %v", table, err)
	}
	return tx
}

func deadlineCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestUpsertUser_AnchorResolveDBErrorIsSurfaced(t *testing.T) {
	pool := testPool(t)
	// A database error resolving the fence is an ERROR outcome for retry,
	// never a degrade to "no anchor".
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := w.upsertUser(ctx, LDAPUser{
		Email:            "anchorfault@example.invalid",
		ImmutableSubject: "anchor-fault-subject",
	}, false, &SyncResult{})
	if err == nil {
		t.Fatal("anchor resolve DB error must surface, got nil")
	}
}

func TestUpsertUser_DeniedAnchorConflictWriteFailureSurfaces(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapdenyfault")
	domain := domainID_domain(t, pool, domainID)
	subject := "deny-fault-" + suffix

	ensureLegacyLDAPActive(t, pool)
	ownedID := upsertFixtureUser(t, pool, domainID, "denyfault-"+suffix, "Deny Fault", "ldap")
	addPrimaryMailbox(t, pool, ownedID)
	anchorFixtureLink(t, pool, ownedID, subject, []string{"provision"})
	if _, err := pool.Exec(ctx,
		`UPDATE user_identity_links SET state = 'suspended' WHERE external_subject = $1`, subject,
	); err != nil {
		t.Fatalf("suspend fixture link: %v", err)
	}

	// The denied-anchor audit INSERT cannot commit: the write fault surfaces
	// instead of silently dropping the operator-review audit row.
	lock := holdTableLock(t, pool, "sync_conflicts")
	defer releaseLock(lock)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	if err := w.upsertUser(deadlineCtx(t), LDAPUser{
		DN:               "CN=DenyFault-" + suffix + ",DC=ldap,DC=local",
		ImmutableSubject: subject,
		Email:            "denyfault-" + suffix + "@" + domain,
		Disabled:         true,
	}, false, &SyncResult{}); err == nil {
		t.Fatal("denied-anchor conflict write failure must surface, got nil")
	}
}

func TestUpsertUser_ProvisionFailureSurfaces(t *testing.T) {
	pool := testPool(t)
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapprovisionfault")
	domain := domainID_domain(t, pool, domainID)

	// The gated email path finds nothing (its SELECT faults), provisioning
	// then faults too: the error must propagate, never count as created.
	lock := holdTableLock(t, pool, "users")
	defer func() {
		releaseLock(lock)
		// If the canceled provision INSERT won any race with the lock
		// release, its row is removed here, inside the test body, before
		// the fixture domain cleanup runs.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE email = $1`,
			"provisionfault-"+suffix+"@"+domain)
	}()
	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(deadlineCtx(t), LDAPUser{
		Email:       "provisionfault-" + suffix + "@" + domain,
		DisplayName: "Provision Fault",
	}, false, &result); err == nil {
		t.Fatal("provisioning write failure must surface, got nil")
	}
	if result.Created != 0 {
		t.Errorf("created = %d, want 0 on failed provisioning", result.Created)
	}
}

func TestUpsertUser_UnanchoredConflictWriteFailureSurfaces(t *testing.T) {
	pool := testPool(t)
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapunanchfault")
	domain := domainID_domain(t, pool, domainID)
	upsertFixtureUser(t, pool, domainID, "unanchfault-"+suffix, "Unanchored Fault", "local")

	lock := holdTableLock(t, pool, "sync_conflicts")
	defer releaseLock(lock)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(deadlineCtx(t), LDAPUser{
		Email: "unanchfault-" + suffix + "@" + domain,
	}, false, &result); err == nil {
		t.Fatal("unanchored-match conflict write failure must surface, got nil")
	}
	if result.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 (skip decision stands even though the audit write failed)", result.Skipped)
	}
}

func TestUpsertUser_FieldPolicyReadFailureFailsClosed(t *testing.T) {
	pool := testPool(t)
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldappolicyfault")
	domain := domainID_domain(t, pool, domainID)
	upsertFixtureUser(t, pool, domainID, "policyfault-"+suffix, "Policy Fault", "ldap")

	// LDAPSYNC-005: an unreadable protection set fails the update closed.
	lock := holdTableLock(t, pool, "field_policy")
	defer releaseLock(lock)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(deadlineCtx(t), LDAPUser{
		Email:       "policyfault-" + suffix + "@" + domain,
		DisplayName: "Policy Fault Updated",
	}, false, &result); err == nil {
		t.Fatal("local-only field policy read failure must surface, got nil")
	}
}

func TestPreviewRow_PolicyReadFailureSkipsClosed(t *testing.T) {
	pool := testPool(t)
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldappreviewfault")
	domain := domainID_domain(t, pool, domainID)
	upsertFixtureUser(t, pool, domainID, "previewfault-"+suffix, "Preview Fault", "ldap")

	lock := holdTableLock(t, pool, "field_policy")
	defer releaseLock(lock)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	row := w.previewRow(deadlineCtx(t), LDAPUser{
		Email:       "previewfault-" + suffix + "@" + domain,
		DisplayName: "Preview Fault",
	})
	if row.Action != "skip" {
		t.Errorf("action = %q, want skip (fail-closed preview)", row.Action)
	}
}

func TestResolveAnchor_QueryError(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.resolveAnchor(ctx, "some-subject"); err == nil {
		t.Fatal("anchor resolve query error must surface, got nil")
	}
}

func TestLinkProvisionedUser_QueryErrorIsLoggedOnly(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Best-effort anchoring never fails the sync: the error is logged.
	w.linkProvisionedUser(ctx, 1, "unreachable-subject", 0)
}

func TestRecordAbsenceSweep_ErrorSurfaces(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.recordAbsenceSweep(ctx); err == nil {
		t.Fatal("absence sweep timestamp write failure must surface, got nil")
	}
}

func TestDisableAbsentUsers_QueryErrorSurfaces(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var result SyncResult
	if err := w.disableAbsentUsers(ctx, []LDAPUser{{Email: "a@example.invalid"}}, &result); err == nil {
		t.Fatal("absence sweep query failure must surface, got nil")
	}
	if result.Disabled != 0 {
		t.Errorf("disabled = %d, want 0 on query failure", result.Disabled)
	}
}

func TestDisableAbsentUsers_CollectsPresentSubjects(t *testing.T) {
	pool := testPool(t)
	// Present entries carrying immutable subjects must join the exclusion
	// set so anchored (renamed) accounts are never swept as absentees.
	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.disableAbsentUsers(context.Background(), []LDAPUser{
		{Email: "present@example.invalid", ImmutableSubject: "present-subject"},
	}, &result); err != nil {
		t.Fatalf("absence sweep with subjects: %v", err)
	}
}

func TestResolveManagerIDs_AuthorizedTargetsErrorIsSwallowed(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The manager pass is advisory: a failed authorization resolution is
	// logged and skipped, never a sync error.
	w.resolveManagerIDs(ctx, []LDAPUser{{Email: "mgr@example.invalid"}})
}

func TestAuthorizedManagerTargets_QueryError(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := w.authorizedManagerTargets(ctx, []string{"a@example.invalid"}, []string{"s"}); err == nil {
		t.Fatal("authorized target query failure must surface, got nil")
	}
}

func TestResolveManagerIDs_EntryWithoutEmailYieldsNoTarget(t *testing.T) {
	pool := testPool(t)
	// A DN-bearing entry with no address and no authorized anchor resolves
	// to no mutation target (the empty-email guard in resolveSelfID).
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.resolveManagerIDs(context.Background(), []LDAPUser{
		{DN: "CN=no-email,DC=ldap,DC=local", ImmutableSubject: "unlinked-no-email"},
	})
}

func TestScanLocalOnlyFields_PropagatesQueryError(t *testing.T) {
	w := &SyncWorker{logger: testLogger()}
	fields, err := w.scanLocalOnlyFields(nil, errors.New("query fault"))
	if err == nil {
		t.Fatal("query error must propagate, got nil")
	}
	if fields != nil {
		t.Errorf("fields = %v, want nil on error", fields)
	}
}

// failingRows is a minimal pgx.Rows whose Scan fails — the stand-in for a
// driver-level row fault in the field_policy scan.
type failingRows struct {
	started bool
}

func (r *failingRows) Next() bool {
	if !r.started {
		r.started = true
		return true
	}
	return false
}

func (r *failingRows) Scan(dest ...any) error { return errors.New("row fault") }
func (r *failingRows) Close()                 {}
func (r *failingRows) Err() error             { return nil }
func (r *failingRows) CommandTag() pgconn.CommandTag {
	return pgconn.NewCommandTag("SELECT 0")
}
func (r *failingRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *failingRows) Values() ([]any, error)                       { return nil, nil }
func (r *failingRows) RawValues() [][]byte                          { return nil }
func (r *failingRows) Conn() *pgx.Conn                              { return nil }

var _ pgx.Rows = (*failingRows)(nil)

func TestScanLocalOnlyFields_PropagatesScanError(t *testing.T) {
	w := &SyncWorker{logger: testLogger()}
	fields, err := w.scanLocalOnlyFields(&failingRows{}, nil)
	if err == nil {
		t.Fatal("scan error must propagate, got nil")
	}
	if fields != nil {
		t.Errorf("fields = %v, want nil on error", fields)
	}
}

// TestSync_RecordAbsenceSweepFailureRetainsCursor pins the sweep's caller
// contract: when the sweep succeeds but its timestamp write cannot commit
// (row lock held by an uncommitted transaction), the cycle counts an error —
// the cursor stays unadvanced and absent accounts stay disabled-but-retried.
func TestSync_RecordAbsenceSweepFailureRetainsCursor(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapsweepfault")
	domain := domainID_domain(t, pool, domainID)

	presentID := upsertFixtureUser(t, pool, domainID, "sweepfp-"+suffix, "Sweep Present", "ldap")
	absentID := upsertFixtureUser(t, pool, domainID, "sweepfa-"+suffix, "Sweep Absent", "ldap")
	seedSession(t, pool, absentID)

	// Seed the sweep timestamp row so the test can pin its row lock, and
	// backdate it so the cycle promotes itself to a full enumeration.
	setSyncSystemConfig(t, pool, "ldap_sync_last_absence_sweep",
		jsonQuote(time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339)))

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	fake.users = []LDAPUser{
		{Email: "sweepfp-" + suffix + "@" + domain, DisplayName: "Sweep Present"},
	}
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	// Hold the sweep timestamp row: every read of it (MVCC) still succeeds,
	// the sweep runs, but the final INSERT .. ON CONFLICT DO UPDATE blocks
	// until the cycle's deadline expires.
	lock := holdRowLock(t, pool, "ldap_sync_last_absence_sweep")
	defer releaseLock(lock)

	result, err := w.SyncNow(deadlineCtx(t))
	if err != nil {
		t.Fatalf("sync with sweep timestamp fault: %v", err)
	}
	if result.Errors != 1 {
		t.Fatalf("result = %+v, want exactly 1 error (the timestamp write)", result)
	}
	if result.Disabled != 1 {
		t.Errorf("disabled = %d, want 1 (the sweep itself succeeded)", result.Disabled)
	}
	if userBool(t, pool, absentID, "enabled") {
		t.Error("absent account was not disabled before the timestamp fault")
	}
	if !userBool(t, pool, presentID, "enabled") {
		t.Error("present account was swept")
	}
	var stamp string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&stamp); err != nil {
		t.Fatalf("read sweep timestamp: %v", err)
	}
	if stamp == jsonQuote(time.Now().UTC().Format(time.RFC3339)) {
		t.Error("sweep timestamp advanced despite the write fault")
	}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
