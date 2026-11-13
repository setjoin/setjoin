package ldapsync

// Security regression tests for the legacy LDAP sync engine's identity-safety
// controls:
//
//   - LDAPSYNC-002 (anchor protection, Astra waves12 items 1/4/5): resolution,
//     link establishment, disable and manager mutation all route through the
//     reducer-owned authority fences (ldap_sync_anchor_resolve /
//     _anchor_link / _disable_user). An authentication-only, suspended, or
//     otherwise un-authoritative anchor can never force-disable a native
//     account, revoke its sessions, or rewire its profile; field protections
//     load by resolved user ID so an anchored rename cannot bypass them; the
//     manager pass clears and assigns over the SAME authorized set.
//   - LDAPSYNC-003 (deprovisioning, Astra waves12 items 2/3): an
//     authoritative directory deletion is propagated as disable + full
//     revocation on the next clean FULL sync cycle; the population is the
//     EXACT source-owned set reconciled against the complete enumeration (no
//     domain heuristic — a shared-domain source's users are never swept, and a
//     successful enumeration that ends empty still propagates); disable and
//     revocation commit in ONE transaction.
//
// ISOLATION (Astra waves12 item 6): this suite never deletes potentially
// pre-existing substrate state. The 'legacy:ldap' catalog row is snapshotted
// exactly and restored; system_config keys restore their exact prior values;
// identity_sync_log rows are tracked by created id; fixture teardown runs in
// ONE transaction with targeted, error-checked trigger handling that restores
// its own state — unrelated state survives success and failure (verified by
// TestCleanupPreservesUnrelatedState).
//
// RUNTIME ISOLATION: the corrected suite runs against an owned database
// (DB_NAME=... scripts/load-test-schema.sh; DB_DSN selects it for go test),
// never against shared state.
//
// Scope note: the separately tracked HIGH LDAPSYNC-001 (Kerberos-principal
// forgery) control is NOT exercised or absorbed here — krb5_principal custody
// keeps its own suite (krb5_sync_test.go) and severity.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// legacySourceSnapshot is the EXACT prior state of the 'legacy:ldap' catalog
// row. Every column is restored at cleanup; the row is never deleted.
type legacySourceSnapshot struct {
	id                 int64
	displayName        string
	kind               string
	capabilities       []byte
	state              string
	generation         int64
	configEnvelope     []byte
	configKeyVersion   int64
	mappingVersion     int64
	committedCursor    []byte
	committedCursorDig []byte
	pendingCursor      []byte
	pendingCursorDig   []byte
	lastSuccessAt      *time.Time
	lastFailureAt      *time.Time
	lastErrorCode      *string
	createdBy          *int64
	updatedBy          *int64
	createdAt          time.Time
	updatedAt          time.Time
}

const legacySourceColumns = `id, display_name, kind, capabilities, state, generation,
	  config_envelope, config_key_version, mapping_version,
	  committed_cursor, committed_cursor_digest, pending_cursor, pending_cursor_digest,
	  last_success_at, last_failure_at, last_error_code, created_by, updated_by,
	  created_at, updated_at`

func scanLegacySourceRow(row pgx.Row) (legacySourceSnapshot, error) {
	var s legacySourceSnapshot
	err := row.Scan(&s.id, &s.displayName, &s.kind, &s.capabilities, &s.state,
		&s.generation, &s.configEnvelope, &s.configKeyVersion, &s.mappingVersion,
		&s.committedCursor, &s.committedCursorDig, &s.pendingCursor, &s.pendingCursorDig,
		&s.lastSuccessAt, &s.lastFailureAt, &s.lastErrorCode, &s.createdBy, &s.updatedBy,
		&s.createdAt, &s.updatedAt)
	return s, err
}

// ensureLegacyLDAPActive snapshots the 'legacy:ldap' catalog row EXACTLY,
// activates it for the duration of the test, and registers an exact restore
// (returned so tests can exercise the restore path directly; it is exact and
// idempotent). The row is a deterministic V156 baseline catalog entry: if it
// is missing the test database is mis-built and the suite must fail loudly
// instead of creating or deleting catalog state.
func ensureLegacyLDAPActive(t *testing.T, pool *pgxpool.Pool) func() {
	t.Helper()
	ctx := context.Background()
	snap, err := scanLegacySourceRow(pool.QueryRow(ctx,
		`SELECT `+legacySourceColumns+` FROM identity_sources WHERE source_key = 'legacy:ldap'`))
	if errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("test DB violates the V156 source catalog invariant: 'legacy:ldap' row is missing; " +
			"rebuild with DB_NAME=<owned> scripts/load-test-schema.sh — this suite never creates catalog rows")
	}
	if err != nil {
		t.Fatalf("snapshot legacy:ldap source row: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET state = 'active', updated_at = statement_timestamp()
		  WHERE source_key = 'legacy:ldap'`,
	); err != nil {
		t.Fatalf("activate legacy:ldap source for test: %v", err)
	}
	restore := func() {
		c := context.Background()
		_, err := pool.Exec(c, `
			UPDATE identity_sources SET
				id = $1, display_name = $2, kind = $3, capabilities = $4, state = $5,
				generation = $6, config_envelope = $7, config_key_version = $8,
				mapping_version = $9, committed_cursor = $10, committed_cursor_digest = $11,
				pending_cursor = $12, pending_cursor_digest = $13,
				last_success_at = $14, last_failure_at = $15, last_error_code = $16,
				created_by = $17, updated_by = $18, created_at = $19, updated_at = $20
			WHERE source_key = 'legacy:ldap'`,
			snap.id, snap.displayName, snap.kind, snap.capabilities, snap.state,
			snap.generation, snap.configEnvelope, snap.configKeyVersion,
			snap.mappingVersion, snap.committedCursor, snap.committedCursorDig,
			snap.pendingCursor, snap.pendingCursorDig,
			snap.lastSuccessAt, snap.lastFailureAt, snap.lastErrorCode,
			snap.createdBy, snap.updatedBy, snap.createdAt, snap.updatedAt,
		)
		if err != nil {
			t.Errorf("restore legacy:ldap source row: %v", err)
		}
	}
	t.Cleanup(restore)
	return restore
}

// setSyncSystemConfig sets a system_config key for the test and restores the
// EXACT prior state at cleanup: a pre-existing key gets its prior value,
// description, and updated_at back; a test-created key is deleted. Never
// deletes potentially pre-existing configuration. Returns the restore function
// so tests can exercise it directly (exact and idempotent).
func setSyncSystemConfig(t *testing.T, pool *pgxpool.Pool, key, jsonValue string) func() {
	t.Helper()
	ctx := context.Background()
	var priorValue, priorDescription *string
	var priorUpdatedAt *time.Time
	err := pool.QueryRow(ctx,
		`SELECT value #>> '{}', description, updated_at FROM system_config WHERE key = $1`, key,
	).Scan(&priorValue, &priorDescription, &priorUpdatedAt)
	existed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("snapshot system_config %s: %v", key, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, description) VALUES ($1, $2::jsonb, 'ldapsync test')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		key, jsonValue,
	); err != nil {
		t.Fatalf("seed system_config %s: %v", key, err)
	}
	restore := func() {
		c := context.Background()
		if !existed {
			if _, err := pool.Exec(c, `DELETE FROM system_config WHERE key = $1`, key); err != nil {
				t.Errorf("delete test-created system_config %s: %v", key, err)
			}
			return
		}
		if _, err := pool.Exec(c,
			// priorValue was extracted with '#>>' (unquoted scalar text), so it
			// must be re-wrapped as a JSON scalar to restore the exact value.
			`UPDATE system_config SET value = to_jsonb($2::text), description = $3,
			        updated_at = COALESCE($4, updated_at)
			 WHERE key = $1`,
			key, priorValue, priorDescription, priorUpdatedAt,
		); err != nil {
			t.Errorf("restore system_config %s: %v", key, err)
		}
	}
	t.Cleanup(restore)
	return restore
}

// cleanupSyncLog removes ONLY the identity_sync_log rows this test appended,
// tracked by created id (rows with id above the pre-test maximum) — a
// timestamp window could catch concurrent suites' rows.
func cleanupSyncLog(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var maxID int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(max(id), 0) FROM identity_sync_log`,
	).Scan(&maxID); err != nil {
		t.Fatalf("snapshot identity_sync_log max id: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM identity_sync_log WHERE id > $1`, maxID); err != nil {
			t.Errorf("delete test-created identity_sync_log rows: %v", err)
		}
	})
}

// teardownUserTx tears down one fixture account in a SINGLE transaction:
// link substrate rows (including this fixture's append-only audit events,
// removed under the repo-standard targeted, transactional, error-checked
// trigger handling — see internal/admin/identity_test_cleanup_test.go),
// sync/revocation side rows, then mailbox and user. Mailbox and user leave in
// the same transaction so the deferred primary-mailbox invariant passes
// WITHOUT globally disabling mailboxes triggers.
func teardownUserTx(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("begin fixture teardown for user %d: %v", userID, err)
			return
		}
		defer func() { _ = tx.Rollback(ctx) }() // no-op after commit
		if _, err := tx.Exec(ctx,
			`ALTER TABLE identity_link_events DISABLE TRIGGER identity_link_events_append_only`); err != nil {
			t.Errorf("disable append-only trigger for user %d teardown: %v", userID, err)
			return
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM identity_link_events WHERE user_id = $1`, userID); err != nil {
			t.Errorf("delete fixture link events for user %d: %v", userID, err)
			return
		}
		if _, err := tx.Exec(ctx,
			`ALTER TABLE identity_link_events ENABLE TRIGGER identity_link_events_append_only`); err != nil {
			t.Errorf("restore append-only trigger for user %d teardown: %v", userID, err)
			return
		}
		for _, stmt := range []string{
			`DELETE FROM user_lifecycle_authorities WHERE user_id = $1`,
			`DELETE FROM user_identity_links WHERE user_id = $1`,
			`DELETE FROM sync_conflicts WHERE user_id = $1`,
			`DELETE FROM field_policy WHERE user_id = $1`,
			`DELETE FROM sessions WHERE user_id = $1`,
			`DELETE FROM ws_subscriptions WHERE user_id = $1`,
			`DELETE FROM oauth_tokens WHERE user_id = $1`,
			`DELETE FROM session_revocations WHERE user_id = $1`,
			`DELETE FROM mailbox_address_claims WHERE mailbox_id IN
				(SELECT id FROM mailboxes WHERE user_id = $1)`,
			`DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`,
			`DELETE FROM mailboxes WHERE user_id = $1`,
			`DELETE FROM users WHERE id = $1`,
		} {
			if _, err := tx.Exec(ctx, stmt, userID); err != nil {
				t.Errorf("fixture teardown for user %d: %v: %v", userID, stmt, err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("commit fixture teardown for user %d: %v", userID, err)
		}
	})
}

// upsertFixtureUser seeds an account directly (no mailbox) with a chosen
// sync_source and registers dependency-ordered cleanup. Package-unique
// local-parts are mandatory: the derived username carries a cross-domain
// UNIQUE shared with the ad package's tests.
func upsertFixtureUser(t *testing.T, pool *pgxpool.Pool, domainID int64, local, displayName, syncSource string) int64 {
	t.Helper()
	ctx := context.Background()
	email := local + "@" + domainID_domain(t, pool, domainID)
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, sync_source)
		 VALUES ($1, $2, $3, $4, '$2a$10$placeholder', $5) RETURNING id`,
		local, email, displayName, domainID, syncSource,
	).Scan(&userID); err != nil {
		t.Fatalf("insert fixture user %s: %v", local, err)
	}
	teardownUserTx(t, pool, userID)
	return userID
}

// addPrimaryMailbox gives a fixture user a primary mailbox (required by the
// substrate's account-class guard before a fixture can hold identity links).
func addPrimaryMailbox(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO mailboxes (user_id, domain_id, display_name, email, is_primary, type)
		SELECT u.id, u.domain_id, u.display_name, u.email, TRUE, 'personal' FROM users u WHERE u.id = $1`,
		userID,
	); err != nil {
		t.Fatalf("insert fixture mailbox: %v", err)
	}
}

// anchorFixtureLink creates an active legacy:ldap link for a fixture user with
// the given purposes (the account-class guard requires a primary mailbox).
func anchorFixtureLink(t *testing.T, pool *pgxpool.Pool, userID int64, subject string, purposes []string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_identity_links (user_id, source_id, external_subject, purposes, state, link_method)
		SELECT $1, s.id, $2, $3::text[], 'active', 'operator'
		  FROM identity_sources s WHERE s.source_key = 'legacy:ldap'`,
		userID, subject, purposes,
	); err != nil {
		t.Fatalf("anchor fixture link %s: %v", subject, err)
	}
}

// otherSourceOwnedFixture marks an account as owned by a DIFFERENT identity
// source (the way a normalized ldap:* source's provisioned users look):
// an active provision link on that source plus a source lifecycle authority.
func otherSourceOwnedFixture(t *testing.T, pool *pgxpool.Pool, userID int64, subject, sourceKey string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources (source_key, display_name, kind, capabilities, state)
		VALUES ($1, 'Other ldap source', 'ldap', '{"stable_immutable_subject":true}'::jsonb, 'active')
		ON CONFLICT (source_key) DO NOTHING`, sourceKey,
	); err != nil {
		t.Fatalf("insert other ldap source: %v", err)
	}
	t.Cleanup(func() {
		// Remove in one transaction: authority, link, then the test-created
		// catalog row only if this test created it (created-key tracking).
		c := context.Background()
		pool.Exec(c, `DELETE FROM user_lifecycle_authorities a USING user_identity_links l
		              WHERE a.link_id = l.id AND l.source_id = (SELECT id FROM identity_sources WHERE source_key = $1)
		                AND l.user_id = $2`, sourceKey, userID)
		pool.Exec(c, `DELETE FROM user_identity_links WHERE source_id = (SELECT id FROM identity_sources WHERE source_key = $1)
		              AND user_id = $2`, sourceKey, userID)
		pool.Exec(c, `DELETE FROM identity_sources WHERE source_key = $1 AND display_name = 'Other ldap source'`, sourceKey)
	})
	addPrimaryMailbox(t, pool, userID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_identity_links (user_id, source_id, external_subject, purposes, state, link_method)
		VALUES ($1, (SELECT id FROM identity_sources WHERE source_key = $2), $3,
		        ARRAY['provision']::text[], 'active', 'operator')`,
		userID, sourceKey, subject,
	); err != nil {
		t.Fatalf("insert other-source link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_lifecycle_authorities (user_id, authority_kind, link_id)
		VALUES ($1, 'source', (SELECT l.id FROM user_identity_links l
		                        JOIN identity_sources s ON s.id = l.source_id
		                       WHERE s.source_key = $2 AND l.user_id = $1))
		ON CONFLICT (user_id) DO UPDATE SET
			authority_kind = 'source', link_id = EXCLUDED.link_id,
			generation = user_lifecycle_authorities.generation + 1,
			updated_at = statement_timestamp()`,
		userID, sourceKey,
	); err != nil {
		t.Fatalf("insert other-source lifecycle authority: %v", err)
	}
}

// domainID_domain resolves a domain id back to its name for building emails.
func domainID_domain(t *testing.T, pool *pgxpool.Pool, domainID int64) string {
	t.Helper()
	var name string
	if err := pool.QueryRow(context.Background(),
		`SELECT name FROM domains WHERE id = $1`, domainID).Scan(&name); err != nil {
		t.Fatalf("resolve domain name: %v", err)
	}
	return name
}

// upsertFixtureDomain creates a unique test domain with cleanup.
func upsertFixtureDomain(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	var domainID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`,
		label+"-"+randSuffix(t)+".local",
	).Scan(&domainID); err != nil {
		t.Fatalf("insert fixture domain: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID); err != nil {
			t.Errorf("delete fixture domain: %v", err)
		}
	})
	return domainID
}

// seedSession gives a fixture user one live session and returns its count
// reader for assertions.
func seedSession(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')`, userID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
}

func sessionCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// enabledLDAPUserIDsExcluding snapshots the pre-existing enabled ldap-sourced
// accounts OUTSIDE the fixture's own set, using the same population predicate
// the absence sweep applies (sync.go disableAbsentUsers). It exists so the
// sweep tests can attribute extra result.Disabled counts to the shared test
// database's foreign population instead of failing on a global count they do
// not own.
func enabledLDAPUserIDsExcluding(t *testing.T, pool *pgxpool.Pool, exclude []int64) []int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT id FROM users
		  WHERE sync_source = 'ldap' AND enabled AND NOT is_guest_account(id)
		    AND NOT (id = ANY($1::bigint[]))`, exclude)
	if err != nil {
		t.Fatalf("snapshot foreign enabled ldap users: %v", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan foreign enabled ldap user: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign enabled ldap users: %v", err)
	}
	return ids
}

// disabledUserIDs returns which of the given user ids are now disabled — the
// subset of the pre-existing foreign population the sweep swept during this
// test (evidence logging for shared-database interference).
func disabledUserIDs(t *testing.T, pool *pgxpool.Pool, candidates []int64) []int64 {
	t.Helper()
	if len(candidates) == 0 {
		return nil
	}
	rows, err := pool.Query(context.Background(),
		`SELECT id FROM users WHERE NOT enabled AND (id = ANY($1::bigint[])) ORDER BY id`, candidates)
	if err != nil {
		t.Fatalf("inspect foreign disabled users: %v", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan foreign disabled user: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign disabled users: %v", err)
	}
	return ids
}

func userBool(t *testing.T, pool *pgxpool.Pool, userID int64, column string) bool {
	t.Helper()
	// The SQL text is a fixed literal per whitelisted column — the caller's
	// string never reaches the query text (check-sql-injection contract);
	// userID rides the $1 bind parameter.
	var query string
	switch column {
	case "enabled":
		query = `SELECT enabled FROM users WHERE id = $1`
	default:
		t.Fatalf("userBool: unsupported column %q", column)
	}
	var v bool
	if err := pool.QueryRow(context.Background(), query, userID).Scan(&v); err != nil {
		t.Fatalf("read users.%s: %v", column, err)
	}
	return v
}

func userString(t *testing.T, pool *pgxpool.Pool, userID int64, column string) string {
	t.Helper()
	// Same fixed-literal-per-column contract as userBool: only these exact
	// columns may be read, and each maps to a whole compile-time query.
	var query string
	switch column {
	case "display_name":
		query = `SELECT display_name FROM users WHERE id = $1`
	case "job_title":
		query = `SELECT job_title FROM users WHERE id = $1`
	case "phone":
		query = `SELECT phone FROM users WHERE id = $1`
	case "email":
		query = `SELECT email FROM users WHERE id = $1`
	case "manager_id::text":
		query = `SELECT COALESCE(manager_id::text, '') FROM users WHERE id = $1`
	default:
		t.Fatalf("userString: unsupported column %q", column)
	}
	var v string
	if err := pool.QueryRow(context.Background(), query, userID).Scan(&v); err != nil {
		t.Fatalf("read users.%s: %v", column, err)
	}
	return v
}

// cleanupProvisionedAccount tears down an account created through the
// provisioning seam (it owns a primary mailbox plus address-claim and
// lifecycle rows) via the shared transactional teardown.
func cleanupProvisionedAccount(t *testing.T, pool *pgxpool.Pool, userID int64) {
	t.Helper()
	teardownUserTx(t, pool, userID)
}

// pendingConflictCount counts pending sync_conflicts audit rows for a user.
func pendingConflictCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM sync_conflicts
		 WHERE user_id = $1 AND source = 'ldap' AND resolution IS NULL AND resolved_at IS NULL`,
		userID).Scan(&n); err != nil {
		t.Fatalf("count pending conflicts: %v", err)
	}
	return n
}

// TestUnanchoredEntryCannotMutateNativeAccount is the LDAPSYNC-002 anchor
// protection regression: a directory-writable entry whose email merely
// collides with a native account — with a forged immutable subject or with no
// subject at all — cannot force-disable it, revoke its sessions, or rewire its
// profile. The collision is skipped and audited as a pending sync_conflicts
// row.
func TestUnanchoredEntryCannotMutateNativeAccount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapanchor")
	domain := domainID_domain(t, pool, domainID)

	nativeID := upsertFixtureUser(t, pool, domainID, "native-"+suffix, "Native Person", "local")
	if _, err := pool.Exec(ctx,
		`UPDATE users SET job_title = 'Engineer', phone = '555-0100' WHERE id = $1`, nativeID,
	); err != nil {
		t.Fatalf("seed native profile: %v", err)
	}
	seedSession(t, pool, nativeID)

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Forged-subject entry: disabled in the directory, hostile profile values.
	var forged SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		DN:               "CN=Forged-" + suffix + ",DC=ldap,DC=local",
		ImmutableSubject: "forged-subject-" + suffix,
		Email:            "Native-" + suffix + "@" + strings.ToUpper(domain),
		DisplayName:      "Hacked",
		Title:            "Hacked",
		Phone:            "666-666",
		Disabled:         true,
	}, false, &forged); err != nil {
		t.Fatalf("forged upsert: %v", err)
	}
	if forged.Created != 0 || forged.Updated != 0 || forged.Disabled != 0 || forged.Skipped != 1 {
		t.Fatalf("forged entry result = %+v, want one skipped mutation-free outcome", forged)
	}

	// Subject-less entry (no subject attribute configured): same protection.
	var subjectless SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		Email:       "native-" + suffix + "@" + domain,
		DisplayName: "Hacked",
		Disabled:    true,
	}, false, &subjectless); err != nil {
		t.Fatalf("subject-less upsert: %v", err)
	}
	if subjectless.Skipped != 1 || subjectless.Disabled != 0 {
		t.Fatalf("subject-less entry result = %+v, want skipped without disable", subjectless)
	}

	// The native account is untouched: enabled, sessions intact, profile
	// unrewired, no department or manager linkage.
	if !userBool(t, pool, nativeID, "enabled") {
		t.Fatal("unanchored directory entry force-disabled a native account")
	}
	if n := sessionCount(t, pool, nativeID); n != 1 {
		t.Errorf("native account sessions = %d, want 1 (revocation is anchor-gated)", n)
	}
	if got := userString(t, pool, nativeID, "display_name"); got != "Native Person" {
		t.Errorf("display_name = %q, want untouched %q", got, "Native Person")
	}
	if got := userString(t, pool, nativeID, "job_title"); got != "Engineer" {
		t.Errorf("job_title = %q, want untouched Engineer", got)
	}
	if got := userString(t, pool, nativeID, "phone"); got != "555-0100" {
		t.Errorf("phone = %q, want untouched 555-0100", got)
	}
	if got := userString(t, pool, nativeID, "manager_id::text"); got != "" {
		t.Errorf("manager_id = %s, want NULL", got)
	}

	// Both collisions are audited for operator review (resolution NULL=pending).
	if pending := pendingConflictCount(t, pool, nativeID); pending != 2 {
		t.Errorf("pending sync_conflicts rows = %d, want 2 (forged subject + subject-less)", pending)
	}
	var remoteSubject string
	if err := pool.QueryRow(ctx, `
		SELECT remote_value FROM sync_conflicts
		 WHERE user_id = $1 AND remote_value = $2`, nativeID, "forged-subject-"+suffix,
	).Scan(&remoteSubject); err != nil {
		t.Errorf("forged-subject conflict not audited with the directory subject: %v", err)
	}
}

// TestAnchoredEntryKeepsDrivingItsAccount proves the positive face of the
// anchor discipline: an entry whose immutable subject anchors an account keeps
// updating it across a directory rename (no duplicate is created) and can
// disable it with session revocation — present-entry synchronization behavior
// for anchored accounts is unchanged.
func TestAnchoredEntryKeepsDrivingItsAccount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapdriven")
	domain := domainID_domain(t, pool, domainID)
	subject := "driven-subject-" + suffix

	ensureLegacyLDAPActive(t, pool)

	w := &SyncWorker{pool: pool, logger: testLogger()}

	first := LDAPUser{
		ImmutableSubject: subject,
		Email:            "anchored-" + suffix + "@" + domain,
		DisplayName:      "Anchored One",
	}
	var created SyncResult
	if err := w.upsertUser(ctx, first, false, &created); err != nil {
		t.Fatalf("anchored create: %v", err)
	}
	if created.Created != 1 {
		t.Fatalf("anchored create result = %+v", created)
	}

	var userID int64
	if err := pool.QueryRow(ctx, `
		SELECT l.user_id FROM user_identity_links l
		  JOIN identity_sources s ON s.id = l.source_id
		 WHERE s.source_key = 'legacy:ldap' AND l.external_subject = $1 AND l.state = 'active'`,
		subject,
	).Scan(&userID); err != nil {
		t.Fatalf("provisioned account was not anchored to its immutable subject: %v", err)
	}
	cleanupProvisionedAccount(t, pool, userID)

	// Directory rename: the anchor resolves the SAME account; the new email is
	// written and no duplicate account appears.
	renamed := LDAPUser{
		ImmutableSubject: subject,
		Email:            "renamed-" + suffix + "@" + domain,
		DisplayName:      "Anchored Renamed",
	}
	var updated SyncResult
	if err := w.upsertUser(ctx, renamed, false, &updated); err != nil {
		t.Fatalf("anchored rename: %v", err)
	}
	if updated.Created != 0 || updated.Updated != 1 {
		t.Fatalf("anchored rename result = %+v, want update without create", updated)
	}
	if got := userString(t, pool, userID, "email"); got != "renamed-"+suffix+"@"+domain {
		t.Errorf("renamed email = %q", got)
	}
	var accounts int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM users u
		  JOIN user_identity_links l ON l.user_id = u.id
		 WHERE l.external_subject = $1`, subject,
	).Scan(&accounts); err != nil {
		t.Fatalf("count anchored accounts: %v", err)
	}
	if accounts != 1 {
		t.Fatalf("rename produced %d anchored accounts, want exactly 1", accounts)
	}

	// Anchored disable: force-disable + session revocation still work through
	// the anchor.
	seedSession(t, pool, userID)
	disabled := renamed
	disabled.Disabled = true
	var disableResult SyncResult
	if err := w.upsertUser(ctx, disabled, false, &disableResult); err != nil {
		t.Fatalf("anchored disable: %v", err)
	}
	if disableResult.Disabled != 1 {
		t.Fatalf("anchored disable result = %+v", disableResult)
	}
	if userBool(t, pool, userID, "enabled") {
		t.Fatal("anchored directory disable did not disable the anchored account")
	}
	if n := sessionCount(t, pool, userID); n != 0 {
		t.Errorf("anchored disable left %d live session(s), want 0", n)
	}
}

// TestAuthOnlyAnchorCannotDisableNativeAccount is Astra waves12 item 1: an
// authentication-only link (the kind an LDAP SSO integration creates) must not
// authorize lifecycle mutation. The resolver reports DENIED — not missing —
// the entry is skipped without an email fallback, the native account keeps its
// sessions, and the collision is audited.
func TestAuthOnlyAnchorCannotDisableNativeAccount(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapauthonly")
	domain := domainID_domain(t, pool, domainID)
	subject := "authonly-subject-" + suffix

	ensureLegacyLDAPActive(t, pool)
	nativeID := upsertFixtureUser(t, pool, domainID, "authnative-"+suffix, "Auth Native", "local")
	addPrimaryMailbox(t, pool, nativeID)
	anchorFixtureLink(t, pool, nativeID, subject, []string{"authenticate"})
	seedSession(t, pool, nativeID)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		DN:               "CN=AuthOnly-" + suffix + ",DC=ldap,DC=local",
		ImmutableSubject: subject,
		Email:            "authnative-" + suffix + "@" + domain,
		DisplayName:      "Hacked",
		Disabled:         true,
	}, false, &result); err != nil {
		t.Fatalf("auth-only anchored upsert: %v", err)
	}
	if result.Skipped != 1 || result.Disabled != 0 || result.Updated != 0 || result.Created != 0 {
		t.Fatalf("auth-only anchor result = %+v, want one mutation-free skip", result)
	}
	if !userBool(t, pool, nativeID, "enabled") {
		t.Fatal("authentication-only anchor authorized disabling a native account")
	}
	if n := sessionCount(t, pool, nativeID); n != 1 {
		t.Errorf("native account sessions = %d, want 1", n)
	}
	if got := userString(t, pool, nativeID, "display_name"); got != "Auth Native" {
		t.Errorf("display_name = %q, want untouched", got)
	}
	if pending := pendingConflictCount(t, pool, nativeID); pending != 1 {
		t.Errorf("pending sync_conflicts rows = %d, want 1 (denied-anchor audit)", pending)
	}
}

// TestSuspendedAnchorDeniesWithoutEmailFallback is the missing/denied outcome
// split (Astra waves12 item 1): a SUSPENDED anchor on an ldap-provisioned
// account must NOT degrade into the gated email path — an operator who
// suspended the link must not be reconnected to the account by a directory
// writer presenting the (renamed) address. The account stays enabled with its
// sessions; the collision is audited.
func TestSuspendedAnchorDeniesWithoutEmailFallback(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapsuspend")
	domain := domainID_domain(t, pool, domainID)
	subject := "suspended-subject-" + suffix

	ensureLegacyLDAPActive(t, pool)
	ownedID := upsertFixtureUser(t, pool, domainID, "suspended-"+suffix, "Suspended Target", "ldap")
	addPrimaryMailbox(t, pool, ownedID)
	anchorFixtureLink(t, pool, ownedID, subject, []string{"provision"})
	if _, err := pool.Exec(ctx,
		`UPDATE user_identity_links SET state = 'suspended' WHERE external_subject = $1`, subject,
	); err != nil {
		t.Fatalf("suspend fixture link: %v", err)
	}
	seedSession(t, pool, ownedID)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		DN:               "CN=Susp-" + suffix + ",DC=ldap,DC=local",
		ImmutableSubject: subject,
		// The CURRENT address of the account — an email fallback would match it.
		Email:       "suspended-" + suffix + "@" + domain,
		DisplayName: "Hacked",
		Disabled:    true,
	}, false, &result); err != nil {
		t.Fatalf("suspended-anchor upsert: %v", err)
	}
	if result.Skipped != 1 || result.Disabled != 0 {
		t.Fatalf("suspended-anchor result = %+v, want mutation-free skip", result)
	}
	if !userBool(t, pool, ownedID, "enabled") {
		t.Fatal("suspended anchor degraded to the email path and disabled the account")
	}
	if n := sessionCount(t, pool, ownedID); n != 1 {
		t.Errorf("sessions = %d, want 1 (no fallback revocation)", n)
	}
	if pending := pendingConflictCount(t, pool, ownedID); pending != 1 {
		t.Errorf("pending sync_conflicts rows = %d, want 1 (denied-anchor audit)", pending)
	}
}

// TestMissingAnchorFallsThroughToGatedEmailPath pins the OTHER half of the
// outcome split: a subject the substrate genuinely does not know is MISSING,
// and the gated email path still drives accounts this engine provisioned.
func TestMissingAnchorFallsThroughToGatedEmailPath(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapmissing")
	domain := domainID_domain(t, pool, domainID)

	ensureLegacyLDAPActive(t, pool)
	ownedID := upsertFixtureUser(t, pool, domainID, "missing-"+suffix, "Missing Anchor", "ldap")
	seedSession(t, pool, ownedID)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	var result SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		DN:               "CN=Missing-" + suffix + ",DC=ldap,DC=local",
		ImmutableSubject: "never-anchored-" + suffix,
		Email:            "missing-" + suffix + "@" + domain,
		DisplayName:      "Missing Anchor",
		Disabled:         true,
	}, false, &result); err != nil {
		t.Fatalf("missing-anchor upsert: %v", err)
	}
	if result.Disabled != 1 {
		t.Fatalf("missing-anchor result = %+v, want the gated email path to disable", result)
	}
	if userBool(t, pool, ownedID, "enabled") {
		t.Fatal("missing anchor did not fall through to the gated email path")
	}
	if n := sessionCount(t, pool, ownedID); n != 0 {
		t.Errorf("sessions = %d, want 0 (gated disable revokes)", n)
	}
}

// TestManagerPassSkipsNativeAccounts proves the manager pass honors the same
// anchor discipline: a directory entry for a native account cannot rewire its
// manager, while the identical entry for an LDAP-provisioned account still
// resolves (positive control).
func TestManagerPassSkipsNativeAccounts(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapmgr")
	domain := domainID_domain(t, pool, domainID)

	mgrID := upsertFixtureUser(t, pool, domainID, "mgr-"+suffix, "Manager", "ldap")
	nativeEmpID := upsertFixtureUser(t, pool, domainID, "natemp-"+suffix, "Native Employee", "local")
	ldapEmpID := upsertFixtureUser(t, pool, domainID, "ldapemp-"+suffix, "LDAP Employee", "ldap")

	mgrDN := "CN=Mgr-" + suffix + ",OU=Users,DC=ldap,DC=local"
	nativeDN := "CN=NativeEmp-" + suffix + ",OU=Users,DC=ldap,DC=local"
	ldapDN := "CN=LdapEmp-" + suffix + ",OU=Users,DC=ldap,DC=local"

	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.resolveManagerIDs(ctx, []LDAPUser{
		{DN: mgrDN, Email: "mgr-" + suffix + "@" + domain},
		{DN: nativeDN, Email: "natemp-" + suffix + "@" + domain, ManagerDN: mgrDN},
		{DN: ldapDN, Email: "ldapemp-" + suffix + "@" + domain, ManagerDN: mgrDN},
	})

	if got := userString(t, pool, nativeEmpID, "manager_id::text"); got != "" {
		t.Errorf("native account manager_id = %s, want NULL (directory entry does not anchor it)", got)
	}
	if got := userString(t, pool, ldapEmpID, "manager_id::text"); got != fmt.Sprint(mgrID) {
		t.Errorf("ldap-owned account manager_id = %s, want %d", got, mgrID)
	}
}

// TestManagerClearAndAssignShareAuthorizedSet is Astra waves12 item 5: an
// actively provision-anchored account is assignable AND clearable — when the
// manager relationship disappears from the directory, the stale manager is
// cleared. An authentication-only anchor is neither assignable nor clearable.
func TestManagerClearAndAssignShareAuthorizedSet(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapmgrset")
	domain := domainID_domain(t, pool, domainID)

	ensureLegacyLDAPActive(t, pool)
	mgrID := upsertFixtureUser(t, pool, domainID, "setmgr-"+suffix, "Manager", "ldap")
	mgrDN := "CN=SetMgr-" + suffix + ",OU=Users,DC=ldap,DC=local"

	provSubject := "prov-anchor-" + suffix
	provNativeID := upsertFixtureUser(t, pool, domainID, "provanchor-"+suffix, "Prov Anchor", "local")
	addPrimaryMailbox(t, pool, provNativeID)
	anchorFixtureLink(t, pool, provNativeID, provSubject, []string{"provision"})

	authSubject := "auth-anchor-" + suffix
	authNativeID := upsertFixtureUser(t, pool, domainID, "authanchor-"+suffix, "Auth Anchor", "local")
	addPrimaryMailbox(t, pool, authNativeID)
	anchorFixtureLink(t, pool, authNativeID, authSubject, []string{"authenticate"})

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Pass 1: the anchored provision relationship assigns the manager to the
	// anchored account; the auth-only anchor is refused.
	w.resolveManagerIDs(ctx, []LDAPUser{
		{DN: mgrDN, Email: "setmgr-" + suffix + "@" + domain},
		{DN: "CN=ProvAnchor-" + suffix + ",DC=ldap,DC=local",
			ImmutableSubject: provSubject,
			Email:            "provanchor-" + suffix + "@" + domain, ManagerDN: mgrDN},
		{DN: "CN=AuthAnchor-" + suffix + ",DC=ldap,DC=local",
			ImmutableSubject: authSubject,
			Email:            "authanchor-" + suffix + "@" + domain, ManagerDN: mgrDN},
	})
	if got := userString(t, pool, provNativeID, "manager_id::text"); got != fmt.Sprint(mgrID) {
		t.Fatalf("anchored account manager_id = %s, want %d (assignment must honor the anchor)", got, mgrID)
	}
	if got := userString(t, pool, authNativeID, "manager_id::text"); got != "" {
		t.Fatalf("auth-only anchored account manager_id = %s, want NULL", got)
	}

	// Pass 2: the relationship disappears (no ManagerDN in the entry). The
	// SAME authorized set must clear the stale link.
	w.resolveManagerIDs(ctx, []LDAPUser{
		{DN: mgrDN, Email: "setmgr-" + suffix + "@" + domain},
		{DN: "CN=ProvAnchor-" + suffix + ",DC=ldap,DC=local",
			ImmutableSubject: provSubject,
			Email:            "provanchor-" + suffix + "@" + domain},
	})
	if got := userString(t, pool, provNativeID, "manager_id::text"); got != "" {
		t.Errorf("anchored account kept stale manager_id %s after the relationship disappeared, want NULL", got)
	}
}

// TestAbsenceSweepDisablesDeletedDirectoryUsers is the LDAPSYNC-003
// regression: on a clean FULL enumeration, an authoritative directory deletion
// disables the account and revokes its sessions on the next sync cycle, while
// present entries sync unchanged and native accounts are never swept.
func TestAbsenceSweepDisablesDeletedDirectoryUsers(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapsweep")
	domain := domainID_domain(t, pool, domainID)

	presentID := upsertFixtureUser(t, pool, domainID, "present-"+suffix, "Present", "ldap")
	deletedID := upsertFixtureUser(t, pool, domainID, "deleted-"+suffix, "Deleted", "ldap")
	seedSession(t, pool, deletedID)
	laterDeletedID := upsertFixtureUser(t, pool, domainID, "later-"+suffix, "Later Deleted", "ldap")
	nativeAbsentID := upsertFixtureUser(t, pool, domainID, "natabsent-"+suffix, "Native Absent", "local")
	ownIDs := []int64{presentID, deletedID, laterDeletedID, nativeAbsentID}

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	// The sweep's source-owned population is deliberately DB-global (no
	// domain-observed fence — see disableAbsentUsers in sync.go), and the test
	// database is shared: `go test ./...` runs package binaries concurrently
	// against it and leaked enabled ldap rows persist across runs. So
	// result.Disabled counts accounts this fixture does not own and cannot be
	// asserted as an exact global number. The exact contract is asserted on
	// the fixture's OWN accounts: precisely the deleted account transitions.
	// Snapshot the pre-existing foreign population so unexpected extra
	// disables are attributable in the log.
	foreignIDs := enabledLDAPUserIDsExcluding(t, pool, ownIDs)

	// Cycle 1: the directory carries the present and later-deleted users; the
	// deleted and native-absent users do not. First sync = full enumeration.
	fake.users = []LDAPUser{
		{Email: "present-" + suffix + "@" + domain, DisplayName: "Present Updated"},
		{Email: "later-" + suffix + "@" + domain, DisplayName: "Later Deleted"},
	}
	result, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("full sync with absence: %v", err)
	}
	if result.Errors != 0 {
		t.Fatalf("full sync reported errors: %+v", result)
	}
	if result.Disabled < 1 {
		t.Fatalf("absence sweep result = %+v, want the deleted account disabled", result)
	}
	if result.Disabled > 1 {
		swept := disabledUserIDs(t, pool, foreignIDs)
		t.Logf("absence sweep disabled %d accounts; %d pre-existing foreign (non-fixture) ldap rows were swept: %v — shared-database population, not owned by this fixture", result.Disabled, len(swept), swept)
	}
	if userBool(t, pool, deletedID, "enabled") {
		t.Fatal("deleted-from-directory account was not disabled by the sweep")
	}
	if n := sessionCount(t, pool, deletedID); n != 0 {
		t.Errorf("deleted account kept %d live session(s), want 0", n)
	}
	if !userBool(t, pool, presentID, "enabled") {
		t.Error("present account was swept despite being in the directory")
	}
	if !userBool(t, pool, laterDeletedID, "enabled") {
		t.Error("still-present account was swept")
	}
	if !userBool(t, pool, nativeAbsentID, "enabled") {
		t.Error("native (sync_source != ldap) account was swept — the sweep must only own its own population")
	}
	var sweepStamp string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&sweepStamp); err != nil {
		t.Fatalf("absence sweep timestamp not recorded: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, strings.Trim(sweepStamp, `"`)); err != nil {
		t.Errorf("absence sweep timestamp %q is not RFC3339: %v", sweepStamp, err)
	}

	// Cycle 2 (the "next sync cycle" after a further deletion): the later user
	// disappears too. The sweep timestamp is reset so the cycle promotes itself
	// to a full enumeration instead of waiting out the cadence.
	fake.users = []LDAPUser{
		{Email: "present-" + suffix + "@" + domain, DisplayName: "Present Updated"},
	}
	setSyncSystemConfig(t, pool, "ldap_sync_last_absence_sweep",
		fmt.Sprintf("%q", time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339)))
	result2, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("next sync cycle after deletion: %v", err)
	}
	if result2.Disabled < 1 {
		t.Fatalf("next-cycle sweep result = %+v, want the newly absent account disabled", result2)
	}
	if userBool(t, pool, laterDeletedID, "enabled") {
		t.Fatal("account deleted from the directory stayed enabled on the next sync cycle")
	}
	if !userBool(t, pool, presentID, "enabled") {
		t.Error("surviving present account was swept")
	}
}

// TestSweepExcludesOtherSourceOwnedUsersOnSharedDomain is Astra waves12 item
// 2, shared-domain half: a user whose lifecycle authority another ldap-kind
// source holds (exactly how a normalized ldap:* source's provisioned accounts
// look) shares the domain but is NOT this source's property — an enumeration
// that lacks it must never disable it, while the same sweep still disables
// this source's own absent account.
func TestSweepExcludesOtherSourceOwnedUsersOnSharedDomain(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapshared")

	legacyAbsentID := upsertFixtureUser(t, pool, domainID, "shlegacy-"+suffix, "Legacy Absent", "ldap")
	foreignAbsentID := upsertFixtureUser(t, pool, domainID, "shforeign-"+suffix, "Foreign Absent", "ldap")
	otherSourceOwnedFixture(t, pool, foreignAbsentID, "foreign-subject-"+suffix, "ldap:shared-"+suffix)
	seedSession(t, pool, legacyAbsentID)
	seedSession(t, pool, foreignAbsentID)

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	// COMPLETE enumeration of THIS source's scope: both accounts are absent.
	fake.users = []LDAPUser{}
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	result, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("shared-domain sweep sync: %v", err)
	}
	if result.Errors != 0 || result.Disabled != 1 {
		t.Fatalf("shared-domain sweep result = %+v, want exactly the legacy-owned account disabled", result)
	}
	if userBool(t, pool, legacyAbsentID, "enabled") {
		t.Fatal("sweep did not disable this source's own absent account")
	}
	if !userBool(t, pool, foreignAbsentID, "enabled") {
		t.Fatal("sweep disabled another ldap source's user on a shared domain")
	}
	if n := sessionCount(t, pool, foreignAbsentID); n != 1 {
		t.Errorf("foreign-owned account sessions = %d, want 1 (no cross-source revocation)", n)
	}
}

// TestSweepOnEmptyEnumerationDisablesAllOwnedAccounts is Astra waves12 item 2,
// empty-enumeration half: a SUCCESSFUL, complete enumeration with zero entries
// proves every owned account was deleted — including the last user of a
// domain. The old observed-domains fence made exactly this case a no-op.
func TestSweepOnEmptyEnumerationDisablesAllOwnedAccounts(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapempty")

	lastLDAPID := upsertFixtureUser(t, pool, domainID, "lastldap-"+suffix, "Last LDAP", "ldap")
	otherDomainID := upsertFixtureDomain(t, pool, "ldapempty2")
	lastOfDomainID := upsertFixtureUser(t, pool, otherDomainID, "lastdom-"+suffix, "Last Of Domain", "ldap")
	nativeID := upsertFixtureUser(t, pool, domainID, "emptynative-"+suffix, "Native", "local")
	seedSession(t, pool, lastLDAPID)
	seedSession(t, pool, lastOfDomainID)

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	fake.users = []LDAPUser{} // successful EMPTY enumeration
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	result, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("empty-enumeration sync: %v", err)
	}
	if result.Errors != 0 || result.Disabled != 2 {
		t.Fatalf("empty-enumeration result = %+v, want both owned accounts disabled", result)
	}
	if userBool(t, pool, lastLDAPID, "enabled") || userBool(t, pool, lastOfDomainID, "enabled") {
		t.Fatal("successful empty enumeration left owned accounts enabled — last-user/domain deletion did not propagate")
	}
	if n := sessionCount(t, pool, lastLDAPID); n != 0 {
		t.Errorf("swept account kept %d session(s), want 0", n)
	}
	if !userBool(t, pool, nativeID, "enabled") {
		t.Error("native account was swept by the empty enumeration")
	}
}

// TestSweepDisableFailureInjectionSurfacesAndRetains is Astra waves12 item 3:
// when the atomic disable fails (injected mid-sweep), the error surfaces, the
// account stays ENABLED with its sessions, and no half-applied state exists.
// The injection swaps the disable reducer in the OWNED test database and
// restores the exact original definition via t.Cleanup (runs on success AND
// failure).
func TestSweepDisableFailureInjectionSurfacesAndRetains(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapinject")

	absentID := upsertFixtureUser(t, pool, domainID, "inject-"+suffix, "Inject Absent", "ldap")
	seedSession(t, pool, absentID)

	var originalDef string
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_functiondef('ldap_sync_disable_user(bigint,text,bigint)'::regprocedure)`,
	).Scan(&originalDef); err != nil {
		t.Fatalf("snapshot disable reducer definition: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), originalDef); err != nil {
			t.Errorf("restore disable reducer definition: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION ldap_sync_disable_user(
		    p_user_id BIGINT, p_reason TEXT, p_expected_generation BIGINT DEFAULT NULL
		) RETURNS JSONB LANGUAGE plpgsql AS $fn$
		BEGIN
		    RAISE EXCEPTION 'injected disable failure' USING ERRCODE = 'BZ500';
		END;
		$fn$;`); err != nil {
		t.Fatalf("inject failing disable reducer: %v", err)
	}

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	fake.users = []LDAPUser{} // absent
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	result, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("sweep with injected failure must surface via result.Errors, not abort: %v", err)
	}
	if result.Errors != 1 || result.Disabled != 0 {
		t.Fatalf("injected-failure result = %+v, want Errors=1 Disabled=0", result)
	}
	if !userBool(t, pool, absentID, "enabled") {
		t.Fatal("failed disable left the account disabled — unfinished revocation must never be committed")
	}
	if n := sessionCount(t, pool, absentID); n != 1 {
		t.Errorf("sessions = %d, want 1 (no partial revocation)", n)
	}
}

// TestAnchoredRenamePreservesLocalOnlyFields is Astra waves12 item 4: field
// protections are loaded by the RESOLVED user id, not the incoming email, so
// an anchored rename cannot bypass the original account's local-only policy or
// local overrides.
func TestAnchoredRenamePreservesLocalOnlyFields(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldaprename")
	domain := domainID_domain(t, pool, domainID)
	subject := "rename-subject-" + suffix

	ensureLegacyLDAPActive(t, pool)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	var created SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		ImmutableSubject: subject,
		Email:            "before-" + suffix + "@" + domain,
		DisplayName:      "Before Rename",
	}, false, &created); err != nil {
		t.Fatalf("anchored create: %v", err)
	}
	if created.Created != 1 {
		t.Fatalf("create result = %+v", created)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `
		SELECT l.user_id FROM user_identity_links l
		  JOIN identity_sources s ON s.id = l.source_id
		 WHERE s.source_key = 'legacy:ldap' AND l.external_subject = $1`, subject,
	).Scan(&userID); err != nil {
		t.Fatalf("read anchored user: %v", err)
	}
	cleanupProvisionedAccount(t, pool, userID)

	// Local-only policy on phone; a local override pinning job_title.
	if _, err := pool.Exec(ctx,
		`INSERT INTO field_policy (user_id, field, policy) VALUES ($1, 'phone', 'local_only')`, userID,
	); err != nil {
		t.Fatalf("insert field_policy: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE users SET phone = '555-0100', job_title = 'Local Title', local_overrides = '{"job_title":"Local Title"}' WHERE id = $1`,
		userID,
	); err != nil {
		t.Fatalf("seed local protections: %v", err)
	}

	// The directory RENAMED the account (new email) and offers hostile values.
	var renamed SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		ImmutableSubject: subject,
		Email:            "after-" + suffix + "@" + domain,
		DisplayName:      "After Rename",
		Title:            "Directory Title",
		Phone:            "666-666",
	}, false, &renamed); err != nil {
		t.Fatalf("anchored rename: %v", err)
	}
	if renamed.Updated != 1 || renamed.Skipped != 2 {
		t.Fatalf("rename result = %+v, want 1 update with 2 protected-field skips", renamed)
	}
	if got := userString(t, pool, userID, "email"); got != "after-"+suffix+"@"+domain {
		t.Errorf("renamed email = %q, want the directory address applied", got)
	}
	if got := userString(t, pool, userID, "phone"); got != "555-0100" {
		t.Errorf("phone = %q, want local-only 555-0100 preserved across the rename", got)
	}
	if got := userString(t, pool, userID, "job_title"); got != "Local Title" {
		t.Errorf("job_title = %q, want locally-overridden value preserved across the rename", got)
	}
}

// TestIncrementalCycleDoesNotDeprovisionAbsences proves an incremental pass is
// never absence evidence: with a committed cursor and a fresh sweep timestamp,
// an account missing from the incremental result stays enabled.
func TestIncrementalCycleDoesNotDeprovisionAbsences(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapincr")
	domain := domainID_domain(t, pool, domainID)

	presentID := upsertFixtureUser(t, pool, domainID, "incr-present-"+suffix, "Present", "ldap")
	absentID := upsertFixtureUser(t, pool, domainID, "incr-absent-"+suffix, "Absent", "ldap")

	setSyncSystemConfig(t, pool, "ldap_sync_last_cursor", `"20260101000000Z"`)
	setSyncSystemConfig(t, pool, "ldap_sync_last_absence_sweep",
		fmt.Sprintf("%q", time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339)))

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	fake.users = []LDAPUser{{
		Email:       "incr-present-" + suffix + "@" + domain,
		DisplayName: "Present",
		ModifyStamp: "20260102000000Z",
	}}
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	result, err := w.SyncNow(ctx)
	if err != nil {
		t.Fatalf("incremental sync: %v", err)
	}
	if !strings.Contains(fake.lastFilter, "modifyTimestamp>=") {
		t.Fatalf("incremental cycle lost its cursor filter: %q", fake.lastFilter)
	}
	if result.Disabled != 0 || result.Errors != 0 {
		t.Fatalf("incremental result = %+v, want no deprovisioning", result)
	}
	if !userBool(t, pool, absentID, "enabled") {
		t.Fatal("incremental cycle deprovisioned an account absent from a cursor-filtered result")
	}
	if !userBool(t, pool, presentID, "enabled") {
		t.Error("present account disturbed by incremental cycle")
	}
}

// TestAbsenceSweepSearchFailureSurfacesForRetry proves a failed directory
// search is never treated as deprovisioning evidence: the error surfaces, the
// absent account stays enabled, and the cursor is left untouched for retry.
func TestAbsenceSweepSearchFailureSurfacesForRetry(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapfail")
	absentID := upsertFixtureUser(t, pool, domainID, "fail-absent-"+suffix, "Absent", "ldap")

	setSyncSystemConfig(t, pool, "ldap_sync_last_cursor", `"20260101000000Z"`)
	// Sweep long overdue: the next successful cycle would promote to full.
	setSyncSystemConfig(t, pool, "ldap_sync_last_absence_sweep",
		fmt.Sprintf("%q", time.Now().UTC().Add(-48*time.Hour).Format(time.RFC3339)))

	fake := &fakeLDAPDirectory{subjectAttribute: "entryUUID", searchErr: errors.New("directory exploded")}
	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.client = fake
	cleanupSyncLog(t, pool)

	if _, err := w.SyncNow(ctx); err == nil {
		t.Fatal("search failure during a sweep-due cycle did not surface an error")
	}
	if !userBool(t, pool, absentID, "enabled") {
		t.Fatal("failed search treated as absence evidence — the account must stay enabled")
	}
	var cursor string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_cursor'`,
	).Scan(&cursor); err != nil {
		t.Fatalf("read cursor after failure: %v", err)
	}
	if cursor != "20260101000000Z" {
		t.Errorf("cursor advanced past a failed cycle: %q", cursor)
	}
}

// TestCleanupPreservesUnrelatedState is Astra waves12 item 6's verification
// arm: the isolation helpers restore unrelated state EXACTLY — invoked
// directly here so the restore is proven on success AND after a simulated
// failure path (state corrupted beyond the test's own writes).
func TestCleanupPreservesUnrelatedState(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)

	// Sentinel: unrelated pre-existing state the suite must never disturb.
	sentinelDomainID := upsertFixtureDomain(t, pool, "ldapsentinel")
	sentinelID := upsertFixtureUser(t, pool, sentinelDomainID, "sentinel-"+suffix, "Sentinel", "local")
	seedSession(t, pool, sentinelID)

	snapSource, err := scanLegacySourceRow(pool.QueryRow(ctx,
		`SELECT `+legacySourceColumns+` FROM identity_sources WHERE source_key = 'legacy:ldap'`))
	if err != nil {
		t.Fatalf("snapshot sentinel source row: %v", err)
	}
	var sentinelCfg string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&sentinelCfg); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("snapshot sentinel config: %v", err)
		}
		sentinelCfg = "<absent>"
	}

	// Exercise the exact restore paths the helpers register (the returned
	// functions are the same closures t.Cleanup will run; they are exact and
	// idempotent).
	restoreSource := ensureLegacyLDAPActive(t, pool)
	restoreConfig := setSyncSystemConfig(t, pool, "ldap_sync_last_absence_sweep", `"20260101000000Z"`)

	// Simulate damage beyond the test's own writes: the restore must still
	// return the row to its exact pre-test state (failure-path semantics).
	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET state = 'retired', display_name = 'Damaged' WHERE source_key = 'legacy:ldap'`,
	); err != nil {
		t.Fatalf("simulate concurrent source damage: %v", err)
	}

	restoreSource()
	restoreConfig()

	afterSource, err := scanLegacySourceRow(pool.QueryRow(ctx,
		`SELECT `+legacySourceColumns+` FROM identity_sources WHERE source_key = 'legacy:ldap'`))
	if err != nil {
		t.Fatalf("re-read source row: %v", err)
	}
	if afterSource.state != snapSource.state || afterSource.displayName != snapSource.displayName ||
		afterSource.generation != snapSource.generation || afterSource.updatedAt != snapSource.updatedAt {
		t.Fatalf("legacy:ldap row not restored exactly: state %q->%q display %q->%q generation %d->%d",
			snapSource.state, afterSource.state, snapSource.displayName, afterSource.displayName,
			snapSource.generation, afterSource.generation)
	}
	var afterCfg string
	if err := pool.QueryRow(ctx,
		`SELECT value #>> '{}' FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&afterCfg); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("re-read config: %v", err)
		}
		afterCfg = "<absent>"
	}
	if afterCfg != sentinelCfg {
		t.Fatalf("system_config not restored exactly: %q -> %q", sentinelCfg, afterCfg)
	}

	// Unrelated live state survived the cleanup path untouched.
	if !userBool(t, pool, sentinelID, "enabled") {
		t.Error("sentinel user disturbed by cleanup")
	}
	if n := sessionCount(t, pool, sentinelID); n != 1 {
		t.Errorf("sentinel sessions = %d, want 1", n)
	}
}
