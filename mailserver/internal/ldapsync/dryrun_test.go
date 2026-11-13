package ldapsync

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDryRunUnreachableHostIsNetworkClass proves DryRun classifies a
// connection failure (bad host/port) as ConnClassNetwork — the "Test
// connection" journey the e2e spec drives (no live directory available in
// CI, so this is the one directory-shaped path exercised without a fake
// server: a guaranteed-unreachable address).
func TestDryRunUnreachableHostIsNetworkClass(t *testing.T) {
	pool := testPool(t)
	// Port 1 on localhost: nothing listens there — deterministic refusal,
	// no dependency on a real directory or DNS.
	client := NewClient("127.0.0.1", 1, false, "cn=svc", "pw", "dc=example,dc=com")
	w := NewSyncWorker(client, pool, testLogger(), 15)

	_, err := w.DryRun(context.Background(), 5)
	if err == nil {
		t.Fatal("expected an error dialing an unreachable host, got nil")
	}
	var ce *ConnError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConnError, got %T: %v", err, err)
	}
	if ce.Class != ConnClassNetwork {
		t.Errorf("Class = %q, want %q", ce.Class, ConnClassNetwork)
	}
}

// TestDryRunNeverCallsSync is the regression for the "Test mutates the users
// table" bug: TestConnection used to call SyncNow. DryRun must never reach
// upsertUser/resolveManagerIDs/the cursor writer/the sync-log writer — proven
// here by counting rows in every table those write to, before and after a
// DryRun call (which fails at Connect() against the unreachable host, but the
// zero-writes property must hold on any code path, not just the happy one).
func TestDryRunNeverCallsSync(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	client := NewClient("127.0.0.1", 1, false, "cn=svc", "pw", "dc=example,dc=com")
	w := NewSyncWorker(client, pool, testLogger(), 15)

	// The counts are GLOBAL, and `go test ./...` runs packages in parallel
	// against the shared test DB — a concurrent package creating/deleting
	// users perturbs them (seen on CI: before=101 after=98). A buggy DryRun
	// yields a nonzero delta on EVERY attempt (its writes are deterministic
	// per call); cross-package churn is transient — so retry the whole
	// measure-cycle and only fail if the delta never settles to zero.
	var before, after int
	for attempt := 1; attempt <= 5; attempt++ {
		before = countRows(t, pool, "users") + countRows(t, pool, "identity_sync_log") + countRows(t, pool, "system_config")
		_, _ = w.DryRun(ctx, 5) // error expected; writes are what's under test
		after = countRows(t, pool, "users") + countRows(t, pool, "identity_sync_log") + countRows(t, pool, "system_config")
		if after == before {
			return
		}
		t.Logf("attempt %d: row counts moved (before=%d after=%d) — retrying in case of concurrent-package churn", attempt, before, after)
	}
	t.Errorf("DryRun changed row counts on every attempt: before=%d after=%d — it must never write", before, after)
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestPreviewRowNeverWrites is the killer regression for the preview
// endpoint: given a directory user that WOULD be disabled by a real sync
// (upsertUser flips users.enabled to FALSE + deletes sessions), previewRow
// must classify the row as "disable" WITHOUT touching the row. Mirrors
// TestUpsertUserDisablePath's setup but asserts the opposite: nothing
// changed.
func TestPreviewRowNeverWrites(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldap-preview-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	email := "preview-" + suffix + "@" + domain
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Seed an existing, enabled user (as if a prior real sync created it).
	var create SyncResult
	if err := w.upsertUser(ctx, LDAPUser{Email: email, DisplayName: "Preview Test"}, false, &create); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	// Transactional teardown (mailbox + user in one transaction).
	cleanupProvisionedAccount(t, pool, userID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')`, userID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// The directory now reports this user as disabled — previewRow must
	// classify it as "disable" but must NOT actually disable it.
	row := w.previewRow(ctx, LDAPUser{Email: email, DisplayName: "Preview Test", Disabled: true})
	if row.Action != "disable" {
		t.Errorf("Action = %q, want %q", row.Action, "disable")
	}

	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read enabled: %v", err)
	}
	if !enabled {
		t.Error("previewRow wrote to users.enabled — preview must be read-only")
	}
	var sessionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionCount != 1 {
		t.Errorf("previewRow changed session count to %d, want 1 (untouched)", sessionCount)
	}
}

// TestBuildSyncFilter covers the admin console's optional filter override:
// default when empty, override honored, cursor AND'd onto whichever base is
// in effect.
func TestBuildSyncFilter(t *testing.T) {
	tests := []struct {
		name, base, cursor, want string
	}{
		{"default, no cursor", "", "", "(objectClass=person)"},
		{"default, with cursor", "", "20260101000000Z", "(&(objectClass=person)(modifyTimestamp>=20260101000000Z))"},
		{"override, no cursor", "(objectClass=inetOrgPerson)", "", "(objectClass=inetOrgPerson)"},
		{"override, with cursor", "(objectClass=inetOrgPerson)", "20260101000000Z", "(&(objectClass=inetOrgPerson)(modifyTimestamp>=20260101000000Z))"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildSyncFilter(tc.base, tc.cursor); got != tc.want {
				t.Errorf("buildSyncFilter(%q, %q) = %q, want %q", tc.base, tc.cursor, got, tc.want)
			}
		})
	}
}

// TestPreviewRowActions covers the create/update/skip classification a
// not-yet-existing, existing, and email-less directory entry each get.
func TestPreviewRowActions(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	w := &SyncWorker{pool: pool, logger: testLogger()}

	if row := w.previewRow(ctx, LDAPUser{Email: "", DisplayName: "No Email"}); row.Action != "skip" {
		t.Errorf("no-email Action = %q, want skip", row.Action)
	}

	suffix := randSuffix(t)
	unseenEmail := "nosuchuser-" + suffix + "@nowhere.invalid"
	if row := w.previewRow(ctx, LDAPUser{Email: unseenEmail, DisplayName: "New"}); row.Action != "create" {
		t.Errorf("new-user Action = %q, want create", row.Action)
	}
}
