package ldaputil

// Coverage-gap tests for the ApplyUserUpdate / auditSuppressedPrincipalWrite
// arms in ldaputil.go:
//   - the nil-logger fallback to slog.Default();
//   - the suppressed krb5_principal audit failing on the stored-principal read
//     (unknown user) — the error must propagate, never become a silent skip;
//   - the suppressed krb5_principal audit failing on the sync_conflicts insert
//     (source CHECK violation) — same propagation contract.

import (
	"context"
	"strings"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestApplyUserUpdateNilLoggerFallsBackToDefault: a nil logger must be swapped
// for slog.Default() before the update loop runs (the krb5 audit path logs
// through it). With no attributes there is nothing to write, so the call
// succeeds without a pool.
func TestApplyUserUpdateNilLoggerFallsBackToDefault(t *testing.T) {
	var res SyncResult
	err := ApplyUserUpdate(context.Background(), nil, 1, map[string]string{}, nil, nil, nil, "ad", nil, &res, nil)
	if err != nil {
		t.Fatalf("ApplyUserUpdate with nil logger and no attrs: %v", err)
	}
}

// TestApplyUserUpdateSuppressedPrincipalReadFailsClosed: the directory offered
// a DIFFERENT krb5_principal for an existing user; when the stored principal
// cannot be read back (unknown user id), the audit fails and the whole update
// errors — the suppression evidence must never be silently lost.
func TestApplyUserUpdateSuppressedPrincipalReadFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var res SyncResult
	attrs := map[string]string{FieldKrb5Principal: "ghost@REALM.TEST"}
	err := ApplyUserUpdate(ctx, pool, 987654321, attrs, nil, nil, nil, "ad", nil, &res, testsupport.TestLogger())
	if err == nil {
		t.Fatal("suppressed-principal audit read failure returned nil")
	}
	if !strings.Contains(err.Error(), "read stored krb5_principal") {
		t.Fatalf("err = %v, want the stored-principal read failure", err)
	}
	if res.Skipped != 0 || res.Updated != 0 {
		t.Errorf("failed audit counted as skip/update: %+v", res)
	}
}

// TestApplyUserUpdateSuppressedPrincipalInsertFailsClosed: the audit
// sync_conflicts insert itself fails (source violates the CHECK constraint)
// and the failure propagates to the caller so the sync run counts an error —
// never a clean skip of a would-be principal overwrite.
func TestApplyUserUpdateSuppressedPrincipalInsertFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	suffix := randSuffix(t)
	domain := "ldaputil-krb5-" + suffix + ".local"
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled)
		 VALUES ($1, lower($2), 'Krb5 Gap Test', $3, '$2a$10$placeholder', TRUE)
		 RETURNING id`,
		"krb5gap-"+suffix, "krb5gap-"+suffix+"@"+domain, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var res SyncResult
	attrs := map[string]string{FieldKrb5Principal: "synced@REALM.TEST"}
	// source "bogus-source" violates sync_conflicts' CHECK (source IN ('ad','ldap')).
	err := ApplyUserUpdate(ctx, pool, userID, attrs, nil, nil, nil, "bogus-source", nil, &res, testsupport.TestLogger())
	if err == nil {
		t.Fatal("suppressed-principal audit insert failure returned nil")
	}
	if !strings.Contains(err.Error(), "record suppressed krb5_principal overwrite") {
		t.Fatalf("err = %v, want the audit-insert failure", err)
	}
	if res.Skipped != 0 || res.Updated != 0 {
		t.Errorf("failed audit counted as skip/update: %+v", res)
	}
}
