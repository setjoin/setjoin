package ldapsync

// Security regression tests for the krb5_principal custody fix
// (D-MAILSERVER-INTERNAL-LDAPSYNC-001): users.krb5_principal is the
// Kerberos/SPNEGO SSO identity the auth chain resolves by exact principal
// match for full-access authentication. Directory sync must NEVER overwrite it
// on an existing user — the always-local-only floor (code-level, not
// field_policy-dependent) fences the UPDATE path, creation-time provisioning
// still writes it, and a suppressed overwrite is audited.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/ldaputil"
)

func TestKrb5PrincipalNeverOverwrittenByLegacySync(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldapsync-krb5-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	local := "ldap-krb5-" + suffix // package-unique local-part (derived username is cross-domain UNIQUE)
	email := local + "@" + domain
	originalPrincipal := local + "@CORP.EXAMPLE.COM"
	forgedPrincipal := "attacker-" + suffix + "@EVIL.EXAMPLE.COM"

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	// Creation path: krb5_principal is still provisioned from the directory UPN
	// (the floor fences the UPDATE path only).
	var create SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		Email: email, DisplayName: "Krb5 Test", UPN: originalPrincipal,
	}, false, &create); err != nil {
		t.Fatalf("create upsert: %v", err)
	}
	if create.Created != 1 {
		t.Fatalf("create result = %+v, want Created=1", create)
	}
	var userID int64
	var storedPrincipal string
	if err := pool.QueryRow(ctx,
		`SELECT id, COALESCE(krb5_principal, '') FROM users WHERE email = $1`, email,
	).Scan(&userID, &storedPrincipal); err != nil {
		t.Fatalf("read created user: %v", err)
	}
	// Transactional teardown (mailbox + user + sync_conflicts/field_policy in
	// one transaction).
	cleanupProvisionedAccount(t, pool, userID)
	if storedPrincipal != originalPrincipal {
		t.Fatalf("creation path krb5_principal = %q, want provisioned UPN %q", storedPrincipal, originalPrincipal)
	}

	// field_policy local_only must keep working for NON-floor fields: lock phone.
	if _, err := pool.Exec(ctx,
		`INSERT INTO field_policy (user_id, field, policy) VALUES ($1, 'phone', 'local_only')`,
		userID,
	); err != nil {
		t.Fatalf("insert field_policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET phone = '555-0100' WHERE id = $1`, userID); err != nil {
		t.Fatalf("seed phone: %v", err)
	}

	// Re-sync the same user with a DIFFERENT directory UPN (attacker-controlled)
	// and a different phone. Other attributes are identical so the only skips
	// are krb5_principal (floor) and phone (policy).
	var result SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		Email: email, DisplayName: "Krb5 Test", UPN: forgedPrincipal, Phone: "555-9999",
	}, false, &result); err != nil {
		t.Fatalf("update upsert: %v", err)
	}
	if result.Skipped != 2 {
		t.Errorf("result.Skipped = %d, want 2 (krb5_principal floor + phone policy)", result.Skipped)
	}

	var storedPhone string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(krb5_principal, ''), COALESCE(phone, '') FROM users WHERE id = $1`, userID,
	).Scan(&storedPrincipal, &storedPhone); err != nil {
		t.Fatalf("read user after forged sync: %v", err)
	}
	if storedPrincipal != originalPrincipal {
		t.Errorf("krb5_principal was overwritten to %q, want unchanged %q", storedPrincipal, originalPrincipal)
	}
	if storedPhone != "555-0100" {
		t.Errorf("phone = %q, want unchanged 555-0100 (field_policy local_only must still be respected)", storedPhone)
	}

	// The suppressed overwrite is audited: sync_conflicts row with the stored
	// principal kept and the attacker-controlled UPN recorded.
	var conflicts int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM sync_conflicts
		 WHERE user_id = $1 AND field = $2 AND local_value = $3
		   AND remote_value = $4 AND source = 'ldap' AND resolution = 'kept_local'`,
		userID, ldaputil.FieldKrb5Principal, originalPrincipal, forgedPrincipal,
	).Scan(&conflicts); err != nil {
		t.Fatalf("count sync_conflicts: %v", err)
	}
	if conflicts != 1 {
		t.Errorf("sync_conflicts suppressed-overwrite rows = %d, want 1", conflicts)
	}

	// ...and the slog warn carries the suppressed directory value for forensics.
	if got := logs.String(); !strings.Contains(got, "suppressed krb5_principal overwrite") ||
		!strings.Contains(got, forgedPrincipal) || !strings.Contains(got, fmt.Sprintf("user_id=%d", userID)) {
		t.Errorf("suppression warn missing/incomplete: %q", got)
	}
}
