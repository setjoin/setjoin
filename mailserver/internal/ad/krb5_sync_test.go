package ad

// Security regression test for the krb5_principal custody fix
// (D-MAILSERVER-INTERNAL-LDAPSYNC-001) on the AD path: the AD sync selects its
// target by ad_object_guid and must NEVER rewrite users.krb5_principal on an
// existing user, even when the directory UPN for that GUID changes. The
// always-local-only floor is code-level — no field_policy row is required.

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/ldaputil"
)

func TestKrb5PrincipalNeverOverwrittenByADSync(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-krb5-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var objectGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&objectGUID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}

	local := "ad-krb5-" + suffix // package-unique local-part (derived username is cross-domain UNIQUE)
	email := local + "@" + domain
	originalPrincipal := local + "@CORP.EXAMPLE.COM"
	forgedPrincipal := "attacker-" + suffix + "@EVIL.EXAMPLE.COM"

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM sync_conflicts WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM field_policy WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM users WHERE ad_object_guid::TEXT = $1`, objectGUID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	// Creation path: krb5_principal is still provisioned from the directory UPN.
	u := ADUser{
		ObjectGUID:  objectGUID,
		Email:       email,
		DisplayName: "AD Krb5 Test",
		UPN:         originalPrincipal,
		USNChanged:  1,
	}
	var create SyncResult
	if err := w.upsertUser(ctx, u, false, false, &create); err != nil {
		t.Fatalf("create upsert: %v", err)
	}
	if create.Created != 1 {
		t.Fatalf("create result = %+v, want Created=1", create)
	}
	var userID int64
	var storedPrincipal string
	if err := pool.QueryRow(ctx,
		`SELECT id, COALESCE(krb5_principal, '') FROM users WHERE ad_object_guid::TEXT = $1`, objectGUID,
	).Scan(&userID, &storedPrincipal); err != nil {
		t.Fatalf("read created user: %v", err)
	}
	if storedPrincipal != originalPrincipal {
		t.Fatalf("creation path krb5_principal = %q, want provisioned UPN %q", storedPrincipal, originalPrincipal)
	}

	// Re-sync the same GUID with a DIFFERENT directory UPN (attacker-controlled).
	// Other synced attributes are identical so the only skip is the floor field.
	u.UPN = forgedPrincipal
	var result SyncResult
	if err := w.upsertUser(ctx, u, false, false, &result); err != nil {
		t.Fatalf("update upsert: %v", err)
	}
	if result.Skipped != 1 {
		t.Errorf("result.Skipped = %d, want 1 (krb5_principal floor)", result.Skipped)
	}

	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(krb5_principal, '') FROM users WHERE id = $1`, userID,
	).Scan(&storedPrincipal); err != nil {
		t.Fatalf("read user after forged sync: %v", err)
	}
	if storedPrincipal != originalPrincipal {
		t.Errorf("krb5_principal was overwritten to %q, want unchanged %q", storedPrincipal, originalPrincipal)
	}

	// The suppressed overwrite is audited for the AD source too.
	var conflicts int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM sync_conflicts
		 WHERE user_id = $1 AND field = $2 AND local_value = $3
		   AND remote_value = $4 AND source = 'ad' AND resolution = 'kept_local'`,
		userID, ldaputil.FieldKrb5Principal, originalPrincipal, forgedPrincipal,
	).Scan(&conflicts); err != nil {
		t.Fatalf("count sync_conflicts: %v", err)
	}
	if conflicts != 1 {
		t.Errorf("sync_conflicts suppressed-overwrite rows = %d, want 1", conflicts)
	}

	// ...and the slog warn carries the suppressed directory value for forensics.
	if got := logs.String(); !strings.Contains(got, "suppressed krb5_principal overwrite") ||
		!strings.Contains(got, forgedPrincipal) {
		t.Errorf("suppression warn missing/incomplete: %q", got)
	}
}

// TestKrb5PrincipalNeverOverwrittenByUnmatchedGUIDFallback covers the Astra
// round-2 HOLD: when the objectGUID is UNMATCHED, upsertUser routes the
// directory principal through the provisioner (identity.ProvisionAccount).
// provision_account then falls through its GUID → SCIM → email lookup to an
// EXISTING-email match and takes its UPDATE branch — which used to
// COALESCE-overwrite the victim's krb5_principal with the directory UPN,
// bypassing both the Go floor and the suppression audit. The reducer's UPDATE
// branch now excludes the column entirely (the SQL mirror of
// ldaputil.alwaysLocalOnlyFields); only genuine INSERT provisioning writes it.
func TestKrb5PrincipalNeverOverwrittenByUnmatchedGUIDFallback(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-krb5fb-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	local := "ad-krb5fb-" + suffix // package-unique local-part (derived username is cross-domain UNIQUE)
	email := local + "@" + domain
	existingPrincipal := local + "@LEGACY.EXAMPLE.COM"
	forgedPrincipal := "attacker-fb-" + suffix + "@EVIL.EXAMPLE.COM"

	// A pre-existing LOCAL user with NO ad_object_guid — the exact victim shape
	// the unmatched-GUID fall-through lands on.
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, krb5_principal)
		 VALUES ($1, $2, $3, 'Krb5 Fallback Victim', $4) RETURNING id`,
		local, domainID, email, existingPrincipal,
	).Scan(&userID); err != nil {
		t.Fatalf("seed existing user: %v", err)
	}

	var freshGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&freshGUID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM sync_conflicts WHERE user_id = $1`, userID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM field_policy WHERE user_id = $1`, userID)   //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)      //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)               //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)           //nolint:errcheck
	})

	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	// Unmatched GUID + the victim's email + an attacker-chosen directory UPN.
	u := ADUser{
		ObjectGUID:  freshGUID,
		Email:       email,
		DisplayName: "Krb5 Fallback Victim",
		UPN:         forgedPrincipal,
		USNChanged:  1,
	}
	var result SyncResult
	if err := w.upsertUser(ctx, u, false, false, &result); err != nil {
		t.Fatalf("fallback upsert: %v", err)
	}
	// The fall-through is an UPDATE of an existing person, not a creation.
	if result.Created != 0 || result.Updated != 1 {
		t.Errorf("result = %+v, want Created=0 Updated=1 (existing-email fall-through)", result)
	}

	var storedPrincipal string
	var adoptedGUID *string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(krb5_principal, ''), ad_object_guid::TEXT FROM users WHERE id = $1`, userID,
	).Scan(&storedPrincipal, &adoptedGUID); err != nil {
		t.Fatalf("read user after fallback provision: %v", err)
	}
	if storedPrincipal != existingPrincipal {
		t.Errorf("krb5_principal was overwritten to %q, want unchanged %q", storedPrincipal, existingPrincipal)
	}
	// The GUID was adopted by the same fenced UPDATE branch — proves the
	// provisioner really took the UPDATE path (not a second user, not a miss).
	if adoptedGUID == nil || *adoptedGUID != freshGUID {
		t.Errorf("ad_object_guid = %v, want adopted fresh GUID %s", adoptedGUID, freshGUID)
	}
	var userCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE lower(email) = $1`, email,
	).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Errorf("users with the victim email = %d, want 1 (no duplicate provisioned)", userCount)
	}
}
