package ldaputil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/shared/identity"
	"setjoin.com/shared/testsupport"
)

func TestDomainToBaseDN(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"corp.local", "DC=corp,DC=local"},
		{"example.com", "DC=example,DC=com"},
		{"single", "DC=single"},
		{"a.b.c.d", "DC=a,DC=b,DC=c,DC=d"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := DomainToBaseDN(tt.domain)
			if got != tt.want {
				t.Errorf("DomainToBaseDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestSyncAttrs(t *testing.T) {
	attrs := SyncAttrs(identity.CanonicalizeAddress("user@example.com"),
		"User", "First", "Last", "Engineer", "555-0100", "user@corp.local")
	if attrs["email"] != "user@example.com" {
		t.Errorf("email = %q, want user@example.com", attrs["email"])
	}
	if attrs["display_name"] != "User" {
		t.Errorf("display_name = %q, want User", attrs["display_name"])
	}
	if attrs["first_name"] != "First" {
		t.Errorf("first_name = %q, want First", attrs["first_name"])
	}
	if attrs["last_name"] != "Last" {
		t.Errorf("last_name = %q, want Last", attrs["last_name"])
	}
	if attrs["job_title"] != "Engineer" {
		t.Errorf("job_title = %q, want Engineer", attrs["job_title"])
	}
	if attrs["phone"] != "555-0100" {
		t.Errorf("phone = %q, want 555-0100", attrs["phone"])
	}
	if attrs["krb5_principal"] != "user@corp.local" {
		t.Errorf("krb5_principal = %q, want user@corp.local", attrs["krb5_principal"])
	}
}

// TestSyncAttrs_EmailIsCanonicalAtBoundary proves the UPDATE-path writer's email
// is Go-canonical BY CONSTRUCTION: SyncAttrs only accepts a CanonicalAddress, so
// a mixed-case / TAB-prefixed directory email is trimmed + ASCII-folded before it
// can reach the `UPDATE users SET email = …` bind. (A raw string would not
// compile — that is the soundness of the newtype, not asserted here but proven by
// the type system; this asserts the FOLD result.)
func TestSyncAttrs_EmailIsCanonicalAtBoundary(t *testing.T) {
	// Mixed case + a leading TAB — exactly the non-canonical shape an AD/LDAP
	// attribute can carry that would otherwise match-miss the canonicalizing
	// matcher (silent-lockout class).
	attrs := SyncAttrs(identity.CanonicalizeAddress("\tAlice.Smith@Example.COM"),
		"Alice", "Alice", "Smith", "", "", "alice@CORP.EXAMPLE.COM")
	if got := attrs["email"]; got != "alice.smith@example.com" {
		t.Errorf("UPDATE-path email = %q, want canonical %q", got, "alice.smith@example.com")
	}
	// krb5_principal keeps the raw UPN (case-sensitive Kerberos realm) — NOT folded.
	if got := attrs["krb5_principal"]; got != "alice@CORP.EXAMPLE.COM" {
		t.Errorf("krb5_principal = %q, want RAW (unfolded) %q", got, "alice@CORP.EXAMPLE.COM")
	}
}

// TestEnforceAlwaysLocalOnly proves the code-level custody floor: krb5_principal
// is in the local-only set even when field_policy contributes nothing, and it
// cannot be removed from a policy-derived set (an explicit 'ad_managed' removal
// is filtered out by the merge).
func TestEnforceAlwaysLocalOnly(t *testing.T) {
	fromNil := EnforceAlwaysLocalOnly(nil)
	if !fromNil[FieldKrb5Principal] {
		t.Error("floor set from nil must contain krb5_principal")
	}
	if len(fromNil) != 1 {
		t.Errorf("floor set from nil = %v, want exactly {krb5_principal}", fromNil)
	}

	merged := EnforceAlwaysLocalOnly(map[string]bool{"display_name": true, FieldKrb5Principal: false})
	if !merged["display_name"] || !merged[FieldKrb5Principal] {
		t.Errorf("merged set = %v, want display_name AND krb5_principal (an explicit false must not remove the floor)", merged)
	}
	if len(merged) != 2 {
		t.Errorf("merged set = %v, want exactly {display_name, krb5_principal}", merged)
	}
}

// TestApplyUserUpdateNeverWritesKrb5PrincipalEvenWhenCallerForgets is the
// defense-in-depth regression at the single UPDATE writer: even with an EMPTY
// localOnly set (no field_policy, no engine-level merge), ApplyUserUpdate must
// refuse to write krb5_principal, count it as skipped, and audit the suppressed
// overwrite (sync_conflicts row + slog.Warn with the suppressed directory value).
func TestApplyUserUpdateNeverWritesKrb5PrincipalEvenWhenCallerForgets(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffixBytes := make([]byte, 4)
	if _, err := rand.Read(suffixBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	suffix := hex.EncodeToString(suffixBytes)

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, "ldaputil-krb5-"+suffix+".local",
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	originalPrincipal := "ldaputil-krb5-" + suffix + "@CORP.EXAMPLE.COM"
	forgedPrincipal := "attacker-" + suffix + "@EVIL.EXAMPLE.COM"
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, krb5_principal)
		 VALUES ($1, $2, $3, $4, '$2a$10$placeholder', $5) RETURNING id`,
		"ldaputil-krb5-"+suffix, "ldaputil-krb5-"+suffix+"@ldaputil-krb5-"+suffix+".local",
		"Ldaputil Krb5", domainID, originalPrincipal,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM sync_conflicts WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM field_policy WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	// localOnly is deliberately EMPTY: the floor must hold at the writer itself.
	var result SyncResult
	err := ApplyUserUpdate(ctx, pool, userID,
		map[string]string{"display_name": "Changed Name", FieldKrb5Principal: forgedPrincipal},
		nil, nil, nil, "ldap", nil, &result, logger)
	if err != nil {
		t.Fatalf("ApplyUserUpdate: %v", err)
	}
	if result.Skipped != 1 || result.Updated != 1 {
		t.Errorf("result = %+v, want Skipped=1 (krb5_principal) Updated=1 (display_name)", result)
	}

	var gotPrincipal, gotName string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(krb5_principal, ''), display_name FROM users WHERE id = $1`, userID,
	).Scan(&gotPrincipal, &gotName); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if gotPrincipal != originalPrincipal {
		t.Errorf("krb5_principal = %q, want unchanged %q", gotPrincipal, originalPrincipal)
	}
	if gotName != "Changed Name" {
		t.Errorf("display_name = %q, want %q (non-floor fields must still sync)", gotName, "Changed Name")
	}

	var conflicts int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM sync_conflicts
		 WHERE user_id = $1 AND field = $2 AND local_value = $3
		   AND remote_value = $4 AND source = 'ldap' AND resolution = 'kept_local'`,
		userID, FieldKrb5Principal, originalPrincipal, forgedPrincipal,
	).Scan(&conflicts); err != nil {
		t.Fatalf("count sync_conflicts: %v", err)
	}
	if conflicts != 1 {
		t.Errorf("sync_conflicts suppressed-overwrite rows = %d, want 1", conflicts)
	}

	if got := logs.String(); !strings.Contains(got, "suppressed krb5_principal overwrite") ||
		!strings.Contains(got, forgedPrincipal) {
		t.Errorf("suppression warn missing/incomplete: %q", got)
	}
}
