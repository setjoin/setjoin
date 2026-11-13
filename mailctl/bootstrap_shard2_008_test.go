package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// med-shard2-008 (D-SHARED-VALIDATE-001): the bootstrap (ensure_default_admin)
// provisioning path must refuse RFC 2142 reserved local-parts. The gate runs at
// flag parse — before any database access — so a reserved first-administrator
// identity can never reach the reducer.
func TestParseBootstrapAdminFlagsRejectsReservedLocalPart(t *testing.T) {
	for _, args := range [][]string{
		{"--email", "postmaster@example.com"},
		{"--email", "Postmaster@Example.COM"},
		{"--email", "abuse@example.com"},
		{"--email", "NOBODY@example.com"},
		{"--email", "mailer-daemon@example.com"},
	} {
		if _, err := parseBootstrapAdminFlags(args); err == nil {
			t.Errorf("parseBootstrapAdminFlags(%q) accepted reserved local-part", args)
		} else if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("parseBootstrapAdminFlags(%q) error = %v, want reserved-local-part rejection", args, err)
		}
	}

	// Ordinary local-parts keep working.
	if _, err := parseBootstrapAdminFlags([]string{"--email", "admin@example.com"}); err != nil {
		t.Fatalf("ordinary bootstrap email rejected: %v", err)
	}
}

// TestRunBootstrapAdminRejectsReservedEmailBeforeDatabase proves the reserved
// gate fires before the database is even opened (parse precedes openDB in
// runBootstrapAdmin).
func TestRunBootstrapAdminRejectsReservedEmailBeforeDatabase(t *testing.T) {
	c := &cmdCtx{openDB: func() (*pgxpool.Pool, error) {
		return nil, errors.New("database must not be reached for a reserved email")
	}}
	err := runBootstrapAdmin(c, "", []string{"--email", "hostmaster@example.com", "--password-stdin"})
	if err == nil {
		t.Fatal("bootstrap accepted reserved local-part")
	}
	if strings.Contains(err.Error(), "database") {
		t.Fatalf("reserved rejection happened after openDB: %v", err)
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("error = %v, want reserved-local-part rejection", err)
	}
}

// TestRunBootstrapAdminPasswordContainment pins D-SHARED-VALIDATE-003 on the
// bootstrap path: DisallowEmail is fed the (parse-enforced canonical) bootstrap
// address and passwordContainsEmail evaluates its unquoted local-part over the
// canonical form, so a password containing the account's own local-part is
// rejected BEFORE ensure_default_admin is ever called. The quoted-local defeat
// itself is pinned at the primitive level (TestPasswordContainsEmailQuotedLocalCannotDefeat,
// TestValidatePasswordDisallowEmailQuotedLocal); note the bootstrap CLI cannot
// even be fed a quoted-local address, since its parse step requires the flag
// value to equal its own canonical parse. DB-backed; skips without
// TEST_DB_DSN/DB_DSN.
func TestRunBootstrapAdminPasswordContainment(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	passwordPath := filepath.Join(t.TempDir(), "password")
	// Contains the local-part "bob" of the bootstrap email.
	if err := os.WriteFile(passwordPath, []byte("Corpbob-XYZ-99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &cmdCtx{openDB: func() (*pgxpool.Pool, error) { return pool, nil }}

	err = runBootstrapAdmin(c, "", []string{"--email", "bob@bootstrap-shard2-008.invalid", "--password-file", passwordPath})
	if err == nil {
		t.Fatal("bootstrap accepted a password containing the account's own email local-part")
	}
	if strings.Contains(err.Error(), "bootstrap administrator") || strings.Contains(err.Error(), "decode") {
		t.Fatalf("containment fired after provisioning started: %v", err)
	}
	if !strings.Contains(err.Error(), "email address") {
		t.Fatalf("error = %v, want password-contains-email rejection", err)
	}
}
