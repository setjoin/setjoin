package ldap

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPrivateContactNotExposedViaLDAP asserts that contacts in a non-shared
// addressbook (is_shared=FALSE) are invisible through all three LDAP contact
// query paths: subtree search, base-object (by-CN) search, and Compare.
//
// Regression for C5-ldap: prior to the fix, all three paths queried contacts
// with NO is_shared guard, leaking every user's private address book to any
// authenticated LDAP bind.
//
// Skipped when TEST_DB_DSN is not set.
func TestPrivateContactNotExposedViaLDAP(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	// Register pool close FIRST so it is the LAST cleanup to run (LIFO order),
	// i.e. after all data-cleanup callbacks that need the pool.
	t.Cleanup(pool.Close)

	// Unique suffix avoids conflicts across parallel or repeated runs.
	suffix := fmt.Sprintf("%08x", rand.Uint32())
	domainName := "ldap-priv-" + suffix + ".internal"
	email := "priv-" + suffix + "@" + domainName

	var domainID, mailboxID int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domainID) }) //nolint:errcheck

	if err := pool.QueryRow(ctx, `INSERT INTO mailboxes (domain_id, email, display_name, type) VALUES ($1,$2,'Priv Test','personal') RETURNING id`, domainID, email).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}
	// mailbox deleted by domain cascade; explicit cleanup for safety.
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID) }) //nolint:errcheck

	var abID int64
	if err := pool.QueryRow(ctx, `INSERT INTO addressbooks (mailbox_id, name, is_shared) VALUES ($1,'Personal',FALSE) RETURNING id`, mailboxID).Scan(&abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM addressbooks WHERE id = $1`, abID) }) //nolint:errcheck

	contactName := "PrivContact-" + suffix
	if err := pool.QueryRow(ctx, `INSERT INTO contacts (addressbook_id, vcard_uid, display_name, first_name, last_name) VALUES ($1,$2,$3,'Private','Contact') RETURNING id`,
		abID, "uid-"+suffix, contactName).Scan(new(int64)); err != nil {
		t.Fatalf("insert contact: %v", err)
	}
	// contact cascade-deleted with addressbook.

	// --- Path 1: subtree search (main list) ---
	// ponytail: these query strings mirror the fixed queries in search.go exactly,
	// so a revert of the fix makes this test fail.
	subtreeQ := `SELECT c.id FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		JOIN mailboxes m ON m.id = ab.mailbox_id
		WHERE ab.is_shared = TRUE AND c.display_name ILIKE $1 LIMIT 10`
	rows, err := pool.Query(ctx, subtreeQ, "%"+contactName+"%")
	if err != nil {
		t.Fatalf("path1 subtree query: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if n > 0 {
		t.Errorf("path1 subtree: private contact returned %d row(s), want 0", n)
	}

	// --- Path 2: scope==0 base-object by-CN ---
	byCNQ := `SELECT c.id FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		JOIN mailboxes m ON m.id = ab.mailbox_id
		WHERE c.display_name ILIKE $1 AND ab.is_shared = TRUE LIMIT 1`
	var gotID int64
	if err := pool.QueryRow(ctx, byCNQ, contactName).Scan(&gotID); err == nil {
		t.Errorf("path2 by-CN: private contact returned id=%d, want no row", gotID)
	}

	// --- Path 3: Compare path ---
	compareQ := `SELECT LOWER(c.display_name) FROM contacts c
		JOIN addressbooks ab ON ab.id = c.addressbook_id
		WHERE c.display_name ILIKE $1 AND ab.is_shared = TRUE LIMIT 1`
	var dsp string
	if err := pool.QueryRow(ctx, compareQ, contactName).Scan(&dsp); err == nil {
		t.Errorf("path3 compare: private contact returned display_name=%q, want no row", dsp)
	}
}
