package carddav

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestScanContact_NullAvatar is a regression test: contacts.avatar_sha256 is a
// nullable column with no default (confirmed via jmap_contact_set, which INSERTs
// avatar_sha256 = the JMAP patch's "avatar" key — NULL when the contact has none,
// which is the common case). contactRow.AvatarSHA256 used to be a plain string, so
// scanContact panicked with "cannot scan NULL into *string" for any avatar-less
// contact — i.e. every list/search/GET of a photo-less contact via CardDAV. Fixed by
// making the field *string. This test fails on the unfixed code and passes after.
//
// Skips when TEST_DB_DSN is unset so the pure-Go suite remains runnable without a
// database.
func TestScanContact_NullAvatar(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	t.Cleanup(pool.Close)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })

	var mbID int64
	if err := tx.QueryRow(ctx, `SELECT mk_account('carddav_null_avatar_test')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := tx.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("get user_id: %v", err)
	}
	var abID int64
	if err := tx.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default, is_shared)
		 VALUES ($1, 'Test AB', true, false) RETURNING id`, mbID).Scan(&abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}

	// No avatar_sha256 supplied — the column stays NULL (no default), the common case
	// for a contact with no photo.
	const uid = "null-avatar-regression-uid"
	if _, err := tx.Exec(ctx,
		`INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES ($1, $2, 'No Photo Contact')`,
		abID, uid); err != nil {
		t.Fatalf("insert contact: %v", err)
	}

	rows, err := tx.Query(ctx,
		`SELECT c.id, c.addressbook_id, c.vcard_uid, c.display_name, c.first_name, c.last_name,
		 c.company, c.job_title, c.department, c.emails, c.phones, c.addresses, c.urls,
		 c.instant_msgs, c.notes, c.birthday, c.anniversary, c.avatar_sha256, c.categories, c.etag, c.updated_at
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 WHERE c.addressbook_id = $1 AND ab.mailbox_id IN (SELECT id FROM mailboxes WHERE user_id = $2)`,
		abID, userID)
	if err != nil {
		t.Fatalf("list query: %v", err)
	}
	defer rows.Close()

	var found bool
	for rows.Next() {
		c := &contactRow{}
		if err := scanContact(rows, c); err != nil {
			t.Fatalf("scanContact: %v (NULL avatar_sha256 scan bug)", err)
		}
		if c.VCardUID == uid {
			found = true
			if c.AvatarSHA256 != nil {
				t.Errorf("AvatarSHA256 = %v, want nil", *c.AvatarSHA256)
			}
			// contactToVCard must not panic/emit a PHOTO line for a nil avatar.
			vc := contactToVCard(c)
			if strings.Contains(vc, "PHOTO;") {
				t.Errorf("expected no PHOTO line for avatar-less contact, got: %s", vc)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}
	if !found {
		t.Fatal("inserted contact not returned by list query")
	}
}
