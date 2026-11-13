package migration

import (
	"context"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/carddav"
	"setjoin.com/shared/testsupport"
)

// DB-backed coverage for the contactStore.upsert seam (the CSV "overwrite"
// strategy's statement) and the unidentifiable-row skip in the CSV loop.

// TestContactStoreUpsert_TypedDatesAndNameFallback pins the upsert's typed
// date arms (BDAY/ANNIVERSARY) and the FN-empty fallback to N: a card with
// no FN stores N as the display name, carries both dates, and a second
// upsert of the same UID updates IN PLACE (one row, refreshed payload,
// dates preserved).
func TestContactStoreUpsert_TypedDatesAndNameFallback(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-upsert-gap-test', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	birthday := time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)
	anniversary := time.Date(2010, 6, 5, 0, 0, 0, 0, time.UTC)
	vc := carddav.VCard{
		UID:         "vc-upsert-gap-1",
		N:           "Doe;Jane;;;",
		ORG:         "Acme",
		Emails:      []carddav.VCardValue{{Type: "work", Value: "jane@upsert-gap.test"}},
		Birthday:    &birthday,
		Anniversary: &anniversary,
	}
	store := contactStore{pool: pool, ownerMailboxID: mailboxID}

	// First upsert: absent row inserts.
	if err := store.upsert(ctx, bookID, &vc); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	var displayName string
	var storedBirthday, storedAnniversary *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT display_name, birthday, anniversary FROM contacts
		   WHERE addressbook_id=$1 AND vcard_uid='vc-upsert-gap-1'`,
		bookID).Scan(&displayName, &storedBirthday, &storedAnniversary); err != nil {
		t.Fatalf("read upserted contact: %v", err)
	}
	// FN empty → N ("Doe;Jane;;;") is the stored display name.
	if displayName != "Doe;Jane;;;" {
		t.Errorf("display_name = %q, want the N fallback \"Doe;Jane;;;\"", displayName)
	}
	if storedBirthday == nil || storedBirthday.Format("2006-01-02") != "1980-01-02" {
		t.Errorf("birthday = %v, want 1980-01-02", storedBirthday)
	}
	if storedAnniversary == nil || storedAnniversary.Format("2006-01-02") != "2010-06-05" {
		t.Errorf("anniversary = %v, want 2010-06-05", storedAnniversary)
	}

	// Second upsert of the SAME UID: the conflict arm updates in place —
	// one row, refreshed payload, typed dates preserved.
	vc.ORG = "Acme Rewritten"
	if err := store.upsert(ctx, bookID, &vc); err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	var count int
	var org string
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*), MAX(COALESCE(company,'')) FROM contacts
		   WHERE addressbook_id=$1 AND vcard_uid='vc-upsert-gap-1'`,
		bookID).Scan(&count, &org); err != nil {
		t.Fatalf("count upserted contacts: %v", err)
	}
	if count != 1 || org != "Acme Rewritten" {
		t.Errorf("second upsert: rows=%d company=%q, want one in-place row with the refreshed org", count, org)
	}
	if err := pool.QueryRow(ctx,
		`SELECT birthday, anniversary FROM contacts
		   WHERE addressbook_id=$1 AND vcard_uid='vc-upsert-gap-1'`,
		bookID).Scan(&storedBirthday, &storedAnniversary); err != nil {
		t.Fatalf("re-read upserted contact: %v", err)
	}
	if storedBirthday == nil || storedBirthday.Format("2006-01-02") != "1980-01-02" {
		t.Errorf("birthday lost on update: %v", storedBirthday)
	}
}

// TestContactStoreUpsert_DBErrorSurfaces pins the upsert error branch: an
// unreachable database surfaces the statement error to the import loop,
// never a silent success.
func TestContactStoreUpsert_DBErrorSurfaces(t *testing.T) {
	store := contactStore{pool: refusedMigPool(t), ownerMailboxID: 1}
	vc := carddav.VCard{UID: "vc-upsert-gap-err", FN: "Jane Doe", N: "Doe;Jane;;;"}
	if err := store.upsert(context.Background(), 1, &vc); err == nil {
		t.Fatal("broken-pool upsert: want an error")
	}
}

// TestImportCSVOwned_UnidentifiableRowSkipped pins the third skip arm of the
// CSV loop: a ragged row SHORTER than the mapped email column bypasses the
// blank-email skip, and with no email and no name to fall back on, the row
// has no decodable identity and is skipped — not inserted as an
// unmatchable duplicate.
func TestImportCSVOwned_UnidentifiableRowSkipped(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-csv-unidentifiable', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	// Data row is two EMPTY cells — shorter than the email column at index 2,
	// and carrying no name in the mapped first/last columns.
	const csvData = "First Name,Last Name,E-mail Address\r\n,\r\n"
	mapping := Mapping{FullName: -1, FirstName: 0, LastName: 1, Email: 2, Company: -1, JobTitle: -1, Phone: -1, Notes: -1}

	imported, skipped, errs := ImportCSVOwned(ctx, pool, csvData, bookID, mailboxID, mapping, "", "")
	if imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("unidentifiable row: imported=%d skipped=%d errs=%v, want 0/1/no errors", imported, skipped, errs)
	}
	if n := csvContactCount(t, pool, bookID); n != 0 {
		t.Fatalf("unidentifiable row wrote %d contact(s), want zero", n)
	}
}
