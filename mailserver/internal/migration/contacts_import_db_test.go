package migration

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"time"

	"setjoin.com/shared/testsupport"
)

// DB-backed coverage for the contact import seams: the OWNED CSV/VCF entry
// points (R3 in-statement ownership), every duplicate strategy, and the
// connector contact phase's lazily-resolved migration book.

const fullVCard = "BEGIN:VCARD\r\n" +
	"VERSION:3.0\r\n" +
	"UID:vc-full-1\r\n" +
	"N:Doe;Jane;;;\r\n" +
	"ORG:Acme\r\n" +
	"TITLE:CEO\r\n" +
	"NOTE:imported by coverage test\r\n" +
	"EMAIL;TYPE=HOME:jane@example.test\r\n" +
	"TEL;TYPE=CELL:+15550001\r\n" +
	"URL:https://example.test/jane\r\n" +
	"IMPP:sip:jane@example.test\r\n" +
	"ADR;TYPE=HOME:;;1 Main St;Springfield;IL;12345;US\r\n" +
	"BDAY:19800102\r\n" +
	"ANNIVERSARY:20100605\r\n" +
	"END:VCARD\r\n"

// TestImportVCFOwned_StrategiesAndOwnership pins the owned vCard import:
// plain import lands all typed fields, skip/overwrite/rename honor existing
// UIDs, and a foreign owner book yields row errors with zero writes.
func TestImportVCFOwned_StrategiesAndOwnership(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-import-test', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	// Plain owned import: every typed field round-trips into the contacts row.
	imported, skipped, errs := ImportVCFOwned(ctx, pool, fullVCard, bookID, mailboxID, "")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("plain import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	var emails, phones, urls, impps, addresses string
	var displayName *string
	var birthday *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT emails, phones, urls, instant_msgs, addresses, display_name, birthday
		   FROM contacts WHERE addressbook_id=$1 AND vcard_uid='vc-full-1'`,
		bookID).Scan(&emails, &phones, &urls, &impps, &addresses, &displayName, &birthday); err != nil {
		t.Fatalf("read imported contact: %v", err)
	}
	for name, want := range map[string][2]string{
		"emails":    {emails, "jane@example.test"},
		"phones":    {phones, "+15550001"},
		"urls":      {urls, "https://example.test/jane"},
		"impps":     {impps, "sip:jane@example.test"},
		"addresses": {addresses, "Main St"},
	} {
		if !strings.Contains(want[0], want[1]) {
			t.Errorf("%s lost typed values: %s (want substring %q)", name, want[0], want[1])
		}
	}
	if displayName == nil || *displayName != "Jane Doe" {
		t.Errorf("display_name = %q, want parser FN synthesis from N", safeStr(displayName))
	}
	if birthday == nil || birthday.Format("2006-01-02") != "1980-01-02" {
		t.Errorf("birthday = %v, want 1980-01-02", birthday)
	}

	// skip: same UID is skipped, not duplicated.
	imported, skipped, errs = ImportVCFOwned(ctx, pool, fullVCard, bookID, mailboxID, "skip")
	if imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("skip import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}

	// rename: same UID is re-imported under a migrated suffix.
	imported, skipped, errs = ImportVCFOwned(ctx, pool, fullVCard, bookID, mailboxID, "rename")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("rename import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	var renamed int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM contacts WHERE addressbook_id=$1 AND vcard_uid='vc-full-1-migrated'`,
		bookID).Scan(&renamed); err != nil {
		t.Fatalf("read renamed contact: %v", err)
	}
	if renamed != 1 {
		t.Fatalf("rename strategy did not write vc-full-1-migrated (rows=%d)", renamed)
	}

	// overwrite: same UID replaces the original row.
	imported, skipped, errs = ImportVCFOwned(ctx, pool, fullVCard, bookID, mailboxID, "overwrite")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("overwrite import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}

	// Foreign owner: book belongs to a different mailbox → row errors, zero writes.
	imported, skipped, errs = ImportVCFOwned(ctx, pool, fullVCard, bookID, mailboxID+987654, "skip")
	if imported != 0 || len(errs) != 1 {
		t.Fatalf("foreign-owner import: imported=%d errs=%v, want 1 row error and zero writes", imported, errs)
	}
	if !strings.Contains(errs[0], "not owned") && !strings.Contains(errs[0], "owned") {
		t.Fatalf("foreign-owner error = %q, want ownership complaint", errs[0])
	}
}

// TestImportCSVOwned_StrategiesAndOwnership pins the owned CSV import under
// the D-5 stable identity: the default-insert vs (addressbook_id, vcard_uid)
// uniqueness behavior, the REAL skip/overwrite duplicate strategies (skip
// re-import → 0 new rows; overwrite → atomic ownership-scoped in-place update
// preserving the contact id and its group memberships), name edits resolving
// against the defined identity key, blank-email skipping, and foreign-owner
// row errors with zero writes.
func TestImportCSVOwned_StrategiesAndOwnership(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-csv-test', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM contact_groups WHERE mailbox_id=$1`, mailboxID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	const csvData = "name,email,notes\r\n" +
		"Alice One,a1@example.test,original notes\r\n" +
		"Alice Two,a2@example.test,\r\n" +
		"Blank,a3@x.test,\r\n"
	blankRow := "name,email,notes\r\nNobody,,\r\n"
	mapping := Mapping{FullName: 0, Email: 1, Notes: 2}

	imported, skipped, errs := ImportCSVOwned(ctx, pool, csvData, bookID, mailboxID, mapping, "", "")
	if imported != 3 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("csv import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	firstIDs := csvContactIDs(t, pool, bookID) // vcard_uid → contact id

	// A group membership hangs off the first contact — the overwrite pin must
	// prove it survives the in-place update.
	var groupID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO contact_groups (mailbox_id, name) VALUES ($1, 'mig-csv-group') RETURNING id`,
		mailboxID).Scan(&groupID); err != nil {
		t.Fatalf("seed contact group: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO contact_group_members (group_id, contact_id) VALUES ($1, $2)`,
		groupID, firstIDs["a1@example.test"]); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	// Blank email cell is skipped, not imported.
	imported, skipped, errs = ImportCSVOwned(ctx, pool, blankRow, bookID, mailboxID, mapping, "", "")
	if imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("blank-email import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}

	// skip strategy: rows are keyed by the STABLE derived UID (D-5), so a
	// re-import skips every already-imported row — zero new rows, zero errors.
	imported, skipped, errs = ImportCSVOwned(ctx, pool, csvData, bookID, mailboxID, mapping, "skip", "")
	if imported != 0 || skipped != 3 || len(errs) != 0 {
		t.Fatalf("csv skip re-import: imported=%d skipped=%d errs=%v, want 0/3/no errors", imported, skipped, errs)
	}

	// Default-insert strategy keeps plain INSERT semantics: re-importing the
	// same rows collides with the (addressbook_id, vcard_uid) uniqueness
	// constraint and surfaces as per-row errors — deliberately NOT silently
	// skipped, so "" stays distinguishable from "skip".
	imported, skipped, errs = ImportCSVOwned(ctx, pool, csvData, bookID, mailboxID, mapping, "", "")
	if imported != 0 || len(errs) != 3 {
		t.Fatalf("csv default re-import: imported=%d errs=%v, want 0 inserts and 3 duplicate-key row errors", imported, errs)
	}
	for _, e := range errs {
		if !strings.Contains(e, "duplicate key") {
			t.Errorf("default re-import error = %q, want the uniqueness violation", e)
		}
	}

	// overwrite strategy: every row UPSERTS IN PLACE — count stable, contact
	// ids unchanged (memberships preserved), payload refreshed, including a
	// NAME EDIT and a NOTES EDIT that must still resolve against the
	// email-anchored identity.
	edited := strings.Replace(csvData, "Alice One,a1@example.test,original notes",
		"Alice Renamed,a1@example.test,edited notes", 1)
	edited = strings.Replace(edited, "Blank,a3@x.test,", "Blank With Notes,a3@x.test,", 1)
	imported, skipped, errs = ImportCSVOwned(ctx, pool, edited, bookID, mailboxID, mapping, "overwrite", "")
	if imported != 3 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("csv overwrite re-import: imported=%d skipped=%d errs=%v, want 3 in-place updates", imported, skipped, errs)
	}
	if count := csvContactCount(t, pool, bookID); count != 3 {
		t.Fatalf("contacts after skip+default+overwrite re-imports = %d, want 3 (stable identity, no appends)", count)
	}
	afterIDs := csvContactIDs(t, pool, bookID)
	for uid, before := range firstIDs {
		if afterIDs[uid] != before {
			t.Errorf("contact id for %s changed under overwrite: %d → %d (in-place update required)", uid, before, afterIDs[uid])
		}
	}
	var display, notes string
	if err := pool.QueryRow(ctx,
		`SELECT display_name, COALESCE(notes,'') FROM contacts WHERE addressbook_id=$1 AND display_name='Alice Renamed'`,
		bookID).Scan(&display, &notes); err != nil {
		t.Fatalf("read renamed contact: %v", err)
	}
	if display != "Alice Renamed" {
		t.Errorf("name edit did not land in place: display_name=%q", display)
	}
	if notes != "edited notes" {
		t.Errorf("notes edit did not land in place: notes=%q", notes)
	}

	// The membership survived the in-place overwrite (contact id preserved).
	var memberships int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM contact_group_members WHERE group_id=$1 AND contact_id=$2`,
		groupID, firstIDs["a1@example.test"]).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if memberships != 1 {
		t.Fatalf("memberships after overwrite = %d, want 1 (the in-place update must preserve contact ids and memberships)", memberships)
	}

	// Foreign owner: every row errors, zero writes.
	imported, _, errs = ImportCSVOwned(ctx, pool, csvData, bookID, mailboxID+987654, mapping, "", "")
	if imported != 0 || len(errs) != 3 {
		t.Fatalf("csv foreign owner: imported=%d errs=%v, want 3 row errors", imported, errs)
	}
}

// TestImportCSVOwned_OverwriteInvalidatesEtagValidator pins the Astra r2 D-5
// validator contract on the overwrite upsert: a content-changing overwrite
// must regenerate the etag ATOMICALLY in the same statement. The pre-r2 upsert
// refreshed the payload while keeping the old etag, so CardDAV advertised a
// stale validator and a client's If-Match against the pre-import value still
// succeeded — a silent write over the imported edit. Arms: a fresh insert
// carries the closed empty default (no validator was ever advertised); the
// first update introduces a real validator; reads without writes are stable;
// and a second, content-changing overwrite invalidates it. Same regenerate
// form as the reducer's jmap_contact_set_update.
func TestImportCSVOwned_OverwriteInvalidatesEtagValidator(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-etag-test', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	mapping := Mapping{FullName: 0, Email: 1}
	csvOf := func(name string) string {
		return "name,email\r\n" + name + ",etag-user@example.test\r\n"
	}
	// The imported row's stable selector: the stored email cell inside the
	// contacts.emails JSONB — immune to the display-name edits the test makes.
	contactField := func(field string) string {
		t.Helper()
		var got string
		if err := pool.QueryRow(ctx,
			`SELECT COALESCE(`+field+`,'') FROM contacts
			   WHERE addressbook_id=$1 AND emails->0->>'address' = 'etag-user@example.test'`,
			bookID).Scan(&got); err != nil {
			t.Fatalf("read imported contact (%s): %v", field, err)
		}
		return got
	}

	// Fresh insert: no etag has ever been advertised for this resource, and
	// the '' default fails every If-Match closed (matchETag against '' never
	// equals a client-held validator).
	imported, skipped, errs := ImportCSVOwned(ctx, pool, csvOf("Etag Before"), bookID, mailboxID, mapping, "overwrite", "")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("initial overwrite-import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	if got := contactField("etag"); got != "" {
		t.Errorf("fresh-insert etag = %q, want the closed '' default (no validator advertised before the first update)", got)
	}

	// First content-changing overwrite: the validator must now exist — an
	// updated resource with no etag would leave CardDAV clients unable to
	// precondition anything.
	imported, skipped, errs = ImportCSVOwned(ctx, pool, csvOf("Etag Renamed Once"), bookID, mailboxID, mapping, "overwrite", "")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("first overwrite: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	first := contactField("etag")
	if first == "" {
		t.Fatal("content-changing overwrite left etag empty — CardDAV would advertise no validator for an updated resource")
	}
	// Stable when unchanged: reads without any write return the same validator.
	if again := contactField("etag"); again != first {
		t.Errorf("etag drifted without a write: %q → %q (validators must be stable across reads)", first, again)
	}

	// Second content-changing overwrite: the validator MUST be invalidated in
	// the same statement that changes the content — the stale-If-Match hole.
	imported, skipped, errs = ImportCSVOwned(ctx, pool, csvOf("Etag Renamed Twice"), bookID, mailboxID, mapping, "overwrite", "")
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("second overwrite: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}
	second := contactField("etag")
	if second == "" {
		t.Fatal("second content-changing overwrite left etag empty")
	}
	if second == first {
		t.Fatal("content-changing overwrite kept the old etag — CardDAV advertises a stale validator and If-Match accepts writes over the imported edit (D-5 r2)")
	}

	// Non-vacuous: the payload really changed (the update ran; the etag verdict
	// is not comparing two no-op writes).
	if displayName := contactField("display_name"); displayName != "Etag Renamed Twice" {
		t.Errorf("display_name = %q, want the final overwrite's content", displayName)
	}
}

// TestImportCSVOwned_IdentityAndBooks pins the D-5 identity key's DB-visible
// behavior: email-case variants dedupe, repeated rows inside ONE file behave
// per strategy (skip dedupes, default errors the duplicate, overwrite
// collapses in place), mapping overrides re-anchor identity, and separate
// address books are independent identity namespaces.
func TestImportCSVOwned_IdentityAndBooks(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	books := make([]int64, 2)
	// Cleanup is registered BEFORE any book insert (CONTACTS-002 r2 finding 3
	// pattern): a mid-loop seeding failure must not leak the books already
	// created. Zero-valued entries (a book whose insert failed) delete nothing.
	t.Cleanup(func() {
		for _, b := range books {
			_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, b)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE mailbox_id=$1`, mailboxID)
	})
	for i, name := range []string{"mig-csv-books-a", "mig-csv-books-b"} {
		// Only one default book per mailbox (addressbooks_default_idx): the
		// second book is deliberately non-default.
		if err := pool.QueryRow(ctx,
			`INSERT INTO addressbooks (mailbox_id, name, is_default)
			 VALUES ($1, $2, $3) RETURNING id`, mailboxID, name, i == 0).Scan(&books[i]); err != nil {
			t.Fatalf("seed address book %s: %v", name, err)
		}
	}
	bookA, bookB := books[0], books[1]
	mapping := Mapping{FullName: 0, Email: 1}

	// Email-case variants are the SAME identity: skip must dedupe across case.
	caseCSV := "name,email\r\nCase Person,Up@Example.TEST\r\n"
	if imported, _, errs := ImportCSVOwned(ctx, pool, caseCSV, bookA, mailboxID, mapping, "", ""); imported != 1 || len(errs) != 0 {
		t.Fatalf("case-variant first import = (%d,%v), want 1 imported", imported, errs)
	}
	if imported, skipped, errs := ImportCSVOwned(ctx, pool, strings.Replace(caseCSV, "Up@Example.TEST", "up@example.test", 1), bookA, mailboxID, mapping, "skip", ""); imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("case-variant skip re-import = (%d,%d,%v), want 0 imported / 1 skipped", imported, skipped, errs)
	}

	// Repeated rows in ONE file: skip dedupes, default surfaces the duplicate
	// as a row error, overwrite collapses to one in-place row.
	const dupCSV = "name,email\r\nDup Person,dup@example.test\r\nDup Person,dup@example.test\r\n"
	if imported, skipped, errs := ImportCSVOwned(ctx, pool, dupCSV, bookA, mailboxID, mapping, "skip", ""); imported != 1 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("repeated-row skip = (%d,%d,%v), want 1 imported / 1 skipped", imported, skipped, errs)
	}
	if imported, _, errs := ImportCSVOwned(ctx, pool, dupCSV, bookA, mailboxID, mapping, "", ""); imported != 0 || len(errs) != 2 {
		t.Fatalf("repeated-row default = (%d,%v), want 0 imported / 2 duplicate-key errors", imported, errs)
	}
	if imported, _, errs := ImportCSVOwned(ctx, pool, dupCSV, bookA, mailboxID, mapping, "overwrite", ""); imported != 2 || len(errs) != 0 {
		t.Fatalf("repeated-row overwrite = (%d,%v), want both rows applied in place", imported, errs)
	}
	if n := csvContactCount(t, pool, bookA); n != 2 {
		t.Fatalf("book A contacts = %d, want 2 (case + dup collapsed)", n)
	}

	// Mapping overrides re-anchor the identity: identity is computed from the
	// OVERRIDE-selected column. Overriding to a cell holding the SAME address
	// dedupes; overriding to a cell holding a DIFFERENT address re-identifies.
	const mappedCSV = "name,email,alt\r\nMap Person,map@example.test,map@example.test\r\n"
	if imported, _, errs := ImportCSVOwned(ctx, pool, mappedCSV, bookA, mailboxID, mapping, "skip", ""); imported != 1 || len(errs) != 0 {
		t.Fatalf("mapping first import = (%d,%v), want 1 imported", imported, errs)
	}
	overrideAlt := Mapping{FullName: 0, Email: 2}
	if imported, skipped, errs := ImportCSVOwned(ctx, pool, mappedCSV, bookA, mailboxID, overrideAlt, "skip", ""); imported != 0 || skipped != 1 {
		t.Fatalf("override-to-same-address-cell skip = (%d,%d,%v), want 0 imported / 1 skipped", imported, skipped, errs)
	}
	const altCSV = "name,email,alt\r\nMap Person,map@example.test,other@example.test\r\n"
	altImported, _, altErrs := ImportCSVOwned(ctx, pool, altCSV, bookA, mailboxID, overrideAlt, "", "")
	if altImported != 1 || len(altErrs) != 0 {
		t.Fatalf("override-to-different-address-cell import = (%d,%v), want a NEW contact (different identity)", altImported, altErrs)
	}
	if n := csvContactCount(t, pool, bookA); n != 4 {
		t.Fatalf("book A contacts after override = %d, want 4", n)
	}

	// Separate address books are independent namespaces: the SAME row imports
	// into book B untouched by book A's rows, and skip there only sees B.
	sameRow := "name,email\r\nAlice One,a1@books.example\r\n"
	if imported, _, errs := ImportCSVOwned(ctx, pool, sameRow, bookA, mailboxID, mapping, "", ""); imported != 1 || len(errs) != 0 {
		t.Fatalf("book A import = (%d,%v), want 1", imported, errs)
	}
	if imported, _, errs := ImportCSVOwned(ctx, pool, sameRow, bookB, mailboxID, mapping, "", ""); imported != 1 || len(errs) != 0 {
		t.Fatalf("book B import = (%d,%v), want its own row (books are independent namespaces)", imported, errs)
	}
	if imported, skipped, errs := ImportCSVOwned(ctx, pool, sameRow, bookB, mailboxID, mapping, "skip", ""); imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("book B skip re-import = (%d,%d,%v), want 0/1", imported, skipped, errs)
	}
}

// TestImportCSVOwned_DialectRoundTripStableIdentity pins the dialect axis of
// the identity definition: a Setjoin export (formula-neutralization escaped)
// re-imported under dialect CSVDialectSetjoin decodes to the original values
// AND the same stable identity — a second identical re-import with skip
// dedupes to zero new rows.
func TestImportCSVOwned_DialectRoundTripStableIdentity(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-csv-dialect', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	exported, err := ExportCSV([]ExportContact{
		{FirstName: "=", LastName: "Smith", FullName: "+Alice Smith", Email: "alice@dialect.test",
			Phone: "-1555", Notes: "'quoted"},
	})
	if err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	headers, err := CSVHeaders(exported)
	if err != nil {
		t.Fatalf("export headers: %v", err)
	}
	mapping := DetectMapping(headers)

	imported, skipped, errs := ImportCSVOwned(ctx, pool, exported, bookID, mailboxID, mapping, "", CSVDialectSetjoin)
	if imported != 1 || skipped != 0 || len(errs) != 0 {
		t.Fatalf("dialect import: imported=%d skipped=%d errs=%v", imported, skipped, errs)
	}

	// Decoding inverted the export escaping: the stored payload equals the
	// ORIGINAL cell values, not the escaped forms.
	var firstName, notes string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(first_name,''), COALESCE(notes,'') FROM contacts WHERE addressbook_id=$1`,
		bookID).Scan(&firstName, &notes); err != nil {
		t.Fatalf("read round-tripped contact: %v", err)
	}
	if firstName != "=" || notes != "'quoted" {
		t.Errorf("dialect round trip stored (%q,%q), want the unescaped (\"=\",\"'quoted\")", firstName, notes)
	}

	// The identity survived the escape/unescape round trip: an identical
	// re-import with skip dedupes to zero new rows.
	if imported, skipped, errs := ImportCSVOwned(ctx, pool, exported, bookID, mailboxID, mapping, "skip", CSVDialectSetjoin); imported != 0 || skipped != 1 || len(errs) != 0 {
		t.Fatalf("dialect skip re-import = (%d,%d,%v), want 0 imported / 1 skipped", imported, skipped, errs)
	}
}

// csvContactCount returns the number of contacts in a book.
func csvContactCount(t *testing.T, pool *pgxpool.Pool, bookID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM contacts WHERE addressbook_id=$1`, bookID).Scan(&n); err != nil {
		t.Fatalf("count contacts in book %d: %v", bookID, err)
	}
	return n
}

// csvContactIDs maps each contact's email-cell identity (its first email
// address) to its id, so in-place-update assertions compare ids across
// imports.
func csvContactIDs(t *testing.T, pool *pgxpool.Pool, bookID int64) map[string]int64 {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT emails->0->>'address', id FROM contacts WHERE addressbook_id=$1`, bookID)
	if err != nil {
		t.Fatalf("list contact ids: %v", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var email string
		var id int64
		if err := rows.Scan(&email, &id); err != nil {
			t.Fatalf("scan contact id: %v", err)
		}
		out[email] = id
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate contact ids: %v", err)
	}
	return out
}

// TestOrchestratorConnectorContactPhaseResolvesMigrationBook pins the
// CONTACTS-002 r2 connector path: with the source-identity toggle OFF, a
// contact item resolves the target mailbox's default book lazily (cached
// across items) and imports through the OWNED vCard wrapper.
func TestOrchestratorConnectorContactPhaseResolvesMigrationBook(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	// Toggle explicitly OFF (absent = off; set FALSE to survive a shared DB
	// where another test may have flipped it globally).
	testsupport.SetFeatureToggleForTest(t, pool, "feature.mail_migration_source_identity", false)
	userID, _, mailboxID := adminStartFixture(t, pool)
	ctx := t.Context()

	var bookID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-connector-test', TRUE) RETURNING id`, mailboxID).Scan(&bookID); err != nil {
		t.Fatalf("seed default address book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM contacts WHERE addressbook_id=$1`, bookID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, bookID)
	})

	var jobID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO migration_jobs(user_id,source_type,source_config_enc,target_mailbox_id,status,resume_cursor)
		VALUES($1,'ews',$2,$3,'pending',$4) RETURNING id`,
		userID, []byte("encrypted-fixture"), mailboxID, `{}`,
	).Scan(&jobID); err != nil {
		t.Fatal(err)
	}

	session := &scriptedSourceSession{batches: []SourceBatch{{
		Items: []SourceItem{
			{Type: ItemContact, Change: SourceUpsert,
				SourceObjectID: "contact-1", SourceVersion: "v1",
				RawVCF: fullVCard},
			// A second contact in the same batch exercises the cached
			// migration-book resolution (the second item must not re-query).
			{Type: ItemContact, Change: SourceUpsert,
				SourceObjectID: "contact-2", SourceVersion: "v1",
				RawVCF: strings.Replace(fullVCard, "vc-full-1", "vc-full-2", 1)},
		},
	}}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	orchestrator := NewOrchestrator(pool, nil, "", "coverage-root", logger, ctx, &terminalDispatchSpy{})
	js := &jobState{pauseCh: make(chan struct{}, 1), pauseAck: make(chan struct{}, 1), resumeCh: make(chan struct{}, 1)}

	if err := orchestrator.runConnectorPhase(ctx, jobID, session, orchestrator.loadLegacySourceResume(ctx, jobID), js); err != nil {
		t.Fatalf("connector contact phase: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM contacts WHERE addressbook_id=$1 AND vcard_uid IN ('vc-full-1','vc-full-2')`,
		bookID).Scan(&count); err != nil {
		t.Fatalf("read imported connector contacts: %v", err)
	}
	if count != 2 {
		t.Fatalf("connector contact import landed %d rows, want 2", count)
	}

	// A target mailbox with NO default address book must fail the contact item
	// explicitly (never fall back to the unscoped wrapper).
	booklessUser, _, booklessMailbox := adminStartFixture(t, pool)
	var booklessJob int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO migration_jobs(user_id,source_type,source_config_enc,target_mailbox_id,status,resume_cursor)
		VALUES($1,'ews',$2,$3,'pending',$4) RETURNING id`,
		booklessUser, []byte("encrypted-fixture"), booklessMailbox, `{}`,
	).Scan(&booklessJob); err != nil {
		t.Fatal(err)
	}
	booklessSession := &scriptedSourceSession{batches: []SourceBatch{{
		Items: []SourceItem{{
			Type: ItemContact, Change: SourceUpsert,
			SourceObjectID: "contact-x", SourceVersion: "v1",
			RawVCF: fullVCard,
		}},
	}}}
	err := orchestrator.runConnectorPhase(ctx, booklessJob, booklessSession,
		orchestrator.loadLegacySourceResume(ctx, booklessJob), js)
	if err == nil || !strings.Contains(err.Error(), "no default address book") {
		t.Fatalf("bookless mailbox phase err = %v, want explicit no-default-book failure", err)
	}
}

// TestDefaultAddressBookIDForMailbox pins the mailbox-scoped default-book
// resolution: the mailbox's own default book is returned; a mailbox with no
// default book yields (0, nil) for the caller to turn into a phase error.
func TestDefaultAddressBookIDForMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _, mailboxID := adminStartFixture(t, pool)
	o := &Orchestrator{pool: pool}

	// No default book yet → (0, nil).
	id, err := o.defaultAddressBookIDForMailbox(ctx, mailboxID)
	if err != nil || id != 0 {
		t.Fatalf("no-book resolution = (%d,%v), want (0,nil)", id, err)
	}

	var seeded int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-default-test', TRUE) RETURNING id`, mailboxID).Scan(&seeded); err != nil {
		t.Fatalf("seed default book: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM addressbooks WHERE id=$1`, seeded)
	})

	id, err = o.defaultAddressBookIDForMailbox(ctx, mailboxID)
	if err != nil || id != seeded {
		t.Fatalf("resolution = (%d,%v), want (%d,nil)", id, err, seeded)
	}

	// A non-default book must not satisfy the resolution.
	if _, err := pool.Exec(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default)
		 VALUES ($1, 'mig-nondefault-test', FALSE)`, mailboxID); err != nil {
		t.Fatalf("seed non-default book: %v", err)
	}
	id, err = o.defaultAddressBookIDForMailbox(ctx, mailboxID)
	if err != nil || id != seeded {
		t.Fatalf("resolution with extra books = (%d,%v), want (%d,nil)", id, err, seeded)
	}
}

// safeStr dereferences an optional string for readable failure output.
func safeStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// refusedMigPool returns a lazily-connected pool whose first acquire fails,
// for exercising DB-error branches without touching data.
func refusedMigPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"postgres://migtest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New(refused): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestDefaultAddressBookIDForMailbox_DBErrorFailsPhase pins the generic
// resolution-error branch: an unreachable database surfaces the query error.
func TestDefaultAddressBookIDForMailbox_DBErrorFailsPhase(t *testing.T) {
	o := &Orchestrator{pool: refusedMigPool(t)}
	if _, err := o.defaultAddressBookIDForMailbox(context.Background(), 1); err == nil {
		t.Fatal("resolution on broken pool: want error")
	}
}

// TestImportVCF_DBErrorSurfacesAsRowErrors pins the insert-error branch: an
// unreachable database turns every card into a row error, never a panic and
// never a silent success.
func TestImportVCF_DBErrorSurfacesAsRowErrors(t *testing.T) {
	imported, skipped, errs := ImportVCFOwned(context.Background(), refusedMigPool(t), fullVCard, 1, 1, "")
	if imported != 0 || skipped != 0 || len(errs) != 1 {
		t.Fatalf("broken-pool import: imported=%d skipped=%d errs=%v, want one row error", imported, skipped, errs)
	}
}
