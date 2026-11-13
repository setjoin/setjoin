package contacts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

func testClaims(uid int64) *auth.Claims {
	return &jwtutil.Claims{UserID: uid, Email: "t@t.com", Type: jwtutil.TypeAccess}
}

// multipartCSV builds a multipart/form-data body with one "file" part containing csv.
func multipartCSV(t *testing.T, csv string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", "contacts.csv")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write([]byte(csv)); err != nil {
		t.Fatalf("write file: %v", err)
	}
	_ = w.Close()
	return &body, w.FormDataContentType()
}

// TestPreviewCSV exercises the pool-free preview path: it returns detected headers,
// auto-mapping, and a sample of the first rows.
func TestPreviewCSV(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	body, ct := multipartCSV(t, "First Name,Last Name,E-mail Address\nAlice,Smith,a@x.test\n")
	req := httptest.NewRequest(http.MethodPost, "/contacts/import/csv/preview", body)
	req.Header.Set("Content-Type", ct)
	req = req.WithContext(auth.ContextWithUser(req.Context(), testClaims(5601)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Headers []string
		Mapping migration.Mapping
		Sample  [][]string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Mapping.Email != 2 {
		t.Errorf("Mapping.Email = %d, want 2", resp.Mapping.Email)
	}
	if len(resp.Headers) != 3 {
		t.Errorf("len(Headers) = %d, want 3", len(resp.Headers))
	}
	if len(resp.Sample) != 1 {
		t.Errorf("len(Sample) = %d, want 1", len(resp.Sample))
	}
}

// TestPreviewRequiresAuth confirms an unauthenticated preview is rejected.
func TestPreviewRequiresAuth(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	body, ct := multipartCSV(t, "First Name\nAlice\n")
	req := httptest.NewRequest(http.MethodPost, "/contacts/import/csv/preview", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestUnknownRouteNotFound confirms an unrelated suffix 404s.
func TestUnknownRouteNotFound(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/contacts/import/bogus", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), testClaims(1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestExportVCFRequiresAuth confirms the vCard export route is wired (not a 404)
// and rejects an unauthenticated caller, mirroring TestPreviewRequiresAuth.
func TestExportVCFRequiresAuth(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/contacts/export/vcf?addressBookId=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestExportContactVCFRequiresAuth confirms the single-contact "forward as vCard"
// branch (?contactId=) rejects an unauthenticated caller before touching the DB.
func TestExportContactVCFRequiresAuth(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/contacts/export/vcf?contactId=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestExportContactVCFNoDatabase confirms an authenticated request with no pool
// (the pool-free unit-test configuration) fails closed with 500 rather than a panic,
// mirroring the pool==nil guard shared with importCSV/exportAddressBook.
func TestExportContactVCFNoDatabase(t *testing.T) {
	h := NewImportHandler(nil, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/contacts/export/vcf?contactId=1", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), testClaims(1)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestVCFFilename covers the slug fallback for an empty/all-punctuation display name
// and the happy path, since it's the one piece of new logic with real branches.
func TestVCFFilename(t *testing.T) {
	cases := map[string]string{
		"Alice Smith": "alice-smith.vcf",
		"  ***  ":     "contact.vcf",
		"":            "contact.vcf",
		"Bob-O'Brien": "bob-o-brien.vcf",
	}
	for in, want := range cases {
		if got := vcfFilename(in); got != want {
			t.Errorf("vcfFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- DB-backed import ownership tests (R3 hardening, D-MAILSERVER-INTERNAL-CONTACTS-002) ---
//
// Same convention as the DB-backed tests in sibling packages (carddav, spam,
// webhook): testsupport.OpenTestPool (DB_DSN; skip when unset, fail-closed
// under REQUIRE_DB) + the mk_account SQL fixture from sql/tests/_fixtures.sql.

const importTestCSV = "First Name,Last Name,E-mail Address\nAlice,Smith,alice@x.test\n"

const importTestVCF = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:import-test-uid-1\r\nFN:Bob VCF\r\nN:VCF;Bob;;;\r\nEMAIL;TYPE=INTERNET:bob@x.test\r\nEND:VCARD\r\n"

// importTenant is one seeded account: a user, their mailbox and one address book.
type importTenant struct {
	userID    int64
	mailboxID int64
	bookID    int64
}

// importLookupUser reads the owner of a freshly created mailbox. It is a
// variable solely so TestSeedImportTenantCleanupRecoversOwnerWhenLookupFails
// can fail this lookup immediately after mk_account (the CONTACTS-002 r3 leak
// scenario) while every other test keeps running the real query.
var importLookupUser = func(ctx context.Context, pool *pgxpool.Pool, mailboxID int64) (int64, error) {
	var uid int64
	err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, mailboxID).Scan(&uid)
	return uid, err
}

// seedImportTenant creates an isolated two-tenant fixture via mk_account and
// registers cleanup that fully removes its rows. Cleanup (CONTACTS-002 r3) is
// self-sufficient: it does NOT trust tn.userID, which stays zero whenever the
// post-mk_account owner lookup fails. It deletes the mailboxes with RETURNING
// user_id and removes exactly the owners actually returned (plus tn.userID as
// a deduped fallback should the mailbox row already be gone); a zero cached id
// contributes nothing, preserving the established zero-deletes-nothing guard.
// The deletes still run in ONE transaction in this order: address books first
// (their state-bump trigger needs the mailbox row still present), then the
// mailboxes, then the users — the deferred trg_mailbox_primary_enforce_delete
// check evaluates at COMMIT, where the user no longer exists, and the
// users-delete SET NULL finds no surviving mailbox rows. Fixture ids come from
// sequences, so runs never collide.
func seedImportTenant(t *testing.T, pool *pgxpool.Pool, label string) importTenant {
	t.Helper()
	ctx := context.Background()
	var tn importTenant
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, label).Scan(&tn.mailboxID); err != nil {
		t.Fatalf("mk_account(%s): %v", label, err)
	}
	// Cleanup is registered IMMEDIATELY after the account exists (CONTACTS-002
	// r2 finding 3): mk_account commits, so any later setup failure (user read,
	// book insert) previously leaked the account rows.
	t.Cleanup(func() {
		cctx := context.Background()
		tx, err := pool.Begin(cctx)
		if err != nil {
			t.Errorf("cleanup begin: %v", err)
			return
		}
		if _, err := tx.Exec(cctx, `DELETE FROM addressbooks WHERE mailbox_id = $1`, tn.mailboxID); err != nil {
			t.Errorf("cleanup addressbooks: %v", err)
			_ = tx.Rollback(cctx)
			return
		}
		// Recover the owner HERE rather than trusting tn.userID (CONTACTS-002
		// r3): a zero cached id would miss the real user, the surviving user
		// would keep no primary mailbox, and the deferred
		// trg_mailbox_primary_enforce_delete would raise BZ013 at COMMIT —
		// rolling back the whole cleanup transaction and retaining every
		// fixture row.
		rows, err := tx.Query(cctx, `DELETE FROM mailboxes WHERE id = $1 RETURNING user_id`, tn.mailboxID)
		if err != nil {
			t.Errorf("cleanup mailboxes: %v", err)
			_ = tx.Rollback(cctx)
			return
		}
		var ownerIDs []int64
		for rows.Next() {
			var uid int64
			if err := rows.Scan(&uid); err != nil {
				t.Errorf("cleanup scan owner: %v", err)
				rows.Close()
				_ = tx.Rollback(cctx)
				return
			}
			if uid != 0 { // zero-value guard deletes nothing
				ownerIDs = append(ownerIDs, uid)
			}
		}
		if err := rows.Err(); err != nil {
			t.Errorf("cleanup mailbox owners: %v", err)
			rows.Close()
			_ = tx.Rollback(cctx)
			return
		}
		rows.Close()
		// Fallback for a mailbox row already gone (empty RETURNING): the
		// cached id still deletes its user. Deduped so the second DELETE
		// simply matches nothing.
		dup := false
		for _, uid := range ownerIDs {
			if uid == tn.userID {
				dup = true
				break
			}
		}
		if tn.userID != 0 && !dup {
			ownerIDs = append(ownerIDs, tn.userID)
		}
		for _, uid := range ownerIDs {
			if _, err := tx.Exec(cctx, `DELETE FROM users WHERE id = $1`, uid); err != nil {
				t.Errorf("cleanup user %d: %v", uid, err)
				_ = tx.Rollback(cctx)
				return
			}
		}
		if err := tx.Commit(cctx); err != nil {
			t.Errorf("cleanup commit: %v", err)
		}
	})
	// A failed owner lookup is tolerated, not fatal (CONTACTS-002 r3): cleanup
	// recovers the owner from the mailboxes DELETE itself, so the fixture can
	// no longer leak over an unavailable lookup. tn.userID stays zero and the
	// established zero-deletes-nothing convention keeps covering the books.
	if uid, err := importLookupUser(ctx, pool, tn.mailboxID); err != nil {
		t.Logf("read user_id for %s (cleanup recovers the owner itself): %v", label, err)
	} else {
		tn.userID = uid
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name, is_default, is_shared)
		 VALUES ($1, $2, true, false) RETURNING id`, tn.mailboxID, label+"-book",
	).Scan(&tn.bookID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}
	return tn
}

// contactCount returns the number of contacts in a book (the no-op assertion).
func contactCount(t *testing.T, pool *pgxpool.Pool, bookID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM contacts WHERE addressbook_id = $1`, bookID).Scan(&n); err != nil {
		t.Fatalf("count contacts in book %d: %v", bookID, err)
	}
	return n
}

// seedContact inserts one contact directly into a book, bypassing the import
// paths under test so a test controls exactly what a foreign book contains.
func seedContact(t *testing.T, pool *pgxpool.Pool, bookID int64, uid, displayName string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES ($1, $2, $3)`,
		bookID, uid, displayName); err != nil {
		t.Fatalf("seed contact %q in book %d: %v", uid, bookID, err)
	}
}

// contactDisplayName reads one contact's display name — the undisturbed-row
// assertion for a foreign book that must not be observed or modified.
func contactDisplayName(t *testing.T, pool *pgxpool.Pool, bookID int64, uid string) string {
	t.Helper()
	var name string
	if err := pool.QueryRow(context.Background(),
		`SELECT display_name FROM contacts WHERE addressbook_id = $1 AND vcard_uid = $2`,
		bookID, uid).Scan(&name); err != nil {
		t.Fatalf("read contact %q in book %d: %v", uid, bookID, err)
	}
	return name
}

// contactUID reads the vcard_uid of the single contact in a book (callers
// assert the count first) — the rename-strategy observable.
func contactUID(t *testing.T, pool *pgxpool.Pool, bookID int64) string {
	t.Helper()
	var uid string
	if err := pool.QueryRow(context.Background(),
		`SELECT vcard_uid FROM contacts WHERE addressbook_id = $1 LIMIT 1`,
		bookID).Scan(&uid); err != nil {
		t.Fatalf("read contact uid in book %d: %v", bookID, err)
	}
	return uid
}

// multipartImport builds a multipart/form-data body with one "file" part plus
// the given text form fields (addressBookId/strategy/dialect/mapping).
func multipartImport(t *testing.T, filename, data string, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write([]byte(data)); err != nil {
		t.Fatalf("write file: %v", err)
	}
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return &body, w.FormDataContentType()
}

// postImport runs one authenticated import request against the handler.
func postImport(t *testing.T, h *ImportHandler, path string, own importTenant, filename, data string, fields map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := multipartImport(t, filename, data, fields)
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", ct)
	req = req.WithContext(auth.ContextWithUser(req.Context(), testClaims(own.userID)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestImportCSVForeignBookRejected proves the handler-level R3 shape: a request
// whose addressBookId points at ANOTHER user's address book is rejected 403
// before any statement runs, and the cross-tenant id injected into the request
// creates no rows (no-op, not a partial import).
func TestImportCSVForeignBookRejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-csv-own")
	foreign := seedImportTenant(t, pool, "contacts-csv-foreign")

	h := NewImportHandler(pool, slog.Default())
	rec := postImport(t, h, "/contacts/import/csv", own, "contacts.csv", importTestCSV,
		map[string]string{"addressBookId": strconv.FormatInt(foreign.bookID, 10)})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if n := contactCount(t, pool, foreign.bookID); n != 0 {
		t.Errorf("foreign book contacts = %d, want 0 (cross-tenant import must not create rows)", n)
	}
	if n := contactCount(t, pool, own.bookID); n != 0 {
		t.Errorf("own book contacts = %d, want 0", n)
	}
}

// TestImportVCFForeignBookRejected mirrors the CSV rejection for the vCard
// import route: another tenant's addressBookId is a 403 and writes nothing.
func TestImportVCFForeignBookRejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-vcf-own")
	foreign := seedImportTenant(t, pool, "contacts-vcf-foreign")

	h := NewImportHandler(pool, slog.Default())
	rec := postImport(t, h, "/contacts/import/vcf", own, "contacts.vcf", importTestVCF,
		map[string]string{"addressBookId": strconv.FormatInt(foreign.bookID, 10)})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if n := contactCount(t, pool, foreign.bookID); n != 0 {
		t.Errorf("foreign book contacts = %d, want 0 (cross-tenant import must not create rows)", n)
	}
}

// TestImportOwnedStatementsRejectCrossTenantBook proves the in-statement R3
// enforcement directly, bypassing the HTTP gate: even when a caller pairs
// ANOTHER tenant's addressBookId with its OWN gate-verified mailbox (the
// mid-import re-parent/deletion shape the prior check-then-act gate could not
// close), the Owned import variants must insert nothing and report the book as
// not owned rather than silently succeeding.
func TestImportOwnedStatementsRejectCrossTenantBook(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-stmt-own")
	foreign := seedImportTenant(t, pool, "contacts-stmt-foreign")
	ctx := context.Background()

	imported, _, errs := migration.ImportCSVOwned(ctx, pool, importTestCSV, foreign.bookID, own.mailboxID, migration.Mapping{Email: -1}, "", "")
	if imported != 0 {
		t.Errorf("ImportCSVOwned imported = %d, want 0", imported)
	}
	if len(errs) == 0 {
		t.Error("ImportCSVOwned errs is empty, want an address-book-not-owned row error")
	}
	if n := contactCount(t, pool, foreign.bookID); n != 0 {
		t.Errorf("foreign book contacts = %d after ImportCSVOwned, want 0", n)
	}

	vimported, _, verrs := migration.ImportVCFOwned(ctx, pool, importTestVCF, foreign.bookID, own.mailboxID, "")
	if vimported != 0 {
		t.Errorf("ImportVCFOwned imported = %d, want 0", vimported)
	}
	if len(verrs) == 0 {
		t.Error("ImportVCFOwned errs is empty, want an address-book-not-owned row error")
	}
	if n := contactCount(t, pool, foreign.bookID); n != 0 {
		t.Errorf("foreign book contacts = %d after ImportVCFOwned, want 0", n)
	}
}

// TestImportVCFStrategiesAreScopedToTargetBook (CONTACTS-002 r2 finding 2) is
// the strategy matrix against a NON-empty foreign book: the foreign tenant's
// book holds a contact whose vCard UID matches the import payload, so every
// strategy's exists/remove probe has a real foreign row it could wrongly
// observe, rename against, or delete. Each subtest asserts both directions:
//
//   - foreign target + own gate-verified mailbox: fails closed with a row
//     error and zero writes — a scope-blind exists would report skip/rename
//     progress instead of an error (and under "rename" would loop renaming
//     forever, so the test timing out IS the failure signal), and a scope-blind
//     remove would delete the foreign row;
//   - own target + own gate-verified mailbox: the import succeeds as if the
//     foreign same-UID row did not exist — skip must not skip, rename must
//     keep the original UID, overwrite gives the target book its own row —
//     and the foreign row is left untouched.
func TestImportVCFStrategiesAreScopedToTargetBook(t *testing.T) {
	const foreignUID = "import-test-uid-1" // matches importTestVCF
	const foreignName = "Foreign Original"

	for _, strategy := range []string{"overwrite", "skip", "rename"} {
		t.Run(strategy, func(t *testing.T) {
			pool := testsupport.OpenTestPool(t)
			own := seedImportTenant(t, pool, "contacts-strat-own")
			foreign := seedImportTenant(t, pool, "contacts-strat-foreign")
			seedContact(t, pool, foreign.bookID, foreignUID, foreignName)
			ctx := context.Background()

			imported, skipped, errs := migration.ImportVCFOwned(ctx, pool, importTestVCF, foreign.bookID, own.mailboxID, strategy)
			if imported != 0 || skipped != 0 {
				t.Errorf("foreign-target import = imported=%d skipped=%d, want 0/0", imported, skipped)
			}
			if len(errs) == 0 {
				t.Error("foreign-target import errs is empty, want an address-book-not-owned row error")
			}
			if n := contactCount(t, pool, foreign.bookID); n != 1 {
				t.Fatalf("foreign book contacts = %d, want the seeded row untouched", n)
			}
			if got := contactDisplayName(t, pool, foreign.bookID, foreignUID); got != foreignName {
				t.Errorf("foreign contact display name = %q, want %q (foreign row must not be modified)", got, foreignName)
			}
			if n := contactCount(t, pool, own.bookID); n != 0 {
				t.Errorf("own book contacts = %d after foreign-target import, want 0", n)
			}

			ownImported, ownSkipped, ownErrs := migration.ImportVCFOwned(ctx, pool, importTestVCF, own.bookID, own.mailboxID, strategy)
			if ownImported != 1 || ownSkipped != 0 || len(ownErrs) != 0 {
				t.Errorf("own-target import = imported=%d skipped=%d errs=%v, want imported=1 skipped=0 no errors",
					ownImported, ownSkipped, ownErrs)
			}
			if n := contactCount(t, pool, own.bookID); n != 1 {
				t.Errorf("own book contacts = %d, want the target book's own row", n)
			}
			if got := contactUID(t, pool, own.bookID); got != foreignUID {
				t.Errorf("own book contact uid = %q, want %q (import must behave as if the foreign same-UID row does not exist)", got, foreignUID)
			}
			if n := contactCount(t, pool, foreign.bookID); n != 1 {
				t.Errorf("foreign book contacts = %d after own-target import, want 1", n)
			}
			if got := contactDisplayName(t, pool, foreign.bookID, foreignUID); got != foreignName {
				t.Errorf("foreign contact display name = %q, want %q", got, foreignName)
			}
		})
	}
}

// TestImportCSVStrategiesFailClosedAgainstSeededForeignBook extends the r1
// cross-tenant CSV proof (strategy "" against an empty foreign book) with the
// skip and overwrite strategies against a seeded foreign book: both must fail
// closed with zero writes and leave the foreign row undisturbed, while the own
// target still gets its own row. (Since D-5 the CSV rows carry the stable
// derived identity, but this suite seeds a hand-picked foreign UID that the
// derived key cannot collide with; the matching-UID scope probes live in
// TestImportVCFStrategiesAreScopedToTargetBook.)
func TestImportCSVStrategiesFailClosedAgainstSeededForeignBook(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-csv-strat-own")
	foreign := seedImportTenant(t, pool, "contacts-csv-strat-foreign")
	seedContact(t, pool, foreign.bookID, "csv-foreign-seed-uid", "Foreign CSV Seed")
	ctx := context.Background()

	for _, strategy := range []string{"skip", "overwrite"} {
		imported, skipped, errs := migration.ImportCSVOwned(ctx, pool, importTestCSV, foreign.bookID, own.mailboxID, migration.Mapping{Email: -1}, strategy, "")
		if imported != 0 || skipped != 0 {
			t.Errorf("strategy %q: foreign-target import = imported=%d skipped=%d, want 0/0", strategy, imported, skipped)
		}
		if len(errs) == 0 {
			t.Errorf("strategy %q: foreign-target import errs is empty, want an address-book-not-owned row error", strategy)
		}
	}
	if n := contactCount(t, pool, foreign.bookID); n != 1 {
		t.Errorf("foreign book contacts = %d, want the seeded row untouched", n)
	}
	if got := contactDisplayName(t, pool, foreign.bookID, "csv-foreign-seed-uid"); got != "Foreign CSV Seed" {
		t.Errorf("foreign contact display name = %q, want %q", got, "Foreign CSV Seed")
	}

	ownImported, _, ownErrs := migration.ImportCSVOwned(ctx, pool, importTestCSV, own.bookID, own.mailboxID, migration.Mapping{Email: -1}, "overwrite", "")
	if ownImported != 1 || len(ownErrs) != 0 {
		t.Errorf("own-target overwrite import = imported=%d errs=%v, want imported=1 no errors", ownImported, ownErrs)
	}
	if n := contactCount(t, pool, own.bookID); n != 1 {
		t.Errorf("own book contacts = %d, want the target book's own row", n)
	}
	if n := contactCount(t, pool, foreign.bookID); n != 1 {
		t.Errorf("foreign book contacts = %d after own-target import, want 1", n)
	}
}

// TestImportCSVHappyPathOwnedBook confirms the hardening leaves existing
// behavior unchanged: importing into the caller's own book still inserts.
// (Since D-5, CSV rows carry the stable derived identity — one import per
// fixture keeps this test independent of the dedup semantics exercised in
// internal/migration's strategy-matrix tests.)
func TestImportCSVHappyPathOwnedBook(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-csv-happy")
	h := NewImportHandler(pool, slog.Default())

	rec := postImport(t, h, "/contacts/import/csv", own, "contacts.csv", importTestCSV,
		map[string]string{"addressBookId": strconv.FormatInt(own.bookID, 10)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal import response: %v", err)
	}
	if resp.Imported != 1 || len(resp.Errors) != 0 {
		t.Errorf("import response = %+v, want imported=1 with no errors", resp)
	}
	if n := contactCount(t, pool, own.bookID); n != 1 {
		t.Errorf("own book contacts = %d, want 1", n)
	}
}

// TestImportVCFHappyPathOwnedBook confirms the vCard route still imports into
// the caller's own book and that the skip/overwrite strategies still work
// through the ownership-scoped statements (stable UID across imports).
func TestImportVCFHappyPathOwnedBook(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	own := seedImportTenant(t, pool, "contacts-vcf-happy")
	h := NewImportHandler(pool, slog.Default())
	bookID := strconv.FormatInt(own.bookID, 10)

	doImport := func(strategy string) importResponse {
		t.Helper()
		rec := postImport(t, h, "/contacts/import/vcf", own, "contacts.vcf", importTestVCF,
			map[string]string{"addressBookId": bookID, "strategy": strategy})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		var resp importResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal import response: %v", err)
		}
		return resp
	}

	if resp := doImport(""); resp.Imported != 1 || len(resp.Errors) != 0 {
		t.Errorf("first import = %+v, want imported=1 with no errors", resp)
	}
	if resp := doImport("skip"); resp.Imported != 0 || resp.Skipped != 1 {
		t.Errorf("skip re-import = %+v, want imported=0 skipped=1", resp)
	}
	if resp := doImport("overwrite"); resp.Imported != 1 || resp.Skipped != 0 {
		t.Errorf("overwrite re-import = %+v, want imported=1 skipped=0", resp)
	}
	if n := contactCount(t, pool, own.bookID); n != 1 {
		t.Errorf("own book contacts = %d, want 1 after overwrite re-import", n)
	}
}

// TestSeedImportTenantCleanupRecoversOwnerWhenLookupFails (CONTACTS-002 r3)
// injects the leak scenario end-to-end: the owner lookup fails immediately
// after mk_account, so the fixture never learns tn.userID (it stays zero) yet
// seeding itself completes (the book insert still succeeds). The fixture
// cleanup must STILL remove user, mailbox and books — it recovers the owner
// from the mailboxes DELETE .. RETURNING user_id — because a user delete keyed
// on the zero cached id misses the real owner, the surviving user keeps no
// primary mailbox, and the deferred trg_mailbox_primary_enforce_delete raises
// BZ013 at COMMIT, rolling back the cleanup transaction and retaining every
// fixture row.
func TestSeedImportTenantCleanupRecoversOwnerWhenLookupFails(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	var tn importTenant
	var ownerID int64
	// Registered BEFORE seeding so it runs AFTER the fixture's own cleanup
	// (t.Cleanup is LIFO) while the pool is still open: by then nothing of the
	// tenant may remain even though the fixture never held the owner id.
	t.Cleanup(func() {
		for _, probe := range []struct {
			name string
			sql  string
			args []any
		}{
			{"user", `SELECT count(*) FROM users WHERE id = $1`, []any{ownerID}},
			{"mailbox", `SELECT count(*) FROM mailboxes WHERE id = $1`, []any{tn.mailboxID}},
			{"addressbooks", `SELECT count(*) FROM addressbooks WHERE mailbox_id = $1`, []any{tn.mailboxID}},
		} {
			var n int
			if err := pool.QueryRow(ctx, probe.sql, probe.args...).Scan(&n); err != nil {
				t.Errorf("residue probe %s: %v", probe.name, err)
				continue
			}
			if n != 0 {
				t.Errorf("residue probe %s: %d row(s) remain, want 0 (cleanup must not trust the cached tn.userID)", probe.name, n)
			}
		}
	})

	orig := importLookupUser
	importLookupUser = func(context.Context, *pgxpool.Pool, int64) (int64, error) {
		return 0, errors.New("injected: owner lookup fails right after mk_account")
	}
	defer func() { importLookupUser = orig }()

	tn = seedImportTenant(t, pool, "contacts-cleanup-inject")
	if tn.userID != 0 {
		t.Fatalf("tn.userID = %d, want 0 — the injected lookup failure did not take effect", tn.userID)
	}
	if tn.bookID == 0 {
		t.Fatal("book insert did not complete — seeding must survive the failed lookup")
	}
	// The tenant really exists right now, so the leak scenario is live. The
	// owner id is read for the residue probe ONLY — the fixture cleanup never
	// sees it.
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id = $1`, tn.mailboxID).Scan(&ownerID); err != nil {
		t.Fatalf("probe-side owner read: %v", err)
	}
	if ownerID == 0 {
		t.Fatalf("probe-side owner read returned 0 for mailbox %d", tn.mailboxID)
	}
}
