package carddav

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/reducercall"
)

// med-shard3-009: CardDAV addressbook multi-status identity.
//
// The CardDAV write paths used to pass users.id into the jmap_contact_set_*
// p_mailbox_id slot, so on the production-normal users.id != mailbox_id
// divergence the reducers' ownership predicates (ab.mailbox_id = p_mailbox_id)
// matched zero rows — every item silently landed in notCreated/notUpdated/
// notDestroyed while the handler fabricated 201/204 + ETags. These tests pin
// the fix on both sides of the seam:
//   - TestContactWrite_DivergentMailboxID_HonestLifecycle drives PUT/GET/
//     PUT-update/DELETE through the full handler against a real divergent-id
//     account (mk_account: user ids start at 70000, mailbox ids at 90000, so
//     users.id != mailbox_id by construction) and asserts real persistence,
//     honest status codes, and ETag consistency after each honest write.
//   - TestContactSetReducers_ZeroRowOwnershipSurfacesError pins the reducer
//     contract the handler's per-item inspection relies on: a zero-row
//     ownership match (wrong identity in the p_mailbox_id slot) surfaces a
//     per-item error entry, never a silent success.
//
// Skips without TEST_DB_DSN (matches scan_db_test.go / sync_collection_test.go).

const writeIdentityVCardUID = "write-id-1"

func writeIdentityVCard(fn string) string {
	return "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:" + writeIdentityVCardUID + "\r\n" +
		"FN:" + fn + "\r\nN:Lovelace;Ada;;;\r\nEND:VCARD\r\n"
}

func TestContactWrite_DivergentMailboxID_HonestLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	// Registered BEFORE fixture cleanups so it runs LAST (cleanup is LIFO).
	t.Cleanup(pool.Close)

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('carddav_write_id')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, mbID, userID) })

	// The production-normal divergence this package fixes is the whole point of
	// the test — mk_account guarantees it (user seq 70000+, mailbox seq 90000+).
	if userID == mbID {
		t.Fatalf("fixture divergence lost: user_id %d == mailbox_id %d", userID, mbID)
	}

	var abID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1,'Write Identity') RETURNING id`, mbID).Scan(&abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}

	// A foreign account + addressbook: writes against it must get the per-item
	// error status (404), never a fabricated success.
	var foreignMbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('carddav_write_foreign')`).Scan(&foreignMbID); err != nil {
		t.Fatalf("mk_account foreign: %v", err)
	}
	var foreignUserID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, foreignMbID).Scan(&foreignUserID); err != nil {
		t.Fatalf("foreign user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, foreignMbID, foreignUserID) })
	var foreignAbID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1,'Foreign AB') RETURNING id`, foreignMbID).Scan(&foreignAbID); err != nil {
		t.Fatalf("insert foreign addressbook: %v", err)
	}

	h := &Handler{pool: pool, caller: reducercall.New(pool), logger: slog.Default()}
	do := func(method, path, body, ifMatch string, asUserID int64) *httptest.ResponseRecorder {
		var req *http.Request
		if body == "" {
			req = httptest.NewRequest(method, path, nil)
		} else {
			req = httptest.NewRequest(method, path, strings.NewReader(body))
		}
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: asUserID}))
		if ifMatch != "" {
			req.Header.Set("If-Match", ifMatch)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	abPath := func(ab int64, suffix string) string {
		return "/" + strconv.FormatInt(ab, 10) + "/" + suffix
	}

	// 1. PUT create → honest 201 + non-empty ETag, and the row really persists
	//    under the owning mailbox (pre-fix this no-oped with a fabricated 201).
	rec := do(http.MethodPut, abPath(abID, writeIdentityVCardUID+".vcf"), writeIdentityVCard("Ada Lovelace"), "", userID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("PUT create: want 201, got %d\n%s", rec.Code, rec.Body.String())
	}
	createETag := strings.Trim(rec.Header().Get("ETag"), `"`)
	if createETag == "" {
		t.Fatal("PUT create: expected a non-empty ETag header")
	}
	var (
		gotName  string
		gotAB    int64
		gotMbID  int64
		storedEt string
	)
	if err := pool.QueryRow(ctx,
		`SELECT c.display_name, c.addressbook_id, ab.mailbox_id, c.etag
		   FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id
		  WHERE c.vcard_uid=$1`, writeIdentityVCardUID,
	).Scan(&gotName, &gotAB, &gotMbID, &storedEt); err != nil {
		t.Fatalf("contact not persisted after 201: %v", err)
	}
	if gotName != "Ada Lovelace" || gotAB != abID || gotMbID != mbID {
		t.Errorf("persisted under wrong identity: name=%q ab=%d mailbox=%d (want ab=%d mailbox=%d)",
			gotName, gotAB, gotMbID, abID, mbID)
	}
	if storedEt != createETag {
		t.Errorf("PUT create ETag %q != stored etag %q", createETag, storedEt)
	}

	// 2. GET right after the honest create: ETag consistency (response ETag ==
	//    what GET/PROPFIND return).
	rec = do(http.MethodGet, abPath(abID, writeIdentityVCardUID+".vcf"), "", "", userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after create: want 200, got %d", rec.Code)
	}
	if got := strings.Trim(rec.Header().Get("ETag"), `"`); got != createETag {
		t.Errorf("GET ETag %q != PUT create response ETag %q", got, createETag)
	}

	// 3. PUT update (If-Match on the create ETag) → honest 204, a NEW ETag,
	//    the new ETag equals the stored/GET one, and the field really changed.
	rec = do(http.MethodPut, abPath(abID, writeIdentityVCardUID+".vcf"), writeIdentityVCard("Ada King"), `"`+createETag+`"`, userID)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PUT update: want 204, got %d\n%s", rec.Code, rec.Body.String())
	}
	updateETag := strings.Trim(rec.Header().Get("ETag"), `"`)
	if updateETag == "" {
		t.Fatal("PUT update: expected a non-empty ETag header")
	}
	if updateETag == createETag {
		t.Error("PUT update returned the create ETag — a stale ETag fabricates conflict-free writes")
	}
	var (
		gotName2  string
		storedEt2 string
	)
	if err := pool.QueryRow(ctx,
		`SELECT display_name, etag FROM contacts WHERE vcard_uid=$1`, writeIdentityVCardUID,
	).Scan(&gotName2, &storedEt2); err != nil {
		t.Fatalf("contact vanished after 204 update: %v", err)
	}
	if gotName2 != "Ada King" {
		t.Errorf("update not persisted: display_name=%q, want %q", gotName2, "Ada King")
	}
	if storedEt2 != updateETag {
		t.Errorf("PUT update ETag %q != stored etag %q", updateETag, storedEt2)
	}
	rec = do(http.MethodGet, abPath(abID, writeIdentityVCardUID+".vcf"), "", "", userID)
	if got := strings.Trim(rec.Header().Get("ETag"), `"`); got != updateETag {
		t.Errorf("GET ETag %q != PUT update response ETag %q", got, updateETag)
	}

	// 4. DELETE → honest 204, and the row is really gone.
	rec = do(http.MethodDelete, abPath(abID, writeIdentityVCardUID+".vcf"), "", "", userID)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: want 204, got %d\n%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM contacts WHERE vcard_uid=$1`, writeIdentityVCardUID).Scan(&count); err != nil {
		t.Fatalf("count after delete: %v", err)
	}
	if count != 0 {
		t.Errorf("DELETE reported 204 but %d row(s) survived (fabricated success)", count)
	}
	rec = do(http.MethodGet, abPath(abID, writeIdentityVCardUID+".vcf"), "", "", userID)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET after delete: want 404, got %d", rec.Code)
	}

	// 5. Foreign item: PUT against another user's addressbook gets the honest
	//    per-item error status, and nothing is written anywhere.
	rec = do(http.MethodPut, abPath(foreignAbID, "intruder.vcf"), writeIdentityVCard("Intruder"), "", userID)
	if rec.Code != http.StatusNotFound {
		t.Errorf("PUT to foreign addressbook: want 404, got %d", rec.Code)
	}
	var foreignRows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM contacts WHERE vcard_uid='intruder.vcf' OR vcard_uid='intruder'`).Scan(&foreignRows); err != nil {
		t.Fatalf("count foreign write: %v", err)
	}
	if foreignRows != 0 {
		t.Errorf("PUT to foreign addressbook persisted %d row(s)", foreignRows)
	}
}

// TestContactSetReducers_ZeroRowOwnershipSurfacesError pins the reducer-side
// contract the CardDAV per-item inspection depends on: calling the contact set
// reducers with the WRONG identity in the p_mailbox_id slot (the exact bug
// signature — users.id where the owning mailbox belongs) matches zero rows and
// must surface a per-item error entry (notCreated/notUpdated/notDestroyed),
// never a silent success; the same call with the owning mailbox persists.
func TestContactSetReducers_ZeroRowOwnershipSurfacesError(t *testing.T) {
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

	var mbID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account('carddav_zero_row')`).Scan(&mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mbID).Scan(&userID); err != nil {
		t.Fatalf("user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, mbID, userID) })
	if userID == mbID {
		t.Fatalf("fixture divergence lost: user_id %d == mailbox_id %d", userID, mbID)
	}

	var abID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1,'Zero Row') RETURNING id`, mbID).Scan(&abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}

	h := &Handler{pool: pool, caller: reducercall.New(pool), logger: slog.Default()}

	call := func(fn string, mailbox int64, args ...any) contactSetResult {
		raw, err := h.caller.Call(ctx, fn, append([]any{mailbox}, args...)...)
		if err != nil {
			t.Fatalf("%s(mailbox=%d): %v", fn, mailbox, err)
		}
		set, err := parseContactSetResult(raw)
		if err != nil {
			t.Fatalf("%s(mailbox=%d): parse result: %v", fn, mailbox, err)
		}
		return set
	}
	contactCreate := func(mailbox int64, uid string) contactSetResult {
		return call("jmap_contact_set_create", mailbox, map[string]any{
			"k1": map[string]any{
				"addressbookId": abID, "uid": uid, "displayName": "Zero Row",
			},
		})
	}

	// Zero-row create: wrong identity (user id in the mailbox slot) → the item
	// lands in notCreated, never created.
	wrongCreate := contactCreate(userID, "zero-row-1")
	if failure, hit := wrongCreate.NotCreated["k1"]; !hit || len(failure) == 0 {
		t.Fatalf("wrong-identity create: item not accounted in notCreated: %+v", wrongCreate)
	} else {
		var f struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(failure, &f)
		if f.Type != "invalidArguments" {
			t.Errorf("wrong-identity create: notCreated type=%q, want invalidArguments", f.Type)
		}
	}
	if len(wrongCreate.Created) != 0 {
		t.Errorf("wrong-identity create silently succeeded: created=%s", stringMustJSON(wrongCreate.Created))
	}
	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE vcard_uid='zero-row-1'`).Scan(&rowCount); err != nil {
		t.Fatalf("count after wrong-identity create: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("wrong-identity create persisted %d row(s)", rowCount)
	}

	// Correct identity → the create persists.
	okCreate := contactCreate(mbID, "zero-row-1")
	if _, hit := okCreate.Created["k1"]; !hit {
		t.Fatalf("correct-identity create not acknowledged: %+v", okCreate)
	}
	if failure, hit := okCreate.NotCreated["k1"]; hit {
		t.Fatalf("correct-identity create reported notCreated: %s", string(failure))
	}
	var contactID int64
	if err := pool.QueryRow(ctx,
		`SELECT c.id FROM contacts c JOIN addressbooks ab ON ab.id=c.addressbook_id
		  WHERE c.vcard_uid='zero-row-1' AND ab.mailbox_id=$1`, mbID).Scan(&contactID); err != nil {
		t.Fatalf("correct-identity create not persisted: %v", err)
	}
	contactKey := strconv.FormatInt(contactID, 10)

	// Zero-row update: wrong identity → notUpdated[notFound], updated empty.
	wrongUpdate := call("jmap_contact_set_update", userID, map[string]any{contactKey: map[string]any{"displayName": "Changed"}})
	if failure, hit := wrongUpdate.NotUpdated[contactKey]; !hit {
		t.Fatalf("wrong-identity update: item not accounted in notUpdated: %+v", wrongUpdate)
	} else {
		var f struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(failure, &f)
		if f.Type != "notFound" {
			t.Errorf("wrong-identity update: notUpdated type=%q, want notFound", f.Type)
		}
	}
	if len(wrongUpdate.Updated) != 0 {
		t.Errorf("wrong-identity update silently succeeded: updated=%v", wrongUpdate.Updated)
	}

	// Zero-row destroy: wrong identity → notDestroyed[notFound], destroyed empty.
	wrongDestroy := call("jmap_contact_set_destroy", userID, []int64{contactID})
	if failure, hit := wrongDestroy.NotDestroyed[contactKey]; !hit {
		t.Fatalf("wrong-identity destroy: item not accounted in notDestroyed: %+v", wrongDestroy)
	} else {
		var f struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(failure, &f)
		if f.Type != "notFound" {
			t.Errorf("wrong-identity destroy: notDestroyed type=%q, want notFound", f.Type)
		}
	}
	if len(wrongDestroy.Destroyed) != 0 {
		t.Errorf("wrong-identity destroy silently succeeded: destroyed=%v", wrongDestroy.Destroyed)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE id=$1`, contactID).Scan(&rowCount); err != nil {
		t.Fatalf("count after wrong-identity destroy: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("wrong-identity destroy removed the row it reported as not found (count=%d)", rowCount)
	}

	// Correct identity → update and destroy persist, proving the zero-row
	// matches above are identity-scoped, not a broken reducer.
	okUpdate := call("jmap_contact_set_update", mbID, map[string]any{contactKey: map[string]any{"displayName": "Changed"}})
	if !setContainsID(okUpdate.Updated, contactID) {
		t.Fatalf("correct-identity update not acknowledged: %+v", okUpdate)
	}
	if failure, hit := okUpdate.NotUpdated[contactKey]; hit {
		t.Fatalf("correct-identity update reported notUpdated: %s", string(failure))
	}
	okDestroy := call("jmap_contact_set_destroy", mbID, []int64{contactID})
	if !setContainsID(okDestroy.Destroyed, contactID) {
		t.Fatalf("correct-identity destroy not acknowledged: %+v", okDestroy)
	}
	if failure, hit := okDestroy.NotDestroyed[contactKey]; hit {
		t.Fatalf("correct-identity destroy reported notDestroyed: %s", string(failure))
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE id=$1`, contactID).Scan(&rowCount); err != nil {
		t.Fatalf("count after correct-identity destroy: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("correct-identity destroy left %d row(s)", rowCount)
	}
}

func stringMustJSON(m map[string]json.RawMessage) string {
	b, err := json.Marshal(m)
	if err != nil {
		return "<unmarshalable>"
	}
	return string(b)
}
