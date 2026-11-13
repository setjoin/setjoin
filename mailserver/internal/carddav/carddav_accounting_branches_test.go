package carddav

// CardDAV PUT/DELETE honest-accounting acceptance tests: every per-item
// outcome the jmap_contact_set_* reducers report (created/updated/destroyed,
// notCreated/notUpdated/notDestroyed, unparseable results, transport errors)
// must surface as the honest WebDAV status — never a fabricated 201/204, and
// never a reducer message leak. Complements contact_write_identity_test.go
// (which owns the divergent-id happy-path lifecycle against the real
// reducers) and reducer_error_test.go (which owns the BZ→status projection).

import (
	"context"
	"encoding/json"
	"errors"
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

// w5StubCaller replays canned reducer results so a test can poison the
// accounting the production PoolCaller would faithfully relay. A non-nil
// `next` delegates instead (used to run the fixture's honest writes).
type w5StubCaller struct {
	raw  json.RawMessage
	err  error
	next reducercall.Caller
}

func (c *w5StubCaller) Call(ctx context.Context, fn string, args ...any) (json.RawMessage, error) {
	if c.next != nil {
		return c.next.Call(ctx, fn, args...)
	}
	return c.raw, c.err
}

func (c *w5StubCaller) CallScoped(context.Context, int64, string, ...any) (json.RawMessage, error) {
	return nil, errors.New("w5StubCaller: CallScoped not implemented")
}

func (c *w5StubCaller) CallScopedBatch(context.Context, int64, ...reducercall.ScopedCall) ([]json.RawMessage, error) {
	return nil, errors.New("w5StubCaller: CallScopedBatch not implemented")
}

// w5Fixture builds one mk_account + addressbook and returns a handler whose
// caller can be swapped per case, plus a PUT/DELETE driver.
type w5Fixture struct {
	pool    *pgxpool.Pool
	mbID    int64
	userID  int64
	abID    int64
	handler *Handler
	real    reducercall.Caller
}

func w5Setup(t *testing.T) *w5Fixture {
	t.Helper()
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

	f := &w5Fixture{}
	if err := pool.QueryRow(ctx, `SELECT mk_account('carddav_w5_branches')`).Scan(&f.mbID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, f.mbID).Scan(&f.userID); err != nil {
		t.Fatalf("user_id: %v", err)
	}
	t.Cleanup(func() { teardownAccount(ctx, pool, f.mbID, f.userID) })

	if err := pool.QueryRow(ctx,
		`INSERT INTO addressbooks (mailbox_id, name) VALUES ($1,'W5 Branches') RETURNING id`, f.mbID).Scan(&f.abID); err != nil {
		t.Fatalf("insert addressbook: %v", err)
	}

	f.real = reducercall.New(pool)
	f.pool = pool
	f.handler = &Handler{pool: pool, caller: f.real, logger: slog.Default()}
	return f
}

const w5UID = "w5-branch-1"

func w5VCard() string {
	return "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:" + w5UID + "\r\n" +
		"FN:W5 Branch\r\nN:Branch;W5;;;\r\nEND:VCARD\r\n"
}

func (f *w5Fixture) do(method, path, body, ifMatch string) *httptest.ResponseRecorder {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: f.userID}))
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// w5CreateContact runs one honest PUT-create through the real reducers so the
// error cases have an existing row to update/destroy.
func (f *w5Fixture) w5CreateContact(t *testing.T) (etag string, id int64) {
	t.Helper()
	rec := f.do(http.MethodPut, "/"+strconv.FormatInt(f.abID, 10)+"/"+w5UID+".vcf", w5VCard(), "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("fixture PUT create: want 201, got %d\n%s", rec.Code, rec.Body.String())
	}
	err := f.pool.QueryRow(context.Background(),
		`SELECT id, etag FROM contacts WHERE addressbook_id=$1 AND vcard_uid=$2`, f.abID, w5UID).Scan(&id, &etag)
	if err != nil {
		t.Fatalf("fixture contact row: %v", err)
	}
	return etag, id
}

func TestCarddavPutCreate_AccountingBranches(t *testing.T) {
	f := w5Setup(t)
	abPath := "/" + strconv.FormatInt(f.abID, 10) + "/" + w5UID + ".vcf"

	cases := []struct {
		name       string
		stub       *w5StubCaller
		wantStatus int
	}{
		{
			name:       "reducer transport error -> classified status, not 201",
			stub:       &w5StubCaller{err: errors.New("connection reset by peer")},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unparseable reducer result -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"created":`)},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "empty reducer result -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(``)},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "notCreated notFound -> 404, never a fabricated 201",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"notCreated":{"k1":{"type":"notFound","description":"nope"}}}`)},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "notCreated invalidArguments -> 400",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"notCreated":{"k1":{"type":"invalidArguments","description":"bad vcard"}}}`)},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "notCreated invalidArguments ownership signature -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"notCreated":{"k1":{"type":"invalidArguments","description":"addressbook not found"}}}`)},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "no accounting at all -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"created":{},"notCreated":{}}`)},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.handler.caller = tc.stub
			t.Cleanup(func() { f.handler.caller = f.real })
			rec := f.do(http.MethodPut, abPath, w5VCard(), "")
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d\n%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if rec.Header().Get("ETag") != "" {
				t.Errorf("a non-created PUT must not fabricate an ETag, got %q", rec.Header().Get("ETag"))
			}
		})
	}
}

func TestCarddavPutUpdate_AccountingBranches(t *testing.T) {
	f := w5Setup(t)
	etag, id := f.w5CreateContact(t)
	abPath := "/" + strconv.FormatInt(f.abID, 10) + "/" + w5UID + ".vcf"
	key := strconv.FormatInt(id, 10)

	cases := []struct {
		name       string
		stub       *w5StubCaller
		wantStatus int
	}{
		{
			name:       "reducer transport error -> classified status, not 204",
			stub:       &w5StubCaller{err: errors.New("connection reset by peer")},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unparseable reducer result -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"updated":[`)},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "notUpdated -> 404, never a fabricated 204",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"notUpdated":{"` + key + `":{"type":"notFound"}}}`)},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "no accounting at all -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"updated":[]}`)},
			wantStatus: http.StatusInternalServerError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.handler.caller = tc.stub
			t.Cleanup(func() { f.handler.caller = f.real })
			rec := f.do(http.MethodPut, abPath, w5VCard(), etag)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d\n%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestCarddavDelete_AccountingBranches(t *testing.T) {
	f := w5Setup(t)
	_, id := f.w5CreateContact(t)
	abPath := "/" + strconv.FormatInt(f.abID, 10) + "/" + w5UID + ".vcf"
	key := strconv.FormatInt(id, 10)

	t.Run("If-Match mismatch -> 412, row survives", func(t *testing.T) {
		rec := f.do(http.MethodDelete, abPath, "", `"stale-etag"`)
		if rec.Code != http.StatusPreconditionFailed {
			t.Fatalf("status = %d, want 412", rec.Code)
		}
		var n int
		if err := f.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM contacts WHERE id=$1`, id).Scan(&n); err != nil || n != 1 {
			t.Fatalf("contact must survive a 412 delete (n=%d err=%v)", n, err)
		}
	})

	for _, tc := range []struct {
		name       string
		stub       *w5StubCaller
		wantStatus int
	}{
		{
			name:       "reducer transport error -> classified status, not 204",
			stub:       &w5StubCaller{err: errors.New("connection reset by peer")},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "unparseable reducer result -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"destroyed":"nope"}`)},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "notDestroyed -> 409/404-class per-item status, never 204",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"notDestroyed":{"` + key + `":{"type":"notFound"}}}`)},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "no accounting at all -> 500",
			stub:       &w5StubCaller{raw: json.RawMessage(`{"destroyed":[]}`)},
			wantStatus: http.StatusInternalServerError,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case destroys at most once; recreate the row when a previous
			// case actually destroyed it (the honest lifecycle test owns that path).
			var n int
			if err := f.pool.QueryRow(context.Background(),
				`SELECT count(*) FROM contacts WHERE id=$1`, id).Scan(&n); err != nil || n == 0 {
				f.handler.caller = f.real
				f.do(http.MethodPut, abPath, w5VCard(), "")
			}
			f.handler.caller = tc.stub
			t.Cleanup(func() { f.handler.caller = f.real })
			rec := f.do(http.MethodDelete, abPath, "", "")
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestParseContactSetResult_Rejections: empty and malformed accounting is an
// error, never a silently-acknowledged write.
func TestParseContactSetResult_Rejections(t *testing.T) {
	if _, err := parseContactSetResult(nil); err == nil {
		t.Error("empty reducer result must error")
	}
	if _, err := parseContactSetResult(json.RawMessage(`not-json`)); err == nil {
		t.Error("malformed reducer result must error")
	}
	set, err := parseContactSetResult(json.RawMessage(
		`{"created":{"k1":{}},"notCreated":{},"updated":[7],"notUpdated":{},"destroyed":[8],"notDestroyed":{}}`))
	if err != nil {
		t.Fatalf("valid result: %v", err)
	}
	if _, ok := set.Created["k1"]; !ok {
		t.Error("created must decode")
	}
	if !setContainsID(set.Updated, 7) || setContainsID(set.Updated, 8) || setContainsID(nil, 7) {
		t.Error("setContainsID membership wrong")
	}
	if !setContainsID(set.Destroyed, 8) {
		t.Error("destroyed must decode")
	}
}
