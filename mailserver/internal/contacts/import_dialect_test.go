package contacts

// Test for the CSV import dialect mode-selection gate: only "" (literal default)
// and migration.CSVDialectSetjoin (input explicitly identified as a Setjoin
// export, which applies the formula-neutralization unescape) are accepted; any
// other dialect value fails closed with 400 instead of being silently treated as
// literal.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// TestImportCSVDialectGate pins the dialect contract on the import surface. The
// unreachable pool (closed port, no service started) makes every request that
// passes validation fail at the ownership query with 500, so acceptance of the
// two valid modes and rejection of an unknown one are both observable.
func TestImportCSVDialectGate(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://setjoin_dialect_probe@127.0.0.1:1/noconnect?connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()
	h := NewImportHandler(pool, slog.Default())

	try := func(t *testing.T, dialect string) *httptest.ResponseRecorder {
		t.Helper()
		body, ct := multipartCSV(t, "First Name,E-mail Address\n'+123,a@x.test\n")
		req := httptest.NewRequest(http.MethodPost, "/contacts/import/csv?addressBookId=1&dialect="+dialect, body)
		req.Header.Set("Content-Type", ct)
		req = req.WithContext(auth.ContextWithUser(req.Context(), testClaims(5701)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := try(t, "bogus"); rec.Code != http.StatusBadRequest {
		t.Errorf("dialect=bogus: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	for _, dialect := range []string{"", migration.CSVDialectSetjoin} {
		if rec := try(t, dialect); rec.Code != http.StatusInternalServerError {
			t.Errorf("dialect=%q: status = %d, want 500 (accepted past validation, failed at unreachable ownership query)", dialect, rec.Code)
		}
	}
}
