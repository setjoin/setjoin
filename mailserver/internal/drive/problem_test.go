package drive

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func pgErr(code, hint string) error { return &pgconn.PgError{Code: code, Hint: hint} }

func TestBZStatusMap(t *testing.T) { // the §7 map, verbatim
	want := map[string]int{
		"BZ139": 404, "BZ140": 403, "BZ141": 422, "BZ142": 409, "BZ143": 409,
		"BZ144": 422, "BZ145": 409, "BZ147": 409, "BZ148": 413, "BZ260": 409,
	}
	for code, status := range want {
		rr := httptest.NewRecorder()
		writeDriveProblem(rr, httptest.NewRequest("GET", "/drive/spaces", nil),
			pgErr(code, `{"type":"x","detail":"d"}`))
		if rr.Code != status {
			t.Errorf("%s: want %d got %d", code, status, rr.Code)
		}
	}
}

func TestProblemCarriesCodeExtension(t *testing.T) {
	rr := httptest.NewRecorder()
	writeDriveProblem(rr, httptest.NewRequest("POST", "/drive/nodes", nil),
		pgErr("BZ148", `{"type":"overQuota","detail":"space quota exceeded"}`))
	body := rr.Body.String()
	for _, want := range []string{`"code":"BZ148"`, `"status":413`, `/drive/quota-exceeded`} {
		if !strings.Contains(body, want) {
			t.Errorf("problem body missing %s: %s", want, body)
		}
	}
}

func TestProblemOmitsCodeForUnknownError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeDriveProblem(rr, httptest.NewRequest("GET", "/drive/spaces", nil), pgErr("23505", ""))
	if strings.Contains(rr.Body.String(), `"code"`) {
		t.Errorf("non-drive pg error must not carry a code extension: %s", rr.Body.String())
	}
}
