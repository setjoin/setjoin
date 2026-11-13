package reducererr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/shared/httputil"
)

func wireErr(code, hint string) error { return &pgconn.PgError{Code: code, Hint: hint} }

// TestWriteProblem is the BZ->status->problem table test for the shared
// wire.go kit (whole-pipeline review arch #3). chat's handler_test.go
// (TestBZStatusMap) and meet's handler_test.go (TestBZStatusMap) and drive's
// problem_test.go (TestBZStatusMap/TestProblemCarriesCodeExtension) each keep
// pinning their OWN bzSlug table + wrapper function unchanged (still green
// after this refactor — the wrapper's signature and behavior are untouched);
// this is the one place the shared MECHANICS underneath all three (status,
// the `code` extension, the `type` slug, Override, Extend, QueryJSON) are
// pinned once instead of only being exercised indirectly three times.
func TestWriteProblem(t *testing.T) {
	plainOpts := ProblemOptions{Namespace: "chat", Slugs: map[string]string{
		"BZ163": "forbidden",
	}}

	t.Run("known code projects status+code+type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteProblem(rr, httptest.NewRequest("GET", "/chat/x", nil), wireErr("BZ163", ""), plainOpts)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
		body := rr.Body.String()
		for _, want := range []string{`"code":"BZ163"`, `"status":403`, `/problems/chat/forbidden`} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %s: %s", want, body)
			}
		}
	})

	t.Run("unrecognized error falls through to ClassUnknown 500, no code/type", func(t *testing.T) {
		rr := httptest.NewRecorder()
		WriteProblem(rr, httptest.NewRequest("GET", "/chat/x", nil), wireErr("23505", ""), plainOpts)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", rr.Code)
		}
		if strings.Contains(rr.Body.String(), `"code"`) {
			t.Errorf("unrecognized error must not carry a code extension: %s", rr.Body.String())
		}
	})

	t.Run("Override replaces the class-derived status", func(t *testing.T) {
		opts := ProblemOptions{
			Namespace: "drive",
			Slugs:     map[string]string{"BZ148": "quota-exceeded"},
			Override: func(err error) (int, bool) {
				if IsCode(err, "BZ148") {
					return http.StatusRequestEntityTooLarge, true
				}
				return 0, false
			},
		}
		rr := httptest.NewRecorder()
		WriteProblem(rr, httptest.NewRequest("GET", "/drive/x", nil), wireErr("BZ148", ""), opts)
		// codeClass classifies BZ148 to ClassOverQuota (507) — Override must win.
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 (Override must win over the 507 class default)", rr.Code)
		}
	})

	t.Run("Extend mutates the built Problem", func(t *testing.T) {
		opts := ProblemOptions{
			Namespace: "drive",
			Slugs:     map[string]string{"BZ149": "locked"},
			Extend: func(err error, p *httputil.Problem) {
				if IsCode(err, "BZ149") {
					p.HolderID = 42
				}
			},
		}
		rr := httptest.NewRecorder()
		WriteProblem(rr, httptest.NewRequest("GET", "/drive/x", nil), wireErr("BZ149", ""), opts)
		if !strings.Contains(rr.Body.String(), `"holderId":42`) {
			t.Errorf("body missing Extend-set holderId: %s", rr.Body.String())
		}
	})
}

func TestWriteClassifiedCarriesStableAutomationFields(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteClassified(
		rr,
		httptest.NewRequest("POST", "/admin/identity/v2/transitions/preview", nil),
		wireErr("BZ234", `{"type":"identity_transition_preflight","remediation":"enable transition admission after shadow verification"}`),
	)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`"type":"https://setjoin.com/problems/reducer/bz234"`,
		`"code":"BZ234"`,
		`"retryable":false`,
		`"remediation":"enable transition admission after shadow verification"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %s: %s", want, body)
		}
	}
}

func TestWriteClassifiedTransientDoesNotExposeCode(t *testing.T) {
	rr := httptest.NewRecorder()
	WriteClassified(
		rr,
		httptest.NewRequest("POST", "/api/example", nil),
		wireErr(ErrMissingInbox, `{"type":"internal_dependency"}`),
	)
	body := rr.Body.String()
	if strings.Contains(body, `"code"`) || strings.Contains(body, "BZ008") {
		t.Fatalf("transient internal failure leaked reducer code: %s", body)
	}
	if !strings.Contains(body, `"retryable":true`) {
		t.Fatalf("transient failure must be retryable: %s", body)
	}
}

func TestWriteClassifiedUnknownReturnsFalseWithoutWriting(t *testing.T) {
	rr := httptest.NewRecorder()
	if WriteClassified(
		rr,
		httptest.NewRequest("POST", "/api/example", nil),
		wireErr("ZZ999", ""),
	) {
		t.Fatal("unknown error was reported as classified")
	}
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("unknown error wrote a response: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestClassRemediationCoversEveryActionableClass(t *testing.T) {
	tests := []struct {
		class ReplyClass
		want  string
	}{
		{ClassConflict, "Refresh current state, resolve the conflict, and retry."},
		{ClassCannotCalc, "Refresh current state, resolve the conflict, and retry."},
		{ClassForbidden, "Complete the required authorization, approval, or recovery step before retrying."},
		{ClassNotFound, "Refresh the target identifier and retry only if the resource still exists."},
		{ClassAccountNotFound, "Refresh the target identifier and retry only if the resource still exists."},
		{ClassInvalidArguments, "Correct the request fields and retry."},
		{ClassUnprocessable, "Correct the requested operation using the documented runbook and retry."},
		{ClassOverQuota, "Reduce usage or raise the applicable quota before retrying."},
		{ClassSendQuota, "Reduce usage or raise the applicable quota before retrying."},
		{ClassTransient, "Retry after the service dependency or configuration has recovered."},
		{ClassUnknown, ""},
	}
	for _, tt := range tests {
		if got := classRemediation(tt.class); got != tt.want {
			t.Errorf("classRemediation(%v) = %q, want %q", tt.class, got, tt.want)
		}
	}
}

// TestParseReducerError_MalformedHintFailsTowardServerFailure pins the
// malformed-HINT guard (D-SHARED-REDUCERERR-001): an unparseable or
// type-forged HINT must return (nil, err) — the caller treats the original
// error as a generic server failure — instead of silently populating
// classification-relevant fields from a partially-decoded payload.
func TestParseReducerError_MalformedHintFailsTowardServerFailure(t *testing.T) {
	// A well-formed HINT parses and its type wins.
	rerr, err := ParseReducerError(wireErr("BZ001", `{"type":"mailbox_over_quota"}`))
	if err != nil || rerr == nil || rerr.Type != "mailbox_over_quota" {
		t.Fatalf("valid HINT: got (%+v, %v)", rerr, err)
	}

	// An empty HINT still falls back to the code as the Type.
	rerr, err = ParseReducerError(wireErr("BZ001", ""))
	if err != nil || rerr == nil || rerr.Type != "BZ001" {
		t.Fatalf("empty HINT: got (%+v, %v)", rerr, err)
	}

	// Malformed or type-forged HINTs are rejected outright.
	for _, hint := range []string{
		`{"type":"mailbox_over_quota"`, // truncated JSON (prefix-valid)
		`nonsense`,                     // not JSON at all
		`{"type":123}`,                 // wrong JSON type for a consumed field
	} {
		rerr, err := ParseReducerError(wireErr("BZ001", hint))
		if err == nil || rerr != nil {
			t.Errorf("malformed HINT %q: got (%+v, %v), want (nil, err)", hint, rerr, err)
		}
	}
}
