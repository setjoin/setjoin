package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubClient creates a Client pointed at the given test server.
func stubClient(srv *httptest.Server) *Client {
	return &Client{Server: srv.URL, HTTP: &http.Client{}}
}

// tempDoc writes content to a temp file and returns the path.
func tempDoc(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// minimalDoc is a valid minimal export document.
const minimalDoc = `{"schemaVersion":1,"policies":[],"named_locations":[],"auth_strengths":[]}`

// ── offline validate exit code ────────────────────────────────────────────────

// TestCAValidateExitCode2OnBZ085 — validate exits 2 (not 1) for BZ085 schema errors.
func TestCAValidateExitCode2OnBZ085(t *testing.T) {
	f := tempDoc(t, `{"schemaVersion":1,"policies":[{"conditions":{"bad_key":true},"actions":{"grants":[{"type":"allow"}]}}],"named_locations":[],"auth_strengths":[]}`)
	err := caValidateCmd([]string{f})
	if err == nil {
		t.Fatal("validate bad doc: expected error")
	}
	ec, ok := err.(exitCodeErr)
	if !ok || ec.code != 2 {
		t.Errorf("BZ085 validate: expected exitCodeErr(2), got %T(%v)", err, err)
	}
	if !strings.Contains(err.Error(), "BZ085") {
		t.Errorf("validate error should mention BZ085, got: %v", err)
	}
}

// ── export ────────────────────────────────────────────────────────────────────

// TestCAExportWritesToStdout — export calls GET .../export and prints JSON body.
func TestCAExportWritesToStdout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/admin/conditional-access/export" {
			t.Errorf("export: unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(minimalDoc))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := caExportCmd(stubClient(srv), nil); err != nil {
			t.Fatalf("export: %v", err)
		}
	})
	if !strings.Contains(out, "schemaVersion") {
		t.Errorf("export output missing schemaVersion, got: %q", out)
	}
}

// ── apply ─────────────────────────────────────────────────────────────────────

// TestCAApplyIdempotent — apply -f <file> POSTs to /import with mode=replace.
func TestCAApplyIdempotent(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodPost {
			t.Errorf("apply: expected POST, got %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "import") {
			t.Errorf("apply: expected /import path, got %q", r.URL.Path)
		}
		if mode := r.URL.Query().Get("mode"); mode != "replace" {
			t.Errorf("apply default mode = %q, want replace", mode)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	if err := caApplyCmd(stubClient(srv), []string{"-f", f}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !called {
		t.Fatal("apply: server was not called")
	}
}

// TestCAApplyPrune — apply --prune passes mode=prune.
func TestCAApplyPrune(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mode := r.URL.Query().Get("mode"); mode != "prune" {
			t.Errorf("--prune: mode = %q, want prune", mode)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	if err := caApplyCmd(stubClient(srv), []string{"-f", f, "--prune"}); err != nil {
		t.Fatalf("apply --prune: %v", err)
	}
}

// ── diff ──────────────────────────────────────────────────────────────────────

// TestCADiffNoDrift — diff returns nil (exit 0) when server reports no drift.
func TestCADiffNoDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"drift":   false,
			"changes": []interface{}{},
		})
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	if err := caDiffCmd(stubClient(srv), []string{"-f", f}); err != nil {
		t.Fatalf("diff no-drift: expected nil, got %v", err)
	}
}

// TestCADiffDrift — diff returns exitCodeErr(2) when the server reports drift.
func TestCADiffDrift(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"drift":   true,
			"changes": []interface{}{"+ policy foo"},
		})
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	err := caDiffCmd(stubClient(srv), []string{"-f", f})
	if err == nil {
		t.Fatal("diff drift: expected non-nil error")
	}
	ec, ok := err.(exitCodeErr)
	if !ok || ec.code != 2 {
		t.Errorf("diff drift: expected exitCodeErr(2), got %T(%v)", err, err)
	}
}

// ── exit-code mapping ─────────────────────────────────────────────────────────

// TestCAAuth403ExitCode3 — HTTP 403 from any verb maps to exitCodeErr(3).
func TestCAAuth403ExitCode3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	err := caExportCmd(stubClient(srv), nil)
	if err == nil {
		t.Fatal("403: expected error")
	}
	ec, ok := err.(exitCodeErr)
	if !ok || ec.code != 3 {
		t.Errorf("403 -> expected exitCodeErr(3), got %T(%v)", err, err)
	}
}

// TestCAConflictBZ087ExitCode4 — BZ087 in error body maps to exitCodeErr(4).
func TestCAConflictBZ087ExitCode4(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":"BZ087: priority conflict"}`))
	}))
	defer srv.Close()

	// promote with --yes so it tries the server; BZ087 comes back on conflict.
	// Use a 1-step stub: the impact call returns 0 would_block so promote proceeds,
	// then the actual promote call returns BZ087.
	called := 0
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if strings.Contains(r.URL.Path, "impact") {
			// impact: 0 would_block so --yes check passes
			json.NewEncoder(w).Encode(map[string]interface{}{"would_block": 0, "matched": 1})
			return
		}
		// promote endpoint returns 409/BZ087
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`BZ087: priority conflict`))
	}))
	defer srv2.Close()

	err := caPromoteCmd(stubClient(srv2), []string{"--id", "1", "--yes"})
	if err == nil {
		t.Fatal("BZ087: expected error")
	}
	ec, ok := err.(exitCodeErr)
	if !ok || ec.code != 4 {
		t.Errorf("BZ087 -> expected exitCodeErr(4), got %T(%v)", err, err)
	}
}

// ── promote ───────────────────────────────────────────────────────────────────

// TestCAPromoteRefusesWithoutYes — promote refuses non-interactively when
// would_block > 0 and --yes is absent.
func TestCAPromoteRefusesWithoutYes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "impact") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"would_block": 5,
				"matched":     10,
			})
			return
		}
		t.Error("promote was called despite would_block>0 and no --yes")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := caPromoteCmd(stubClient(srv), []string{"--id", "1"})
	if err == nil {
		t.Fatal("promote without --yes and would_block>0: expected refusal error")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("refusal message should mention --yes, got: %v", err)
	}
}

// TestCAPromoteYesSkipsRefusal — promote with --yes and would_block>0 proceeds.
func TestCAPromoteYesSkipsRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "impact") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"would_block": 5,
				"matched":     10,
			})
			return
		}
		// promote endpoint
		json.NewEncoder(w).Encode(map[string]interface{}{"state": "on"})
	}))
	defer srv.Close()

	if err := caPromoteCmd(stubClient(srv), []string{"--id", "1", "--yes"}); err != nil {
		t.Fatalf("promote --yes: expected nil, got %v", err)
	}
}

// ── simulate ──────────────────────────────────────────────────────────────────

// TestCASimulateExpectMismatch — simulate --expect block exits non-zero on mismatch (got allow).
func TestCASimulateExpectMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":   "allow",
			"matched_by": nil,
		})
	}))
	defer srv.Close()

	err := caSimulateCmd(stubClient(srv), []string{"--user", "alice@example.com", "--expect", "block"})
	if err == nil {
		t.Fatal("simulate --expect block (got allow): expected non-zero")
	}
}

// TestCASimulateExpectMatch — simulate --expect allow exits 0 when matched.
func TestCASimulateExpectMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":   "allow",
			"matched_by": nil,
		})
	}))
	defer srv.Close()

	if err := caSimulateCmd(stubClient(srv), []string{"--user", "alice@example.com", "--expect", "allow"}); err != nil {
		t.Fatalf("simulate --expect allow (match): expected nil, got %v", err)
	}
}

// ── coverage ──────────────────────────────────────────────────────────────────

// TestCACoverageFailOnGap — coverage --fail-on-gap exits non-zero when gaps > 0.
func TestCACoverageFailOnGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"gaps": 3, "shadowed": 1})
	}))
	defer srv.Close()

	if err := caCoverageCmd(stubClient(srv), []string{"--fail-on-gap"}); err == nil {
		t.Fatal("coverage --fail-on-gap with gaps>0: expected non-zero")
	}
}

// TestCACoverageNoGap — coverage --fail-on-gap exits 0 when gaps == 0.
func TestCACoverageNoGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"gaps": 0, "shadowed": 0})
	}))
	defer srv.Close()

	if err := caCoverageCmd(stubClient(srv), []string{"--fail-on-gap"}); err != nil {
		t.Fatalf("coverage --fail-on-gap gaps=0: expected nil, got %v", err)
	}
}

// ── read endpoints ────────────────────────────────────────────────────────────

// TestCAWhyCmd — why <user> calls GET .../why and prints result.
func TestCAWhyCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "why") {
			t.Errorf("why: expected /why path, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision": "block",
			"trace":    []interface{}{},
		})
	}))
	defer srv.Close()

	if err := caWhyCmd(stubClient(srv), []string{"alice@example.com"}); err != nil {
		t.Fatalf("why: %v", err)
	}
}

// TestCAWhyCmdURLEncoding — why encodes + in email addresses (alice+tag@example.com).
func TestCAWhyCmdURLEncoding(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]interface{}{"decision": "allow"})
	}))
	defer srv.Close()

	if err := caWhyCmd(stubClient(srv), []string{"alice+tag@example.com"}); err != nil {
		t.Fatalf("why +email: %v", err)
	}
	// The raw query must not contain a bare +; it should be %2B.
	if strings.Contains(gotQuery, "user=alice+tag") {
		t.Errorf("why: + in email not URL-encoded; raw query: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "alice%2Btag") {
		t.Errorf("why: expected %%2B-encoded +; raw query: %q", gotQuery)
	}
}

// fullDoctorResponse returns a minimal but well-formed doctor JSON payload.
// ponytail: local helper so each test case can mutate one field without duplication.
func fullDoctorResponse(score, total int, allPassed bool) map[string]interface{} {
	passed := func(name string) map[string]interface{} {
		return map[string]interface{}{"name": name, "passed": allPassed, "next_action": func() string {
			if allPassed {
				return ""
			}
			return "fix " + name
		}()}
	}
	return map[string]interface{}{
		"score":  score,
		"total":  total,
		"checks": []interface{}{passed("feature_on"), passed("break_glass_configured"), passed("has_report_only_policy"), passed("no_coverage_gaps")},
		"hygiene": map[string]interface{}{
			"stale_report_only": []interface{}{},
		},
		"time_to_first_policy_sec": nil,
	}
}

// TestCADoctorCmd — doctor calls GET .../doctor and exits 0 when all checks pass.
func TestCADoctorCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "doctor") {
			t.Errorf("doctor: expected /doctor path, got %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(fullDoctorResponse(4, 4, true))
	}))
	defer srv.Close()

	if err := caDoctorCmd(stubClient(srv), nil); err != nil {
		t.Fatalf("doctor (all pass): %v", err)
	}
}

// TestCADoctorFailsWhenChecksFail — doctor exits non-zero when score < total.
func TestCADoctorFailsWhenChecksFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fullDoctorResponse(2, 4, false))
	}))
	defer srv.Close()

	err := caDoctorCmd(stubClient(srv), nil)
	if err == nil {
		t.Fatal("doctor (2/4 pass): expected non-zero exit")
	}
	ec, ok := err.(exitCodeErr)
	if !ok || ec.code != 1 {
		t.Errorf("doctor fail: want exitCodeErr(1), got %T(%v)", err, err)
	}
}

// TestCADoctorJSONFlag — doctor --json prints raw JSON to stdout.
func TestCADoctorJSONFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fullDoctorResponse(4, 4, true))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		if err := caDoctorCmd(stubClient(srv), []string{"--json"}); err != nil {
			t.Errorf("doctor --json: %v", err)
		}
	})
	if !strings.Contains(out, `"score"`) {
		t.Errorf("doctor --json: expected JSON output with 'score', got: %q", out)
	}
	if !strings.Contains(out, `"checks"`) {
		t.Errorf("doctor --json: expected JSON output with 'checks', got: %q", out)
	}
}

// TestCADoctorHumanReadableOutput — without --json, output is human-readable.
func TestCADoctorHumanReadableOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fullDoctorResponse(3, 4, false))
	}))
	defer srv.Close()

	out := captureStdout(t, func() {
		_ = caDoctorCmd(stubClient(srv), nil)
	})
	if !strings.Contains(out, "CA health:") {
		t.Errorf("doctor human: expected 'CA health:' header, got: %q", out)
	}
	if !strings.Contains(out, "[PASS]") && !strings.Contains(out, "[FAIL]") {
		t.Errorf("doctor human: expected [PASS]/[FAIL] markers, got: %q", out)
	}
}

// TestCAInitCmd — init <slug> calls POST .../templates/<slug>/instantiate.
func TestCAInitCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "mfa-require") {
			t.Errorf("init: expected slug in path, got %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("init: expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"id": 42, "name": "MFA Require"})
	}))
	defer srv.Close()

	if err := caInitCmd(stubClient(srv), []string{"mfa-require"}); err != nil {
		t.Fatalf("init: %v", err)
	}
}

// TestCASigninLogCmd — signin-log calls GET .../signin-log.
func TestCASigninLogCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "signin-log") {
			t.Errorf("signin-log: expected /signin-log path, got %q", r.URL.Path)
		}
		// The real server wraps the rows in {"rows": [...]} (see admin
		// admin_conditional_access.go); the command unwraps that envelope.
		json.NewEncoder(w).Encode(map[string]interface{}{"rows": []interface{}{
			map[string]interface{}{"user": "alice@example.com", "decision": "allow"},
		}})
	}))
	defer srv.Close()

	if err := caSigninLogCmd(stubClient(srv), nil); err != nil {
		t.Fatalf("signin-log: %v", err)
	}
}

// TestCAMigrateCmd — migrate calls POST .../migrate.
func TestCAMigrateCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "migrate") {
			t.Errorf("migrate: expected /migrate path, got %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("migrate: expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"migrated": 3})
	}))
	defer srv.Close()

	if err := caMigrateCmd(stubClient(srv), nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

// ── pack verbs ────────────────────────────────────────────────────────────────

// TestCAInstallPackCmd — install-pack <file> POSTs to /import.
func TestCAInstallPackCmd(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if !strings.Contains(r.URL.Path, "import") {
			t.Errorf("install-pack: expected /import path, got %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	if err := caInstallPackCmd(stubClient(srv), []string{f}); err != nil {
		t.Fatalf("install-pack: %v", err)
	}
	if !called {
		t.Fatal("install-pack: server was not called")
	}
}

// TestCAPackDiffCmd — pack diff <file> calls the diff endpoint and exits 0 on no drift.
func TestCAPackDiffCmd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"drift":   false,
			"changes": []interface{}{},
		})
	}))
	defer srv.Close()

	f := tempDoc(t, minimalDoc)
	if err := caPackCmd(stubClient(srv), []string{"diff", f}); err != nil {
		t.Fatalf("pack diff: %v", err)
	}
}
