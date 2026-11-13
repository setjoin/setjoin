package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/toggle"
)

const officeFeatureFixture = `[
  {"key":"feature.drive","enabled":false,"storedEnabled":false,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"database"},
  {"key":"feature.office_editing","enabled":false,"storedEnabled":null,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"default","dependencies":["feature.drive"]},
  {"key":"feature.office_local_open","enabled":false,"storedEnabled":null,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"default","dependencies":["feature.drive"]},
  {"key":"feature.drive_history","enabled":false,"storedEnabled":null,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"default","dependencies":["feature.drive"]}
]`

func officeTestServer(t *testing.T, body string, handler func(*http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/admin/features" {
			t.Errorf("unexpected Office request %s %s", r.Method, r.URL.Path)
			return
		}
		if handler != nil {
			handler(r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
}

func officeTestContext(server *httptest.Server) *cmdCtx {
	return &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}}
}

func TestOfficeCommandRegistration(t *testing.T) {
	command := lookup("office")
	if command == nil {
		t.Fatal("office command is not registered")
	}
	if command.mode != modeREST || command.run == nil {
		t.Fatalf("office command = %+v, want modeREST with a run handler", command)
	}
	if !strings.HasPrefix(command.usage, "office doctor") {
		t.Fatalf("office usage = %q, want doctor/diagnostics usage", command.usage)
	}
}

func TestOfficeInstallCarriesFencesAndNeverActivatesRouting(t *testing.T) {
	key := "11111111-1111-4111-8111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/admin/apps/collabora-code/operations" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Audit-Reason") != "install approved test editor" || r.Header.Get("Idempotency-Key") != key {
			t.Fatalf("mutation headers reason=%q key=%q", r.Header.Get("X-Audit-Reason"), r.Header.Get("Idempotency-Key"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["kind"] != "install" || body["providerId"] != "collabora" {
			t.Fatalf("body=%v", body)
		}
		_, _ = io.WriteString(w, `{"operationId":"22222222-2222-4222-8222-222222222222","state":"requested"}`)
	}))
	defer server.Close()
	ctx := officeTestContext(server)
	ctx.yes = true
	if err := runOffice(ctx, "install", []string{"--generation", "3", "--reason", "install approved test editor", "--idempotency-key", key}); err != nil {
		t.Fatal(err)
	}
}

func TestOfficeActivationRequiresConfirmation(t *testing.T) {
	ctx := &cmdCtx{}
	err := runOffice(ctx, "activate", []string{"--generation", "2", "--qualification", "11111111-1111-4111-8111-111111111111", "--reason", "activate qualified provider"})
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("activation confirmation error=%v", err)
	}
}

func TestOfficeLifecycleCommandsCoverStatusConfigureQualifyActivateRecover(t *testing.T) {
	seen := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path]++
		if r.Method != http.MethodGet {
			if r.Header.Get("X-Audit-Reason") == "" {
				t.Errorf("missing audit reason for %s", r.URL.Path)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode %s: %v", r.URL.Path, err)
			}
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	ctx := officeTestContext(server)
	ctx.yes = true
	qualification := "11111111-1111-4111-8111-111111111111"
	operation := "22222222-2222-4222-8222-222222222222"
	commands := []struct {
		action string
		args   []string
	}{
		{"status", nil},
		{"configure", []string{"--generation", "0", "--discovery-url", "https://office.example/discovery", "--wopi-base-url", "https://setjoin.example/wopi", "--editor-url", "https://office.example/editor", "--allow-hosts", "office.internal, office2.internal", "--allow-cidrs", "10.0.0.0/24", "--build-id", "build", "--reason", "configure coverage"}},
		{"qualify", []string{"--generation", "1", "--synthetic-receipt", "7", "--build-digest", "sha256:" + strings.Repeat("a", 64), "--reason", "qualify coverage"}},
		{"activate", []string{"--generation", "1", "--qualification", qualification, "--scope", `{"departments":[1]}`, "--reason", "activate coverage"}},
		{"recover", []string{"--operation", operation, "--generation", "2", "--reason", "recover coverage"}},
	}
	captureStdout(t, func() {
		for _, command := range commands {
			if err := runOffice(ctx, command.action, command.args); err != nil {
				t.Fatalf("%s: %v", command.action, err)
			}
		}
	})
	for _, key := range []string{
		"GET /api/admin/office",
		"PUT /api/admin/office/providers/collabora",
		"POST /api/admin/office/providers/collabora/qualify",
		"POST /api/admin/office/providers/collabora/activate",
		"POST /api/admin/apps/collabora-code/operations/" + operation + "/recover",
	} {
		if seen[key] != 1 {
			t.Errorf("request %s count=%d", key, seen[key])
		}
	}
}

func TestOfficeLifecycleValidationBranches(t *testing.T) {
	ctx := &cmdCtx{}
	for _, tc := range []struct {
		action string
		args   []string
	}{
		{"status", []string{"extra"}},
		{"configure", nil},
		{"qualify", nil},
		{"activate", []string{"--generation", "0"}},
		{"activate", []string{"--generation", "1", "--qualification", "bad", "--reason", "x"}},
		{"install", []string{"--generation", "0"}},
		{"install", []string{"--generation", "1", "--reason", "x"}},
		{"recover", []string{"--generation", "0"}},
		{"recover", []string{"--operation", "bad", "--generation", "1", "--reason", "x"}},
		{"unknown-lifecycle", nil},
	} {
		if err := officeLifecycleCmd(ctx, tc.action, tc.args); err == nil {
			t.Errorf("%s accepted invalid input", tc.action)
		}
	}
	ctx.yes = true
	if err := officeActivateCmd(ctx, []string{"--generation", "1", "--qualification", "11111111-1111-4111-8111-111111111111", "--scope", `{`, "--reason", "x"}); err == nil {
		t.Fatal("malformed activation scope accepted")
	}
	if err := officeInstallCmd(ctx, []string{"--generation", "1", "--ingress", `{`, "--reason", "x"}); err == nil {
		t.Fatal("malformed ingress accepted")
	}
	if got := splitOfficeCSV(" a, ,b "); len(got) != 2 || nullableOfficeString("") != nil || nullableOfficeString("x") != "x" {
		t.Fatalf("helpers csv=%v", got)
	}
}

func TestOfficeLifecyclePropagatesTransportFailuresAndConfirmationGuards(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "offline", http.StatusServiceUnavailable) }))
	defer server.Close()
	ctx := officeTestContext(server)
	ctx.yes = true
	qualification := "11111111-1111-4111-8111-111111111111"
	operation := "22222222-2222-4222-8222-222222222222"
	for _, tc := range []struct {
		action string
		args   []string
	}{
		{"status", nil},
		{"configure", []string{"--generation", "0", "--discovery-url", "https://office.example/discovery", "--wopi-base-url", "https://setjoin.example/wopi", "--editor-url", "https://office.example/editor", "--reason", "transport failure"}},
		{"qualify", []string{"--generation", "1", "--synthetic-receipt", "1", "--reason", "transport failure"}},
		{"activate", []string{"--generation", "1", "--qualification", qualification, "--reason", "transport failure"}},
		{"install", []string{"--generation", "1", "--reason", "transport failure"}},
		{"recover", []string{"--operation", operation, "--generation", "1", "--reason", "transport failure"}},
	} {
		if err := runOffice(ctx, tc.action, tc.args); err == nil {
			t.Errorf("%s swallowed transport failure", tc.action)
		}
	}
	no := &cmdCtx{}
	if err := officeRecoverCmd(no, []string{"--operation", operation, "--generation", "1", "--reason", "x"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("recover confirmation=%v", err)
	}
	if err := officeInstallCmd(no, []string{"--generation", "1", "--reason", "x"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("install confirmation=%v", err)
	}
	no.yes = true
	if err := officeInstallCmd(no, []string{"--generation", "1", "--idempotency-key", "bad", "--reason", "x"}); err == nil {
		t.Fatal("invalid idempotency key accepted")
	}
	if err := officeMutation(no, http.MethodPost, "/x", "", "", map[string]any{}); err == nil {
		t.Fatal("empty audit reason accepted")
	}
}

func TestOfficeDoctorReadsFeatureRegistryAndReportsDefaultOff(t *testing.T) {
	server := officeTestServer(t, officeFeatureFixture, nil)
	defer server.Close()

	ctx := officeTestContext(server)
	ctx.json = true
	out := captureStdout(t, func() {
		if err := runOffice(ctx, "doctor", nil); err != nil {
			t.Fatalf("office doctor: %v", err)
		}
	})

	var report officeDoctorReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("doctor JSON: %v\n%s", err, out)
	}
	if report.Source != "admin feature registry" || report.Endpoint != officeFeatureEndpoint {
		t.Fatalf("doctor source = %q endpoint = %q", report.Source, report.Endpoint)
	}
	if len(report.Flags) != 3 || len(report.Hints) == 0 {
		t.Fatalf("doctor flags/hints = %d/%d, want three flags and hints", len(report.Flags), len(report.Hints))
	}
	for _, flag := range report.Flags {
		if !flag.Present || flag.Enabled || !flag.DefaultOff || flag.State != "off" {
			t.Errorf("flag %s = %+v, want present/default-OFF/off", flag.Key, flag)
		}
	}
	if !strings.Contains(out, "default-OFF") {
		t.Errorf("doctor JSON should carry the default-OFF configuration hint: %s", out)
	}
}

func TestOfficeDoctorHumanOutputCarriesJSONFacts(t *testing.T) {
	server := officeTestServer(t, officeFeatureFixture, nil)
	defer server.Close()

	out := captureStdout(t, func() {
		if err := runOffice(officeTestContext(server), "doctor", nil); err != nil {
			t.Fatalf("office doctor: %v", err)
		}
	})
	for _, want := range []string{
		"Office doctor",
		"feature.office_editing",
		"feature.office_local_open",
		"feature.drive_history",
		"feature.drive",
		"default OFF",
		"default-OFF",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human doctor output missing %q: %s", want, out)
		}
	}
}

func TestOfficeDoctorFailsWhenARequiredFlagIsMissing(t *testing.T) {
	server := officeTestServer(t, `[{"key":"feature.office_editing","enabled":false,"defaultEnabled":false}]`, nil)
	defer server.Close()

	ctx := officeTestContext(server)
	out := captureStdout(t, func() {
		err := runOffice(ctx, "doctor", nil)
		if err == nil {
			t.Fatal("office doctor: want missing-flag error")
		}
		exit, ok := err.(exitCodeErr)
		if !ok || exit.code != 1 {
			t.Fatalf("office doctor error = %T(%v), want exitCodeErr(1)", err, err)
		}
	})
	if !strings.Contains(out, "missing") || !strings.Contains(out, "feature.drive_history") {
		t.Errorf("missing-flag doctor output = %q", out)
	}
}

func TestOfficeDiagnosticsIsSanitizedAndUsesOnlyFeatureAPI(t *testing.T) {
	const secret = "office-provider-secret-must-not-appear"
	body := `[{"key":"feature.drive","enabled":true,"defaultEnabled":false,"gatewayEffective":true,"gatewaySource":"database"},` +
		`{"key":"feature.office_editing","enabled":true,"storedEnabled":true,"defaultEnabled":false,"gatewayEffective":true,"gatewaySource":"database","dependencies":["feature.drive"],"providerSecret":"` + secret + `"},` +
		`{"key":"feature.office_local_open","enabled":false,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"default"},` +
		`{"key":"feature.drive_history","enabled":false,"defaultEnabled":false,"gatewayEffective":false,"gatewaySource":"default"}]`
	server := officeTestServer(t, body, nil)
	defer server.Close()

	ctx := officeTestContext(server)
	ctx.json = true
	ctx.client.AuthToken = "bearer-token-must-not-appear"
	out := captureStdout(t, func() {
		if err := runOffice(ctx, "diagnostics", nil); err != nil {
			t.Fatalf("office diagnostics: %v", err)
		}
	})
	if strings.Contains(out, secret) || strings.Contains(out, "bearer-token-must-not-appear") {
		t.Fatalf("diagnostics leaked credential/provider data: %s", out)
	}
	var report officeDiagnosticsReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("diagnostics JSON: %v\n%s", err, out)
	}
	if report.Status != "ok" || len(report.Flags) != 3 {
		t.Fatalf("diagnostics report = %+v, want ok and three flags", report)
	}
	if report.Flags[0].Key != toggle.FeatureOfficeEditing && report.Flags[1].Key != toggle.FeatureOfficeEditing && report.Flags[2].Key != toggle.FeatureOfficeEditing {
		t.Fatalf("diagnostics missing Office editing status: %+v", report.Flags)
	}
}

func TestOfficeDiagnosticsReportsPartialRegistryWithoutConfigurationError(t *testing.T) {
	server := officeTestServer(t, `[{"key":"feature.drive_history","enabled":false,"defaultEnabled":false}]`, nil)
	defer server.Close()

	ctx := officeTestContext(server)
	ctx.json = true
	out := captureStdout(t, func() {
		if err := runOffice(ctx, "diagnostics", nil); err != nil {
			t.Fatalf("office diagnostics: %v", err)
		}
	})
	var report officeDiagnosticsReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("diagnostics JSON: %v", err)
	}
	if report.Status != "partial" {
		t.Fatalf("diagnostics status = %q, want partial", report.Status)
	}
}

func TestRunOfficeRejectsUnknownActionAndUnexpectedArguments(t *testing.T) {
	ctx := &cmdCtx{}
	if err := runOffice(ctx, "unknown", nil); err == nil {
		t.Fatal("unknown Office action accepted")
	}
	if err := runOffice(ctx, "doctor", []string{"unexpected"}); err == nil {
		t.Fatal("unexpected Office doctor argument accepted")
	}
	if err := runOffice(ctx, "doctor", []string{"--not-a-flag"}); err == nil {
		t.Fatal("invalid Office doctor flag accepted")
	}
	if err := runOffice(ctx, "diagnostics", []string{"--not-a-flag"}); err == nil {
		t.Fatal("invalid Office diagnostics flag accepted")
	}
}

func TestOfficeDoctorDependencyBlockerAndTransportFailures(t *testing.T) {
	blocked := `[
		{"key":"feature.drive","enabled":false,"gatewayEffective":false},
		{"key":"feature.office_editing","enabled":true,"storedEnabled":true,"defaultEnabled":false,"gatewayEffective":true,"dependencies":["feature.drive"]},
		{"key":"feature.office_local_open","enabled":false,"storedEnabled":false,"defaultEnabled":false,"gatewayEffective":false},
		{"key":"feature.drive_history","enabled":false,"defaultEnabled":false,"gatewayEffective":false}
	]`
	server := officeTestServer(t, blocked, nil)
	defer server.Close()
	err := runOffice(officeTestContext(server), "doctor", []string{"--quiet"})
	if exit, ok := err.(exitCodeErr); !ok || exit.code != 1 || !strings.Contains(exit.msg, "dependencies") {
		t.Fatalf("dependency error=%T(%v)", err, err)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	if err := runOffice(officeTestContext(failing), "doctor", nil); err == nil {
		t.Fatal("doctor accepted failed feature API")
	}
	if err := runOffice(officeTestContext(failing), "diagnostics", nil); err == nil {
		t.Fatal("diagnostics accepted failed feature API")
	}
}

func TestOfficeStatusBranchesAndDiagnosticsHumanOutput(t *testing.T) {
	on, off := true, false
	rows := []officeFeatureWire{
		{Key: toggle.FeatureDrive, Enabled: true, GatewayEffective: &on},
		{Key: toggle.FeatureOfficeEditing, Enabled: false, StoredEnabled: &off, DefaultEnabled: &on, GatewayEffective: &off, GatewaySource: "database"},
		{Key: toggle.FeatureOfficeLocalOpen, Enabled: false, DefaultEnabled: &off, GatewayEffective: &off},
		{Key: toggle.FeatureDriveHistory, Enabled: true, StoredEnabled: &on, DefaultEnabled: &off, GatewayEffective: &on, GatewaySource: "database"},
	}
	statuses, missing, blockers := buildOfficeFlagStatuses(rows)
	if len(missing) != 0 || len(blockers) != 0 || len(statuses) != 3 {
		t.Fatalf("statuses=%+v missing=%v blockers=%v", statuses, missing, blockers)
	}
	if statuses[0].Hint == "" || statuses[1].GatewaySource != "unknown" || statuses[2].State != "on" {
		t.Fatalf("branch status=%+v", statuses)
	}
	hints := officeDoctorHints(statuses, nil, nil)
	if len(hints) == 0 || boolWord(true) != "on" || boolWord(false) != "off" {
		t.Fatalf("hints=%v", hints)
	}

	server := officeTestServer(t, officeFeatureFixture, nil)
	defer server.Close()
	out := captureStdout(t, func() {
		if err := runOffice(officeTestContext(server), "diagnostics", nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Office diagnostics") || !strings.Contains(out, "requires=feature.drive") {
		t.Fatalf("diagnostics human=%q", out)
	}

	defaultOn := captureStdout(t, func() {
		printOfficeDoctorHuman(officeDoctorReport{Flags: []officeFlagStatus{{
			Key: "feature.synthetic", State: "off", DefaultOff: false, Configured: true,
		}}})
	})
	if !strings.Contains(defaultOn, "default ON configured") {
		t.Fatalf("default-ON configured output=%q", defaultOn)
	}

	rows = []officeFeatureWire{
		{Key: toggle.FeatureDrive, Enabled: true, GatewayEffective: &on},
		{Key: toggle.FeatureOfficeEditing, Enabled: false, DefaultEnabled: &on, GatewayEffective: &off},
		{Key: toggle.FeatureOfficeLocalOpen, Enabled: false, DefaultEnabled: &off, GatewayEffective: &off},
		{Key: toggle.FeatureDriveHistory, Enabled: false, DefaultEnabled: &off, GatewayEffective: &off},
	}
	statuses, _, _ = buildOfficeFlagStatuses(rows)
	if statuses[0].Hint == "" || statuses[0].Configured {
		t.Fatalf("default-ON unconfigured status=%+v", statuses[0])
	}
}
