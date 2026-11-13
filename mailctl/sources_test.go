package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/deploysources"
)

func TestBuildSourcesReportIsolatedFailsClosed(t *testing.T) {
	t.Setenv("NETWORK_MODE", "")
	root := sourcesFixture(t)
	report := buildSourcesReport(sourcesOptions{root: root, profile: "isolated", isolatedRegistry: "registry.lan/collabora/code"}, deploysources.ProjectExternalProviders(deploysources.ExternalProviderInput{SpamhausEnabled: true}))
	if report.Healthy {
		t.Fatal("unapproved isolated source reported healthy")
	}
	if report.Collabora.AllowsPublicNetwork || report.Collabora.WritesHost || report.Host.Plan.MutatesHost {
		t.Fatalf("isolated/no-write posture = %+v", report)
	}
	if len(report.Checks) == 0 || report.Checks[0].Code != "isolated_source_unapproved" {
		t.Fatalf("checks = %+v", report.Checks)
	}
}

func TestRunSourcesStatusJSONRedactsAndDoesNotWrite(t *testing.T) {
	t.Setenv("NETWORK_MODE", "global")
	t.Setenv("DB_DSN", "")
	t.Setenv("SAFEBROWSING_API_KEY", "safe-browsing-secret")
	root := sourcesFixture(t)
	path := filepath.Join(root, "etc/apt/sources.list")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := runSources(&cmdCtx{}, "status", []string{"--json", "--root", root}); err != nil {
			t.Fatalf("runSources: %v", err)
		}
	})
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("sources status modified host fixture")
	}
	for _, forbidden := range []string{"safe-browsing-secret", "apt-secret", "token="} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("sources status leaked %q: %s", forbidden, out)
		}
	}
	if !strings.Contains(out, `"mutatesHost": false`) || !strings.Contains(out, `"healthy": true`) {
		t.Fatalf("status output = %s", out)
	}
}

func TestRunSourcesRejectsUnknownAction(t *testing.T) {
	if err := runSources(&cmdCtx{}, "apply", nil); err == nil {
		t.Fatal("mutating sources action unexpectedly accepted")
	}
}

func TestSourcesCLIValidationDoctorAndHumanOutput(t *testing.T) {
	if _, err := parseSourcesOptions("status", []string{"extra"}); err == nil {
		t.Fatal("positional argument accepted")
	}
	if _, err := parseSourcesOptions("status", []string{"--unknown"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
	root := sourcesFixture(t)
	t.Setenv("DB_DSN", "")
	out := captureStdout(t, func() {
		if err := runSources(&cmdCtx{}, "status", []string{"--root", root, "--profile", "global"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"connectivity:", "collabora:", "provider:", "host:", "assist_posture_unavailable"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q: %s", want, out)
		}
	}
	err := runSources(&cmdCtx{}, "doctor", []string{"--root", root, "--profile", "isolated", "--isolated-registry", "registry.lan/collabora/code"})
	var exitErr exitCodeErr
	if !errors.As(err, &exitErr) || exitErr.code != 1 {
		t.Fatalf("doctor error=%v", err)
	}
	for _, value := range []string{"1", " true ", "YES", "on"} {
		t.Setenv("SOURCE_BOOL", value)
		if !envBool("SOURCE_BOOL") {
			t.Fatalf("envBool(%q)=false", value)
		}
	}
	t.Setenv("SOURCE_BOOL", "no")
	if envBool("SOURCE_BOOL") {
		t.Fatal("envBool(no)=true")
	}
}

func TestLocalProviderPostureUnavailableAndDatabase(t *testing.T) {
	t.Setenv("DB_DSN", "configured")
	rows, diagnostic := localProviderPosture(&cmdCtx{openDB: func() (*pgxpool.Pool, error) { return nil, errors.New("offline") }})
	if len(rows) == 0 || diagnostic == nil || diagnostic.Code != "assist_posture_unavailable" {
		t.Fatalf("unavailable posture=%+v %+v", rows, diagnostic)
	}
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		return
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	rows, diagnostic = localProviderPosture(&cmdCtx{openDB: func() (*pgxpool.Pool, error) { return pool, nil }})
	if len(rows) == 0 || diagnostic != nil {
		t.Fatalf("database posture=%+v diagnostic=%+v", rows, diagnostic)
	}
}

func TestBuildSourcesReportExternalMisconfiguration(t *testing.T) {
	report := buildSourcesReport(sourcesOptions{root: sourcesFixture(t), profile: "global"}, []deploysources.ProviderPosture{{Kind: "ai", State: "misconfigured", Detail: "missing model"}})
	if report.Healthy {
		t.Fatal("misconfigured provider reported healthy")
	}
	if got := report.Checks[len(report.Checks)-1].Code; got != "ai_misconfigured" {
		t.Fatalf("check=%s", got)
	}
}

func sourcesFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for path, body := range map[string]string{
		"etc/os-release":       "ID=ubuntu\nVERSION_ID=24.04\n",
		"etc/apt/sources.list": "deb https://" + "user:apt-secret@" + "archive.ubuntu.com/ubuntu noble main\n",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
