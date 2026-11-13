package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/updater"
)

func commandFlatFixture(t *testing.T) (root, config, quarantine string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "setjoin")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"mailserverd": "gateway", "authserverd": "auth", "mailctl": "cli"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "webmail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "webmail", "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	config = filepath.Join(base, "config.env")
	if err := os.WriteFile(config, []byte("SECRET=fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	quarantine = filepath.Join(base, "quarantine")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return root, config, quarantine
}

func TestRunAdoptDispatchAndErrors(t *testing.T) {
	if got := run([]string{"adopt-current-layout", "--unknown"}); got != 2 {
		t.Fatalf("parse exit=%d", got)
	}
	if got := run([]string{"adopt-current-layout", "extra"}); got != 2 {
		t.Fatalf("positional exit=%d", got)
	}
	if got := run([]string{"adopt-current-layout", "--install-root", "relative"}); got != 1 {
		t.Fatalf("bad root exit=%d", got)
	}
	root, config, quarantine := commandFlatFixture(t)
	if got := run([]string{"adopt-current-layout", "--install-root", root, "--config-file", config, "--quarantine-dir", quarantine}); got != 0 {
		t.Fatalf("adopt exit=%d", got)
	}
}

func TestRunDaemonValidationAndObserverOnce(t *testing.T) {
	if got := run([]string{"--unknown"}); got != 2 {
		t.Fatalf("flag exit=%d", got)
	}
	if got := run([]string{"extra"}); got != 2 {
		t.Fatalf("arg exit=%d", got)
	}
	if got := run([]string{"--state-dir", "relative", "--once"}); got != 1 {
		t.Fatalf("journal exit=%d", got)
	}
	base := t.TempDir()
	state := filepath.Join(base, "state")
	storeRoot := filepath.Join(base, "store")
	if err := os.Mkdir(storeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	prior := openDaemonReleaseStore
	openDaemonReleaseStore = updater.OpenReleaseStore
	t.Cleanup(func() { openDaemonReleaseStore = prior })
	missing := filepath.Join(base, "missing-dsn")
	if got := run([]string{"--state-dir", state, "--release-store", storeRoot, "--dsn-file", missing, "--once"}); got != 1 {
		t.Fatalf("credential exit=%d", got)
	}
	badDSN := filepath.Join(base, "bad-dsn")
	if err := os.WriteFile(badDSN, []byte("postgres://127.0.0.1:1/nope?connect_timeout=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"--state-dir", state, "--release-store", storeRoot, "--dsn-file", badDSN, "--once"}); got != 1 {
		t.Fatalf("control exit=%d", got)
	}

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	dsnPath := filepath.Join(base, "dsn")
	if err := os.WriteFile(dsnPath, []byte(dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"--state-dir", state, "--release-store", storeRoot, "--dsn-file", dsnPath, "--once"}); got != 0 {
		t.Fatalf("observer once exit=%d", got)
	}
	corruptState := filepath.Join(base, "corrupt-state")
	if err := os.Mkdir(corruptState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptState, "events.jsonl"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"--state-dir", corruptState, "--release-store", storeRoot, "--dsn-file", dsnPath, "--once"}); got != 1 {
		t.Fatalf("corrupt observer exit=%d", got)
	}
	if got := run([]string{"--state-dir", filepath.Join(base, "poll-state"), "--release-store", storeRoot, "--dsn-file", dsnPath, "--poll-interval", "1ms"}); got != 1 {
		t.Fatalf("invalid poll exit=%d", got)
	}
}

func TestOfficeAppOnlyRequiresExplicitExecutionGate(t *testing.T) {
	if got := run([]string{"--office-app-only", "--once"}); got != 2 {
		t.Fatalf("office-app-only without execution gate exit=%d", got)
	}
}

func TestOfficeDirectHTTPRequiresOneShotAppOnlyMode(t *testing.T) {
	if got := run([]string{"--office-app-test-direct-http"}); got != 2 {
		t.Fatalf("direct HTTP outside app-only exit=%d", got)
	}
	if got := run([]string{"--office-app-only", "--office-app-execution", "--office-app-test-direct-http"}); got != 2 {
		t.Fatalf("direct HTTP without once exit=%d", got)
	}
}

func TestRunOfficeAppOnlyValidationAndIdleWorker(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := t.TempDir()
	missing := filepath.Join(base, "missing")
	if got := runOfficeAppOnly(context.Background(), logger, missing, missing, filepath.Join(base, "state"), "test", time.Millisecond, true, false); got != 1 {
		t.Fatalf("missing credential exit=%d", got)
	}
	badDSN := writePrivateUpdaterFile(t, base, "bad-dsn", "postgres://127.0.0.1:1/nope?connect_timeout=1\n")
	badManifest := writePrivateUpdaterFile(t, base, "bad-manifest", "{")
	if got := runOfficeAppOnly(context.Background(), logger, badDSN, badManifest, filepath.Join(base, "state"), "test", time.Millisecond, true, false); got != 1 {
		t.Fatalf("bad manifest exit=%d", got)
	}
	manifestPath := filepath.Join("..", "..", "..", "config", "office-managed-app-v1.json")
	if got := runOfficeAppOnly(context.Background(), logger, badDSN, manifestPath, filepath.Join(base, "state"), "test", time.Millisecond, true, false); got != 1 {
		t.Fatalf("bad control exit=%d", got)
	}
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		return
	}
	dsnPath := writePrivateUpdaterFile(t, base, "dsn", dsn+"\n")
	if got := runOfficeAppOnly(context.Background(), logger, dsnPath, manifestPath, "relative", "test", time.Millisecond, true, false); got != 1 {
		t.Fatalf("bad journal exit=%d", got)
	}
	if got := runOfficeAppOnly(context.Background(), logger, dsnPath, manifestPath, filepath.Join(base, "state"), "test", time.Millisecond, true, false); got != 0 {
		t.Fatalf("idle once exit=%d", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if got := runOfficeAppOnly(ctx, logger, dsnPath, manifestPath, filepath.Join(base, "poll-state"), "test", time.Second, false, false); got != 0 {
		t.Fatalf("canceled poll exit=%d", got)
	}
}

func TestRunDaemonManagedAppValidation(t *testing.T) {
	base := t.TempDir()
	storeRoot := filepath.Join(base, "store")
	if err := os.Mkdir(storeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	prior := openDaemonReleaseStore
	openDaemonReleaseStore = updater.OpenReleaseStore
	t.Cleanup(func() { openDaemonReleaseStore = prior })
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	dsnPath := writePrivateUpdaterFile(t, base, "dsn", dsn+"\n")
	args := func(state string) []string {
		return []string{"--state-dir", filepath.Join(base, state), "--release-store", storeRoot, "--dsn-file", dsnPath, "--office-app-execution", "--once"}
	}
	if got := run(append(args("missing-worker"), "--office-app-worker-dsn-file", filepath.Join(base, "missing"))); got != 1 {
		t.Fatalf("missing worker exit=%d", got)
	}
	if got := run(append(args("bad-manifest"), "--office-app-worker-dsn-file", dsnPath, "--office-app-manifest", filepath.Join(base, "missing"))); got != 1 {
		t.Fatalf("bad manifest exit=%d", got)
	}
	manifestPath := filepath.Join("..", "..", "..", "config", "office-managed-app-v1.json")
	badDSN := writePrivateUpdaterFile(t, base, "bad-worker", "postgres://127.0.0.1:1/nope?connect_timeout=1\n")
	if got := run(append(args("bad-worker-state"), "--office-app-worker-dsn-file", badDSN, "--office-app-manifest", manifestPath)); got != 1 {
		t.Fatalf("bad worker exit=%d", got)
	}
	if got := run(append(args("bad-journal"), "--office-app-worker-dsn-file", dsnPath, "--office-app-manifest", manifestPath, "--office-app-state-dir", "relative")); got != 1 {
		t.Fatalf("bad app journal exit=%d", got)
	}
	if got := run(append(args("idle"), "--office-app-worker-dsn-file", dsnPath, "--office-app-manifest", manifestPath, "--office-app-state-dir", filepath.Join(base, "app-state"))); got != 0 {
		t.Fatalf("idle app exit=%d", got)
	}
}

func writePrivateUpdaterFile(t *testing.T, dir, name, value string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunDaemonBuildsExecutionCatalogButDatabaseGateStaysAuthoritative(t *testing.T) {
	base := t.TempDir()
	storeRoot := filepath.Join(base, "store")
	installRoot := filepath.Join(base, "install")
	for _, path := range []string{storeRoot, installRoot} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	prior := openDaemonReleaseStore
	openDaemonReleaseStore = updater.OpenReleaseStore
	t.Cleanup(func() { openDaemonReleaseStore = prior })

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	controlDSN := strings.Replace(dsn, "postgres://mail@", "postgres://setjoin_updater@", 1)
	if controlDSN == dsn {
		t.Skip("test DSN does not expose the local role-rewrite fixture")
	}
	controlPath := writePrivateUpdaterFile(t, base, "control-dsn", controlDSN+"\n")
	ownerPath := writePrivateUpdaterFile(t, base, "owner-dsn", dsn+"\n")
	accessPath := writePrivateUpdaterFile(t, base, "recovery-access", "fixture-access")
	secretPath := writePrivateUpdaterFile(t, base, "recovery-secret", "fixture-secret")
	hmacPath := writePrivateUpdaterFile(t, base, "recovery-hmac", strings.Repeat("h", 32))
	probePath := writePrivateUpdaterFile(t, base, "probe", `{"email":"probe@example.test","password":"Probe-Password-123!"}`)
	configPath := writePrivateUpdaterFile(t, base, "execution.json", fmt.Sprintf(
		`{"version":1,"enabled":true,"installRoot":%q,"recoveryProvider":"s3","recoveryEndpoint":"http://127.0.0.1:9000","recoveryRegion":"us-east-1","recoveryBucket":"setjoin-backup"}`,
		installRoot,
	))
	baseArgs := func(state string) []string {
		return []string{"--state-dir", filepath.Join(base, state), "--release-store", storeRoot, "--dsn-file", controlPath, "--execution-config", configPath, "--once"}
	}
	invalidConfig := writePrivateUpdaterFile(t, base, "execution-invalid.json", `{"version":2,"enabled":false}`)
	if got := run([]string{"--state-dir", filepath.Join(base, "invalid-config-state"), "--release-store", storeRoot, "--dsn-file", controlPath, "--execution-config", invalidConfig, "--once"}); got != 1 {
		t.Fatalf("invalid execution config exit=%d", got)
	}
	if got := run(append(baseArgs("missing-owner-state"), "--owner-dsn-file", filepath.Join(base, "missing-owner"))); got != 1 {
		t.Fatalf("missing owner credential exit=%d", got)
	}
	if got := run(append(baseArgs("same-owner-state"), "--owner-dsn-file", controlPath)); got != 1 {
		t.Fatalf("non-distinct owner credential exit=%d", got)
	}
	badOwnerPath := writePrivateUpdaterFile(t, base, "bad-owner-dsn", "postgres://mail@127.0.0.1:1/nope?connect_timeout=1\n")
	if got := run(append(baseArgs("bad-owner-state"), "--owner-dsn-file", badOwnerPath)); got != 1 {
		t.Fatalf("unreachable owner credential exit=%d", got)
	}
	if got := run(append(baseArgs("missing-execution-credentials-state"), "--owner-dsn-file", ownerPath)); got != 1 {
		t.Fatalf("missing execution credentials exit=%d", got)
	}

	got := run([]string{
		"--state-dir", filepath.Join(base, "state"), "--release-store", storeRoot,
		"--dsn-file", controlPath, "--owner-dsn-file", ownerPath,
		"--execution-config", configPath,
		"--recovery-access-key-file", accessPath,
		"--recovery-secret-key-file", secretPath,
		"--recovery-hmac-key-file", hmacPath,
		"--probe-credential-file", probePath,
		"--once",
	})
	if got != 0 {
		t.Fatalf("execution catalog with authoritative database gate exit=%d", got)
	}
}

func TestRunDaemonPollStopsCleanlyOnSignal(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	base := t.TempDir()
	state, storeRoot := filepath.Join(base, "state"), filepath.Join(base, "store")
	if err := os.Mkdir(storeRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	dsnPath := filepath.Join(base, "dsn")
	if err := os.WriteFile(dsnPath, []byte(dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prior := openDaemonReleaseStore
	openDaemonReleaseStore = updater.OpenReleaseStore
	t.Cleanup(func() { openDaemonReleaseStore = prior })
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	if got := run([]string{"--state-dir", state, "--release-store", storeRoot, "--dsn-file", dsnPath, "--poll-interval", "1s"}); got != 0 {
		t.Fatalf("poll exit=%d", got)
	}
}
