package main

// In-process composition-root boot coverage for main() (main.go).
//
// cmd/authserverd/main.go is inside the changed-lines coverage gate (unlike
// mailserverd's, which is excluded), so the boot sequence itself must be
// exercised, not just its extracted helpers. This test runs the REAL main()
// in-process against the test database with a fully offline posture:
//
//   - LISTEN_ADDR is an explicit loopback address on a reserved port;
//   - HTTP(S)_PROXY point at a closed local port and NO_PROXY exempts the
//     loopback server, so the only outbound attempt (the threat-feed fetch
//     goroutine) is refused instantly without touching any network;
//   - the one OIDC RP row seeded for the boot uses a loopback provider_url.
//
// main() exits the process on any boot refusal, so every refusal path the
// environment could reach is PROBED first (schema version, security toggle
// seeds, audit cutover state, signing-keystore decryptability) and reported
// as a loud test failure naming the remediation — never as a dead binary.
// The canonical gate reloads a clean schema (scripts/load-test-schema.sh)
// before the Go lane; a keystore row sealed under a foreign secret means a
// dirty shared database and fails here before main() can exit.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/token"
	maildbschema "setjoin.com/mailserver/sql/dbschema"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// bootTestJWTSecret is deliberately FIXED: the ES256 signing key minted on
// the first boot is sealed under it, so every rerun reuses the same keystore
// row instead of accumulating one key per run.
const bootTestJWTSecret = "boot-test-jwt-secret-0123456789abcdef!!"

// bootTestInternalKey is the INTERNAL_API_KEY the boot uses; the reload
// probes authenticate with it through requireAPIKeyLive.
const bootTestInternalKey = "boot-test-internal-api-key"

// bootVAPIDKey is a base64url raw P-256 scalar (any 32 bytes below the curve
// order are a valid private key) so the push-MFA branch boots fully armed.
//
//	sha256("boot-test-vapid") — deterministic test material.
const bootVAPIDKey = "9U6LCj5VdnAsaBPTRJrLFAq8PGg9Zln3628jUSurh-g"

// TestAuthserverURLHostPort_EmptyHostAfterParse (AUTHSERVERD-005 gap): a URL
// that PARSES with a host part but yields an empty hostname ("http://:8443")
// is not a usable bind contract — the explicit empty-host rejection after
// u.Hostname() must fire, not the earlier u.Host == "" check.
func TestAuthserverURLHostPort_EmptyHostAfterParse(t *testing.T) {
	for name, raw := range map[string]string{
		"port only":      "http://:8443",
		"user port only": "https://user@:8443",
	} {
		t.Run(name, func(t *testing.T) {
			host, port, ok := authserverURLHostPort(raw)
			if ok {
				t.Fatalf("authserverURLHostPort(%q) = (%q, %q, true), want unusable", raw, host, port)
			}
		})
	}
}

// waitHealth polls addr until /health answers 200 (bounded boot window).
func waitHealth(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "ok") {
				return
			}
			t.Fatalf("/health answered %d %q during boot", resp.StatusCode, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("server did not answer /health within the boot window")
}

// postAdminReload POSTs /admin/reload with an optional Bearer key and returns
// the status plus the decoded body.
func postAdminReload(t *testing.T, addr, key string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/admin/reload", nil)
	if err != nil {
		t.Fatalf("build reload request: %v", err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /admin/reload: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// probeBootPreconditions fails the test LOUDLY (with remediation) on any
// database state that would make main() os.Exit mid-boot, so the failure is a
// diagnosable assertion instead of a dead test binary.
func probeBootPreconditions(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	if err := pgxutil.EnforceAuditCutover(ctx, pool, ""); err != nil {
		t.Fatalf("audit cutover precondition: %v (this test boots with an empty AUDIT_HMAC_KEY; activate/clean the test database)", err)
	}
	var expected, actual int
	expected = maildbschema.ExpectedVersion()
	if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&actual); err != nil {
		t.Fatalf("schema version probe: %v", err)
	}
	if actual < expected {
		t.Fatalf("schema stale: expected >= %d, actual %d — run scripts/load-test-schema.sh", expected, actual)
	}
	for _, key := range toggle.SecuritySeededKeys {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM feature_toggles WHERE key = $1`, key).Scan(&n); err != nil {
			t.Fatalf("toggle seed probe: %v", err)
		}
		if n == 0 {
			t.Fatalf("security toggle %q not seeded — run scripts/load-test-schema.sh", key)
		}
	}
	// Signing keystore: every active/retiring row must decrypt under the
	// boot test secret (a foreign-secret row means a dirty shared database —
	// the canonical suite reloads the schema before the Go lane). The probe
	// call is exactly what main() will run at boot, so a failure here is the
	// boot refusal surfaced as a named assertion instead of a dead binary.
	if _, err := token.Load(ctx, pool, []byte(bootTestJWTSecret), cryptokey.ProfileStandard); err != nil {
		t.Fatalf("signing keystore precondition: %v (a signing_keys row is sealed under a foreign JWT secret; run scripts/load-test-schema.sh)", err)
	}
}

func TestMain_BootServesReloadsAndShutsDown(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("TEST_DB_DSN")
	}
	if dsn == "" {
		t.Skip("neither DB_DSN nor TEST_DB_DSN set — the composition-root boot needs its database")
	}

	// Reserve then release a loopback port for the boot's LISTEN_ADDR.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	t.Setenv("DB_DSN", dsn)
	t.Setenv("DB_DIRECT_DSN", dsn)
	t.Setenv("DB_WORKER_DSN", dsn)
	t.Setenv("DB_OWNER_DSN", dsn)
	t.Setenv("JWT_SECRET", bootTestJWTSecret)
	t.Setenv("DB_ENCRYPTION_KEY", "test-totp-encryption-key-32chars")
	t.Setenv("AUDIT_HMAC_KEY", "") // pre-cutover V2: allowed, warns
	t.Setenv("LISTEN_ADDR", addr)
	t.Setenv("AUTHSERVER_URL", "http://"+addr)
	t.Setenv("INTERNAL_API_KEY", bootTestInternalKey)
	t.Setenv("VAPID_PRIVATE_KEY", bootVAPIDKey)
	// OIDC_ENABLED boots the RP provider seam against an EMPTY provider set:
	// the loader reads zero rows, so the boot performs no discovery fetch and
	// no re-seal write. A seeded plaintext row is deliberately avoided — the
	// re-seal sweep is key-pattern-global (oidc_provider_%_config) and the
	// federation package's migration tests assert exact upgraded counts in
	// concurrently running binaries; the re-seal and fail-closed loader
	// behavior is covered by those tests directly.
	t.Setenv("OIDC_ENABLED", "true")
	// Fully offline: the threat-feed goroutine's only outbound request is
	// forced onto a closed local port; the loopback server itself is exempt.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	origSetjoinConfig := os.Getenv("SETJOIN_CONFIG")
	t.Setenv("SETJOIN_CONFIG", "")
	t.Cleanup(func() { os.Setenv("SETJOIN_CONFIG", origSetjoinConfig) })

	// Probe every exit path the environment could reach BEFORE boot.
	probePool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("probe pool: %v", err)
	}
	probeBootPreconditions(t, probePool)
	probePool.Close()

	// Invalid and valid reload sources for the /admin/reload arms.
	badConfig := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	goodPath := filepath.Join(t.TempDir(), "setjoin.yaml")
	if err := os.WriteFile(goodPath, []byte("jwt:\n  issuer: mailserver\n"), 0o600); err != nil {
		t.Fatalf("write reload yaml: %v", err)
	}

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()
	waitHealth(t, addr)

	// Readiness: the pool answers, so /ready must be 200.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/ready")
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ready = %d, want 200", resp.StatusCode)
	}

	// The dynamic INTERNAL_API_KEY gate protects /admin/reload.
	if status, _ := postAdminReload(t, addr, "wrong-key"); status != http.StatusUnauthorized {
		t.Fatalf("/admin/reload with wrong key = %d, want 401", status)
	}

	// Reload with an unloadable config source: honest 500 naming the failure.
	os.Setenv("SETJOIN_CONFIG", badConfig)
	status, body := postAdminReload(t, addr, bootTestInternalKey)
	if status != http.StatusInternalServerError {
		t.Fatalf("/admin/reload with bad source = %d body %v, want 500", status, body)
	}

	// Reload with a valid source: 200 and the partial-reload report.
	os.Setenv("SETJOIN_CONFIG", goodPath)
	status, body = postAdminReload(t, addr, bootTestInternalKey)
	if status != http.StatusOK {
		t.Fatalf("/admin/reload with valid source = %d body %v, want 200", status, body)
	}
	if body["rearmed"] == nil || body["restart_required"] == nil {
		t.Fatalf("reload report missing arms: %v", body)
	}

	// SIGHUP drain: first with the unloadable source (kept old config), then
	// with the valid one (committed) — the drain goroutine's both arms.
	os.Setenv("SETJOIN_CONFIG", badConfig)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	os.Setenv("SETJOIN_CONFIG", goodPath)
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// The live gate serves the rotated-in key material of the last reload.
	status, _ = postAdminReload(t, addr, bootTestInternalKey)
	if status != http.StatusOK {
		t.Fatalf("/admin/reload after SIGHUP reloads = %d, want 200 (key must stay armed)", status)
	}

	// The introspect/revoke routes are live: an authenticated internal caller
	// without a token is answered 400 (never an oracle), an unauthenticated
	// one 401.
	for _, path := range []string{"/auth/introspect", "/auth/revoke"} {
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+path,
			strings.NewReader("token="))
		if err != nil {
			t.Fatalf("build %s request: %v", path, err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+bootTestInternalKey)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("POST %s (key, no token) = %d, want 400", path, resp.StatusCode)
		}

		req2, err := http.NewRequest(http.MethodPost, "http://"+addr+path, nil)
		if err != nil {
			t.Fatalf("build %s request: %v", path, err)
		}
		resp2, err := (&http.Client{Timeout: 5 * time.Second}).Do(req2)
		if err != nil {
			t.Fatalf("POST %s unauthenticated: %v", path, err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusUnauthorized {
			t.Fatalf("POST %s without key = %d, want 401", path, resp2.StatusCode)
		}
	}

	// Graceful shutdown: SIGTERM is caught by main's NotifyContext, which
	// drains the server and returns.
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("main did not return within the shutdown window")
	}
}

// TestMain_BootWithoutInternalKeySkipsInternalRoutes covers the keyless boot
// surface: without INTERNAL_API_KEY the SCIM/reload routes are not registered
// and the loud operator WARN fires — the boot itself still completes and
// shuts down cleanly.
func TestMain_BootWithoutInternalKeySkipsInternalRoutes(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("TEST_DB_DSN")
	}
	if dsn == "" {
		t.Skip("neither DB_DSN nor TEST_DB_DSN set — the composition-root boot needs its database")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	t.Setenv("DB_DSN", dsn)
	t.Setenv("DB_DIRECT_DSN", dsn)
	t.Setenv("DB_WORKER_DSN", dsn)
	t.Setenv("DB_OWNER_DSN", dsn)
	t.Setenv("JWT_SECRET", bootTestJWTSecret)
	t.Setenv("DB_ENCRYPTION_KEY", "test-totp-encryption-key-32chars")
	t.Setenv("AUDIT_HMAC_KEY", "")
	t.Setenv("LISTEN_ADDR", addr)
	t.Setenv("AUTHSERVER_URL", "http://"+addr)
	t.Setenv("INTERNAL_API_KEY", "")
	t.Setenv("OIDC_ENABLED", "")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	done := make(chan struct{})
	go func() {
		main()
		close(done)
	}()
	waitHealth(t, addr)

	// The internal surface must be ABSENT: /admin/reload answers 404 (route
	// never registered), not 401/500.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(
		"http://"+addr+"/admin/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /admin/reload on keyless boot: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /admin/reload on keyless boot = %d, want 404 (not registered)", resp.StatusCode)
	}

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("keyless main did not return within the shutdown window")
	}
}
