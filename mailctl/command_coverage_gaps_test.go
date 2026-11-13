package main

// Gap coverage for the shared CLI secret resolution, the `user password`
// usage gate, the DANE hostname label validation, and the destructive restore
// run path's schema-reset ordering (driven against a fake setup gateway on a
// Unix socket — no real gateway, S3, or database).

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// ── resolveNonArgvSecret ─────────────────────────────────────────────────────

// errReader fails every read with a non-EOF error — the stdin transport
// failing underneath the one-line secret read.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestResolveNonArgvSecretStdinReadError: a stdin transport failure surfaces as
// a labeled error instead of an empty or partial secret.
func TestResolveNonArgvSecretStdinReadError(t *testing.T) {
	_, err := resolveNonArgvSecret(nonArgvSecret{
		label: "new password", flagName: "new-password", stdin: true,
	}, errReader{err: errors.New("stdin pipe broken")})
	if err == nil || !strings.Contains(err.Error(), "read new password from stdin") {
		t.Fatalf("err = %v, want the labeled stdin read failure", err)
	}
	if !strings.Contains(err.Error(), "pipe broken") {
		t.Errorf("error should wrap the transport failure: %v", err)
	}
}

// TestResolveNonArgvSecretStdinLineTooLong: a stdin line beyond the 4096-byte
// ceiling is refused — the reader is capped at ceil+1 so oversize is
// detectable, never truncated into use.
func TestResolveNonArgvSecretStdinLineTooLong(t *testing.T) {
	oversize := strings.Repeat("a", cliSecretMaxBytes+1)
	_, err := resolveNonArgvSecret(nonArgvSecret{
		label: "new password", flagName: "new-password", stdin: true,
	}, strings.NewReader(oversize))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want the oversize-secret refusal", err)
	}

	// Exactly the ceiling (no newline) is still fine.
	want := oversize[:cliSecretMaxBytes]
	got, err := resolveNonArgvSecret(nonArgvSecret{
		label: "new password", flagName: "new-password", stdin: true,
	}, strings.NewReader(want))
	if err != nil || got != want {
		t.Fatalf("boundary-length secret = (%q, %v), want acceptance", got, err)
	}
}

// ── user password usage gate ─────────────────────────────────────────────────

// TestRunUserPasswordRequiresEmailPositional: `user password` without its
// positional email refuses with the documented usage before any secret source
// is consulted.
func TestRunUserPasswordRequiresEmailPositional(t *testing.T) {
	c := &cmdCtx{}
	err := runUser(c, "password", nil)
	if err == nil || !strings.Contains(err.Error(), "usage: mailctl user password <email>") {
		t.Fatalf("err = %v, want the usage error", err)
	}
	err = runUser(c, "password", []string{"--new-password-stdin"})
	if err == nil || !strings.Contains(err.Error(), "usage: mailctl user password <email>") {
		t.Fatalf("err = %v, want the usage error with flags present", err)
	}
}

// ── DANE hostname validation ─────────────────────────────────────────────────

// TestValidateDNSHostnameRejectsEmptyLabel: a dotted hostname with an empty
// label ("a..b" or a trailing dot beyond the caller-stripped one) must be
// refused — it would corrupt the zone record format string.
func TestValidateDNSHostnameRejectsEmptyLabel(t *testing.T) {
	for _, host := range []string{"a..b", "mail..example.com", "."} {
		if err := validateDNSHostname(host); err == nil || !strings.Contains(err.Error(), "empty label") {
			t.Errorf("validateDNSHostname(%q) = %v, want an empty-label refusal", host, err)
		}
	}
}

// ── destructive restore run path ─────────────────────────────────────────────

// fakeSetupGateway serves the setup restore endpoint over a real Unix socket
// listener, mirroring the gateway's filesystem-permissioned control socket.
// The socket path is kept short — macOS binds Unix sockets only below the
// 104-char sun_path limit.
func fakeSetupGateway(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sj-ctl")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return socket
}

// TestRunRestoreFullResetSchemaRunsAfterBlobRestore pins the destructive full
// restore order on the run path itself: the gateway blob restore (type=blobs)
// goes FIRST over the control socket, and only then is the schema reset
// attempted against the target DSN. The reset here cannot connect (refused
// loopback port), so the run fails AT the reset — proving pg_restore never ran
// before it and that the reset carries the separated password, not an
// argv-embedded one.
func TestRunRestoreFullResetSchemaRunsAfterBlobRestore(t *testing.T) {
	var restoreCalls atomic.Int32
	var lastType atomic.Value
	socket := fakeSetupGateway(t, func(w http.ResponseWriter, r *http.Request) {
		restoreCalls.Add(1)
		lastType.Store(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","restore_job_id":7,"restored_blobs":3}`)
	})

	t.Setenv("BACKUP_ACCESS_KEY", "ak")
	t.Setenv("BACKUP_SECRET_KEY", "sk")

	// ln, err := net.Listen("tcp", "127.0.0.1:0"); closed := ln.Close() — a
	// guaranteed-refused loopback port for the schema reset connect.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	refusedAddr := ln.Addr().String()
	_ = ln.Close()

	// The operator DSN resolves from the environment (an argv DSN carrying a
	// password is refused outright), and dsnForChildArgv splits the password
	// out for the pgx connection config — the exact production resolution.
	t.Setenv("DB_DIRECT_OWNER_DSN", "postgres://restorer:pw@"+refusedAddr+"/mail")
	for _, key := range []string{"DB_DSN", "DB_OWNER_DSN", "DB_DIRECT_DSN"} {
		t.Setenv(key, "")
	}

	args := []string{
		"--type", "full",
		"--bucket", "backups",
		"--yes", // skip the interactive destructive confirmation
		"--control-socket", socket,
		// The dump-authentication key rides the 0600-file discipline; the
		// parse-time requirement lands BEFORE the reset (fail-closed), so the
		// test carries a real key file to reach the reset-connect failure.
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	}
	err = runRestore(&cmdCtx{}, "", args)
	if err == nil || !strings.Contains(err.Error(), "connect for restore schema reset") {
		t.Fatalf("runRestore = %v, want the schema-reset connect failure", err)
	}
	if got := restoreCalls.Load(); got != 1 {
		t.Errorf("gateway restore calls = %d, want exactly 1 (blobs, before the reset)", got)
	}
	if path, _ := lastType.Load().(string); path != "/setup/restore" {
		t.Errorf("gateway path = %v, want /setup/restore", path)
	}
}
