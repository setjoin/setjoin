package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/admin"
)

func TestSetupControlSocketIsLocalAndPermissioned(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dir, err := os.MkdirTemp("/tmp", "sj-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := startSetupControlSocket(ctx, socket, "st-token", &admin.SetupHandler{}, logger); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want socket 0600", info.Mode())
	}

	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	resp, err := client.Get("http://setjoin-control/setup/status")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unregistered local GET status = %d, want 404", resp.StatusCode)
	}
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socket); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("control socket was not removed on shutdown")
}

func TestSetupControlSocketRejectsNonSocketCollision(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sj-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(path, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := startSetupControlSocket(context.Background(), path, "st-token", &admin.SetupHandler{}, slog.Default()); err == nil {
		t.Fatal("expected non-socket collision to fail")
	}
}

func TestSetupControlSocketRejectsRelativeAndActivePaths(t *testing.T) {
	if err := startSetupControlSocket(context.Background(), "relative.sock", "st-token", &admin.SetupHandler{}, slog.Default()); err == nil {
		t.Fatal("relative socket path accepted")
	}
	dir, err := os.MkdirTemp("/tmp", "sj-active-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "active.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := startSetupControlSocket(context.Background(), path, "st-token", &admin.SetupHandler{}, slog.Default()); err == nil {
		t.Fatal("active socket collision accepted")
	}
}

func TestSetupControlSocketReplacesStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sj-stale-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "stale.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := startSetupControlSocket(ctx, path, "st-token", &admin.SetupHandler{}, slog.Default()); err != nil {
		t.Fatalf("replace stale socket: %v", err)
	}
	cancel()
}

// TestSetupControlSocketTightensLooseDirectory pins the D-MAILSERVER-CMD-
// MAILSERVERD-005 remediation: a pre-existing socket directory with looser
// permissions is tightened to 0750 instead of being silently used, and the
// socket itself comes up 0600 (born 0700 under the restrictive bind umask,
// then chmod-authoritative — no 0777&^umask accept window).
func TestSetupControlSocketTightensLooseDirectory(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sj-loose-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Pre-create the socket directory world-traversable.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := startSetupControlSocket(ctx, socket, "st-token", &admin.SetupHandler{}, logger); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o750 {
		t.Fatalf("socket dir mode = %v, want 0750 after tightening", got)
	}
	sockInfo, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if sockInfo.Mode().Perm() != 0o600 || sockInfo.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket mode = %v, want socket 0600", sockInfo.Mode())
	}
}

func TestSetupControlSocketReportsFilesystemAndListenFailures(t *testing.T) {
	base := t.TempDir()
	blockingFile := filepath.Join(base, "file")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := startSetupControlSocket(context.Background(), filepath.Join(blockingFile, "control.sock"), "st-token", &admin.SetupHandler{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "create setup control directory") {
		t.Fatalf("directory failure = %v", err)
	}

	// The parent directory must be this test's own temp dir, not /tmp: the
	// socket directory is a pre-existing dir, so a hardened runner (where the
	// test user cannot chmod /tmp) made the tighten step fail INSTEAD of the
	// designed failure injection — the >sun_path listen error below. A test-owned
	// 0700 dir needs no tightening, so the listen failure is what fires.
	tooLong := filepath.Join(t.TempDir(), "sj-"+strings.Repeat("x", 120)+".sock")
	if err := startSetupControlSocket(context.Background(), tooLong, "st-token", &admin.SetupHandler{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "listen on setup control socket") {
		t.Fatalf("listen failure = %v", err)
	}
}

func TestSetupControlSocketReportsStaleRemovalAndPermissionFailures(t *testing.T) {
	originalRemove := removeSetupControlSocket
	originalChmod := chmodSetupControlSocket
	t.Cleanup(func() {
		removeSetupControlSocket = originalRemove
		chmodSetupControlSocket = originalChmod
	})

	staleDir, err := os.MkdirTemp("/tmp", "sj-stale-failure-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(staleDir) })
	stalePath := filepath.Join(staleDir, "control.sock")
	listener, err := net.Listen("unix", stalePath)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = listener.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		probe, dialErr := net.DialTimeout("unix", stalePath, 10*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = probe.Close()
		time.Sleep(10 * time.Millisecond)
	}
	removeSetupControlSocket = func(string) error { return io.ErrUnexpectedEOF }
	if err := startSetupControlSocket(context.Background(), stalePath, "st-token", &admin.SetupHandler{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "remove stale setup control socket") {
		t.Fatalf("stale removal error = %v", err)
	}
	removeSetupControlSocket = originalRemove

	chmodDir, err := os.MkdirTemp("/tmp", "sj-chmod-failure-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(chmodDir) })
	chmodPath := filepath.Join(chmodDir, "control.sock")
	chmodSetupControlSocket = func(string, os.FileMode) error { return io.ErrClosedPipe }
	if err := startSetupControlSocket(context.Background(), chmodPath, "st-token", &admin.SetupHandler{}, slog.Default()); err == nil || !strings.Contains(err.Error(), "secure setup control socket") {
		t.Fatalf("chmod error = %v", err)
	}
}
