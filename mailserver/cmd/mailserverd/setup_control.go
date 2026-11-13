package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"setjoin.com/mailserver/internal/admin"
)

const defaultSetupControlSocket = "/run/setjoin/control.sock"

var (
	removeSetupControlSocket = os.Remove
	chmodSetupControlSocket  = os.Chmod
)

// startSetupControlSocket exposes destructive first-boot recovery operations
// only through a filesystem-permissioned Unix socket. The public HTTP mux never
// registers these routes. Every setup CALL additionally requires the one-time
// setup token install.sh generated (SETJOIN_SETUP_TOKEN — owner decision A3);
// an empty token fails closed inside setupTokenGate (503 on every call).
func startSetupControlSocket(ctx context.Context, socketPath string, setupToken string, setup *admin.SetupHandler, logger *slog.Logger) error {
	if !filepath.IsAbs(socketPath) {
		return fmt.Errorf("setup control socket must be an absolute path")
	}
	dir := filepath.Dir(socketPath)
	//nolint:gosec // G703: socketPath must be absolute and is local operator configuration
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create setup control directory: %w", err)
	}
	// MkdirAll's mode only applies to directories IT creates; a pre-existing
	// directory keeps its (possibly looser) mode. Verify and tighten to 0750 so
	// the socket's parent can never stay world/group-traversable (the finding's
	// "dir perms unverified" arm of the CWE-368 window).
	//nolint:gosec // G703: absolute local operator-configured Unix-socket directory
	if info, statErr := os.Lstat(dir); statErr == nil && info.IsDir() {
		if perm := info.Mode().Perm(); perm&0o027 != 0 {
			//nolint:gosec // G703: same validated directory, tightened to 0750
			if chmodErr := os.Chmod(dir, 0o750); chmodErr != nil {
				return fmt.Errorf("tighten setup control directory permissions: %w", chmodErr)
			}
			logger.Warn("tightened setup control directory permissions", "dir", dir, "old", perm, "new", os.FileMode(0o750))
		}
	}
	//nolint:gosec // G703: absolute local operator-configured Unix-socket path
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("setup control path exists and is not a socket")
		}
		//nolint:gosec // G704: absolute local Unix-socket path, never an IP/network destination
		probe, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if dialErr == nil {
			_ = probe.Close()
			return fmt.Errorf("setup control socket is already active")
		}
		//nolint:gosec // G703: same validated Unix-socket path; Lstat proved socket type
		if err := removeSetupControlSocket(socketPath); err != nil {
			return fmt.Errorf("remove stale setup control socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect setup control socket: %w", err)
	}

	// Bind with a restrictive umask so the socket is born 0700: net.Listen(2)
	// creates the node 0777&^umask, so without this the control socket — front
	// door for destructive recovery endpoints — accepts connections from any
	// local process in the window between listen(2) and the chmod below
	// (CWE-368). The chmod(0600) stays as the authoritative permission.
	oldMask := syscall.Umask(0o077)
	listener, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen on setup control socket: %w", err)
	}
	//nolint:gosec // G703: chmod of the just-created validated Unix socket
	if err := chmodSetupControlSocket(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = removeSetupControlSocket(socketPath)
		return fmt.Errorf("secure setup control socket: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /setup/preflight", setupTokenGate(setupToken, logger, setup.PreFlight))
	mux.HandleFunc("POST /setup/restore", setupTokenGate(setupToken, logger, setup.StartRestore))
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       30 * time.Second,
	}
	//nolint:gosec // G118: server lifetime is owned by the sibling ctx shutdown goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error("setup control server failed", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		//nolint:gosec // G703: socketPath is validated as an absolute configured control-socket path above.
		_ = removeSetupControlSocket(socketPath)
	}()
	logger.Info("local setup control socket ready", "path", socketPath)
	return nil
}
