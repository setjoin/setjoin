package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseBootstrapAdminFlags(t *testing.T) {
	cfg, err := parseBootstrapAdminFlags([]string{"--email", "Admin@Example.COM", "--password-stdin"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if cfg.email != "admin@example.com" || !cfg.passwordStdin {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseBootstrapAdminFlagsRejectsDisplayAddressAndTwoSources(t *testing.T) {
	for _, args := range [][]string{
		{"--email", "Administrator <admin@example.com>"},
		{"--email", "admin@example.com", "--password-stdin", "--password-file", "secret"},
		{"--unknown"},
		{"--email", "admin@example.com", "extra"},
	} {
		if _, err := parseBootstrapAdminFlags(args); err == nil {
			t.Fatalf("parseBootstrapAdminFlags(%q) succeeded, want error", args)
		}
	}
}

func TestReadBootstrapPasswordPropagatesStdinFailure(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	_ = read.Close()
	if _, err := readBootstrapPassword(bootstrapAdminConfig{passwordStdin: true}, read, &strings.Builder{}); err == nil {
		t.Fatal("closed stdin accepted")
	}
}

func TestRunBootstrapAdminReportsArgumentDatabaseAndPasswordFailures(t *testing.T) {
	if err := runBootstrapAdmin(&cmdCtx{}, "unexpected-action", nil); err == nil {
		t.Fatal("unexpected action accepted")
	}
	c := &cmdCtx{openDB: func() (*pgxpool.Pool, error) { return nil, errors.New("database unavailable") }}
	if err := runBootstrapAdmin(c, "", []string{"--email", "admin@example.test", "--password-stdin"}); err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("database error = %v", err)
	}
}

func TestRunBootstrapAdminRejectsInvalidPasswordAndClosedPool(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &cmdCtx{openDB: func() (*pgxpool.Pool, error) { return pool, nil }}
	if err := runBootstrapAdmin(c, "", []string{"--email", "admin@example.test", "--password-file", filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing password file accepted")
	}
	if err := runBootstrapAdmin(c, "", []string{"--email", "admin@example.test", "--password-file", passwordPath}); err == nil {
		t.Fatal("weak password accepted")
	}
	pool.Close()
	if err := os.WriteFile(passwordPath, []byte("Strong-Password-123!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runBootstrapAdmin(c, "", []string{"--email", "admin@example.test", "--password-file", passwordPath}); err == nil || !strings.Contains(err.Error(), "load password policy") {
		t.Fatalf("closed pool error = %v", err)
	}
}

func TestReadBootstrapPasswordFileRequiresPrivateRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("Strong-Password-123!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, err := readBootstrapPassword(bootstrapAdminConfig{passwordFile: path}, os.Stdin, &strings.Builder{})
	if err != nil {
		t.Fatalf("read private password file: %v", err)
	}
	if string(pw) != "Strong-Password-123!" {
		t.Fatalf("password mismatch: %q", pw)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapPassword(bootstrapAdminConfig{passwordFile: path}, os.Stdin, &strings.Builder{}); err == nil {
		t.Fatal("world-readable password file succeeded, want error")
	}
}

func TestReadBootstrapPasswordRejectsMissingAndDirectory(t *testing.T) {
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), t.TempDir()} {
		if _, err := readBootstrapPassword(bootstrapAdminConfig{passwordFile: path}, os.Stdin, &strings.Builder{}); err == nil {
			t.Fatalf("password path %q accepted", path)
		}
	}
}

func TestReadBootstrapPasswordFromNonTerminalStdin(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	if _, err := write.WriteString("Strong-Password-123!\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	password, err := readBootstrapPassword(bootstrapAdminConfig{passwordStdin: true}, read, &strings.Builder{})
	if err != nil || string(password) != "Strong-Password-123!" {
		t.Fatalf("password=%q err=%v", password, err)
	}
}

func TestReadBootstrapPasswordInteractiveConfirmation(t *testing.T) {
	originalIsTerminal := bootstrapIsTerminal
	originalReadPassword := bootstrapReadPassword
	t.Cleanup(func() {
		bootstrapIsTerminal = originalIsTerminal
		bootstrapReadPassword = originalReadPassword
	})
	bootstrapIsTerminal = func(int) bool { return true }
	responses := [][]byte{[]byte("Strong-Password-123!"), []byte("Strong-Password-123!")}
	bootstrapReadPassword = func(int) ([]byte, error) {
		response := responses[0]
		responses = responses[1:]
		return response, nil
	}
	out := &strings.Builder{}
	password, err := readBootstrapPassword(bootstrapAdminConfig{}, os.Stdin, out)
	if err != nil || string(password) != "Strong-Password-123!" || !strings.Contains(out.String(), "Confirm password") {
		t.Fatalf("password=%q output=%q err=%v", password, out.String(), err)
	}

	responses = [][]byte{[]byte("first"), []byte("second")}
	if _, err := readBootstrapPassword(bootstrapAdminConfig{}, os.Stdin, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("confirmation mismatch error = %v", err)
	}

	bootstrapReadPassword = func(int) ([]byte, error) { return nil, errors.New("terminal failed") }
	if _, err := readBootstrapPassword(bootstrapAdminConfig{}, os.Stdin, &strings.Builder{}); err == nil {
		t.Fatal("first terminal read failure ignored")
	}
	reads := 0
	bootstrapReadPassword = func(int) ([]byte, error) {
		reads++
		if reads == 1 {
			return []byte("first"), nil
		}
		return nil, errors.New("terminal failed")
	}
	if _, err := readBootstrapPassword(bootstrapAdminConfig{}, os.Stdin, &strings.Builder{}); err == nil {
		t.Fatal("confirmation terminal read failure ignored")
	}
}

func TestRunBootstrapAdminRefusesInitializedDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var users int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if users == 0 {
		t.Skip("initialized-database fixture requires at least one user")
	}
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("Strong-Password-123!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &cmdCtx{openDB: func() (*pgxpool.Pool, error) { return pool, nil }}
	err = runBootstrapAdmin(c, "", []string{"--email", "first-admin@example.test", "--password-file", passwordPath})
	if err == nil || !strings.Contains(err.Error(), "bootstrap refused") {
		t.Fatalf("error=%v, want initialized-database refusal", err)
	}
}
