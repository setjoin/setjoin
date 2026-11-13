package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestControlClientUsesUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sj-mailctl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(preflightResp{BlobCount: 3})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	resp, err := newControlClient(socket).preflight(restoreReq{Type: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.BlobCount != 3 {
		t.Fatalf("blob count = %d, want 3", resp.BlobCount)
	}
}

// TestPgRestoreArgs asserts the exact flag set the restore command builds for
// pg_restore: custom-format input, --clean --if-exists, the DSN, and the input
// file. TDD-able core of the os/exec shell. The builder receives an
// already-stripped (credential-free) DSN — dsnForChildArgv separates the
// password at parse time and pgChildEnv delivers it via PGPASSWORD, never argv.
func TestPgRestoreArgs(t *testing.T) {
	dsn := "postgres://u@localhost:5432/maildb"
	in := "/tmp/db-dump.dump"
	args := pgRestoreArgs(dsn, in)

	if !contains(args, "--clean") {
		t.Errorf("pgRestoreArgs missing --clean: %v", args)
	}
	if !contains(args, "--if-exists") {
		t.Errorf("pgRestoreArgs missing --if-exists: %v", args)
	}
	if !contains(args, "--dbname="+dsn) {
		t.Errorf("pgRestoreArgs missing --dbname=%s: %v", dsn, args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "password=") {
			t.Errorf("pgRestoreArgs must never carry a password in argv: %v", args)
		}
	}
	if contains(args, "--no-owner") {
		t.Errorf("pgRestoreArgs must replay specialized ownership: %v", args)
	}
	if contains(args, "--no-privileges") {
		t.Errorf("pgRestoreArgs must replay runtime ACLs: %v", args)
	}
	// The input file is the trailing positional argument.
	if args[len(args)-1] != in {
		t.Errorf("pgRestoreArgs last arg = %q, want input path %q", args[len(args)-1], in)
	}
}

// TestParseRestoreFlagsInvalidType rejects an unknown --type.
func TestParseRestoreFlagsInvalidType(t *testing.T) {
	// Env-sourced credentials keep the argv-secret refusal out of the way so the
	// type validation is what is under test.
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseRestoreFlags([]string{
		"--type", "bogus", "--bucket", "b", "--control-socket", "/tmp/control.sock", "--yes",
	})
	if err == nil {
		t.Fatal("expected error for invalid --type")
	}
	if !strings.Contains(err.Error(), "type") {
		t.Errorf("error should mention type: %v", err)
	}
}

func TestParseRestoreFlagsDefaultsToLocalControlSocket(t *testing.T) {
	t.Setenv("SETJOIN_CONTROL_SOCKET", "")
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	cfg, err := parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--yes",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.controlSocket != defaultSetupControlSocket {
		t.Fatalf("control socket = %q, want %q", cfg.controlSocket, defaultSetupControlSocket)
	}
}

func TestParseRestoreFlagsRejectsRelativeControlSocket(t *testing.T) {
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseRestoreFlags([]string{"--type", "config", "--bucket", "b", "--control-socket", "relative.sock"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("error = %v, want absolute-path rejection", err)
	}
}

// TestParseRestoreFlagsFullRequiresDSN: a non-dry-run full restore needs a DSN
// for pg_restore.
func TestParseRestoreFlagsFullRequiresDSN(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b",
		"--control-socket", "/tmp/control.sock", "--yes",
	})
	if err == nil {
		t.Fatal("expected error: full restore needs a DSN")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "dsn") {
		t.Errorf("error should mention DSN: %v", err)
	}
}

// TestParseRestoreFlagsFullDryRunNoDSN: a dry-run never needs a DSN (it only
// hits preflight).
func TestParseRestoreFlagsFullDryRunNoDSN(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	cfg, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b",
		"--control-socket", "/tmp/control.sock", "--dry-run",
	})
	if err != nil {
		t.Fatalf("dry-run full should not require a DSN: %v", err)
	}
	if !cfg.dryRun {
		t.Error("dryRun flag not set")
	}
}

// TestParseRestoreFlagsHashes parses the csv --hashes list for type=blobs.
func TestParseRestoreFlagsHashes(t *testing.T) {
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	cfg, err := parseRestoreFlags([]string{
		"--type", "blobs", "--bucket", "b",
		"--control-socket", "/tmp/control.sock",
		"--hashes", "aaa,bbb,ccc", "--yes",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.hashes) != 3 || cfg.hashes[0] != "aaa" || cfg.hashes[2] != "ccc" {
		t.Errorf("hashes not parsed: %v", cfg.hashes)
	}
}

// TestParseRestoreFlagsRefusesArgvSecrets asserts the Invariant 5 control on the
// restore lane: explicit --access-key/--secret-key argv values are refused with
// guidance, without echoing the secret.
func TestParseRestoreFlagsRefusesArgvSecrets(t *testing.T) {
	for _, name := range []string{"access-key", "secret-key"} {
		args := []string{"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock", "--" + name, "argv-value"}
		_, err := parseRestoreFlags(args)
		if err == nil {
			t.Fatalf("--%s on the command line: expected refusal", name)
		}
		if !strings.Contains(err.Error(), "must not be passed on the command line") {
			t.Errorf("--%s: error should refuse argv secrets: %v", name, err)
		}
		if strings.Contains(err.Error(), "argv-value") {
			t.Errorf("--%s: refusal must not echo the secret value: %v", name, err)
		}
	}
}

// TestParseRestoreFlagsAcceptsFileSecrets asserts the 0600-file source feeds the
// wire request credentials.
func TestParseRestoreFlagsAcceptsFileSecrets(t *testing.T) {
	accessPath, secretPath := writeCredentialFiles(t, "file-access", "file-secret")
	cfg, err := parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock",
		"--access-key-file", accessPath, "--secret-key-file", secretPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.s3.AccessKey != "file-access" || cfg.s3.SecretKey != "file-secret" {
		t.Errorf("file credentials not resolved: %+v", cfg.s3)
	}
}

// TestParseRestoreFlagsRefusesArgvDSNWithEmbeddedPassword mirrors the backup-db
// control: credential-bearing --dsn argv values are refused (they sit in this
// process's own command line); credential-free DSNs stay allowed.
func TestParseRestoreFlagsRefusesArgvDSNWithEmbeddedPassword(t *testing.T) {
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock",
		"--dsn", "postgres://owner:sekret@h/db",
	})
	if err == nil || !strings.Contains(err.Error(), "embedded credentials") {
		t.Fatalf("expected --dsn credential refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Errorf("refusal must not echo the secret: %v", err)
	}
	cfg, err := parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock",
		"--dsn", "postgres://owner@h/db",
	})
	if err != nil {
		t.Fatalf("credential-free --dsn must be accepted: %v", err)
	}
	if cfg.dsn != "postgres://owner@h/db" {
		t.Errorf("dsn = %q", cfg.dsn)
	}
}

// TestParseRestoreFlagsEnvDSNPasswordStrippedForChildArgv mirrors the backup-db
// round-2 control: a credential-bearing DSN from the ENVIRONMENT is stripped at
// parse time and its password travels via PGPASSWORD/pgx, never pg_restore argv.
// Both conninfo shapes are covered.
func TestParseRestoreFlagsEnvDSNPasswordStrippedForChildArgv(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")

	t.Setenv("DB_OWNER_DSN", "postgres://owner:envsecret@h/db")
	cfg, err := parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "postgres://owner@h/db" || strings.Contains(cfg.dsn, "envsecret") {
		t.Errorf("env DSN not stripped: %q", cfg.dsn)
	}
	if cfg.dbPassword != "envsecret" {
		t.Errorf("dbPassword = %q, want the separated env secret", cfg.dbPassword)
	}

	t.Setenv("DB_OWNER_DSN", "host=h dbname=db password=kwsecret")
	cfg, err = parseRestoreFlags([]string{
		"--type", "config", "--bucket", "b", "--control-socket", "/tmp/c.sock",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "host=h dbname=db" || strings.Contains(cfg.dsn, "kwsecret") {
		t.Errorf("keyword-form env DSN not stripped: %q", cfg.dsn)
	}
	if cfg.dbPassword != "kwsecret" {
		t.Errorf("dbPassword = %q, want the separated env secret", cfg.dbPassword)
	}
}

// TestRestoreUnknownFlagUsageDoesNotLeakResolvedSecret pins the round-2 fix on
// the restore lane: secret flags carry placeholder defaults, so Go's default
// usage printer — invoked when an unknown flag fails parsing — cannot echo an
// environment-resolved secret.
func TestRestoreUnknownFlagUsageDoesNotLeakResolvedSecret(t *testing.T) {
	const secret = "supersecret-env-value"
	t.Setenv("BACKUP_ACCESS_KEY", "access-"+secret)
	t.Setenv("BACKUP_SECRET_KEY", secret)
	usage := captureFlagUsageStderr(t, func() {
		_, _ = parseRestoreFlags([]string{"--nonexistent-flag", "--bucket", "b"})
	})
	if !strings.Contains(usage, "flag provided but not defined") {
		t.Fatalf("expected Go's default usage output on an unknown flag, got:\n%s", usage)
	}
	if strings.Contains(usage, secret) {
		t.Errorf("usage output leaked the resolved secret:\n%s", usage)
	}
}

// ── Gateway HTTP client ────────────────────────────────────────────────────

// TestGatewayPreflight200 drives the preflight client against a canned 200 and
// asserts the decoded preview.
func TestGatewayPreflight200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/setup/preflight" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req restoreReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Bucket != "mybucket" {
			t.Errorf("bucket not forwarded: %+v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(preflightResp{
			Timestamp:          "2026-06-21T00:00:00Z",
			BlobCount:          42,
			BlobTotalSizeBytes: 1024,
			ConfigSizeBytes:    256,
			UserCount:          7,
			DomainCount:        2,
			Warnings:           []string{"stale manifest"},
		})
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	resp, err := gc.preflight(restoreReq{Bucket: "mybucket", AccessKey: "a", SecretKey: "s", Type: "full"})
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if resp.BlobCount != 42 || resp.UserCount != 7 || resp.DomainCount != 2 {
		t.Errorf("preflight decode wrong: %+v", resp)
	}
	if len(resp.Warnings) != 1 || resp.Warnings[0] != "stale manifest" {
		t.Errorf("warnings not decoded: %+v", resp.Warnings)
	}
}

// TestGatewayPreflight409 maps a 409 (already has users / not in setup mode) to
// an error.
func TestGatewayPreflight409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"Setup already completed"}`))
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	_, err := gc.preflight(restoreReq{Bucket: "b", AccessKey: "a", SecretKey: "s", Type: "full"})
	if err == nil {
		t.Fatal("expected error on 409")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error should mention status 409: %v", err)
	}
}

// TestGatewayRestore200 drives the restore client against a canned success.
func TestGatewayRestore200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setup/restore" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req restoreReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(restoreResp{
			Status:             "completed",
			RestoreJobID:       99,
			RestoredConfigKeys: 12,
			RestoredBlobs:      42,
			Errors:             []string{},
		})
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	resp, err := gc.restore(restoreReq{Bucket: "b", AccessKey: "a", SecretKey: "s", Type: "config"}, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if resp.Status != "completed" || resp.RestoreJobID != 99 {
		t.Errorf("restore decode wrong: %+v", resp)
	}
	if resp.RestoredConfigKeys != 12 || resp.RestoredBlobs != 42 {
		t.Errorf("restore counts wrong: %+v", resp)
	}
}

// TestGatewayRestoreHashesForwarded ensures the optional hashes list is sent for
// type=blobs.
func TestGatewayRestoreHashesForwarded(t *testing.T) {
	var gotHashes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req restoreReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotHashes = req.Hashes
		_ = json.NewEncoder(w).Encode(restoreResp{Status: "completed"})
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	_, err := gc.restore(restoreReq{Bucket: "b", AccessKey: "a", SecretKey: "s", Type: "blobs"}, []string{"h1", "h2"})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if len(gotHashes) != 2 || gotHashes[0] != "h1" {
		t.Errorf("hashes not forwarded: %v", gotHashes)
	}
}

// TestGatewayRestore500 maps a hard failure to an error.
func TestGatewayRestore500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	_, err := gc.restore(restoreReq{Bucket: "b", AccessKey: "a", SecretKey: "s", Type: "config"}, nil)
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
}

// TestGatewayRestore200WithErrors: a 200 carrying a non-empty errors array is a
// partial failure the command must surface as non-zero.
func TestGatewayRestore200WithErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(restoreResp{
			Status: "completed",
			Errors: []string{"blob xyz missing"},
		})
	}))
	defer srv.Close()

	gc := &gatewayClient{baseURL: srv.URL, http: srv.Client()}
	resp, err := gc.restore(restoreReq{Bucket: "b", AccessKey: "a", SecretKey: "s", Type: "blobs"}, nil)
	if err != nil {
		t.Fatalf("restore (transport) should succeed: %v", err)
	}
	if len(resp.Errors) != 1 {
		t.Errorf("expected the errors array to be decoded: %+v", resp.Errors)
	}
}

// TestFormatPreflight pretty-prints a preview without panicking and includes the
// salient numbers.
func TestFormatPreflight(t *testing.T) {
	out := formatPreflight(preflightResp{
		Timestamp:          "2026-06-21T00:00:00Z",
		BlobCount:          42,
		BlobTotalSizeBytes: 2048,
		ConfigSizeBytes:    512,
		UserCount:          7,
		DomainCount:        2,
		Warnings:           []string{"a warning"},
	})
	for _, want := range []string{"42", "7", "2", "2026-06-21", "a warning"} {
		if !strings.Contains(out, want) {
			t.Errorf("formatPreflight output missing %q:\n%s", want, out)
		}
	}
}

// TestOrchestrateRestore_FullRestoresBlobsBeforePgRestore: a full restore must
// drive the gateway BLOB restore FIRST (while the system is still empty, so the
// no-users guard passes), THEN replace the preloaded schema, THEN pg_restore
// (which brings users + config). The gateway call must use type=blobs — config
// comes from pg_restore, not the gateway.
func TestOrchestrateRestore_FullRestoresBlobsBeforePgRestore(t *testing.T) {
	var order []string
	var gotType string
	steps := restoreSteps{
		gatewayRestore: func(req restoreReq, _ []string) (restoreResp, error) {
			order = append(order, "gateway")
			gotType = req.Type
			return restoreResp{Status: "completed"}, nil
		},
		resetSchema: func() error { order = append(order, "reset"); return nil },
		pgRestore:   func() error { order = append(order, "pgrestore"); return nil },
	}
	cfg := restoreConfig{typ: "full", controlSocket: "/tmp/control.sock"}
	if _, err := orchestrateRestore(cfg, steps); err != nil {
		t.Fatalf("orchestrateRestore: %v", err)
	}
	if len(order) != 3 || order[0] != "gateway" || order[1] != "reset" || order[2] != "pgrestore" {
		t.Errorf("order = %v, want [gateway reset pgrestore]", order)
	}
	if gotType != "blobs" {
		t.Errorf("full restore gateway type = %q, want blobs (config comes from pg_restore)", gotType)
	}
}

// TestOrchestrateRestore_ConfigIsSingleGatewayCall: config/blobs restores are a
// single gateway call with no pg_restore.
func TestOrchestrateRestore_ConfigIsSingleGatewayCall(t *testing.T) {
	var order []string
	var gotType string
	steps := restoreSteps{
		gatewayRestore: func(req restoreReq, _ []string) (restoreResp, error) {
			order = append(order, "gateway")
			gotType = req.Type
			return restoreResp{Status: "completed"}, nil
		},
		resetSchema: func() error { order = append(order, "reset"); return nil },
		pgRestore:   func() error { order = append(order, "pgrestore"); return nil },
	}
	if _, err := orchestrateRestore(restoreConfig{typ: "config", controlSocket: "/tmp/control.sock"}, steps); err != nil {
		t.Fatalf("orchestrateRestore: %v", err)
	}
	if len(order) != 1 || order[0] != "gateway" {
		t.Errorf("config order = %v, want a single [gateway] call (no pg_restore)", order)
	}
	if gotType != "config" {
		t.Errorf("config gateway type = %q, want config", gotType)
	}
}

func TestOrchestrateRestore_ResetFailureStopsBeforePgRestore(t *testing.T) {
	var order []string
	steps := restoreSteps{
		gatewayRestore: func(restoreReq, []string) (restoreResp, error) {
			order = append(order, "gateway")
			return restoreResp{Status: "completed"}, nil
		},
		resetSchema: func() error {
			order = append(order, "reset")
			return fmt.Errorf("target became populated")
		},
		pgRestore: func() error {
			order = append(order, "pgrestore")
			return nil
		},
	}
	_, err := orchestrateRestore(restoreConfig{typ: "full"}, steps)
	if err == nil || !strings.Contains(err.Error(), "populated") {
		t.Fatalf("expected reset failure, got %v", err)
	}
	if got := strings.Join(order, ","); got != "gateway,reset" {
		t.Fatalf("order = %s, want gateway,reset", got)
	}
}

type restoreSchemaRowStub struct {
	users int64
	err   error
}

func (r restoreSchemaRowStub) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*int64)) = r.users
	return nil
}

type restoreSchemaTxStub struct {
	users     int64
	queryErr  error
	failSQL   string
	commitErr error
	executed  []string
	committed bool
}

func (tx *restoreSchemaTxStub) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	tx.executed = append(tx.executed, sql)
	if tx.failSQL != "" && strings.Contains(sql, tx.failSQL) {
		return pgconn.CommandTag{}, errors.New("injected " + tx.failSQL + " failure")
	}
	return pgconn.CommandTag{}, nil
}

func (tx *restoreSchemaTxStub) QueryRow(context.Context, string, ...any) pgx.Row {
	return restoreSchemaRowStub{users: tx.users, err: tx.queryErr}
}

func (tx *restoreSchemaTxStub) Commit(context.Context) error {
	if tx.commitErr != nil {
		return tx.commitErr
	}
	tx.committed = true
	return nil
}

func TestResetPublicSchemaTransactionCoversEveryDestructiveBoundary(t *testing.T) {
	tests := []struct {
		name      string
		tx        *restoreSchemaTxStub
		wantError string
		wantExecs int
		committed bool
	}{
		{"success", &restoreSchemaTxStub{}, "", 3, true},
		{"lock fails", &restoreSchemaTxStub{failSQL: "LOCK TABLE"}, "lock users", 1, false},
		{"count fails", &restoreSchemaTxStub{queryErr: errors.New("count failed")}, "re-check users", 1, false},
		{"target populated", &restoreSchemaTxStub{users: 1}, "became populated", 1, false},
		{"drop fails", &restoreSchemaTxStub{failSQL: "DROP SCHEMA"}, "drop preloaded", 2, false},
		{"create fails", &restoreSchemaTxStub{failSQL: "CREATE SCHEMA"}, "recreate public", 3, false},
		{"commit fails", &restoreSchemaTxStub{commitErr: errors.New("commit failed")}, "commit restore", 3, false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := resetPublicSchemaTransaction(context.Background(), test.tx)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("resetPublicSchemaTransaction: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
			if len(test.tx.executed) != test.wantExecs || test.tx.committed != test.committed {
				t.Fatalf("executed=%v committed=%t, want %d/%t", test.tx.executed, test.tx.committed, test.wantExecs, test.committed)
			}
		})
	}
}

func TestResetPublicSchemaForRestoreRejectsInvalidDSN(t *testing.T) {
	err := resetPublicSchemaForRestore(context.Background(), "://invalid-dsn", "")
	if err == nil || !strings.Contains(err.Error(), "connect for restore schema reset") {
		t.Fatalf("error = %v, want connect failure", err)
	}
}

// ── Dump authentication at the restore seam (occ_f2695a92cddad0cd92e90513) ──
// runPgRestoreStep must verify the dump's published HMAC sidecar FAIL-CLOSED
// BEFORE pg_restore executes owner-privileged SQL: valid → proceeds; tampered
// bytes, missing sidecar, or wrong key → refused with pg_restore never run.
// The S3 leg is a GET stub and pg_restore is a PATH stub writing a marker, so
// the whole matrix runs DB-free.

// dumpS3GetFixture serves GET requests for a fixed object map (plus minio's
// bucket-location probe); absent keys 404 like a real store.
func dumpS3GetFixture(t *testing.T, objects map[string][]byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = fmt.Fprint(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/backups/")
		body, ok := objects[key]
		if !ok {
			http.Error(w, "NoSuchKey", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server
}

// stubPgRestore installs a PATH-stubbed pg_restore that records its execution
// by touching the marker file named in PG_RESTORE_MARKER.
func stubPgRestore(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
printf 'restored' > "$PG_RESTORE_MARKER"
`
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	return bin
}

// restoreStepFixture builds the shared fixture: a sealed dump+sidecar object
// map, the S3 GET stub, the marker path, and a resolved full-restore config.
func restoreStepFixture(t *testing.T, objects map[string][]byte) (restoreConfig, string) {
	t.Helper()
	server := dumpS3GetFixture(t, objects)
	marker := filepath.Join(t.TempDir(), "pg_restore-ran")
	t.Setenv("PG_RESTORE_MARKER", marker)
	stubPgRestore(t)
	cfg := restoreConfig{
		s3:  s3Config{Bucket: "backups", Endpoint: server.URL, AccessKey: "a", SecretKey: "s"},
		typ: "full",
		dsn: "postgres://owner@db/setjoin",
	}
	return cfg, marker
}

func TestRunPgRestoreStepAuthenticatesThenRestores(t *testing.T) {
	dump := []byte("PGDMP authenticated restore fixture")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dbDumpObjectKey:                     dump,
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)

	if err := runPgRestoreStep(context.Background(), cfg); err != nil {
		t.Fatalf("a valid authenticated dump must restore: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("pg_restore never executed for a valid authenticated dump")
	}
}

func TestRunPgRestoreStepRefusesTamperedDumpBeforeExec(t *testing.T) {
	dump := []byte("PGDMP authenticated restore fixture")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// One flipped byte in the served dump versus the sealed binding.
	tampered := append([]byte{}, dump...)
	tampered[len(tampered)-1] ^= 0x20
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dbDumpObjectKey:                     tampered,
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)

	err = runPgRestoreStep(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "refusing to restore") {
		t.Fatalf("a one-byte-tampered dump must refuse: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore executed on a tampered dump — the fail-closed gate failed")
	}
}

func TestRunPgRestoreStepRefusesMissingSidecarBeforeExec(t *testing.T) {
	dump := []byte("PGDMP legacy dump without sidecar")
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dbDumpObjectKey: dump, // no sidecar object published
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)

	err := runPgRestoreStep(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "sidecar unavailable") {
		t.Fatalf("a dump without its published authentication binding must refuse (the lookup-error leg): %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore executed on an unauthenticated dump — the fail-closed gate failed")
	}
}

func TestRunPgRestoreStepRefusesWrongKeyBeforeExec(t *testing.T) {
	dump := []byte("PGDMP restore fixture, other key")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dbDumpObjectKey:                     dump,
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey + "0987654321-rotated-key")

	err = runPgRestoreStep(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "HMAC mismatch") {
		t.Fatalf("a dump sealed under a different key must refuse: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore executed under a key mismatch — the fail-closed gate failed")
	}
}

// TestParseRestoreFlagsFullRequiresDumpHMACKey: no key means no verification
// is possible, so a type=full execution parse refuses (fail-closed) — while a
// dry-run (preflight only) does not need one.
func TestParseRestoreFlagsFullRequiresDumpHMACKey(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", "")
	if _, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b", "--dsn", "postgres://owner@db/setjoin",
		"--control-socket", "/tmp/control.sock", "--yes",
	}); err == nil || !strings.Contains(err.Error(), "authenticates the dump") {
		t.Fatalf("type=full without a dump-authentication key must refuse: %v", err)
	}
	if _, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b", "--dsn", "postgres://owner@db/setjoin",
		"--control-socket", "/tmp/control.sock", "--dry-run",
	}); err != nil {
		t.Fatalf("dry-run full must not require the dump-authentication key: %v", err)
	}
	cfg, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b", "--dsn", "postgres://owner@db/setjoin",
		"--control-socket", "/tmp/control.sock", "--yes",
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err != nil {
		t.Fatalf("parse with a 0600 dump-auth key file must succeed: %v", err)
	}
	if string(cfg.dumpHMACKey) != testDumpAuthKey {
		t.Fatalf("resolved dump auth key drifted: %d bytes", len(cfg.dumpHMACKey))
	}
}

// ── Dump-authentication fail-closed error legs at the restore seam
// (occ_f2695a92cddad0cd92e90513): every reachable refusal of the pgRestore
// step refuses BEFORE pg_restore runs — the marker file proves no exec. ──

// TestParseRestoreFlagsMissingDumpKeyFile: an absent dump-auth key file is a
// parse-time refusal for type=full, not a mid-restore surprise.
func TestParseRestoreFlagsMissingDumpKeyFile(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", "")
	if _, err := parseRestoreFlags([]string{
		"--type", "full", "--bucket", "b", "--dsn", "postgres://owner@db/setjoin",
		"--control-socket", "/tmp/control.sock", "--yes",
		"--dump-hmac-key-file", filepath.Join(t.TempDir(), "absent.key"),
	}); err == nil || !strings.Contains(err.Error(), "dump authentication HMAC key") {
		t.Fatalf("an absent dump-auth key file must refuse at parse: %v", err)
	}
}

// TestRunPgRestoreStepRefusesWithoutPgRestoreBinary: the LookPath guard runs
// before any download, so an unusable environment never reaches SQL.
func TestRunPgRestoreStepRefusesWithoutPgRestoreBinary(t *testing.T) {
	dump := []byte("PGDMP authenticated restore fixture")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dbDumpObjectKey:                     dump,
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)
	t.Setenv("PATH", t.TempDir()) // no pg_restore anywhere

	if err := runPgRestoreStep(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "pg_restore binary not found") {
		t.Fatalf("a PATH without pg_restore must refuse: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore marker touched despite missing binary")
	}
}

// TestRunPgRestoreStepRefusesWhenTempCreationFails: the step's temp file is
// created before any download; an unusable TMPDIR refuses immediately.
func TestRunPgRestoreStepRefusesWhenTempCreationFails(t *testing.T) {
	cfg, marker := restoreStepFixture(t, map[string][]byte{})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent-tmpdir"))

	if err := runPgRestoreStep(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "create temp file") {
		t.Fatalf("an unusable temp directory must refuse: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore executed despite temp-file failure")
	}
}

// TestRunPgRestoreStepRefusesWhenDumpDownloadFails: a dump object that 404s
// (its sidecar present or not) refuses before any authentication or exec.
func TestRunPgRestoreStepRefusesWhenDumpDownloadFails(t *testing.T) {
	dump := []byte("PGDMP authenticated restore fixture")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Only the sidecar object exists; the dump key 404s.
	cfg, marker := restoreStepFixture(t, map[string][]byte{
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	cfg.dumpHMACKey = []byte(testDumpAuthKey)

	if err := runPgRestoreStep(context.Background(), cfg); err == nil {
		t.Fatal("a dump that cannot be downloaded must refuse the restore")
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("pg_restore executed without a downloaded dump")
	}
}

// TestRunPgRestoreStepPropagatesPgRestoreFailure: once the dump IS
// authenticated, a pg_restore that itself fails surfaces as an error — the
// gate never masks a broken restore as success.
func TestRunPgRestoreStepPropagatesPgRestoreFailure(t *testing.T) {
	dump := []byte("PGDMP authenticated restore fixture")
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, dump, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := dumpS3GetFixture(t, map[string][]byte{
		dbDumpObjectKey:                     dump,
		dumpAuthSidecarKey(dbDumpObjectKey): sidecar,
	})
	marker := filepath.Join(t.TempDir(), "pg_restore-ran")
	t.Setenv("PG_RESTORE_MARKER", marker)
	bin := t.TempDir()
	script := `#!/bin/sh
echo "pg_restore: error: input file does not appear to be a valid archive" >&2
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	cfg := restoreConfig{
		s3:  s3Config{Bucket: "backups", Endpoint: server.URL, AccessKey: "a", SecretKey: "s"},
		typ: "full",
		dsn: "postgres://owner@db/setjoin",
	}
	cfg.dumpHMACKey = []byte(testDumpAuthKey)

	err = runPgRestoreStep(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "pg_restore failed") {
		t.Fatalf("a failing pg_restore must surface as an error: %v", err)
	}
}
