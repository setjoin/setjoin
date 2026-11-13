package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPgDumpArgs asserts the exact flag set the backup-db command builds for
// pg_dump: custom format, the DSN, and the output file path. This is the
// TDD-able core of the os/exec shell. The builder receives an already-stripped
// (credential-free) DSN — dsnForChildArgv separates the password at parse time
// and pgChildEnv delivers it via PGPASSWORD, never argv.
func TestPgDumpArgs(t *testing.T) {
	dsn := "postgres://u@localhost:5432/maildb"
	out := "/tmp/db-dump.dump"
	args := pgDumpArgs(dsn, out)

	joined := strings.Join(args, " ")

	if !contains(args, "--format=custom") {
		t.Errorf("pgDumpArgs missing --format=custom: %v", args)
	}
	if !contains(args, "--file="+out) {
		t.Errorf("pgDumpArgs missing --file=%s: %v", out, args)
	}
	// The DSN must be present (as the dbname conninfo argument) and must not
	// carry password material.
	if !contains(args, dsn) {
		t.Errorf("pgDumpArgs missing dsn %q: %v", dsn, args)
	}
	for _, arg := range args {
		if strings.Contains(arg, "password=") {
			t.Errorf("pgDumpArgs must never carry a password in argv: %v", args)
		}
	}
	// Full restore rebuilds public and must replay both specialized worker
	// ownership and runtime ACLs.
	if contains(args, "--no-owner") {
		t.Errorf("pgDumpArgs must retain specialized ownership: %v", joined)
	}
	if contains(args, "--no-privileges") {
		t.Errorf("pgDumpArgs must retain runtime ACLs: %v", joined)
	}
}

// TestPgDumpArgsEmptyDSN ensures the builder still emits a stable shape with an
// empty DSN (validation happens at the command layer, not the builder).
func TestPgDumpArgsEmptyDSN(t *testing.T) {
	args := pgDumpArgs("", "/tmp/out.dump")
	if len(args) == 0 {
		t.Fatal("pgDumpArgs returned no args")
	}
	if !contains(args, "--file=/tmp/out.dump") {
		t.Errorf("pgDumpArgs missing --file: %v", args)
	}
}

func TestPgRestoreListArgsUsesOnlyGeneratedDumpPath(t *testing.T) {
	path := "/tmp/generated.dump"
	args := pgRestoreListArgs(path)
	if len(args) != 2 || args[0] != "--list" || args[1] != path {
		t.Fatalf("pgRestoreListArgs=%v", args)
	}
}

// TestParseBackupDBFlagsMissingBucket asserts flag validation rejects a missing
// required S3 field. Credentials come from the environment: argv secret flags
// are refused outright (Invariant 5, no command-line secrets).
func TestParseBackupDBFlagsMissingBucket(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://x")
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseBackupDBFlags(nil)
	if err == nil {
		t.Fatal("expected error when --bucket is missing")
	}
	if !strings.Contains(err.Error(), "bucket") {
		t.Errorf("error should mention bucket: %v", err)
	}
}

// TestParseBackupDBFlagsMissingDSN asserts a missing DSN (no flag, no env) errors.
func TestParseBackupDBFlagsMissingDSN(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseBackupDBFlags([]string{"--bucket", "b"})
	if err == nil {
		t.Fatal("expected error when DSN is unresolvable")
	}
	if !strings.Contains(err.Error(), "dsn") && !strings.Contains(err.Error(), "DSN") {
		t.Errorf("error should mention DSN: %v", err)
	}
}

// TestParseBackupDBFlagsValid parses a complete, valid flag set with credentials
// delivered through 0600 files (the non-argv control this module uses).
func TestParseBackupDBFlagsValid(t *testing.T) {
	clearOperatorDSNEnv(t)
	accessPath, secretPath := writeCredentialFiles(t, "AK", "SK")
	cfg, err := parseBackupDBFlags([]string{
		"--dsn", "postgres://u@h/db",
		"--provider", "minio",
		"--endpoint", "s3.example.com",
		"--region", "us-east-1",
		"--bucket", "backups",
		"--access-key-file", accessPath,
		"--secret-key-file", secretPath,
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "postgres://u@h/db" {
		t.Errorf("dsn = %q", cfg.dsn)
	}
	if cfg.s3.Bucket != "backups" || cfg.s3.AccessKey != "AK" || cfg.s3.SecretKey != "SK" {
		t.Errorf("s3 config not parsed: %+v", cfg.s3)
	}
	if cfg.s3.Endpoint != "s3.example.com" || cfg.s3.Region != "us-east-1" {
		t.Errorf("s3 endpoint/region not parsed: %+v", cfg.s3)
	}
}

// TestParseBackupDBFlagsRefusesArgvSecrets asserts the Invariant 5 control: an
// explicit --access-key/--secret-key on the command line is refused with
// guidance, even though the flags remain registered.
func TestParseBackupDBFlagsRefusesArgvSecrets(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://x")
	for _, name := range []string{"access-key", "secret-key"} {
		args := []string{"--bucket", "b", "--" + name, "argv-value"}
		_, err := parseBackupDBFlags(args)
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

// TestParseBackupDBFlagsAcceptsEnvSecrets asserts environment-seeded defaults
// are the supported non-argv source and do not trip the argv refusal.
func TestParseBackupDBFlagsAcceptsEnvSecrets(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://x")
	t.Setenv("BACKUP_ACCESS_KEY", "env-access")
	t.Setenv("BACKUP_SECRET_KEY", "env-secret")
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", dumpHMACKeyFile(t, testDumpAuthKey))
	cfg, err := parseBackupDBFlags([]string{"--bucket", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.s3.AccessKey != "env-access" || cfg.s3.SecretKey != "env-secret" {
		t.Errorf("env credentials not used: %+v", cfg.s3)
	}
}

// TestParseBackupDBFlagsFileCredentialsWinOverEnv mirrors the backup create/verify
// precedence: an explicit 0600 file beats the environment default.
func TestParseBackupDBFlagsFileCredentialsWinOverEnv(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://x")
	t.Setenv("BACKUP_ACCESS_KEY", "env-access")
	t.Setenv("BACKUP_SECRET_KEY", "env-secret")
	accessPath, secretPath := writeCredentialFiles(t, "file-access", "file-secret")
	cfg, err := parseBackupDBFlags([]string{
		"--bucket", "b",
		"--access-key-file", accessPath,
		"--secret-key-file", secretPath,
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.s3.AccessKey != "file-access" || cfg.s3.SecretKey != "file-secret" {
		t.Errorf("file credentials must win over env: %+v", cfg.s3)
	}
}

// TestParseBackupDBFlagsRejectsLooseSecretFilePerms asserts the 0600 file control.
func TestParseBackupDBFlagsRejectsLooseSecretFilePerms(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://x")
	dir := t.TempDir()
	loose := filepath.Join(dir, "secret")
	if err := os.WriteFile(loose, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := parseBackupDBFlags([]string{"--bucket", "b", "--secret-key-file", loose})
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected 0600 refusal, got %v", err)
	}
}

// TestParseBackupDBFlagsRefusesArgvDSNWithEmbeddedPassword asserts the operator
// DSN control: a credential-bearing --dsn is refused (it would reach pg_dump
// argv for the dump duration); credential-free DSNs stay allowed.
func TestParseBackupDBFlagsRefusesArgvDSNWithEmbeddedPassword(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseBackupDBFlags([]string{"--bucket", "b", "--dsn", "postgres://owner:sekret@h/db"})
	if err == nil {
		t.Fatal("expected refusal of --dsn with embedded password")
	}
	if !strings.Contains(err.Error(), "embedded credentials") {
		t.Errorf("error should explain the DSN refusal: %v", err)
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Errorf("refusal must not echo the secret: %v", err)
	}
	// Keyword-form conninfo with a password is refused too.
	if _, err := parseBackupDBFlags([]string{"--bucket", "b", "--dsn", "host=h dbname=db password=sekret"}); err == nil {
		t.Fatal("expected refusal of keyword-form --dsn with password")
	}
	// r3 HOLD regression: the spaced pair must be refused on argv as well —
	// the old detector missed it and dsnForChildArgv accepted its own result.
	if _, err := parseBackupDBFlags([]string{"--bucket", "b", "--dsn", "host=h dbname=db password = sekret"}); err == nil {
		t.Fatal("expected refusal of spaced keyword-form --dsn with password")
	}
	// Credential-free DSN (peer auth) stays allowed.
	cfg, err := parseBackupDBFlags([]string{
		"--bucket", "b", "--dsn", "postgres://owner@h/db",
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err != nil {
		t.Fatalf("credential-free --dsn must be accepted: %v", err)
	}
	if cfg.dsn != "postgres://owner@h/db" {
		t.Errorf("dsn = %q", cfg.dsn)
	}
}

// TestDSNEmbedsCredential unit-tests the conninfo credential detector. The
// keyword cases pin the r3 contract: detection tokenizes with the same libpq
// rules the stripper uses, so a spaced pair ("password = secret") is caught —
// the substring check this table used to encode missed it and let the
// unstripped DSN reach pg_dump argv.
func TestDSNEmbedsCredential(t *testing.T) {
	cases := map[string]bool{
		"postgres://owner:pw@h/db":            true,
		"postgres://owner@h/db":               false,
		"postgresql://setjoin_owner@h/mail":   false,
		"host=h dbname=db password=pw":        true,
		"HOST=h PASSWORD=pw":                  true,
		"host=h dbname=db":                    false,
		"postgres://h/db?password=pw":         true,
		"postgres://h/db?sslmode=require":     false,
		"":                                    false,
		"postgres://owner%3Auser:p%40ss@h/db": true,
		// Spaced/quoted pairs the old substring detector missed (r3 HOLD).
		"host=h dbname=db password = secret":    true,
		"host=h dbname=db password = 'sec ret'": true,
		"password = secret":                     true,
		"host=h password\t=\tsecret":            true,
		// Tokenization negatives: a longer keyword or a bare dbname carries no
		// password pair.
		"host=h dbname=db pass=word": false,
		"host=h dbpassword=x":        false,
		"setjoin":                    false,
		// Password-shaped text the tokenizer cannot attribute (a quoted value
		// containing "password=") fails closed, matching the stripper's
		// refusal of the same shape.
		"host=h dbname='x password=y'": true,
	}
	for dsn, want := range cases {
		if got := dsnEmbedsCredential(dsn); got != want {
			t.Errorf("dsnEmbedsCredential(%q) = %v, want %v", dsn, got, want)
		}
	}
}

// TestSplitDSNCredentials unit-tests the conninfo credential separator behind
// dsnForChildArgv: passwords come out of every DSN shape, unstrippable shapes
// refuse, and credential-free DSNs pass through byte-identical (so .pgpass and
// peer-auth conninfos never drift).
func TestSplitDSNCredentials(t *testing.T) {
	cases := []struct {
		name         string
		dsn          string
		wantDSN      string
		wantPassword string
		wantErr      bool
	}{
		{"empty", "", "", "", false},
		{"credential-free url unchanged", "postgres://owner@h/db", "postgres://owner@h/db", "", false},
		{"credential-free keyword unchanged", "host=h dbname=db", "host=h dbname=db", "", false},
		{"url userinfo password", "postgres://owner:pw@h/db", "postgres://owner@h/db", "pw", false},
		{"url encoded username preserved", "postgres://owner%3Auser:p%40ss@h/db", "postgres://owner%3Auser@h/db", "p@ss", false},
		{"url query password", "postgres://h/db?password=pw", "postgres://h/db", "pw", false},
		{"url userinfo and query same password", "postgres://owner:pw@h/db?password=pw", "postgres://owner@h/db", "pw", false},
		{"url userinfo and query differ", "postgres://owner:pw1@h/db?password=pw2", "", "", true},
		{"url empty query password stripped", "postgres://h/db?password=", "postgres://h/db", "", false},
		{"url other query params kept", "postgres://owner:pw@h/db?sslmode=require&password=pw", "postgres://owner@h/db?sslmode=require", "pw", false},
		{"keyword password", "host=h dbname=db password=pw", "host=h dbname=db", "pw", false},
		{"keyword password first", "password=pw host=h", "host=h", "pw", false},
		{"keyword spaced pair", "host = h password=pw dbname=db", "host = h dbname=db", "pw", false},
		// r3 HOLD regressions: whitespace around the password pair's '=' and
		// quoted values must be stripped, not just detected.
		{"keyword spaced password pair", "host=h dbname=db password = secret", "host=h dbname=db", "secret", false},
		{"keyword spaced quoted password", "host=h password = 'sec ret'", "host=h", "sec ret", false},
		{"keyword spaced quoted password first", "password = 'sec ret' host=h", "host=h", "sec ret", false},
		{"keyword tab-spaced password", "host=h password\t=\tsecret dbname=db", "host=h dbname=db", "secret", false},
		{"keyword case-insensitive", "host=h PASSWORD=pw", "host=h", "pw", false},
		{"keyword quoted password with spaces", "host=h password='two words'", "host=h", "two words", false},
		{"keyword quoted escaped quote", "host=h password='it''s'", "host=h", "it's", false},
		{"keyword backslash-escaped space", `host=h password=sp\ ace`, "host=h", "sp ace", false},
		{"bare dbname unchanged", "setjoin", "setjoin", "", false},
		{"unparseable url with userinfo password refused", "postgres://owner:pw@h/db%zz?sslmode=require", "", "", true},
		{"unparseable url with query password refused", "postgres://h/db%zz?password=pw", "", "", true},
		{"unparseable url without credentials passes through", "postgres://h/db%zz?sslmode=require", "postgres://h/db%zz?sslmode=require", "", false},
		{"keyword password hidden in quoted value refused", "host=h dbname='x password=y'", "", "", true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			gotDSN, gotPassword, err := splitDSNCredentials(test.dsn)
			if test.wantErr {
				if err == nil {
					t.Fatalf("splitDSNCredentials(%q) = (%q, %q), want refusal", test.dsn, gotDSN, gotPassword)
				}
				if test.dsn != "" && strings.Contains(err.Error(), test.dsn) {
					t.Errorf("refusal must not echo the credential-bearing DSN: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("splitDSNCredentials(%q): %v", test.dsn, err)
			}
			if gotDSN != test.wantDSN || gotPassword != test.wantPassword {
				t.Fatalf("splitDSNCredentials(%q) = (%q, %q), want (%q, %q)", test.dsn, gotDSN, gotPassword, test.wantDSN, test.wantPassword)
			}
			// The stripped DSN must be genuinely credential-free — the parse
			// backstop re-runs this check, so it must hold on every clean output.
			if dsnEmbedsCredential(gotDSN) {
				t.Errorf("stripped DSN %q still detected as credential-bearing", gotDSN)
			}
		})
	}
}

// TestParseBackupDBFlagsEnvDSNPasswordStrippedForChildArgv pins the round-2
// control the flagWasSet("dsn") check missed: a credential-bearing DSN from the
// ENVIRONMENT is stripped at parse time and its password travels via
// PGPASSWORD, never pg_dump argv. Both conninfo shapes are covered.
func TestParseBackupDBFlagsEnvDSNPasswordStrippedForChildArgv(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", dumpHMACKeyFile(t, testDumpAuthKey))

	t.Setenv("DB_OWNER_DSN", "postgres://owner:envsecret@h/db")
	cfg, err := parseBackupDBFlags([]string{"--bucket", "b"})
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
	cfg, err = parseBackupDBFlags([]string{"--bucket", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "host=h dbname=db" || strings.Contains(cfg.dsn, "kwsecret") {
		t.Errorf("keyword-form env DSN not stripped: %q", cfg.dsn)
	}
	if cfg.dbPassword != "kwsecret" {
		t.Errorf("dbPassword = %q, want the separated env secret", cfg.dbPassword)
	}

	// r3 HOLD regression: the spaced pair shape ("password = secret") from the
	// environment must be stripped too — the old detector bypassed stripping
	// for it and let the password reach pg_dump argv.
	t.Setenv("DB_OWNER_DSN", "host=h dbname=db password = envspaced")
	cfg, err = parseBackupDBFlags([]string{"--bucket", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dsn != "host=h dbname=db" || strings.Contains(cfg.dsn, "envspaced") {
		t.Errorf("spaced keyword-form env DSN not stripped: %q", cfg.dsn)
	}
	if cfg.dbPassword != "envspaced" {
		t.Errorf("dbPassword = %q, want the separated env secret", cfg.dbPassword)
	}
}

// TestParseBackupDBFlagsRefusesUnstrippableEnvDSN asserts the fail-closed arm
// of dsnForChildArgv: a DSN that embeds credentials in a shape the separator
// cannot prove it stripped is refused for ANY source, so no path can place a
// password in child argv.
func TestParseBackupDBFlagsRefusesUnstrippableEnvDSN(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	t.Setenv("DB_OWNER_DSN", "postgres://owner:unstrippable@h/db%zz?sslmode=require")
	_, err := parseBackupDBFlags([]string{"--bucket", "b"})
	if err == nil {
		t.Fatal("expected refusal of an unstrippable credential-bearing env DSN")
	}
	if !strings.Contains(err.Error(), "cannot be safely stripped") {
		t.Errorf("error should explain the refusal: %v", err)
	}
	if strings.Contains(err.Error(), "unstrippable") {
		t.Errorf("refusal must not echo the secret: %v", err)
	}
}

// TestParseBackupDBFlagsPgpassStyleDSNKeepsChildEnvClean covers the file source
// of the directive triad (flag / env / file): a credential-free DSN whose
// password libpq resolves upstream from a 0600 .pgpass carries no password and
// must not inject a PGPASSWORD override into the child environment.
func TestParseBackupDBFlagsPgpassStyleDSNKeepsChildEnvClean(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://owner@h/db")
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", dumpHMACKeyFile(t, testDumpAuthKey))
	cfg, err := parseBackupDBFlags([]string{"--bucket", "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.dbPassword != "" {
		t.Errorf("credential-free DSN must not yield a password: %q", cfg.dbPassword)
	}
	if env := pgChildEnv(os.Environ(), cfg.dbPassword); len(env) != 0 {
		t.Errorf(".pgpass-style DSN must inherit the environment unchanged, got %v", env)
	}
}

// TestPgChildEnv asserts the PGPASSWORD delivery contract: no password inherits
// the parent environment untouched; a separated password is appended (os/exec
// keeps the last duplicate, so it overrides any inherited value).
func TestPgChildEnv(t *testing.T) {
	if env := pgChildEnv([]string{"A=1"}, ""); len(env) != 0 {
		t.Errorf("empty password must inherit unchanged, got %v", env)
	}
	got := pgChildEnv([]string{"A=1", "PGPASSWORD=stale"}, "fresh")
	last := ""
	for _, kv := range got {
		if strings.HasPrefix(kv, "PGPASSWORD=") {
			last = kv
		}
	}
	if last != "PGPASSWORD=fresh" {
		t.Errorf("PGPASSWORD = %q, want the appended value to win: %v", last, got)
	}
	if got[0] != "A=1" {
		t.Errorf("parent environment not preserved: %v", got)
	}
}

// TestBackupDBUnknownFlagUsageDoesNotLeakResolvedSecret pins the round-2 fix:
// secret flags carry placeholder defaults, so Go's default usage printer —
// invoked when an unknown flag fails parsing — cannot echo an
// environment-resolved secret.
func TestBackupDBUnknownFlagUsageDoesNotLeakResolvedSecret(t *testing.T) {
	clearOperatorDSNEnv(t)
	const secret = "supersecret-env-value"
	t.Setenv("BACKUP_ACCESS_KEY", "access-"+secret)
	t.Setenv("BACKUP_SECRET_KEY", secret)
	usage := captureFlagUsageStderr(t, func() {
		_, _ = parseBackupDBFlags([]string{"--nonexistent-flag", "--bucket", "b"})
	})
	if !strings.Contains(usage, "flag provided but not defined") {
		t.Fatalf("expected Go's default usage output on an unknown flag, got:\n%s", usage)
	}
	if strings.Contains(usage, secret) {
		t.Errorf("usage output leaked the resolved secret:\n%s", usage)
	}
}

// captureFlagUsageStderr runs fn while capturing os.Stderr — the default
// output of a flag.FlagSet that hits Go's default usage printer — and returns
// everything written. Not for use with t.Parallel tests.
func captureFlagUsageStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	fn()
	w.Close()
	os.Stderr = original
	return <-done
}

func TestValidateCustomDumpRejectsInvalidFile(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte("#!/bin/sh\necho invalid-dump >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	path := filepath.Join(t.TempDir(), "not-a-dump")
	if err := os.WriteFile(path, []byte("not a PostgreSQL custom dump"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCustomDump(path); err == nil || !strings.Contains(err.Error(), "pg_restore --list rejected") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunBackupDBPropagatesCompletedDumpValidationFailure(t *testing.T) {
	bin := t.TempDir()
	pgDump := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in --file=*) printf 'not-a-dump' > "${arg#--file=}";; esac
done
`
	if err := os.WriteFile(filepath.Join(bin, "pg_dump"), []byte(pgDump), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte("#!/bin/sh\necho invalid-dump >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	err := runBackupDB(&cmdCtx{}, "", []string{
		"--dsn", "postgres://owner@db/setjoin", "--bucket", "backups",
		"--access-key-file", accessKeyFile(t, "access"), "--secret-key-file", secretKeyFile(t, "secret"),
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err == nil || !strings.Contains(err.Error(), "pg_restore --list rejected") {
		t.Fatalf("err=%v", err)
	}
}

func TestRunBackupDBRequiresPostgresClientBinaries(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("PATH", "")
	err := runBackupDB(&cmdCtx{}, "", []string{
		"--dsn", "postgres://owner@db/setjoin",
		"--bucket", "backups",
		"--access-key-file", accessKeyFile(t, "access"),
		"--secret-key-file", secretKeyFile(t, "secret"),
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err == nil || !strings.Contains(err.Error(), "pg_dump binary not found") {
		t.Fatalf("err=%v", err)
	}
}

// testDumpAuthKey is a fixed ≥32-byte HMAC key for the dump-authentication
// tests (the exact file bytes are the key — readPrivateKeyFile does not trim).
const testDumpAuthKey = "0123456789abcdef0123456789abcdef"

// dumpHMACKeyFile writes a 0600 ≥32-byte HMAC key file — the same
// readPrivateKeyFile contract the recovery-set HMAC key uses. No trailing
// newline: the exact file bytes are the key.
func dumpHMACKeyFile(t *testing.T, value string) string {
	t.Helper()
	if len(value) < 32 {
		t.Fatalf("test dump auth key must be at least 32 bytes, got %d", len(value))
	}
	path := filepath.Join(t.TempDir(), "dump-hmac-key")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunBackupDBRequiresDumpHMACKey(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_DUMP_HMAC_KEY_FILE", "")
	t.Setenv("PATH", "")
	err := runBackupDB(&cmdCtx{}, "", []string{
		"--dsn", "postgres://owner@db/setjoin",
		"--bucket", "backups",
		"--access-key-file", accessKeyFile(t, "access"),
		"--secret-key-file", secretKeyFile(t, "secret"),
	})
	if err == nil || !strings.Contains(err.Error(), "dump authentication is mandatory at publication") {
		t.Fatalf("backup without a dump-authentication key must refuse: err=%v", err)
	}
}

// stubPgDumpProducesFixture installs the scripted pg_dump/pg_restore PATH pair
// for runBackupDB tests: pg_dump writes a fixed body, pg_restore's --list
// accepts anything.
func stubPgDumpProducesFixture(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	pgDump := `#!/bin/sh
out=""
for arg in "$@"; do
  case "$arg" in --file=*) out="${arg#--file=}";; esac
done
test -n "$out" || exit 2
printf 'PGDMP fixture' > "$out"
`
	if err := os.WriteFile(filepath.Join(bin, "pg_dump"), []byte(pgDump), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
}

// sealAndUploadFixture is a scripted pg_dump/pg_restore + S3 stub pair for
// runBackupDB end-to-end tests: pg_dump writes a fixed body, pg_restore's
// --list accepts anything.
func sealAndUploadFixture(t *testing.T) (map[string][]byte, *httptest.Server) {
	t.Helper()
	stubPgDumpProducesFixture(t)
	return s3PutFixture(t)
}

func TestRunBackupDBCreatesValidatedCanonicalAndArchivalObjects(t *testing.T) {
	objects, server := sealAndUploadFixture(t)
	err := runBackupDB(&cmdCtx{}, "", []string{
		"--dsn", "postgres://owner@db/setjoin", "--endpoint", server.URL,
		"--bucket", "backups",
		"--access-key-file", accessKeyFile(t, "access"), "--secret-key-file", secretKeyFile(t, "secret"),
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The canonical dump + its sidecar, plus the archival copy + its sidecar.
	if string(objects[dbDumpObjectKey]) != "PGDMP fixture" || len(objects) != 4 {
		t.Fatalf("objects=%v", objects)
	}
	canonicalSidecar := objects[dumpAuthSidecarKey(dbDumpObjectKey)]
	if len(canonicalSidecar) == 0 {
		t.Fatal("canonical dump has no authentication sidecar")
	}
	// The canonical sidecar binds THE CANONICAL OBJECT: it verifies against
	// the uploaded dump bytes under the publication key...
	dumpPath := filepath.Join(t.TempDir(), "canonical.dump")
	if err := os.WriteFile(dumpPath, objects[dbDumpObjectKey], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), canonicalSidecar); err != nil {
		t.Fatalf("canonical sidecar does not verify against its uploaded dump: %v", err)
	}
	// ...and refuses to stand in for any other object or under another key.
	if err := verifyDumpAuthEnvelope(dumpPath, "db-dump-other.dump", []byte(testDumpAuthKey), canonicalSidecar); err == nil ||
		!strings.Contains(err.Error(), "not the requested") {
		t.Fatalf("a foreign object key must refuse: err=%v", err)
	}
	if err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey+"x"), canonicalSidecar); err == nil ||
		!strings.Contains(err.Error(), "HMAC mismatch") {
		t.Fatalf("a wrong key must refuse: err=%v", err)
	}
	// The archival copy carries its OWN binding: same bytes, different
	// objectKey inside the MAC.
	var archivalKey string
	for key := range objects {
		if key != dbDumpObjectKey && key != dumpAuthSidecarKey(dbDumpObjectKey) && strings.HasPrefix(key, "db-dump-") && strings.HasSuffix(key, ".dump") {
			archivalKey = key
		}
	}
	if archivalKey == "" || len(objects[dumpAuthSidecarKey(archivalKey)]) == 0 {
		t.Fatalf("archival copy or its sidecar missing: %v", objects)
	}
	if err := verifyDumpAuthEnvelope(dumpPath, archivalKey, []byte(testDumpAuthKey), objects[dumpAuthSidecarKey(archivalKey)]); err != nil {
		t.Fatalf("archival sidecar does not verify against its own binding: %v", err)
	}
	if err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), objects[dumpAuthSidecarKey(archivalKey)]); err == nil {
		t.Fatal("the archival sidecar must not verify as the canonical dump's binding")
	}
}

// TestRunBackupDBEnvDSNPasswordStaysOutOfChildArgv drives the real exec shell
// with a credential-bearing ENVIRONMENT DSN — the source the round-1
// flagWasSet("dsn") check missed. The scripted pg_dump fails if any argv
// element carries the secret and asserts the password arrived through
// PGPASSWORD instead.
func TestRunBackupDBEnvDSNPasswordStaysOutOfChildArgv(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_OWNER_DSN", "postgres://owner:envsecret@h/db")
	bin := t.TempDir()
	pgDump := `#!/bin/sh
for arg in "$@"; do
  case "$arg" in
    *envsecret*) echo "password leaked into argv: $arg" >&2; exit 3;;
  esac
done
out=""
for arg in "$@"; do
  case "$arg" in --file=*) out="${arg#--file=}";; esac
done
test -n "$out" || exit 2
if [ "$PGPASSWORD" != "envsecret" ]; then echo "password not delivered via PGPASSWORD" >&2; exit 4; fi
printf 'PGDMP fixture' > "$out"
`
	if err := os.WriteFile(filepath.Join(bin, "pg_dump"), []byte(pgDump), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "pg_restore"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	_, server := s3PutFixture(t)
	if err := runBackupDB(&cmdCtx{}, "", []string{
		"--bucket", "backups", "--endpoint", server.URL,
		"--access-key-file", accessKeyFile(t, "access"), "--secret-key-file", secretKeyFile(t, "secret"),
		"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
	}); err != nil {
		t.Fatalf("backup with credential-bearing env DSN must strip the password out of child argv: %v", err)
	}
}

// s3PutFixture starts an S3-compatible stub that records PUT object bodies
// (decoding AWS chunked framing), for backup upload assertions.
func s3PutFixture(t *testing.T) (map[string][]byte, *httptest.Server) {
	t.Helper()
	objects := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if bytes.Contains(raw, []byte(";chunk-signature=")) {
			raw, err = decodeAWSChunkedFixture(raw)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		objects[strings.TrimPrefix(r.URL.Path, "/backups/")] = raw
		w.Header().Set("ETag", `"fixture-etag"`)
	}))
	t.Cleanup(server.Close)
	return objects, server
}

// writeCredentialFiles creates a pair of 0600 credential files and returns
// their paths, exercising the module's non-argv credential control.
func writeCredentialFiles(t *testing.T, access, secret string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	accessPath := filepath.Join(dir, "access-key")
	secretPath := filepath.Join(dir, "secret-key")
	if err := os.WriteFile(accessPath, []byte(access+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretPath, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return accessPath, secretPath
}

func accessKeyFile(t *testing.T, value string) string {
	t.Helper()
	path, _ := writeCredentialFiles(t, value, "unused")
	return path
}

func secretKeyFile(t *testing.T, value string) string {
	t.Helper()
	_, path := writeCredentialFiles(t, "unused", value)
	return path
}

// contains is a small test helper.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestDumpAuthEnvelopeVerifyMatrix pins the fail-closed verification matrix of
// the dump-authentication sidecar (occ_f2695a92cddad0cd92e90513): a sealed
// binding verifies; a single flipped dump byte, a wrong key, a tampered or
// foreign-bound sidecar, and malformed envelopes all refuse.
func TestDumpAuthEnvelopeVerifyMatrix(t *testing.T) {
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, []byte("PGDMP authentic dump body"), 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Date(2026, 9, 20, 1, 2, 3, 0, time.UTC))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Run("valid binding verifies", func(t *testing.T) {
		if err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), sidecar); err != nil {
			t.Fatalf("valid sealed binding must verify: %v", err)
		}
	})

	t.Run("one flipped dump byte refuses", func(t *testing.T) {
		tamperedPath := filepath.Join(t.TempDir(), "tampered.dump")
		tampered := []byte("PGDMP authentic dump bodx") // last byte flipped
		if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		err := verifyDumpAuthEnvelope(tamperedPath, dbDumpObjectKey, []byte(testDumpAuthKey), sidecar)
		if err == nil || !strings.Contains(err.Error(), "substituted or corrupted") {
			t.Fatalf("a one-byte tampered dump must refuse: err=%v", err)
		}
	})

	t.Run("truncated dump refuses on size", func(t *testing.T) {
		shortPath := filepath.Join(t.TempDir(), "short.dump")
		if err := os.WriteFile(shortPath, []byte("PGDMP"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := verifyDumpAuthEnvelope(shortPath, dbDumpObjectKey, []byte(testDumpAuthKey), sidecar)
		if err == nil || !strings.Contains(err.Error(), "substituted or corrupted") {
			t.Fatalf("a size-mismatched dump must refuse: err=%v", err)
		}
	})

	t.Run("wrong key refuses with HMAC mismatch", func(t *testing.T) {
		err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey+"wrong-wrong-wrong-wrong"), sidecar)
		if err == nil || !strings.Contains(err.Error(), "HMAC mismatch") {
			t.Fatalf("a wrong key must refuse: err=%v", err)
		}
	})

	t.Run("foreign object binding refuses", func(t *testing.T) {
		archivalSidecar, err := sealDumpAuthEnvelope(dumpPath, "db-dump-20260101T000000Z.dump", []byte(testDumpAuthKey), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		err = verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), archivalSidecar)
		if err == nil || !strings.Contains(err.Error(), "not the requested") {
			t.Fatalf("a sidecar bound to another object must refuse: err=%v", err)
		}
	})

	t.Run("tampered sidecar fields refuse", func(t *testing.T) {
		var envelope dumpAuthEnvelope
		if err := json.Unmarshal(sidecar, &envelope); err != nil {
			t.Fatal(err)
		}
		tampered := envelope
		tampered.SHA256 = strings.Repeat("a", 64) // digest rewritten outside the MAC
		tamperedBody, err := json.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		err = verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), tamperedBody)
		if err == nil || !strings.Contains(err.Error(), "HMAC mismatch") {
			t.Fatalf("a rewritten digest must refuse via the MAC: err=%v", err)
		}
	})

	t.Run("schema/algorithm mismatch refuses", func(t *testing.T) {
		var envelope dumpAuthEnvelope
		if err := json.Unmarshal(sidecar, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Schema = "setjoin.mailctl.dump-auth/v9"
		envelope.HMACSHA256 = ""
		body, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		err = verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), body)
		if err == nil || !strings.Contains(err.Error(), "schema/algorithm mismatch") {
			t.Fatalf("an unknown envelope version must refuse: err=%v", err)
		}
	})

	t.Run("unknown fields and trailing data refuse", func(t *testing.T) {
		err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey),
			[]byte(`{"schema":"setjoin.mailctl.dump-auth/v1","objectKey":"db-dump.dump","sizeBytes":25,"sha256":"`+strings.Repeat("0", 64)+`","algorithm":"hmac-sha256","createdAt":"2026-09-20T01:02:03Z","hmacSha256":"`+strings.Repeat("0", 64)+`","extra":1}`))
		if err == nil || !strings.Contains(err.Error(), "not valid") {
			t.Fatalf("an unknown sidecar field must refuse: err=%v", err)
		}
		err = verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), append(append([]byte{}, sidecar[:len(sidecar)-1]...), []byte(`{"junk":true}`)...))
		if err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("trailing sidecar data must refuse: err=%v", err)
		}
	})

	t.Run("short key refuses", func(t *testing.T) {
		err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte("short"), sidecar)
		if err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
			t.Fatalf("a sub-32-byte key must refuse: err=%v", err)
		}
	})

	t.Run("malformed digest shape refuses", func(t *testing.T) {
		bad := []byte(`{"schema":"setjoin.mailctl.dump-auth/v1","objectKey":"db-dump.dump","sizeBytes":25,"sha256":"` +
			strings.Repeat("z", 64) + `","algorithm":"hmac-sha256","createdAt":"2026-09-20T01:02:03Z","hmacSha256":"` +
			strings.Repeat("0", 64) + `"}`)
		err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), bad)
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("a non-hex digest field must refuse as malformed: err=%v", err)
		}
	})

	t.Run("non-RFC3339 timestamp refuses", func(t *testing.T) {
		bad := []byte(`{"schema":"setjoin.mailctl.dump-auth/v1","objectKey":"db-dump.dump","sizeBytes":25,"sha256":"` +
			strings.Repeat("0", 64) + `","algorithm":"hmac-sha256","createdAt":"not-a-timestamp","hmacSha256":"` +
			strings.Repeat("0", 64) + `"}`)
		err := verifyDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), bad)
		if err == nil || !strings.Contains(err.Error(), "RFC 3339") {
			t.Fatalf("a non-RFC3339 createdAt must refuse: err=%v", err)
		}
	})
}

// ── Dump-authentication fail-closed error legs (occ_f2695a92cddad0cd92e90513).
// Every reachable refusal of the seal/verify pair is pinned by a named test so
// a mutation that turns any refusal into a pass fails here. ──

// TestSealDumpAuthEnvelopeErrorLegs: a missing dump, an unreadable dump, and a
// sub-32-byte key all refuse at seal time; a dump that vanishes between seal
// and verify refuses at verify time — never a silent pass.
func TestSealDumpAuthEnvelopeErrorLegs(t *testing.T) {
	dumpPath := filepath.Join(t.TempDir(), "db-dump.dump")
	if err := os.WriteFile(dumpPath, []byte("PGDMP sealable body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sealDumpAuthEnvelope(filepath.Join(t.TempDir(), "missing.dump"), dbDumpObjectKey, []byte(testDumpAuthKey), time.Now()); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("sealing a missing dump must refuse: %v", err)
	}
	// A directory opens but cannot be read: the digest leg refuses.
	dirDump := filepath.Join(t.TempDir(), "dump-dir")
	if err := os.Mkdir(dirDump, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := sealDumpAuthEnvelope(dirDump, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now()); err == nil || !strings.Contains(err.Error(), "digest ") {
		t.Fatalf("sealing an unreadable dump must refuse at the digest: %v", err)
	}
	if _, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte("short"), time.Now()); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("sealing under a sub-32-byte key must refuse: %v", err)
	}
	sidecar, err := sealDumpAuthEnvelope(dumpPath, dbDumpObjectKey, []byte(testDumpAuthKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyDumpAuthEnvelope(filepath.Join(t.TempDir(), "vanished.dump"), dbDumpObjectKey, []byte(testDumpAuthKey), sidecar); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("verifying a binding whose dump vanished must refuse: %v", err)
	}
}

// TestRunBackupDBRefusesWhenAnyPublicationUploadFails: all four publication
// objects (canonical dump + sidecar, archival dump + sidecar) must upload or
// the backup fails — a dump whose authentication sidecar never published is
// exactly the artifact the restore path refuses, so publication refuses
// up-front instead of producing one.
func TestRunBackupDBRefusesWhenAnyPublicationUploadFails(t *testing.T) {
	clearOperatorDSNEnv(t)
	stubPgDumpProducesFixture(t)
	for name, allow := range map[string]int{
		"canonical dump upload fails":    0,
		"canonical sidecar upload fails": 1,
		"archival dump upload fails":     2,
		"archival sidecar upload fails":  3,
	} {
		t.Run(name, func(t *testing.T) {
			server := failingPutFixture(t, allow)
			err := runBackupDB(&cmdCtx{}, "", []string{
				"--dsn", "postgres://owner@db/setjoin", "--endpoint", server.URL,
				"--bucket", "backups",
				"--access-key-file", accessKeyFile(t, "access"), "--secret-key-file", secretKeyFile(t, "secret"),
				"--dump-hmac-key-file", dumpHMACKeyFile(t, testDumpAuthKey),
			})
			// The refusal must come from the upload leg itself, not an
			// earlier environment failure — "upload to s3://" proves the
			// publication path was actually reached.
			if err == nil || !strings.Contains(err.Error(), "upload to s3://") {
				t.Fatalf("a failed publication upload (%s) must fail the backup at the upload: %v", name, err)
			}
		})
	}
}

// failingPutFixture serves the bucket-location probe and fails every PUT
// after the first `allow` successes with a non-retryable 403.
func failingPutFixture(t *testing.T, allow int) *httptest.Server {
	t.Helper()
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
			return
		}
		puts++
		if puts > allow {
			http.Error(w, `<Error><Code>AccessDenied</Code></Error>`, http.StatusForbidden)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("ETag", `"fixture-etag"`)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestParseBackupDBFlagsMissingDumpKeyFile: an absent dump-auth key file is a
// parse-time refusal, not a mid-backup surprise.
func TestParseBackupDBFlagsMissingDumpKeyFile(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("BACKUP_ACCESS_KEY", "a")
	t.Setenv("BACKUP_SECRET_KEY", "s")
	_, err := parseBackupDBFlags([]string{
		"--dsn", "postgres://owner@db/setjoin", "--bucket", "backups",
		"--dump-hmac-key-file", filepath.Join(t.TempDir(), "absent.key"),
	})
	if err == nil || !strings.Contains(err.Error(), "dump authentication HMAC key") {
		t.Fatalf("an absent dump-auth key file must refuse at parse: %v", err)
	}
}
