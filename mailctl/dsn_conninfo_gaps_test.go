package main

// Gap coverage for the backup_db/restore DSN credential-splitting stack and
// the flag parsers' file-credential branches: residual-embedding refusal after
// stripping, multi-password and password-only-userinfo URL forms, the
// fail-closed fallbacks for conninfo the tokenizer cannot handle, the
// tokenizer's own edge shapes, and the 0600-file credential read errors both
// parsers surface.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── dsnForChildArgv / splitDSNCredentials ────────────────────────────────────

// TestDSNForChildArgvRefusesResidualEmbedding: a keyword DSN whose password is
// strippable but whose surviving token still contains password-shaped text
// (here a quoted value embedding "password=") must be refused at the
// child-argv gate — the stripped conninfo is re-checked before use.
func TestDSNForChildArgvRefusesResidualEmbedding(t *testing.T) {
	cleanDSN, dbPassword, err := splitDSNCredentials("password=real db='password=x'")
	if err != nil {
		t.Fatalf("split refused the DSN outright: %v", err)
	}
	if dbPassword != "real" {
		t.Fatalf("split password = %q, want real", dbPassword)
	}
	if _, _, err := dsnForChildArgv("password=real db='password=x'"); err == nil ||
		!strings.Contains(err.Error(), "still embeds credentials after stripping") {
		t.Fatalf("dsnForChildArgv = %v, want the residual-embedding refusal", err)
	}
	_ = cleanDSN
}

// TestSplitURLDSNCredentialsRefusesMultipleQueryPasswords: two ?password=
// parameters are ambiguous — refused instead of guessed.
func TestSplitURLDSNCredentialsRefusesMultipleQueryPasswords(t *testing.T) {
	_, _, err := splitDSNCredentials("postgres://host/db?password=first&password=second")
	if err == nil || !strings.Contains(err.Error(), "multiple ?password= parameters") {
		t.Fatalf("split = %v, want the multiple-password refusal", err)
	}
}

// TestSplitURLDSNCredentialsStripsPasswordOnlyUserinfo: a userinfo carrying
// only a password (":secret@") strips to a credential-free URL and yields the
// password for PGPASSWORD delivery.
func TestSplitURLDSNCredentialsStripsPasswordOnlyUserinfo(t *testing.T) {
	clean, pw, err := splitDSNCredentials("postgres://:sekret@host.example:5432/mail?sslmode=require")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if pw != "sekret" {
		t.Errorf("password = %q, want sekret", pw)
	}
	if strings.Contains(clean, "sekret") {
		t.Errorf("clean DSN %q still embeds the password", clean)
	}
	if !strings.HasPrefix(clean, "postgres://host.example:5432/mail?") {
		t.Errorf("clean DSN = %q, want the credential-free URL form", clean)
	}
}

// TestURLUserinfoMayHidePasswordWithoutScheme: the conservative fallback only
// applies to URL-form conninfo; a string without "://" cannot hide a userinfo
// password in that shape.
func TestURLUserinfoMayHidePasswordWithoutScheme(t *testing.T) {
	if urlUserinfoMayHidePassword("user:pw@host/db") {
		t.Error("conninfo without :// must not be treated as URL-userinfo-bearing")
	}
	if urlUserinfoMayHidePassword("postgres://host/db") {
		t.Error("URL without a userinfo segment must not be treated as password-bearing")
	}
	if !urlUserinfoMayHidePassword("postgres://user:pw@host/db") {
		t.Error("URL with a user:password userinfo must be treated as password-bearing")
	}
}

// TestSplitKeywordDSNCredentialsRefusesUnscannableConninfo: a keyword-form DSN
// the tokenizer cannot parse (a bare keyword with no '=' following) is refused
// rather than passed through to child argv.
func TestSplitKeywordDSNCredentialsRefusesUnscannableConninfo(t *testing.T) {
	_, _, err := splitDSNCredentials("foo bar=baz")
	if err == nil || !strings.Contains(err.Error(), "cannot be safely stripped") {
		t.Fatalf("split = %v, want the unstrippable refusal", err)
	}
}

// ── scanKeywordConninfo edge shapes ──────────────────────────────────────────

func TestScanKeywordConninfoEdgeShapes(t *testing.T) {
	t.Run("trailing whitespace terminates cleanly", func(t *testing.T) {
		pw, found, kept, err := scanKeywordConninfo("host=h dbname=d ")
		if err != nil || found || pw != "" {
			t.Fatalf("scan = (%q, %v, %v, %v), want clean no-password result", pw, found, kept, err)
		}
		if len(kept) != 2 {
			t.Errorf("kept = %v, want both tokens", kept)
		}
	})

	t.Run("malformed keyword without equals is an error", func(t *testing.T) {
		if _, _, _, err := scanKeywordConninfo("foo bar=baz"); err == nil ||
			!strings.Contains(err.Error(), "malformed keyword/value conninfo") {
			t.Fatalf("scan = %v, want the malformed-conninfo error", err)
		}
	})

	t.Run("unterminated quoted value propagates an error", func(t *testing.T) {
		if _, _, _, err := scanKeywordConninfo("password='never-ends"); err == nil ||
			!strings.Contains(err.Error(), "unterminated quoted value") {
			t.Fatalf("scan = %v, want the unterminated-quote error", err)
		}
	})

	t.Run("empty value at end of conninfo", func(t *testing.T) {
		pw, found, kept, err := scanKeywordConninfo("host=")
		if err != nil || found || pw != "" {
			t.Fatalf("scan = (%q, %v, %v, %v), want clean empty-value result", pw, found, kept, err)
		}
		if len(kept) != 1 || kept[0] != "host=" {
			t.Errorf("kept = %v, want [host=]", kept)
		}
	})
}

// TestScanConninfoValueEscapeAndQuoteEdges pins the value scanner's refusal
// shapes: unterminated backslash escapes inside and outside quotes, and an
// unterminated single-quoted value.
func TestScanConninfoValueEscapeAndQuoteEdges(t *testing.T) {
	t.Run("unterminated backslash escape inside quotes", func(t *testing.T) {
		if _, _, err := scanConninfoValue(`'ab\`, 0); err == nil ||
			!strings.Contains(err.Error(), "unterminated backslash escape") {
			t.Fatalf("scan = %v, want the unterminated-escape error", err)
		}
	})
	t.Run("backslash escape inside quotes decodes", func(t *testing.T) {
		val, next, err := scanConninfoValue(`'a\b'`, 0)
		if err != nil || val != "ab" || next != len(`'a\b'`) {
			t.Fatalf("scan = (%q, %d, %v), want decoded %q", val, next, err, "ab")
		}
	})
	t.Run("unterminated quoted value", func(t *testing.T) {
		if _, _, err := scanConninfoValue("'abc", 0); err == nil ||
			!strings.Contains(err.Error(), "unterminated quoted value") {
			t.Fatalf("scan = %v, want the unterminated-quote error", err)
		}
	})
	t.Run("unterminated backslash escape in unquoted value", func(t *testing.T) {
		if _, _, err := scanConninfoValue(`ab\`, 0); err == nil ||
			!strings.Contains(err.Error(), "unterminated backslash escape") {
			t.Fatalf("scan = %v, want the unterminated-escape error", err)
		}
	})
	t.Run("start past the end yields an empty value", func(t *testing.T) {
		val, next, err := scanConninfoValue("host=", len("host="))
		if err != nil || val != "" || next != len("host=") {
			t.Fatalf("scan = (%q, %d, %v), want empty value at end", val, next, err)
		}
	})
}

// ── flag parsers: file-credential read failures ──────────────────────────────

func TestParseBackupDBFlagsFileCredentialReadFailures(t *testing.T) {
	dir := t.TempDir()
	goodSecret := filepath.Join(dir, "secret")
	if err := os.WriteFile(goodSecret, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	t.Setenv("BACKUP_ACCESS_KEY", "")
	t.Setenv("BACKUP_SECRET_KEY", "")
	t.Setenv("BACKUP_ACCESS_KEY_FILE", "")
	t.Setenv("BACKUP_SECRET_KEY_FILE", "")
	t.Setenv("DB_DSN", "")
	t.Setenv("DB_DIRECT_OWNER_DSN", "")
	t.Setenv("DB_OWNER_DSN", "")
	t.Setenv("DB_DIRECT_DSN", "")

	t.Run("missing access-key file", func(t *testing.T) {
		_, err := parseBackupDBFlags([]string{
			"--bucket", "backups",
			"--access-key-file", missing,
			"--secret-key-file", goodSecret,
		})
		if err == nil || !strings.Contains(err.Error(), "backup access key") {
			t.Fatalf("err = %v, want the access-key file read failure", err)
		}
	})

	t.Run("missing secret-key file", func(t *testing.T) {
		_, err := parseBackupDBFlags([]string{
			"--bucket", "backups",
			"--access-key-file", goodSecret,
			"--secret-key-file", missing,
		})
		if err == nil || !strings.Contains(err.Error(), "backup secret key") {
			t.Fatalf("err = %v, want the secret-key file read failure", err)
		}
	})
}

func TestParseRestoreFlagsFileCredentialReadFailures(t *testing.T) {
	dir := t.TempDir()
	goodSecret := filepath.Join(dir, "secret")
	if err := os.WriteFile(goodSecret, []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing")

	t.Setenv("BACKUP_ACCESS_KEY", "")
	t.Setenv("BACKUP_SECRET_KEY", "")
	t.Setenv("BACKUP_ACCESS_KEY_FILE", "")
	t.Setenv("BACKUP_SECRET_KEY_FILE", "")
	t.Setenv("DB_DSN", "")
	t.Setenv("DB_DIRECT_OWNER_DSN", "")
	t.Setenv("DB_OWNER_DSN", "")
	t.Setenv("DB_DIRECT_DSN", "")

	t.Run("unstrippable env dsn is refused at the child-argv gate", func(t *testing.T) {
		// An ENV-sourced DSN skips the parent-argv refusal (nothing was passed
		// on the command line) and must fail the child-argv gate instead. The
		// DSN gate runs before the bucket/credential checks.
		t.Setenv("DB_DIRECT_OWNER_DSN", "foo bar=baz")
		for _, key := range []string{"DB_DSN", "DB_OWNER_DSN", "DB_DIRECT_DSN"} {
			t.Setenv(key, "")
		}
		_, err := parseRestoreFlags([]string{
			"--type", "config",
			"--bucket", "backups",
			"--dry-run",
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be safely stripped") {
			t.Fatalf("err = %v, want the unstrippable-DSN refusal", err)
		}
	})

	t.Run("bucket and credentials are required", func(t *testing.T) {
		_, err := parseRestoreFlags([]string{"--type", "config", "--dry-run"})
		if err == nil || !strings.Contains(err.Error(), "backup bucket and access/secret credentials") {
			t.Fatalf("err = %v, want the missing-credentials error", err)
		}
	})

	t.Run("missing access-key file", func(t *testing.T) {
		_, err := parseRestoreFlags([]string{
			"--type", "config",
			"--bucket", "backups",
			"--access-key-file", missing,
			"--secret-key-file", goodSecret,
			"--dry-run",
		})
		if err == nil || !strings.Contains(err.Error(), "backup access key") {
			t.Fatalf("err = %v, want the access-key file read failure", err)
		}
	})

	t.Run("missing secret-key file", func(t *testing.T) {
		_, err := parseRestoreFlags([]string{
			"--type", "config",
			"--bucket", "backups",
			"--access-key-file", goodSecret,
			"--secret-key-file", missing,
			"--dry-run",
		})
		if err == nil || !strings.Contains(err.Error(), "backup secret key") {
			t.Fatalf("err = %v, want the secret-key file read failure", err)
		}
	})
}
