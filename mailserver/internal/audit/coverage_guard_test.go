package audit_test

// TestCoverageGuard enforces two structural invariants:
//
//  1. Single INSERT path: only audit_write.sql may INSERT INTO admin_audit_log.
//     Any other file doing so is a silent-loss risk — audit rows written outside
//     the choke point bypass tier validation, autonomous-write semantics, and
//     future policy hooks.
//
//  2. Sensitive→core classification: every perm in SensitivePermissions and
//     every perm whose SoD class is "security" or "audit" must resolve to
//     tier="core" via TierForPerm. A newly-added sensitive perm that silently
//     resolves to "routine" would be mis-classified and dropped at the lean
//     audit level.
//
// The non-vacuous sub-test proves the scanner actually flags violations, not
// just vacuously passes over an empty scan.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/shared/permissions"
)

// repoRoot returns the repo root by walking up from the package directory.
// go test sets CWD to the package dir (mailserver/internal/audit).
func repoRoot(t *testing.T) string {
	t.Helper()
	// Walk up until we find go.work or a directory with both mailserver/ and shared/.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "shared")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "mailserver")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no shared/ + mailserver/ ancestor found)")
		}
		dir = parent
	}
}

// scanForDirectInsert walks all .go files under goDir and all .sql files under
// sqlDir and returns file paths that contain "INSERT INTO admin_audit_log"
// (case-insensitive), EXCLUDING the exempt file (by path suffix).
func scanForDirectInsert(t *testing.T, goDir, sqlDir, exemptSuffix string) []string {
	t.Helper()
	var hits []string

	walk := func(root, ext string) {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ext) {
				return nil
			}
			// ponytail: skip _test.go files — test fixtures legitimately reference
			// the table name (e.g. the non-vacuous proof below) and are not
			// production insert paths.
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(strings.ToLower(string(data)), "insert into admin_audit_log") {
				// Exempt by path suffix (not content pattern — immune to comment tricks).
				if !strings.HasSuffix(filepath.ToSlash(path), exemptSuffix) {
					hits = append(hits, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	walk(goDir, ".go")
	walk(sqlDir, ".sql")
	return hits
}

func TestCoverageGuard(t *testing.T) {
	root := repoRoot(t)
	goInternal := filepath.Join(root, "mailserver", "internal")
	goCmd := filepath.Join(root, "mailserver", "cmd")
	sqlDir := filepath.Join(root, "mailserver", "sql", "reducers")

	// Verify the directories exist before scanning.
	for _, d := range []string{goInternal, goCmd, sqlDir} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("expected directory %s to exist: %v", d, err)
		}
	}

	t.Run("SingleInsertPath", func(t *testing.T) {
		// ponytail: exempt by trailing path, not by comment or regex — path is
		// harder to accidentally satisfy than a pattern in content.
		// Scan internal/ + cmd/ + sql/reducers/ — all Go and SQL owned by mailserver.
		exempt := "sql/reducers/audit_write.sql"
		var hits []string
		hits = append(hits, scanForDirectInsert(t, goInternal, sqlDir, exempt)...)
		hits = append(hits, scanForDirectInsert(t, goCmd, sqlDir, exempt)...)
		if len(hits) > 0 {
			t.Errorf("direct INSERT INTO admin_audit_log found outside choke point (%d file(s)):\n  %s\n"+
				"Route all audit writes through audit_write.sql via audit.Write / audit.WriteAutonomous / audit.WriteSystem.",
				len(hits), strings.Join(hits, "\n  "))
		}
	})

	t.Run("SensitivePermsResolveToCoreNoVacuous", func(t *testing.T) {
		// Collect perms that must be core: SensitivePermissions ∪ {security,audit}-class.
		mustBeCore := make(map[string]string) // perm → reason
		for perm := range permissions.SensitivePermissions {
			mustBeCore[perm] = "SensitivePermissions"
		}
		for _, perm := range permissions.AllPermissions {
			for _, c := range permissions.ClassOf(perm) {
				if c == "security" || c == "audit" {
					if _, ok := mustBeCore[perm]; !ok {
						mustBeCore[perm] = "class=" + c
					}
				}
			}
		}

		if len(mustBeCore) == 0 {
			t.Fatal("mustBeCore set is empty — SensitivePermissions and security/audit classes are both empty; the guard is vacuous")
		}

		var bad []string
		for perm, reason := range mustBeCore {
			if got := audit.TierForPerm(perm); got != "core" {
				bad = append(bad, perm+" ("+reason+"): got "+got)
			}
		}
		if len(bad) > 0 {
			t.Errorf("%d sensitive/security/audit perm(s) resolve to non-core tier:\n  %s",
				len(bad), strings.Join(bad, "\n  "))
		}
	})

	// Non-vacuous proof: the scanner MUST flag a planted INSERT.
	t.Run("ScannerNonVacuous", func(t *testing.T) {
		dir := t.TempDir()

		// Fixture that SHOULD be flagged.
		bad := filepath.Join(dir, "rogue_writer.go")
		if err := os.WriteFile(bad, []byte(`package x
// rogue: INSERT INTO admin_audit_log VALUES (1,2,3)
`), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		// Exempt file that should NOT be flagged.
		exemptDir := filepath.Join(dir, "sql", "reducers")
		if err := os.MkdirAll(exemptDir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		exempt := filepath.Join(exemptDir, "audit_write.sql")
		if err := os.WriteFile(exempt, []byte(`INSERT INTO admin_audit_log SELECT $1`), 0o600); err != nil {
			t.Fatalf("write exempt: %v", err)
		}

		hits := scanForDirectInsert(t, dir, exemptDir, "sql/reducers/audit_write.sql")
		if len(hits) != 1 {
			t.Errorf("scanner non-vacuous proof failed: expected 1 hit, got %d (%v)", len(hits), hits)
		}
		if len(hits) == 1 && hits[0] != bad {
			t.Errorf("scanner hit wrong file: got %s, want %s", hits[0], bad)
		}
	})
}
