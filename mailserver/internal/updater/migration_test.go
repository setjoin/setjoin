package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/shared/release"
)

type fakeMigrationDB struct {
	current        int
	evidence       map[int]MigrationEvidence
	applied        []string
	failAfterApply bool
	applyErr       error
	evidenceErr    error
	currentCalls   int
	currentErrs    map[int]error
}

func (db *fakeMigrationDB) CurrentVersion(context.Context) (int, error) {
	db.currentCalls++
	if err := db.currentErrs[db.currentCalls]; err != nil {
		return 0, err
	}
	return db.current, nil
}
func (db *fakeMigrationDB) Evidence(_ context.Context, version int) (*MigrationEvidence, error) {
	if db.evidenceErr != nil {
		return nil, db.evidenceErr
	}
	evidence, ok := db.evidence[version]
	if !ok {
		return nil, nil
	}
	return &evidence, nil
}
func (db *fakeMigrationDB) Apply(_ context.Context, migration release.Migration, _ string, evidence MigrationEvidence) error {
	if db.applyErr != nil {
		return db.applyErr
	}
	db.current = migration.ToSchema
	db.evidence[migration.ToSchema] = evidence
	db.applied = append(db.applied, migration.ID)
	if db.failAfterApply {
		db.failAfterApply = false
		return errors.New("commit response lost")
	}
	return nil
}

func migrationFixture(t *testing.T, sqls ...string) (string, string, *release.Manifest) {
	t.Helper()
	dir := t.TempDir()
	migrationsDir := filepath.Join(dir, "share", "migrations")
	if err := os.MkdirAll(migrationsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := &release.Manifest{ReleaseID: "release-2", SchemaFrom: 178, SchemaTo: 178 + len(sqls)}
	for index, sql := range sqls {
		id := "migration-v" + string(rune('a'+index))
		sum := sha256.Sum256([]byte(sql))
		digest := hex.EncodeToString(sum[:])
		manifest.Migrations = append(manifest.Migrations, release.Migration{ID: id, FromSchema: 178 + index,
			ToSchema: 179 + index, SHA256: digest, Class: release.MigrationExpand,
			CompatibilityEvidence: "old-binary-ok", PreviousBinaryEvidence: "rollback-ok", TransactionRequired: true})
		if err := os.WriteFile(filepath.Join(migrationsDir, id+".sql"), []byte(sql), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	return dir, strings.Repeat("a", 64), manifest
}

func TestMigrationRunnerAppliesAndReconcilesLostCommitResponse(t *testing.T) {
	dir, digest, manifest := migrationFixture(t,
		"CREATE TABLE one(id bigint); INSERT INTO schema_migrations(version,applied_at) VALUES(179,now());",
		"CREATE TABLE two(id bigint); INSERT INTO schema_migrations(version,applied_at) VALUES(180,now());",
	)
	db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}, failAfterApply: true}
	runner := MigrationRunner{DB: db}
	if err := runner.ApplyRelease(context.Background(), dir, digest, manifest, 178, 180); err != nil {
		t.Fatal(err)
	}
	if db.current != 180 || strings.Join(db.applied, ",") != "migration-va,migration-vb" {
		t.Fatalf("current=%d applied=%v", db.current, db.applied)
	}
	if err := runner.ApplyRelease(context.Background(), dir, digest, manifest, 178, 180); err != nil {
		t.Fatalf("exact replay failed: %v", err)
	}
	if len(db.applied) != 2 {
		t.Fatalf("replay reapplied migrations: %v", db.applied)
	}
}

func TestMigrationRunnerRefusesRangeEvidenceChecksumAndUnsafeSQL(t *testing.T) {
	t.Run("range", func(t *testing.T) {
		dir, digest, manifest := migrationFixture(t, "SELECT 1")
		db := &fakeMigrationDB{current: 177, evidence: map[int]MigrationEvidence{}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationRange) {
			t.Fatalf("range error=%v", err)
		}
	})
	t.Run("evidence", func(t *testing.T) {
		dir, digest, manifest := migrationFixture(t, "SELECT 1")
		db := &fakeMigrationDB{current: 179, evidence: map[int]MigrationEvidence{179: {Version: 179, SHA256: strings.Repeat("0", 64)}}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationEvidence) {
			t.Fatalf("evidence error=%v", err)
		}
	})
	t.Run("checksum", func(t *testing.T) {
		dir, digest, manifest := migrationFixture(t, "SELECT 1")
		if err := os.Chmod(filepath.Join(dir, "share", "migrations", "migration-va.sql"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "share", "migrations", "migration-va.sql"), []byte("SELECT 2"), 0o444); err != nil {
			t.Fatal(err)
		}
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationEvidence) {
			t.Fatalf("checksum error=%v", err)
		}
	})
	for name, sql := range map[string]string{
		"concurrent":        "CREATE INDEX CONCURRENTLY x ON y(z)",
		"transaction":       "BEGIN; SELECT 1; COMMIT;",
		"qualified type":    "ALTER TYPE public.mood ADD VALUE 'sad'",
		"database":          "CREATE DATABASE other",
		"tablespace":        "DROP TABLESPACE other",
		"alter system":      "ALTER SYSTEM SET work_mem='1GB'",
		"copy program":      "COPY x FROM PROGRAM 'id'",
		"procedure control": "CALL migration_procedure()",
	} {
		t.Run(name, func(t *testing.T) {
			dir, digest, manifest := migrationFixture(t, sql)
			db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
			if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationUnsafe) {
				t.Fatalf("unsafe SQL error=%v", err)
			}
		})
	}
	if err := validateTransactionalSQL("-- COMMIT\nCREATE TABLE commit_log(v text DEFAULT 'BEGIN'); DO $$ BEGIN NULL; END $$;"); err != nil {
		t.Fatalf("tokens inside comments/strings/dollar bodies were rejected: %v", err)
	}
}

func TestMigrationRunnerNoOpRequiresExactRange(t *testing.T) {
	dir, digest, manifest := migrationFixture(t)
	db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
	if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 178); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationRunnerRejectsInvalidDependenciesAndBrokenChains(t *testing.T) {
	dir, digest, manifest := migrationFixture(t, "SELECT 1")
	validDB := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
	for name, candidate := range map[string]struct {
		runner   MigrationRunner
		digest   string
		manifest *release.Manifest
	}{
		"nil database":   {runner: MigrationRunner{}, digest: digest, manifest: manifest},
		"nil manifest":   {runner: MigrationRunner{DB: validDB}, digest: digest},
		"invalid digest": {runner: MigrationRunner{DB: validDB}, digest: "invalid", manifest: manifest},
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate.runner.ApplyRelease(context.Background(), dir, candidate.digest, candidate.manifest, 178, 179); err == nil {
				t.Fatal("invalid migration runner input was accepted")
			}
		})
	}

	t.Run("manifest range", func(t *testing.T) {
		if err := (MigrationRunner{DB: validDB}).ApplyRelease(context.Background(), dir, digest, manifest, 177, 179); !errors.Is(err, ErrMigrationRange) {
			t.Fatalf("range error=%v", err)
		}
	})
	t.Run("current version read", func(t *testing.T) {
		db := &fakeMigrationDB{evidence: map[int]MigrationEvidence{}, currentErrs: map[int]error{1: errors.New("read failed")}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); err == nil || err.Error() != "read failed" {
			t.Fatalf("current version error=%v", err)
		}
	})
	t.Run("database above range", func(t *testing.T) {
		db := &fakeMigrationDB{current: 180, evidence: map[int]MigrationEvidence{}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationRange) {
			t.Fatalf("range error=%v", err)
		}
	})
	t.Run("chain gap", func(t *testing.T) {
		broken := *manifest
		broken.Migrations = append([]release.Migration(nil), manifest.Migrations...)
		broken.Migrations[0].FromSchema = 177
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, &broken, 178, 179); !errors.Is(err, ErrMigrationRange) {
			t.Fatalf("gap error=%v", err)
		}
	})
	t.Run("chain ends early", func(t *testing.T) {
		broken := *manifest
		broken.Migrations = nil
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, &broken, 178, 179); !errors.Is(err, ErrMigrationRange) {
			t.Fatalf("end error=%v", err)
		}
	})
}

func TestMigrationRunnerPreservesUncertainCommitFailures(t *testing.T) {
	dir, digest, manifest := migrationFixture(t, "SELECT 1")
	t.Run("apply did not commit", func(t *testing.T) {
		applyErr := errors.New("apply failed")
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}, applyErr: applyErr}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, applyErr) {
			t.Fatalf("apply error=%v", err)
		}
	})
	t.Run("version reconciliation failed", func(t *testing.T) {
		readErr := errors.New("reconciliation read failed")
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}, applyErr: errors.New("response lost"), currentErrs: map[int]error{2: readErr}}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); err == nil || err.Error() != "response lost" {
			t.Fatalf("uncertain commit error=%v", err)
		}
	})
	t.Run("durable evidence read failed", func(t *testing.T) {
		evidenceErr := errors.New("evidence read failed")
		db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}, failAfterApply: true, evidenceErr: evidenceErr}
		err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179)
		if err == nil || !strings.Contains(err.Error(), "commit response lost") || !strings.Contains(err.Error(), evidenceErr.Error()) {
			t.Fatalf("joined reconciliation error=%v", err)
		}
	})
	t.Run("replay evidence read failed", func(t *testing.T) {
		db := &fakeMigrationDB{current: 179, evidence: map[int]MigrationEvidence{}, evidenceErr: errors.New("evidence unavailable")}
		if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); err == nil || err.Error() != "evidence unavailable" {
			t.Fatalf("evidence error=%v", err)
		}
	})
}

func TestMigrationRunnerRejectsUnsafeMigrationFiles(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string){
		"missing": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"writable": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"empty": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, 0); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o444); err != nil {
				t.Fatal(err)
			}
		},
		"oversize": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, (16<<20)+1); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o444); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, digest, manifest := migrationFixture(t, "SELECT 1")
			mutate(t, filepath.Join(dir, "share", "migrations", "migration-va.sql"))
			db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
			if err := (MigrationRunner{DB: db}).ApplyRelease(context.Background(), dir, digest, manifest, 178, 179); !errors.Is(err, ErrMigrationUnsafe) {
				t.Fatalf("unsafe file error=%v", err)
			}
		})
	}
}

func TestSQLWordsRejectsMalformedLexicalBoundaries(t *testing.T) {
	for name, input := range map[string]string{
		"block comment": "/* unterminated",
		"single quote":  "SELECT 'unterminated",
		"identifier":    "SELECT \"unterminated",
		"dollar quote":  "DO $body$ BEGIN NULL; END",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sqlWords(input); err == nil {
				t.Fatal("malformed SQL was accepted")
			}
			if err := validateTransactionalSQL(input); !errors.Is(err, ErrMigrationUnsafe) {
				t.Fatalf("validation error=%v", err)
			}
		})
	}
	words, err := sqlWords("-- tail comment\nSELECT _v2, $1, $bad-tag$ FROM \"BEGIN\" WHERE value='COMMIT''SAFE'")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(words, ",") != "select,_v2,bad,tag,from,where,value" {
		t.Fatalf("words=%v", words)
	}
}
