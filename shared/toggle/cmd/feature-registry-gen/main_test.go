package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/shared/toggle"
)

func put(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryVersionsAndNextMigrationVersion(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "shared/toggle/testdata/registry-v184.json"), []byte("{}"))
	put(t, filepath.Join(root, "shared/toggle/testdata/registry-v183.json"), []byte("{}"))
	put(t, filepath.Join(root, "mailserver/sql/dbschema/V183__a.sql"), nil)
	put(t, filepath.Join(root, "mailserver/sql/dbschema/V199__b.sql"), nil)

	versions, err := registryVersions(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(versions, ","), "V183,V184"; got != want {
		t.Fatalf("registry versions = %s, want %s", got, want)
	}
	next, err := nextMigrationVersion(root)
	if err != nil {
		t.Fatal(err)
	}
	if next != "V200" {
		t.Fatalf("next migration = %s, want V200", next)
	}
}

func TestVerifyChecksumsCoversMigrationAndSnapshot(t *testing.T) {
	root := t.TempDir()
	migration := filepath.Join(root, "V184__feature_toggle_registry_projection.sql")
	snapshot := filepath.Join(root, "registry-v184.json")
	checksum := snapshot + ".sha256"
	migrationBody := []byte("SELECT 1;\n")
	snapshotBody := []byte("{\"version\":\"V184\"}\n")
	put(t, migration, migrationBody)
	put(t, snapshot, snapshotBody)
	put(t, checksum, checksumDocument(
		checksumEntry(migration, migrationBody),
		checksumEntry(snapshot, snapshotBody),
	))
	if err := verifyChecksums(migration, snapshot, checksum); err != nil {
		t.Fatalf("valid checksums rejected: %v", err)
	}
	put(t, snapshot, append(bytes.Clone(snapshotBody), ' '))
	if err := verifyChecksums(migration, snapshot, checksum); err == nil {
		t.Fatal("mutated snapshot passed immutable checksum")
	}
}

func TestMigrationFooterUsesValidatedStaticProjection(t *testing.T) {
	footer := string(migrationFooter("V184"))
	if strings.Contains(footer, "{{") {
		t.Fatalf("migration footer contains an unresolved placeholder: %s", footer)
	}
	if !strings.Contains(footer, "registry_digest='"+toggle.RegistryDigest()+"'") {
		t.Fatalf("migration footer does not pin the registry digest: %s", footer)
	}
	if !strings.Contains(footer, "VALUES (184, now())") {
		t.Fatalf("migration footer does not pin the schema version: %s", footer)
	}
}

func TestGeneratorHelpersAndRepositoryRoot(t *testing.T) {
	if boolCount(true, false, true, false) != 2 {
		t.Fatal("boolCount did not count true values")
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repository root is invalid: %v", err)
	}
	outside := t.TempDir()
	if err := os.Chdir(outside); err != nil {
		t.Fatal(err)
	}
	if _, err := repositoryRoot(); err == nil {
		t.Fatal("repositoryRoot accepted a tree without go.work")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunCommandModes(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--check"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "feature_registry_projection_ok\n" {
		t.Fatalf("check output=%q", output.String())
	}
	output.Reset()
	if err := run([]string{"--print-sql"}, &output); err != nil {
		t.Fatal(err)
	}
	wantSQL, err := currentSQL()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), wantSQL) {
		t.Fatal("print-sql output differs from current projection")
	}
	for _, args := range [][]string{
		nil,
		{"--unknown"},
		{"--check", "extra"},
		{"--check", "--print-sql"},
		{"--check", "--migration", "V184"},
		{"--print-sql", "--migration", "V184"},
		{"--bootstrap-v183", "--migration", "V184"},
		{"--write"},
		{"--write", "--migration", "V183"},
	} {
		if err := run(args, &output); err == nil {
			t.Fatalf("arguments %v accepted", args)
		}
	}
	if err := run([]string{"--check"}, failingWriter{}); err == nil {
		t.Fatal("check ignored output failure")
	}
	if err := run([]string{"--print-sql"}, failingWriter{}); err == nil {
		t.Fatal("print-sql ignored output failure")
	}

	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	root := t.TempDir()
	put(t, filepath.Join(root, "go.work"), []byte("go 1.26.4\n"))
	put(t, filepath.Join(root, "mailserver/sql/dbschema/V183__feature_toggle_registry_authority.sql"), []byte("-- v183\n"))
	if err := os.MkdirAll(filepath.Join(root, "shared/toggle/testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "mailserver/sql/generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--bootstrap-v183"}, &output); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--write", "--migration", "V184"}, &output); err != nil {
		t.Fatal(err)
	}
}

func TestWriteFrozenCreatesImmutableArtifacts(t *testing.T) {
	root := t.TempDir()
	migration := filepath.Join(root, "mailserver/sql/dbschema/V183__feature_toggle_registry_authority.sql")
	put(t, migration, []byte("-- frozen migration\n"))
	if err := os.MkdirAll(filepath.Join(root, "shared/toggle/testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "mailserver/sql/generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFrozen(root); err != nil {
		t.Fatal(err)
	}
	snapshotPath, sqlPath := paths(root, initialVersion)
	if err := verifyChecksums(migration, snapshotPath, snapshotPath+".sha256"); err != nil {
		t.Fatal(err)
	}
	projection, err := currentSQL()
	if err != nil {
		t.Fatal(err)
	}
	if err := sameFile(sqlPath, projection); err != nil {
		t.Fatal(err)
	}
	if err := writeFrozen(root); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second freeze error=%v", err)
	}

	missing := t.TempDir()
	if err := os.MkdirAll(filepath.Join(missing, "shared/toggle/testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(missing, "mailserver/sql/generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFrozen(missing); err == nil || !strings.Contains(err.Error(), "read migration") {
		t.Fatalf("missing migration error=%v", err)
	}
}

func TestWriteNextCreatesVersionedProjectionAndRejectsBadVersions(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "mailserver/sql/dbschema/V183__feature_toggle_registry_authority.sql"), []byte("-- v183\n"))
	if err := os.MkdirAll(filepath.Join(root, "shared/toggle/testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "mailserver/sql/generated"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeNext(root, "V184"); err != nil {
		t.Fatal(err)
	}
	snapshotPath, sqlPath := paths(root, "V184")
	migrationPath := registryMigrationPath(root, "V184")
	if err := verifyChecksums(migrationPath, snapshotPath, snapshotPath+".sha256"); err != nil {
		t.Fatal(err)
	}
	projection, err := currentSQL()
	if err != nil {
		t.Fatal(err)
	}
	if err := sameFile(sqlPath, projection); err != nil {
		t.Fatal(err)
	}
	migrationBody, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(migrationBody, []byte("VALUES (184, now())")) {
		t.Fatal("next migration footer is absent")
	}
	if err := writeNext(root, "V184"); err == nil || !strings.Contains(err.Error(), "next unused") {
		t.Fatalf("reused version error=%v", err)
	}
	for _, version := range []string{"184", "V18x", "V186"} {
		if err := writeNext(root, version); err == nil {
			t.Fatalf("invalid/non-next version %q accepted", version)
		}
	}

	maxed := t.TempDir()
	put(t, filepath.Join(maxed, "mailserver/sql/dbschema/V999__last.sql"), nil)
	if _, err := nextMigrationVersion(maxed); err == nil {
		t.Fatal("V999 produced a next migration")
	}
	empty := t.TempDir()
	if _, err := nextMigrationVersion(empty); err == nil {
		t.Fatal("empty migration directory produced a next migration")
	}
}

func TestChecksumAndDriftFailuresArePrecise(t *testing.T) {
	root := t.TempDir()
	if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), "V183") {
		t.Fatalf("missing snapshot error=%v", err)
	}
	path := filepath.Join(root, "artifact")
	put(t, path, []byte("actual"))
	if err := sameFile(path, []byte("wanted")); err == nil {
		t.Fatal("stale file matched")
	}
	if err := sameFile(filepath.Join(root, "missing"), nil); err == nil {
		t.Fatal("missing file matched")
	}

	migration := filepath.Join(root, "migration.sql")
	snapshot := filepath.Join(root, "snapshot.json")
	checksum := filepath.Join(root, "checksums")
	put(t, migration, []byte("migration"))
	put(t, snapshot, []byte("snapshot"))
	put(t, checksum, []byte("bad\n"))
	if err := verifyChecksums(migration, snapshot, checksum); err == nil {
		t.Fatal("malformed checksum accepted")
	}
	entry := checksumEntry(migration, []byte("migration"))
	put(t, checksum, checksumDocument(entry, entry))
	if err := verifyChecksums(migration, snapshot, checksum); err == nil {
		t.Fatal("duplicate checksum accepted")
	}
	put(t, checksum, checksumDocument(entry))
	if err := verifyChecksums(migration, snapshot, checksum); err == nil {
		t.Fatal("partial checksum accepted")
	}
	put(t, checksum, checksumDocument(checksumLine{name: filepath.Base(migration), hash: strings.Repeat("0", 64)}, checksumEntry(snapshot, []byte("snapshot"))))
	if err := verifyChecksums(migration, snapshot, checksum); err == nil {
		t.Fatal("wrong checksum accepted")
	}
	if got := driftError(errors.New("stale"), path).Error(); !strings.Contains(got, "E_FEATURE_REGISTRY_DRIFT") || !strings.Contains(got, path) {
		t.Fatalf("drift error=%s", got)
	}
}

func TestCheckOutputsUsesLatestVersionWithoutRewritingV183(t *testing.T) {
	root := t.TempDir()
	oldSnapshot, err := currentSnapshot("V183")
	if err != nil {
		t.Fatal(err)
	}
	oldSnapshot.RegistryDigest = strings.Repeat("0", 64)
	oldPayload, err := marshalSnapshotValue(oldSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	currentPayload, err := marshalSnapshot("V184")
	if err != nil {
		t.Fatal(err)
	}
	oldMigration := filepath.Join(root, "mailserver/sql/dbschema/V183__feature_toggle_registry_authority.sql")
	currentMigration := filepath.Join(root, "mailserver/sql/dbschema/V184__feature_toggle_registry_projection.sql")
	oldSnapshotPath := filepath.Join(root, "shared/toggle/testdata/registry-v183.json")
	currentSnapshotPath := filepath.Join(root, "shared/toggle/testdata/registry-v184.json")
	currentSQLPath := filepath.Join(root, "mailserver/sql/generated/feature_toggle_registry_current.sql")
	put(t, oldMigration, []byte("-- historical V183\n"))
	put(t, oldSnapshotPath, oldPayload)
	put(t, oldSnapshotPath+".sha256", checksumDocument(
		checksumEntry(oldMigration, []byte("-- historical V183\n")),
		checksumEntry(oldSnapshotPath, oldPayload),
	))
	projection, err := currentSQL()
	if err != nil {
		t.Fatal(err)
	}
	put(t, currentMigration, projection)
	put(t, currentSnapshotPath, currentPayload)
	put(t, currentSnapshotPath+".sha256", checksumDocument(
		checksumEntry(currentMigration, projection),
		checksumEntry(currentSnapshotPath, currentPayload),
	))
	put(t, currentSQLPath, projection)

	if err := checkOutputs(root); err != nil {
		t.Fatalf("latest projection rejected: %v", err)
	}
}

func validRegistryRoot(t *testing.T) (root, migrationPath, snapshotPath, sqlPath string) {
	t.Helper()
	root = t.TempDir()
	migrationPath = registryMigrationPath(root, initialVersion)
	snapshotPath, sqlPath = paths(root, initialVersion)
	payload, err := marshalSnapshot(initialVersion)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := currentSQL()
	if err != nil {
		t.Fatal(err)
	}
	put(t, migrationPath, migration)
	put(t, snapshotPath, payload)
	put(t, sqlPath, migration)
	put(t, snapshotPath+".sha256", checksumDocument(
		checksumEntry(migrationPath, migration),
		checksumEntry(snapshotPath, payload),
	))
	return root, migrationPath, snapshotPath, sqlPath
}

func rewriteRegistryChecksum(t *testing.T, migrationPath, snapshotPath string) {
	t.Helper()
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	put(t, snapshotPath+".sha256", checksumDocument(
		checksumEntry(migrationPath, migration),
		checksumEntry(snapshotPath, snapshot),
	))
}

func TestCheckOutputsRejectsEveryMutableProjectionBoundary(t *testing.T) {
	t.Run("checksum", func(t *testing.T) {
		root, _, snapshotPath, _ := validRegistryRoot(t)
		if err := os.Remove(snapshotPath + ".sha256"); err != nil {
			t.Fatal(err)
		}
		if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("missing checksum error=%v", err)
		}
	})
	t.Run("snapshot", func(t *testing.T) {
		root, migrationPath, snapshotPath, _ := validRegistryRoot(t)
		put(t, snapshotPath, []byte("{}\n"))
		rewriteRegistryChecksum(t, migrationPath, snapshotPath)
		if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), "E_FEATURE_REGISTRY_DRIFT") {
			t.Fatalf("snapshot drift error=%v", err)
		}
	})
	t.Run("generated sql", func(t *testing.T) {
		root, _, _, sqlPath := validRegistryRoot(t)
		put(t, sqlPath, []byte("-- stale\n"))
		if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), "E_FEATURE_REGISTRY_DRIFT") {
			t.Fatalf("SQL drift error=%v", err)
		}
	})
	t.Run("migration digest", func(t *testing.T) {
		root, migrationPath, snapshotPath, _ := validRegistryRoot(t)
		body, err := os.ReadFile(migrationPath)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.Replace(body, []byte(toggle.RegistryDigest()), []byte(strings.Repeat("0", 64)), 1)
		put(t, migrationPath, body)
		rewriteRegistryChecksum(t, migrationPath, snapshotPath)
		if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("migration digest error=%v", err)
		}
	})
	t.Run("migration key", func(t *testing.T) {
		root, migrationPath, snapshotPath, _ := validRegistryRoot(t)
		body, err := os.ReadFile(migrationPath)
		if err != nil {
			t.Fatal(err)
		}
		key := string(toggle.Definitions()[0].Key)
		body = bytes.Replace(body, []byte("    '"+key+"',\n"), nil, 1)
		put(t, migrationPath, body)
		rewriteRegistryChecksum(t, migrationPath, snapshotPath)
		if err := checkOutputs(root); err == nil || !strings.Contains(err.Error(), key) {
			t.Fatalf("migration key error=%v", err)
		}
	})
}

func TestGeneratorFilesystemFailureBoundaries(t *testing.T) {
	badPatternRoot := filepath.Join(t.TempDir(), "[")
	if _, err := registryVersions(badPatternRoot); err == nil {
		t.Fatal("registryVersions accepted a malformed glob root")
	}
	if _, err := nextMigrationVersion(badPatternRoot); err == nil {
		t.Fatal("nextMigrationVersion accepted a malformed glob root")
	}
	if err := checkOutputs(badPatternRoot); err == nil {
		t.Fatal("checkOutputs hid registry glob failure")
	}

	t.Run("freeze stat", func(t *testing.T) {
		root := t.TempDir()
		snapshotPath, _ := paths(root, initialVersion)
		if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(snapshotPath), snapshotPath); err != nil {
			t.Fatal(err)
		}
		if err := writeFrozen(root); err == nil {
			t.Fatal("freeze accepted an unreadable existing artifact")
		}
	})
	t.Run("freeze snapshot write", func(t *testing.T) {
		root := t.TempDir()
		put(t, registryMigrationPath(root, initialVersion), []byte("-- v183\n"))
		if err := writeFrozen(root); err == nil {
			t.Fatal("freeze hid missing snapshot directory")
		}
	})
	t.Run("freeze sql write", func(t *testing.T) {
		root := t.TempDir()
		put(t, registryMigrationPath(root, initialVersion), []byte("-- v183\n"))
		snapshotPath, _ := paths(root, initialVersion)
		if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeFrozen(root); err == nil {
			t.Fatal("freeze hid missing SQL directory")
		}
	})
	t.Run("next existing", func(t *testing.T) {
		root := t.TempDir()
		put(t, registryMigrationPath(root, initialVersion), []byte("-- v183\n"))
		snapshotPath, _ := paths(root, "V184")
		put(t, snapshotPath, []byte("existing"))
		if err := writeNext(root, "V184"); err == nil || !strings.Contains(err.Error(), "overwrite") {
			t.Fatalf("existing next artifact error=%v", err)
		}
	})
	t.Run("next snapshot write", func(t *testing.T) {
		root := t.TempDir()
		put(t, registryMigrationPath(root, initialVersion), []byte("-- v183\n"))
		if err := writeNext(root, "V184"); err == nil {
			t.Fatal("next write hid missing snapshot directory")
		}
	})
	t.Run("next current sql write", func(t *testing.T) {
		root := t.TempDir()
		put(t, registryMigrationPath(root, initialVersion), []byte("-- v183\n"))
		snapshotPath, _ := paths(root, "V184")
		if err := os.MkdirAll(filepath.Dir(snapshotPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeNext(root, "V184"); err == nil {
			t.Fatal("next write hid missing current SQL directory")
		}
	})

	migration := filepath.Join(t.TempDir(), "migration.sql")
	snapshot := filepath.Join(filepath.Dir(migration), "snapshot.json")
	put(t, migration, []byte("migration"))
	put(t, snapshot, []byte("snapshot"))
	if err := verifyChecksums(migration, snapshot, filepath.Join(filepath.Dir(migration), "missing")); err == nil {
		t.Fatal("missing checksum document accepted")
	}
	checksum := filepath.Join(filepath.Dir(migration), "checksums")
	put(t, checksum, []byte("placeholder"))
	if err := verifyChecksums(filepath.Join(filepath.Dir(migration), "missing-migration"), snapshot, checksum); err == nil {
		t.Fatal("missing migration accepted")
	}
	if err := verifyChecksums(migration, filepath.Join(filepath.Dir(migration), "missing-snapshot"), checksum); err == nil {
		t.Fatal("missing snapshot accepted")
	}
}

func TestRunReportsMissingRepositoryRoot(t *testing.T) {
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(original) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--check"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "repository root") {
		t.Fatalf("missing repository root error=%v", err)
	}
}

func marshalSnapshotValue(value snapshot) ([]byte, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}
