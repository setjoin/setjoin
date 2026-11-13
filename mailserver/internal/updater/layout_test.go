package updater

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func flatFixture(t *testing.T) AdoptionOptions {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "setjoin")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"mailserverd": "gateway", "authserverd": "auth", "mailctl": "cli", "setjoin-gateway": "rust"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "webmail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "webmail", "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(base, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(configDir, "config.env")
	if err := os.WriteFile(config, []byte("SECRET=never-copied\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := AdoptionOptions{InstallRoot: root, ConfigPath: config, QuarantineDir: filepath.Join(base, "quarantine"), SchemaVersion: 178}
	t.Cleanup(func() { makeWritableForCleanup(root) })
	return options
}

func TestAdoptCurrentLayoutIsCompleteIdempotentAndSecretFree(t *testing.T) {
	options := flatFixture(t)
	if err := os.WriteFile(filepath.Join(options.InstallRoot, "mailserverd.prev"), []byte("not-a-cohort"), 0o755); err != nil {
		t.Fatal(err)
	}
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	current, err := activeReleaseID(options.InstallRoot, "current")
	if err != nil || current != evidence.ReleaseID {
		t.Fatalf("current=%q err=%v evidence=%q", current, err, evidence.ReleaseID)
	}
	if _, err := os.Lstat(filepath.Join(options.InstallRoot, "previous")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("adoption invented a previous release: %v", err)
	}
	if _, err := os.Stat(filepath.Join(options.QuarantineDir, "mailserverd.prev")); err != nil {
		t.Fatalf("legacy prev was not quarantined: %v", err)
	}
	if _, err := os.Stat(filepath.Join(options.InstallRoot, "mailserverd.prev")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy prev remains executable: %v", err)
	}
	releaseDir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
	raw, err := os.ReadFile(filepath.Join(releaseDir, "adoption.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || containsBytes(raw, []byte("never-copied")) {
		t.Fatal("adoption evidence is empty or copied a configuration secret")
	}
	again, err := AdoptCurrentLayout(options)
	if err != nil || again.ReleaseID != evidence.ReleaseID {
		t.Fatalf("idempotent adoption=%#v err=%v", again, err)
	}
}

// #264: the flat cohort's Rust front door is adopted with the Go binaries,
// its legacy *.prev is quarantined like theirs, and a release adopted before
// the gateway existed still validates as a rollback target.
func TestAdoptionCarriesTheRustGatewayAndKeepsPreGatewayRollback(t *testing.T) {
	options := flatFixture(t)
	if err := os.WriteFile(filepath.Join(options.InstallRoot, "setjoin-gateway.prev"), []byte("old rust"), 0o755); err != nil {
		t.Fatal(err)
	}
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Artifacts["setjoin-gateway"] == "" {
		t.Fatalf("adoption evidence lacks the gateway: %#v", evidence.Artifacts)
	}
	releaseDir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
	if raw, err := os.ReadFile(filepath.Join(releaseDir, "setjoin-gateway")); err != nil || string(raw) != "rust" {
		t.Fatalf("adopted gateway=%q err=%v", raw, err)
	}
	if err := validateManagedReleaseDir(releaseDir, evidence.ReleaseID); err != nil {
		t.Fatalf("adopted gateway cohort invalid: %v", err)
	}
	if _, err := os.Stat(filepath.Join(options.QuarantineDir, "setjoin-gateway.prev")); err != nil {
		t.Fatalf("legacy gateway prev was not quarantined: %v", err)
	}

	legacy := flatFixture(t)
	if err := os.Remove(filepath.Join(legacy.InstallRoot, "setjoin-gateway")); err != nil {
		t.Fatal(err)
	}
	old, err := AdoptCurrentLayout(legacy)
	if err != nil {
		t.Fatalf("pre-gateway flat cohort: %v", err)
	}
	if err := validateManagedReleaseDir(filepath.Join(legacy.InstallRoot, "releases", old.ReleaseID), old.ReleaseID); err != nil {
		t.Fatalf("pre-gateway adopted release is no longer a rollback target: %v", err)
	}
}

func TestAdoptCurrentLayoutRecoversAtEveryDurableBoundary(t *testing.T) {
	boundaries := []string{"copied_mailserverd", "copied_authserverd", "copied_mailctl", "copied_webmail", "staging_synced", "release_committed", "current_switched"}
	for _, boundary := range boundaries {
		t.Run(boundary, func(t *testing.T) {
			options := flatFixture(t)
			interrupted := errors.New("interrupted")
			options.Boundary = func(name string) error {
				if name == boundary {
					return interrupted
				}
				return nil
			}
			if _, err := AdoptCurrentLayout(options); !errors.Is(err, interrupted) {
				t.Fatalf("first adoption error=%v", err)
			}
			options.Boundary = nil
			evidence, err := AdoptCurrentLayout(options)
			if err != nil {
				t.Fatalf("resume: %v", err)
			}
			current, err := activeReleaseID(options.InstallRoot, "current")
			if err != nil || current != evidence.ReleaseID {
				t.Fatalf("current=%q err=%v", current, err)
			}
		})
	}
}

func TestAdoptCurrentLayoutRejectsPartialOrIndirectCohort(t *testing.T) {
	t.Run("missing webmail", func(t *testing.T) {
		options := flatFixture(t)
		if err := os.RemoveAll(filepath.Join(options.InstallRoot, "webmail")); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); !errors.Is(err, ErrLayoutIncomplete) {
			t.Fatalf("partial cohort error=%v", err)
		}
	})
	t.Run("symlink binary", func(t *testing.T) {
		options := flatFixture(t)
		if err := os.Remove(filepath.Join(options.InstallRoot, "mailserverd")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/bin/true", filepath.Join(options.InstallRoot, "mailserverd")); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); !errors.Is(err, ErrLayoutIncomplete) {
			t.Fatalf("symlink cohort error=%v", err)
		}
	})
}

func TestActivateReleaseAndPreviousAreIdentityBoundAndReplaySafe(t *testing.T) {
	options := flatFixture(t)
	adopted, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	newID := "release-new"
	newDir := filepath.Join(options.InstallRoot, "releases", newID)
	if err := os.Mkdir(newDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mailserverd", "authserverd", "mailctl"} {
		if err := os.WriteFile(filepath.Join(newDir, name), []byte(name), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(newDir, "webmail"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "webmail", "index.html"), []byte("new"), 0o444); err != nil {
		t.Fatal(err)
	}
	evidence := AdoptionEvidence{SchemaVersion: 1, ReleaseID: newID, DatabaseSchema: 178,
		ConfigSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Artifacts:    map[string]string{}}
	for _, name := range []string{"authserverd", "mailctl", "mailserverd"} {
		evidence.Artifacts[name], err = digestPrivateRegular(filepath.Join(newDir, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	evidence.Artifacts["webmail"], err = digestPrivateTree(filepath.Join(newDir, "webmail"))
	if err != nil {
		t.Fatal(err)
	}
	evidenceRaw, _ := json.Marshal(evidence)
	if err := os.WriteFile(filepath.Join(newDir, "adoption.json"), evidenceRaw, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := makeTreeImmutable(newDir); err != nil {
		t.Fatal(err)
	}
	if err := ActivateRelease(options.InstallRoot, newID); err != nil {
		t.Fatal(err)
	}
	current, _ := activeReleaseID(options.InstallRoot, "current")
	previous, _ := activeReleaseID(options.InstallRoot, "previous")
	if current != newID || previous != adopted.ReleaseID {
		t.Fatalf("current=%q previous=%q", current, previous)
	}
	if err := ActivateRelease(options.InstallRoot, newID); err != nil {
		t.Fatalf("activation replay: %v", err)
	}
	if err := ActivatePrevious(options.InstallRoot, newID); err != nil {
		t.Fatal(err)
	}
	current, _ = activeReleaseID(options.InstallRoot, "current")
	previous, _ = activeReleaseID(options.InstallRoot, "previous")
	if current != adopted.ReleaseID || previous != newID {
		t.Fatalf("rolled back current=%q previous=%q", current, previous)
	}
	if err := ActivatePrevious(options.InstallRoot, newID); err != nil {
		t.Fatalf("completed rollback replay: %v", err)
	}
	// Model the crash boundary after current changed but before previous was
	// updated: make previous equal current, then replay with the journal ID.
	if err := switchRelativeSymlink(options.InstallRoot, "previous", filepath.Join("releases", adopted.ReleaseID)); err != nil {
		t.Fatal(err)
	}
	if err := ActivatePrevious(options.InstallRoot, newID); err != nil {
		t.Fatalf("rollback replay: %v", err)
	}
	previous, _ = activeReleaseID(options.InstallRoot, "previous")
	if previous != newID {
		t.Fatalf("rollback replay previous=%q", previous)
	}
}

func TestActivateReleaseRejectsCorruptedAdoptedCohort(t *testing.T) {
	options := flatFixture(t)
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	releaseDir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
	path := filepath.Join(releaseDir, "mailserverd")
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := validateManagedReleaseDir(releaseDir, evidence.ReleaseID); err == nil || !strings.Contains(err.Error(), "content differs") {
		t.Fatalf("corrupt adopted cohort error=%v", err)
	}
}

func TestAdoptionRejectsInvalidPathsSchemaAndCurrentPointers(t *testing.T) {
	if _, err := AdoptCurrentLayout(AdoptionOptions{InstallRoot: "relative", ConfigPath: "/tmp/config", QuarantineDir: "/tmp/q", SchemaVersion: 1}); err == nil {
		t.Fatal("relative adoption root accepted")
	}
	options := flatFixture(t)
	options.SchemaVersion = 0
	if _, err := AdoptCurrentLayout(options); err == nil {
		t.Fatal("zero schema accepted")
	}
	options = flatFixture(t)
	if err := os.Symlink("/tmp", filepath.Join(options.InstallRoot, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := AdoptCurrentLayout(options); err == nil {
		t.Fatal("unsafe current pointer accepted")
	}
	options = flatFixture(t)
	if err := os.Chmod(options.InstallRoot, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := AdoptCurrentLayout(options); err == nil {
		t.Fatal("mutable install root accepted")
	}
}

func TestLayoutDigestAndCopyHelpersRejectUnsafeTrees(t *testing.T) {
	base := t.TempDir()
	if _, err := digestPrivateRegular(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing regular file accepted")
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateRegular(file); err == nil {
		t.Fatal("mutable regular file accepted")
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateRegular(link); err == nil {
		t.Fatal("symlink regular file accepted")
	}
	hardlink := filepath.Join(base, "hardlink")
	if err := os.Link(file, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateRegular(file); err == nil {
		t.Fatal("hardlinked regular file accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(base, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateTree(empty); err == nil {
		t.Fatal("empty tree accepted")
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateTree(loose); err == nil {
		t.Fatal("mutable tree accepted")
	}
	tree := filepath.Join(base, "tree")
	if err := os.Mkdir(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(tree, "entry")); err != nil {
		t.Fatal(err)
	}
	if _, err := digestPrivateTree(tree); err == nil {
		t.Fatal("tree symlink accepted")
	}
	if _, err := digestPrivateTreeExcept(tree, "entry"); err == nil {
		t.Fatal("symlink excluded evidence accepted")
	}
	if err := copyLegacyTree(tree, filepath.Join(base, "copy")); err == nil {
		t.Fatal("unsafe legacy tree copied")
	}
}

func TestLayoutSymlinkActivationAndRollbackErrorBoundaries(t *testing.T) {
	base := t.TempDir()
	for _, target := range []string{"/absolute", "other/release", "releases/../escape"} {
		if err := switchRelativeSymlink(base, "current", target); err == nil {
			t.Fatalf("target %q accepted", target)
		}
	}
	if err := ActivateRelease("relative", "release"); err == nil {
		t.Fatal("relative activation accepted")
	}
	if err := ActivateRelease(base, "/release"); err == nil {
		t.Fatal("invalid release id accepted")
	}
	if err := ActivatePrevious("relative", "release"); err == nil {
		t.Fatal("relative rollback accepted")
	}
	if err := ActivatePrevious(base, "/release"); err == nil {
		t.Fatal("invalid rollback id accepted")
	}
	if err := os.Symlink("/tmp", filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := activeReleaseID(base, "current"); err == nil {
		t.Fatal("absolute active release accepted")
	}
	if err := os.Remove(filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", "missing"), filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := activeReleaseID(base, "current"); err == nil {
		t.Fatal("missing active release accepted")
	}

	options := flatFixture(t)
	adopted, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := ActivatePrevious(options.InstallRoot, adopted.ReleaseID); err == nil {
		t.Fatal("rollback without previous accepted")
	}
}

func TestAdoptionEvidenceRejectsEveryMalformedDocumentShape(t *testing.T) {
	options := flatFixture(t)
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
	path := filepath.Join(dir, "adoption.json")
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"malformed": []byte(`{`),
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"unknown":   bytes.Replace(valid, []byte(`"schema_version": 1`), []byte(`"schema_version": 1,"unknown":true`), 1),
		"schema":    bytes.Replace(valid, []byte(`"schema_version": 1`), []byte(`"schema_version": 2`), 1),
		"database":  bytes.Replace(valid, []byte(`"database_schema": 178`), []byte(`"database_schema": 0`), 1),
		"release":   bytes.Replace(valid, []byte(`"release_id": "`+evidence.ReleaseID+`"`), []byte(`"release_id": "/"`), 1),
		"config":    bytes.Replace(valid, []byte(`"config_sha256": "`+evidence.ConfigSHA256+`"`), []byte(`"config_sha256": "bad"`), 1),
		"artifacts": bytes.Replace(valid, []byte(`"authserverd": "`+evidence.Artifacts["authserverd"]+`"`), []byte(`"authserverd": "bad"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := readAdoptionEvidence(dir); err == nil {
				t.Fatal("invalid adoption evidence accepted")
			}
		})
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, valid, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra")
	if err := os.WriteFile(extra, []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := verifyAdoptionArtifacts(dir, evidence); err == nil {
		t.Fatal("extra adopted artifact accepted")
	}
}

func TestCurrentManagedManifestCanBeReAdoptedWithoutCopyingSecrets(t *testing.T) {
	options := flatFixture(t)
	if _, err := AdoptCurrentLayout(options); err != nil {
		t.Fatal(err)
	}
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"})
	storeRoot, releaseID, digest, manifest := writeStageFixture(t, archive)
	store, err := OpenReleaseStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRelease(context.Background(), options.InstallRoot, releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := ActivateRelease(options.InstallRoot, releaseID); err != nil {
		t.Fatal(err)
	}
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.ReleaseID != releaseID || evidence.DatabaseSchema != manifest.SchemaTo || evidence.ConfigSHA256 == "" {
		t.Fatalf("evidence=%#v", evidence)
	}
}

func TestLegacyQuarantineRefusesCollisionAndReportsBoundary(t *testing.T) {
	options := flatFixture(t)
	if err := os.WriteFile(filepath.Join(options.InstallRoot, "mailserverd.prev"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(options.QuarantineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.QuarantineDir, "mailserverd.prev"), []byte("collision"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := quarantineLegacyPrevious(options); err == nil {
		t.Fatal("quarantine collision accepted")
	}
	if err := os.Remove(filepath.Join(options.QuarantineDir, "mailserverd.prev")); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("boundary")
	options.Boundary = func(name string) error {
		if name == "quarantined_mailserverd.prev" {
			return injected
		}
		return nil
	}
	if err := quarantineLegacyPrevious(options); !errors.Is(err, injected) {
		t.Fatalf("boundary error=%v", err)
	}
}

func TestAdoptionExistingCurrentAndFlatEvidenceFailuresAreClosed(t *testing.T) {
	t.Run("current evidence corrupt", func(t *testing.T) {
		options := flatFixture(t)
		evidence, err := AdoptCurrentLayout(options)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID, "adoption.json")
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{"), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); err == nil {
			t.Fatal("corrupt current adoption evidence was accepted")
		}
	})
	t.Run("current quarantine collision", func(t *testing.T) {
		options := flatFixture(t)
		if _, err := AdoptCurrentLayout(options); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(options.InstallRoot, "mailserverd.prev"), []byte("old"), 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(options.QuarantineDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(options.QuarantineDir, "mailserverd.prev"), []byte("collision"), 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); err == nil {
			t.Fatal("current adoption ignored quarantine collision")
		}
	})
	t.Run("config missing", func(t *testing.T) {
		options := flatFixture(t)
		if err := os.Remove(options.ConfigPath); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); !errors.Is(err, ErrLayoutIncomplete) {
			t.Fatalf("missing config error=%v", err)
		}
	})
	t.Run("existing adopted release differs", func(t *testing.T) {
		options := flatFixture(t)
		evidence, err := AdoptCurrentLayout(options)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(options.InstallRoot, "current")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID, "adoption.json")
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte(evidence.ConfigSHA256), []byte(strings.Repeat("b", 64)), 1)
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := AdoptCurrentLayout(options); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("existing release error=%v", err)
		}
	})
}

func TestManagedReleaseValidationRejectsEveryAuthorityBoundary(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, string){
		"mutable directory": func(t *testing.T, dir, _ string) {
			t.Helper()
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"missing core": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			if err := os.Remove(filepath.Join(dir, "mailctl")); err != nil {
				t.Fatal(err)
			}
		},
		"indirect core": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			path := filepath.Join(dir, "mailctl")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("mailserverd", path); err != nil {
				t.Fatal(err)
			}
		},
		"missing manifest": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			if err := os.Remove(filepath.Join(dir, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		},
		"malformed manifest": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			path := filepath.Join(dir, "manifest.json")
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("{"), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"manifest identity": func(t *testing.T, dir, releaseID string) {
			t.Helper()
			makeWritableForCleanup(dir)
			path := filepath.Join(dir, "manifest.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.Replace(raw, []byte(`"release_id":"`+releaseID+`"`), []byte(`"release_id":"other-release"`), 1)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"manifest digest": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			path := filepath.Join(dir, "manifest.digest")
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Repeat("0", 64)+"\n"), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"installed evidence": func(t *testing.T, dir, _ string) {
			t.Helper()
			makeWritableForCleanup(dir)
			if err := os.Remove(filepath.Join(dir, installedEvidenceName)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			options, _, _, failed := recoveryFixture(t)
			dir := filepath.Join(options.InstallRoot, "releases", failed)
			mutate(t, dir, failed)
			if err := validateManagedReleaseDir(dir, failed); err == nil {
				t.Fatal("invalid managed release was accepted")
			}
		})
	}
	if err := validateManagedReleaseDir(filepath.Join(t.TempDir(), "missing"), "missing"); err == nil {
		t.Fatal("missing managed release was accepted")
	}
}

func TestAdoptedReleaseIdentityInventoryAndWebmailAreVerified(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		options := flatFixture(t)
		evidence, err := AdoptCurrentLayout(options)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
		if err := validateManagedReleaseDir(dir, "different-release"); err == nil || !strings.Contains(err.Error(), "release ID differs") {
			t.Fatalf("identity error=%v", err)
		}
	})
	t.Run("same count undeclared entry", func(t *testing.T) {
		options := flatFixture(t)
		evidence, err := AdoptCurrentLayout(options)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
		makeWritableForCleanup(dir)
		if err := os.Rename(filepath.Join(dir, "mailctl"), filepath.Join(dir, "unexpected")); err != nil {
			t.Fatal(err)
		}
		if err := verifyAdoptionArtifacts(dir, evidence); err == nil || !strings.Contains(err.Error(), "undeclared") {
			t.Fatalf("inventory error=%v", err)
		}
	})
	t.Run("webmail content", func(t *testing.T) {
		options := flatFixture(t)
		evidence, err := AdoptCurrentLayout(options)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(options.InstallRoot, "releases", evidence.ReleaseID)
		makeWritableForCleanup(dir)
		path := filepath.Join(dir, "webmail", "index.html")
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("changed"), 0o400); err != nil {
			t.Fatal(err)
		}
		if err := verifyAdoptionArtifacts(dir, evidence); err == nil || !strings.Contains(err.Error(), "webmail content") {
			t.Fatalf("webmail error=%v", err)
		}
	})
}

func TestLayoutActivationRejectsPointerAndRollbackDivergence(t *testing.T) {
	if err := switchRelativeSymlink(filepath.Join(t.TempDir(), "missing"), "current", filepath.Join("releases", "release")); err == nil {
		t.Fatal("symlink in missing root succeeded")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "current"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current", "entry"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := switchRelativeSymlink(root, "current", filepath.Join("releases", "release")); err == nil {
		t.Fatal("symlink replaced non-empty directory")
	}

	options := flatFixture(t)
	evidence, err := AdoptCurrentLayout(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(options.InstallRoot, "current")); err != nil {
		t.Fatal(err)
	}
	if err := ActivatePrevious(options.InstallRoot, evidence.ReleaseID); err == nil {
		t.Fatal("rollback without current pointer succeeded")
	}
	if err := switchRelativeSymlink(options.InstallRoot, "current", filepath.Join("releases", evidence.ReleaseID)); err != nil {
		t.Fatal(err)
	}
	if err := switchRelativeSymlink(options.InstallRoot, "previous", filepath.Join("releases", evidence.ReleaseID)); err != nil {
		t.Fatal(err)
	}
	if err := ActivatePrevious(options.InstallRoot, evidence.ReleaseID); err == nil || !strings.Contains(err.Error(), "equals failed") {
		t.Fatalf("same previous error=%v", err)
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
