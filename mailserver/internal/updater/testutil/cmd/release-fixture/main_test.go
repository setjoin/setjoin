package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"setjoin.com/shared/release"
)

func writeFixtureSource(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"mailserverd", "authserverd", "mailctl", "setjoin-gateway"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture-"+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "webmail"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "webmail", "index.html"), []byte("fixture-webmail"), 0o600); err != nil {
		t.Fatal(err)
	}
	guide := filepath.Join(t.TempDir(), "UPGRADE_RECOVERY.md")
	if err := os.WriteFile(guide, []byte("fixture recovery guide"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, guide
}

func TestCreateFixtureBuildsDigestBoundCohortAndRollbackBinary(t *testing.T) {
	source, guide := writeFixtureSource(t)
	store := filepath.Join(t.TempDir(), "releases")
	if err := os.Mkdir(store, 0o750); err != nil {
		t.Fatal(err)
	}
	digest, err := createFixture(source, store, guide, "fixture-success", "9.4.0", 179, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(store, "fixture-success", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(canonical)
	if digest != hex.EncodeToString(want[:]) || manifest.ReleaseID != "fixture-success" ||
		manifest.SchemaFrom != 179 || manifest.SchemaTo != 179 || len(manifest.Artifacts) != 8 {
		t.Fatalf("digest=%s manifest=%#v", digest, manifest)
	}
	if _, err := createFixture(source, store, guide, "fixture-success", "9.4.0", 179, false); err == nil {
		t.Fatal("existing fixture release was overwritten")
	}
	if _, err := createFixture(source, store, guide, "fixture-rollback", "9.4.1", 179, true); err != nil {
		t.Fatal(err)
	}
	broken, err := os.ReadFile(filepath.Join(store, "fixture-rollback", "mailserverd"))
	if err != nil || string(broken) != "#!/bin/sh\nexit 42\n" {
		t.Fatalf("broken fixture=%q err=%v", broken, err)
	}
}
