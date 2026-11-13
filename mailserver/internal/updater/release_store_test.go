package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

// pinTreeMode makes fixture directories umask-independent: t.TempDir and
// os.Mkdir both inherit the process umask (e.g. 002 on CI runners, yielding
// 0775), and the release-store guards correctly refuse group/world-writable
// trees, so pin store roots and release trees to 0755 explicitly.
func pinTreeMode(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseStoreBindsExactImmutableTree(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	pinTreeMode(t, root)
	releaseDir := filepath.Join(root, "release-1")
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinTreeMode(t, releaseDir)
	manifest := minimalManifest()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), data, 0o444); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.VerifyTree("release-1", hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleaseID != "release-1" {
		t.Fatalf("got release %q", got.ReleaseID)
	}
	manifest.Signatures[0].Value = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	rotated, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(releaseDir, "manifest.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), rotated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTree("release-1", hex.EncodeToString(digest[:])); err != nil {
		t.Fatalf("signature-only rotation changed canonical payload binding: %v", err)
	}
	if _, err := store.VerifyTree("release-1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("wrong digest: %v", err)
	}
}

func TestReleaseStoreRejectsMissingSymlinkAndWritableTree(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	pinTreeMode(t, root)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTree("missing", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("missing tree: %v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTree("linked", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("symlink tree: %v", err)
	}
	writable := filepath.Join(root, "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTree("writable", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("writable tree: %v", err)
	}
}

func TestReleaseStoreCanPinTrustedOwner(t *testing.T) {
	root := t.TempDir()
	pinTreeMode(t, root)
	store, err := OpenReleaseStoreOwnedBy(root, uint32(os.Getuid()))
	if err != nil || store.requiredUID == nil {
		t.Fatalf("owner-pinned store=%#v err=%v", store, err)
	}
	if _, err := OpenReleaseStoreOwnedBy(root, uint32(os.Getuid()+1)); err == nil {
		t.Fatal("release store accepted a different required owner")
	}
}

func TestOpenReleaseStoreRejectsUnsafeRoots(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	linked := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(target, linked); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(t.TempDir(), "writable")
	if err := os.Mkdir(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]string{
		"empty": "", "relative": "relative", "missing": missing,
		"file": file, "symlink": linked, "writable": writable,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenReleaseStore(root); err == nil {
				t.Fatal("unsafe release store root was accepted")
			}
		})
	}
}

func TestReleaseStoreRejectsInvalidIdentityAndManifestBoundaries(t *testing.T) {
	root := t.TempDir()
	pinTreeMode(t, root)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []struct{ name, releaseID, digest string }{
		{"bad release", "../escape", strings.Repeat("a", 64)},
		{"bad digest", "release-1", "bad"},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			if _, err := store.VerifyTree(candidate.releaseID, candidate.digest); err == nil {
				t.Fatal("invalid release identity was accepted")
			}
		})
	}

	for name, prepare := range map[string]func(*testing.T, string){
		"release is file": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(dir, []byte("file"), 0o444); err != nil {
				t.Fatal(err)
			}
		},
		"missing manifest": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
		},
		"manifest symlink": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), filepath.Join(dir, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		},
		"manifest writable": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o666); err != nil {
				t.Fatal(err)
			}
		},
		"manifest hardlink": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
			source := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(source, []byte("{}"), 0o444); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(source, filepath.Join(dir, "manifest.json")); err != nil {
				t.Fatal(err)
			}
		},
		"manifest oversized": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
			path := filepath.Join(dir, "manifest.json")
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(path, release.MaxDocumentBytes+1); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o444); err != nil {
				t.Fatal(err)
			}
		},
		"manifest malformed": func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			pinTreeMode(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{\"unknown\":true}"), 0o444); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, strings.ReplaceAll(name, " ", "-"))
			prepare(t, dir)
			if _, err := store.VerifyTree(filepath.Base(dir), strings.Repeat("a", 64)); !errors.Is(err, ErrReleaseUnavailable) {
				t.Fatalf("manifest boundary error=%v", err)
			}
		})
	}
}

func TestReleaseStoreRejectsManifestIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	pinTreeMode(t, root)
	releaseDir := filepath.Join(root, "release-2")
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinTreeMode(t, releaseDir)
	manifest := minimalManifest()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), data, 0o444); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyTree("release-2", hex.EncodeToString(digest[:])); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("release ID mismatch error=%v", err)
	}
}

// writeManifestFixture materializes a manifest into a fresh release tree and
// returns an opened store plus the canonical digest to present.
func writeManifestFixture(t *testing.T, root, releaseID string, mutate func(m *release.Manifest)) (store *ReleaseStore, digestHex string) {
	t.Helper()
	pinTreeMode(t, root)
	releaseDir := filepath.Join(root, releaseID)
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinTreeMode(t, releaseDir)
	manifest := minimalManifest()
	manifest.ReleaseID = releaseID
	if mutate != nil {
		mutate(manifest)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), data, 0o444); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	store, err = OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return store, hex.EncodeToString(digest[:])
}

// TestReleaseStoreRejectsExpiredAndEarlyManifests proves UPDATER-002's fix:
// VerifyTree re-checks the signed freshness commitment against the wall clock
// on every use, so an expired or not-yet-valid manifest is refused even with a
// perfectly matching catalog digest.
func TestReleaseStoreRejectsExpiredAndEarlyManifests(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()

	t.Run("expired manifest rejected", func(t *testing.T) {
		root := t.TempDir()
		store, digest := writeManifestFixture(t, root, "release-exp",
			func(m *release.Manifest) {
				m.PublishedAt = now.Add(-72 * time.Hour).Format(time.RFC3339)
				m.ExpiresAt = now.Add(-time.Hour).Format(time.RFC3339)
			})
		if _, err := store.VerifyTree("release-exp", digest); !errors.Is(err, ErrReleaseUnavailable) {
			t.Fatalf("expired manifest accepted: %v", err)
		} else if !strings.Contains(err.Error(), "expired") {
			t.Fatalf("expired rejection mislabeled: %v", err)
		}
	})

	t.Run("not-yet-valid manifest rejected", func(t *testing.T) {
		root := t.TempDir()
		store, digest := writeManifestFixture(t, root, "release-early",
			func(m *release.Manifest) {
				m.PublishedAt = now.Add(time.Hour).Format(time.RFC3339)
				m.ExpiresAt = now.Add(49 * time.Hour).Format(time.RFC3339)
			})
		if _, err := store.VerifyTree("release-early", digest); !errors.Is(err, ErrReleaseUnavailable) {
			t.Fatalf("not-yet-valid manifest accepted: %v", err)
		}
	})

	t.Run("fresh manifest still accepted", func(t *testing.T) {
		root := t.TempDir()
		store, digest := writeManifestFixture(t, root, "release-fresh", nil)
		got, err := store.VerifyTree("release-fresh", digest)
		if err != nil {
			t.Fatalf("fresh manifest rejected: %v", err)
		}
		if got.ReleaseID != "release-fresh" {
			t.Fatalf("got release %q", got.ReleaseID)
		}
	})
}

func TestReleaseStoreOwnerAndManifestOpenFailuresAreClosed(t *testing.T) {
	if _, err := OpenReleaseStoreOwnedBy("relative", uint32(os.Getuid())); err == nil {
		t.Fatal("relative owner-pinned store accepted")
	}
	makeStore := func(t *testing.T) (*ReleaseStore, string, string) {
		t.Helper()
		root := t.TempDir()
		pinTreeMode(t, root)
		releaseID := "release-1"
		dir := filepath.Join(root, releaseID)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		pinTreeMode(t, dir)
		manifest := minimalManifest()
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o444); err != nil {
			t.Fatal(err)
		}
		canonical, err := release.CanonicalManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		store, err := OpenReleaseStore(root)
		if err != nil {
			t.Fatal(err)
		}
		return store, releaseID, hex.EncodeToString(sum[:])
	}
	t.Run("release owner", func(t *testing.T) {
		store, releaseID, digest := makeStore(t)
		wrong := uint32(os.Getuid() + 1)
		store.requiredUID = &wrong
		if _, err := store.VerifyTree(releaseID, digest); !errors.Is(err, ErrReleaseUnavailable) || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("owner error=%v", err)
		}
	})
	t.Run("manifest unreadable", func(t *testing.T) {
		store, releaseID, digest := makeStore(t)
		path := filepath.Join(store.root, releaseID, "manifest.json")
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := store.VerifyTree(releaseID, digest); !errors.Is(err, ErrReleaseUnavailable) {
			t.Fatalf("unreadable manifest error=%v", err)
		}
	})
}

func minimalManifest() *release.Manifest {
	// Freshness dates are relative to the wall clock: VerifyTree re-checks the
	// signed expiry on every use, so a hard-coded fixture silently ages into
	// the rejected-expired class.
	now := time.Now().UTC()
	return &release.Manifest{
		SchemaVersion: 1, ReleaseID: "release-1", Version: "1.2.4",
		Channel: release.ChannelCommunity, PublishedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339), MetadataVersion: 1,
		PreviousVersionFloor: "1.2.3", Platforms: []string{"linux"},
		Architectures: []string{"amd64"},
		Compatibility: release.Compatibility{SourceVersionRange: ">=1.2.3 <1.2.5", PostgresRange: ">=16.0.0 <19.0.0"},
		SchemaFrom:    178, SchemaTo: 178,
		Artifacts: []release.Artifact{
			artifact("authserverd", release.ArtifactAuthserver, release.TargetAuthserver, "core"),
			artifact("mailctl", release.ArtifactMailctl, release.TargetMailctl, "core"),
			artifact("mailserverd", release.ArtifactMailserver, release.TargetMailserver, "core"),
			artifact("provenance", release.ArtifactProvenance, release.TargetProvenance, "evidence"),
			artifact("recovery-guide", release.ArtifactRecoveryGuide, release.TargetRecoveryGuide, "evidence"),
			artifact("sbom", release.ArtifactSBOM, release.TargetSBOM, "evidence"),
			artifact("setjoin-gateway", release.ArtifactGateway, release.TargetGateway, "core"),
			artifact("webmail", release.ArtifactWebmail, release.TargetWebmail, "core"),
		},
		HealthGates: release.HealthGates{Preflight: []string{"disk"}, Readiness: []string{"gateway"}, Data: []string{"mail"}, PostCommit: []string{"audit"}},
		Recovery:    release.RecoveryRequirements{MaximumAgeSeconds: 3600, MinimumFreeBytes: 1},
		Notes:       release.ReleaseNotes{Summary: "test", SupportChannel: "community"},
		Signing:     release.SigningPolicy{Threshold: 1},
		Signatures:  []release.Signature{{KeyID: "vendor", Algorithm: "ed25519", Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}},
	}
}

func artifact(id string, class release.ArtifactClass, target release.InstallTarget, cohort string) release.Artifact {
	return release.Artifact{ID: id, Class: class, Platform: "linux", Architecture: "amd64",
		Size: 1, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MediaType: "application/octet-stream", Cohort: cohort, Target: target}
}
