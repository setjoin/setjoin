package updater

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/shared/release"
)

type webmailEntry struct {
	name     string
	typeflag byte
	data     string
	linkname string
	mode     int64
}

func webmailArchive(t *testing.T, entries ...webmailEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		mode := entry.mode
		if mode == 0 {
			mode = 0o644
		}
		header := &tar.Header{Name: entry.name, Typeflag: entry.typeflag, Mode: mode, Linkname: entry.linkname}
		if entry.typeflag == tar.TypeReg || entry.typeflag == tar.TypeRegA {
			header.Size = int64(len(entry.data))
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func writeStageFixture(t *testing.T, archive []byte) (root, releaseID, digest string, manifest *release.Manifest) {
	t.Helper()
	root = t.TempDir()
	// The release-store guards reject group/world-writable trees. t.TempDir
	// and os.Mkdir both inherit the process umask (e.g. 002 on CI runners,
	// yielding 0775), so pin the store and release tree to 0755 explicitly to
	// keep the fixture umask-independent.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	releaseID = "release-1"
	releaseDir := filepath.Join(root, releaseID)
	if err := os.Mkdir(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{
		"authserverd":     []byte("auth"),
		"mailctl":         []byte("mailctl"),
		"mailserverd":     []byte("mail"),
		"provenance":      []byte(`{"predicate":"fixture"}`),
		"recovery-guide":  []byte("# Recovery\n\nNever restore PostgreSQL automatically.\n"),
		"sbom":            []byte(`{"spdxVersion":"SPDX-2.3"}`),
		"setjoin-gateway": []byte("rust gateway"),
		"webmail":         archive,
	}
	manifest = minimalManifest()
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		data := contents[artifact.ID]
		sum := sha256.Sum256(data)
		artifact.Size = uint64(len(data))
		artifact.SHA256 = hex.EncodeToString(sum[:])
		switch artifact.Target {
		case release.TargetWebmail:
			artifact.MediaType = "application/vnd.setjoin.webmail.tar"
		case release.TargetRecoveryGuide:
			artifact.MediaType = "text/markdown"
		case release.TargetSBOM:
			artifact.MediaType = "application/spdx+json"
		case release.TargetProvenance:
			artifact.MediaType = "application/vnd.in-toto+json"
		default:
			artifact.MediaType = "application/octet-stream"
		}
		if err := os.WriteFile(filepath.Join(releaseDir, artifact.ID), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	digest = hex.EncodeToString(sum[:])
	return root, releaseID, digest, manifest
}

func TestStageReleaseBuildsExactImmutableCohort(t *testing.T) {
	archive := webmailArchive(t,
		webmailEntry{name: "assets/", typeflag: tar.TypeDir},
		webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "<html>ok</html>"},
		webmailEntry{name: "assets/app.js", typeflag: tar.TypeReg, data: "ok"},
	)
	root, releaseID, digest, _ := writeStageFixture(t, archive)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(t.TempDir(), "setjoin")
	t.Cleanup(func() { makeWritableForCleanup(installRoot) })
	path, err := store.StageRelease(context.Background(), installRoot, releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"mailserverd", "authserverd", "mailctl", "setjoin-gateway", "webmail/index.html",
		"share/docs/UPGRADE_RECOVERY.md", "share/evidence/sbom.json",
		"share/evidence/provenance.json", "manifest.json", "manifest.digest",
		installedEvidenceName,
	} {
		info, err := os.Stat(filepath.Join(path, rel))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("installed %s: info=%v err=%v", rel, info, err)
		}
	}
	if path2, err := store.StageRelease(context.Background(), installRoot, releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 0, errors.New("must not restage") }}); err != nil || path2 != path {
		t.Fatalf("idempotent stage path=%q err=%v", path2, err)
	}
}

// #264: a signed release staged by this updater must carry the Rust front
// door beside the Go cohort; a release without it never becomes `current`.
func TestStageReleaseRequiresTheRustGatewayArtifact(t *testing.T) {
	root, releaseID, _, manifest := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
	kept := manifest.Artifacts[:0]
	for _, artifact := range manifest.Artifacts {
		if artifact.Target != release.TargetGateway {
			kept = append(kept, artifact)
		}
	}
	manifest.Artifacts = kept
	releaseDir := filepath.Join(root, releaseID)
	if err := os.Remove(filepath.Join(releaseDir, "setjoin-gateway")); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), raw, 0o644); err != nil {
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
	installRoot := filepath.Join(t.TempDir(), "install")
	t.Cleanup(func() { makeWritableForCleanup(installRoot) })
	_, err = store.StageRelease(context.Background(), installRoot, releaseID, hex.EncodeToString(sum[:]),
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if !errors.Is(err, ErrArtifactUnsafe) || !strings.Contains(err.Error(), string(release.TargetGateway)) {
		t.Fatalf("release without the gateway staged: %v", err)
	}
}

func TestStageReleaseRejectsCorruptedInstalledCohort(t *testing.T) {
	root, releaseID, digest, _ := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(t.TempDir(), "install")
	t.Cleanup(func() { makeWritableForCleanup(installRoot) })
	path, err := store.StageRelease(context.Background(), installRoot, releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "webmail", "index.html"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "webmail", "index.html"), []byte("corrupt"), 0o400); err != nil {
		t.Fatal(err)
	}
	_, err = store.StageRelease(context.Background(), installRoot, releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if !errors.Is(err, ErrArtifactUnsafe) || !strings.Contains(err.Error(), "content differs") {
		t.Fatalf("corrupt installed cohort error=%v", err)
	}
}

func TestMakeTreeImmutablePreservesDeclaredExecutableMode(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { makeWritableForCleanup(root) })
	path := filepath.Join(root, "sidecars", "worker")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("binary"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := makeTreeImmutable(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("sidecar mode=%v", info.Mode().Perm())
	}
}

func TestStageReleaseRejectsTraversalLinksExtraFilesAndLowDisk(t *testing.T) {
	for name, archive := range map[string][]byte{
		"traversal": webmailArchive(t, webmailEntry{name: "../escape", typeflag: tar.TypeReg, data: "x"}),
		"symlink":   webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}),
		"hardlink":  webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeLink, linkname: "/etc/passwd"}),
	} {
		t.Run(name, func(t *testing.T) {
			root, releaseID, digest, _ := writeStageFixture(t, archive)
			store, err := OpenReleaseStore(root)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest,
				StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
			if !errors.Is(err, ErrArtifactUnsafe) {
				t.Fatalf("unsafe archive error=%v", err)
			}
		})
	}
	t.Run("extra inventory file", func(t *testing.T) {
		root, releaseID, digest, _ := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
		if err := os.WriteFile(filepath.Join(root, releaseID, "undeclared"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		store, _ := OpenReleaseStore(root)
		_, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest,
			StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
		if !errors.Is(err, ErrArtifactUnsafe) {
			t.Fatalf("extra file error=%v", err)
		}
	})
	t.Run("low disk", func(t *testing.T) {
		root, releaseID, digest, _ := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
		store, _ := OpenReleaseStore(root)
		_, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest,
			StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1, nil }})
		if !errors.Is(err, ErrInsufficientSpace) {
			t.Fatalf("low disk error=%v", err)
		}
	})
}

func TestStageReleaseRejectsDigestMismatchAndMutableInput(t *testing.T) {
	root, releaseID, digest, _ := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
	if err := os.WriteFile(filepath.Join(root, releaseID, "mailserverd"), []byte("fail"), 0o644); err != nil {
		t.Fatal(err)
	}
	store, _ := OpenReleaseStore(root)
	_, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("tampered artifact error=%v", err)
	}
	if err := os.Chmod(filepath.Join(root, releaseID, "mailserverd"), 0o666); err != nil {
		t.Fatal(err)
	}
	_, err = store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "other"), releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatalf("mutable artifact error=%v", err)
	}
}

func TestStageReleaseRejectsHardlinkedInputArtifact(t *testing.T) {
	root, releaseID, digest, _ := writeStageFixture(t, webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"}))
	if err := os.Link(filepath.Join(root, releaseID, "mailserverd"), filepath.Join(root, "second-link")); err != nil {
		t.Fatal(err)
	}
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
	if !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatalf("hardlinked source error=%v", err)
	}
}

func rewriteStageManifest(t *testing.T, root, releaseID string, manifest *release.Manifest) string {
	t.Helper()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, releaseID, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func TestStageReleaseRejectsPolicyCapacityAndFilesystemBoundaries(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"})
	root, releaseID, digest, manifest := writeStageFixture(t, archive)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if policy := DefaultStagePolicy(); policy.Platform == "" || policy.Architecture == "" || policy.FreeBytes == nil {
		t.Fatalf("default policy=%#v", policy)
	}
	for _, policy := range []StagePolicy{{Platform: "bad/platform", Architecture: "amd64"}, {Platform: "darwin", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}} {
		if _, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest, policy); err == nil {
			t.Fatalf("policy %#v accepted", policy)
		}
	}
	fileRoot := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRelease(context.Background(), fileRoot, releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); err == nil {
		t.Fatal("file install root accepted")
	}
	install := filepath.Join(t.TempDir(), "install")
	if err := os.Mkdir(install, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(install, "releases"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageRelease(context.Background(), install, releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); err == nil {
		t.Fatal("file releases root accepted")
	}
	if _, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 0, errors.New("statfs failed") }}); err == nil || !strings.Contains(err.Error(), "statfs failed") {
		t.Fatalf("free bytes error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.StageRelease(cancelled, filepath.Join(t.TempDir(), "install"), releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error=%v", err)
	}

	manifest.Artifacts[0].Size = maxReleaseBytes
	manifest.Artifacts[1].Size = 1
	digest = rewriteStageManifest(t, root, releaseID, manifest)
	if _, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), releaseID, digest, StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return ^uint64(0), nil }}); err == nil || !strings.Contains(err.Error(), "declared release") {
		t.Fatalf("capacity error=%v", err)
	}
}

func TestArtifactStagingTargetAndArchiveFailureBoundaries(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "artifact")
	if err := os.WriteFile(source, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &ReleaseStore{root: base}
	sum := sha256.Sum256([]byte("content"))
	artifact := release.Artifact{ID: "artifact", Size: 7, SHA256: hex.EncodeToString(sum[:]), MediaType: "application/octet-stream", Target: release.TargetSidecar}
	staging := filepath.Join(base, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.stageArtifact(staging, ".", artifact); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(staging, "sidecars", "artifact")); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("sidecar info=%v err=%v", info, err)
	}
	migration := artifact
	migration.Target = release.TargetMigrations
	migration.MediaType = "application/sql"
	if err := store.stageArtifact(filepath.Join(base, "migration-stage"), ".", migration); err != nil {
		t.Fatalf("migration staging: %v", err)
	}
	for _, tc := range []release.Artifact{
		{ID: "artifact", Target: release.TargetMigrations, MediaType: "text/plain"},
		{ID: "artifact", Target: release.TargetRecoveryGuide, MediaType: "text/plain"},
		{ID: "artifact", Target: "future"},
	} {
		if err := store.stageArtifact(filepath.Join(base, "other"), ".", tc); err == nil {
			t.Fatalf("target %s accepted", tc.Target)
		}
	}

	archives := []struct {
		name string
		raw  []byte
	}{
		{"invalid tar", []byte("not a tar archive")},
		{"missing index", webmailArchive(t, webmailEntry{name: "app.js", typeflag: tar.TypeReg, data: "x"})},
		{"privileged", webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "x", mode: 0o4755})},
		{"duplicate", webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "x"}, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "y"})},
	}
	for _, tc := range archives {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "webmail.tar")
			if err := os.WriteFile(path, tc.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(tc.raw)
			a := release.Artifact{ID: "webmail", Size: uint64(len(tc.raw)), SHA256: hex.EncodeToString(sum[:]), MediaType: "application/vnd.setjoin.webmail.tar"}
			if err := extractWebmail(path, filepath.Join(t.TempDir(), "webmail"), a); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	wrong := release.Artifact{MediaType: "application/zip"}
	if err := extractWebmail(source, filepath.Join(base, "wrong"), wrong); err == nil {
		t.Fatal("wrong webmail media accepted")
	}
}

func TestArtifactStagingCoversReleaseStoreAndFilesystemFailureBoundaries(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"})
	root, releaseID, digest, manifest := writeStageFixture(t, archive)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	policy := StagePolicy{}
	if err := policy.normalize(); err != nil || policy.Platform == "" || policy.Architecture == "" || policy.FreeBytes == nil {
		t.Fatalf("normalized policy=%#v err=%v", policy, err)
	}
	if _, err := store.StageRelease(context.Background(), filepath.Join(t.TempDir(), "install"), "missing", digest,
		StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); !errors.Is(err, ErrReleaseUnavailable) {
		t.Fatalf("missing release error=%v", err)
	}

	t.Run("final path is file", func(t *testing.T) {
		install := filepath.Join(t.TempDir(), "install")
		if err := os.MkdirAll(filepath.Join(install, "releases"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(install, "releases", releaseID), []byte("collision"), 0o444); err != nil {
			t.Fatal(err)
		}
		if _, err := store.StageRelease(context.Background(), install, releaseID, digest,
			StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); !errors.Is(err, ErrArtifactUnsafe) {
			t.Fatalf("final path error=%v", err)
		}
	})
	t.Run("stale staging is symlink", func(t *testing.T) {
		install := filepath.Join(t.TempDir(), "install")
		if err := os.MkdirAll(filepath.Join(install, "releases"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), filepath.Join(install, "releases", ".staging-"+releaseID)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.StageRelease(context.Background(), install, releaseID, digest,
			StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }}); !errors.Is(err, ErrArtifactUnsafe) {
			t.Fatalf("stale staging error=%v", err)
		}
	})

	if err := store.verifyInventory(&release.Manifest{ReleaseID: "missing"}); !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatalf("missing inventory error=%v", err)
	}
	releaseDir := filepath.Join(root, releaseID)
	removed := filepath.Join(releaseDir, manifest.Artifacts[0].ID)
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "same-count-extra"), []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := store.verifyInventory(manifest); !errors.Is(err, ErrArtifactUnsafe) || !strings.Contains(err.Error(), "undeclared") {
		t.Fatalf("same-count inventory error=%v", err)
	}
	if err := os.Remove(filepath.Join(releaseDir, "same-count-extra")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(removed, []byte("auth"), 0o444); err != nil {
		t.Fatal(err)
	}
	wrongOwner := uint32(os.Getuid() + 1)
	store.requiredUID = &wrongOwner
	if err := store.verifyInventory(manifest); !errors.Is(err, ErrArtifactUnsafe) || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("owner inventory error=%v", err)
	}
}

func TestWebmailExtractionRejectsChecksumDestinationAndTruncatedEntry(t *testing.T) {
	valid := webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"})
	writeArtifact := func(t *testing.T, raw []byte) (string, release.Artifact) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "webmail.tar")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		return path, release.Artifact{ID: "webmail", Size: uint64(len(raw)), SHA256: hex.EncodeToString(sum[:]), MediaType: "application/vnd.setjoin.webmail.tar"}
	}
	path, descriptor := writeArtifact(t, valid)
	bad := descriptor
	bad.SHA256 = strings.Repeat("0", 64)
	if err := extractWebmail(path, filepath.Join(t.TempDir(), "out"), bad); err == nil {
		t.Fatal("checksum-mismatched webmail archive accepted")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := extractWebmail(path, filepath.Join(t.TempDir(), "mutable"), descriptor); !errors.Is(err, ErrArtifactUnsafe) {
		t.Fatalf("mutable archive error=%v", err)
	}

	path, descriptor = writeArtifact(t, valid)
	destination := filepath.Join(t.TempDir(), "destination")
	if err := os.WriteFile(destination, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractWebmail(path, destination, descriptor); err == nil {
		t.Fatal("file extraction destination accepted")
	}

	var truncated bytes.Buffer
	writer := tar.NewWriter(&truncated)
	if err := writer.WriteHeader(&tar.Header{Name: "index.html", Typeflag: tar.TypeReg, Mode: 0o644, Size: 10}); err != nil {
		t.Fatal(err)
	}
	path, descriptor = writeArtifact(t, truncated.Bytes())
	if err := extractWebmail(path, filepath.Join(t.TempDir(), "truncated"), descriptor); err == nil || !strings.Contains(err.Error(), "extract webmail entry") {
		t.Fatalf("truncated entry error=%v", err)
	}

	conflict := webmailArchive(t,
		webmailEntry{name: "assets", typeflag: tar.TypeReg, data: "file"},
		webmailEntry{name: "assets/", typeflag: tar.TypeDir},
	)
	path, descriptor = writeArtifact(t, conflict)
	if err := extractWebmail(path, filepath.Join(t.TempDir(), "conflict"), descriptor); err == nil {
		t.Fatal("directory/file archive collision accepted")
	}
}

func TestInstalledReleaseVerificationRejectsMissingIdentityAndWriteFailures(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: tar.TypeReg, data: "ok"})
	for name, mutate := range map[string]func(*testing.T, string, *release.Manifest){
		"digest": func(t *testing.T, dir string, _ *release.Manifest) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "manifest.digest")); err != nil {
				t.Fatal(err)
			}
		},
		"core": func(t *testing.T, dir string, _ *release.Manifest) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, "mailserverd")); err != nil {
				t.Fatal(err)
			}
		},
		"identity": func(_ *testing.T, _ string, manifest *release.Manifest) { manifest.ReleaseID = "other-release" },
	} {
		t.Run(name, func(t *testing.T) {
			root, releaseID, digest, manifest := writeStageFixture(t, archive)
			store, _ := OpenReleaseStore(root)
			install := filepath.Join(t.TempDir(), "install")
			t.Cleanup(func() { makeWritableForCleanup(install) })
			dir, err := store.StageRelease(context.Background(), install, releaseID, digest,
				StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }})
			if err != nil {
				t.Fatal(err)
			}
			makeWritableForCleanup(dir)
			mutate(t, dir, manifest)
			if err := verifyInstalledRelease(dir, manifest, digest); !errors.Is(err, ErrArtifactUnsafe) {
				t.Fatalf("verification error=%v", err)
			}
		})
	}

	empty := t.TempDir()
	if err := os.Chmod(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeInstalledReleaseEvidence(empty, "release", strings.Repeat("a", 64)); err == nil {
		t.Fatal("empty installed release received evidence")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, installedEvidenceName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeInstalledReleaseEvidence(dir, "release", strings.Repeat("a", 64)); err == nil {
		t.Fatal("evidence directory collision accepted")
	}
	if err := makeTreeImmutable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing immutable tree accepted")
	}
}

func TestArtifactFilesystemAndEvidenceHelpersRejectUnsafeShapes(t *testing.T) {
	base := t.TempDir()
	created := filepath.Join(base, "created")
	if err := ensureSecureDirectory(created, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystemFreeBytes(created); err != nil {
		t.Fatal(err)
	}
	if _, err := filesystemFreeBytes(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing statfs path accepted")
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(file, 0o700); err == nil {
		t.Fatal("file secure directory accepted")
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(loose, 0o700); err == nil {
		t.Fatal("loose directory accepted")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(created, link); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureDirectory(link, 0o700); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if err := removeImmutableTree(filepath.Join(base, "missing")); err != nil {
		t.Fatal(err)
	}
	tree := filepath.Join(base, "tree")
	if err := os.Mkdir(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(tree, "link")); err != nil {
		t.Fatal(err)
	}
	if err := removeImmutableTree(tree); err == nil {
		t.Fatal("stale tree symlink accepted")
	}
	if err := makeTreeImmutable(tree); err == nil {
		t.Fatal("staged tree symlink accepted")
	}
	makeWritableForCleanup(tree)
	if err := syncTree(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing tree synced")
	}
	if err := copyVerifiedRegular(filepath.Join(base, "missing"), filepath.Join(base, "out"), 0o400, nil); err == nil {
		t.Fatal("missing source copied")
	}
	if err := copyVerifiedRegular(link, filepath.Join(base, "out"), 0o400, nil); err == nil {
		t.Fatal("symlink source copied")
	}
	destination := filepath.Join(base, "destination")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedRegular(file, destination, 0o400, nil); err == nil {
		t.Fatal("existing destination replaced")
	}
}

func TestInstalledReleaseEvidenceRejectsMalformedAndMismatchedDocuments(t *testing.T) {
	dir := t.TempDir()
	// t.TempDir() returns a subdirectory created with Mkdir(0o777), so under a
	// umask like 002 it lands group-writable (0775) and the installed-release
	// guards refuse it. Pin 0755 so the fixture is umask-independent.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "payload"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := writeInstalledReleaseEvidence(dir, "release", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, installedEvidenceName)
	valid, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"malformed": []byte(`{`),
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"unknown":   bytes.Replace(valid, []byte(`"schema_version": 1`), []byte(`"schema_version": 1,"unknown":true`), 1),
		"release":   bytes.Replace(valid, []byte(`"release_id": "release"`), []byte(`"release_id": "other"`), 1),
		"digest":    bytes.Replace(valid, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o400); err != nil {
				t.Fatal(err)
			}
			if err := verifyInstalledReleaseEvidence(dir, "release", strings.Repeat("a", 64)); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("payload", path); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledReleaseEvidence(dir, "release", strings.Repeat("a", 64)); err == nil {
		t.Fatal("symlink evidence accepted")
	}
}

func makeWritableForCleanup(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0o755)
		}
		return nil
	})
}
