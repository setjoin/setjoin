// Command release-fixture builds a signed, test-only release cohort from a
// disposable installation. It is intentionally below internal/updater/testutil
// and is never built or installed by scripts/build.sh.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"setjoin.com/mailserver/internal/updater/testutil"
	"setjoin.com/shared/release"
)

func main() {
	var source, output, releaseID, version, guide string
	var schema int
	var broken bool
	flag.StringVar(&source, "source-runtime", "", "disposable current runtime directory")
	flag.StringVar(&output, "output-store", "", "root-owned fixture release store")
	flag.StringVar(&releaseID, "release-id", "", "fixture release identifier")
	flag.StringVar(&version, "version", "", "fixture semantic version")
	flag.StringVar(&guide, "recovery-guide", "", "source recovery guide")
	flag.IntVar(&schema, "schema", 0, "unchanged source/target schema version")
	flag.BoolVar(&broken, "broken-mailserver", false, "replace mailserverd with an exit-only rollback fixture")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(source) || !filepath.IsAbs(output) || !filepath.IsAbs(guide) || releaseID == "" || version == "" || schema <= 0 {
		fatal("all absolute paths, release-id, version, and positive schema are required")
	}
	digest, err := createFixture(source, output, guide, releaseID, version, schema, broken)
	if err != nil {
		fatal(err.Error())
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"releaseId": releaseID, "version": version, "manifestDigest": digest,
		"schemaFrom": schema, "schemaTo": schema, "testOnly": true, "brokenMailserver": broken,
	})
}

func createFixture(source, output, guide, releaseID, version string, schema int, broken bool) (string, error) {
	releaseDir := filepath.Join(output, releaseID)
	if _, err := os.Lstat(releaseDir); !os.IsNotExist(err) {
		return "", fmt.Errorf("fixture release already exists: %s", releaseID)
	}
	if err := os.MkdirAll(releaseDir, 0o750); err != nil {
		return "", err
	}
	artifacts := []release.Artifact{}
	add := func(id string, class release.ArtifactClass, target release.InstallTarget, mediaType, cohort string, write func(string) error) error {
		path := filepath.Join(releaseDir, id)
		if err := write(path); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return fmt.Errorf("fixture artifact %s is not a non-empty regular file", id)
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, release.Artifact{
			ID: id, Class: class, Target: target, Platform: "linux", Architecture: "amd64",
			// The non-empty regular-file check above proves Size is positive and
			// therefore exactly representable by uint64.
			Size:   uint64(info.Size()), //nolint:gosec // G115: positive int64 to uint64.
			SHA256: digest, MediaType: mediaType, Cohort: cohort,
		})
		return nil
	}
	copyArtifact := func(sourcePath string) func(string) error {
		return func(destination string) error { return copyFile(sourcePath, destination) }
	}
	mailserverWriter := copyArtifact(filepath.Join(source, "mailserverd"))
	if broken {
		mailserverWriter = func(destination string) error {
			return os.WriteFile(destination, []byte("#!/bin/sh\nexit 42\n"), 0o600)
		}
	}
	for _, item := range []struct {
		id, media, cohort string
		class             release.ArtifactClass
		target            release.InstallTarget
		write             func(string) error
	}{
		{"attestation-provenance", "application/json", "evidence", release.ArtifactProvenance, release.TargetProvenance, func(path string) error {
			return os.WriteFile(path, []byte(`{"builder":"setjoin-updater-fixture","testOnly":true}`), 0o600)
		}},
		{"attestation-sbom", "application/json", "evidence", release.ArtifactSBOM, release.TargetSBOM, func(path string) error {
			return os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","testOnly":true}`), 0o600)
		}},
		{"authserverd", "application/octet-stream", "core", release.ArtifactAuthserver, release.TargetAuthserver, copyArtifact(filepath.Join(source, "authserverd"))},
		{"mailctl", "application/octet-stream", "core", release.ArtifactMailctl, release.TargetMailctl, copyArtifact(filepath.Join(source, "mailctl"))},
		{"mailserverd", "application/octet-stream", "core", release.ArtifactMailserver, release.TargetMailserver, mailserverWriter},
		{"recovery-guide", "text/markdown", "evidence", release.ArtifactRecoveryGuide, release.TargetRecoveryGuide, copyArtifact(guide)},
		{"setjoin-gateway", "application/octet-stream", "core", release.ArtifactGateway, release.TargetGateway, copyArtifact(filepath.Join(source, "setjoin-gateway"))},
		{"webmail", "application/vnd.setjoin.webmail.tar", "core", release.ArtifactWebmail, release.TargetWebmail, func(path string) error { return writeTar(filepath.Join(source, "webmail"), path) }},
	} {
		if err := add(item.id, item.class, item.target, item.media, item.cohort, item.write); err != nil {
			return "", err
		}
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].ID < artifacts[j].ID })
	now := time.Now().UTC().Truncate(time.Second)
	manifest := &release.Manifest{
		SchemaVersion: release.ManifestSchemaV1, ReleaseID: releaseID, Version: version,
		Channel: release.ChannelCommunity, PublishedAt: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), MetadataVersion: 1,
		PreviousVersionFloor: "0.0.1", Platforms: []string{"linux"}, Architectures: []string{"amd64"},
		Compatibility: release.Compatibility{SourceVersionRange: ">=0.0.1 <99.0.0", PostgresRange: ">=16.0.0 <19.0.0"},
		SchemaFrom:    schema, SchemaTo: schema, Artifacts: artifacts,
		HealthGates: release.HealthGates{Preflight: []string{"fixed_preflight"}, Readiness: []string{"fixed_readiness"}, Data: []string{"login_imap"}, PostCommit: []string{"smtp_imap_round_trip"}},
		Recovery:    release.RecoveryRequirements{MaximumAgeSeconds: 86400, MinimumFreeBytes: 1024},
		Notes:       release.ReleaseNotes{Summary: "Disposable Ubuntu transactional updater fixture", DowntimeMaximumSec: 60, SupportChannel: "fixture"},
		Signing:     release.SigningPolicy{Threshold: 1},
	}
	if _, err := testutil.SignManifest(manifest); err != nil {
		return "", err
	}
	raw, err := release.MarshalManifest(manifest)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "manifest.json"), raw, 0o600); err != nil {
		return "", err
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func copyFile(source, destination string) error {
	// Both paths are derived only from validated absolute fixture roots and the
	// command's fixed artifact inventory, never a request or manifest value.
	//nolint:gosec // G304: test-only fixed fixture paths.
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	//nolint:gosec // G304: test-only fixed fixture paths.
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func hashFile(path string) (string, error) {
	// path is a just-created file below the validated fixture release root.
	//nolint:gosec // G304: test-only fixed fixture path.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeTar(root, destination string) error {
	// destination is the fixed webmail artifact below the validated fixture
	// output root; it is never taken from a manifest or network request.
	//nolint:gosec // G304: test-only fixed fixture path.
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = out.Close()
		}
	}()
	writer := tar.NewWriter(out)
	writerClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
	}()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return fmt.Errorf("webmail fixture contains unsupported entry %s", path)
		}
		paths = append(paths, path)
		return nil
	}); err != nil {
		_ = writer.Close()
		_ = out.Close()
		return err
	}
	sort.Strings(paths)
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		header := &tar.Header{Name: filepath.ToSlash(name), Mode: 0o644, ModTime: time.Unix(0, 0), AccessTime: time.Unix(0, 0), ChangeTime: time.Unix(0, 0)}
		if info.IsDir() {
			header.Typeflag, header.Mode, header.Name = tar.TypeDir, 0o755, filepath.ToSlash(name)+"/"
		} else {
			header.Typeflag, header.Size = tar.TypeReg, info.Size()
		}
		if err := writer.WriteHeader(header); err != nil {
			return err
		}
		if !info.IsDir() {
			// WalkDir supplied path from the validated source runtime tree after
			// rejecting links and non-regular entries.
			//nolint:gosec // G304: test-only validated fixture source path.
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(writer, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	if err := writer.Close(); err != nil {
		writerClosed = true
		_ = out.Close()
		closed = true
		return err
	}
	writerClosed = true
	err = out.Close()
	closed = true
	return err
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
