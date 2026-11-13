package updater

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"setjoin.com/shared/release"
)

const (
	maxReleaseBytes         = uint64(16 << 30)
	maxExpandedWebmailBytes = uint64(2 << 30)
	maxWebmailEntries       = 100_000
	installedEvidenceName   = "installed.evidence.json"
)

var (
	ErrArtifactUnsafe    = errors.New("release artifact is unsafe")
	ErrInsufficientSpace = errors.New("insufficient release staging space")
)

// StagePolicy fixes the host facts used by the artifact adapter. Production
// uses runtime.GOOS/GOARCH; tests may provide an explicit disposable target.
type StagePolicy struct {
	Platform     string
	Architecture string
	FreeBytes    func(string) (uint64, error)
}

// InstalledReleaseEvidence binds the signed manifest to the exact expanded
// on-disk cohort. ContentSHA256 covers every directory and regular file below
// the release root except this evidence file itself, avoiding a circular hash.
type InstalledReleaseEvidence struct {
	SchemaVersion  int    `json:"schema_version"`
	ReleaseID      string `json:"release_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ContentSHA256  string `json:"content_sha256"`
}

func DefaultStagePolicy() StagePolicy {
	return StagePolicy{Platform: runtime.GOOS, Architecture: runtime.GOARCH, FreeBytes: filesystemFreeBytes}
}

// StageRelease materializes one manifest-bound release into a new immutable
// directory. It accepts no artifact paths from an intent or operator.
func (store *ReleaseStore) StageRelease(ctx context.Context, installRoot, releaseID, manifestDigest string, policy StagePolicy) (string, error) {
	manifest, err := store.VerifyTree(releaseID, manifestDigest)
	if err != nil {
		return "", err
	}
	if err := policy.normalize(); err != nil {
		return "", err
	}
	if err := validateTargetArtifacts(manifest, policy.Platform, policy.Architecture); err != nil {
		return "", err
	}
	if err := store.verifyInventory(manifest); err != nil {
		return "", err
	}
	releasesDir := filepath.Join(installRoot, "releases")
	if err := ensureSecureDirectory(installRoot, 0o755); err != nil {
		return "", err
	}
	if err := ensureSecureDirectory(releasesDir, 0o755); err != nil {
		return "", err
	}
	finalDir := filepath.Join(releasesDir, releaseID)
	if info, statErr := os.Lstat(finalDir); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("%w: final release path is indirect", ErrArtifactUnsafe)
		}
		if err := verifyInstalledRelease(finalDir, manifest, manifestDigest); err != nil {
			return "", err
		}
		return finalDir, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	var required uint64
	for _, artifact := range manifest.Artifacts {
		if artifact.Platform == policy.Platform && artifact.Architecture == policy.Architecture {
			if required > maxReleaseBytes-artifact.Size {
				return "", fmt.Errorf("%w: declared release exceeds %d bytes", ErrArtifactUnsafe, maxReleaseBytes)
			}
			required += artifact.Size
		}
	}
	if required > maxReleaseBytes {
		return "", fmt.Errorf("%w: declared release exceeds %d bytes", ErrArtifactUnsafe, maxReleaseBytes)
	}
	if manifest.Recovery.MinimumFreeBytes > ^uint64(0)-required {
		return "", fmt.Errorf("%w: free-space requirement overflow", ErrArtifactUnsafe)
	}
	free, err := policy.FreeBytes(installRoot)
	if err != nil {
		return "", fmt.Errorf("measure release staging space: %w", err)
	}
	if free < required+manifest.Recovery.MinimumFreeBytes {
		return "", fmt.Errorf("%w: have %d bytes, require %d", ErrInsufficientSpace, free, required+manifest.Recovery.MinimumFreeBytes)
	}

	staging := filepath.Join(releasesDir, ".staging-"+releaseID)
	if err := removeImmutableTree(staging); err != nil {
		return "", fmt.Errorf("clear stale staging directory: %w", err)
	}
	if err := os.Mkdir(staging, 0o700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = removeImmutableTree(staging)
		}
	}()

	for _, artifact := range manifest.Artifacts {
		if artifact.Platform != policy.Platform || artifact.Architecture != policy.Architecture {
			continue
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := store.stageArtifact(staging, releaseID, artifact); err != nil {
			return "", err
		}
	}
	manifestSource := filepath.Join(store.root, releaseID, "manifest.json")
	if err := copyVerifiedRegular(manifestSource, filepath.Join(staging, "manifest.json"), 0o444, nil); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(staging, "manifest.digest"), []byte(manifestDigest+"\n"), 0o400); err != nil {
		return "", fmt.Errorf("write installed manifest digest: %w", err)
	}
	if err := writeInstalledReleaseEvidence(staging, releaseID, manifestDigest); err != nil {
		return "", err
	}
	if err := makeTreeImmutable(staging); err != nil {
		return "", err
	}
	if err := syncTree(staging); err != nil {
		return "", err
	}
	if err := os.Rename(staging, finalDir); err != nil {
		return "", fmt.Errorf("commit staged release: %w", err)
	}
	if err := syncDirectory(releasesDir); err != nil {
		return "", err
	}
	committed = true
	return finalDir, nil
}

func (policy *StagePolicy) normalize() error {
	if policy.Platform == "" {
		policy.Platform = runtime.GOOS
	}
	if policy.Architecture == "" {
		policy.Architecture = runtime.GOARCH
	}
	if policy.FreeBytes == nil {
		policy.FreeBytes = filesystemFreeBytes
	}
	if !journalIdentifierExpr.MatchString(policy.Platform) || !journalIdentifierExpr.MatchString(policy.Architecture) {
		return fmt.Errorf("invalid staging platform or architecture")
	}
	return nil
}

func validateTargetArtifacts(manifest *release.Manifest, platform, architecture string) error {
	wanted := map[release.InstallTarget]int{}
	for _, artifact := range manifest.Artifacts {
		if artifact.Platform == platform && artifact.Architecture == architecture {
			wanted[artifact.Target]++
		}
	}
	for _, target := range []release.InstallTarget{
		release.TargetMailserver, release.TargetAuthserver, release.TargetMailctl,
		release.TargetWebmail, release.TargetRecoveryGuide, release.TargetSBOM,
		release.TargetProvenance, release.TargetGateway,
	} {
		if wanted[target] != 1 {
			return fmt.Errorf("%w: target %q has %d artifacts for %s/%s, want 1", ErrArtifactUnsafe, target, wanted[target], platform, architecture)
		}
	}
	return nil
}

func (store *ReleaseStore) verifyInventory(manifest *release.Manifest) error {
	dir := filepath.Join(store.root, manifest.ReleaseID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: inventory read failed: %v", ErrArtifactUnsafe, err)
	}
	want := map[string]bool{"manifest.json": true}
	for _, artifact := range manifest.Artifacts {
		want[artifact.ID] = true
	}
	if len(entries) != len(want) {
		return fmt.Errorf("%w: release inventory has undeclared or missing files", ErrArtifactUnsafe)
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return fmt.Errorf("%w: undeclared release file %q", ErrArtifactUnsafe, entry.Name())
		}
		info, statErr := entry.Info()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return fmt.Errorf("%w: inventory entry %q is not a private regular file", ErrArtifactUnsafe, entry.Name())
		}
		if store.requiredUID != nil && !ownedBy(info, *store.requiredUID) {
			return fmt.Errorf("%w: inventory entry %q owner differs", ErrArtifactUnsafe, entry.Name())
		}
	}
	return nil
}

func (store *ReleaseStore) stageArtifact(staging, releaseID string, artifact release.Artifact) error {
	source := filepath.Join(store.root, releaseID, artifact.ID)
	switch artifact.Target {
	case release.TargetMailserver:
		return copyVerifiedRegular(source, filepath.Join(staging, "mailserverd"), 0o500, &artifact)
	case release.TargetAuthserver:
		return copyVerifiedRegular(source, filepath.Join(staging, "authserverd"), 0o500, &artifact)
	case release.TargetMailctl:
		return copyVerifiedRegular(source, filepath.Join(staging, "mailctl"), 0o500, &artifact)
	case release.TargetGateway:
		return copyVerifiedRegular(source, filepath.Join(staging, "setjoin-gateway"), 0o500, &artifact)
	case release.TargetWebmail:
		return extractWebmail(source, filepath.Join(staging, "webmail"), artifact)
	case release.TargetMigrations:
		if artifact.MediaType != "application/sql" {
			return fmt.Errorf("%w: migration %q has media type %q", ErrArtifactUnsafe, artifact.ID, artifact.MediaType)
		}
		return copyVerifiedRegular(source, filepath.Join(staging, "share", "migrations", artifact.ID+".sql"), 0o400, &artifact)
	case release.TargetRecoveryGuide:
		if artifact.MediaType != "text/markdown" {
			return fmt.Errorf("%w: recovery guide has media type %q", ErrArtifactUnsafe, artifact.MediaType)
		}
		return copyVerifiedRegular(source, filepath.Join(staging, "share", "docs", "UPGRADE_RECOVERY.md"), 0o400, &artifact)
	case release.TargetSBOM:
		return copyVerifiedRegular(source, filepath.Join(staging, "share", "evidence", "sbom.json"), 0o400, &artifact)
	case release.TargetProvenance:
		return copyVerifiedRegular(source, filepath.Join(staging, "share", "evidence", "provenance.json"), 0o400, &artifact)
	case release.TargetSidecar:
		return copyVerifiedRegular(source, filepath.Join(staging, "sidecars", artifact.ID), 0o500, &artifact)
	default:
		return fmt.Errorf("%w: unsupported install target %q", ErrArtifactUnsafe, artifact.Target)
	}
}

func filesystemFreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}

func ensureSecureDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, mode); err != nil {
			return fmt.Errorf("create secure directory %s: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is not a secure real directory", ErrArtifactUnsafe, path)
	}
	return nil
}

func removeImmutableTree(path string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	// The staging root is a validated real directory writable only by the
	// updater. A non-owner cannot replace entries during this recovery walk.
	//nolint:gosec // G122: the validated private staging boundary prevents an attacker-controlled TOCTOU race.
	if err := filepath.Walk(path, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in stale staging tree", ErrArtifactUnsafe)
		}
		if info.IsDir() {
			//nolint:gosec // G302: traversal requires owner-only directory execute permission before removal.
			return os.Chmod(current, 0o700)
		}
		return os.Chmod(current, 0o600)
	}); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

func copyVerifiedRegular(source, destination string, mode os.FileMode, artifact *release.Artifact) error {
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("%w: stat %s: %v", ErrArtifactUnsafe, source, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%w: %s is not a private regular file", ErrArtifactUnsafe, source)
	}
	// source is derived from validated release/artifact identifiers and was
	// lstat-checked above as a private, single-link regular file.
	//nolint:gosec // G304: no caller-controlled path is opened.
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if artifact != nil {
		if err := release.VerifyArtifact(in, *artifact); err != nil {
			return err
		}
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	// destination is a fixed install target below the owner-only staging root.
	//nolint:gosec // G304: no caller-controlled path is opened.
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func extractWebmail(source, destination string, artifact release.Artifact) error {
	if artifact.MediaType != "application/vnd.setjoin.webmail.tar" {
		return fmt.Errorf("%w: webmail media type %q is unsupported", ErrArtifactUnsafe, artifact.MediaType)
	}
	info, err := os.Lstat(source)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: webmail archive is not a private regular file", ErrArtifactUnsafe)
	}
	// source is derived from validated release/artifact identifiers and was
	// lstat-checked above as a private, single-link regular file.
	//nolint:gosec // G304: no caller-controlled path is opened.
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	if err := release.VerifyArtifact(file, artifact); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return err
	}
	defer func() { _ = file.Close() }()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	reader := tar.NewReader(file)
	var expanded uint64
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: read webmail archive: %v", ErrArtifactUnsafe, err)
		}
		entries++
		if entries > maxWebmailEntries || header.Size < 0 || uint64(header.Size) > maxExpandedWebmailBytes-expanded {
			return fmt.Errorf("%w: webmail archive exceeds expansion limits", ErrArtifactUnsafe)
		}
		expanded += uint64(header.Size)
		clean := filepath.Clean(filepath.FromSlash(header.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("%w: path traversal in webmail archive", ErrArtifactUnsafe)
		}
		target := filepath.Join(destination, clean)
		if !pathWithin(destination, target) {
			return fmt.Errorf("%w: webmail archive escaped destination", ErrArtifactUnsafe)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Mode&0o7000 != 0 {
				return fmt.Errorf("%w: webmail entry has privileged mode", ErrArtifactUnsafe)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			// target is a traversal-checked relative archive path below the
			// newly created owner-only destination and O_EXCL rejects collisions.
			//nolint:gosec // G304: the archive path cannot escape the private extraction root.
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, reader, header.Size)
			syncErr := out.Sync()
			closeErr := out.Close()
			if copyErr != nil || syncErr != nil || closeErr != nil {
				return fmt.Errorf("extract webmail entry: copy=%v sync=%v close=%v", copyErr, syncErr, closeErr)
			}
		default:
			return fmt.Errorf("%w: webmail archive contains links or special nodes", ErrArtifactUnsafe)
		}
	}
	if _, err := os.Stat(filepath.Join(destination, "index.html")); err != nil {
		return fmt.Errorf("%w: webmail archive lacks index.html", ErrArtifactUnsafe)
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func makeTreeImmutable(root string) error {
	// root is the newly created owner-only staging directory. A non-owner cannot
	// replace entries between the walk's lstat and chmod operations.
	//nolint:gosec // G122: the validated private staging boundary prevents an attacker-controlled TOCTOU race.
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink appeared in staged release", ErrArtifactUnsafe)
		}
		if info.IsDir() {
			//nolint:gosec // G302: immutable directories require execute permission for traversal.
			return os.Chmod(path, 0o555)
		}
		mode := os.FileMode(0o444)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o555
		}
		//nolint:gosec // G302: executable release artifacts intentionally retain owner/world execute bits.
		return os.Chmod(path, mode)
	})
}

func syncTree(root string) error {
	var directories []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			directories = append(directories, path)
			return nil
		}
		// path came from walking the just-staged, symlink-rejected private tree.
		//nolint:gosec // G304: no caller-controlled path is opened.
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil {
			return syncErr
		}
		return closeErr
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(directories[i]); err != nil {
			return err
		}
	}
	return nil
}

func verifyInstalledRelease(dir string, manifest *release.Manifest, digest string) error {
	// dir is <validated install root>/releases/<validated release ID> and was
	// lstat-checked as a real immutable directory before this call.
	//nolint:gosec // G304: no caller-controlled path is read.
	data, err := os.ReadFile(filepath.Join(dir, "manifest.digest"))
	if err != nil || strings.TrimSpace(string(data)) != digest {
		return fmt.Errorf("%w: installed release digest differs", ErrArtifactUnsafe)
	}
	for _, path := range []string{"mailserverd", "authserverd", "mailctl", filepath.Join("webmail", "index.html"), filepath.Join("share", "docs", "UPGRADE_RECOVERY.md")} {
		info, err := os.Stat(filepath.Join(dir, path))
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: installed release is missing %s", ErrArtifactUnsafe, path)
		}
	}
	if manifest.ReleaseID != filepath.Base(dir) {
		return fmt.Errorf("%w: installed directory identity differs", ErrArtifactUnsafe)
	}
	return verifyInstalledReleaseEvidence(dir, manifest.ReleaseID, digest)
}

func writeInstalledReleaseEvidence(dir, releaseID, manifestDigest string) error {
	contentDigest, err := digestPrivateTreeExcept(dir, installedEvidenceName)
	if err != nil {
		return fmt.Errorf("digest installed release: %w", err)
	}
	evidence := InstalledReleaseEvidence{
		SchemaVersion:  1,
		ReleaseID:      releaseID,
		ManifestSHA256: manifestDigest,
		ContentSHA256:  contentDigest,
	}
	raw, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, installedEvidenceName), raw, 0o400); err != nil {
		return fmt.Errorf("write installed release evidence: %w", err)
	}
	return nil
}

func verifyInstalledReleaseEvidence(dir, releaseID, manifestDigest string) error {
	path := filepath.Join(dir, installedEvidenceName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: installed release evidence is missing or unsafe", ErrArtifactUnsafe)
	}
	// path is the fixed evidence filename below the validated immutable release
	// directory and was just checked as a private, single-link regular file.
	//nolint:gosec // G304: no caller-controlled path is read.
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: read installed release evidence: %v", ErrArtifactUnsafe, err)
	}
	var evidence InstalledReleaseEvidence
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil {
		return fmt.Errorf("%w: invalid installed release evidence", ErrArtifactUnsafe)
	}
	if err := requireJSONEOF(decoder); err != nil || evidence.SchemaVersion != 1 ||
		evidence.ReleaseID != releaseID || evidence.ManifestSHA256 != manifestDigest ||
		!journalDigestExpr.MatchString(evidence.ContentSHA256) {
		return fmt.Errorf("%w: installed release evidence differs", ErrArtifactUnsafe)
	}
	actual, err := digestPrivateTreeExcept(dir, installedEvidenceName)
	if err != nil || actual != evidence.ContentSHA256 {
		return fmt.Errorf("%w: installed release content differs", ErrArtifactUnsafe)
	}
	return nil
}
