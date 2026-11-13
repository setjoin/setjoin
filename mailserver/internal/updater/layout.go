package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"setjoin.com/shared/release"
)

var ErrLayoutIncomplete = errors.New("flat installation is incomplete")

// gatewayArtifact is the Rust front door (#264). It joins the cohort when the
// flat or managed release carries it; cohorts from before it existed stay
// valid so they remain rollback targets.
const gatewayArtifact = "setjoin-gateway"

type AdoptionOptions struct {
	InstallRoot   string
	ConfigPath    string
	QuarantineDir string
	SchemaVersion int
	// Boundary is a test-only interruption seam. Production leaves it nil.
	Boundary func(string) error
}

type AdoptionEvidence struct {
	SchemaVersion  int               `json:"schema_version"`
	ReleaseID      string            `json:"release_id"`
	DatabaseSchema int               `json:"database_schema"`
	ConfigSHA256   string            `json:"config_sha256"`
	Artifacts      map[string]string `json:"artifacts"`
}

// AdoptCurrentLayout captures a complete legacy core cohort without copying
// configuration secrets into the release. It is idempotent across every
// durable boundary and never claims a lone *.prev file as a rollback release.
func AdoptCurrentLayout(options AdoptionOptions) (*AdoptionEvidence, error) {
	if !filepath.IsAbs(options.InstallRoot) || !filepath.IsAbs(options.ConfigPath) || !filepath.IsAbs(options.QuarantineDir) {
		return nil, fmt.Errorf("adoption paths must be absolute")
	}
	if err := ensureSecureDirectory(options.InstallRoot, 0o755); err != nil {
		return nil, err
	}
	if current, err := activeReleaseID(options.InstallRoot, "current"); err == nil {
		evidence, readErr := readCurrentLayoutEvidence(filepath.Join(options.InstallRoot, "releases", current), options.ConfigPath)
		if readErr != nil {
			return nil, readErr
		}
		if err := quarantineLegacyPrevious(options); err != nil {
			return nil, err
		}
		return evidence, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	artifacts, configDigest, err := inspectFlatCohort(options.InstallRoot, options.ConfigPath)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	for _, name := range sortedKeys(artifacts) {
		_, _ = io.WriteString(hash, name+"\x00"+artifacts[name]+"\x00")
	}
	_, _ = io.WriteString(hash, "config\x00"+configDigest+"\x00")
	releaseID := "legacy-adopted-" + hex.EncodeToString(hash.Sum(nil))
	if options.SchemaVersion < 1 {
		return nil, fmt.Errorf("adoption schema version must be positive")
	}
	evidence := &AdoptionEvidence{SchemaVersion: 1, ReleaseID: releaseID, DatabaseSchema: options.SchemaVersion, ConfigSHA256: configDigest, Artifacts: artifacts}

	releasesDir := filepath.Join(options.InstallRoot, "releases")
	if err := ensureSecureDirectory(releasesDir, 0o755); err != nil {
		return nil, err
	}
	finalDir := filepath.Join(releasesDir, releaseID)
	if _, err := os.Lstat(finalDir); errors.Is(err, os.ErrNotExist) {
		staging := filepath.Join(releasesDir, ".staging-"+releaseID)
		if err := removeImmutableTree(staging); err != nil {
			return nil, err
		}
		if err := os.Mkdir(staging, 0o700); err != nil {
			return nil, err
		}
		committed := false
		defer func() {
			if !committed {
				_ = removeImmutableTree(staging)
			}
		}()
		for _, name := range cohortBinaries(artifacts) {
			if err := copyLegacyRegular(filepath.Join(options.InstallRoot, name), filepath.Join(staging, name), 0o500); err != nil {
				return nil, err
			}
			if err := adoptionBoundary(options, "copied_"+name); err != nil {
				return nil, err
			}
		}
		if err := copyLegacyTree(filepath.Join(options.InstallRoot, "webmail"), filepath.Join(staging, "webmail")); err != nil {
			return nil, err
		}
		if err := adoptionBoundary(options, "copied_webmail"); err != nil {
			return nil, err
		}
		raw, err := json.MarshalIndent(evidence, "", "  ")
		if err != nil {
			return nil, err
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(filepath.Join(staging, "adoption.json"), raw, 0o400); err != nil {
			return nil, err
		}
		if err := makeTreeImmutable(staging); err != nil {
			return nil, err
		}
		if err := syncTree(staging); err != nil {
			return nil, err
		}
		if err := adoptionBoundary(options, "staging_synced"); err != nil {
			return nil, err
		}
		if err := os.Rename(staging, finalDir); err != nil {
			return nil, err
		}
		committed = true
		if err := syncDirectory(releasesDir); err != nil {
			return nil, err
		}
		if err := adoptionBoundary(options, "release_committed"); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		stored, readErr := readAdoptionEvidence(finalDir)
		if readErr != nil || stored.ReleaseID != releaseID || stored.ConfigSHA256 != configDigest {
			return nil, fmt.Errorf("existing adopted release does not match flat installation")
		}
	}

	if err := switchRelativeSymlink(options.InstallRoot, "current", filepath.Join("releases", releaseID)); err != nil {
		return nil, err
	}
	if err := adoptionBoundary(options, "current_switched"); err != nil {
		return nil, err
	}
	if err := quarantineLegacyPrevious(options); err != nil {
		return nil, err
	}
	return evidence, nil
}

func inspectFlatCohort(root, configPath string) (map[string]string, string, error) {
	artifacts := map[string]string{}
	for _, name := range []string{"authserverd", "mailctl", "mailserverd"} {
		digest, err := digestPrivateRegular(filepath.Join(root, name))
		if err != nil {
			return nil, "", fmt.Errorf("%w: %s: %v", ErrLayoutIncomplete, name, err)
		}
		artifacts[name] = digest
	}
	if err := addOptionalGateway(artifacts, root); err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrLayoutIncomplete, gatewayArtifact, err)
	}
	webmailDigest, err := digestPrivateTree(filepath.Join(root, "webmail"))
	if err != nil {
		return nil, "", fmt.Errorf("%w: webmail: %v", ErrLayoutIncomplete, err)
	}
	artifacts["webmail"] = webmailDigest
	configDigest, err := digestPrivateRegular(configPath)
	if err != nil {
		return nil, "", fmt.Errorf("%w: config evidence: %v", ErrLayoutIncomplete, err)
	}
	return artifacts, configDigest, nil
}

// cohortBinaries lists the regular-file binaries of a cohort, the gateway
// only when the cohort's evidence carries it.
func cohortBinaries(artifacts map[string]string) []string {
	names := []string{"mailserverd", "authserverd", "mailctl"}
	if _, ok := artifacts[gatewayArtifact]; ok {
		names = append(names, gatewayArtifact)
	}
	return names
}

// addOptionalGateway records the gateway digest when dir holds one; an
// absent gateway is a pre-#264 cohort, any other shape fails closed.
func addOptionalGateway(artifacts map[string]string, dir string) error {
	path := filepath.Join(dir, gatewayArtifact)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	digest, err := digestPrivateRegular(path)
	if err != nil {
		return err
	}
	artifacts[gatewayArtifact] = digest
	return nil
}

func digestPrivateRegular(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return "", fmt.Errorf("not a private regular file")
	}
	// The caller constructs this path from a validated layout root and fixed
	// artifact/config names; lstat above rejects links and unsafe files.
	//nolint:gosec // G304: no request-controlled path is opened.
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestPrivateTree(root string) (string, error) {
	return digestPrivateTreeExcept(root, "")
}

func digestPrivateTreeExcept(root, excludedRelativePath string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("not a private real directory")
	}
	type item struct{ kind, path, digest string }
	var items []item
	regularFiles := 0
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == excludedRelativePath && rel != "" {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("excluded evidence path is not a regular file")
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unsafe entry %s", path)
		}
		if info.IsDir() {
			if rel != "." {
				items = append(items, item{kind: "d", path: rel})
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special entry %s", path)
		}
		digest, err := digestPrivateRegular(path)
		if err != nil {
			return err
		}
		items = append(items, item{kind: "f", path: rel, digest: digest})
		regularFiles++
		return nil
	})
	if err != nil {
		return "", err
	}
	if regularFiles == 0 {
		return "", fmt.Errorf("tree is empty")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	hash := sha256.New()
	for _, item := range items {
		_, _ = io.WriteString(hash, item.kind+"\x00"+item.path+"\x00"+item.digest+"\x00")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyLegacyRegular(source, destination string, mode os.FileMode) error {
	return copyVerifiedRegular(source, destination, mode, nil)
}

func copyLegacyTree(source, destination string) error {
	if _, err := digestPrivateTree(source); err != nil {
		return err
	}
	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		return copyLegacyRegular(path, target, 0o600)
	})
}

func switchRelativeSymlink(root, name, target string) error {
	if filepath.IsAbs(target) || !strings.HasPrefix(filepath.ToSlash(target), "releases/") || strings.Contains(target, "..") {
		return fmt.Errorf("invalid release symlink target")
	}
	temporary := filepath.Join(root, "."+name+".new")
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(root, name)); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(root)
}

// ActivateRelease atomically advances current after first preserving the old
// complete cohort as previous. The ordering makes a crash safe: previous is
// durable before current can change.
func ActivateRelease(root, releaseID string) error {
	if !filepath.IsAbs(root) || !journalIdentifierExpr.MatchString(releaseID) {
		return fmt.Errorf("invalid release activation identity")
	}
	targetDir := filepath.Join(root, "releases", releaseID)
	if err := validateManagedReleaseDir(targetDir, releaseID); err != nil {
		return fmt.Errorf("%w: activation target is unavailable", ErrArtifactUnsafe)
	}
	current, err := activeReleaseID(root, "current")
	if err != nil {
		return err
	}
	if current == releaseID {
		return nil
	}
	if err := switchRelativeSymlink(root, "previous", filepath.Join("releases", current)); err != nil {
		return err
	}
	return switchRelativeSymlink(root, "current", filepath.Join("releases", releaseID))
}

// ActivatePrevious rolls current back to the preserved previous cohort. The
// failed release ID comes from the signed intent/journal, never a path. If a
// crash occurs after current changes, a replay restores previous to that known
// failed release without guessing.
func ActivatePrevious(root, failedReleaseID string) error {
	if !filepath.IsAbs(root) || !journalIdentifierExpr.MatchString(failedReleaseID) {
		return fmt.Errorf("invalid rollback identity")
	}
	failedDir := filepath.Join(root, "releases", failedReleaseID)
	if err := validateManagedReleaseDir(failedDir, failedReleaseID); err != nil {
		return fmt.Errorf("%w: failed release evidence is unavailable", ErrArtifactUnsafe)
	}
	current, err := activeReleaseID(root, "current")
	if err != nil {
		return err
	}
	previous, err := activeReleaseID(root, "previous")
	if err != nil {
		return fmt.Errorf("rollback unavailable without a complete previous cohort: %w", err)
	}
	if current != failedReleaseID {
		// A fully switched rollback is already complete. If only current changed
		// before a crash, previous still points at the now-active old release and
		// this replay finishes the second pointer update.
		if previous == failedReleaseID {
			return nil
		}
		if previous == current {
			return switchRelativeSymlink(root, "previous", filepath.Join("releases", failedReleaseID))
		}
		return fmt.Errorf("rollback layout differs from journal identity")
	}
	if previous == failedReleaseID {
		return fmt.Errorf("rollback previous release equals failed release")
	}
	if err := validateManagedReleaseDir(filepath.Join(root, "releases", previous), previous); err != nil {
		return fmt.Errorf("rollback previous cohort is incomplete: %w", err)
	}
	if err := switchRelativeSymlink(root, "current", filepath.Join("releases", previous)); err != nil {
		return err
	}
	return switchRelativeSymlink(root, "previous", filepath.Join("releases", failedReleaseID))
}

func validateManagedReleaseDir(dir, releaseID string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("release directory is mutable or indirect")
	}
	for _, rel := range []string{"mailserverd", "authserverd", "mailctl", filepath.Join("webmail", "index.html")} {
		entry, err := os.Lstat(filepath.Join(dir, rel))
		if err != nil || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || entry.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("release is missing private regular %s", rel)
		}
	}
	if evidence, err := readAdoptionEvidence(dir); err == nil {
		if evidence.ReleaseID != releaseID {
			return fmt.Errorf("adoption evidence release ID differs")
		}
		return verifyAdoptionArtifacts(dir, evidence)
	}
	// dir and each fixed required artifact were validated above as a real,
	// non-group-writable managed release cohort.
	//nolint:gosec // G304: no caller-controlled filename is read.
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("release has no adoption or manifest evidence")
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil || manifest.ReleaseID != releaseID {
		return fmt.Errorf("release manifest identity differs")
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canonical)
	//nolint:gosec // G304: manifest.digest is a fixed file in the validated managed release cohort.
	digestRaw, err := os.ReadFile(filepath.Join(dir, "manifest.digest"))
	if err != nil || strings.TrimSpace(string(digestRaw)) != hex.EncodeToString(sum[:]) {
		return fmt.Errorf("release manifest digest evidence differs")
	}
	return verifyInstalledReleaseEvidence(dir, releaseID, hex.EncodeToString(sum[:]))
}

func activeReleaseID(root, name string) (string, error) {
	path := filepath.Join(root, name)
	target, err := os.Readlink(path)
	if err != nil {
		return "", err
	}
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) || filepath.Dir(clean) != "releases" || !journalIdentifierExpr.MatchString(filepath.Base(clean)) {
		return "", fmt.Errorf("%w: %s symlink target is unsafe", ErrArtifactUnsafe, name)
	}
	info, err := os.Lstat(filepath.Join(root, clean))
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: %s release target is unavailable", ErrArtifactUnsafe, name)
	}
	return filepath.Base(clean), nil
}

func readAdoptionEvidence(dir string) (*AdoptionEvidence, error) {
	path := filepath.Join(dir, "adoption.json")
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read adoption evidence: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !singleLink(info) || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("invalid adoption evidence file")
	}
	// path is the fixed adoption filename and was just lstat-checked as a
	// private, single-link regular file.
	//nolint:gosec // G304: no caller-controlled filename is read.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read adoption evidence: %w", err)
	}
	var evidence AdoptionEvidence
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&evidence); err != nil || requireJSONEOF(decoder) != nil || evidence.SchemaVersion != 1 || evidence.DatabaseSchema < 1 || !journalIdentifierExpr.MatchString(evidence.ReleaseID) || !journalDigestExpr.MatchString(evidence.ConfigSHA256) || len(evidence.Artifacts) < 4 || len(evidence.Artifacts) > 5 {
		return nil, fmt.Errorf("invalid adoption evidence")
	}
	required := []string{"authserverd", "mailctl", "mailserverd", "webmail"}
	if len(evidence.Artifacts) == 5 {
		required = append(required, gatewayArtifact)
	}
	for _, name := range required {
		if !journalDigestExpr.MatchString(evidence.Artifacts[name]) {
			return nil, fmt.Errorf("invalid adoption artifact evidence")
		}
	}
	return &evidence, nil
}

func verifyAdoptionArtifacts(dir string, evidence *AdoptionEvidence) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	want := map[string]bool{"adoption.json": true, "authserverd": true, "mailctl": true, "mailserverd": true, "webmail": true}
	if _, ok := evidence.Artifacts[gatewayArtifact]; ok {
		want[gatewayArtifact] = true
	}
	if len(entries) != len(want) {
		return fmt.Errorf("adopted release inventory differs")
	}
	for _, entry := range entries {
		if !want[entry.Name()] {
			return fmt.Errorf("adopted release has undeclared entry %s", entry.Name())
		}
	}
	for _, name := range cohortBinaries(evidence.Artifacts) {
		digest, err := digestPrivateRegular(filepath.Join(dir, name))
		if err != nil || digest != evidence.Artifacts[name] {
			return fmt.Errorf("adopted release %s content differs", name)
		}
	}
	digest, err := digestPrivateTree(filepath.Join(dir, "webmail"))
	if err != nil || digest != evidence.Artifacts["webmail"] {
		return fmt.Errorf("adopted release webmail content differs")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}

func readCurrentLayoutEvidence(dir, configPath string) (*AdoptionEvidence, error) {
	if evidence, err := readAdoptionEvidence(dir); err == nil {
		if err := verifyAdoptionArtifacts(dir, evidence); err != nil {
			return nil, err
		}
		return evidence, nil
	} else if !errors.Is(errorCause(err), os.ErrNotExist) {
		return nil, err
	}
	// dir is a validated current release cohort and manifest.json is fixed.
	//nolint:gosec // G304: no caller-controlled filename is read.
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("managed release lacks adoption or manifest evidence: %w", err)
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil || manifest.ReleaseID != filepath.Base(dir) {
		return nil, fmt.Errorf("managed release manifest identity is invalid")
	}
	artifacts := map[string]string{}
	for _, name := range []string{"authserverd", "mailctl", "mailserverd"} {
		digest, err := digestPrivateRegular(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("managed release %s: %w", name, err)
		}
		artifacts[name] = digest
	}
	if err := addOptionalGateway(artifacts, dir); err != nil {
		return nil, fmt.Errorf("managed release %s: %w", gatewayArtifact, err)
	}
	webmailDigest, err := digestPrivateTree(filepath.Join(dir, "webmail"))
	if err != nil {
		return nil, fmt.Errorf("managed release webmail: %w", err)
	}
	artifacts["webmail"] = webmailDigest
	configDigest, err := digestPrivateRegular(configPath)
	if err != nil {
		return nil, fmt.Errorf("managed release config evidence: %w", err)
	}
	return &AdoptionEvidence{SchemaVersion: 1, ReleaseID: manifest.ReleaseID, DatabaseSchema: manifest.SchemaTo, ConfigSHA256: configDigest, Artifacts: artifacts}, nil
}

func errorCause(err error) error {
	for err != nil {
		next := errors.Unwrap(err)
		if next == nil {
			return err
		}
		err = next
	}
	return nil
}

func quarantineLegacyPrevious(options AdoptionOptions) error {
	var present []string
	for _, name := range []string{"authserverd.prev", "mailctl.prev", "mailserverd.prev", gatewayArtifact + ".prev", "webmail.prev"} {
		if _, err := os.Lstat(filepath.Join(options.InstallRoot, name)); err == nil {
			present = append(present, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if len(present) == 0 {
		return nil
	}
	if err := ensureSecureDirectory(options.QuarantineDir, 0o700); err != nil {
		return err
	}
	for _, name := range present {
		destination := filepath.Join(options.QuarantineDir, name)
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("legacy quarantine destination already exists for %s", name)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(filepath.Join(options.InstallRoot, name), destination); err != nil {
			return err
		}
		if err := adoptionBoundary(options, "quarantined_"+name); err != nil {
			return err
		}
	}
	return syncDirectory(options.QuarantineDir)
}

func adoptionBoundary(options AdoptionOptions, name string) error {
	if options.Boundary != nil {
		return options.Boundary(name)
	}
	return nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
