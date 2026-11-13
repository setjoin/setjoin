package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"setjoin.com/shared/release"
)

var ErrReleaseUnavailable = errors.New("verified release tree is unavailable")

// ReleaseStore resolves immutable, publisher-verified release trees. It never
// accepts an operator-supplied filesystem path.
type ReleaseStore struct {
	root        string
	requiredUID *uint32
}

func OpenReleaseStore(root string) (*ReleaseStore, error) {
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("release store root must be absolute")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("stat release store: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("release store must be a real directory not writable by group or world")
	}
	return &ReleaseStore{root: root}, nil
}

// OpenReleaseStoreOwnedBy adds the production ownership boundary. Tests use
// OpenReleaseStore because their temporary files are intentionally unprivileged.
func OpenReleaseStoreOwnedBy(root string, uid uint32) (*ReleaseStore, error) {
	store, err := OpenReleaseStore(root)
	if err != nil {
		return nil, err
	}
	store.requiredUID = &uid
	info, err := os.Lstat(root)
	if err != nil || !ownedBy(info, uid) {
		return nil, fmt.Errorf("release store owner differs from required uid %d", uid)
	}
	return store, nil
}

// VerifyTree binds an intent's release ID and manifest digest to the exact
// immutable manifest at <root>/<release-id>/manifest.json.
func (store *ReleaseStore) VerifyTree(releaseID, manifestDigest string) (*release.Manifest, error) {
	if !journalIdentifierExpr.MatchString(releaseID) || !journalDigestExpr.MatchString(manifestDigest) {
		return nil, fmt.Errorf("invalid release identity")
	}
	dir := filepath.Join(store.root, releaseID)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReleaseUnavailable, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: release tree is mutable or indirect", ErrReleaseUnavailable)
	}
	if store.requiredUID != nil && !ownedBy(info, *store.requiredUID) {
		return nil, fmt.Errorf("%w: release tree owner differs", ErrReleaseUnavailable)
	}
	path := filepath.Join(dir, "manifest.json")
	manifestInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReleaseUnavailable, err)
	}
	if !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 ||
		manifestInfo.Mode().Perm()&0o022 != 0 || manifestInfo.Size() > release.MaxDocumentBytes || !singleLink(manifestInfo) {
		return nil, fmt.Errorf("%w: manifest is not a bounded regular file", ErrReleaseUnavailable)
	}
	if store.requiredUID != nil && !ownedBy(manifestInfo, *store.requiredUID) {
		return nil, fmt.Errorf("%w: manifest owner differs", ErrReleaseUnavailable)
	}
	// path is the fixed manifest filename below a validated release ID and was
	// just lstat-checked as a bounded, private, single-link regular file.
	//nolint:gosec // G304: no request-controlled filesystem path is opened.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReleaseUnavailable, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, release.MaxDocumentBytes+1))
	if err != nil || len(data) > release.MaxDocumentBytes {
		return nil, fmt.Errorf("%w: manifest read failed or exceeded limit", ErrReleaseUnavailable)
	}
	manifest, err := release.ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReleaseUnavailable, err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: canonical manifest failed: %v", ErrReleaseUnavailable, err)
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != manifestDigest {
		return nil, fmt.Errorf("%w: canonical manifest digest differs", ErrReleaseUnavailable)
	}
	if manifest.ReleaseID != releaseID {
		return nil, fmt.Errorf("%w: manifest release ID differs", ErrReleaseUnavailable)
	}
	// The DB catalog's digest binding is necessary but not sufficient
	// (release-store trust boundary): the signed freshness commitment is
	// re-checked against the wall clock on EVERY use, so an expired (or
	// not-yet-valid) manifest can neither stage nor execute even when its
	// catalog row is still open. ParseManifest already proved both timestamps
	// are RFC3339 and that ExpiresAt is after PublishedAt.
	now := time.Now().UTC()
	published, _ := time.Parse(time.RFC3339, manifest.PublishedAt)
	expiresAt, _ := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if now.Before(published) {
		return nil, fmt.Errorf("%w: manifest is not yet valid (published_at %s)", ErrReleaseUnavailable, manifest.PublishedAt)
	}
	if !now.Before(expiresAt) {
		return nil, fmt.Errorf("%w: manifest expired at %s", ErrReleaseUnavailable, manifest.ExpiresAt)
	}
	return manifest, nil
}

func ownedBy(info os.FileInfo, uid uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid
}

func singleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
