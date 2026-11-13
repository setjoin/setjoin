package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Pinned SeaweedFS artifact (D-MAILSERVER-INTERNAL-DEPLOY-R-003).
//
// The deploy wizard previously installed SeaweedFS from the mutable
// "latest" GitHub release tarball piped straight into tar as root, with no
// version pin, checksum, or signature. That is an unauthenticated
// supply-chain path to root on every target node. The helpers here make the
// artifact a pinned, digest-verified object:
//
//   - pinnedSeaweedFSVersion is the only version the wizard will install; the
//     mutable "latest/download" URL is never generated.
//   - seaweedfsPinnedChecksums is the version→sha256 pin table (the eventual
//     home of the authoritative supply-chain decision: pinned GitHub release
//     vs signed mirror).
//   - Until a digest is recorded in the table, the operator-supplied
//     DEPLOY_SEAWEEDFS_SHA256 environment variable (same admin trust domain
//     as DEPLOY_HOST_KEY) may record the digest for the pinned version.
//   - With neither source, resolution fails CLOSED: installPackages returns
//     an error before any remote command runs, so nothing is executed as
//     root without a verified artifact.
//
// The generated remote command stages the download into a temp directory,
// verifies its sha256 against the pinned digest (sha256sum, with a shasum
// fallback), and only extracts/installs the weed binary after verification
// succeeds — mirroring mailserver/deploy/scripts/lib-livekit.sh.
const (
	// pinnedSeaweedFSVersion is the fixed SeaweedFS release the wizard installs.
	pinnedSeaweedFSVersion = "3.80"

	// seaweedfsReleaseAsset is the linux/amd64 release asset name.
	seaweedfsReleaseAsset = "linux_amd64.tar.gz"

	// seaweedfsChecksumEnv is the admin-set digest override for the pinned
	// version while the authoritative pin table entry is pending.
	seaweedfsChecksumEnv = "DEPLOY_SEAWEEDFS_SHA256"
)

// seaweedfsPinnedChecksums maps a pinned SeaweedFS version to the expected
// sha256 hex digest of its linux/amd64 release tarball. An entry here is the
// authoritative pin; installs refuse when neither this table nor
// DEPLOY_SEAWEEDFS_SHA256 provides a digest for the pinned version.
var seaweedfsPinnedChecksums = map[string]string{}

// seaweedfsInstallSpec describes the single artifact the wizard may install.
type seaweedfsInstallSpec struct {
	Version        string
	Asset          string
	URL            string
	ExpectedSHA256 string
}

// seaweedfsArtifactURL builds the version-pinned release URL. It never
// references the mutable "latest" release.
func seaweedfsArtifactURL(version string) string {
	return fmt.Sprintf("https://github.com/seaweedfs/seaweedfs/releases/download/v%s/%s",
		version, seaweedfsReleaseAsset)
}

// validateSeaweedFSDigest enforces a 64-character hex sha256 digest so a
// malformed pin fails at resolution time instead of producing an install
// command that can never verify.
func validateSeaweedFSDigest(digest string) error {
	if digest == "" {
		return fmt.Errorf("no pinned sha256 checksum recorded for SeaweedFS v%s — refusing to install an unverified artifact (record it in seaweedfsPinnedChecksums or set %s)",
			pinnedSeaweedFSVersion, seaweedfsChecksumEnv)
	}
	if len(digest) != 64 {
		return fmt.Errorf("pinned sha256 checksum for SeaweedFS v%s is malformed (want 64 hex chars, got %d)",
			pinnedSeaweedFSVersion, len(digest))
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("pinned sha256 checksum for SeaweedFS v%s is not hex: %w",
			pinnedSeaweedFSVersion, err)
	}
	return nil
}

// resolveSeaweedFSSpec returns the pinned artifact spec: the fixed version,
// its pinned download URL, and the expected sha256 digest. The pin table wins
// over the environment override. Resolution is fail-closed: an unresolvable
// or malformed digest is an error, and installPackages surfaces it before any
// remote root execution.
func resolveSeaweedFSSpec() (seaweedfsInstallSpec, error) {
	digest := ""
	if d, ok := seaweedfsPinnedChecksums[pinnedSeaweedFSVersion]; ok {
		digest = strings.TrimSpace(d)
	} else if d := strings.TrimSpace(os.Getenv(seaweedfsChecksumEnv)); d != "" {
		digest = d
	}
	if err := validateSeaweedFSDigest(digest); err != nil {
		return seaweedfsInstallSpec{}, err
	}
	return seaweedfsInstallSpec{
		Version:        pinnedSeaweedFSVersion,
		Asset:          seaweedfsReleaseAsset,
		URL:            seaweedfsArtifactURL(pinnedSeaweedFSVersion),
		ExpectedSHA256: strings.ToLower(digest),
	}, nil
}

// VerifySeaweedFSArchive is the Go-side reference implementation of the
// remote checksum gate: it hashes the archive bytes and compares them with
// expectedHex. It is the verification entry point for any non-SSH caller and
// the seam tests exercise with local fixture files (never downloads); the
// generated remote command performs the equivalent check before extraction.
func VerifySeaweedFSArchive(archive []byte, expectedHex string) error {
	sum := sha256.Sum256(archive)
	got := hex.EncodeToString(sum[:])
	if got != strings.ToLower(expectedHex) {
		return fmt.Errorf("seaweedfs archive checksum mismatch: expected %s, got %s — refusing to install",
			strings.ToLower(expectedHex), got)
	}
	return nil
}

// buildSeaweedFSInstallCommand resolves the pinned spec and renders the
// remote shell command that installs it. The command:
//
//  1. creates a temp staging dir with cleanup on exit,
//  2. downloads the version-pinned asset with curl -fsSL (fail on HTTP error,
//     never a "latest" URL, never piped straight into tar),
//  3. refuses (exit 1) unless the downloaded archive's sha256 equals the
//     pinned digest — before any extraction,
//  4. only then extracts the weed binary into the staging dir and installs it
//     at /usr/local/bin/weed with mode 0755.
func buildSeaweedFSInstallCommand() (string, error) {
	spec, err := resolveSeaweedFSSpec()
	if err != nil {
		return "", err
	}
	tarball := "$weedTmp/" + spec.Asset
	return "weedTmp=$(mktemp -d) && trap 'rm -rf \"$weedTmp\"' EXIT && " +
		"curl -fsSL -o " + tarball + " " + spec.URL + " && " +
		"if command -v sha256sum >/dev/null 2>&1; then weedGot=$(sha256sum " + tarball + " | cut -d' ' -f1); " +
		"else weedGot=$(shasum -a 256 " + tarball + " | cut -d' ' -f1); fi && " +
		"if [ \"$weedGot\" != \"" + spec.ExpectedSHA256 + "\" ]; then " +
		"echo \"seaweedfs v" + spec.Version + " checksum mismatch: expected " + spec.ExpectedSHA256 + ", got $weedGot — refusing to install\" >&2; exit 1; fi && " +
		"tar -xzf " + tarball + " -C \"$weedTmp\" weed && " +
		"install -m 0755 \"$weedTmp/weed\" /usr/local/bin/weed", nil
}
