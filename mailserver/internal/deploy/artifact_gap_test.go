package deploy

// Artifact-pin gap coverage: the digest validator's non-hex refusal, the pin
// table's precedence over the environment override, and the Go-side reference
// checksum gate (VerifySeaweedFSArchive) accept/reject behavior.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestValidateSeaweedFSDigestRejectsNonHex: a 64-character value that is not
// hex must be refused at resolution time — an install command keyed to it could
// never verify.
func TestValidateSeaweedFSDigestRejectsNonHex(t *testing.T) {
	nonHex := strings.Repeat("z", 64)
	err := validateSeaweedFSDigest(nonHex)
	if err == nil || !strings.Contains(err.Error(), "not hex") {
		t.Fatalf("validateSeaweedFSDigest(%q) = %v, want a not-hex refusal", nonHex, err)
	}
}

// TestResolveSeaweedFSSpecPrefersPinnedChecksumTable: the pin table is the
// authoritative source — it wins over DEPLOY_SEAWEEDFS_SHA256, its value is
// trimmed and lower-cased into the spec, and the URL stays version-pinned.
func TestResolveSeaweedFSSpecPrefersPinnedChecksumTable(t *testing.T) {
	tableDigest := strings.ToUpper(strings.Repeat("ab", 32))
	envDigest := strings.Repeat("cd", 32)
	t.Setenv(seaweedfsChecksumEnv, envDigest)

	orig := seaweedfsPinnedChecksums[pinnedSeaweedFSVersion]
	seaweedfsPinnedChecksums[pinnedSeaweedFSVersion] = "  " + tableDigest + "  "
	defer func() {
		if orig == "" {
			delete(seaweedfsPinnedChecksums, pinnedSeaweedFSVersion)
			return
		}
		seaweedfsPinnedChecksums[pinnedSeaweedFSVersion] = orig
	}()

	spec, err := resolveSeaweedFSSpec()
	if err != nil {
		t.Fatalf("resolveSeaweedFSSpec with a pin-table entry: %v", err)
	}
	if spec.ExpectedSHA256 != strings.ToLower(tableDigest) {
		t.Errorf("ExpectedSHA256 = %q, want the trimmed, lower-cased pin-table digest", spec.ExpectedSHA256)
	}
	if spec.Version != pinnedSeaweedFSVersion {
		t.Errorf("Version = %q, want the pinned version %q", spec.Version, pinnedSeaweedFSVersion)
	}
	if !strings.Contains(spec.URL, "/v"+pinnedSeaweedFSVersion+"/") || strings.Contains(spec.URL, "latest") {
		t.Errorf("URL = %q, want the version-pinned release URL without any latest reference", spec.URL)
	}
}

// TestVerifySeaweedFSArchiveAcceptsAndRejects pins the Go-side reference
// implementation of the checksum gate: byte-identical content passes, any
// other content (or a wrong digest) is refused.
func TestVerifySeaweedFSArchiveAcceptsAndRejects(t *testing.T) {
	archive := []byte("fake seaweedfs release tarball bytes")
	sum := sha256.Sum256(archive)
	want := hex.EncodeToString(sum[:])

	if err := VerifySeaweedFSArchive(archive, want); err != nil {
		t.Fatalf("matching archive rejected: %v", err)
	}
	if err := VerifySeaweedFSArchive(archive, strings.ToUpper(want)); err != nil {
		t.Fatalf("case-insensitive digest comparison failed: %v", err)
	}
	tampered := append([]byte(nil), archive...)
	tampered[0] ^= 0xFF
	err := VerifySeaweedFSArchive(tampered, want)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered archive = %v, want a checksum-mismatch refusal", err)
	}
}
