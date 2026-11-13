package contractvectors

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

func TestRecordRelease(t *testing.T) {
	type vector struct {
		Name   string `json:"name"`
		Input  any    `json:"input"`
		Output any    `json:"output"`
	}
	digest := strings.Repeat("a", 64)
	m := &release.Manifest{
		SchemaVersion: 1, ReleaseID: "release-2.1.0", Version: "2.1.0", Channel: release.ChannelCommunity,
		PublishedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-08-08T00:00:00Z", MetadataVersion: 7, PreviousVersionFloor: "2.0.0",
		Platforms: []string{"linux"}, Architectures: []string{"amd64"},
		Compatibility: release.Compatibility{SourceVersionRange: ">=2.0.0 <2.1.0", PostgresRange: ">=16.0.0 <19.0.0", MinimumClient: "1.5.0"},
		SchemaFrom:    177, SchemaTo: 178,
		Artifacts: []release.Artifact{
			{ID: "attestation-provenance", Class: release.ArtifactProvenance, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/vnd.in-toto+json", Cohort: "evidence", Target: release.TargetProvenance},
			{ID: "attestation-sbom", Class: release.ArtifactSBOM, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/spdx+json", Cohort: "evidence", Target: release.TargetSBOM},
			{ID: "authserverd", Class: release.ArtifactAuthserver, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetAuthserver},
			{ID: "mailctl", Class: release.ArtifactMailctl, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetMailctl},
			{ID: "mailserverd", Class: release.ArtifactMailserver, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetMailserver},
			{ID: "migration-v178", Class: release.ArtifactMigration, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/sql", Cohort: "core", Target: release.TargetMigrations},
			{ID: "recovery-guide", Class: release.ArtifactRecoveryGuide, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "text/markdown", Cohort: "evidence", Target: release.TargetRecoveryGuide},
			{ID: "webmail", Class: release.ArtifactWebmail, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/zstd", Cohort: "core", Target: release.TargetWebmail},
		},
		Migrations:  []release.Migration{{ID: "migration-v178", FromSchema: 177, ToSchema: 178, SHA256: digest, Class: release.MigrationExpand, CompatibilityEvidence: "ci-old-binary-2.0.0", TransactionRequired: true, PreviousBinaryEvidence: "ci-rollback-2.0.0"}},
		HealthGates: release.HealthGates{Preflight: []string{"disk_space"}, Readiness: []string{"gateway_ready"}, Data: []string{"mail_round_trip"}, PostCommit: []string{"worker_round_trip"}},
		Recovery:    release.RecoveryRequirements{MaximumAgeSeconds: 86400, MinimumFreeBytes: 1024},
		Notes:       release.ReleaseNotes{Summary: "Test release <stable>", DowntimeMaximumSec: 30, SupportChannel: "community"},
		Signing:     release.SigningPolicy{Threshold: 1}, Signatures: []release.Signature{},
	}
	// A public deterministic fixture key, never a production credential.
	key := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	signer := release.Ed25519Signer{ID: "fixture-key", PrivateKey: key}
	unsigned, err := release.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := release.SignManifest(context.Background(), m, signer); err != nil {
		t.Fatal(err)
	}
	signed, err := release.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	store, err := release.NewTrustStore([]release.TrustedKey{{ID: "fixture-key", Purpose: release.PurposeRelease, PublicKey: key.Public().(ed25519.PublicKey)}}, false)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawStdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	now := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	cases := []vector{{"sign_manifest", map[string]any{"operation": "sign_manifest", "document": string(unsigned), "seed_utf8": "0123456789abcdef0123456789abcdef", "key_id": "fixture-key"}, map[string]any{"document": string(signed)}}}
	for _, c := range []struct {
		name, document string
		at             time.Time
		minimum        int
	}{
		{"signed_manifest", string(signed), now, 1},
		{"whitespace", " \n" + string(signed) + "\n", now, 1},
		{"expiry_boundary", string(signed), time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC), 1},
		{"verifier_threshold", string(signed), now, 2},
		{"tampered_version", strings.Replace(string(signed), `"version":"2.1.0"`, `"version":"2.1.1"`, 1), now, 1},
		{"unknown_field", strings.Replace(string(signed), `"schema_version":1`, `"schema_version":1,"unexpected":true`, 1), now, 1},
		{"duplicate_key", strings.Replace(string(signed), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), now, 1},
		{"malformed_json", `{`, now, 1},
	} {
		verified, verifyErr := store.VerifyManifest([]byte(c.document), release.VerifyManifestOptions{Now: c.at, MinimumThreshold: c.minimum})
		output := map[string]any{"accepted": verifyErr == nil}
		if verifyErr != nil {
			output["error"] = verifyErr.Error()
		} else {
			output["canonical"] = string(verified.CanonicalBytes)
			output["sha256"] = verified.Digest
			output["signer_key_ids"] = verified.SignerKeyIDs
		}
		cases = append(cases, vector{c.name, map[string]any{"operation": "verify_manifest", "document": c.document, "public_key_base64": publicKey, "key_id": "fixture-key", "now": c.at.Format(time.RFC3339), "minimum_threshold": c.minimum}, output})
	}
	for _, c := range []struct {
		name, content, expectedSHA string
		size                       uint64
	}{
		{"artifact_sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 3},
		{"artifact_hash_mismatch", "abd", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 3},
		{"artifact_size_mismatch", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 4},
	} {
		artifact := release.Artifact{ID: "fixture", SHA256: c.expectedSHA, Size: c.size}
		verifyErr := release.VerifyArtifact(strings.NewReader(c.content), artifact)
		output := map[string]any{"accepted": verifyErr == nil}
		if verifyErr != nil {
			output["error"] = verifyErr.Error()
		}
		cases = append(cases, vector{c.name, map[string]any{"operation": "verify_artifact", "content_utf8": c.content, "sha256": c.expectedSHA, "size": c.size}, output})
	}
	writeVectors(t, "release", cases)
}
