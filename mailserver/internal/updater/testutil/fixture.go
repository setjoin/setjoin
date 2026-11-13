// Package testutil generates deterministic updater fixtures. Its trust root is
// marked TestOnly and is rejected by production release policy.
package testutil

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"time"

	"setjoin.com/shared/release"
)

const FixtureKeyID = "setjoin-updater-fixture-v1"

func SignedManifest(now time.Time, channel release.Channel) ([]byte, release.TrustedKey, error) {
	now = now.UTC().Truncate(time.Second)
	privateKey, trusted := fixtureSigner()
	digest := strings.Repeat("a", 64)
	artifact := func(id string, class release.ArtifactClass, target release.InstallTarget, cohort string) release.Artifact {
		return release.Artifact{ID: id, Class: class, Platform: "linux", Architecture: "amd64",
			Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: cohort, Target: target}
	}
	manifest := &release.Manifest{
		SchemaVersion: release.ManifestSchemaV1, ReleaseID: "fixture-2.1.0", Version: "2.1.0",
		Channel: channel, PublishedAt: now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), MetadataVersion: 1,
		PreviousVersionFloor: "2.0.0", Platforms: []string{"linux"}, Architectures: []string{"amd64"},
		Compatibility: release.Compatibility{SourceVersionRange: ">=2.0.0 <2.1.0", PostgresRange: ">=16.0.0 <19.0.0"},
		SchemaFrom:    178, SchemaTo: 178,
		Artifacts: []release.Artifact{
			artifact("attestation-provenance", release.ArtifactProvenance, release.TargetProvenance, "evidence"),
			artifact("attestation-sbom", release.ArtifactSBOM, release.TargetSBOM, "evidence"),
			artifact("authserverd", release.ArtifactAuthserver, release.TargetAuthserver, "core"),
			artifact("mailctl", release.ArtifactMailctl, release.TargetMailctl, "core"),
			artifact("mailserverd", release.ArtifactMailserver, release.TargetMailserver, "core"),
			artifact("recovery-guide", release.ArtifactRecoveryGuide, release.TargetRecoveryGuide, "evidence"),
			artifact("setjoin-gateway", release.ArtifactGateway, release.TargetGateway, "core"),
			artifact("webmail", release.ArtifactWebmail, release.TargetWebmail, "core"),
		},
		HealthGates: release.HealthGates{Preflight: []string{"disk_space"}, Readiness: []string{"gateway_ready"},
			Data: []string{"mail_round_trip"}, PostCommit: []string{"worker_round_trip"}},
		Recovery: release.RecoveryRequirements{MaximumAgeSeconds: 86400, MinimumFreeBytes: 1024},
		Notes:    release.ReleaseNotes{Summary: "Deterministic fixture release", DowntimeMaximumSec: 30, SupportChannel: string(channel)},
		Signing:  release.SigningPolicy{Threshold: 1},
	}
	if err := release.SignManifest(context.Background(), manifest,
		release.Ed25519Signer{ID: FixtureKeyID, PrivateKey: privateKey}); err != nil {
		return nil, release.TrustedKey{}, err
	}
	data, err := release.MarshalManifest(manifest)
	return data, trusted, err
}

func SignManifest(manifest *release.Manifest) (release.TrustedKey, error) {
	privateKey, trusted := fixtureSigner()
	if err := release.SignManifest(context.Background(), manifest,
		release.Ed25519Signer{ID: FixtureKeyID, PrivateKey: privateKey}); err != nil {
		return release.TrustedKey{}, err
	}
	return trusted, nil
}

func fixtureSigner() (ed25519.PrivateKey, release.TrustedKey) {
	seed := sha256.Sum256([]byte("setjoin updater public test fixture root v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey, release.TrustedKey{ID: FixtureKeyID, Purpose: release.PurposeRelease,
		PublicKey: privateKey.Public().(ed25519.PublicKey), TestOnly: true}
}
