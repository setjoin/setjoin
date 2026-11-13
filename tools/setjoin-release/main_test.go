package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

func publisherDraft() *release.Manifest {
	artifacts := []release.Artifact{
		{ID: "attestation-provenance", Class: release.ArtifactProvenance, Platform: "linux", Architecture: "amd64", MediaType: "application/vnd.in-toto+json", Cohort: "evidence", Target: release.TargetProvenance},
		{ID: "attestation-sbom", Class: release.ArtifactSBOM, Platform: "linux", Architecture: "amd64", MediaType: "application/spdx+json", Cohort: "evidence", Target: release.TargetSBOM},
		{ID: "authserverd", Class: release.ArtifactAuthserver, Platform: "linux", Architecture: "amd64", MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetAuthserver},
		{ID: "mailctl", Class: release.ArtifactMailctl, Platform: "linux", Architecture: "amd64", MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetMailctl},
		{ID: "mailserverd", Class: release.ArtifactMailserver, Platform: "linux", Architecture: "amd64", MediaType: "application/octet-stream", Cohort: "core", Target: release.TargetMailserver},
		{ID: "migration-v178", Class: release.ArtifactMigration, Platform: "linux", Architecture: "amd64", MediaType: "application/sql", Cohort: "core", Target: release.TargetMigrations},
		{ID: "recovery-guide", Class: release.ArtifactRecoveryGuide, Platform: "linux", Architecture: "amd64", MediaType: "text/markdown", Cohort: "evidence", Target: release.TargetRecoveryGuide},
		{ID: "webmail", Class: release.ArtifactWebmail, Platform: "linux", Architecture: "amd64", MediaType: "application/zstd", Cohort: "core", Target: release.TargetWebmail},
	}
	return &release.Manifest{SchemaVersion: 1, ReleaseID: "release-2.1.0", Version: "2.1.0", Channel: release.ChannelCommunity, PublishedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-08-08T00:00:00Z", MetadataVersion: 7, PreviousVersionFloor: "2.0.0", Platforms: []string{"linux"}, Architectures: []string{"amd64"}, Compatibility: release.Compatibility{SourceVersionRange: ">=2.0.0 <2.1.0", PostgresRange: ">=16.0.0 <19.0.0"}, SchemaFrom: 177, SchemaTo: 178, Artifacts: artifacts, Migrations: []release.Migration{{ID: "migration-v178", FromSchema: 177, ToSchema: 178, Class: release.MigrationExpand, CompatibilityEvidence: "ci-old-binary-2.0.0", TransactionRequired: true, PreviousBinaryEvidence: "ci-rollback-2.0.0"}}, HealthGates: release.HealthGates{Preflight: []string{"disk_space"}, Readiness: []string{"gateway_ready"}, Data: []string{"mail_round_trip"}, PostCommit: []string{"worker_round_trip"}}, Recovery: release.RecoveryRequirements{MaximumAgeSeconds: 86400, MinimumFreeBytes: 1024}, Notes: release.ReleaseNotes{Summary: "Test release", DowntimeMaximumSec: 30, SupportChannel: "community"}, Signing: release.SigningPolicy{Threshold: 1}, Signatures: []release.Signature{}}
}

func writePublisherFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	artifacts := filepath.Join(dir, "artifacts")
	if err := os.Mkdir(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	draft := publisherDraft()
	for _, artifact := range draft.Artifacts {
		if err := os.WriteFile(filepath.Join(artifacts, artifact.ID), []byte("abc"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := json.Marshal(draft)
	draftPath := filepath.Join(dir, "draft.json")
	if err := os.WriteFile(draftPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return draftPath, artifacts
}

func TestBuildIsReproducibleAndInventoriesExactBytes(t *testing.T) {
	draft, artifacts := writePublisherFixture(t)
	out1 := filepath.Join(t.TempDir(), "one.json")
	out2 := filepath.Join(t.TempDir(), "two.json")
	args := func(out string) []string {
		return []string{"--draft", draft, "--artifacts-dir", artifacts, "--output", out}
	}
	if err := runBuild(args(out1)); err != nil {
		t.Fatal(err)
	}
	if err := runBuild(args(out2)); err != nil {
		t.Fatal(err)
	}
	one, _ := os.ReadFile(out1)
	two, _ := os.ReadFile(out2)
	if string(one) != string(two) {
		t.Fatal("identical publisher inputs produced different manifests")
	}
	manifest, err := release.ParseManifest(one)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Size != 3 || artifact.SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Fatalf("artifact=%#v", artifact)
		}
	}
}

func TestBuildRejectsSymlinkAndMissingAttestation(t *testing.T) {
	draft, artifacts := writePublisherFixture(t)
	if err := os.Remove(filepath.Join(artifacts, "mailctl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mailserverd", filepath.Join(artifacts, "mailctl")); err != nil {
		t.Fatal(err)
	}
	if err := runBuild([]string{"--draft", draft, "--artifacts-dir", artifacts, "--output", filepath.Join(t.TempDir(), "out.json")}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink error=%v", err)
	}
	draftManifest := publisherDraft()
	draftManifest.Artifacts = draftManifest.Artifacts[1:]
	raw, _ := json.Marshal(draftManifest)
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, raw, 0o644)
	if err := runBuild([]string{"--draft", bad, "--artifacts-dir", artifacts, "--output", filepath.Join(t.TempDir(), "bad-out.json")}); err == nil || !strings.Contains(err.Error(), "SBOM") {
		t.Fatalf("attestation error=%v", err)
	}
}

func TestSignerHelperFailureIsRedacted(t *testing.T) {
	_, err := helperSigner{path: "/private/secret/pin-123", keyID: "release-a"}.Sign(context.Background(), []byte("payload"))
	if err == nil {
		t.Fatal("missing helper succeeded")
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "pin-123") {
		t.Fatalf("signer error leaked descriptor: %v", err)
	}
}

func TestSignAndOfflineVerifyEndToEnd(t *testing.T) {
	draft, artifacts := writePublisherFixture(t)
	dir := t.TempDir()
	built := filepath.Join(dir, "built.json")
	signed := filepath.Join(dir, "signed.json")
	if err := runBuild([]string{"--draft", draft, "--artifacts-dir", artifacts, "--output", built}); err != nil {
		t.Fatal(err)
	}
	builtRaw, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := release.ParseManifest(builtRaw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := release.CanonicalManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// Dual-control fixture: the verifier enforces MinVerificationThreshold = 2
	// regardless of the manifest's self-declared Signing.Threshold (1 in the
	// draft), so an honestly dual-signed release is the minimal passing shape.
	// Canonical bytes exclude signatures, so the second helper signs the SAME
	// canonical document the first signed.
	seedA := bytes.Repeat([]byte{0x71}, ed25519.SeedSize)
	privateA := ed25519.NewKeyFromSeed(seedA)
	publicA := privateA.Public().(ed25519.PublicKey)
	seedB := bytes.Repeat([]byte{0x72}, ed25519.SeedSize)
	privateB := ed25519.NewKeyFromSeed(seedB)
	publicB := privateB.Public().(ed25519.PublicKey)
	sigA := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateA, canonical))
	sigB := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateB, canonical))
	helperA := filepath.Join(dir, "signer-helper-a")
	scriptA := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + sigA + "'\n"
	if err := os.WriteFile(helperA, []byte(scriptA), 0o700); err != nil {
		t.Fatal(err)
	}
	helperB := filepath.Join(dir, "signer-helper-b")
	scriptB := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + sigB + "'\n"
	if err := os.WriteFile(helperB, []byte(scriptB), 0o700); err != nil {
		t.Fatal(err)
	}
	signedA := filepath.Join(dir, "signed-a.json")
	if err := runSign([]string{"--manifest", built, "--signer-helper", helperA,
		"--key-id", "release-2026-a", "--output", signedA}); err != nil {
		t.Fatal(err)
	}
	if err := runSign([]string{"--manifest", signedA, "--signer-helper", helperB,
		"--key-id", "release-2026-b", "--output", signed}); err != nil {
		t.Fatal(err)
	}
	roots := release.TrustRootDocument{SchemaVersion: 1, Purpose: release.PurposeRelease,
		Keys: []release.TrustRootWire{{ID: "release-2026-a", Algorithm: "ed25519",
			PublicKey: base64.RawStdEncoding.EncodeToString(publicA)},
			{ID: "release-2026-b", Algorithm: "ed25519",
				PublicKey: base64.RawStdEncoding.EncodeToString(publicB)}}}
	rootsRaw, _ := json.Marshal(roots)
	rootsPath := filepath.Join(dir, "roots.json")
	if err := os.WriteFile(rootsPath, rootsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	priorNow := publisherNow
	publisherNow = func() time.Time { return time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { publisherNow = priorNow })
	verifyArgs := []string{"--offline", "--manifest", signed, "--artifacts-dir", artifacts,
		"--trust-roots", rootsPath, "--channel", "community", "--current-version", "2.0.5",
		"--platform", "linux", "--arch", "amd64"}
	// Floor pin (occ_ca6a33cce6cf9e18f41e3d51): the SAME manifest carrying only
	// ONE vendor signature is refused even though it self-declares Threshold 1 —
	// the verifier floor, not the manifest, is authoritative.
	singleVerifyArgs := []string{"--offline", "--manifest", signedA, "--artifacts-dir", artifacts,
		"--trust-roots", rootsPath, "--channel", "community", "--current-version", "2.0.5",
		"--platform", "linux", "--arch", "amd64"}
	if err := runVerify(singleVerifyArgs); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("self-lowered single-signer manifest accepted at the verifier floor: err=%v", err)
	}
	if err := runVerify(verifyArgs); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "mailctl"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runVerify(verifyArgs); err == nil || !strings.Contains(err.Error(), "artifact") {
		t.Fatalf("tampered offline bundle error=%v", err)
	}
	roots.Keys[0].TestOnly = true
	roots.Keys[1].TestOnly = true
	rootsRaw, _ = json.Marshal(roots)
	if err := os.WriteFile(rootsPath, rootsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runVerify(verifyArgs); err == nil || !strings.Contains(err.Error(), "test trust root") {
		t.Fatalf("fixture trust root error=%v", err)
	}
}
