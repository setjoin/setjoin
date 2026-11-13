package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testManifest() *Manifest {
	digest := strings.Repeat("a", 64)
	return &Manifest{
		SchemaVersion: ManifestSchemaV1, ReleaseID: "release-2.1.0", Version: "2.1.0", Channel: ChannelCommunity,
		PublishedAt: "2026-08-01T00:00:00Z", ExpiresAt: "2026-08-08T00:00:00Z", MetadataVersion: 7, PreviousVersionFloor: "2.0.0",
		Platforms: []string{"linux"}, Architectures: []string{"amd64"},
		Compatibility: Compatibility{SourceVersionRange: ">=2.0.0 <2.1.0", PostgresRange: ">=16.0.0 <19.0.0", MinimumClient: "1.5.0"},
		SchemaFrom:    177, SchemaTo: 178,
		Artifacts: []Artifact{
			{ID: "attestation-provenance", Class: ArtifactProvenance, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/vnd.in-toto+json", Cohort: "evidence", Target: TargetProvenance},
			{ID: "attestation-sbom", Class: ArtifactSBOM, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/spdx+json", Cohort: "evidence", Target: TargetSBOM},
			{ID: "authserverd", Class: ArtifactAuthserver, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: TargetAuthserver},
			{ID: "mailctl", Class: ArtifactMailctl, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: TargetMailctl},
			{ID: "mailserverd", Class: ArtifactMailserver, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/octet-stream", Cohort: "core", Target: TargetMailserver},
			{ID: "migration-v178", Class: ArtifactMigration, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/sql", Cohort: "core", Target: TargetMigrations},
			{ID: "recovery-guide", Class: ArtifactRecoveryGuide, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "text/markdown", Cohort: "evidence", Target: TargetRecoveryGuide},
			{ID: "webmail", Class: ArtifactWebmail, Platform: "linux", Architecture: "amd64", Size: 3, SHA256: digest, MediaType: "application/zstd", Cohort: "core", Target: TargetWebmail},
		},
		Migrations:  []Migration{{ID: "migration-v178", FromSchema: 177, ToSchema: 178, SHA256: digest, Class: MigrationExpand, CompatibilityEvidence: "ci-old-binary-2.0.0", TransactionRequired: true, PreviousBinaryEvidence: "ci-rollback-2.0.0"}},
		HealthGates: HealthGates{Preflight: []string{"disk_space"}, Readiness: []string{"gateway_ready"}, Data: []string{"mail_round_trip"}, PostCommit: []string{"worker_round_trip"}},
		Recovery:    RecoveryRequirements{MaximumAgeSeconds: 86400, MinimumFreeBytes: 1024},
		Notes:       ReleaseNotes{Summary: "Test release", DowntimeMaximumSec: 30, SupportChannel: "community"},
		Signing:     SigningPolicy{Threshold: 1}, Signatures: []Signature{},
	}
}

func TestTrustRootDocumentIsStrictAndProductionRejectsFixtureKeys(t *testing.T) {
	key, _ := keypairForFuzz()
	document := TrustRootDocument{SchemaVersion: 1, Purpose: PurposeEntitlement, Keys: []TrustRootWire{{ID: key.ID, Algorithm: "ed25519", PublicKey: base64.RawStdEncoding.EncodeToString(key.PublicKey)}}}
	data, _ := json.Marshal(document)
	keys, err := ParseTrustRootDocument(data, PurposeEntitlement, false)
	if err != nil || len(keys) != 1 || keys[0].Purpose != PurposeEntitlement {
		t.Fatalf("keys=%#v err=%v", keys, err)
	}
	document.Keys[0].TestOnly = true
	data, _ = json.Marshal(document)
	if _, err := ParseTrustRootDocument(data, PurposeEntitlement, false); err == nil {
		t.Fatal("production accepted test root")
	}
	unknown := bytes.Replace(data, []byte(`"purpose":"entitlement"`), []byte(`"purpose":"entitlement","credential":"secret"`), 1)
	if _, err := ParseTrustRootDocument(unknown, PurposeEntitlement, true); err == nil {
		t.Fatal("unknown trust-root field accepted")
	}
}

func keypair(t *testing.T, id string, purpose KeyPurpose, testOnly bool) (TrustedKey, Ed25519Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return TrustedKey{ID: id, Purpose: purpose, PublicKey: pub, TestOnly: testOnly}, Ed25519Signer{ID: id, PrivateKey: priv}
}

func signedManifest(t *testing.T, m *Manifest, signers ...Ed25519Signer) []byte {
	t.Helper()
	for _, signer := range signers {
		if err := SignManifest(context.Background(), m, signer); err != nil {
			t.Fatal(err)
		}
	}
	data, err := MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestManifestStrictParsingAndCanonicalSignature(t *testing.T) {
	key, signer := keypair(t, "release-2026-a", PurposeRelease, false)
	store, err := NewTrustStore([]TrustedKey{key}, false)
	if err != nil {
		t.Fatal(err)
	}
	data := signedManifest(t, testManifest(), signer)
	verified, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), Channel: ChannelCommunity, CurrentVersion: "2.0.5", Platform: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Manifest.ReleaseID != "release-2.1.0" || len(verified.SignerKeyIDs) != 1 {
		t.Fatalf("verified = %#v", verified)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unknown"] = true
	unknown, _ := json.Marshal(raw)
	if _, err := ParseManifest(unknown); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
	duplicate := bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
	if _, err := ParseManifest(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate error = %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"version":"2.1.0"`), []byte(`"version":"2.1.1"`), 1)
	if _, err := store.VerifyManifest(tampered, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

func TestManifestThresholdReplayAndFixtureRootPolicy(t *testing.T) {
	k1, s1 := keypair(t, "release-a", PurposeRelease, false)
	k2, s2 := keypair(t, "release-b", PurposeRelease, false)
	m := testManifest()
	m.Signing.Threshold = 2
	data := signedManifest(t, m, s1)
	store, _ := NewTrustStore([]TrustedKey{k1, k2}, false)
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)}); err == nil {
		t.Fatal("one of two signatures accepted")
	}
	data = signedManifest(t, m, s2)
	verified, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), LastMetadataVersion: 8}); err == nil {
		t.Fatal("metadata rollback accepted")
	}
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), LastMetadataVersion: 7, LastMetadataDigest: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("equivocation accepted")
	}
	fixture, _ := keypair(t, "fixture-root", PurposeRelease, true)
	if _, err := NewTrustStore([]TrustedKey{fixture}, false); err == nil {
		t.Fatal("production store accepted fixture root")
	}
	_ = verified
}

// TestManifestSelfLoweredThresholdNeedsVerifierFloor pins the
// manifest-controlled-threshold closure (occ_ca6a33cce6cf9e18f41e3d51):
// Signing.Threshold is manifest-authored, so the self-lowered case — a single
// signer declaring Threshold 1 — is only defeated by the verifier-side policy
// floor (VerifyManifestOptions.MinimumThreshold >= MinVerificationThreshold).
// The floor must reject the self-lowered manifest, must never reject a
// honestly dual-signed one, and must never be satisfiable below two vendor
// keys for a production trust domain.
func TestManifestSelfLoweredThresholdNeedsVerifierFloor(t *testing.T) {
	if MinVerificationThreshold < 1 || MinVerificationThreshold > 8 {
		t.Fatalf("MinVerificationThreshold = %d outside the schema range 1..8", MinVerificationThreshold)
	}

	baseTime := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)

	// A manifest that self-declares the minimum threshold and carries exactly
	// one signature — the single-compromised-key shape.
	k1, s1 := keypair(t, "release-a", PurposeRelease, false)
	k2, s2 := keypair(t, "release-b", PurposeRelease, false)
	store, _ := NewTrustStore([]TrustedKey{k1, k2}, false)
	data := signedManifest(t, testManifest(), s1) // Signing.Threshold = 1

	// Documented residual: with a zero floor the declared value is the only
	// requirement, so one signature passes — the declared threshold is never
	// authority by itself.
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: baseTime}); err != nil {
		t.Fatalf("zero-floor verification unexpectedly rejected: %v", err)
	}

	// The policy floor closes it: two are required, one is not enough.
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: baseTime, MinimumThreshold: MinVerificationThreshold}); err == nil {
		t.Fatal("self-lowered single-signer manifest accepted at the verification floor")
	}

	// A second independent signature satisfies the floor (no floor-induced DoS
	// for honestly dual-signed releases).
	dual := signedManifest(t, testManifest(), s1, s2)
	if _, err := store.VerifyManifest(dual, VerifyManifestOptions{Now: baseTime, MinimumThreshold: MinVerificationThreshold}); err != nil {
		t.Fatalf("dual-signed manifest rejected at the floor: %v", err)
	}

	// Same-signature double counting is impossible: a second signature from
	// the SAME key is refused at signing time.
	one := testManifest()
	signedManifest(t, one, s1)
	if err := SignManifest(context.Background(), one, s1); err == nil {
		t.Fatal("duplicate signature from one key accepted")
	}
	if _, err := store.VerifyManifest(dual, VerifyManifestOptions{Now: baseTime, MinimumThreshold: 3}); err == nil {
		t.Fatal("threshold floor above signer count accepted")
	}
}

func TestManifestRejectsUnsafeMigrationAndCoreSkew(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"contract migration":          func(m *Manifest) { m.Migrations[0].Class = MigrationContract },
		"nontransactional migration":  func(m *Manifest) { m.Migrations[0].TransactionRequired = false },
		"missing old binary evidence": func(m *Manifest) { m.Migrations[0].PreviousBinaryEvidence = "" },
		"partial core cohort":         func(m *Manifest) { m.Artifacts = m.Artifacts[:3] },
		"missing recovery guide":      func(m *Manifest) { m.Artifacts = append(m.Artifacts[:6], m.Artifacts[7:]...) },
		"duplicate fixed target":      func(m *Manifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[2]) },
		"path-like artifact":          func(m *Manifest) { m.Artifacts[0].ID = "../authserverd" },
	} {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(m)
			if err := m.Validate(); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}

func TestManifestFeatureRegistryContractIsSignedAndStrict(t *testing.T) {
	digest := strings.Repeat("a", 64)
	m := testManifest()
	m.SchemaFrom, m.SchemaTo = 183, 183
	m.Migrations = nil
	// The migration artifact no longer belongs in a no-op schema cohort.
	m.Artifacts = append(m.Artifacts[:5], m.Artifacts[6:]...)
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "feature registry") {
		t.Fatalf("schema 183 without registry contract error=%v", err)
	}
	m.FeatureRegistry = &FeatureRegistryContract{
		CatalogDigest: digest, CompatibleModes: []string{"enforce", "observe"},
		CompatibleRollbackDigests: []string{digest},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("valid feature registry contract: %v", err)
	}
	for name, mutate := range map[string]func(*FeatureRegistryContract){
		"catalog digest":   func(c *FeatureRegistryContract) { c.CatalogDigest = "bad" },
		"modes empty":      func(c *FeatureRegistryContract) { c.CompatibleModes = nil },
		"modes unknown":    func(c *FeatureRegistryContract) { c.CompatibleModes = []string{"observe", "shadow"} },
		"modes unsorted":   func(c *FeatureRegistryContract) { c.CompatibleModes = []string{"observe", "enforce"} },
		"observe omitted":  func(c *FeatureRegistryContract) { c.CompatibleModes = []string{"enforce"} },
		"rollback empty":   func(c *FeatureRegistryContract) { c.CompatibleRollbackDigests = nil },
		"rollback invalid": func(c *FeatureRegistryContract) { c.CompatibleRollbackDigests = []string{"bad"} },
		"rollback duplicate": func(c *FeatureRegistryContract) {
			c.CompatibleRollbackDigests = []string{digest, digest}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneManifest(t, m)
			mutate(candidate.FeatureRegistry)
			if err := candidate.Validate(); err == nil {
				t.Fatal("malformed feature registry contract accepted")
			}
		})
	}
}

func cloneManifest(t *testing.T, source *Manifest) *Manifest {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copy Manifest
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestManifestValidationRejectsEveryMalformedTopLevelContract(t *testing.T) {
	t.Parallel()
	if err := (*Manifest)(nil).Validate(); err == nil {
		t.Fatal("nil manifest accepted")
	}
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"schema", func(m *Manifest) { m.SchemaVersion = 2 }},
		{"release id", func(m *Manifest) { m.ReleaseID = "/release" }},
		{"version", func(m *Manifest) { m.Version = "v2" }},
		{"channel", func(m *Manifest) { m.Channel = "preview" }},
		{"published", func(m *Manifest) { m.PublishedAt = "2026-08-01T00:00:00+00:00" }},
		{"expires", func(m *Manifest) { m.ExpiresAt = "tomorrow" }},
		{"time order", func(m *Manifest) { m.ExpiresAt = m.PublishedAt }},
		{"metadata", func(m *Manifest) { m.MetadataVersion = 0 }},
		{"previous floor", func(m *Manifest) { m.PreviousVersionFloor = "2" }},
		{"platform invalid", func(m *Manifest) { m.Platforms = []string{"linux/amd64"} }},
		{"platform order", func(m *Manifest) { m.Platforms = []string{"z", "a"} }},
		{"architecture empty", func(m *Manifest) { m.Architectures = nil }},
		{"source range", func(m *Manifest) { m.Compatibility.SourceVersionRange = "" }},
		{"postgres range", func(m *Manifest) { m.Compatibility.PostgresRange = "not-semver" }},
		{"minimum client", func(m *Manifest) { m.Compatibility.MinimumClient = "latest" }},
		{"schema negative", func(m *Manifest) { m.SchemaFrom = -1 }},
		{"schema reversed", func(m *Manifest) { m.SchemaTo = m.SchemaFrom - 1 }},
		{"artifacts empty", func(m *Manifest) { m.Artifacts = nil }},
		{"artifacts excessive", func(m *Manifest) { m.Artifacts = make([]Artifact, 257) }},
		{"recovery zero", func(m *Manifest) { m.Recovery.MaximumAgeSeconds = 0 }},
		{"recovery excessive", func(m *Manifest) { m.Recovery.MaximumAgeSeconds = uint64((31 * 24 * time.Hour) / time.Second) }},
		{"downtime", func(m *Manifest) { m.Notes.DowntimeMinimumSec, m.Notes.DowntimeMaximumSec = 2, 1 }},
		{"notes empty", func(m *Manifest) { m.Notes.Summary = "" }},
		{"notes summary", func(m *Manifest) { m.Notes.Summary = strings.Repeat("x", 4097) }},
		{"notes support", func(m *Manifest) { m.Notes.SupportChannel = strings.Repeat("x", 257) }},
		{"threshold low", func(m *Manifest) { m.Signing.Threshold = 0 }},
		{"threshold high", func(m *Manifest) { m.Signing.Threshold = 9 }},
		{"rotation ids", func(m *Manifest) { m.Signing.RotationKeyIDs = []string{"b", "a"} }},
		{"signature count", func(m *Manifest) { m.Signatures = make([]Signature, 17) }},
		{"signature id", func(m *Manifest) { m.Signatures = []Signature{{KeyID: "/", Algorithm: "ed25519", Value: "x"}} }},
		{"signature algorithm", func(m *Manifest) { m.Signatures = []Signature{{KeyID: "key", Algorithm: "rsa", Value: "x"}} }},
		{"signature empty", func(m *Manifest) { m.Signatures = []Signature{{KeyID: "key", Algorithm: "ed25519"}} }},
		{"signature duplicate", func(m *Manifest) {
			m.Signatures = []Signature{{KeyID: "key", Algorithm: "ed25519", Value: "x"}, {KeyID: "key", Algorithm: "ed25519", Value: "y"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneManifest(t, testManifest())
			tc.mutate(m)
			if err := m.Validate(); err == nil {
				t.Fatal("malformed manifest accepted")
			}
		})
	}
}

func TestManifestValidationRejectsEveryArtifactAndMigrationContract(t *testing.T) {
	t.Parallel()
	artifactCases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"dot id", func(m *Manifest) { m.Artifacts[0].ID = "." }},
		{"duplicate id", func(m *Manifest) { m.Artifacts[1].ID = m.Artifacts[0].ID }},
		{"unsorted", func(m *Manifest) { m.Artifacts[0], m.Artifacts[1] = m.Artifacts[1], m.Artifacts[0] }},
		{"size", func(m *Manifest) { m.Artifacts[0].Size = 0 }},
		{"digest", func(m *Manifest) { m.Artifacts[0].SHA256 = "bad" }},
		{"media empty", func(m *Manifest) { m.Artifacts[0].MediaType = "" }},
		{"media long", func(m *Manifest) { m.Artifacts[0].MediaType = strings.Repeat("x", 129) }},
		{"platform", func(m *Manifest) { m.Artifacts[0].Platform = "darwin" }},
		{"architecture", func(m *Manifest) { m.Artifacts[0].Architecture = "arm64" }},
		{"target", func(m *Manifest) { m.Artifacts[0].Target = TargetSBOM }},
		{"fixed target", func(m *Manifest) {
			copy := m.Artifacts[2]
			copy.ID = "authservere"
			m.Artifacts = append(m.Artifacts[:3], append([]Artifact{copy}, m.Artifacts[3:]...)...)
		}},
		{"cohort", func(m *Manifest) { m.Artifacts[0].Cohort = "/" }},
		{"compatibility", func(m *Manifest) { m.Artifacts[0].CompatibleWithCore = "bad" }},
		{"sidecar compatibility", func(m *Manifest) {
			sidecar := Artifact{ID: "sidecar", Class: ArtifactSidecar, Platform: "linux", Architecture: "amd64", Size: 1, SHA256: strings.Repeat("a", 64), MediaType: "application/octet-stream", Cohort: "sidecars", Target: TargetSidecar}
			m.Artifacts = append(m.Artifacts, sidecar)
		}},
		{"missing core", func(m *Manifest) { m.Artifacts[2].Cohort = "other" }},
		{"missing sbom", func(m *Manifest) { m.Artifacts = append(m.Artifacts[:1], m.Artifacts[2:]...) }},
		{"missing provenance", func(m *Manifest) { m.Artifacts = m.Artifacts[1:] }},
		{"missing guide", func(m *Manifest) { m.Artifacts = append(m.Artifacts[:6], m.Artifacts[7:]...) }},
	}
	for _, tc := range artifactCases {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneManifest(t, testManifest())
			tc.mutate(m)
			if err := m.Validate(); err == nil {
				t.Fatal("malformed artifact inventory accepted")
			}
		})
	}

	migrationCases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"excessive", func(m *Manifest) { m.Migrations = make([]Migration, 257) }},
		{"id", func(m *Manifest) { m.Migrations[0].ID = "/" }},
		{"order", func(m *Manifest) { m.Migrations[0].FromSchema = 176 }},
		{"to source", func(m *Manifest) { m.Migrations[0].ToSchema = 177 }},
		{"to beyond", func(m *Manifest) { m.Migrations[0].ToSchema = 179 }},
		{"digest", func(m *Manifest) { m.Migrations[0].SHA256 = "bad" }},
		{"class", func(m *Manifest) { m.Migrations[0].Class = MigrationContract }},
		{"compat evidence", func(m *Manifest) { m.Migrations[0].CompatibilityEvidence = "" }},
		{"previous evidence", func(m *Manifest) { m.Migrations[0].PreviousBinaryEvidence = "" }},
		{"transaction", func(m *Manifest) { m.Migrations[0].TransactionRequired = false }},
		{"artifact match", func(m *Manifest) { m.Migrations[0].ID = "migration-v179" }},
		{"chain end", func(m *Manifest) { m.Migrations = nil }},
	}
	for _, tc := range migrationCases {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneManifest(t, testManifest())
			tc.mutate(m)
			if err := m.Validate(); err == nil {
				t.Fatal("malformed migration inventory accepted")
			}
		})
	}
}

func TestManifestValidationRejectsEveryHealthGateContract(t *testing.T) {
	t.Parallel()
	cases := []func(*Manifest){
		func(m *Manifest) { m.HealthGates.Preflight = nil },
		func(m *Manifest) { m.HealthGates.Readiness = make([]string, 33) },
		func(m *Manifest) { m.HealthGates.Data = []string{"z", "a"} },
		func(m *Manifest) { m.HealthGates.PostCommit = []string{"UPPER"} },
	}
	for i, mutate := range cases {
		m := cloneManifest(t, testManifest())
		mutate(m)
		if err := m.Validate(); err == nil {
			t.Fatalf("malformed health gate %d accepted", i)
		}
	}
}

func TestManifestDraftRequiresPublisherOwnedHashes(t *testing.T) {
	m := testManifest()
	for i := range m.Artifacts {
		m.Artifacts[i].Size = 0
		m.Artifacts[i].SHA256 = ""
	}
	for i := range m.Migrations {
		m.Migrations[i].SHA256 = ""
	}
	raw, _ := json.Marshal(m)
	if _, err := ParseManifestDraft(raw); err != nil {
		t.Fatal(err)
	}
	m.Artifacts[0].SHA256 = strings.Repeat("f", 64)
	raw, _ = json.Marshal(m)
	if _, err := ParseManifestDraft(raw); err == nil {
		t.Fatal("draft accepted caller-provided artifact digest")
	}
}

func TestSemanticVersionRangeAndOverflow(t *testing.T) {
	for _, tc := range []struct {
		v, r string
		want bool
	}{{"2.0.0", ">=2.0.0 <3.0.0", true}, {"3.0.0", ">=2.0.0 <3.0.0", false}, {"2.0.0-beta.2", ">=2.0.0-beta.1 <2.0.0", true}} {
		got, err := VersionInRange(tc.v, tc.r)
		if err != nil || got != tc.want {
			t.Fatalf("%s in %s = %v,%v", tc.v, tc.r, got, err)
		}
	}
	if _, err := ParseVersion("18446744073709551616.0.0"); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestSemanticVersionComparisonAndRangeBoundaries(t *testing.T) {
	t.Parallel()
	comparisons := []struct {
		left, right string
		want        int
	}{
		{"1.0.0", "2.0.0", -1}, {"2.0.0", "1.0.0", 1},
		{"1.1.0", "1.2.0", -1}, {"1.2.0", "1.1.0", 1},
		{"1.0.1", "1.0.2", -1}, {"1.0.2", "1.0.1", 1},
		{"1.0.0", "1.0.0", 0}, {"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.1", "1.0.0", -1}, {"1.0.0-1", "1.0.0-2", -1},
		{"1.0.0-a", "1.0.0-1", 1}, {"1.0.0-1", "1.0.0-a", -1},
		{"1.0.0-a", "1.0.0-b", -1}, {"1.0.0-b", "1.0.0-a", 1},
		{"1.0.0-a", "1.0.0-a.1", -1}, {"1.0.0-a.1", "1.0.0-a", 1},
	}
	for _, tc := range comparisons {
		left, err := ParseVersion(tc.left)
		if err != nil {
			t.Fatal(err)
		}
		right, err := ParseVersion(tc.right)
		if err != nil {
			t.Fatal(err)
		}
		if got := left.Compare(right); got != tc.want {
			t.Fatalf("%s compare %s=%d want %d", tc.left, tc.right, got, tc.want)
		}
	}
	for _, raw := range []string{"1.0.0-01", "", "1.0", "1.0.0+build"} {
		if _, err := ParseVersion(raw); err == nil {
			t.Fatalf("invalid version %q accepted", raw)
		}
	}
	for _, tc := range []struct {
		version, constraint string
		want                bool
	}{
		{"2.0.0", "=2.0.0", true}, {"2.0.1", "=2.0.0", false},
		{"2.0.1", ">2.0.0", true}, {"2.0.0", ">2.0.0", false},
		{"2.0.0", ">=2.0.0", true}, {"1.9.9", ">=2.0.0", false},
		{"1.9.9", "<2.0.0", true}, {"2.0.0", "<2.0.0", false},
		{"2.0.0", "<=2.0.0", true}, {"2.0.1", "<=2.0.0", false},
	} {
		got, err := VersionInRange(tc.version, tc.constraint)
		if err != nil || got != tc.want {
			t.Fatalf("%q in %q=%t err=%v", tc.version, tc.constraint, got, err)
		}
	}
	if _, err := VersionInRange("bad", ">=1.0.0"); err == nil {
		t.Fatal("bad candidate accepted")
	}
	if _, err := VersionInRange("1.0.0", ""); err == nil {
		t.Fatal("empty range accepted")
	}
	if err := ValidateVersionRange("1.0.0 2.0.0 3.0.0 4.0.0 5.0.0"); err == nil {
		t.Fatal("five constraints accepted")
	}
}

func TestCheckCompatibilityRejectsEveryMismatch(t *testing.T) {
	t.Parallel()
	base := LocalState{Version: "2.0.5", SchemaVersion: 177, Platform: "linux", Architecture: "amd64", Channel: ChannelCommunity, LastMetadataVersion: 7}
	if err := CheckCompatibility(testManifest(), base); err != nil {
		t.Fatal(err)
	}
	cases := []func(*Manifest, *LocalState){
		func(_ *Manifest, s *LocalState) { s.Channel = ChannelEnterprise },
		func(_ *Manifest, s *LocalState) { s.Platform = "darwin" },
		func(_ *Manifest, s *LocalState) { s.Architecture = "arm64" },
		func(_ *Manifest, s *LocalState) { s.Version = "3.0.0" },
		func(_ *Manifest, s *LocalState) { s.SchemaVersion = 176 },
		func(m *Manifest, s *LocalState) { m.Channel = ChannelEnterprise; s.Channel = ChannelEnterprise },
		func(_ *Manifest, s *LocalState) { s.LastMetadataVersion = 8 },
		func(m *Manifest, _ *LocalState) { m.SchemaVersion = 2 },
	}
	for i, mutate := range cases {
		m := cloneManifest(t, testManifest())
		s := base
		mutate(m, &s)
		if err := CheckCompatibility(m, s); err == nil {
			t.Fatalf("mismatch %d accepted", i)
		}
	}
	enterprise := cloneManifest(t, testManifest())
	enterprise.Channel = ChannelEnterprise
	s := base
	s.Channel, s.AllowEnterprise = ChannelEnterprise, true
	if err := CheckCompatibility(enterprise, s); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyArtifactSizeAndDigest(t *testing.T) {
	good := Artifact{ID: "artifact", Size: 3, SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
	if err := VerifyArtifact(strings.NewReader("abc"), good); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(strings.NewReader("abcd"), good); err == nil {
		t.Fatal("extra bytes accepted")
	}
	bad := good
	bad.SHA256 = strings.Repeat("0", 64)
	if err := VerifyArtifact(strings.NewReader("abc"), bad); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	if err := VerifyArtifact(nil, good); err == nil {
		t.Fatal("nil artifact reader accepted")
	}
	invalid := good
	invalid.Size = 0
	if err := VerifyArtifact(strings.NewReader("abc"), invalid); err == nil {
		t.Fatal("zero artifact size accepted")
	}
	if err := VerifyArtifact(strings.NewReader("ab"), good); err == nil {
		t.Fatal("short artifact accepted")
	}
}

func testEntitlement() *Entitlement {
	return &Entitlement{SchemaVersion: EntitlementSchemaV1, EntitlementID: "ent-1", InstallationID: "install-1", CustomerID: "customer-1", Channels: []Channel{ChannelEnterprise}, VersionRanges: []string{">=2.0.0 <3.0.0"}, IssuedAt: "2026-08-01T00:00:00Z", ValidFrom: "2026-08-01T00:00:00Z", ValidUntil: "2026-08-31T00:00:00Z", GraceUntil: "2026-09-07T00:00:00Z", NonProductionRights: []string{"dr", "staging"}, KeyID: "entitlement-a"}
}

func TestEntitlementScopeGraceAndSeatExclusions(t *testing.T) {
	key, signer := keypair(t, "entitlement-a", PurposeEntitlement, false)
	e := testEntitlement()
	if err := SignEntitlement(e, signer); err != nil {
		t.Fatal(err)
	}
	data, err := MarshalEntitlement(e)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewTrustStore([]TrustedKey{key}, false)
	verified, err := store.VerifyEntitlement(data, "install-1", ChannelEnterprise, "2.4.0", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || verified.State != EntitlementGrace {
		t.Fatalf("grace = %#v, %v", verified, err)
	}
	if _, err := store.VerifyEntitlement(data, "wrong", ChannelEnterprise, "2.4.0", time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("wrong installation accepted")
	}
	if _, err := store.VerifyEntitlement(data, "install-1", ChannelEnterprise, "2.4.0", time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expired entitlement accepted")
	}
	seats := CountBillableSeats([]SeatSubject{{Enabled: true, InternalHuman: true}, {Enabled: false, InternalHuman: true}, {Enabled: true, InternalHuman: true, MailboxlessGuest: true}, {Enabled: true, InternalHuman: true, SharedOrResource: true}, {Enabled: true, InternalHuman: true, Alias: true}, {Enabled: true, InternalHuman: true, ServicePrincipal: true}})
	if seats != 1 {
		t.Fatalf("billable seats=%d", seats)
	}
}

func cloneEntitlement(t *testing.T, source *Entitlement) *Entitlement {
	t.Helper()
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var copy Entitlement
	if err := json.Unmarshal(raw, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestEntitlementValidationAndVerificationRejectEveryInvalidBoundary(t *testing.T) {
	t.Parallel()
	if err := (*Entitlement)(nil).ValidateUnsigned(); err == nil {
		t.Fatal("nil entitlement accepted")
	}
	unsignedCases := []func(*Entitlement){
		func(e *Entitlement) { e.SchemaVersion = 2 },
		func(e *Entitlement) { e.EntitlementID = "/" },
		func(e *Entitlement) { e.InstallationID = "" },
		func(e *Entitlement) { e.CustomerID = "customer/1" },
		func(e *Entitlement) { e.KeyID = "" },
		func(e *Entitlement) { e.Channels = nil },
		func(e *Entitlement) { e.Channels = []Channel{ChannelEnterprise, ChannelEnterprise, ChannelEnterprise} },
		func(e *Entitlement) { e.Channels = []Channel{ChannelCommunity} },
		func(e *Entitlement) { e.Channels = []Channel{ChannelEnterprise, ChannelEnterprise} },
		func(e *Entitlement) { e.VersionRanges = nil },
		func(e *Entitlement) { e.VersionRanges = make([]string, 17) },
		func(e *Entitlement) { e.VersionRanges = []string{"bad"} },
		func(e *Entitlement) { e.IssuedAt = "bad" },
		func(e *Entitlement) { e.ValidFrom = "bad" },
		func(e *Entitlement) { e.ValidUntil = "bad" },
		func(e *Entitlement) { e.GraceUntil = "bad" },
		func(e *Entitlement) { e.ValidFrom = "2026-07-31T00:00:00Z" },
		func(e *Entitlement) { e.ValidUntil = e.ValidFrom },
		func(e *Entitlement) { e.GraceUntil = "2026-08-30T00:00:00Z" },
		func(e *Entitlement) { e.NonProductionRights = []string{"staging", "dr"} },
	}
	for i, mutate := range unsignedCases {
		e := cloneEntitlement(t, testEntitlement())
		mutate(e)
		if err := e.ValidateUnsigned(); err == nil {
			t.Fatalf("invalid unsigned entitlement %d accepted", i)
		}
	}
	for i, signatures := range [][]Signature{
		nil,
		{{KeyID: "other", Algorithm: "ed25519", Value: "x"}},
		{{KeyID: "entitlement-a", Algorithm: "rsa", Value: "x"}},
		{{KeyID: "entitlement-a", Algorithm: "ed25519", Value: ""}},
		{{KeyID: "entitlement-a", Algorithm: "ed25519", Value: "x"}, {KeyID: "entitlement-a", Algorithm: "ed25519", Value: "x"}},
	} {
		e := cloneEntitlement(t, testEntitlement())
		e.Signatures = signatures
		if err := e.Validate(); err == nil {
			t.Fatalf("invalid signature shape %d accepted", i)
		}
	}

	key, signer := keypair(t, "entitlement-a", PurposeEntitlement, false)
	e := testEntitlement()
	if err := SignEntitlement(e, signer); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalEntitlement(e)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]TrustedKey{key}, false)
	if err != nil {
		t.Fatal(err)
	}
	validTime := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	if _, err := store.VerifyEntitlement(raw, "install-1", ChannelEnterprise, "", validTime); err == nil {
		t.Fatal("missing version accepted")
	}
	if _, err := store.VerifyEntitlementDocument(raw, "install-1", ChannelCommunity, validTime); err == nil {
		t.Fatal("community entitlement accepted")
	}
	if _, err := store.VerifyEntitlement(raw, "install-1", ChannelEnterprise, "3.0.0", validTime); err == nil {
		t.Fatal("version mismatch accepted")
	}
	if _, err := store.VerifyEntitlement(raw, "install-1", ChannelEnterprise, "2.1.0", time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("future entitlement accepted")
	}

	wrongPurpose, _ := keypair(t, "entitlement-a", PurposeRelease, false)
	wrongStore, _ := NewTrustStore([]TrustedKey{wrongPurpose}, false)
	if _, err := wrongStore.VerifyEntitlementDocument(raw, "install-1", ChannelEnterprise, validTime); err == nil {
		t.Fatal("wrong-purpose key accepted")
	}
	tampered := bytes.Replace(raw, []byte(`"customer_id":"customer-1"`), []byte(`"customer_id":"customer-2"`), 1)
	if _, err := store.VerifyEntitlementDocument(tampered, "install-1", ChannelEnterprise, validTime); err == nil {
		t.Fatal("tampered entitlement accepted")
	}

	badSigner := Ed25519Signer{ID: "other", PrivateKey: signer.PrivateKey}
	if err := SignEntitlement(testEntitlement(), badSigner); err == nil {
		t.Fatal("mismatched entitlement signer accepted")
	}
	badSigner = Ed25519Signer{ID: "entitlement-a"}
	if err := SignEntitlement(testEntitlement(), badSigner); err == nil {
		t.Fatal("invalid entitlement private key accepted")
	}
}

type failingSigner struct {
	id        string
	signature []byte
	err       error
}

func (s failingSigner) KeyID() string                                { return s.id }
func (s failingSigner) Sign(context.Context, []byte) ([]byte, error) { return s.signature, s.err }

func TestTrustStoreAndManifestVerificationRejectEveryTrustBoundary(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	invalidStores := [][]TrustedKey{
		{{ID: "/", Purpose: PurposeRelease, PublicKey: pub}},
		{{ID: "key", Purpose: PurposeRelease, PublicKey: []byte("short")}},
		{{ID: "key", Purpose: "future", PublicKey: pub}},
		{{ID: "key", Purpose: PurposeRelease, PublicKey: pub}, {ID: "key", Purpose: PurposeRelease, PublicKey: pub}},
	}
	for i, keys := range invalidStores {
		if _, err := NewTrustStore(keys, false); err == nil {
			t.Fatalf("invalid trust store %d accepted", i)
		}
	}

	key, signer := keypair(t, "release-a", PurposeRelease, false)
	store, _ := NewTrustStore([]TrustedKey{key}, false)
	baseTime := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	data := signedManifest(t, testManifest(), signer)
	verifyCases := []VerifyManifestOptions{
		{Now: time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)},
		{Now: time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)},
		{Now: baseTime, Channel: ChannelEnterprise},
		{Now: baseTime, Platform: "darwin"},
		{Now: baseTime, Architecture: "arm64"},
		{Now: baseTime, CurrentVersion: "3.0.0"},
		{Now: baseTime, CurrentVersion: "1.9.9"},
		{Now: baseTime, MinimumThreshold: 2},
	}
	for i, options := range verifyCases {
		if _, err := store.VerifyManifest(data, options); err == nil {
			t.Fatalf("invalid verify options %d accepted", i)
		}
	}

	unknownStore, _ := NewTrustStore(nil, false)
	if _, err := unknownStore.VerifyManifest(data, VerifyManifestOptions{Now: baseTime}); err == nil {
		t.Fatal("unknown signature accepted")
	}
	tamperedSig := cloneManifest(t, testManifest())
	tamperedSig.Signatures = []Signature{{KeyID: "release-a", Algorithm: "ed25519", Value: base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize))}}
	tamperedRaw, _ := MarshalManifest(tamperedSig)
	if _, err := store.VerifyManifest(tamperedRaw, VerifyManifestOptions{Now: baseTime}); err == nil {
		t.Fatal("invalid signature accepted")
	}

	orgKey, orgSigner := keypair(t, "org-a", PurposeOrganization, false)
	orgKey.OrganizationArtifactSet = map[ArtifactClass]bool{ArtifactRecoveryGuide: true}
	noRepackRaw := signedManifest(t, cloneManifest(t, testManifest()), signer, orgSigner)
	orgStore, _ := NewTrustStore([]TrustedKey{key, orgKey}, false)
	if _, err := orgStore.VerifyManifest(noRepackRaw, VerifyManifestOptions{Now: baseTime}); err == nil {
		t.Fatal("organization signature with no vendor-authorized repack accepted")
	}
	orgManifest := cloneManifest(t, testManifest())
	for i := range orgManifest.Artifacts {
		if orgManifest.Artifacts[i].Class == ArtifactRecoveryGuide {
			orgManifest.Artifacts[i].OrganizationRepack = true
		}
	}
	orgRaw := signedManifest(t, orgManifest, signer, orgSigner)
	orgKey.OrganizationArtifactSet = map[ArtifactClass]bool{ArtifactSidecar: true}
	orgStore, _ = NewTrustStore([]TrustedKey{key, orgKey}, false)
	if _, err := orgStore.VerifyManifest(orgRaw, VerifyManifestOptions{Now: baseTime}); err == nil {
		t.Fatal("unauthorized organization artifact class accepted")
	}
	orgKey.OrganizationArtifactSet = map[ArtifactClass]bool{ArtifactRecoveryGuide: true}
	orgStore, _ = NewTrustStore([]TrustedKey{key, orgKey}, false)
	if _, err := orgStore.VerifyManifest(orgRaw, VerifyManifestOptions{Now: baseTime}); err != nil {
		t.Fatal(err)
	}

	if err := SignManifest(context.Background(), testManifest(), nil); err == nil {
		t.Fatal("nil signer accepted")
	}
	if err := SignManifest(context.Background(), testManifest(), failingSigner{id: "/"}); err == nil {
		t.Fatal("invalid signer id accepted")
	}
	m := testManifest()
	if err := SignManifest(context.Background(), m, signer); err != nil {
		t.Fatal(err)
	}
	if err := SignManifest(context.Background(), m, signer); err == nil {
		t.Fatal("duplicate signer accepted")
	}
	if err := SignManifest(context.Background(), testManifest(), failingSigner{id: "release-a", err: context.Canceled}); err == nil {
		t.Fatal("signer failure accepted")
	}
	if err := SignManifest(context.Background(), testManifest(), failingSigner{id: "release-a", signature: []byte("short")}); err == nil {
		t.Fatal("short signature accepted")
	}
}

func TestStrictDocumentsAndTrustRootsRejectMalformedInputs(t *testing.T) {
	t.Parallel()
	var dst map[string]any
	for _, raw := range [][]byte{
		nil,
		bytes.Repeat([]byte("x"), MaxDocumentBytes+1),
		[]byte(`{"a":1} {"b":2}`),
		[]byte(`{"a":{"b":1,"b":2}}`),
		[]byte(`{"a":[{"b":1,"b":2}]}`),
		[]byte(`{"a":[1,2}`),
	} {
		if err := strictDecode(raw, &dst); err == nil {
			t.Fatalf("malformed JSON accepted: %.32q", raw)
		}
	}
	if _, err := ParseManifest([]byte(`{`)); err == nil {
		t.Fatal("malformed manifest accepted")
	}
	if _, err := ParseEntitlement([]byte(`{`)); err == nil {
		t.Fatal("malformed entitlement accepted")
	}

	_, signer := keypair(t, "entitlement-a", PurposeEntitlement, false)
	e := testEntitlement()
	if _, err := CanonicalEntitlement(e); err != nil {
		t.Fatal(err)
	}
	if _, err := MarshalEntitlement(e); err == nil {
		t.Fatal("unsigned entitlement marshaled")
	}
	m := testManifest()
	if _, err := CanonicalManifest(m); err != nil {
		t.Fatal(err)
	}
	m.SchemaVersion = 2
	if _, err := CanonicalManifest(m); err == nil {
		t.Fatal("invalid manifest canonicalized")
	}
	if _, err := MarshalManifest(m); err == nil {
		t.Fatal("invalid manifest marshaled")
	}
	_ = signer

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	valid := TrustRootDocument{SchemaVersion: 1, Purpose: PurposeRelease, Keys: []TrustRootWire{{ID: "release-a", Algorithm: "ed25519", PublicKey: base64.RawStdEncoding.EncodeToString(pub)}}}
	rootCases := []func(*TrustRootDocument){
		func(d *TrustRootDocument) { d.SchemaVersion = 2 },
		func(d *TrustRootDocument) { d.Purpose = PurposeEntitlement },
		func(d *TrustRootDocument) { d.Keys = nil },
		func(d *TrustRootDocument) { d.Keys = make([]TrustRootWire, 17) },
		func(d *TrustRootDocument) { d.Keys[0].ID = "/" },
		func(d *TrustRootDocument) { d.Keys[0].Algorithm = "rsa" },
		func(d *TrustRootDocument) { d.Keys = append(d.Keys, d.Keys[0]) },
		func(d *TrustRootDocument) { d.Keys[0].PublicKey = "bad" },
	}
	for i, mutate := range rootCases {
		d := valid
		d.Keys = append([]TrustRootWire(nil), valid.Keys...)
		mutate(&d)
		raw, _ := json.Marshal(d)
		if _, err := ParseTrustRootDocument(raw, PurposeRelease, false); err == nil {
			t.Fatalf("invalid root document %d accepted", i)
		}
	}
	if got := wirePurpose(PurposeOrganization); got != PurposeOrganization {
		t.Fatalf("wire purpose=%s", got)
	}
}

func TestTrustPurposeSeparation(t *testing.T) {
	for _, purpose := range []KeyPurpose{PurposeRecovery, PurposeAuditChain, PurposeOfflineUpdate} {
		t.Run(string(purpose), func(t *testing.T) {
			key, _ := keypair(t, "purpose-key", purpose, false)
			store, err := NewTrustStore([]TrustedKey{key}, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := store.keys[key.ID]; !ok {
				t.Fatal("purpose-specific key missing from trust store")
			}
		})
	}
}

func TestDetachedVerificationEnforcesPurposeKeyAndSignature(t *testing.T) {
	key, privateKey := keypair(t, "recovery-key", PurposeRecovery, false)
	store, err := NewTrustStore([]TrustedKey{key}, false)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("recovery-head")
	rawSignature, err := privateKey.Sign(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawStdEncoding.EncodeToString(rawSignature)
	if err := store.VerifyDetached(PurposeRecovery, key.ID, message, signature); err != nil {
		t.Fatalf("valid detached signature: %v", err)
	}
	for _, tc := range []struct {
		purpose   KeyPurpose
		keyID     string
		message   []byte
		signature string
	}{
		{PurposeAuditChain, key.ID, message, signature},
		{PurposeRecovery, "missing", message, signature},
		{PurposeRecovery, key.ID, []byte("tampered"), signature},
		{PurposeRecovery, key.ID, message, "not-base64"},
	} {
		if err := store.VerifyDetached(tc.purpose, tc.keyID, tc.message, tc.signature); err == nil {
			t.Fatalf("invalid detached case accepted: %+v", tc)
		}
	}
	if _, err := store.VerifyManifestForPurpose([]byte(`{}`), VerifyManifestOptions{}, PurposeRecovery); err == nil {
		t.Fatal("unsupported manifest purpose accepted")
	}
}

func TestCanonicalAndDuplicateKeyScannerErrorBoundaries(t *testing.T) {
	for _, raw := range [][]byte{[]byte("x"), []byte("]"), []byte("{} x")} {
		if err := rejectDuplicateJSONKeys(raw); err == nil {
			t.Fatalf("malformed token stream accepted: %q", raw)
		}
	}
	e := testEntitlement()
	e.SchemaVersion = 2
	if _, err := CanonicalEntitlement(e); err == nil {
		t.Fatal("invalid entitlement canonicalized")
	}
}

func TestEntitlementParseChannelClockAndSigningFailures(t *testing.T) {
	invalid := testEntitlement()
	invalid.SchemaVersion = 2
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEntitlement(raw); err == nil {
		t.Fatal("structurally valid but semantically invalid entitlement parsed")
	}
	invalid.Signatures = []Signature{{KeyID: invalid.KeyID, Algorithm: "ed25519", Value: "x"}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid unsigned fields passed signed validation")
	}

	key, signer := keypair(t, "entitlement-a", PurposeEntitlement, false)
	e := testEntitlement()
	if err := SignEntitlement(e, signer); err != nil {
		t.Fatal(err)
	}
	raw, err = MarshalEntitlement(e)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]TrustedKey{key}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyEntitlementDocument([]byte("{"), "install-1", ChannelEnterprise, time.Now()); err == nil {
		t.Fatal("malformed entitlement verified")
	}
	if _, err := store.VerifyEntitlementDocument(raw, "install-1", Channel("future"), time.Now()); err == nil {
		t.Fatal("out-of-scope channel verified")
	}
	// A zero verification clock evaluates against real wall-clock time, so the
	// shared fixture's fixed 2026-08 window expires (this test becomes a time
	// bomb). Re-pin THIS case's window relative to now before signing.
	now := time.Now().UTC()
	e.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339)
	e.ValidFrom = now.Add(-time.Hour).Format(time.RFC3339)
	e.ValidUntil = now.Add(24 * time.Hour).Format(time.RFC3339)
	e.GraceUntil = now.Add(48 * time.Hour).Format(time.RFC3339)
	if err := SignEntitlement(e, signer); err != nil {
		t.Fatal(err)
	}
	raw, err = MarshalEntitlement(e)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifyEntitlementDocument(raw, "install-1", ChannelEnterprise, time.Time{})
	if err != nil || verified.State != EntitlementValid {
		t.Fatalf("zero-clock verification=%#v err=%v", verified, err)
	}
	bad := testEntitlement()
	bad.SchemaVersion = 2
	if err := SignEntitlement(bad, signer); err == nil {
		t.Fatal("invalid entitlement signed")
	}
}

func TestManifestParsingDraftAndSidecarFailureBoundaries(t *testing.T) {
	invalid := cloneManifest(t, testManifest())
	invalid.SchemaVersion = 2
	raw, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(raw); err == nil {
		t.Fatal("semantically invalid manifest parsed")
	}
	if _, err := ParseManifestDraft([]byte("{")); err == nil {
		t.Fatal("malformed manifest draft parsed")
	}

	draft := cloneManifest(t, testManifest())
	for i := range draft.Artifacts {
		draft.Artifacts[i].Size, draft.Artifacts[i].SHA256 = 0, ""
	}
	if len(draft.Migrations) == 0 {
		t.Fatal("fixture must carry a migration")
	}
	raw, _ = json.Marshal(draft)
	if _, err := ParseManifestDraft(raw); err == nil {
		t.Fatal("draft migration digest accepted")
	}
	for i := range draft.Migrations {
		draft.Migrations[i].SHA256 = ""
	}
	draft.Signatures = []Signature{{KeyID: "release-a", Algorithm: "ed25519", Value: "x"}}
	raw, _ = json.Marshal(draft)
	if _, err := ParseManifestDraft(raw); err == nil {
		t.Fatal("signed manifest draft accepted")
	}
	draft.Signatures = nil
	draft.Channel = Channel("future")
	raw, _ = json.Marshal(draft)
	if _, err := ParseManifestDraft(raw); err == nil {
		t.Fatal("semantically invalid manifest draft accepted")
	}

	manifest := cloneManifest(t, testManifest())
	manifest.Architectures = []string{"amd64", "amd64"}
	if err := manifest.Validate(); err == nil {
		t.Fatal("duplicate architectures accepted")
	}
	manifest = cloneManifest(t, testManifest())
	sidecar := manifest.Artifacts[0]
	sidecar.ID, sidecar.Class, sidecar.Target, sidecar.Cohort = "zz-sidecar", ArtifactSidecar, TargetSidecar, "optional"
	sidecar.CompatibleWithCore = ""
	manifest.Artifacts = append(manifest.Artifacts, sidecar)
	if err := manifest.Validate(); err == nil || !strings.Contains(err.Error(), "core compatibility") {
		t.Fatalf("sidecar compatibility error=%v", err)
	}
}

func TestTrustVerificationParseClockFloorAndCanonicalFailures(t *testing.T) {
	key, signer := keypair(t, "release-a", PurposeRelease, false)
	store, err := NewTrustStore([]TrustedKey{key}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyManifest([]byte("{"), VerifyManifestOptions{}); err == nil {
		t.Fatal("malformed release manifest verified")
	}
	// A zero Now option deliberately falls back to the wall clock. Keep this
	// fixture live relative to the test run so the assertion does not acquire a
	// hidden calendar expiry while the fixed-date fixtures remain deterministic.
	now := time.Now().UTC().Truncate(time.Second)
	live := cloneManifest(t, testManifest())
	live.PublishedAt = now.Add(-time.Hour).Format(time.RFC3339)
	live.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	data := signedManifest(t, live, signer)
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{}); err != nil {
		t.Fatalf("zero-clock release verification: %v", err)
	}
	floor := cloneManifest(t, testManifest())
	floor.Compatibility.SourceVersionRange = ">=1.0.0 <3.0.0"
	floor.PreviousVersionFloor = "2.0.0"
	data = signedManifest(t, floor, signer)
	if _, err := store.VerifyManifest(data, VerifyManifestOptions{Now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), CurrentVersion: "1.9.9"}); err == nil || !strings.Contains(err.Error(), "rollback floor") {
		t.Fatalf("rollback floor error=%v", err)
	}
	bad := cloneManifest(t, testManifest())
	bad.SchemaVersion = 2
	if err := SignManifest(context.Background(), bad, signer); err == nil {
		t.Fatal("invalid manifest signed")
	}
}

func FuzzParseManifestNeverPanics(f *testing.F) {
	data, _ := json.Marshal(testManifest())
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"schema_version":2}`))
	f.Add(bytes.Repeat([]byte("{"), 64))
	f.Fuzz(func(t *testing.T, input []byte) {
		manifest, err := ParseManifest(input)
		if err == nil {
			canonical, canonicalErr := CanonicalManifest(manifest)
			if canonicalErr != nil || len(canonical) == 0 {
				t.Fatalf("accepted manifest cannot canonicalize: %v", canonicalErr)
			}
		}
	})
}

func FuzzParseEntitlementNeverPanics(f *testing.F) {
	e := testEntitlement()
	_, signer := keypairForFuzz()
	_ = SignEntitlement(e, signer)
	data, _ := json.Marshal(e)
	f.Add(data)
	f.Add([]byte(`{"schema_version":1,"unknown":true}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		entitlement, err := ParseEntitlement(input)
		if err == nil {
			canonical, canonicalErr := CanonicalEntitlement(entitlement)
			if canonicalErr != nil || len(canonical) == 0 {
				t.Fatalf("accepted entitlement cannot canonicalize: %v", canonicalErr)
			}
		}
	})
}

func keypairForFuzz() (TrustedKey, Ed25519Signer) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return TrustedKey{ID: "entitlement-a", Purpose: PurposeEntitlement, PublicKey: public, TestOnly: true}, Ed25519Signer{ID: "entitlement-a", PrivateKey: private}
}

// #264: signed releases carry the Rust front door beside the Go cohort. The
// gateway is a fixed singleton core target; manifests minted before it
// existed (installed previous releases) still validate for rollback.
func TestManifestCarriesRustGatewayAsFixedCoreTarget(t *testing.T) {
	gateway := Artifact{ID: "setjoin-gateway", Class: ArtifactGateway, Platform: "linux", Architecture: "amd64", Size: 3,
		SHA256: strings.Repeat("a", 64), MediaType: "application/octet-stream", Cohort: "core", Target: TargetGateway}
	withGateway := func(extra ...Artifact) *Manifest {
		m := testManifest()
		// Keep IDs sorted: recovery-guide < setjoin-gateway < webmail.
		artifacts := append([]Artifact{}, m.Artifacts[:7]...)
		artifacts = append(artifacts, gateway)
		artifacts = append(artifacts, extra...)
		m.Artifacts = append(artifacts, m.Artifacts[7:]...)
		return m
	}
	if err := withGateway().Validate(); err != nil {
		t.Fatalf("manifest carrying the gateway: %v", err)
	}
	if err := testManifest().Validate(); err != nil {
		t.Fatalf("pre-gateway manifest must still validate for rollback: %v", err)
	}
	wrongTarget := withGateway()
	wrongTarget.Artifacts[7].Target = TargetMailserver
	if err := wrongTarget.Validate(); err == nil {
		t.Fatal("gateway accepted with the mailserverd target")
	}
	duplicate := gateway
	duplicate.ID = "setjoin-gateway2"
	if err := withGateway(duplicate).Validate(); err == nil || !strings.Contains(err.Error(), "share fixed target") {
		t.Fatalf("two gateway artifacts accepted: %v", err)
	}
}
