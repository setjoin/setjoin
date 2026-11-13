// Package release defines Setjoin's signed release and offline-entitlement
// documents. It deliberately has no dependency on JWT/OIDC keys or runtime
// business logic.
package release

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ManifestSchemaV1    = 1
	EntitlementSchemaV1 = 1
	MaxDocumentBytes    = 1 << 20
)

// MinVerificationThreshold is the signature-count floor a release verifier
// must enforce (signature-policy.manifest-controlled-threshold closure,
// occ_ca6a33cce6cf9e18f41e3d51). Signing.Threshold is declared BY the manifest
// itself, so it is written by the same party that holds the signing keys and
// can never be authoritative for verification: a manifest that lowers its own
// threshold to 1 satisfies itself with a single (possibly compromised) signer
// key. The binding verifier therefore applies the contract
//
//	effectiveThreshold = max(manifest.Signing.Threshold, verifier floor)
//
// where the floor comes from verifier policy — VerifyManifestOptions.
// MinimumThreshold in shared/release/trust.go — and MUST be at least
// MinVerificationThreshold for any release trusted to update production
// (channel installers, offline updaters, restore tooling). Two independent
// vendor signatures is the floor that makes single-key compromise
// insufficient, which is the property the dual-control release process
// otherwise assumes. Verification callers that pass a zero floor admit
// self-declared single-signer manifests and carry that decision in their own
// review record.
const MinVerificationThreshold = 2

type Channel string

const (
	ChannelCommunity  Channel = "community"
	ChannelEnterprise Channel = "enterprise"
)

type ArtifactClass string

const (
	ArtifactMailserver    ArtifactClass = "mailserverd"
	ArtifactAuthserver    ArtifactClass = "authserverd"
	ArtifactMailctl       ArtifactClass = "mailctl"
	ArtifactWebmail       ArtifactClass = "webmail"
	ArtifactMigration     ArtifactClass = "migration"
	ArtifactRecoveryGuide ArtifactClass = "recovery_guide"
	ArtifactSBOM          ArtifactClass = "sbom"
	ArtifactProvenance    ArtifactClass = "provenance"
	ArtifactSidecar       ArtifactClass = "sidecar"
	// ArtifactGateway is the Rust front door (`setjoin-gateway`, ARCH-027).
	// Releases staged by the updater must carry it; manifests minted before it
	// existed still parse so installed previous releases stay rollback targets.
	ArtifactGateway ArtifactClass = "setjoin-gateway"
)

type InstallTarget string

const (
	TargetMailserver    InstallTarget = "core_mailserverd"
	TargetAuthserver    InstallTarget = "core_authserverd"
	TargetMailctl       InstallTarget = "core_mailctl"
	TargetWebmail       InstallTarget = "core_webmail"
	TargetMigrations    InstallTarget = "core_migrations"
	TargetRecoveryGuide InstallTarget = "recovery_guide"
	TargetSBOM          InstallTarget = "release_sbom"
	TargetProvenance    InstallTarget = "release_provenance"
	TargetSidecar       InstallTarget = "compatible_sidecar"
	TargetGateway       InstallTarget = "core_setjoin_gateway"
)

type MigrationClass string

const (
	MigrationExpand       MigrationClass = "expand"
	MigrationContract     MigrationClass = "contract"
	MigrationIrreversible MigrationClass = "irreversible"
)

type Signature struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
type SigningPolicy struct {
	// Threshold is the manifest-authored signature requirement. It is a
	// self-declared value inside the signed payload — the party that mints the
	// manifest also writes it — so verifiers must never trust it as the
	// enforcement floor: they enforce max(Threshold, MinVerificationThreshold)
	// via VerifyManifestOptions.MinimumThreshold (see that constant's contract).
	Threshold      int      `json:"threshold"`
	RotationKeyIDs []string `json:"rotation_key_ids,omitempty"`
}
type Compatibility struct {
	SourceVersionRange string `json:"source_version_range"`
	PostgresRange      string `json:"postgres_range"`
	MinimumClient      string `json:"minimum_client,omitempty"`
}
type Artifact struct {
	ID                 string        `json:"id"`
	Class              ArtifactClass `json:"class"`
	Platform           string        `json:"platform"`
	Architecture       string        `json:"architecture"`
	Size               uint64        `json:"size"`
	SHA256             string        `json:"sha256"`
	MediaType          string        `json:"media_type"`
	Cohort             string        `json:"cohort"`
	Target             InstallTarget `json:"target"`
	CompatibleWithCore string        `json:"compatible_with_core,omitempty"`
	OrganizationRepack bool          `json:"organization_repack,omitempty"`
}
type Migration struct {
	ID                     string         `json:"id"`
	FromSchema             int            `json:"from_schema"`
	ToSchema               int            `json:"to_schema"`
	SHA256                 string         `json:"sha256"`
	Class                  MigrationClass `json:"class"`
	CompatibilityEvidence  string         `json:"compatibility_evidence"`
	TransactionRequired    bool           `json:"transaction_required"`
	PreviousBinaryEvidence string         `json:"previous_binary_evidence"`
}
type RecoveryRequirements struct {
	MaximumAgeSeconds uint64 `json:"maximum_age_seconds"`
	MinimumFreeBytes  uint64 `json:"minimum_free_bytes"`
}
type HealthGates struct {
	Preflight  []string `json:"preflight"`
	Readiness  []string `json:"readiness"`
	Data       []string `json:"data_contract"`
	PostCommit []string `json:"post_commit"`
}
type FeatureRegistryContract struct {
	CatalogDigest             string   `json:"catalog_digest"`
	CompatibleModes           []string `json:"compatible_modes"`
	CompatibleRollbackDigests []string `json:"compatible_rollback_digests"`
}
type ReleaseNotes struct {
	Summary            string   `json:"summary"`
	DowntimeMinimumSec uint64   `json:"downtime_minimum_seconds"`
	DowntimeMaximumSec uint64   `json:"downtime_maximum_seconds"`
	SupportChannel     string   `json:"support_channel"`
	KnownBlockers      []string `json:"known_blockers,omitempty"`
}
type Manifest struct {
	SchemaVersion        int                      `json:"schema_version"`
	ReleaseID            string                   `json:"release_id"`
	Version              string                   `json:"version"`
	Channel              Channel                  `json:"channel"`
	PublishedAt          string                   `json:"published_at"`
	ExpiresAt            string                   `json:"expires_at"`
	MetadataVersion      uint64                   `json:"metadata_version"`
	PreviousVersionFloor string                   `json:"previous_version_floor"`
	Platforms            []string                 `json:"platforms"`
	Architectures        []string                 `json:"architectures"`
	Compatibility        Compatibility            `json:"compatibility"`
	SchemaFrom           int                      `json:"schema_from"`
	SchemaTo             int                      `json:"schema_to"`
	Artifacts            []Artifact               `json:"artifacts"`
	Migrations           []Migration              `json:"migrations"`
	HealthGates          HealthGates              `json:"health_gates"`
	FeatureRegistry      *FeatureRegistryContract `json:"feature_registry,omitempty"`
	Recovery             RecoveryRequirements     `json:"recovery"`
	Notes                ReleaseNotes             `json:"notes"`
	Signing              SigningPolicy            `json:"signing"`
	Signatures           []Signature              `json:"signatures"`
}

var identifierRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
var gateRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := strictDecode(data, &m); err != nil {
		return nil, fmt.Errorf("release manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ParseManifestDraft is the CI publisher's only pre-hash entry point. Drafts
// use the final schema but must leave artifact sizes/digests and migration
// digests empty; the publisher fills them from the fixed artifact inventory.
func ParseManifestDraft(data []byte) (*Manifest, error) {
	var m Manifest
	if err := strictDecode(data, &m); err != nil {
		return nil, fmt.Errorf("release manifest draft: %w", err)
	}
	copy := m
	copy.Artifacts = append([]Artifact(nil), m.Artifacts...)
	copy.Migrations = append([]Migration(nil), m.Migrations...)
	for i := range copy.Artifacts {
		if copy.Artifacts[i].Size != 0 || copy.Artifacts[i].SHA256 != "" {
			return nil, fmt.Errorf("draft artifact %q must not provide size or digest", copy.Artifacts[i].ID)
		}
		copy.Artifacts[i].Size = 1
		copy.Artifacts[i].SHA256 = strings.Repeat("0", 64)
	}
	for i := range copy.Migrations {
		if copy.Migrations[i].SHA256 != "" {
			return nil, fmt.Errorf("draft migration %q must not provide a digest", copy.Migrations[i].ID)
		}
		copy.Migrations[i].SHA256 = strings.Repeat("0", 64)
	}
	if len(copy.Signatures) != 0 {
		return nil, fmt.Errorf("manifest draft must not contain signatures")
	}
	if err := copy.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("release manifest is nil")
	}
	if m.SchemaVersion != ManifestSchemaV1 {
		return fmt.Errorf("unsupported release manifest schema %d", m.SchemaVersion)
	}
	if !identifierRE.MatchString(m.ReleaseID) {
		return fmt.Errorf("invalid release_id")
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}
	if m.Channel != ChannelCommunity && m.Channel != ChannelEnterprise {
		return fmt.Errorf("invalid channel %q", m.Channel)
	}
	if err := validateUTCSecond("published_at", m.PublishedAt); err != nil {
		return err
	}
	if err := validateUTCSecond("expires_at", m.ExpiresAt); err != nil {
		return err
	}
	published, _ := time.Parse(time.RFC3339, m.PublishedAt)
	expires, _ := time.Parse(time.RFC3339, m.ExpiresAt)
	if !expires.After(published) {
		return fmt.Errorf("expires_at must be after published_at")
	}
	if m.MetadataVersion == 0 {
		return fmt.Errorf("metadata_version must be positive")
	}
	if _, err := ParseVersion(m.PreviousVersionFloor); err != nil {
		return fmt.Errorf("invalid previous_version_floor: %w", err)
	}
	if err := validateSortedUnique("platforms", m.Platforms); err != nil {
		return err
	}
	if err := validateSortedUnique("architectures", m.Architectures); err != nil {
		return err
	}
	if len(m.Platforms) == 0 || len(m.Architectures) == 0 {
		return fmt.Errorf("platforms and architectures must not be empty")
	}
	if err := ValidateVersionRange(m.Compatibility.SourceVersionRange); err != nil {
		return fmt.Errorf("invalid source version range: %w", err)
	}
	if err := ValidateVersionRange(m.Compatibility.PostgresRange); err != nil {
		return fmt.Errorf("invalid postgres range: %w", err)
	}
	if m.Compatibility.MinimumClient != "" {
		if _, err := ParseVersion(m.Compatibility.MinimumClient); err != nil {
			return fmt.Errorf("invalid minimum client: %w", err)
		}
	}
	if m.SchemaFrom < 0 || m.SchemaTo < m.SchemaFrom {
		return fmt.Errorf("invalid schema range")
	}
	if len(m.Artifacts) == 0 || len(m.Artifacts) > 256 {
		return fmt.Errorf("artifacts count must be between 1 and 256")
	}
	if err := validateArtifacts(m); err != nil {
		return err
	}
	if err := validateMigrations(m); err != nil {
		return err
	}
	if err := validateGates(m.HealthGates); err != nil {
		return err
	}
	if m.SchemaTo >= 183 && m.FeatureRegistry == nil {
		return fmt.Errorf("schema %d release must declare feature registry compatibility", m.SchemaTo)
	}
	if m.FeatureRegistry != nil {
		if err := validateFeatureRegistryContract(*m.FeatureRegistry); err != nil {
			return err
		}
	}
	if m.Recovery.MaximumAgeSeconds == 0 || m.Recovery.MaximumAgeSeconds > uint64((30*24*time.Hour)/time.Second) {
		return fmt.Errorf("recovery maximum age must be between one second and 30 days")
	}
	if m.Notes.DowntimeMaximumSec < m.Notes.DowntimeMinimumSec {
		return fmt.Errorf("downtime maximum must not be less than minimum")
	}
	if len(m.Notes.Summary) == 0 || len(m.Notes.Summary) > 4096 || len(m.Notes.SupportChannel) > 256 {
		return fmt.Errorf("invalid release notes")
	}
	if m.Signing.Threshold < 1 || m.Signing.Threshold > 8 {
		return fmt.Errorf("signature threshold must be between 1 and 8")
	}
	if err := validateSortedUnique("rotation_key_ids", m.Signing.RotationKeyIDs); err != nil {
		return err
	}
	if len(m.Signatures) > 16 {
		return fmt.Errorf("too many signatures")
	}
	seen := map[string]bool{}
	for _, sig := range m.Signatures {
		if !identifierRE.MatchString(sig.KeyID) || sig.Algorithm != "ed25519" || sig.Value == "" {
			return fmt.Errorf("invalid signature entry")
		}
		if seen[sig.KeyID] {
			return fmt.Errorf("duplicate signature key_id %q", sig.KeyID)
		}
		seen[sig.KeyID] = true
	}
	return nil
}

func validateFeatureRegistryContract(contract FeatureRegistryContract) error {
	if !sha256RE.MatchString(contract.CatalogDigest) {
		return fmt.Errorf("feature registry catalog digest is invalid")
	}
	if len(contract.CompatibleModes) == 0 || len(contract.CompatibleModes) > 2 {
		return fmt.Errorf("feature registry compatible modes must contain observe and optionally enforce")
	}
	for index, mode := range contract.CompatibleModes {
		if mode != "observe" && mode != "enforce" {
			return fmt.Errorf("feature registry compatible mode %q is invalid", mode)
		}
		if index > 0 && contract.CompatibleModes[index-1] >= mode {
			return fmt.Errorf("feature registry compatible modes must be sorted and unique")
		}
	}
	if !contains(contract.CompatibleModes, "observe") {
		return fmt.Errorf("feature registry compatibility must include observe")
	}
	if len(contract.CompatibleRollbackDigests) == 0 || len(contract.CompatibleRollbackDigests) > 16 {
		return fmt.Errorf("feature registry rollback digests must contain one to sixteen values")
	}
	for index, digest := range contract.CompatibleRollbackDigests {
		if !sha256RE.MatchString(digest) {
			return fmt.Errorf("feature registry rollback digest is invalid")
		}
		if index > 0 && contract.CompatibleRollbackDigests[index-1] >= digest {
			return fmt.Errorf("feature registry rollback digests must be sorted and unique")
		}
	}
	return nil
}

func validateArtifacts(m *Manifest) error {
	seen := map[string]bool{}
	last := ""
	core := map[ArtifactClass]bool{}
	classes := map[ArtifactClass]int{}
	fixedTargets := map[InstallTarget]string{}
	for _, a := range m.Artifacts {
		if !identifierRE.MatchString(a.ID) || strings.ContainsAny(a.ID, `/\\`) || a.ID == "." || a.ID == ".." {
			return fmt.Errorf("artifact id %q is path-like or invalid", a.ID)
		}
		if seen[a.ID] {
			return fmt.Errorf("duplicate artifact id %q", a.ID)
		}
		seen[a.ID] = true
		classes[a.Class]++
		if last != "" && a.ID < last {
			return fmt.Errorf("artifacts must be sorted by id")
		}
		last = a.ID
		if a.Size == 0 || !sha256RE.MatchString(a.SHA256) || len(a.MediaType) == 0 || len(a.MediaType) > 128 {
			return fmt.Errorf("artifact %q has invalid size, digest, or media type", a.ID)
		}
		if !contains(m.Platforms, a.Platform) || !contains(m.Architectures, a.Architecture) {
			return fmt.Errorf("artifact %q platform or architecture is undeclared", a.ID)
		}
		if !validArtifactTarget(a.Class, a.Target) {
			return fmt.Errorf("artifact %q has invalid class/target pair", a.ID)
		}
		// Every fixed install target is a singleton. Migrations and sidecars are
		// the only multi-artifact targets; accepting two mailserverd/webmail/etc.
		// artifacts would leave the host installer to guess which signed object
		// is authoritative.
		if a.Target != TargetMigrations && a.Target != TargetSidecar {
			if prior := fixedTargets[a.Target]; prior != "" {
				return fmt.Errorf("artifacts %q and %q share fixed target %q", prior, a.ID, a.Target)
			}
			fixedTargets[a.Target] = a.ID
		}
		if a.Cohort == "core" {
			core[a.Class] = true
		} else if !identifierRE.MatchString(a.Cohort) {
			return fmt.Errorf("artifact %q has invalid cohort", a.ID)
		}
		if a.CompatibleWithCore != "" {
			if err := ValidateVersionRange(a.CompatibleWithCore); err != nil {
				return fmt.Errorf("artifact %q compatibility: %w", a.ID, err)
			}
		}
		if a.Class == ArtifactSidecar && a.CompatibleWithCore == "" {
			return fmt.Errorf("sidecar artifact %q must declare core compatibility", a.ID)
		}
	}
	if len(core) != 0 {
		for _, required := range []ArtifactClass{ArtifactMailserver, ArtifactAuthserver, ArtifactMailctl, ArtifactWebmail} {
			if !core[required] {
				return fmt.Errorf("core cohort is missing %s", required)
			}
		}
	}
	if classes[ArtifactSBOM] != 1 || classes[ArtifactProvenance] != 1 {
		return fmt.Errorf("release must contain exactly one SBOM and one provenance artifact")
	}
	if classes[ArtifactRecoveryGuide] != 1 {
		return fmt.Errorf("release must contain exactly one recovery guide artifact")
	}
	return nil
}

func validateMigrations(m *Manifest) error {
	if len(m.Migrations) > 256 {
		return fmt.Errorf("too many migrations")
	}
	lastTo := m.SchemaFrom
	seen := map[string]bool{}
	for _, x := range m.Migrations {
		if !identifierRE.MatchString(x.ID) || seen[x.ID] {
			return fmt.Errorf("invalid or duplicate migration id %q", x.ID)
		}
		seen[x.ID] = true
		if x.FromSchema != lastTo || x.ToSchema <= x.FromSchema || x.ToSchema > m.SchemaTo {
			return fmt.Errorf("migration %q is out of order", x.ID)
		}
		lastTo = x.ToSchema
		if !sha256RE.MatchString(x.SHA256) || x.Class != MigrationExpand {
			return fmt.Errorf("migration %q is not an attested expand migration", x.ID)
		}
		if !identifierRE.MatchString(x.CompatibilityEvidence) || !identifierRE.MatchString(x.PreviousBinaryEvidence) {
			return fmt.Errorf("migration %q lacks compatibility evidence", x.ID)
		}
		if !x.TransactionRequired {
			return fmt.Errorf("migration %q is nontransactional", x.ID)
		}
		matchedArtifact := false
		for _, artifact := range m.Artifacts {
			if artifact.ID == x.ID && artifact.Class == ArtifactMigration && artifact.SHA256 == x.SHA256 {
				matchedArtifact = true
				break
			}
		}
		if !matchedArtifact {
			return fmt.Errorf("migration %q does not match a hashed migration artifact", x.ID)
		}
	}
	if lastTo != m.SchemaTo {
		return fmt.Errorf("migration chain ends at schema %d, want %d", lastTo, m.SchemaTo)
	}
	return nil
}

func validArtifactTarget(class ArtifactClass, target InstallTarget) bool {
	return map[ArtifactClass]InstallTarget{ArtifactMailserver: TargetMailserver, ArtifactAuthserver: TargetAuthserver, ArtifactMailctl: TargetMailctl, ArtifactWebmail: TargetWebmail, ArtifactMigration: TargetMigrations, ArtifactRecoveryGuide: TargetRecoveryGuide, ArtifactSBOM: TargetSBOM, ArtifactProvenance: TargetProvenance, ArtifactSidecar: TargetSidecar, ArtifactGateway: TargetGateway}[class] == target
}
func validateGates(g HealthGates) error {
	for name, gates := range map[string][]string{"preflight": g.Preflight, "readiness": g.Readiness, "data_contract": g.Data, "post_commit": g.PostCommit} {
		if len(gates) == 0 || len(gates) > 32 {
			return fmt.Errorf("%s gates count must be between 1 and 32", name)
		}
		if err := validateSortedUnique(name+" gates", gates); err != nil {
			return err
		}
		for _, gate := range gates {
			if !gateRE.MatchString(gate) {
				return fmt.Errorf("invalid %s gate %q", name, gate)
			}
		}
	}
	return nil
}
func validateSortedUnique(name string, values []string) error {
	for i, v := range values {
		if !identifierRE.MatchString(v) {
			return fmt.Errorf("%s contains invalid value %q", name, v)
		}
		if i > 0 && values[i-1] >= v {
			return fmt.Errorf("%s must be sorted and unique", name)
		}
	}
	return nil
}
func validateUTCSecond(name, value string) error {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339) != value {
		return fmt.Errorf("%s must be canonical UTC RFC3339 seconds", name)
	}
	return nil
}
func contains(values []string, want string) bool {
	i := sort.SearchStrings(values, want)
	return i < len(values) && values[i] == want
}
