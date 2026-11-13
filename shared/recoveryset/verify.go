// Package recoveryset defines the portable, cryptographically bound recovery
// evidence shared by the gateway, updater, and operator CLI.
package recoveryset

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	ManifestVersion        = 1
	DefaultFreshness       = 24 * time.Hour
	RestoreProofWarningAge = 90 * 24 * time.Hour
)

type Artifact struct {
	ObjectKey string `json:"objectKey"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
}

type ProtectedKeyEvidence struct {
	Mode        string `json:"mode"`
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
}

type Counts struct {
	Blobs     int64 `json:"blobs"`
	BlobBytes int64 `json:"blobBytes"`
	Users     int64 `json:"users"`
	Mailboxes int64 `json:"mailboxes"`
}

type Manifest struct {
	Version              int                  `json:"version"`
	RecoverySetID        string               `json:"recoverySetId"`
	InstallationID       string               `json:"installationId"`
	TimelineID           string               `json:"timelineId"`
	SourceReleaseID      string               `json:"sourceReleaseId"`
	SchemaVersion        int                  `json:"schemaVersion"`
	CreatedAt            time.Time            `json:"createdAt"`
	ExpiresAt            time.Time            `json:"expiresAt"`
	Database             Artifact             `json:"database"`
	DatabaseRestoreList  Artifact             `json:"databaseRestoreList"`
	Blobs                Artifact             `json:"blobs"`
	Configuration        Artifact             `json:"configuration"`
	ProtectedKeyEvidence ProtectedKeyEvidence `json:"protectedKeyEvidence"`
	FeatureToggleSHA256  string               `json:"featureToggleSha256"`
	Counts               Counts               `json:"counts"`
	RepresentativeIDs    []string             `json:"representativeIds"`
}

type Envelope struct {
	Manifest       Manifest `json:"manifest"`
	ManifestSHA256 string   `json:"manifestSha256"`
	HMACSHA256     string   `json:"hmacSha256"`
}

type RestoreProof struct {
	Version            int       `json:"version"`
	RecoverySetID      string    `json:"recoverySetId"`
	TargetID           string    `json:"targetId"`
	SourceInstallation string    `json:"sourceInstallationId"`
	Isolated           bool      `json:"isolated"`
	SchemaChecked      bool      `json:"schemaChecked"`
	LoginChecked       bool      `json:"loginChecked"`
	MailChecked        bool      `json:"mailChecked"`
	BlobChecked        bool      `json:"blobChecked"`
	ProvedAt           time.Time `json:"provedAt"`
}

var (
	canonicalDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stableID        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type VerifyPolicy struct {
	Now                    time.Time
	ExpectedInstallationID string
	ExpectedTimelineID     string
	MaxAge                 time.Duration
}

type Verdict struct {
	RecoverySetID  string    `json:"recoverySetId"`
	CreatedAt      time.Time `json:"createdAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
	Fresh          bool      `json:"fresh"`
	ManifestSHA256 string    `json:"manifestSha256"`
}

func Seal(manifest Manifest, key []byte) (Envelope, error) {
	if err := validateManifest(manifest); err != nil {
		return Envelope{}, err
	}
	if len(key) < 32 {
		return Envelope{}, errors.New("recovery set HMAC key must be at least 32 bytes")
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal recovery manifest: %w", err)
	}
	digest := sha256.Sum256(raw)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return Envelope{Manifest: manifest, ManifestSHA256: hex.EncodeToString(digest[:]), HMACSHA256: hex.EncodeToString(mac.Sum(nil))}, nil
}

func Verify(envelope Envelope, key []byte, policy VerifyPolicy) (Verdict, error) {
	if err := validateManifest(envelope.Manifest); err != nil {
		return Verdict{}, err
	}
	if len(key) < 32 || !canonicalDigest.MatchString(envelope.ManifestSHA256) || !canonicalDigest.MatchString(envelope.HMACSHA256) {
		return Verdict{}, errors.New("invalid recovery set envelope")
	}
	raw, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return Verdict{}, fmt.Errorf("marshal recovery manifest: %w", err)
	}
	digest := sha256.Sum256(raw)
	if !hmac.Equal([]byte(envelope.ManifestSHA256), []byte(hex.EncodeToString(digest[:]))) {
		return Verdict{}, errors.New("recovery set manifest digest mismatch")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	wantMAC, err := hex.DecodeString(envelope.HMACSHA256)
	if err != nil || !hmac.Equal(mac.Sum(nil), wantMAC) {
		return Verdict{}, errors.New("recovery set HMAC mismatch")
	}
	now := policy.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxAge := policy.MaxAge
	if maxAge == 0 {
		maxAge = DefaultFreshness
	}
	if maxAge <= 0 || envelope.Manifest.CreatedAt.After(now.Add(time.Minute)) || now.Sub(envelope.Manifest.CreatedAt) > maxAge || !now.Before(envelope.Manifest.ExpiresAt) {
		return Verdict{}, errors.New("recovery set is stale")
	}
	if policy.ExpectedInstallationID != "" && envelope.Manifest.InstallationID != policy.ExpectedInstallationID {
		return Verdict{}, errors.New("recovery set installation mismatch")
	}
	if policy.ExpectedTimelineID != "" && envelope.Manifest.TimelineID != policy.ExpectedTimelineID {
		return Verdict{}, errors.New("recovery set timeline mismatch")
	}
	return Verdict{RecoverySetID: envelope.Manifest.RecoverySetID, CreatedAt: envelope.Manifest.CreatedAt, ExpiresAt: envelope.Manifest.ExpiresAt, Fresh: true, ManifestSHA256: envelope.ManifestSHA256}, nil
}

// ValidateRestoreProof checks an operator-provided drill/restore proof against
// a verified manifest. It validates FIELD CONSISTENCY only (version, set and
// installation binding, target isolation, all checks performed, temporal
// ordering) — it authenticates nothing by itself: an unsigned proof is
// self-asserted operator bookkeeping whose authority lives in the operator
// process and the reducer, not in this check.
//
// Warning contract: a returned warning with a nil error (currently a proof
// older than RestoreProofWarningAge) is a LOUD caveat, not a pass — callers
// must surface it to the operator; silently discarding the warning voids the
// check. Replay/single-use tracking is the CONSUMER's obligation: proofs are
// bearer evidence, so a consumer that must enforce single use needs its own
// reducer/state keyed on the sealed proof (see SealRestoreProof), because this
// package holds no state store. For any path where the proof authorizes
// anything, prefer VerifySignedRestoreProof over this function.
func ValidateRestoreProof(proof RestoreProof, manifest Manifest, now time.Time) (warning string, err error) {
	if proof.Version != ManifestVersion || proof.RecoverySetID != manifest.RecoverySetID || proof.SourceInstallation != manifest.InstallationID || proof.TargetID == "" || proof.TargetID == manifest.InstallationID || !proof.Isolated || !proof.SchemaChecked || !proof.LoginChecked || !proof.MailChecked || !proof.BlobChecked || proof.ProvedAt.IsZero() || proof.ProvedAt.Before(manifest.CreatedAt) || proof.ProvedAt.After(now.UTC().Add(time.Minute)) {
		return "", errors.New("restore proof is incomplete or not isolated")
	}
	if now.UTC().Sub(proof.ProvedAt) > RestoreProofWarningAge {
		return "restore proof is older than 90 days", nil
	}
	return "", nil
}

// SignedRestoreProof is the authenticated form of a RestoreProof: the proof's
// canonical JSON bound by HMAC-SHA256 under the recovery-set HMAC key
// (D-SHARED-RECOVERYSET-V-002). Unsigned proofs are self-asserted; the sealed
// form is what any consumer that acts on a proof should require.
type SignedRestoreProof struct {
	Proof      RestoreProof `json:"proof"`
	HMACSHA256 string       `json:"hmacSha256"`
}

// SealRestoreProof authenticates a proof: every field — recovery set,
// installation, target, isolation flags, and especially ProvedAt — is bound
// into the MAC, so a sealed proof cannot be altered, re-targeted, or re-dated
// without detection. Use the SAME key discipline as Seal/Verify (≥32 bytes).
func SealRestoreProof(proof RestoreProof, key []byte) ([]byte, error) {
	if len(key) < 32 {
		return nil, errors.New("recovery set HMAC key must be at least 32 bytes")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("marshal restore proof: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw)
	return json.Marshal(SignedRestoreProof{Proof: proof, HMACSHA256: hex.EncodeToString(mac.Sum(nil))})
}

// VerifySignedRestoreProof authenticates a sealed proof, then runs the same
// field-consistency and freshness checks as ValidateRestoreProof (including
// the 90-day warning contract). A proof that fails HMAC verification, whose
// JSON is malformed, or whose fields do not cohere is rejected — never
// treated as advisory.
func VerifySignedRestoreProof(raw []byte, key []byte, manifest Manifest, now time.Time) (RestoreProof, string, error) {
	if len(key) < 32 {
		return RestoreProof{}, "", errors.New("recovery set HMAC key must be at least 32 bytes")
	}
	var signed SignedRestoreProof
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return RestoreProof{}, "", errors.New("invalid signed restore proof JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RestoreProof{}, "", errors.New("invalid trailing signed restore proof JSON")
	}
	if !canonicalDigest.MatchString(signed.HMACSHA256) {
		return RestoreProof{}, "", errors.New("invalid signed restore proof envelope")
	}
	proofRaw, err := json.Marshal(signed.Proof)
	if err != nil {
		return RestoreProof{}, "", fmt.Errorf("marshal restore proof: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(proofRaw)
	wantMAC, err := hex.DecodeString(signed.HMACSHA256)
	if err != nil || !hmac.Equal(mac.Sum(nil), wantMAC) {
		return RestoreProof{}, "", errors.New("restore proof HMAC mismatch")
	}
	warning, err := ValidateRestoreProof(signed.Proof, manifest, now)
	if err != nil {
		return RestoreProof{}, "", err
	}
	return signed.Proof, warning, nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Version != ManifestVersion {
		return errors.New("unsupported recovery set manifest version")
	}
	if _, err := uuid.Parse(manifest.RecoverySetID); err != nil {
		return errors.New("invalid recovery set id")
	}
	if _, err := uuid.Parse(manifest.InstallationID); err != nil {
		return errors.New("invalid installation id")
	}
	if _, err := uuid.Parse(manifest.TimelineID); err != nil {
		return errors.New("invalid timeline id")
	}
	if !stableID.MatchString(manifest.SourceReleaseID) || manifest.SchemaVersion <= 0 || manifest.CreatedAt.IsZero() || manifest.ExpiresAt.IsZero() || !manifest.ExpiresAt.After(manifest.CreatedAt) || manifest.ExpiresAt.Sub(manifest.CreatedAt) > DefaultFreshness {
		return errors.New("invalid recovery set identity or freshness")
	}
	if manifest.Counts.Blobs < 0 || manifest.Counts.BlobBytes < 0 || manifest.Counts.Users < 0 || manifest.Counts.Mailboxes < 0 || !canonicalDigest.MatchString(manifest.FeatureToggleSHA256) || len(manifest.RepresentativeIDs) > 64 {
		return errors.New("invalid recovery set counts")
	}
	if manifest.ProtectedKeyEvidence.Mode != "encrypted" && manifest.ProtectedKeyEvidence.Mode != "external" {
		return errors.New("protected-key evidence is required")
	}
	if !stableID.MatchString(manifest.ProtectedKeyEvidence.KeyID) || !canonicalDigest.MatchString(manifest.ProtectedKeyEvidence.Fingerprint) {
		return errors.New("invalid protected-key evidence")
	}
	artifacts := []Artifact{manifest.Database, manifest.DatabaseRestoreList, manifest.Blobs, manifest.Configuration}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if err := validateArtifact(artifact); err != nil {
			return err
		}
		if _, exists := seen[artifact.ObjectKey]; exists {
			return errors.New("duplicate recovery artifact key")
		}
		seen[artifact.ObjectKey] = struct{}{}
	}
	ids := append([]string(nil), manifest.RepresentativeIDs...)
	sort.Strings(ids)
	for i, id := range ids {
		if !stableID.MatchString(id) || (i > 0 && id == ids[i-1]) {
			return errors.New("invalid representative id evidence")
		}
	}
	return nil
}

func validateArtifact(artifact Artifact) error {
	if artifact.Size < 0 || !canonicalDigest.MatchString(artifact.SHA256) || artifact.ObjectKey == "" || len(artifact.ObjectKey) > 512 || strings.Contains(artifact.ObjectKey, `\`) || strings.HasPrefix(artifact.ObjectKey, "/") || path.Clean(artifact.ObjectKey) != artifact.ObjectKey || artifact.ObjectKey == "." || artifact.ObjectKey == ".." || strings.HasPrefix(artifact.ObjectKey, "../") {
		return errors.New("invalid recovery artifact")
	}
	return nil
}
