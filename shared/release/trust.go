package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type KeyPurpose string

const (
	PurposeRelease       KeyPurpose = "release"
	PurposeEntitlement   KeyPurpose = "entitlement"
	PurposeOrganization  KeyPurpose = "organization"
	PurposeRecovery      KeyPurpose = "recovery"
	PurposeAuditChain    KeyPurpose = "audit-chain"
	PurposeOfflineUpdate KeyPurpose = "offline-update"
)

type TrustedKey struct {
	ID                      string
	Purpose                 KeyPurpose
	PublicKey               ed25519.PublicKey
	TestOnly                bool
	OrganizationArtifactSet map[ArtifactClass]bool
}
type TrustStore struct {
	keys           map[string]TrustedKey
	allowTestRoots bool
}

func NewTrustStore(keys []TrustedKey, allowTestRoots bool) (*TrustStore, error) {
	s := &TrustStore{keys: make(map[string]TrustedKey, len(keys)), allowTestRoots: allowTestRoots}
	for _, k := range keys {
		if !identifierRE.MatchString(k.ID) || len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trusted key")
		}
		if !validKeyPurpose(k.Purpose) {
			return nil, fmt.Errorf("invalid key purpose")
		}
		if _, ok := s.keys[k.ID]; ok {
			return nil, fmt.Errorf("duplicate trusted key %q", k.ID)
		}
		if k.TestOnly && !allowTestRoots {
			return nil, fmt.Errorf("test trust root %q is forbidden by production policy", k.ID)
		}
		s.keys[k.ID] = k
	}
	return s, nil
}

type VerifyManifestOptions struct {
	Now                                    time.Time
	Channel                                Channel
	CurrentVersion, Platform, Architecture string
	LastMetadataVersion                    uint64
	LastMetadataDigest                     string
	MinimumThreshold                       int
}
type VerifiedManifest struct {
	Manifest       *Manifest
	CanonicalBytes []byte
	Digest         string
	SignerKeyIDs   []string
}

func (s *TrustStore) VerifyManifest(data []byte, o VerifyManifestOptions) (*VerifiedManifest, error) {
	return s.VerifyManifestForPurpose(data, o, PurposeRelease)
}

// VerifyManifestForPurpose verifies a release-shaped signed document against
// exactly one trust domain. Purpose separation prevents a recovery, audit, or
// offline-update key from being accepted as a normal release signer.
func (s *TrustStore) VerifyManifestForPurpose(data []byte, o VerifyManifestOptions, purpose KeyPurpose) (*VerifiedManifest, error) {
	if purpose != PurposeRelease && purpose != PurposeOfflineUpdate {
		return nil, fmt.Errorf("manifest verification does not support key purpose %q", purpose)
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalManifest(m)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])
	now := o.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	published, _ := time.Parse(time.RFC3339, m.PublishedAt)
	expires, _ := time.Parse(time.RFC3339, m.ExpiresAt)
	if now.Before(published) {
		return nil, fmt.Errorf("release metadata is not yet valid")
	}
	if !now.Before(expires) {
		return nil, fmt.Errorf("release metadata is expired")
	}
	if o.Channel != "" && m.Channel != o.Channel {
		return nil, fmt.Errorf("wrong release channel")
	}
	if o.Platform != "" && !contains(m.Platforms, o.Platform) {
		return nil, fmt.Errorf("wrong platform")
	}
	if o.Architecture != "" && !contains(m.Architectures, o.Architecture) {
		return nil, fmt.Errorf("wrong architecture")
	}
	if o.CurrentVersion != "" {
		ok, e := VersionInRange(o.CurrentVersion, m.Compatibility.SourceVersionRange)
		if e != nil || !ok {
			return nil, fmt.Errorf("incompatible source version")
		}
		floor, _ := ParseVersion(m.PreviousVersionFloor)
		current, e := ParseVersion(o.CurrentVersion)
		if e != nil || current.Compare(floor) < 0 {
			return nil, fmt.Errorf("source version is below the signed rollback floor")
		}
	}
	if m.MetadataVersion < o.LastMetadataVersion {
		return nil, fmt.Errorf("release metadata rollback detected")
	}
	if m.MetadataVersion == o.LastMetadataVersion && o.LastMetadataDigest != "" && o.LastMetadataDigest != digest {
		return nil, fmt.Errorf("release metadata equivocation detected")
	}
	threshold := m.Signing.Threshold
	if o.MinimumThreshold > threshold {
		threshold = o.MinimumThreshold
	}
	vendor := map[string]bool{}
	all := []string{}
	for _, sig := range m.Signatures {
		k, ok := s.keys[sig.KeyID]
		if !ok || (k.TestOnly && !s.allowTestRoots) {
			continue
		}
		raw, e := base64.RawStdEncoding.DecodeString(sig.Value)
		if e != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(k.PublicKey, canonical, raw) {
			continue
		}
		if k.Purpose == PurposeOrganization {
			if !organizationMaySign(k, m) {
				return nil, fmt.Errorf("organization key %q is not authorized for this artifact set", k.ID)
			}
		} else if k.Purpose == purpose {
			vendor[k.ID] = true
		}
		all = append(all, k.ID)
	}
	if len(vendor) < threshold {
		return nil, fmt.Errorf("release signature threshold not met")
	}
	sort.Strings(all)
	return &VerifiedManifest{Manifest: m, CanonicalBytes: canonical, Digest: digest, SignerKeyIDs: all}, nil
}

func validKeyPurpose(p KeyPurpose) bool {
	switch p {
	case PurposeRelease, PurposeEntitlement, PurposeOrganization, PurposeRecovery, PurposeAuditChain, PurposeOfflineUpdate:
		return true
	default:
		return false
	}
}

// VerifyDetached verifies one purpose-separated Ed25519 signature for compact
// documents that do not use the full release-manifest schema (recovery heads,
// audit anchors, and offline target metadata).
func (s *TrustStore) VerifyDetached(purpose KeyPurpose, keyID string, message []byte, signature string) error {
	key, ok := s.keys[keyID]
	if !ok || key.Purpose != purpose || (key.TestOnly && !s.allowTestRoots) {
		return fmt.Errorf("untrusted %s signing key", purpose)
	}
	raw, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, message, raw) {
		return fmt.Errorf("invalid %s signature", purpose)
	}
	return nil
}
func organizationMaySign(k TrustedKey, m *Manifest) bool {
	sawRepack := false
	for _, a := range m.Artifacts {
		if !a.OrganizationRepack {
			continue
		}
		sawRepack = true
		if !k.OrganizationArtifactSet[a.Class] {
			return false
		}
	}
	return sawRepack
}

type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

func SignManifest(ctx context.Context, m *Manifest, s Signer) error {
	if s == nil || !identifierRE.MatchString(s.KeyID()) {
		return fmt.Errorf("invalid signer")
	}
	for _, sig := range m.Signatures {
		if sig.KeyID == s.KeyID() {
			return fmt.Errorf("manifest already has signature from %q", s.KeyID())
		}
	}
	canonical, err := CanonicalManifest(m)
	if err != nil {
		return err
	}
	raw, err := s.Sign(ctx, canonical)
	if err != nil {
		return fmt.Errorf("sign manifest: signer failed")
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("sign manifest: signer returned invalid signature")
	}
	m.Signatures = append(m.Signatures, Signature{KeyID: s.KeyID(), Algorithm: "ed25519", Value: base64.RawStdEncoding.EncodeToString(raw)})
	sort.Slice(m.Signatures, func(i, j int) bool { return m.Signatures[i].KeyID < m.Signatures[j].KeyID })
	return nil
}

type Ed25519Signer struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

func (s Ed25519Signer) KeyID() string { return s.ID }
func (s Ed25519Signer) Sign(_ context.Context, p []byte) ([]byte, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key")
	}
	return ed25519.Sign(s.PrivateKey, p), nil
}
