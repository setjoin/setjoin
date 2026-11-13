package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

type Entitlement struct {
	SchemaVersion       int         `json:"schema_version"`
	EntitlementID       string      `json:"entitlement_id"`
	InstallationID      string      `json:"installation_id"`
	CustomerID          string      `json:"customer_id"`
	Channels            []Channel   `json:"channels"`
	VersionRanges       []string    `json:"version_ranges"`
	IssuedAt            string      `json:"issued_at"`
	ValidFrom           string      `json:"valid_from"`
	ValidUntil          string      `json:"valid_until"`
	GraceUntil          string      `json:"grace_until"`
	NonProductionRights []string    `json:"non_production_rights,omitempty"`
	KeyID               string      `json:"key_id"`
	Signatures          []Signature `json:"signatures"`
}

func ParseEntitlement(data []byte) (*Entitlement, error) {
	var e Entitlement
	if err := strictDecode(data, &e); err != nil {
		return nil, fmt.Errorf("entitlement: %w", err)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}
func (e *Entitlement) ValidateUnsigned() error {
	if e == nil {
		return fmt.Errorf("entitlement is nil")
	}
	if e.SchemaVersion != EntitlementSchemaV1 {
		return fmt.Errorf("unsupported entitlement schema %d", e.SchemaVersion)
	}
	for name, value := range map[string]string{"entitlement_id": e.EntitlementID, "installation_id": e.InstallationID, "customer_id": e.CustomerID, "key_id": e.KeyID} {
		if !identifierRE.MatchString(value) {
			return fmt.Errorf("invalid %s", name)
		}
	}
	if len(e.Channels) == 0 || len(e.Channels) > 2 {
		return fmt.Errorf("invalid entitlement channels")
	}
	for i, c := range e.Channels {
		if c != ChannelEnterprise {
			return fmt.Errorf("local entitlement cannot gate community channel")
		}
		if i > 0 && e.Channels[i-1] >= c {
			return fmt.Errorf("entitlement channels must be sorted and unique")
		}
	}
	if len(e.VersionRanges) == 0 || len(e.VersionRanges) > 16 {
		return fmt.Errorf("invalid entitlement version ranges")
	}
	for _, r := range e.VersionRanges {
		if err := ValidateVersionRange(r); err != nil {
			return fmt.Errorf("invalid entitlement version range: %w", err)
		}
	}
	for name, value := range map[string]string{"issued_at": e.IssuedAt, "valid_from": e.ValidFrom, "valid_until": e.ValidUntil, "grace_until": e.GraceUntil} {
		if err := validateUTCSecond(name, value); err != nil {
			return err
		}
	}
	issued, _ := time.Parse(time.RFC3339, e.IssuedAt)
	from, _ := time.Parse(time.RFC3339, e.ValidFrom)
	until, _ := time.Parse(time.RFC3339, e.ValidUntil)
	grace, _ := time.Parse(time.RFC3339, e.GraceUntil)
	if from.Before(issued) || !until.After(from) || grace.Before(until) {
		return fmt.Errorf("invalid entitlement time ordering")
	}
	return validateSortedUnique("non_production_rights", e.NonProductionRights)
}
func (e *Entitlement) Validate() error {
	if err := e.ValidateUnsigned(); err != nil {
		return err
	}
	if len(e.Signatures) != 1 {
		return fmt.Errorf("entitlement requires exactly one signature")
	}
	sig := e.Signatures[0]
	if sig.KeyID != e.KeyID || sig.Algorithm != "ed25519" || sig.Value == "" {
		return fmt.Errorf("invalid entitlement signature")
	}
	return nil
}

type EntitlementState string

const (
	EntitlementValid EntitlementState = "valid"
	EntitlementGrace EntitlementState = "grace"
)

type VerifiedEntitlement struct {
	Entitlement *Entitlement
	State       EntitlementState
	Digest      string
}

func (s *TrustStore) VerifyEntitlement(data []byte, installationID string, channel Channel, version string, now time.Time) (*VerifiedEntitlement, error) {
	if version == "" {
		return nil, fmt.Errorf("entitlement target version is required")
	}
	return s.verifyEntitlement(data, installationID, channel, version, now)
}

// VerifyEntitlementDocument verifies an offline entitlement at import/show
// time. Target-release range eligibility is deliberately deferred until the
// updater evaluates a concrete signed release.
func (s *TrustStore) VerifyEntitlementDocument(data []byte, installationID string, channel Channel, now time.Time) (*VerifiedEntitlement, error) {
	return s.verifyEntitlement(data, installationID, channel, "", now)
}

func (s *TrustStore) verifyEntitlement(data []byte, installationID string, channel Channel, version string, now time.Time) (*VerifiedEntitlement, error) {
	if channel == ChannelCommunity {
		return nil, fmt.Errorf("community releases do not require a local entitlement")
	}
	e, err := ParseEntitlement(data)
	if err != nil {
		return nil, err
	}
	if e.InstallationID != installationID {
		return nil, fmt.Errorf("entitlement installation scope mismatch")
	}
	if !containsChannel(e.Channels, channel) {
		return nil, fmt.Errorf("entitlement channel scope mismatch")
	}
	if version != "" {
		eligible := false
		for _, r := range e.VersionRanges {
			ok, rangeErr := VersionInRange(version, r)
			if rangeErr == nil && ok {
				eligible = true
				break
			}
		}
		if !eligible {
			return nil, fmt.Errorf("entitlement version scope mismatch")
		}
	}
	canonical, err := CanonicalEntitlement(e)
	if err != nil {
		return nil, err
	}
	key, ok := s.keys[e.KeyID]
	if !ok || key.Purpose != PurposeEntitlement || (key.TestOnly && !s.allowTestRoots) {
		return nil, fmt.Errorf("untrusted entitlement key")
	}
	sig, err := base64.RawStdEncoding.DecodeString(e.Signatures[0].Value)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key.PublicKey, canonical, sig) {
		return nil, fmt.Errorf("invalid entitlement signature")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	from, _ := time.Parse(time.RFC3339, e.ValidFrom)
	until, _ := time.Parse(time.RFC3339, e.ValidUntil)
	grace, _ := time.Parse(time.RFC3339, e.GraceUntil)
	if now.Before(from) {
		return nil, fmt.Errorf("entitlement is not yet valid")
	}
	state := EntitlementValid
	if !now.Before(until) {
		if !now.Before(grace) {
			return nil, fmt.Errorf("entitlement is expired")
		}
		state = EntitlementGrace
	}
	sum := sha256.Sum256(canonical)
	return &VerifiedEntitlement{Entitlement: e, State: state, Digest: hex.EncodeToString(sum[:])}, nil
}
func SignEntitlement(e *Entitlement, s Ed25519Signer) error {
	if e.KeyID != s.ID {
		return fmt.Errorf("entitlement key_id does not match signer")
	}
	e.Signatures = nil
	canonical, err := CanonicalEntitlement(e)
	if err != nil {
		return err
	}
	raw, err := s.Sign(nil, canonical)
	if err != nil {
		return fmt.Errorf("sign entitlement: signer failed")
	}
	e.Signatures = []Signature{{KeyID: s.ID, Algorithm: "ed25519", Value: base64.RawStdEncoding.EncodeToString(raw)}}
	return nil
}
func containsChannel(channels []Channel, want Channel) bool {
	i := sort.Search(len(channels), func(i int) bool { return channels[i] >= want })
	return i < len(channels) && channels[i] == want
}

type SeatSubject struct {
	Enabled, Deleted, InternalHuman                             bool
	MailboxlessGuest, SharedOrResource, Alias, ServicePrincipal bool
}

func CountBillableSeats(subjects []SeatSubject) int {
	n := 0
	for _, s := range subjects {
		if s.Enabled && !s.Deleted && s.InternalHuman && !s.MailboxlessGuest && !s.SharedOrResource && !s.Alias && !s.ServicePrincipal {
			n++
		}
	}
	return n
}
