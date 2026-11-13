package recoveryset

import (
	"time"

	shared "setjoin.com/shared/recoveryset"
)

type ObjectInfo = shared.ObjectInfo
type Store = shared.Store
type Coordinator = shared.Coordinator

const ManifestVersion = shared.ManifestVersion

const (
	DefaultFreshness       = shared.DefaultFreshness
	RestoreProofWarningAge = shared.RestoreProofWarningAge
)

type Artifact = shared.Artifact
type ProtectedKeyEvidence = shared.ProtectedKeyEvidence
type Counts = shared.Counts
type Manifest = shared.Manifest
type Envelope = shared.Envelope
type RestoreProof = shared.RestoreProof

type VerifyPolicy = shared.VerifyPolicy
type Verdict = shared.Verdict

func ManifestObjectKey(recoverySetID string) string {
	return shared.ManifestObjectKey(recoverySetID)
}

func Seal(manifest Manifest, key []byte) (Envelope, error) {
	return shared.Seal(manifest, key)
}

func Verify(envelope Envelope, key []byte, policy VerifyPolicy) (Verdict, error) {
	return shared.Verify(envelope, key, policy)
}

func ValidateRestoreProof(proof RestoreProof, manifest Manifest, now time.Time) (string, error) {
	return shared.ValidateRestoreProof(proof, manifest, now)
}
