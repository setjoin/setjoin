package updater

import (
	"context"
	"errors"
	"time"

	"setjoin.com/mailserver/internal/recoveryset"
)

// VerifiedRecoveryPointProvider bridges the portable recovery-set verifier to
// the updater's narrow evidence-only interface. It never creates backups or
// accepts a caller-controlled location while an upgrade is running.
type VerifiedRecoveryPointProvider struct {
	Coordinator recoveryset.Coordinator
	Identity    RecoveryIdentityProvider
	Now         func() time.Time
}

type RecoveryIdentity struct {
	InstallationID string
	TimelineID     string
}

type RecoveryIdentityProvider interface {
	RecoveryIdentity(context.Context) (RecoveryIdentity, error)
}

func NewRecoveryCoordinator(store recoveryset.Store, key []byte) recoveryset.Coordinator {
	return recoveryset.Coordinator{Store: store, Key: append([]byte(nil), key...)}
}

func (provider VerifiedRecoveryPointProvider) RequireFresh(ctx context.Context, tx Transaction) (RecoveryPointEvidence, error) {
	if tx.RecoverySetID == "" || tx.RecoverySetDigest == "" || provider.Identity == nil {
		return RecoveryPointEvidence{}, ErrRecoveryPointUnavailable
	}
	identity, err := provider.Identity.RecoveryIdentity(ctx)
	if err != nil || identity.InstallationID == "" || identity.TimelineID == "" {
		return RecoveryPointEvidence{}, errors.Join(ErrRecoveryPointUnavailable, err)
	}
	now := time.Now().UTC()
	if provider.Now != nil {
		now = provider.Now().UTC()
	}
	verdict, err := provider.Coordinator.LoadVerified(ctx, tx.RecoverySetID, recoveryset.VerifyPolicy{
		Now: now, ExpectedInstallationID: identity.InstallationID,
		ExpectedTimelineID: identity.TimelineID, MaxAge: recoveryset.DefaultFreshness,
	})
	if err != nil {
		return RecoveryPointEvidence{}, errors.Join(ErrRecoveryPointUnavailable, err)
	}
	if verdict.ManifestSHA256 != tx.RecoverySetDigest {
		return RecoveryPointEvidence{}, errors.New("recovery set digest differs from the authorized intent")
	}
	return RecoveryPointEvidence{
		RecoverySetID: verdict.RecoverySetID, ManifestSHA256: verdict.ManifestSHA256,
		CreatedAt: verdict.CreatedAt, ExpiresAt: verdict.ExpiresAt,
	}, nil
}
