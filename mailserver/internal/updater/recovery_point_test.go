package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/recoveryset"
)

type recoveryPointStore struct{ objects map[string][]byte }

type staticRecoveryIdentity struct {
	identity RecoveryIdentity
	err      error
}

func (provider staticRecoveryIdentity) RecoveryIdentity(context.Context) (RecoveryIdentity, error) {
	return provider.identity, provider.err
}

func (store recoveryPointStore) HeadObject(_ context.Context, key string) (recoveryset.ObjectInfo, error) {
	raw, ok := store.objects[key]
	if !ok {
		return recoveryset.ObjectInfo{}, errors.New("not found")
	}
	return recoveryset.ObjectInfo{Size: int64(len(raw))}, nil
}

func (store recoveryPointStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	raw, ok := store.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func (store recoveryPointStore) PutObject(_ context.Context, key string, reader io.Reader, _ int64) error {
	raw, err := io.ReadAll(reader)
	if err == nil {
		store.objects[key] = raw
	}
	return err
}

func recoveryPointArtifact(key string, raw []byte) recoveryset.Artifact {
	digest := sha256.Sum256(raw)
	return recoveryset.Artifact{ObjectKey: key, Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
}

func verifiedRecoveryPointFixtureAt(t *testing.T, now time.Time) (VerifiedRecoveryPointProvider, Transaction, time.Time) {
	t.Helper()
	objects := map[string][]byte{
		"recovery/db.dump":    []byte("database"),
		"recovery/db.list":    []byte("restore-list"),
		"recovery/blobs.json": []byte(`{"timestamp":"20260801T110000Z","type":"full","hashes":[],"count":0,"total_size":0}`),
		"recovery/config.enc": []byte("encrypted-config"),
	}
	store := recoveryPointStore{objects: objects}
	manifest := recoveryset.Manifest{
		Version: recoveryset.ManifestVersion, RecoverySetID: "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222", TimelineID: "33333333-3333-4333-8333-333333333333",
		SourceReleaseID: "release-178", SchemaVersion: 178, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(23 * time.Hour),
		Database:             recoveryPointArtifact("recovery/db.dump", objects["recovery/db.dump"]),
		DatabaseRestoreList:  recoveryPointArtifact("recovery/db.list", objects["recovery/db.list"]),
		Blobs:                recoveryPointArtifact("recovery/blobs.json", objects["recovery/blobs.json"]),
		Configuration:        recoveryPointArtifact("recovery/config.enc", objects["recovery/config.enc"]),
		ProtectedKeyEvidence: recoveryset.ProtectedKeyEvidence{Mode: "external", KeyID: "db-key", Fingerprint: strings.Repeat("a", 64)},
		FeatureToggleSHA256:  strings.Repeat("b", 64),
	}
	coordinator := recoveryset.Coordinator{Store: store, Key: bytes.Repeat([]byte{0x42}, 32)}
	envelope, err := coordinator.Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	provider := VerifiedRecoveryPointProvider{
		Coordinator: coordinator,
		Identity: staticRecoveryIdentity{identity: RecoveryIdentity{
			InstallationID: manifest.InstallationID, TimelineID: manifest.TimelineID,
		}},
		Now: func() time.Time { return now },
	}
	tx := Transaction{RecoverySetID: manifest.RecoverySetID, RecoverySetDigest: envelope.ManifestSHA256}
	return provider, tx, now
}

func verifiedRecoveryPointFixture(t *testing.T) (VerifiedRecoveryPointProvider, Transaction, time.Time) {
	t.Helper()
	return verifiedRecoveryPointFixtureAt(t, time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC))
}

func TestVerifiedRecoveryPointProviderBindsFreshManifestToIntent(t *testing.T) {
	provider, tx, _ := verifiedRecoveryPointFixture(t)
	evidence, err := provider.RequireFresh(context.Background(), tx)
	if err != nil || evidence.RecoverySetID != tx.RecoverySetID || evidence.ManifestSHA256 != tx.RecoverySetDigest || evidence.CreatedAt.IsZero() || evidence.ExpiresAt.IsZero() {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
	tx.RecoverySetDigest = strings.Repeat("0", 64)
	if _, err := provider.RequireFresh(context.Background(), tx); err == nil || !strings.Contains(err.Error(), "authorized intent") {
		t.Fatalf("digest mismatch err=%v", err)
	}
}

func TestVerifiedRecoveryPointProviderFailsClosedOnMissingOrInvalidEvidence(t *testing.T) {
	provider, tx, now := verifiedRecoveryPointFixture(t)
	for name, mutate := range map[string]func(*VerifiedRecoveryPointProvider, *Transaction){
		"set":              func(_ *VerifiedRecoveryPointProvider, tx *Transaction) { tx.RecoverySetID = "" },
		"digest":           func(_ *VerifiedRecoveryPointProvider, tx *Transaction) { tx.RecoverySetDigest = "" },
		"identity missing": func(p *VerifiedRecoveryPointProvider, _ *Transaction) { p.Identity = nil },
		"identity error": func(p *VerifiedRecoveryPointProvider, _ *Transaction) {
			p.Identity = staticRecoveryIdentity{err: errors.New("identity unavailable")}
		},
		"stale": func(p *VerifiedRecoveryPointProvider, _ *Transaction) {
			p.Now = func() time.Time { return now.Add(25 * time.Hour) }
		},
		"wrong installation": func(p *VerifiedRecoveryPointProvider, _ *Transaction) {
			p.Identity = staticRecoveryIdentity{identity: RecoveryIdentity{
				InstallationID: "44444444-4444-4444-8444-444444444444",
				TimelineID:     "33333333-3333-4333-8333-333333333333",
			}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateProvider, candidateTx := provider, tx
			mutate(&candidateProvider, &candidateTx)
			if _, err := candidateProvider.RequireFresh(context.Background(), candidateTx); !errors.Is(err, ErrRecoveryPointUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	liveProvider, liveTx, _ := verifiedRecoveryPointFixtureAt(t, time.Now().UTC())
	liveProvider.Now = nil
	if _, err := liveProvider.RequireFresh(context.Background(), liveTx); err != nil {
		t.Fatalf("wall-clock default rejected fresh evidence: %v", err)
	}
}
