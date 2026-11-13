package recoveryset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type memoryStore struct {
	objects      map[string][]byte
	writes       []string
	headErr      error
	getErr       error
	corruptOnPut bool
}

func (store *memoryStore) HeadObject(_ context.Context, key string) (ObjectInfo, error) {
	if store.headErr != nil {
		return ObjectInfo{}, store.headErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return ObjectInfo{}, errors.New("not found")
	}
	return ObjectInfo{Size: int64(len(raw))}, nil
}

func (store *memoryStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	if store.getErr != nil {
		return nil, store.getErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func (store *memoryStore) PutObject(_ context.Context, key string, reader io.Reader, _ int64) error {
	raw, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if store.corruptOnPut {
		raw = append([]byte(nil), raw...)
		raw[0] ^= 0xff
	}
	store.objects[key] = raw
	store.writes = append(store.writes, key)
	return nil
}

func artifact(key string, raw []byte) Artifact {
	digest := sha256.Sum256(raw)
	return Artifact{ObjectKey: key, Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
}

func validManifest(now time.Time, objects map[string][]byte) Manifest {
	return Manifest{
		Version:         ManifestVersion,
		RecoverySetID:   "11111111-1111-4111-8111-111111111111",
		InstallationID:  "22222222-2222-4222-8222-222222222222",
		TimelineID:      "33333333-3333-4333-8333-333333333333",
		SourceReleaseID: "release-178", SchemaVersion: 178,
		CreatedAt: now.Add(-time.Hour).UTC(), ExpiresAt: now.Add(23 * time.Hour).UTC(),
		Database:             artifact("recovery/db.dump", objects["recovery/db.dump"]),
		DatabaseRestoreList:  artifact("recovery/db.list", objects["recovery/db.list"]),
		Blobs:                artifact("recovery/blobs.json", objects["recovery/blobs.json"]),
		Configuration:        artifact("recovery/config.enc", objects["recovery/config.enc"]),
		ProtectedKeyEvidence: ProtectedKeyEvidence{Mode: "external", KeyID: "recovery-key-1", Fingerprint: strings.Repeat("a", 64)},
		FeatureToggleSHA256:  strings.Repeat("b", 64),
		Counts:               Counts{Blobs: 1, BlobBytes: 4, Users: 2, Mailboxes: 2},
		RepresentativeIDs:    []string{"blob:abcd", "mailbox:42"},
	}
}

func fixture(t *testing.T) (*memoryStore, Manifest, []byte, time.Time) {
	t.Helper()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	blob := []byte("blob")
	blobDigest := sha256.Sum256(blob)
	blobHash := hex.EncodeToString(blobDigest[:])
	blobInventory := []byte(fmt.Sprintf(`{"timestamp":"20260801T110000Z","type":"incr","hashes":[%q],"count":1,"total_size":4}`, blobHash))
	objects := map[string][]byte{
		"recovery/db.dump": []byte("database"), "recovery/db.list": []byte("restore-list"),
		"recovery/blobs.json": blobInventory, "recovery/config.enc": []byte("encrypted-config"),
		"blobs/" + blobHash: blob,
	}
	return &memoryStore{objects: objects}, validManifest(now, objects), bytes.Repeat([]byte{0x42}, 32), now
}

func TestCoordinatorWritesManifestLastAndVerifiesEveryComponent(t *testing.T) {
	store, manifest, key, now := fixture(t)
	coordinator := Coordinator{Store: store, Key: key}
	envelope, err := coordinator.Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.writes[len(store.writes)-1]; got != ManifestObjectKey(manifest.RecoverySetID) {
		t.Fatalf("last write=%q", got)
	}
	verdict, err := coordinator.LoadVerified(context.Background(), manifest.RecoverySetID, VerifyPolicy{
		Now: now, ExpectedInstallationID: manifest.InstallationID, ExpectedTimelineID: manifest.TimelineID,
	})
	if err != nil || !verdict.Fresh || verdict.ManifestSHA256 != envelope.ManifestSHA256 {
		t.Fatalf("verdict=%+v err=%v", verdict, err)
	}
}

func TestCoordinatorRejectsPartialCorruptAndUnreadableSets(t *testing.T) {
	for _, mutate := range []func(*memoryStore, *Manifest){
		func(store *memoryStore, manifest *Manifest) { delete(store.objects, manifest.Blobs.ObjectKey) },
		func(store *memoryStore, manifest *Manifest) { store.objects[manifest.Database.ObjectKey][0] ^= 0xff },
		func(store *memoryStore, _ *Manifest) {
			for key := range store.objects {
				if strings.HasPrefix(key, "blobs/") {
					store.objects[key][0] ^= 0xff
					return
				}
			}
		},
		func(store *memoryStore, _ *Manifest) { store.headErr = errors.New("storage unavailable") },
		func(store *memoryStore, _ *Manifest) { store.getErr = errors.New("read denied") },
	} {
		store, manifest, key, _ := fixture(t)
		mutate(store, &manifest)
		if _, err := (Coordinator{Store: store, Key: key}).Commit(context.Background(), manifest); err == nil {
			t.Fatal("incomplete/corrupt/unreadable recovery set accepted")
		}
		if len(store.writes) != 0 {
			t.Fatal("commit point was written after failed component verification")
		}
	}
}

func TestVerifyRejectsTamperStaleAndWrongIdentity(t *testing.T) {
	_, manifest, key, now := fixture(t)
	envelope, err := Seal(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]struct {
		envelope Envelope
		policy   VerifyPolicy
	}{
		"tamper":       {func() Envelope { altered := envelope; altered.Manifest.Counts.Users++; return altered }(), VerifyPolicy{Now: now}},
		"stale":        {envelope, VerifyPolicy{Now: now.Add(25 * time.Hour)}},
		"installation": {envelope, VerifyPolicy{Now: now, ExpectedInstallationID: "44444444-4444-4444-8444-444444444444"}},
		"timeline":     {envelope, VerifyPolicy{Now: now, ExpectedTimelineID: "55555555-5555-4555-8555-555555555555"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(candidate.envelope, key, candidate.policy); err == nil {
				t.Fatal("invalid recovery set accepted")
			}
		})
	}
}

func TestRestoreProofRequiresNewIsolatedTargetAndWarnsAtNinetyDays(t *testing.T) {
	_, manifest, _, now := fixture(t)
	proof := RestoreProof{
		Version: ManifestVersion, RecoverySetID: manifest.RecoverySetID,
		TargetID: "isolated-target-1", SourceInstallation: manifest.InstallationID,
		Isolated: true, SchemaChecked: true, LoginChecked: true, MailChecked: true, BlobChecked: true,
		ProvedAt: manifest.CreatedAt.Add(time.Hour),
	}
	if warning, err := ValidateRestoreProof(proof, manifest, proof.ProvedAt.Add(91*24*time.Hour)); err != nil || warning == "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}
	proof.TargetID = manifest.InstallationID
	if _, err := ValidateRestoreProof(proof, manifest, now); err == nil {
		t.Fatal("in-place restore accepted as proof")
	}
}
