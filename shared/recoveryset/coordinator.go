package recoveryset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

const maxManifestBytes = 1 << 20
const maxBlobInventoryBytes = 256 << 20

type blobInventory struct {
	Timestamp string   `json:"timestamp"`
	Type      string   `json:"type"`
	Hashes    []string `json:"hashes"`
	Count     int      `json:"count"`
	TotalSize int64    `json:"total_size"`
}

type ObjectInfo struct{ Size int64 }

type Store interface {
	HeadObject(context.Context, string) (ObjectInfo, error)
	GetObject(context.Context, string) (io.ReadCloser, error)
	PutObject(context.Context, string, io.Reader, int64) error
}

type Coordinator struct {
	Store Store
	Key   []byte
}

func ManifestObjectKey(recoverySetID string) string {
	return "recovery-sets/" + recoverySetID + "/manifest.json"
}

func (coordinator Coordinator) Commit(ctx context.Context, manifest Manifest) (Envelope, error) {
	if coordinator.Store == nil {
		return Envelope{}, errors.New("recovery set store is required")
	}
	for _, artifact := range []Artifact{manifest.Database, manifest.DatabaseRestoreList, manifest.Blobs, manifest.Configuration} {
		if err := verifyArtifact(ctx, coordinator.Store, artifact); err != nil {
			return Envelope{}, fmt.Errorf("verify %s: %w", artifact.ObjectKey, err)
		}
	}
	if err := verifyBlobInventory(ctx, coordinator.Store, manifest.Blobs, manifest.Counts); err != nil {
		return Envelope{}, fmt.Errorf("verify blob inventory: %w", err)
	}
	envelope, err := Seal(manifest, coordinator.Key)
	if err != nil {
		return Envelope{}, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal recovery envelope: %w", err)
	}
	if err := coordinator.Store.PutObject(ctx, ManifestObjectKey(manifest.RecoverySetID), bytes.NewReader(raw), int64(len(raw))); err != nil {
		return Envelope{}, fmt.Errorf("write recovery set commit point: %w", err)
	}
	return envelope, nil
}

func (coordinator Coordinator) LoadVerified(ctx context.Context, recoverySetID string, policy VerifyPolicy) (Verdict, error) {
	_, verdict, err := coordinator.LoadVerifiedEnvelope(ctx, recoverySetID, policy)
	return verdict, err
}

// LoadVerifiedEnvelope returns the authenticated manifest as well as its
// verdict so an operator client can register the exact evidence it verified.
func (coordinator Coordinator) LoadVerifiedEnvelope(ctx context.Context, recoverySetID string, policy VerifyPolicy) (Envelope, Verdict, error) {
	if _, err := uuid.Parse(recoverySetID); err != nil {
		return Envelope{}, Verdict{}, errors.New("invalid recovery set id")
	}
	r, err := coordinator.Store.GetObject(ctx, ManifestObjectKey(recoverySetID))
	if err != nil {
		return Envelope{}, Verdict{}, fmt.Errorf("read recovery set: %w", err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(r, maxManifestBytes+1))
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return Envelope{}, Verdict{}, fmt.Errorf("read recovery set: %w", err)
	}
	if len(raw) > maxManifestBytes {
		return Envelope{}, Verdict{}, errors.New("recovery set manifest exceeds size limit")
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, Verdict{}, errors.New("invalid recovery set envelope JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Envelope{}, Verdict{}, errors.New("invalid trailing recovery set JSON")
	}
	verdict, err := Verify(envelope, coordinator.Key, policy)
	if err != nil {
		return Envelope{}, Verdict{}, err
	}
	// Bind the object-storage locator to the verified manifest
	// (D-SHARED-RECOVERYSET-V-001): the locator is the one unauthenticated
	// input not covered by the HMAC, so out-of-band store manipulation could
	// otherwise serve a legitimately sealed manifest for set A under set B's
	// key and have it verify cleanly. Commit always writes under the
	// manifest's own ID, so a mismatch here is corruption or tampering.
	if envelope.Manifest.RecoverySetID != recoverySetID {
		return Envelope{}, Verdict{}, errors.New("recovery set manifest does not match the requested recovery set id")
	}
	for _, artifact := range []Artifact{envelope.Manifest.Database, envelope.Manifest.DatabaseRestoreList, envelope.Manifest.Blobs, envelope.Manifest.Configuration} {
		if err := verifyArtifact(ctx, coordinator.Store, artifact); err != nil {
			return Envelope{}, Verdict{}, fmt.Errorf("verify %s: %w", artifact.ObjectKey, err)
		}
	}
	if err := verifyBlobInventory(ctx, coordinator.Store, envelope.Manifest.Blobs, envelope.Manifest.Counts); err != nil {
		return Envelope{}, Verdict{}, fmt.Errorf("verify blob inventory: %w", err)
	}
	return envelope, verdict, nil
}

func verifyBlobInventory(ctx context.Context, store Store, artifact Artifact, counts Counts) error {
	if artifact.Size > maxBlobInventoryBytes {
		return errors.New("blob inventory exceeds size limit")
	}
	r, err := store.GetObject(ctx, artifact.ObjectKey)
	if err != nil {
		return err
	}
	raw, readErr := io.ReadAll(io.LimitReader(r, maxBlobInventoryBytes+1))
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if len(raw) > maxBlobInventoryBytes {
		return errors.New("blob inventory exceeds size limit")
	}
	var inventory blobInventory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return errors.New("invalid blob inventory JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing blob inventory JSON")
	}
	if inventory.Type != "full" && inventory.Type != "incr" {
		return errors.New("invalid blob inventory type")
	}
	if inventory.Count != len(inventory.Hashes) || int64(inventory.Count) != counts.Blobs || inventory.TotalSize != counts.BlobBytes {
		return errors.New("blob inventory counts do not match recovery manifest")
	}
	seen := make(map[string]struct{}, len(inventory.Hashes))
	var total int64
	for _, digest := range inventory.Hashes {
		if !canonicalDigest.MatchString(digest) {
			return errors.New("blob inventory contains invalid digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("blob inventory contains duplicate digest")
		}
		seen[digest] = struct{}{}
		key := "blobs/" + digest
		info, err := store.HeadObject(ctx, key)
		if err != nil {
			return fmt.Errorf("head %s: %w", key, err)
		}
		blob, err := store.GetObject(ctx, key)
		if err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		h := sha256.New()
		n, readErr := io.Copy(h, blob)
		closeErr := blob.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		if n != info.Size || hex.EncodeToString(h.Sum(nil)) != digest {
			return fmt.Errorf("blob %s failed content verification", digest)
		}
		if info.Size > int64(^uint64(0)>>1)-total {
			return errors.New("blob inventory size overflow")
		}
		total += info.Size
	}
	if total != inventory.TotalSize {
		return errors.New("blob inventory byte count does not match stored objects")
	}
	return nil
}

func verifyArtifact(ctx context.Context, store Store, artifact Artifact) error {
	if err := validateArtifact(artifact); err != nil {
		return err
	}
	info, err := store.HeadObject(ctx, artifact.ObjectKey)
	if err != nil {
		return err
	}
	if info.Size != artifact.Size {
		return fmt.Errorf("size mismatch: expected %d got %d", artifact.Size, info.Size)
	}
	r, err := store.GetObject(ctx, artifact.ObjectKey)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, readErr := io.Copy(h, r)
	closeErr := r.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	if n != artifact.Size || hex.EncodeToString(h.Sum(nil)) != artifact.SHA256 {
		return errors.New("artifact digest mismatch")
	}
	return nil
}
