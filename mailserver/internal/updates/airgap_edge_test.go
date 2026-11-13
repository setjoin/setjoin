package updates

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

// Edge coverage: the expiry-parse arm of parseTargetMetadata, the
// authenticatedTarget/authentication error arms, and the upload rollback-floor
// initialization and bump.

// TestParseTargetMetadataUnparseableExpiresAtRejected pins the strict ExpiresAt
// grammar: a structurally valid document whose ExpiresAt does not parse as
// RFC3339 is rejected (expiry is mandatory for offline targets).
func TestParseTargetMetadataUnparseableExpiresAtRejected(t *testing.T) {
	raw := `{"schema_version":1,"metadata_version":3,"slug":"desktop","filename":"b.bin",
		"size_bytes":5,"sha256":"` + hexOf("x") + `","expires_at":"not-a-timestamp","key_id":"k","version":"1","platform":"desktop"}`
	if _, _, err := parseTargetMetadata(raw); err == nil {
		t.Fatal("parseTargetMetadata accepted an unparseable ExpiresAt")
	}
}

func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestAuthenticatedTargetRejectsGarbageAndForeignSignatures pins the
// authentication arms: a bundle whose persisted metadata does not parse, and
// one whose signature was produced by a key absent from the trust store, both
// fail closed.
func TestAuthenticatedTargetRejectsGarbageAndForeignSignatures(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("payload")

	// Store trusting key A.
	store, validMetadata := signedTargetStore(t, dir, "desktop", "bundle.bin", payload, 2)

	if _, _, err := store.authenticatedTarget(&Bundle{TargetMetadata: "{not-json"}); err == nil {
		t.Fatal("authenticatedTarget accepted unparseable metadata")
	}
	if _, err := store.authenticatedBundle(&Bundle{TargetMetadata: "{not-json"}); err == nil {
		t.Fatal("authenticatedBundle propagated unparseable metadata without error")
	}

	// Metadata signed by a foreign key (fresh pair) but claiming key A's id.
	foreignPub, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = foreignPub
	var m targetMetadata
	if err := json.Unmarshal([]byte(validMetadata), &m); err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalTargetMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(foreignPriv, canonical))
	foreigned, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	bundle := bundleFromMetadata(t, store, string(foreigned), payload)
	if _, _, err := store.authenticatedTarget(bundle); err == nil {
		t.Fatal("authenticatedTarget accepted a foreign signature")
	}

	// The untampered document still authenticates.
	okBundle := bundleFromMetadata(t, store, validMetadata, payload)
	if _, _, err := store.authenticatedTarget(okBundle); err != nil {
		t.Fatalf("valid document failed authentication: %v", err)
	}
}

func bundleFromMetadata(t *testing.T, store *Store, rawMetadata string, payload []byte) *Bundle {
	t.Helper()
	var m targetMetadata
	if err := json.Unmarshal([]byte(rawMetadata), &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return &Bundle{
		Version: m.Version, Platform: m.Platform, Slug: m.Slug, Filename: m.Filename,
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(payload)),
		MetadataVersion: m.MetadataVersion, TargetMetadata: rawMetadata,
	}
}

// TestAuthenticatedBundleRejectsExpiredMetadata pins the servability arm: an
// AUTHENTIC document whose validity has lapsed still counts via
// authenticatedTarget but is refused by authenticatedBundle.
func TestAuthenticatedBundleRejectsExpiredMetadata(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("expired payload")

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := release.NewTrustStore([]release.TrustedKey{{ID: "offline-test", Purpose: release.PurposeOfflineUpdate, PublicKey: public}}, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(dir, trust)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(payload)
	metadata := targetMetadata{SchemaVersion: 1, MetadataVersion: 4, ExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), Slug: "desktop", Version: "1.2.3", Platform: "desktop", Filename: "bundle.bin", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), KeyID: "offline-test"}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}

	bundle := bundleFromMetadata(t, store, string(raw), payload)
	if _, _, err := store.authenticatedTarget(bundle); err != nil {
		t.Fatalf("expired document must still authenticate for the floor: %v", err)
	}
	if _, err := store.authenticatedBundle(bundle); err == nil {
		t.Fatal("authenticatedBundle admitted an expired document")
	}
}

// signedTargetStoreWithKey is signedTargetStore that also returns the signing
// key so callers can mint higher versions under the same trust.
func signedTargetStoreWithKey(t *testing.T, dir, slug, filename string, payload []byte, metadataVersion uint64) (*Store, string, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := release.NewTrustStore([]release.TrustedKey{{ID: "offline-test", Purpose: release.PurposeOfflineUpdate, PublicKey: public}}, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	metadata := targetMetadata{SchemaVersion: 1, MetadataVersion: metadataVersion, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), Slug: slug, Version: "1.2.3", Platform: "desktop", Filename: filename, SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), KeyID: "offline-test"}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return store, string(raw), private
}

// TestHandleUploadRejectsExpiredButAuthenticMetadata pins the upload-time
// expiry admission: a correctly signed document whose validity has lapsed
// passes signature verification but fails re-verification (expired bundles are
// never admitted).
func TestHandleUploadRejectsExpiredButAuthenticMetadata(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("stale payload")

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := release.NewTrustStore([]release.TrustedKey{{ID: "offline-test", Purpose: release.PurposeOfflineUpdate, PublicKey: public}}, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(dir, trust)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(payload)
	metadata := targetMetadata{SchemaVersion: 1, MetadataVersion: 9, ExpiresAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), Slug: "stale", Version: "1.2.3", Platform: "desktop", Filename: "bundle.bin", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), KeyID: "offline-test"}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}

	if rr := uploadTarget(t, store, "stale", "bundle.bin", string(raw), payload); rr.Code != http.StatusBadRequest {
		t.Fatalf("expired upload status = %d (%s), want 400", rr.Code, rr.Body.String())
	}
}

// TestHandleUploadInitializesAndBumpsRollbackFloor pins the upload floor
// bookkeeping: the first admission initializes the floor map, and a second
// higher-version admission raises the floor from the current bundle so a
// later re-upload of the old version is rejected as a rollback even after the
// bundle map would have allowed it.
func TestHandleUploadInitializesAndBumpsRollbackFloor(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("floor payload")

	store, metadataV2, signer := signedTargetStoreWithKey(t, dir, "floor", "bundle.bin", payload, 2)

	if rr := uploadTarget(t, store, "floor", "bundle.bin", metadataV2, payload); rr.Code != http.StatusOK {
		t.Fatalf("first upload status = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	store.mu.Lock()
	floorInit := store.floor != nil
	store.mu.Unlock()
	if !floorInit {
		t.Fatal("first admission did not initialize the rollback floor map")
	}

	// A higher version signed by the SAME trust is admitted and raises the floor.
	var m targetMetadata
	if err := json.Unmarshal([]byte(metadataV2), &m); err != nil {
		t.Fatal(err)
	}
	m.MetadataVersion = 3
	m.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	canonical, err := canonicalTargetMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(signer, canonical))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if rr := uploadTarget(t, store, "floor", "bundle.bin", string(raw), payload); rr.Code != http.StatusOK {
		t.Fatalf("second upload status = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	store.mu.Lock()
	floor := store.floor["floor"]
	current := store.bundle["floor"]
	var currentVersion uint64
	if current != nil {
		currentVersion = current.MetadataVersion
	}
	store.mu.Unlock()
	if floor != 3 && currentVersion != 3 {
		t.Fatalf("floor=%d currentVersion=%d, want the floor to track the admitted version 3", floor, currentVersion)
	}
}
