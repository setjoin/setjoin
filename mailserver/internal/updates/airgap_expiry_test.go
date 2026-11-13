package updates

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

// This file covers the authenticated air-gap bundle contract: the persisted
// sidecar carries expiry/key metadata bound into the bundle's signature, so
// reload, appcast advertisement, and ServeFile enforce authenticity rather
// than mere field presence. Expired and revoked-key bundles disappear from
// the appcast and 404 on serve, and legacy sidecars without authenticated
// metadata are quarantined, never advertised, never served.

// airgapSigner generates one offline-update signing key and an empty store
// trusting it, so tests can sign target documents and reload stores against
// the same or a different trust set.
type airgapSigner struct {
	store   *Store
	private ed25519.PrivateKey
	keyID   string
}

func newAirgapSigner(t *testing.T, dir, keyID string) *airgapSigner {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := release.NewTrustStore([]release.TrustedKey{{ID: keyID, Purpose: release.PurposeOfflineUpdate, PublicKey: public}}, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	return &airgapSigner{store: store, private: private, keyID: keyID}
}

// sign returns the signed offline target metadata document for the bundle;
// the detached signature binds ExpiresAt and KeyID via the canonical form.
func (s *airgapSigner) sign(t *testing.T, slug, filename string, payload []byte, metadataVersion uint64, expires time.Time) string {
	t.Helper()
	sum := sha256.Sum256(payload)
	metadata := targetMetadata{
		SchemaVersion:   1,
		MetadataVersion: metadataVersion,
		ExpiresAt:       expires.Format(time.RFC3339),
		Slug:            slug,
		Version:         "1.2.3",
		Platform:        "desktop",
		Filename:        filename,
		SizeBytes:       int64(len(payload)),
		SHA256:          hex.EncodeToString(sum[:]),
		KeyID:           s.keyID,
	}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.private, canonical))
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// signedSidecarBundle builds the persisted sidecar form of a bundle admitted
// under its signed metadata document, with ExpiresAt derived from the
// authenticated document exactly as the admission path does.
func (s *airgapSigner) signedSidecarBundle(t *testing.T, slug, filename string, payload []byte, metadataVersion uint64, expires time.Time) Bundle {
	t.Helper()
	metadata := s.sign(t, slug, filename, payload, metadataVersion, expires)
	parsed, err := time.Parse(time.RFC3339, expires.Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	return Bundle{
		Version:         "1.2.3",
		Platform:        "desktop",
		Slug:            slug,
		Filename:        filename,
		SHA256:          hex.EncodeToString(sum[:]),
		SizeBytes:       int64(len(payload)),
		Uploaded:        time.Now(),
		MetadataVersion: metadataVersion,
		ExpiresAt:       parsed,
		KeyID:           s.keyID,
		TargetMetadata:  metadata,
	}
}

func writeAirgapSidecar(t *testing.T, dir string, b Bundle) {
	t.Helper()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, b.Slug+".json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
}

func airgapAppcastBody(t *testing.T, store *Store) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/updates/appcast", nil)
	rr := httptest.NewRecorder()
	store.HandleAppcast(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("appcast status = %d, want 200", rr.Code)
	}
	return rr.Body.String()
}

func airgapServe(t *testing.T, store *Store, slug, filename string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/updates/"+slug+"/"+filename, nil)
	req.SetPathValue("slug", slug)
	req.SetPathValue("filename", filename)
	rr := httptest.NewRecorder()
	store.ServeFile(rr, req)
	return rr
}

// TestAirgapExpiredBundleDisappearsFromAppcastAndServe verifies that a bundle
// past its authenticated expiry is quarantined at reload, and that a bundle
// which expires while the server runs disappears from the appcast and 404s
// on serve.
func TestAirgapExpiredBundleDisappearsFromAppcastAndServe(t *testing.T) {
	payload := []byte("expiring payload")

	// Reload-time: a sidecar whose authenticated expiry already passed is
	// never re-admitted.
	expiredDir := t.TempDir()
	expiredSigner := newAirgapSigner(t, expiredDir, "offline-test")
	writeAirgapSidecar(t, expiredDir, expiredSigner.signedSidecarBundle(t, "desktop", "bundle.bin", payload, 1, time.Now().UTC().Add(-time.Minute)))
	if err := os.WriteFile(filepath.Join(expiredDir, "desktop_bundle.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newStore(expiredDir, expiredSigner.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Get("desktop") != nil {
		t.Fatal("expired bundle was re-admitted at reload")
	}
	if body := airgapAppcastBody(t, reloaded); strings.Contains(body, "1.2.3") {
		t.Fatalf("expired bundle advertised in appcast: %s", body)
	}
	if rr := airgapServe(t, reloaded, "desktop", "bundle.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("expired bundle serve status = %d, want 404", rr.Code)
	}

	// Runtime: a bundle admitted before its authenticated expiry stops being
	// advertised and served once the expiry passes.
	liveDir := t.TempDir()
	liveSigner := newAirgapSigner(t, liveDir, "offline-test")
	metadata := liveSigner.sign(t, "desktop", "bundle.bin", payload, 1, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, liveSigner.store, "desktop", "bundle.bin", metadata, payload); rr.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200", rr.Code)
	}
	liveSigner.store.mu.RLock()
	admitted := liveSigner.store.bundle["desktop"]
	liveSigner.store.mu.RUnlock()
	if admitted == nil || admitted.ExpiresAt.IsZero() {
		t.Fatalf("admitted bundle = %#v, want authenticated expiry", admitted)
	}
	liveSigner.store.mu.Lock()
	admitted.ExpiresAt = time.Now().UTC().Add(-time.Second)
	liveSigner.store.mu.Unlock()
	if body := airgapAppcastBody(t, liveSigner.store); strings.Contains(body, "1.2.3") {
		t.Fatalf("bundle still advertised after authenticated expiry: %s", body)
	}
	if rr := airgapServe(t, liveSigner.store, "desktop", "bundle.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("bundle serve status after expiry = %d, want 404", rr.Code)
	}
}

// TestAirgapRevokedKeyBundleRejectedAtReloadAndNeverServed verifies that a
// sidecar signed by a key that is no longer trusted is rejected at reload and
// never advertised or served, while the same sidecar still loads under the
// trust set that contains its signing key.
func TestAirgapRevokedKeyBundleRejectedAtReloadAndNeverServed(t *testing.T) {
	payload := []byte("revoked-key payload")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-key-1")
	writeAirgapSidecar(t, dir, signer.signedSidecarBundle(t, "desktop", "bundle.bin", payload, 1, time.Now().UTC().Add(time.Hour)))
	if err := os.WriteFile(filepath.Join(dir, "desktop_bundle.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}

	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	revokedTrust, err := release.NewTrustStore([]release.TrustedKey{{ID: "offline-key-2", Purpose: release.PurposeOfflineUpdate, PublicKey: otherPublic}}, false)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := newStore(dir, revokedTrust)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Get("desktop") != nil {
		t.Fatal("revoked-key bundle was re-admitted at reload")
	}
	if body := airgapAppcastBody(t, revoked); strings.Contains(body, "1.2.3") {
		t.Fatalf("revoked-key bundle advertised in appcast: %s", body)
	}
	if rr := airgapServe(t, revoked, "desktop", "bundle.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("revoked-key bundle serve status = %d, want 404", rr.Code)
	}

	trusting, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	if trusting.Get("desktop") == nil {
		t.Fatal("identical sidecar failed to load under the trusting store")
	}
}

// TestAirgapReloadRejectsMutatedExpiresAtKeyIDAndOuterFields verifies that a
// mutated ExpiresAt or KeyID inside the persisted metadata fails signature
// verification at reload, and that persisted bundle fields diverging from the
// authenticated metadata are rejected as well.
func TestAirgapReloadRejectsMutatedExpiresAtKeyIDAndOuterFields(t *testing.T) {
	payload := []byte("signed payload")
	goodExpiry := time.Now().UTC().Add(time.Hour)

	mutateDocument := func(field string, value any) func(*testing.T, string, *airgapSigner, Bundle) {
		return func(t *testing.T, dir string, signer *airgapSigner, bundle Bundle) {
			t.Helper()
			var doc map[string]any
			if err := json.Unmarshal([]byte(bundle.TargetMetadata), &doc); err != nil {
				t.Fatal(err)
			}
			doc[field] = value
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			bundle.TargetMetadata = string(raw)
			writeAirgapSidecar(t, dir, bundle)
		}
	}

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, dir string, signer *airgapSigner, bundle Bundle)
	}{
		{name: "mutated_expires_at", mutate: mutateDocument("expires_at", goodExpiry.Add(2*time.Hour).Format(time.RFC3339))},
		{name: "mutated_key_id", mutate: mutateDocument("key_id", "offline-other")},
		{name: "mutated_outer_sha256", mutate: func(t *testing.T, dir string, signer *airgapSigner, bundle Bundle) {
			t.Helper()
			bundle.SHA256 = strings.Repeat("b", 64)
			writeAirgapSidecar(t, dir, bundle)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			signer := newAirgapSigner(t, dir, "offline-test")
			bundle := signer.signedSidecarBundle(t, "desktop", "bundle.bin", payload, 1, goodExpiry)
			tc.mutate(t, dir, signer, bundle)
			reloaded, err := newStore(dir, signer.store.trust)
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.Get("desktop") != nil {
				t.Fatalf("%s: mutated bundle was re-admitted at reload", tc.name)
			}
			if body := airgapAppcastBody(t, reloaded); strings.Contains(body, "1.2.3") {
				t.Fatalf("%s: mutated bundle advertised in appcast: %s", tc.name, body)
			}
			if rr := airgapServe(t, reloaded, "desktop", "bundle.bin"); rr.Code != http.StatusNotFound {
				t.Fatalf("%s: serve status = %d, want 404", tc.name, rr.Code)
			}
		})
	}
}

// TestAirgapLegacySidecarQuarantinedAndNeverServed verifies that a legacy
// sidecar without authenticated metadata fails closed: quarantined on disk,
// never re-admitted, never advertised, never served. Even a validly signed
// sidecar fails closed when no trust roots are installed.
func TestAirgapLegacySidecarQuarantinedAndNeverServed(t *testing.T) {
	payload := []byte("legacy payload")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-test")

	sum := sha256.Sum256(payload)
	writeAirgapSidecar(t, dir, Bundle{
		Version: "1.2.3", Platform: "desktop", Slug: "desktop", Filename: "bundle.bin",
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(payload)),
		Uploaded: time.Now(), MetadataVersion: 1,
	})
	if err := os.WriteFile(filepath.Join(dir, "desktop_bundle.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}
	writeAirgapSidecar(t, dir, signer.signedSidecarBundle(t, "signed", "bundle.bin", payload, 1, time.Now().UTC().Add(time.Hour)))
	if err := os.WriteFile(filepath.Join(dir, "signed_bundle.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Get("desktop") != nil {
		t.Fatal("legacy sidecar without authenticated metadata was re-admitted")
	}
	if body := airgapAppcastBody(t, reloaded); strings.Contains(body, `"slug":"desktop"`) {
		t.Fatalf("legacy bundle advertised in appcast: %s", body)
	}
	if rr := airgapServe(t, reloaded, "desktop", "bundle.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("legacy bundle serve status = %d, want 404", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "desktop.json")); err != nil {
		t.Fatalf("legacy sidecar was deleted instead of quarantined: %v", err)
	}

	// Without installed trust roots nothing can be authenticated: fail closed.
	noTrust, err := newStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if noTrust.Get("signed") != nil || noTrust.Get("desktop") != nil {
		t.Fatal("bundles admitted without installed trust roots")
	}
	if rr := airgapServe(t, noTrust, "signed", "bundle.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("no-trust serve status = %d, want 404", rr.Code)
	}
}

// TestAirgapUnexpiredSignedBundleServesUnchanged verifies the positive path:
// an unexpired validly signed bundle is advertised and served unchanged, and
// its persisted sidecar reloads with the authenticated expiry and key derived.
func TestAirgapUnexpiredSignedBundleServesUnchanged(t *testing.T) {
	payload := []byte("valid bundle payload")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-test")
	metadata := signer.sign(t, "desktop", "bundle.bin", payload, 3, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, signer.store, "desktop", "bundle.bin", metadata, payload); rr.Code != http.StatusOK {
		t.Fatalf("upload status = %d, want 200", rr.Code)
	}

	body := airgapAppcastBody(t, signer.store)
	if !strings.Contains(body, `"version":"1.2.3"`) || !strings.Contains(body, "/updates/desktop/bundle.bin") {
		t.Fatalf("appcast = %s", body)
	}
	if rr := airgapServe(t, signer.store, "desktop", "bundle.bin"); rr.Code != http.StatusOK || rr.Body.String() != string(payload) {
		t.Fatalf("serve = %d %q, want 200 with payload", rr.Code, rr.Body.String())
	}

	reloaded, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	loaded := reloaded.Get("desktop")
	if loaded == nil || loaded.KeyID != "offline-test" || loaded.ExpiresAt.IsZero() {
		t.Fatalf("reloaded bundle = %#v, want authenticated expiry and key", loaded)
	}
	if rr := airgapServe(t, reloaded, "desktop", "bundle.bin"); rr.Code != http.StatusOK || rr.Body.String() != string(payload) {
		t.Fatalf("reloaded serve = %d %q, want 200 with payload", rr.Code, rr.Body.String())
	}
}

// TestAirgapExpiryRestartRejectsOlderVersionUpload is the expiry → restart →
// older-upload regression: after the highest admitted version expires, a
// reload must keep quarantining it as unservable while still counting its
// authenticated metadata version toward the upload rollback floor. A
// still-validly signed older version must then be rejected with 409 instead
// of being admitted as if nothing had ever been published.
func TestAirgapExpiryRestartRejectsOlderVersionUpload(t *testing.T) {
	payload := []byte("expired v2 payload")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-test")
	// On-disk state after version 2 was admitted and later expired: the
	// signature still verifies against the installed trust roots, but the
	// authenticated expiry has passed.
	writeAirgapSidecar(t, dir, signer.signedSidecarBundle(t, "desktop", "v2.bin", payload, 2, time.Now().UTC().Add(-time.Minute)))
	if err := os.WriteFile(filepath.Join(dir, "desktop_v2.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}

	restarted, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	// Expiry still quarantines: never admitted, never served.
	if restarted.Get("desktop") != nil {
		t.Fatal("expired bundle was re-admitted at reload")
	}
	if rr := airgapServe(t, restarted, "desktop", "v2.bin"); rr.Code != http.StatusNotFound {
		t.Fatalf("expired bundle serve status = %d, want 404", rr.Code)
	}

	// A still-valid signed version 1 with unexpired metadata must hit the
	// rollback floor left by the expired version 2, not the empty bundle map.
	v1Payload := []byte("rollback attempt payload")
	v1Metadata := signer.sign(t, "desktop", "v1.bin", v1Payload, 1, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, restarted, "desktop", "v1.bin", v1Metadata, v1Payload); rr.Code != http.StatusConflict {
		t.Fatalf("older upload after expiry+restart status = %d, want 409", rr.Code)
	}

	// The equal version is equally behind the floor.
	v2Payload := []byte("replayed v2 payload")
	v2Metadata := signer.sign(t, "desktop", "v2.bin", v2Payload, 2, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, restarted, "desktop", "v2.bin", v2Metadata, v2Payload); rr.Code != http.StatusConflict {
		t.Fatalf("equal-version upload after expiry+restart status = %d, want 409", rr.Code)
	}

	// The floor blocks only older versions: a genuinely newer signed version
	// must still be admitted and served.
	v3Payload := []byte("newer v3 payload")
	v3Metadata := signer.sign(t, "desktop", "v3.bin", v3Payload, 3, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, restarted, "desktop", "v3.bin", v3Metadata, v3Payload); rr.Code != http.StatusOK {
		t.Fatalf("newer upload after expiry+restart status = %d, want 200", rr.Code)
	}
	if got := restarted.Get("desktop"); got == nil || got.Filename != "v3.bin" {
		t.Fatalf("bundle after newer upload = %#v, want v3.bin", got)
	}
}

// TestAirgapRollbackFloorPersistsAcrossReload verifies that the highest
// authenticated admitted metadata version survives a reload through its
// sidecar: after a store that admitted version 3 is reloaded from disk, older
// or equal still-valid signed uploads are rejected even though the rollback
// decision can no longer rely on any in-memory state from the original run.
func TestAirgapRollbackFloorPersistsAcrossReload(t *testing.T) {
	payload := []byte("highest admitted payload")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-test")
	v3Metadata := signer.sign(t, "desktop", "v3.bin", payload, 3, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, signer.store, "desktop", "v3.bin", v3Metadata, payload); rr.Code != http.StatusOK {
		t.Fatalf("initial v3 upload status = %d, want 200", rr.Code)
	}

	reloaded, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Get("desktop") == nil {
		t.Fatal("valid bundle failed to reload")
	}

	for _, tc := range []struct {
		version  uint64
		filename string
		want     int
	}{
		{version: 2, filename: "v2.bin", want: http.StatusConflict},
		{version: 1, filename: "v1.bin", want: http.StatusConflict},
		{version: 3, filename: "v3-again.bin", want: http.StatusConflict},
	} {
		olderPayload := []byte("older payload " + tc.filename)
		olderMetadata := signer.sign(t, "desktop", tc.filename, olderPayload, tc.version, time.Now().UTC().Add(time.Hour))
		if rr := uploadTarget(t, reloaded, "desktop", tc.filename, olderMetadata, olderPayload); rr.Code != tc.want {
			t.Fatalf("version %d upload after reload status = %d, want %d", tc.version, rr.Code, tc.want)
		}
	}
}

// TestAirgapUnauthenticatedSidecarDoesNotRaiseRollbackFloor verifies the
// floor counts only authenticated admissions: a sidecar whose metadata
// signature fails (tampered, untrusted key) is quarantined and must not
// reserve its claimed version, so the operator can still publish a genuine
// lower version for that slug.
func TestAirgapUnauthenticatedSidecarDoesNotRaiseRollbackFloor(t *testing.T) {
	payload := []byte("forged high version")
	dir := t.TempDir()
	signer := newAirgapSigner(t, dir, "offline-test")
	forged := signer.signedSidecarBundle(t, "desktop", "v9.bin", payload, 9, time.Now().UTC().Add(time.Hour))
	// Invalidate the signature without touching the claimed version fields.
	forged.TargetMetadata = strings.Replace(forged.TargetMetadata, `"version":"1.2.3"`, `"version":"9.9.9"`, 1)
	writeAirgapSidecar(t, dir, forged)
	if err := os.WriteFile(filepath.Join(dir, "desktop_v9.bin"), payload, 0o640); err != nil {
		t.Fatal(err)
	}

	reloaded, err := newStore(dir, signer.store.trust)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Get("desktop") != nil {
		t.Fatal("forged sidecar was re-admitted at reload")
	}

	// The forged version 9 did not floor the slug: a genuine version 1 upload
	// signed by the trusted key is admitted.
	v1Payload := []byte("genuine v1 payload")
	v1Metadata := signer.sign(t, "desktop", "v1.bin", v1Payload, 1, time.Now().UTC().Add(time.Hour))
	if rr := uploadTarget(t, reloaded, "desktop", "v1.bin", v1Metadata, v1Payload); rr.Code != http.StatusOK {
		t.Fatalf("genuine v1 upload status = %d, want 200", rr.Code)
	}
}
