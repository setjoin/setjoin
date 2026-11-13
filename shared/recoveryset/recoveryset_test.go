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
	"strings"
	"testing"
	"time"
)

type testReadCloser struct {
	*bytes.Reader
	readErr  error
	closeErr error
}

func (r *testReadCloser) Read(p []byte) (int, error) {
	if r.readErr != nil {
		return 0, r.readErr
	}
	return r.Reader.Read(p)
}

func (r *testReadCloser) Close() error { return r.closeErr }

type memoryStore struct {
	objects      map[string][]byte
	writes       []string
	headErr      error
	getErr       error
	putErr       error
	readErr      error
	closeErr     error
	sizeDelta    int64
	headErrKey   string
	getErrKey    string
	readErrKey   string
	closeErrKey  string
	corruptOnPut bool
}

func (store *memoryStore) HeadObject(_ context.Context, key string) (ObjectInfo, error) {
	if store.headErr != nil || store.headErrKey == key {
		return ObjectInfo{}, store.headErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return ObjectInfo{}, errors.New("not found")
	}
	return ObjectInfo{Size: int64(len(raw)) + store.sizeDelta}, nil
}

func (store *memoryStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	if store.getErr != nil || store.getErrKey == key {
		return nil, store.getErr
	}
	raw, ok := store.objects[key]
	if !ok {
		return nil, errors.New("not found")
	}
	readErr := store.readErr
	if store.readErrKey != "" && store.readErrKey != key {
		readErr = nil
	}
	closeErr := store.closeErr
	if store.closeErrKey != "" && store.closeErrKey != key {
		closeErr = nil
	}
	return &testReadCloser{Reader: bytes.NewReader(raw), readErr: readErr, closeErr: closeErr}, nil
}

func (store *memoryStore) PutObject(_ context.Context, key string, reader io.Reader, _ int64) error {
	if store.putErr != nil {
		return store.putErr
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if store.corruptOnPut && len(raw) > 0 {
		raw = append([]byte(nil), raw...)
		raw[0] ^= 0xff
	}
	store.objects[key] = raw
	store.writes = append(store.writes, key)
	return nil
}

func testArtifact(key string, raw []byte) Artifact {
	digest := sha256.Sum256(raw)
	return Artifact{ObjectKey: key, Size: int64(len(raw)), SHA256: hex.EncodeToString(digest[:])}
}

func testFixture() (*memoryStore, Manifest, []byte, time.Time) {
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
	manifest := Manifest{
		Version: ManifestVersion, RecoverySetID: "11111111-1111-4111-8111-111111111111",
		InstallationID: "22222222-2222-4222-8222-222222222222", TimelineID: "33333333-3333-4333-8333-333333333333",
		SourceReleaseID: "release-178", SchemaVersion: 178,
		CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(23 * time.Hour),
		Database:             testArtifact("recovery/db.dump", objects["recovery/db.dump"]),
		DatabaseRestoreList:  testArtifact("recovery/db.list", objects["recovery/db.list"]),
		Blobs:                testArtifact("recovery/blobs.json", objects["recovery/blobs.json"]),
		Configuration:        testArtifact("recovery/config.enc", objects["recovery/config.enc"]),
		ProtectedKeyEvidence: ProtectedKeyEvidence{Mode: "external", KeyID: "recovery-key-1", Fingerprint: strings.Repeat("a", 64)},
		FeatureToggleSHA256:  strings.Repeat("b", 64), Counts: Counts{Blobs: 1, BlobBytes: 4, Users: 2, Mailboxes: 2},
		RepresentativeIDs: []string{"blob:abcd", "mailbox:42"},
	}
	return &memoryStore{objects: objects}, manifest, bytes.Repeat([]byte{0x42}, 32), now
}

func TestRecoverySetCommitLoadAndProofHappyPath(t *testing.T) {
	store, manifest, key, now := testFixture()
	coordinator := Coordinator{Store: store, Key: key}
	envelope, err := coordinator.Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if store.writes[len(store.writes)-1] != ManifestObjectKey(manifest.RecoverySetID) {
		t.Fatalf("manifest was not the commit point: %v", store.writes)
	}
	loaded, verdict, err := coordinator.LoadVerifiedEnvelope(context.Background(), manifest.RecoverySetID, VerifyPolicy{
		Now: now, ExpectedInstallationID: manifest.InstallationID, ExpectedTimelineID: manifest.TimelineID,
	})
	if err != nil || loaded.HMACSHA256 != envelope.HMACSHA256 || verdict.ManifestSHA256 != envelope.ManifestSHA256 || !verdict.Fresh {
		t.Fatalf("loaded=%+v verdict=%+v err=%v", loaded, verdict, err)
	}
	if second, err := coordinator.LoadVerified(context.Background(), manifest.RecoverySetID, VerifyPolicy{Now: now}); err != nil || second.RecoverySetID != manifest.RecoverySetID {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	proof := RestoreProof{Version: ManifestVersion, RecoverySetID: manifest.RecoverySetID, TargetID: "isolated-target-1", SourceInstallation: manifest.InstallationID, Isolated: true, SchemaChecked: true, LoginChecked: true, MailChecked: true, BlobChecked: true, ProvedAt: now}
	if warning, err := ValidateRestoreProof(proof, manifest, now); err != nil || warning != "" {
		t.Fatalf("warning=%q err=%v", warning, err)
	}
	if warning, err := ValidateRestoreProof(proof, manifest, now.Add(RestoreProofWarningAge+time.Hour)); err != nil || warning == "" {
		t.Fatalf("old proof warning=%q err=%v", warning, err)
	}
}

func TestSealRejectsEveryManifestAuthorityBoundary(t *testing.T) {
	_, base, key, _ := testFixture()
	mutations := map[string]func(*Manifest){
		"version":                  func(m *Manifest) { m.Version++ },
		"set id":                   func(m *Manifest) { m.RecoverySetID = "bad" },
		"installation":             func(m *Manifest) { m.InstallationID = "bad" },
		"timeline":                 func(m *Manifest) { m.TimelineID = "bad" },
		"release":                  func(m *Manifest) { m.SourceReleaseID = "../release" },
		"schema":                   func(m *Manifest) { m.SchemaVersion = 0 },
		"created":                  func(m *Manifest) { m.CreatedAt = time.Time{} },
		"expiry":                   func(m *Manifest) { m.ExpiresAt = m.CreatedAt },
		"freshness":                func(m *Manifest) { m.ExpiresAt = m.CreatedAt.Add(DefaultFreshness + time.Second) },
		"negative counts":          func(m *Manifest) { m.Counts.Blobs = -1 },
		"toggle digest":            func(m *Manifest) { m.FeatureToggleSHA256 = "bad" },
		"too many ids":             func(m *Manifest) { m.RepresentativeIDs = make([]string, 65) },
		"key mode":                 func(m *Manifest) { m.ProtectedKeyEvidence.Mode = "plain" },
		"key id":                   func(m *Manifest) { m.ProtectedKeyEvidence.KeyID = "../key" },
		"key fingerprint":          func(m *Manifest) { m.ProtectedKeyEvidence.Fingerprint = "bad" },
		"artifact size":            func(m *Manifest) { m.Database.Size = -1 },
		"artifact digest":          func(m *Manifest) { m.Database.SHA256 = "bad" },
		"artifact empty":           func(m *Manifest) { m.Database.ObjectKey = "" },
		"artifact long":            func(m *Manifest) { m.Database.ObjectKey = strings.Repeat("a", 513) },
		"artifact slash":           func(m *Manifest) { m.Database.ObjectKey = `bad\key` },
		"artifact absolute":        func(m *Manifest) { m.Database.ObjectKey = "/bad" },
		"artifact clean":           func(m *Manifest) { m.Database.ObjectKey = "a/../bad" },
		"artifact dot":             func(m *Manifest) { m.Database.ObjectKey = "." },
		"artifact parent":          func(m *Manifest) { m.Database.ObjectKey = "../bad" },
		"artifact duplicate":       func(m *Manifest) { m.Configuration = m.Database },
		"representative bad":       func(m *Manifest) { m.RepresentativeIDs = []string{"../bad"} },
		"representative duplicate": func(m *Manifest) { m.RepresentativeIDs = []string{"user:1", "user:1"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			candidate.RepresentativeIDs = append([]string(nil), base.RepresentativeIDs...)
			mutate(&candidate)
			if _, err := Seal(candidate, key); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	if _, err := Seal(base, []byte("short")); err == nil {
		t.Fatal("short HMAC key accepted")
	}
}

func TestVerifyRejectsTamperFreshnessIdentityAndEnvelopeBoundaries(t *testing.T) {
	_, manifest, key, now := testFixture()
	envelope, err := Seal(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	invalidManifestEnvelope := envelope
	invalidManifestEnvelope.Manifest.RecoverySetID = "bad"
	if _, err := Verify(invalidManifestEnvelope, key, VerifyPolicy{Now: now}); err == nil {
		t.Fatal("invalid manifest inside envelope accepted")
	}
	tests := map[string]struct {
		envelope Envelope
		key      []byte
		policy   VerifyPolicy
	}{
		"short key":        {envelope, []byte("short"), VerifyPolicy{Now: now}},
		"digest syntax":    {func() Envelope { c := envelope; c.ManifestSHA256 = "bad"; return c }(), key, VerifyPolicy{Now: now}},
		"hmac syntax":      {func() Envelope { c := envelope; c.HMACSHA256 = "bad"; return c }(), key, VerifyPolicy{Now: now}},
		"digest mismatch":  {func() Envelope { c := envelope; c.ManifestSHA256 = strings.Repeat("0", 64); return c }(), key, VerifyPolicy{Now: now}},
		"hmac mismatch":    {func() Envelope { c := envelope; c.HMACSHA256 = strings.Repeat("0", 64); return c }(), key, VerifyPolicy{Now: now}},
		"negative max age": {envelope, key, VerifyPolicy{Now: now, MaxAge: -time.Second}},
		"future":           {envelope, key, VerifyPolicy{Now: manifest.CreatedAt.Add(-2 * time.Minute)}},
		"too old":          {envelope, key, VerifyPolicy{Now: manifest.CreatedAt.Add(DefaultFreshness + time.Second)}},
		"expired":          {envelope, key, VerifyPolicy{Now: manifest.ExpiresAt}},
		"installation":     {envelope, key, VerifyPolicy{Now: now, ExpectedInstallationID: "other"}},
		"timeline":         {envelope, key, VerifyPolicy{Now: now, ExpectedTimelineID: "other"}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(tt.envelope, tt.key, tt.policy); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	live := manifest
	live.CreatedAt = time.Now().UTC().Add(-time.Hour)
	live.ExpiresAt = live.CreatedAt.Add(DefaultFreshness)
	liveEnvelope, err := Seal(live, key)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := Verify(liveEnvelope, key, VerifyPolicy{}); err != nil || !verdict.Fresh {
		t.Fatalf("zero-time default policy failed: %+v %v", verdict, err)
	}
}

func TestCoordinatorRejectsStorageAndComponentFailures(t *testing.T) {
	store, manifest, key, now := testFixture()
	if _, err := (Coordinator{Key: key}).Commit(context.Background(), manifest); err == nil {
		t.Fatal("nil store accepted")
	}
	for name, mutate := range map[string]func(*memoryStore, *Manifest){
		"head":   func(s *memoryStore, _ *Manifest) { s.headErr = errors.New("head") },
		"size":   func(s *memoryStore, _ *Manifest) { s.sizeDelta = 1 },
		"get":    func(s *memoryStore, _ *Manifest) { s.getErr = errors.New("get") },
		"read":   func(s *memoryStore, _ *Manifest) { s.readErr = errors.New("read") },
		"close":  func(s *memoryStore, _ *Manifest) { s.closeErr = errors.New("close") },
		"digest": func(s *memoryStore, m *Manifest) { s.objects[m.Database.ObjectKey][0] ^= 0xff },
		"inventory malformed": func(s *memoryStore, m *Manifest) {
			s.objects[m.Blobs.ObjectKey] = []byte("{")
			m.Blobs = testArtifact(m.Blobs.ObjectKey, s.objects[m.Blobs.ObjectKey])
		},
		"inventory trailing": func(s *memoryStore, m *Manifest) {
			s.objects[m.Blobs.ObjectKey] = append(s.objects[m.Blobs.ObjectKey], []byte("{}")...)
			m.Blobs = testArtifact(m.Blobs.ObjectKey, s.objects[m.Blobs.ObjectKey])
		},
		"inventory type": func(s *memoryStore, m *Manifest) {
			s.objects[m.Blobs.ObjectKey] = []byte(`{"type":"delta","hashes":[],"count":0,"total_size":0}`)
			m.Blobs = testArtifact(m.Blobs.ObjectKey, s.objects[m.Blobs.ObjectKey])
			m.Counts.Blobs, m.Counts.BlobBytes = 0, 0
		},
		"inventory counts": func(_ *memoryStore, m *Manifest) { m.Counts.Blobs++ },
		"put":              func(s *memoryStore, _ *Manifest) { s.putErr = errors.New("put") },
	} {
		t.Run(name, func(t *testing.T) {
			s, m, k, _ := testFixture()
			mutate(s, &m)
			if _, err := (Coordinator{Store: s, Key: k}).Commit(context.Background(), m); err == nil {
				t.Fatal("failed component accepted")
			}
		})
	}
	envelope, err := Seal(manifest, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"manifest":`) // deliberately malformed
	store.objects[ManifestObjectKey(manifest.RecoverySetID)] = raw
	if _, _, err := (Coordinator{Store: store, Key: key}).LoadVerifiedEnvelope(context.Background(), manifest.RecoverySetID, VerifyPolicy{Now: now}); err == nil {
		t.Fatal("malformed commit point accepted")
	}
	store.objects[ManifestObjectKey(manifest.RecoverySetID)], _ = jsonMarshal(envelope)
	if _, _, err := (Coordinator{Store: store, Key: key}).LoadVerifiedEnvelope(context.Background(), "bad", VerifyPolicy{Now: now}); err == nil {
		t.Fatal("invalid recovery ID accepted")
	}
}

func TestLoadVerifiedEnvelopeRejectsCommitPointAndPostCommitDrift(t *testing.T) {
	baseStore, manifest, key, now := testFixture()
	coordinator := Coordinator{Store: baseStore, Key: key}
	envelope, err := coordinator.Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	validRaw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	manifestKey := ManifestObjectKey(manifest.RecoverySetID)
	tests := map[string]func(*memoryStore){
		"missing":  func(s *memoryStore) { delete(s.objects, manifestKey) },
		"oversize": func(s *memoryStore) { s.objects[manifestKey] = bytes.Repeat([]byte("x"), maxManifestBytes+1) },
		"read":     func(s *memoryStore) { s.readErr, s.readErrKey = errors.New("read"), manifestKey },
		"close":    func(s *memoryStore) { s.closeErr, s.closeErrKey = errors.New("close"), manifestKey },
		"unknown JSON": func(s *memoryStore) {
			s.objects[manifestKey] = append(validRaw[:len(validRaw)-1], []byte(`,"unknown":true}`)...)
		},
		"trailing JSON": func(s *memoryStore) {
			s.objects[manifestKey] = append(append([]byte(nil), validRaw...), []byte(`{}`)...)
		},
		"invalid envelope": func(s *memoryStore) {
			candidate := envelope
			candidate.HMACSHA256 = strings.Repeat("0", 64)
			s.objects[manifestKey], _ = json.Marshal(candidate)
		},
		"artifact drift": func(s *memoryStore) { s.objects[manifest.Database.ObjectKey][0] ^= 0xff },
		"blob drift": func(s *memoryStore) {
			for objectKey := range s.objects {
				if strings.HasPrefix(objectKey, "blobs/") {
					s.objects[objectKey][0] ^= 0xff
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s, _, _, _ := testFixture()
			s.objects[manifestKey] = append([]byte(nil), validRaw...)
			mutate(s)
			if _, _, err := (Coordinator{Store: s, Key: key}).LoadVerifiedEnvelope(context.Background(), manifest.RecoverySetID, VerifyPolicy{Now: now}); err == nil {
				t.Fatal("invalid committed recovery set accepted")
			}
		})
	}
}

func TestBlobInventoryRejectsEveryReferencedObjectBoundary(t *testing.T) {
	store, _, _, _ := testFixture()
	blobKey := ""
	for key := range store.objects {
		if strings.HasPrefix(key, "blobs/") {
			blobKey = key
		}
	}
	setInventory := func(store *memoryStore, manifest *Manifest, raw []byte, counts Counts) {
		store.objects[manifest.Blobs.ObjectKey] = raw
		manifest.Blobs = testArtifact(manifest.Blobs.ObjectKey, raw)
		manifest.Counts = counts
	}
	tests := map[string]func(*memoryStore, *Manifest){
		"too large":       func(_ *memoryStore, m *Manifest) { m.Blobs.Size = maxBlobInventoryBytes + 1 },
		"inventory get":   func(s *memoryStore, m *Manifest) { s.getErr, s.getErrKey = errors.New("get"), m.Blobs.ObjectKey },
		"inventory read":  func(s *memoryStore, m *Manifest) { s.readErr, s.readErrKey = errors.New("read"), m.Blobs.ObjectKey },
		"inventory close": func(s *memoryStore, m *Manifest) { s.closeErr, s.closeErrKey = errors.New("close"), m.Blobs.ObjectKey },
		"invalid digest": func(s *memoryStore, m *Manifest) {
			setInventory(s, m, []byte(`{"type":"full","hashes":["bad"],"count":1,"total_size":4}`), Counts{Blobs: 1, BlobBytes: 4})
		},
		"duplicate": func(s *memoryStore, m *Manifest) {
			digest := strings.TrimPrefix(blobKey, "blobs/")
			setInventory(s, m, []byte(fmt.Sprintf(`{"type":"full","hashes":[%q,%q],"count":2,"total_size":8}`, digest, digest)), Counts{Blobs: 2, BlobBytes: 8})
		},
		"blob head":   func(s *memoryStore, _ *Manifest) { s.headErr, s.headErrKey = errors.New("head"), blobKey },
		"blob get":    func(s *memoryStore, _ *Manifest) { s.getErr, s.getErrKey = errors.New("get"), blobKey },
		"blob close":  func(s *memoryStore, _ *Manifest) { s.closeErr, s.closeErrKey = errors.New("close"), blobKey },
		"blob digest": func(s *memoryStore, _ *Manifest) { s.objects[blobKey][0] ^= 0xff },
		"total bytes": func(s *memoryStore, m *Manifest) {
			digest := strings.TrimPrefix(blobKey, "blobs/")
			setInventory(s, m, []byte(fmt.Sprintf(`{"type":"full","hashes":[%q],"count":1,"total_size":5}`, digest)), Counts{Blobs: 1, BlobBytes: 5})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s, m, _, _ := testFixture()
			mutate(s, &m)
			if err := verifyBlobInventory(context.Background(), s, m.Blobs, m.Counts); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

func jsonMarshal(value any) ([]byte, error) {
	// Kept as a test helper so the valid envelope fixture remains visually
	// separate from the deliberately malformed bytes above.
	return json.Marshal(value)
}

func TestRestoreProofRejectsIncompleteOrInPlaceEvidence(t *testing.T) {
	_, manifest, _, now := testFixture()
	base := RestoreProof{Version: ManifestVersion, RecoverySetID: manifest.RecoverySetID, TargetID: "target", SourceInstallation: manifest.InstallationID, Isolated: true, SchemaChecked: true, LoginChecked: true, MailChecked: true, BlobChecked: true, ProvedAt: now}
	mutations := []func(*RestoreProof){
		func(p *RestoreProof) { p.Version++ }, func(p *RestoreProof) { p.RecoverySetID = "other" },
		func(p *RestoreProof) { p.SourceInstallation = "other" }, func(p *RestoreProof) { p.TargetID = "" },
		func(p *RestoreProof) { p.TargetID = manifest.InstallationID }, func(p *RestoreProof) { p.Isolated = false },
		func(p *RestoreProof) { p.SchemaChecked = false }, func(p *RestoreProof) { p.LoginChecked = false },
		func(p *RestoreProof) { p.MailChecked = false }, func(p *RestoreProof) { p.BlobChecked = false },
		func(p *RestoreProof) { p.ProvedAt = time.Time{} }, func(p *RestoreProof) { p.ProvedAt = manifest.CreatedAt.Add(-time.Second) },
		func(p *RestoreProof) { p.ProvedAt = now.Add(2 * time.Minute) },
	}
	for _, mutate := range mutations {
		candidate := base
		mutate(&candidate)
		if _, err := ValidateRestoreProof(candidate, manifest, now); err == nil {
			t.Fatal("invalid restore proof accepted")
		}
	}
}

// TestLoadVerifiedEnvelopeRejectsLocatorManifestMismatch pins the
// locator/manifest binding (D-SHARED-RECOVERYSET-V-001): a legitimately
// sealed manifest for set A stored under set B's locator must not verify —
// the object-storage locator is an unauthenticated input and is now bound to
// the authenticated manifest.
func TestLoadVerifiedEnvelopeRejectsLocatorManifestMismatch(t *testing.T) {
	store, manifest, key, now := testFixture()
	coordinator := Coordinator{Store: store, Key: key}
	envelope, err := coordinator.Commit(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	otherID := "44444444-4444-4444-8444-444444444444"
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutObject(context.Background(), ManifestObjectKey(otherID), bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := coordinator.LoadVerifiedEnvelope(context.Background(), otherID, VerifyPolicy{Now: now}); err == nil {
		t.Fatal("a sealed manifest for set A must not verify under set B's locator")
	}
	// The correct locator keeps verifying.
	if _, _, err := coordinator.LoadVerifiedEnvelope(context.Background(), manifest.RecoverySetID, VerifyPolicy{Now: now}); err != nil {
		t.Fatalf("correct locator must still verify: %v", err)
	}
}

// TestSignedRestoreProof pins the signed/single-use-ready proof semantics
// (D-SHARED-RECOVERYSET-V-002): the HMAC binds every proof field (including
// ProvedAt), so a sealed proof cannot be altered, re-targeted, or re-dated
// without detection, and the freshness/warning contract still applies.
func TestSignedRestoreProof(t *testing.T) {
	_, manifest, key, now := testFixture()
	proof := RestoreProof{
		Version: ManifestVersion, RecoverySetID: manifest.RecoverySetID,
		TargetID: "isolated-target-1", SourceInstallation: manifest.InstallationID,
		Isolated: true, SchemaChecked: true, LoginChecked: true, MailChecked: true, BlobChecked: true,
		ProvedAt: now,
	}
	raw, err := SealRestoreProof(proof, key)
	if err != nil {
		t.Fatal(err)
	}

	got, warning, err := VerifySignedRestoreProof(raw, key, manifest, now)
	if err != nil || warning != "" || got.TargetID != proof.TargetID {
		t.Fatalf("roundtrip: got=%+v warning=%q err=%v", got, warning, err)
	}

	// Same-length tamper keeps the JSON valid but must break the MAC.
	tampered := bytes.Replace(raw, []byte("isolated-target-1"), []byte("isolated-target-9"), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper replacement did not apply")
	}
	if _, _, err := VerifySignedRestoreProof(tampered, key, manifest, now); err == nil {
		t.Fatal("tampered proof must be rejected")
	}

	// Wrong key must be rejected.
	if _, _, err := VerifySignedRestoreProof(raw, []byte("wrong-key-wrong-key-wrong-key-32"), manifest, now); err == nil {
		t.Fatal("proof sealed under a different key must be rejected")
	}

	// Malformed envelope must be rejected, not treated as advisory.
	if _, _, err := VerifySignedRestoreProof([]byte(`{"proof":{`), key, manifest, now); err == nil {
		t.Fatal("malformed signed proof must be rejected")
	}

	// The freshness contract flows through: verified against a later clock the
	// proof still authenticates but returns the loud 90-day warning.
	if _, warning, err := VerifySignedRestoreProof(raw, key, manifest, now.Add(RestoreProofWarningAge+time.Hour)); err != nil || warning == "" {
		t.Fatalf("aged sealed proof warning=%q err=%v", warning, err)
	}

	// Re-dating a sealed proof is detected: re-sealing the altered proof under
	// the same key is required to forge a fresh ProvedAt.
	redated := proof
	redated.ProvedAt = now.Add(-RestoreProofWarningAge - time.Hour)
	if bytes.Equal(redatedProofBytes(t, redated, key), raw) {
		t.Fatal("re-dated proof must produce a different sealed envelope")
	}
}

func redatedProofBytes(t *testing.T, proof RestoreProof, key []byte) []byte {
	t.Helper()
	raw, err := SealRestoreProof(proof, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
