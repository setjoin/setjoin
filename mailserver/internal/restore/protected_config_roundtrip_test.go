package restore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"

	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/backup"
	"setjoin.com/mailserver/internal/restore"
	"setjoin.com/mailserver/internal/storage"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

type configRoundTripStore struct{ objects map[string][]byte }

func (s *configRoundTripStore) HeadObject(_ context.Context, key string) (*storage.ObjectInfo, error) {
	b, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	return &storage.ObjectInfo{Key: key, Size: int64(len(b))}, nil
}
func (s *configRoundTripStore) GetObject(_ context.Context, key string) (io.ReadCloser, error) {
	b, ok := s.objects[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
func (s *configRoundTripStore) PutObject(_ context.Context, key string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err == nil {
		s.objects[key] = b
	}
	return err
}

// legacyManifestBytes builds the legacy (schema_version 0, unsigned — the shape
// backup.VerifyEmbeddedManifest admits) manifest binding configJSON, the
// integrity metadata every complete backup run writes for config.json
// (occ_902b7cb5: restore now requires it instead of silently skipping
// verification when the manifest lookup fails or the manifest is absent).
func legacyManifestBytes(t *testing.T, configJSON []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(configJSON)
	raw, err := json.Marshal(backup.BackupManifest{
		Timestamp:    "20260101T000000Z",
		ConfigSize:   int64(len(configJSON)),
		ConfigSHA256: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProtectedConfigCiphertextIsQuarantinedForRotation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "ldap_sync_recovery_roundtrip_enc"
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_config_quarantine WHERE config_key = $1`, key)
	})

	codec, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  "recovery-roundtrip-installation",
		ActiveVersion: 1,
		ActiveKey:     []byte("0123456789abcdef0123456789abcdef"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := json.RawMessage(`"protected-value"`)
	ciphertext, err := codec.Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]backup.ConfigEntry{
		key: {Value: string(ciphertext), Encrypted: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &configRoundTripStore{objects: map[string][]byte{
		"config.json":          raw,
		"backup-manifest.json": legacyManifestBytes(t, raw),
	}}
	engine := restore.NewEngine(pool, store, store, testsupport.TestLogger())
	if _, err := engine.RestoreConfig(ctx); err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, key).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("source-bound ciphertext was applied to system_config")
	}
	var quarantined json.RawMessage
	var encrypted bool
	var disposition string
	if err := pool.QueryRow(ctx,
		`SELECT config_value, encrypted, disposition FROM restore_config_quarantine WHERE config_key = $1 ORDER BY id DESC LIMIT 1`,
		key).Scan(&quarantined, &encrypted, &disposition); err != nil {
		t.Fatal(err)
	}
	var quarantinedEnvelope map[string]any
	var sourceEnvelope map[string]any
	if err := json.Unmarshal(quarantined, &quarantinedEnvelope); err != nil {
		t.Fatalf("decode quarantined envelope: %v", err)
	}
	if err := json.Unmarshal(ciphertext, &sourceEnvelope); err != nil {
		t.Fatalf("decode source envelope: %v", err)
	}
	if !encrypted || disposition != "rotate" || !reflect.DeepEqual(quarantinedEnvelope, sourceEnvelope) {
		t.Fatalf("quarantine did not preserve rotation material: encrypted=%v disposition=%q value=%s", encrypted, disposition, quarantined)
	}
}

func TestOperatorApprovedConfigRequiresIndependentTrustProof(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "auto_update.restore_trust_test"
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, key)
		_, _ = pool.Exec(ctx, `DELETE FROM restore_config_quarantine WHERE config_key = $1`, key)
	})

	raw, err := json.Marshal(map[string]backup.ConfigEntry{
		key: {Value: `"candidate-channel"`},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &configRoundTripStore{objects: map[string][]byte{
		"config.json":          raw,
		"backup-manifest.json": legacyManifestBytes(t, raw),
	}}
	engine := restore.NewEngine(pool, store, store, testsupport.TestLogger())
	n, err := engine.RestoreConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("restored %d operator-approved keys without an independent trust proof", n)
	}

	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = $1`, key).Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatal("operator-approved configuration crossed the embedded-only restore boundary")
	}
	var disposition string
	var sourceVerified bool
	if err := pool.QueryRow(ctx,
		`SELECT disposition, source_verified FROM restore_config_quarantine
		  WHERE config_key = $1 ORDER BY id DESC LIMIT 1`, key,
	).Scan(&disposition, &sourceVerified); err != nil {
		t.Fatal(err)
	}
	if disposition != "operator_approve" || sourceVerified {
		t.Fatalf("quarantine disposition=%q source_verified=%v, want operator_approve/false", disposition, sourceVerified)
	}
}
