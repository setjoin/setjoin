package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

const (
	testConfigDeploymentID = "70d9ba1e-7f63-48c4-995f-77477a040847"
	testConfigMasterKey    = "0123456789abcdef0123456789abcdef"
)

func testConfigSecretCodec(t *testing.T) *ConfigSecretCodec {
	t.Helper()
	codec, err := NewConfigSecretCodec(ConfigSecretKeyring{
		DeploymentID:  testConfigDeploymentID,
		ActiveVersion: 1,
		ActiveKey:     []byte(testConfigMasterKey),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatalf("NewConfigSecretCodec: %v", err)
	}
	return codec
}

func TestConfigSecretCodecEncryptsWithBoundAAD(t *testing.T) {
	codec := testConfigSecretCodec(t)
	plaintext := json.RawMessage(`"directory-password"`)

	stored, err := codec.Encrypt("ldap_sync_password_enc", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(stored, []byte("directory-password")) {
		t.Fatalf("stored value contains plaintext: %s", stored)
	}

	got, err := codec.Decrypt("ldap_sync_password_enc", stored)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %s, want %s", got, plaintext)
	}

	if _, err := codec.Decrypt("ad_sync_password_enc", stored); err == nil {
		t.Fatal("ciphertext moved to another source/key decrypted despite AAD binding")
	}
}

func TestConfigSecretCodecReadsRetiringKeyVersion(t *testing.T) {
	oldCodec := testConfigSecretCodec(t)
	stored, err := oldCodec.Encrypt("ldap_sync_password_enc", json.RawMessage(`"old-secret"`))
	if err != nil {
		t.Fatalf("old Encrypt: %v", err)
	}

	rotated, err := NewConfigSecretCodec(ConfigSecretKeyring{
		DeploymentID:  testConfigDeploymentID,
		ActiveVersion: 2,
		ActiveKey:     []byte("fedcba9876543210fedcba9876543210"),
		ActiveProfile: cryptokey.ProfileSMx,
		RetiringKeys: map[uint32][]byte{
			1: []byte(testConfigMasterKey),
		},
	})
	if err != nil {
		t.Fatalf("rotated codec: %v", err)
	}
	got, err := rotated.Decrypt("ldap_sync_password_enc", stored)
	if err != nil {
		t.Fatalf("decrypt retiring version: %v", err)
	}
	if string(got) != `"old-secret"` {
		t.Fatalf("decrypt retiring version = %s", got)
	}

	newStored, err := rotated.Encrypt("ldap_sync_password_enc", json.RawMessage(`"new-secret"`))
	if err != nil {
		t.Fatalf("new Encrypt: %v", err)
	}
	var record configSecretRecord
	if err := json.Unmarshal(newStored, &record); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	if record.KeyVersion != 2 {
		t.Fatalf("new write key version = %d, want 2", record.KeyVersion)
	}
}

func TestParseConfigSecretRetiringKeys(t *testing.T) {
	got, err := ParseConfigSecretRetiringKeys(`{"1":"0123456789abcdef","7":"fedcba9876543210"}`)
	if err != nil {
		t.Fatalf("ParseConfigSecretRetiringKeys: %v", err)
	}
	if string(got[1]) != "0123456789abcdef" || string(got[7]) != "fedcba9876543210" {
		t.Fatalf("parsed keyring = %#v", got)
	}
	for _, raw := range []string{`[]`, `{"0":"key"}`, `{"bad":"key"}`} {
		if _, err := ParseConfigSecretRetiringKeys(raw); err == nil {
			t.Fatalf("ParseConfigSecretRetiringKeys(%s) succeeded", raw)
		}
	}
}

func TestConfigSecretCodecRejectsEveryMalformedKeyringAndEnvelopeClass(t *testing.T) {
	if (*ConfigSecretCodec)(nil).ActiveVersion() != 0 {
		t.Fatal("nil codec exposed an active version")
	}
	for name, keyring := range map[string]ConfigSecretKeyring{
		"missing deployment": {
			ActiveVersion: 1, ActiveKey: []byte(testConfigMasterKey),
		},
		"oversized deployment": {
			DeploymentID:  strings.Repeat("d", 256),
			ActiveVersion: 1, ActiveKey: []byte(testConfigMasterKey),
		},
		"zero active version": {
			DeploymentID: testConfigDeploymentID,
			ActiveKey:    []byte(testConfigMasterKey),
		},
		"short standard key": {
			DeploymentID: testConfigDeploymentID, ActiveVersion: 1,
			ActiveKey: []byte("short"),
		},
		"short smx key": {
			DeploymentID: testConfigDeploymentID, ActiveVersion: 1,
			ActiveKey: []byte("short"), ActiveProfile: cryptokey.ProfileSMx,
		},
		"zero retiring version": {
			DeploymentID: testConfigDeploymentID, ActiveVersion: 1,
			ActiveKey:    []byte(testConfigMasterKey),
			RetiringKeys: map[uint32][]byte{0: []byte(testConfigMasterKey)},
		},
		"active version retires": {
			DeploymentID: testConfigDeploymentID, ActiveVersion: 1,
			ActiveKey:    []byte(testConfigMasterKey),
			RetiringKeys: map[uint32][]byte{1: []byte(testConfigMasterKey)},
		},
		"short retiring key": {
			DeploymentID: testConfigDeploymentID, ActiveVersion: 1,
			ActiveKey:    []byte(testConfigMasterKey),
			RetiringKeys: map[uint32][]byte{2: []byte("short")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewConfigSecretCodec(keyring); err == nil {
				t.Fatal("malformed keyring accepted")
			}
		})
	}

	var nilCodec *ConfigSecretCodec
	if _, err := nilCodec.Encrypt("tls_private_key_enc", json.RawMessage(`"x"`)); err == nil {
		t.Fatal("nil codec encrypted a secret")
	}
	if _, err := nilCodec.Decrypt("tls_private_key_enc", json.RawMessage(`{}`)); err == nil {
		t.Fatal("nil codec decrypted a secret")
	}

	codec := testConfigSecretCodec(t)
	stored, err := codec.Encrypt("identity_source.corp", json.RawMessage(`"secret"`))
	if err != nil {
		t.Fatal(err)
	}
	var base configSecretRecord
	if err := json.Unmarshal(stored, &base); err != nil {
		t.Fatal(err)
	}
	mutate := func(change func(*configSecretRecord)) json.RawMessage {
		t.Helper()
		value := base
		change(&value)
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string]json.RawMessage{
		"not json": json.RawMessage(`{`),
		"format": mutate(func(r *configSecretRecord) {
			r.Format = "unknown"
		}),
		"version": mutate(func(r *configSecretRecord) {
			r.Version = 2
		}),
		"source": mutate(func(r *configSecretRecord) {
			r.SourceKey = "other"
		}),
		"key version": mutate(func(r *configSecretRecord) {
			r.KeyVersion = 99
		}),
		"encoding": mutate(func(r *configSecretRecord) {
			r.Ciphertext = "!"
		}),
		"ciphertext": mutate(func(r *configSecretRecord) {
			r.Ciphertext = "AA"
		}),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := codec.Decrypt("identity_source.corp", value); err == nil {
				t.Fatal("malformed envelope accepted")
			}
		})
	}

	for key, source := range map[string]string{
		"ad_sync_password_enc":      "legacy:ad",
		"ldap_sync_password_enc":    "legacy:ldap",
		"tls_private_key_enc":       "legacy:tls",
		"identity_source.corp-oidc": "corp-oidc",
		"unclassified":              "legacy:system",
	} {
		if got := configSecretSourceKey(key); got != source {
			t.Fatalf("source for %q = %q, want %q", key, got, source)
		}
	}
	if !isConfigSecretEnvelope(stored) ||
		isConfigSecretEnvelope(json.RawMessage(`{"format":"other","version":1}`)) ||
		!isRedactedConfigSentinel(json.RawMessage(`"[ENCRYPTED]"`)) ||
		isRedactedConfigSentinel(json.RawMessage(`null`)) {
		t.Fatal("config secret envelope/sentinel classification is inconsistent")
	}
}

func TestConfigStoreEncryptsSecretsAndPreservesRedactionSentinel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	const key = "ldap_sync_password_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})

	if err := store.SetKey(ctx, key, ConfigValue{
		Value:     json.RawMessage(`"first-secret"`),
		Encrypted: true,
	}, "test"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	var stored []byte
	var encrypted bool
	if err := pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = $1`, key,
	).Scan(&stored, &encrypted); err != nil {
		t.Fatalf("read stored row: %v", err)
	}
	if !encrypted {
		t.Fatal("encrypted marker was not persisted")
	}
	if bytes.Contains(stored, []byte("first-secret")) {
		t.Fatalf("database contains plaintext secret: %s", stored)
	}

	runtimeRows, err := store.GetDecryptedByPrefix(ctx, "ldap_sync_")
	if err != nil {
		t.Fatalf("GetDecryptedByPrefix: %v", err)
	}
	if len(runtimeRows) != 1 || string(runtimeRows[0].Value) != `"first-secret"` {
		t.Fatalf("runtime rows = %+v", runtimeRows)
	}

	if err := store.SetKey(ctx, key, ConfigValue{
		Value:     json.RawMessage(`"[ENCRYPTED]"`),
		Encrypted: true,
	}, "test"); err != nil {
		t.Fatalf("preserve sentinel: %v", err)
	}
	var preserved []byte
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&preserved); err != nil {
		t.Fatalf("read preserved row: %v", err)
	}
	if !bytes.Equal(preserved, stored) {
		t.Fatal("[ENCRYPTED] sentinel replaced the existing ciphertext")
	}

	if err := store.SetKey(ctx, key, ConfigValue{
		Value:     json.RawMessage(`"rotated-secret"`),
		Encrypted: true,
	}, "test"); err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	var rotated []byte
	if err := pool.QueryRow(ctx, `SELECT value FROM system_config WHERE key = $1`, key).Scan(&rotated); err != nil {
		t.Fatalf("read rotated row: %v", err)
	}
	if bytes.Equal(rotated, stored) || bytes.Contains(rotated, []byte("rotated-secret")) {
		t.Fatal("secret rotation did not write a fresh ciphertext")
	}
}

func TestConfigStoreSecretReadFailsClosedWithoutOrWithWrongKey(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "ldap_sync_password_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})

	writer := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	if err := writer.SetKey(ctx, key, ConfigValue{
		Value:     json.RawMessage(`"secret"`),
		Encrypted: true,
	}, "test"); err != nil {
		t.Fatalf("seed encrypted value: %v", err)
	}

	if _, err := NewConfigStore(pool, nil).GetDecryptedByPrefix(ctx, "ldap_sync_"); err == nil {
		t.Fatal("encrypted runtime read succeeded without a codec")
	}

	wrongCodec, err := NewConfigSecretCodec(ConfigSecretKeyring{
		DeploymentID:  testConfigDeploymentID,
		ActiveVersion: 1,
		ActiveKey:     []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatalf("wrong codec: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, wrongCodec).GetDecryptedByPrefix(ctx, "ldap_sync_"); err == nil {
		t.Fatal("encrypted runtime read succeeded with the wrong key")
	}
	if _, err := NewConfigStore(pool, nil, wrongCodec).EnsureSecretEncryption(ctx, "ldap_sync_"); err == nil {
		t.Fatal("startup validation succeeded with the wrong key")
	} else if !strings.Contains(err.Error(), "restore identity.deployment_id with the ciphertext") {
		t.Fatalf("startup validation lacks deployment/key recovery guidance: %v", err)
	}
}

func TestConfigStoreEnsureSecretEncryptionUpgradesLegacyPlaintext(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	const key = "ad_sync_password_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ($1, to_jsonb($2::text), false)
		 ON CONFLICT (key) DO UPDATE
		 SET value = EXCLUDED.value, encrypted = false`,
		key, "legacy-password",
	); err != nil {
		t.Fatalf("seed legacy secret: %v", err)
	}

	upgraded, err := store.EnsureSecretEncryption(ctx, "ad_sync_")
	if err != nil {
		t.Fatalf("EnsureSecretEncryption: %v", err)
	}
	if upgraded != 1 {
		t.Fatalf("upgraded = %d, want 1", upgraded)
	}

	var stored []byte
	var encrypted bool
	if err := pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = $1`, key,
	).Scan(&stored, &encrypted); err != nil {
		t.Fatalf("read upgraded secret: %v", err)
	}
	if !encrypted || bytes.Contains(stored, []byte("legacy-password")) {
		t.Fatalf("legacy secret was not encrypted: encrypted=%v value=%s", encrypted, stored)
	}

	rows, err := store.GetDecryptedByPrefix(ctx, "ad_sync_")
	if err != nil {
		t.Fatalf("runtime read: %v", err)
	}
	if len(rows) != 1 || string(rows[0].Value) != `"legacy-password"` {
		t.Fatalf("runtime rows = %+v", rows)
	}
}
