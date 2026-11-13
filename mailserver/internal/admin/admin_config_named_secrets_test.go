// ER5 occ_130c4ed3dfc8ef275164387e (assist-api-key-plaintext-admin-read):
// assist.api_key is a named secret config key. These tests pin the three
// halves of the closure: the classification (redaction on every read/export
// path), the ConfigStore write path encrypting it at rest, and the startup
// upgrade that moves legacy plaintext into envelopes.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iassist "setjoin.com/mailserver/internal/assist"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

func TestIsSecretConfigKeyClassifiesNamedBearerCredentials(t *testing.T) {
	if !isSecretConfigKey("assist.api_key") {
		t.Fatal("assist.api_key is not classified as secret material")
	}
	for _, plaintextKey := range []string{"assist.provider_url", "assist.model", "identity.deployment_id"} {
		if isSecretConfigKey(plaintextKey) {
			t.Fatalf("%s must not be classified as secret", plaintextKey)
		}
	}
	// The _enc suffix convention is unchanged.
	if !isSecretConfigKey("ldap_sync_password_enc") {
		t.Fatal("_enc suffix classification regressed")
	}
}

// TestConfigHandlerReadsRedactNamedSecretKey pins the admin-read half: a
// stored assist.api_key row — even legacy plaintext — is returned as the
// [ENCRYPTED] sentinel by the single-key and prefix read paths, never in the
// clear.
func TestConfigHandlerReadsRedactNamedSecretKey(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	h := NewConfigHandler(pool, testsupport.TestLogger())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'assist.api_key'`)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', to_jsonb('sk-super-secret'::text), false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = false`,
	); err != nil {
		t.Fatalf("seed assist.api_key: %v", err)
	}

	// Single-key read.
	req := httptest.NewRequest(http.MethodGet, "/admin/system/config/assist.api_key", nil)
	req.SetPathValue("key", "assist.api_key")
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Get returned %d", rec.Code)
	}
	var body struct {
		Value     any  `json:"value"`
		Encrypted bool `json:"encrypted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode Get body: %v", err)
	}
	if body.Value != redactedConfigValue {
		t.Fatalf("Get exposed named secret: value=%v", body.Value)
	}

	// Prefix list read.
	req = httptest.NewRequest(http.MethodGet, "/admin/system/config?prefix=assist.", nil)
	rec = httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List returned %d", rec.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode List body: %v", err)
	}
	for _, row := range rows {
		if row["key"] != "assist.api_key" {
			continue
		}
		if row["value"] != redactedConfigValue {
			t.Fatalf("List exposed named secret: row=%v", row)
		}
		return
	}
	t.Fatal("assist.api_key row missing from prefix list")
}

// TestConfigStoreNamedSecretRoundTrip pins the write half: a BatchSet of the
// named key persists an authenticated envelope with the encrypted flag, and
// the runtime read decrypts it back.
func TestConfigStoreNamedSecretRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'assist.api_key'`)
	})
	if err := store.BatchSet(ctx, "assist key write", map[string]ConfigValue{
		"assist.api_key": {Value: json.RawMessage(`"sk-roundtrip"`), Encrypted: false},
	}); err != nil {
		t.Fatalf("BatchSet named secret: %v", err)
	}

	var stored []byte
	var encrypted bool
	if err := pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = 'assist.api_key'`,
	).Scan(&stored, &encrypted); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if !encrypted || !isConfigSecretEnvelope(stored) {
		t.Fatalf("named secret not stored as encrypted envelope: encrypted=%v value=%s", encrypted, stored)
	}
	if bytes.Contains(stored, []byte("sk-roundtrip")) {
		t.Fatal("named secret stored in plaintext")
	}

	rows, err := store.GetDecryptedByPrefix(ctx, "assist.")
	if err != nil {
		t.Fatalf("runtime read: %v", err)
	}
	if len(rows) != 1 || string(rows[0].Value) != `"sk-roundtrip"` {
		t.Fatalf("runtime rows = %+v", rows)
	}
}

// TestEnsureNamedSecretEncryptionUpgradesLegacyPlaintext pins the startup
// upgrade: an existing plaintext assist.api_key is rewritten to an envelope
// with the encrypted flag before the server accepts traffic, and the upgrade
// is idempotent.
func TestEnsureNamedSecretEncryptionUpgradesLegacyPlaintext(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'assist.api_key'`)
	})
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', to_jsonb('sk-legacy'::text), false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = false`,
	); err != nil {
		t.Fatalf("seed legacy plaintext: %v", err)
	}

	upgraded, err := store.EnsureNamedSecretEncryption(ctx)
	if err != nil {
		t.Fatalf("EnsureNamedSecretEncryption: %v", err)
	}
	if upgraded != 1 {
		t.Fatalf("upgraded = %d, want 1", upgraded)
	}

	var stored []byte
	var encrypted bool
	if err := pool.QueryRow(ctx,
		`SELECT value, encrypted FROM system_config WHERE key = 'assist.api_key'`,
	).Scan(&stored, &encrypted); err != nil {
		t.Fatalf("read upgraded secret: %v", err)
	}
	if !encrypted || !isConfigSecretEnvelope(stored) || bytes.Contains(stored, []byte("sk-legacy")) {
		t.Fatalf("legacy secret not upgraded: encrypted=%v value=%s", encrypted, stored)
	}

	// Idempotent: a second run upgrades nothing.
	if again, err := store.EnsureNamedSecretEncryption(ctx); err != nil || again != 0 {
		t.Fatalf("second upgrade = (%d, %v), want (0, nil)", again, err)
	}

	rows, err := store.GetDecryptedByPrefix(ctx, "assist.")
	if err != nil {
		t.Fatalf("runtime read after upgrade: %v", err)
	}
	if len(rows) != 1 || string(rows[0].Value) != `"sk-legacy"` {
		t.Fatalf("runtime rows = %+v", rows)
	}
}

// TestAssistReaderDecryptsNamedSecretRow drives the production assist config
// reader against a real envelope row: the codec-bound reader decrypts
// assist.api_key, while the codec-less variant fails closed rather than
// returning ciphertext (import direction forces this test into the admin
// package — admin already builds on assist transitively, never the reverse).
func TestAssistReaderDecryptsNamedSecretRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)

	envelope, err := codec.Encrypt("assist.api_key", json.RawMessage(`"sk-db-encrypted"`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', $1, true)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = true`,
		envelope); err != nil {
		t.Fatalf("seed envelope row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'assist.api_key'`)
	})

	withCodec := iassist.NewPoolConfigReaderWithSecrets(pool, codec)
	got, err := withCodec.Get(ctx, "assist.api_key")
	if err != nil {
		t.Fatalf("Get with codec: %v", err)
	}
	if got != "sk-db-encrypted" {
		t.Fatalf("Get = %q, want sk-db-encrypted", got)
	}

	withoutCodec := iassist.NewPoolConfigReader(pool)
	if got, err := withoutCodec.Get(ctx, "assist.api_key"); err == nil {
		t.Fatalf("codec-less Get returned %q instead of failing closed", got)
	}
}

// TestEnsureNamedSecretEncryptionFailurePaths pins the fail-closed arms of the
// startup upgrade: no codec, dead pool, codec encryption failure, failed
// envelope-marker update, failed ciphertext update, and failed commit.
func TestEnsureNamedSecretEncryptionFailurePaths(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	const prefix = "assist_named_failure_"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, "assist.api_key")
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+prefix+`reject_update ON system_config`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+prefix+`reject_update()`)
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+prefix+`reject_commit ON system_config`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+prefix+`reject_commit()`)
	})

	// No codec bound → refuse to operate.
	if _, err := NewConfigStore(pool, nil).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("named-secret upgrade succeeded without a codec")
	}

	// Dead pool → Begin fails.
	closed := testsupport.OpenTestPool(t)
	closed.Close()
	if _, err := NewConfigStore(closed, nil, codec).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("named-secret upgrade began a transaction on a closed pool")
	}

	// Codec encryption failure on a legacy plaintext row.
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', to_jsonb('sk-inject'::text), false)`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if _, err := (&ConfigStore{pool: pool, secrets: failingConfigSecretCodec{}}).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("named-secret upgrade ignored codec encryption failure")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'assist.api_key'`); err != nil {
		t.Fatalf("delete legacy row: %v", err)
	}

	// A BEFORE UPDATE trigger that rejects any named-key rewrite makes both
	// the envelope-marker repair and the legacy-ciphertext upgrade fail.
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION `+prefix+`reject_update() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected named-secret update failure';
		END
		$$;
		CREATE TRIGGER `+prefix+`reject_update
		BEFORE UPDATE ON system_config
		FOR EACH ROW EXECUTE FUNCTION `+prefix+`reject_update()
	`); err != nil {
		t.Fatalf("install update-failure trigger: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION `+prefix+`reject_commit() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'injected named-secret commit failure';
		END
		$$;
		CREATE CONSTRAINT TRIGGER `+prefix+`reject_commit
		AFTER UPDATE ON system_config
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION `+prefix+`reject_commit()
	`); err != nil {
		t.Fatalf("install commit-failure trigger: %v", err)
	}

	// Envelope row with a false encrypted flag → marker-repair UPDATE fails.
	envelope, err := codec.Encrypt("assist.api_key", json.RawMessage(`"sk-sealed"`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'assist.api_key'`); err != nil {
		t.Fatalf("clear assist.api_key: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', $1, false)`,
		envelope); err != nil {
		t.Fatalf("seed envelope row: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("envelope-marker update failure was ignored")
	}

	// Legacy plaintext row → ciphertext UPDATE fails.
	if _, err := pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'assist.api_key'`); err != nil {
		t.Fatalf("clear assist.api_key: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', to_jsonb('sk-legacy-fail'::text), false)`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("legacy ciphertext update failure was ignored")
	}

	// Drop the BEFORE trigger so the update succeeds and the DEFERRED
	// constraint trigger is what fails the COMMIT.
	if _, err := pool.Exec(ctx, `DROP TRIGGER IF EXISTS `+prefix+`reject_update ON system_config`); err != nil {
		t.Fatalf("drop update trigger: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("deferred commit failure was ignored")
	}
}
// TestEnsureNamedSecretEncryptionValidatesExistingEnvelope pins the startup
// gate: an existing envelope that the configured keyring cannot authenticate
// aborts the upgrade with recovery guidance instead of starting degraded.
func TestEnsureNamedSecretEncryptionValidatesExistingEnvelope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = 'assist.api_key'`)
	})
	sealed, err := codec.Encrypt("assist.api_key", json.RawMessage(`"sk-sealed"`))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted)
		 VALUES ('assist.api_key', $1, true)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = true`,
		sealed); err != nil {
		t.Fatalf("seed envelope: %v", err)
	}

	wrongKey := NewConfigStore(pool, nil, func() *ConfigSecretCodec {
		c, err := NewConfigSecretCodec(ConfigSecretKeyring{
			DeploymentID:  testConfigDeploymentID,
			ActiveVersion: 9, // different key version → unavailable for the envelope
			ActiveKey:     []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
			ActiveProfile: cryptokey.ProfileStandard,
		})
		if err != nil {
			t.Fatalf("wrong codec: %v", err)
		}
		return c
	}())
	if _, err := wrongKey.EnsureNamedSecretEncryption(ctx); err == nil {
		t.Fatal("startup gate accepted an envelope the keyring cannot authenticate")
	} else if !strings.Contains(err.Error(), "restore identity.deployment_id") {
		t.Fatalf("error lacks recovery guidance: %v", err)
	}
}
