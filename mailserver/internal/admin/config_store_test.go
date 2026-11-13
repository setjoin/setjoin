package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// ---- SideEffectRegistry unit (no DB) ----------------------------------------

// TestSideEffectRegistryFiresOnPrefixMatch proves a registered hook fires for a
// key under its prefix, receives the old + new ConfigValue, and that a hook
// registered under a different prefix does NOT fire.
func TestSideEffectRegistryFiresOnPrefixMatch(t *testing.T) {
	var reg SideEffectRegistry

	type call struct {
		key      string
		old, new ConfigValue
	}
	var mu sync.Mutex
	var ldapCalls, adCalls []call

	reg.Register("ldap_sync_", func(_ context.Context, key string, old, nw ConfigValue) {
		mu.Lock()
		ldapCalls = append(ldapCalls, call{key, old, nw})
		mu.Unlock()
	})
	reg.Register("ad_sync_", func(_ context.Context, key string, old, nw ConfigValue) {
		mu.Lock()
		adCalls = append(adCalls, call{key, old, nw})
		mu.Unlock()
	})

	oldV := ConfigValue{Value: json.RawMessage(`"old"`), Encrypted: false}
	newV := ConfigValue{Value: json.RawMessage(`"new"`), Encrypted: true}
	reg.fire(context.Background(), "ldap_sync_host", oldV, newV)

	if len(ldapCalls) != 1 {
		t.Fatalf("expected 1 ldap hook call, got %d", len(ldapCalls))
	}
	if len(adCalls) != 0 {
		t.Fatalf("expected 0 ad hook calls, got %d", len(adCalls))
	}
	c := ldapCalls[0]
	if c.key != "ldap_sync_host" {
		t.Errorf("hook key = %q, want ldap_sync_host", c.key)
	}
	if string(c.old.Value) != `"old"` || c.old.Encrypted {
		t.Errorf("hook old = %+v, want {\"old\", false}", c.old)
	}
	if string(c.new.Value) != `"new"` || !c.new.Encrypted {
		t.Errorf("hook new = %+v, want {\"new\", true}", c.new)
	}
}

// TestTLSStatusAndSetConfigUsePersistedKeys pins the admin TLS page to the
// underscore-form system_config keys seeded by the schema. It also proves JSONB
// string values are decoded as plain text rather than returned with JSON quotes.
func TestTLSStatusAndSetConfigUsePersistedKeys(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	keys := []string{
		"tls_autocert_challenge", "tls_autocert_domains", "tls_autocert_email",
		"tls_dns_provider", "tls_autocert_cache_dir",
	}
	values := []string{"dns-01", "mail.example.test, imap.example.test", "ops@example.test", "cloudflare", "/var/lib/acme"}
	for i, key := range keys {
		if _, err := pool.Exec(ctx,
			`INSERT INTO system_config (key, value, encrypted) VALUES ($1, to_jsonb($2::text), false)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = false`, key, values[i]); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	t.Cleanup(func() {
		for i, key := range keys {
			_, _ = pool.Exec(context.Background(),
				`UPDATE system_config SET value = to_jsonb($2::text) WHERE key = $1`, key, values[i])
		}
	})

	h := NewTLSHandler(pool, nil, "")
	w := httptest.NewRecorder()
	h.GetStatus(w, httptest.NewRequest(http.MethodGet, "/admin/tls/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GetStatus: expected 200, got %d — %s", w.Code, w.Body.String())
	}
	var got tlsStatus
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Challenge != "dns-01" || got.Email != "ops@example.test" || got.DNSProvider != "cloudflare" {
		t.Fatalf("status returned wrong persisted values: %+v", got)
	}
	if len(got.Domains) != 2 || got.Domains[0] != "mail.example.test" || got.Domains[1] != "imap.example.test" {
		t.Fatalf("status domains = %#v", got.Domains)
	}

	body := `{"tls_autocert_email":"new@example.test","unrelated_key":"must-not-write"}`
	w = httptest.NewRecorder()
	h.SetConfig(w, httptest.NewRequest(http.MethodPut, "/admin/tls/config", strings.NewReader(body)))
	if w.Code != http.StatusNoContent {
		t.Fatalf("SetConfig: expected 204, got %d — %s", w.Code, w.Body.String())
	}
	if got := h.getConfig(ctx, "tls_autocert_email"); got != "new@example.test" {
		t.Fatalf("saved email = %q", got)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE system_config SET value = to_jsonb(''::text) WHERE key = 'tls_autocert_challenge'`); err != nil {
		t.Fatalf("disable autocert: %v", err)
	}
	w = httptest.NewRecorder()
	h.GetStatus(w, httptest.NewRequest(http.MethodGet, "/admin/tls/status", nil))
	got = tlsStatus{}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode disabled status: %v", err)
	}
	if got.Enabled || got.Challenge != "none" || len(got.Domains) != 2 || got.Email != "new@example.test" {
		t.Fatalf("disabled status hid persisted form values: %+v", got)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM system_config WHERE key = 'unrelated_key'`).Scan(&count); err != nil {
		t.Fatalf("count unrelated key: %v", err)
	}
	if count != 0 {
		t.Fatal("SetConfig wrote an out-of-scope key")
	}
}

// TestSideEffectRegistryMultipleHooksSamePrefix proves every hook whose prefix
// matches fires (not just the first).
func TestSideEffectRegistryMultipleHooksSamePrefix(t *testing.T) {
	var reg SideEffectRegistry
	var fired int
	reg.Register("ldap_sync_", func(context.Context, string, ConfigValue, ConfigValue) { fired++ })
	reg.Register("ldap_", func(context.Context, string, ConfigValue, ConfigValue) { fired++ })
	reg.fire(context.Background(), "ldap_sync_host", ConfigValue{}, ConfigValue{})
	if fired != 2 {
		t.Fatalf("expected both matching hooks to fire, got %d", fired)
	}
}

// ---- ConfigStore DB-backed round trip ---------------------------------------

// TestConfigStoreRoundTrip exercises SetKey/GetKey/GetByPrefix/BatchSet and the
// authoritative `encrypted` column: a secret value persists encrypted=true so
// the column (not just the _enc suffix) carries the secret marker through to the
// config-backup export contract.
func TestConfigStoreRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))

	const (
		plainKey  = "cfgstore_test_plain"
		secretKey = "cfgstore_test_secret_enc"
		prefix    = "cfgstore_test_"
	)
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	})

	// SetKey plain (encrypted=false) then secret (encrypted=true).
	if err := store.SetKey(ctx, plainKey, ConfigValue{Value: json.RawMessage(`"visible"`)}, "test"); err != nil {
		t.Fatalf("SetKey(plain): %v", err)
	}
	if err := store.SetKey(ctx, secretKey, ConfigValue{Value: json.RawMessage(`"CIPHER=="`), Encrypted: true}, "test"); err != nil {
		t.Fatalf("SetKey(secret): %v", err)
	}

	// GetKey round-trip.
	got, ok, err := store.GetKey(ctx, secretKey)
	if err != nil || !ok {
		t.Fatalf("GetKey(secret): ok=%v err=%v", ok, err)
	}
	if !got.Encrypted {
		t.Errorf("GetKey(secret): encrypted column not persisted (got false)")
	}
	if bytes.Contains(got.Value, []byte("CIPHER==")) {
		t.Errorf("GetKey(secret): plaintext leaked into stored value = %s", got.Value)
	}

	gotP, ok, err := store.GetKey(ctx, plainKey)
	if err != nil || !ok {
		t.Fatalf("GetKey(plain): ok=%v err=%v", ok, err)
	}
	if gotP.Encrypted {
		t.Errorf("GetKey(plain): expected encrypted=false")
	}

	// Missing key → ok=false, no error.
	if _, ok, err := store.GetKey(ctx, prefix+"absent"); err != nil || ok {
		t.Errorf("GetKey(absent): ok=%v err=%v, want false,nil", ok, err)
	}

	// GetByPrefix returns both seeded rows with the encrypted column intact.
	rows, err := store.GetByPrefix(ctx, prefix)
	if err != nil {
		t.Fatalf("GetByPrefix: %v", err)
	}
	byKey := map[string]StoredConfig{}
	for _, rrow := range rows {
		byKey[rrow.Key] = rrow
	}
	if sc, ok := byKey[secretKey]; !ok || !sc.Encrypted {
		t.Errorf("GetByPrefix: secret row missing or encrypted=false: %+v", sc)
	}
	if sc, ok := byKey[plainKey]; !ok || sc.Encrypted {
		t.Errorf("GetByPrefix: plain row missing or encrypted=true: %+v", sc)
	}

	// BatchSet updates the plain key encrypted and adds a third — verify the
	// encrypted column is written per-key.
	if err := store.BatchSet(ctx, "test", map[string]ConfigValue{
		plainKey:            {Value: json.RawMessage(`"still-visible"`), Encrypted: false},
		prefix + "third":    {Value: json.RawMessage(`"v3"`), Encrypted: false},
		prefix + "four_enc": {Value: json.RawMessage(`"CIPHER2"`), Encrypted: true},
	}); err != nil {
		t.Fatalf("BatchSet: %v", err)
	}
	four, ok, err := store.GetKey(ctx, prefix+"four_enc")
	if err != nil || !ok {
		t.Fatalf("GetKey(four): ok=%v err=%v", ok, err)
	}
	if !four.Encrypted {
		t.Errorf("BatchSet: encrypted column not written for four_enc")
	}
}

// TestConfigStoreBatchSetFiresHooks proves BatchSet fires the registered hook for
// each matching key with the pre-write old value and the post-write new value.
func TestConfigStoreBatchSetFiresHooks(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const (
		key    = "cfgstore_hook_test_host"
		prefix = "cfgstore_hook_test_"
	)
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	})

	var reg SideEffectRegistry
	var mu sync.Mutex
	var oldSeen, newSeen string
	var fireCount int
	reg.Register("cfgstore_hook_test_", func(_ context.Context, k string, old, nw ConfigValue) {
		mu.Lock()
		defer mu.Unlock()
		fireCount++
		oldSeen = string(old.Value)
		newSeen = string(nw.Value)
	})

	store := NewConfigStore(pool, &reg)

	// Seed an initial value so the hook sees a non-empty old.
	if err := store.SetKey(ctx, key, ConfigValue{Value: json.RawMessage(`"v1"`)}, "test"); err != nil {
		t.Fatalf("seed SetKey: %v", err)
	}
	// SetKey fired once already; reset the observation.
	mu.Lock()
	fireCount = 0
	mu.Unlock()

	if err := store.BatchSet(ctx, "test", map[string]ConfigValue{
		key: {Value: json.RawMessage(`"v2"`)},
	}); err != nil {
		t.Fatalf("BatchSet: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if fireCount != 1 {
		t.Fatalf("expected hook to fire once on BatchSet, got %d", fireCount)
	}
	if oldSeen != `"v1"` {
		t.Errorf("hook old value = %q, want \"v1\"", oldSeen)
	}
	if newSeen != `"v2"` {
		t.Errorf("hook new value = %q, want \"v2\"", newSeen)
	}
}

// ---- TLS GetConfig redaction consistency (the fixed bug) --------------------

// TestTLSGetConfigRedactsSecret proves the TLS GetConfig handler redacts a
// secret tls_* key (encrypted column OR _enc suffix) to the [ENCRYPTED]
// sentinel, matching the LDAP/AD/config read-path discipline. Before the fix,
// TLS GetConfig returned every value raw.
func TestTLSGetConfigRedactsSecret(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const (
		secretKey = "tls_acme_eab_hmac_enc"
		secretVal = "RAW-TLS-CIPHERTEXT-must-not-leak"
		plainKey  = "tls_autocert_email"
		plainVal  = "admin@example.com"
	)
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted) VALUES ($1, to_jsonb($2::text), false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = false`,
		secretKey, secretVal); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, encrypted) VALUES ($1, to_jsonb($2::text), false)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = false`,
		plainKey, plainVal); err != nil {
		t.Fatalf("seed plain: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key IN ($1, $2)`, secretKey, plainKey)
	})

	h := NewTLSHandler(pool, nil, "")
	req := httptest.NewRequest(http.MethodGet, "/admin/tls/config", nil)
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetConfig: expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var cfg map[string]any
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := cfg[secretKey]; got != redactedConfigValue {
		t.Errorf("secret key %q leaked: got %v, want %q", secretKey, got, redactedConfigValue)
	}
	if cfg[secretKey] == secretVal {
		t.Fatalf("raw TLS ciphertext returned for %q", secretKey)
	}
	if cfg[plainKey] == redactedConfigValue {
		t.Errorf("non-secret key %q was over-redacted", plainKey)
	}
}

func TestConfigStoreRefusalAndRecoveryBranches(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	prefix := "cfgstore_branches_"
	legacyKey := prefix + "legacy_enc"
	envelopeKey := prefix + "envelope_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	})

	if _, err := NewConfigStore(pool, nil).EnsureSecretEncryption(ctx, prefix); err == nil {
		t.Fatal("EnsureSecretEncryption succeeded without a codec")
	}
	if err := NewConfigStore(pool, nil).SetKey(ctx, prefix+"missing_enc", ConfigValue{
		Value:     json.RawMessage(`"[ENCRYPTED]"`),
		Encrypted: true,
	}, "test"); err == nil {
		t.Fatal("redaction sentinel preserved an absent secret")
	}
	if err := NewConfigStore(pool, nil).SetKey(ctx, prefix+"plain_enc", ConfigValue{
		Value:     json.RawMessage(`"secret"`),
		Encrypted: true,
	}, "test"); err == nil {
		t.Fatal("secret write succeeded without a codec")
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, legacyKey); err != nil {
		t.Fatalf("seed legacy secret: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).GetDecryptedByPrefix(ctx, prefix); err == nil {
		t.Fatal("runtime read accepted legacy plaintext before startup migration")
	}

	envelope, err := codec.Encrypt(envelopeKey, json.RawMessage(`"already-enveloped"`))
	if err != nil {
		t.Fatalf("encrypt existing envelope: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, $2::jsonb, FALSE)
	`, envelopeKey, envelope); err != nil {
		t.Fatalf("seed unmarked envelope: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureSecretEncryption(ctx, prefix); err != nil {
		t.Fatalf("validate/mark existing envelope: %v", err)
	}
	var marked bool
	if err := pool.QueryRow(ctx, `SELECT encrypted FROM system_config WHERE key = $1`, envelopeKey).Scan(&marked); err != nil {
		t.Fatalf("read envelope marker: %v", err)
	}
	if !marked {
		t.Fatal("valid existing envelope was not marked encrypted")
	}

	if !hasAnyConfigPrefix("anything", nil) {
		t.Fatal("empty prefix set should select every secret")
	}
	if hasAnyConfigPrefix("ldap_sync_password_enc", []string{"ad_sync_"}) {
		t.Fatal("non-matching prefix selected a secret")
	}
}

func TestConfigStoreSecretMigrationReportsEveryInvalidEnvelope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	const prefix = "cfgstore_validation_failure_"
	badKeys := []string{prefix + "a_enc", prefix + "b_enc"}
	legacyKey := prefix + "legacy_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	})

	for _, key := range badKeys {
		if _, err := pool.Exec(ctx, `
			INSERT INTO system_config (key, value, encrypted)
			VALUES (
				$1,
				'{"format":"setjoin-config-secret","version":1,"keyVersion":1,"sourceKey":"legacy:system","ciphertext":"not-base64!"}'::jsonb,
				TRUE
			)
		`, key); err != nil {
			t.Fatalf("seed invalid envelope %q: %v", key, err)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, legacyKey); err != nil {
		t.Fatalf("seed legacy secret: %v", err)
	}

	_, err := NewConfigStore(pool, nil, codec).EnsureSecretEncryption(ctx, prefix)
	if err == nil {
		t.Fatal("startup migration accepted invalid envelopes")
	}
	for _, key := range badKeys {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("startup diagnostic omitted invalid key %q: %v", key, err)
		}
	}

	var encrypted bool
	var value string
	if err := pool.QueryRow(ctx,
		`SELECT encrypted, value #>> '{}' FROM system_config WHERE key = $1`,
		legacyKey,
	).Scan(&encrypted, &value); err != nil {
		t.Fatalf("read legacy secret after failed validation: %v", err)
	}
	if encrypted || value != "legacy-plaintext" {
		t.Fatalf("legacy secret changed despite failed validation: encrypted=%v value=%q", encrypted, value)
	}
}

func TestConfigStoreClosedPoolFailures(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	ctx := context.Background()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))

	if _, err := store.GetDecryptedByPrefix(ctx, "ldap_sync_"); err == nil {
		t.Fatal("GetDecryptedByPrefix succeeded on a closed pool")
	}
	if _, _, err := store.GetKey(ctx, "ldap_sync_password_enc"); err == nil {
		t.Fatal("GetKey succeeded on a closed pool")
	}
	if err := store.SetKey(ctx, "ldap_sync_password_enc", ConfigValue{
		Value:     json.RawMessage(`"[ENCRYPTED]"`),
		Encrypted: true,
	}, "test"); err == nil {
		t.Fatal("redaction-sentinel lookup succeeded on a closed pool")
	}
	if _, err := store.EnsureSecretEncryption(ctx, "ldap_sync_"); err == nil {
		t.Fatal("EnsureSecretEncryption began a transaction on a closed pool")
	}
}

func TestDirectoryConfigInputBounds(t *testing.T) {
	tooMany := make(map[string]interface{}, 65)
	for i := 0; i < 65; i++ {
		tooMany["ldap_sync_"+string(rune('a'+i))] = "value"
	}
	if err := validatePrefixedStringConfig(tooMany, "ldap_sync_"); err == nil {
		t.Fatal("65 config keys were accepted")
	}
	if err := validatePrefixedStringConfig(map[string]interface{}{"ldap_sync_port": 636}, "ldap_sync_"); err == nil {
		t.Fatal("non-string config value was accepted")
	}
	if err := validatePrefixedStringConfig(map[string]interface{}{"ldap_sync_host": "bad\x00host"}, "ldap_sync_"); err == nil {
		t.Fatal("control-bearing config value was accepted")
	}
	if _, err := configValuesFromRaw(map[string]interface{}{"ldap_sync_host": make(chan int)}); err == nil {
		t.Fatal("unmarshalable config value was accepted")
	}
}

type failingConfigSecretCodec struct{}

func (failingConfigSecretCodec) Encrypt(string, json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("injected encryption failure")
}

func (failingConfigSecretCodec) Decrypt(string, json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("injected decryption failure")
}

func TestConfigStoreFailsClosedOnCodecEncryptionFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "cfgstore_codec_failure_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})

	store := &ConfigStore{pool: pool, secrets: failingConfigSecretCodec{}}
	if err := store.SetKey(ctx, key, ConfigValue{
		Value:     json.RawMessage(`"secret"`),
		Encrypted: true,
	}, "test"); err == nil {
		t.Fatal("secret write ignored codec encryption failure")
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, key); err != nil {
		t.Fatalf("seed legacy secret: %v", err)
	}
	if _, err := store.EnsureSecretEncryption(ctx, "cfgstore_codec_failure_"); err == nil {
		t.Fatal("startup migration ignored codec encryption failure")
	}
}

func TestConfigStoreSecretMigrationRollsBackUpdateFailures(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	const (
		functionName = "test_config_store_reject_update"
		triggerName  = "test_config_store_reject_update"
		prefix       = "cfgstore_update_failure_"
	)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+triggerName+` ON system_config`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+functionName+`()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	})
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION `+functionName+`() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.key LIKE 'cfgstore_update_failure_%' THEN
				RAISE EXCEPTION 'injected config update failure';
			END IF;
			RETURN NEW;
		END
		$$;
		CREATE TRIGGER `+triggerName+`
		BEFORE UPDATE ON system_config
		FOR EACH ROW EXECUTE FUNCTION `+functionName+`()
	`); err != nil {
		t.Fatalf("install update-failure trigger: %v", err)
	}

	envelopeKey := prefix + "envelope_enc"
	envelope, err := codec.Encrypt(envelopeKey, json.RawMessage(`"secret"`))
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, $2::jsonb, FALSE)
	`, envelopeKey, envelope); err != nil {
		t.Fatalf("seed envelope fixture: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureSecretEncryption(ctx, prefix); err == nil {
		t.Fatal("envelope marker update failure was ignored")
	}

	if _, err := pool.Exec(ctx, `DELETE FROM system_config WHERE key = $1`, envelopeKey); err != nil {
		t.Fatalf("delete envelope fixture: %v", err)
	}
	legacyKey := prefix + "legacy_enc"
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, legacyKey); err != nil {
		t.Fatalf("seed legacy fixture: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureSecretEncryption(ctx, prefix); err == nil {
		t.Fatal("legacy ciphertext update failure was ignored")
	}
}

func TestConfigStoreSecretMigrationReportsDeferredCommitFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := testConfigSecretCodec(t)
	const (
		functionName = "test_config_store_reject_commit"
		triggerName  = "test_config_store_reject_commit"
		prefix       = "cfgstore_commit_failure_"
		key          = prefix + "secret_enc"
	)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+triggerName+` ON system_config`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS `+functionName+`()`)
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION `+functionName+`() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.key LIKE 'cfgstore_commit_failure_%' THEN
				RAISE EXCEPTION 'injected deferred commit failure';
			END IF;
			RETURN NEW;
		END
		$$;
		CREATE CONSTRAINT TRIGGER `+triggerName+`
		AFTER UPDATE ON system_config
		DEFERRABLE INITIALLY DEFERRED
		FOR EACH ROW EXECUTE FUNCTION `+functionName+`()
	`); err != nil {
		t.Fatalf("install commit-failure trigger: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO system_config (key, value, encrypted)
		VALUES ($1, to_jsonb('legacy-plaintext'::text), FALSE)
	`, key); err != nil {
		t.Fatalf("seed legacy fixture: %v", err)
	}
	if _, err := NewConfigStore(pool, nil, codec).EnsureSecretEncryption(ctx, prefix); err == nil {
		t.Fatal("deferred commit failure was ignored")
	}
}

// ---- EnsureNamedSecretEncryption tx-fault legs (Query/Scan/rows.Err) --------

// ConfigStore binds a concrete *pgxpool.Pool (no querier seam to stub), so the
// candidate-SELECT fault arms of the startup gate are driven the same way the
// secret-migration suite drives its Exec/Commit arms: a real database fault at
// the exact seam. Each test below resolves `system_config` through a
// session-scoped search_path to a test-owned shadow schema (prefixed, dropped
// in cleanup); the real system_config table is never mutated and no other pool
// ever uses these schemas.
func openNamedSecretFaultPool(t *testing.T, searchPath string) *pgxpool.Pool {
	t.Helper()
	// Delegate the skip/fatal policy (REQUIRE_DB, missing DB_DSN) to the shared
	// helper, matching openSingleConnPool in admin_ca_guard_test.go.
	testsupport.OpenTestPool(t).Close()

	cfg, err := pgxpool.ParseConfig(os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["search_path"] = searchPath
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// TestEnsureNamedSecretEncryptionQueryFaultAbortsUpgrade pins the tx.Query
// fault arm (candidate SELECT cannot even be prepared): the upgrade fails
// closed with the database's own error instead of reporting a successful
// zero-upgrade migration over a candidate set it never read.
func TestEnsureNamedSecretEncryptionQueryFaultAbortsUpgrade(t *testing.T) {
	pool := openNamedSecretFaultPool(t, "pg_catalog")
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))

	upgraded, err := store.EnsureNamedSecretEncryption(context.Background())
	if err == nil {
		t.Fatal("named-secret upgrade ignored a failing candidate SELECT")
	}
	if !strings.Contains(err.Error(), "system_config") {
		t.Fatalf("candidate SELECT fault surfaced the wrong error: %v", err)
	}
	if upgraded != 0 {
		t.Fatalf("upgraded = %d on a failed candidate SELECT, want 0", upgraded)
	}
}

// TestEnsureNamedSecretEncryptionScanFaultAbortsUpgrade pins the per-row Scan
// fault arm: a candidate row that does not fit the StoredConfig scan targets
// aborts the upgrade instead of migrating a half-read candidate set.
func TestEnsureNamedSecretEncryptionScanFaultAbortsUpgrade(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const schema = "cfgstore_named_scan_fault"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if _, err := pool.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS `+schema+`;
		CREATE TABLE IF NOT EXISTS `+schema+`.system_config (key text, value text, encrypted text);
		INSERT INTO `+schema+`.system_config (key, value, encrypted)
		VALUES ('assist.api_key', '"sk-shadow"', 'not-a-bool');
	`); err != nil {
		t.Fatalf("seed shadow scan-fault table: %v", err)
	}

	store := NewConfigStore(openNamedSecretFaultPool(t, schema), nil, testConfigSecretCodec(t))
	upgraded, err := store.EnsureNamedSecretEncryption(ctx)
	if err == nil {
		t.Fatal("named-secret upgrade ignored an unreadable candidate row")
	}
	if upgraded != 0 {
		t.Fatalf("upgraded = %d on a failed candidate scan, want 0", upgraded)
	}
}

// TestEnsureNamedSecretEncryptionRowsErrFaultAbortsUpgrade pins the
// post-iteration rows.Err fault arm: a candidate SELECT that fails during
// execution aborts the upgrade — an iteration error must never read as an
// empty candidate set. The shadow view emits the named key so the WHERE clause
// matches and the projection runs; its scalar subquery raises only at EXECUTE,
// after PREPARE has succeeded, landing the fault in rows.Err.
func TestEnsureNamedSecretEncryptionRowsErrFaultAbortsUpgrade(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const schema = "cfgstore_named_rowserr_fault"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if _, err := pool.Exec(ctx, `
		CREATE SCHEMA IF NOT EXISTS `+schema+`;
		CREATE OR REPLACE VIEW `+schema+`.system_config AS
		SELECT 'assist.api_key'::text AS key,
		       '"sk-shadow"'::text AS value,
		       (SELECT 1/0)::boolean AS encrypted;
	`); err != nil {
		t.Fatalf("seed shadow rows.Err view: %v", err)
	}

	store := NewConfigStore(openNamedSecretFaultPool(t, schema), nil, testConfigSecretCodec(t))
	upgraded, err := store.EnsureNamedSecretEncryption(ctx)
	if err == nil {
		t.Fatal("named-secret upgrade ignored a failing candidate iteration")
	}
	if !strings.Contains(err.Error(), "division by zero") {
		t.Fatalf("candidate iteration fault surfaced the wrong error: %v", err)
	}
	if upgraded != 0 {
		t.Fatalf("upgraded = %d on a failed candidate iteration, want 0", upgraded)
	}
}
