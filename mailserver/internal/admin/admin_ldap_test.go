package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/ad"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/mailserver/internal/ldapsync"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

func TestLDAPConfigKeyPrefixes(t *testing.T) {
	// Verify the LDAP config key prefix used by GetConfig
	prefix := "ldap_sync_"
	expectedKeys := []string{
		"ldap_sync_enabled",
		"ldap_sync_host",
		"ldap_sync_port",
		"ldap_sync_tls",
		"ldap_sync_bind_dn",
		"ldap_sync_password_enc",
		"ldap_sync_base_dn",
		"ldap_sync_user_filter",
		"ldap_sync_interval_min",
		"ldap_sync_auto_create_depts",
	}

	for _, key := range expectedKeys {
		if !hasPrefix(key, prefix) {
			t.Errorf("expected %q to start with %q", key, prefix)
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// ---- redactConfigValue unit (no DB) -----------------------------------------

// TestRedactConfigValue covers the read-path redaction contract: secret material
// (encrypted column OR a `_enc` key) is replaced with the [ENCRYPTED] sentinel;
// non-secret keys pass through untouched.
func TestRedactConfigValue(t *testing.T) {
	cases := []struct {
		name      string
		key       string
		value     string
		encrypted bool
		want      string
	}{
		{"enc suffix, column false", "ldap_sync_password_enc", "AESCIPHERTEXT==", false, redactedConfigValue},
		{"enc suffix, column true", "ad_sync_password_enc", "AESCIPHERTEXT==", true, redactedConfigValue},
		{"encrypted column only", "some_secret", "rawsecret", true, redactedConfigValue},
		{"non-secret passes through", "ldap_sync_host", "ldap.example.com", false, "ldap.example.com"},
		{"non-secret enabled flag", "ldap_sync_enabled", "true", false, "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactConfigValue(tc.key, tc.value, tc.encrypted); got != tc.want {
				t.Errorf("redactConfigValue(%q,%q,%v) = %q, want %q",
					tc.key, tc.value, tc.encrypted, got, tc.want)
			}
		})
	}
}

func TestConfigStringForResponseDecodesOneJSONScalarWithoutLeakingSecrets(t *testing.T) {
	if got := configStringForResponse("ldap_sync_user_filter", []byte(`""`), false); got != "" {
		t.Fatalf("empty JSON string = %q, want empty scalar", got)
	}
	if got := configStringForResponse("ldap_sync_user_filter", []byte(`"(objectClass=person)"`), false); got != "(objectClass=person)" {
		t.Fatalf("filter JSON string = %q", got)
	}
	if got := configStringForResponse("ldap_sync_user_filter", []byte(`legacy-unquoted`), false); got != "legacy-unquoted" {
		t.Fatalf("legacy non-JSON value = %q, want compatibility fallback", got)
	}
	if got := configStringForResponse("ldap_sync_password_enc", []byte(`"plaintext"`), false); got != redactedConfigValue {
		t.Fatalf("secret response = %q", got)
	}
}

// ---- GetConfig DB-backed redaction (skipped without DB_DSN) -----------------

// TestLDAPGetConfigRedactsSecret proves the LDAP GetConfig handler never returns
// the raw ldap_sync_password_enc ciphertext, while non-secret keys come through.
// It seeds rows with encrypted=false to mirror the batchUpsertSystemConfig write
// path (which does not set the encrypted flag) — the redaction must hold anyway.
func TestLDAPGetConfigRedactsSecret(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const (
		secretKey = "ldap_sync_password_enc"
		secretVal = "RAW-LDAP-CIPHERTEXT-must-not-leak"
		plainKey  = "ldap_sync_host"
		plainVal  = "ldap.test.example.com"
	)
	// Seed with encrypted=false on purpose: the suffix backstop must still redact.
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

	h := NewLDAPHandler(pool, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/ldap/config", nil)
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetConfig: expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var cfg map[string]string
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := cfg[secretKey]; got != redactedConfigValue {
		t.Errorf("secret key %q leaked: got %q, want %q", secretKey, got, redactedConfigValue)
	}
	if cfg[secretKey] == secretVal {
		t.Fatalf("raw ciphertext returned for %q", secretKey)
	}
	if got := cfg[plainKey]; got != plainVal {
		t.Errorf("non-secret key %q = %q, want exact scalar %q", plainKey, got, plainVal)
	}
}

// TestADGetConfigRedactsSecret is the AD twin of the LDAP redaction test.
func TestADGetConfigRedactsSecret(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const (
		secretKey = "ad_sync_password_enc"
		secretVal = "RAW-AD-CIPHERTEXT-must-not-leak"
		plainKey  = "ad_sync_host"
		plainVal  = "ad.test.example.com"
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

	h := NewADHandler(pool, nil, &config.Config{})
	req := httptest.NewRequest(http.MethodGet, "/admin/ad/config", nil)
	w := httptest.NewRecorder()
	h.GetConfig(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GetConfig: expected 200, got %d — %s", w.Code, w.Body.String())
	}

	var cfg map[string]string
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := cfg[secretKey]; got != redactedConfigValue {
		t.Errorf("secret key %q leaked: got %q, want %q", secretKey, got, redactedConfigValue)
	}
	if cfg[secretKey] == secretVal {
		t.Fatalf("raw ciphertext returned for %q", secretKey)
	}
	if got := cfg[plainKey]; got != plainVal {
		t.Errorf("non-secret key %q = %q, want exact scalar %q", plainKey, got, plainVal)
	}
}

// ---- defect #2: console-written system_config never rebuilds the client ----

// TestSetConfigRebuildsSyncWorker is the regression for the "console config =
// 503 forever" bug: a fresh LDAPHandler (no env-configured worker, exactly
// what NewLDAPHandler(pool, logger) gives a deployment that never set
// LDAPSyncHost) must go from nil syncWorker (every Test/Sync/Preview call
// 503s) to a live one the moment an admin PUTs /admin/ldap/config — no
// restart required.
func TestSetConfigRebuildsSyncWorker(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	t.Cleanup(func() {
		pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'`)
	})

	h := NewLDAPHandler(pool, testsupport.TestLogger())
	h.SetConfigStore(NewConfigStore(pool, nil, testConfigSecretCodec(t)))

	// Before any config write: no worker, every live-directory endpoint 503s.
	preReq := httptest.NewRequest(http.MethodPost, "/admin/ldap/test-connection", nil)
	preW := httptest.NewRecorder()
	h.TestConnection(preW, preReq)
	if preW.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-config TestConnection = %d, want 503 (nil syncWorker)", preW.Code)
	}

	body, _ := json.Marshal(map[string]string{
		"ldap_sync_enabled":      "false",
		"ldap_sync_host":         "127.0.0.1",
		"ldap_sync_port":         "1", // unreachable — connectivity isn't under test here
		"ldap_sync_bind_dn":      "cn=svc,dc=example,dc=com",
		"ldap_sync_password_enc": "hunter2",
		"ldap_sync_base_dn":      "dc=example,dc=com",
	})
	setReq := httptest.NewRequest(http.MethodPut, "/admin/ldap/config", strings.NewReader(string(body)))
	setW := httptest.NewRecorder()
	h.SetConfig(setW, setReq)
	if setW.Code != http.StatusNoContent {
		t.Fatalf("SetConfig = %d, want 204 — %s", setW.Code, setW.Body.String())
	}
	if h.SyncWorker() == nil || h.Enabled() {
		t.Fatalf("disabled configured LDAP state worker=%v enabled=%v", h.SyncWorker(), h.Enabled())
	}

	// A disabled-but-configured directory remains available to read-only
	// TestConnection/Preview, but mutating sync stays fail-closed.
	postReq := httptest.NewRequest(http.MethodPost, "/admin/ldap/test-connection", nil)
	postW := httptest.NewRecorder()
	h.TestConnection(postW, postReq)
	if postW.Code == http.StatusServiceUnavailable {
		t.Fatal("post-config TestConnection still 503s — SetConfig did not rebuild the sync worker")
	}
	disabledSyncW := httptest.NewRecorder()
	h.SyncNow(disabledSyncW, httptest.NewRequest(http.MethodPost, "/admin/ldap/sync", nil))
	if disabledSyncW.Code != http.StatusServiceUnavailable ||
		!strings.Contains(disabledSyncW.Body.String(), "not enabled") {
		t.Fatalf("disabled SyncNow = %d %s, want explicit 503", disabledSyncW.Code, disabledSyncW.Body.String())
	}

	enableReq := httptest.NewRequest(http.MethodPut, "/admin/ldap/config",
		strings.NewReader(`{"ldap_sync_enabled":"true"}`))
	enableW := httptest.NewRecorder()
	h.SetConfig(enableW, enableReq)
	if enableW.Code != http.StatusNoContent || !h.Enabled() || h.SyncWorker() == nil {
		t.Fatalf("enabled LDAP config status=%d enabled=%v worker=%v",
			enableW.Code, h.Enabled(), h.SyncWorker())
	}

	disableReq := httptest.NewRequest(http.MethodPut, "/admin/ldap/config",
		strings.NewReader(`{"ldap_sync_enabled":"false"}`))
	disableW := httptest.NewRecorder()
	h.SetConfig(disableW, disableReq)
	if disableW.Code != http.StatusNoContent || h.SyncWorker() == nil || h.Enabled() {
		t.Fatalf("disabled LDAP config status=%d enabled=%v worker=%v",
			disableW.Code, h.Enabled(), h.SyncWorker())
	}
}

func TestADSetConfigRebuildsSyncWorkerFromEncryptedPassword(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE 'ad_sync_%'`)
	})

	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{ADSyncEnabled: true})
	enabled := true
	h.SetEnabledResolver(func() bool { return enabled })
	h.SetConfigStore(NewConfigStore(pool, nil, testConfigSecretCodec(t)))
	body, _ := json.Marshal(map[string]string{
		"ad_sync_domain":       "example.test",
		"ad_sync_ldap_host":    "127.0.0.1",
		"ad_sync_bind_dn":      "cn=svc,dc=example,dc=test",
		"ad_sync_password_enc": "directory-password",
		"ad_sync_interval_min": "15",
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/ad/config", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.SetConfig(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("SetConfig = %d, want 204 — %s", w.Code, w.Body.String())
	}
	if h.SyncWorker() == nil {
		t.Fatal("AD worker was not rebuilt from stored config")
	}

	var stored []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT value FROM system_config WHERE key = 'ad_sync_password_enc'`,
	).Scan(&stored); err != nil {
		t.Fatalf("read stored AD password: %v", err)
	}
	if bytes.Contains(stored, []byte("directory-password")) {
		t.Fatalf("AD password persisted as plaintext: %s", stored)
	}
}

func TestDirectoryConfigRejectsOutOfNamespaceKeys(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	for name, handler := range map[string]http.HandlerFunc{
		"ldap": NewLDAPHandler(pool, testsupport.TestLogger()).SetConfig,
		"ad":   NewADHandler(pool, testsupport.TestLogger(), &config.Config{}).SetConfig,
	} {
		t.Run(name, func(t *testing.T) {
			key := "cfg_namespace_escape_" + name
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
			})
			req := httptest.NewRequest(http.MethodPut, "/admin/"+name+"/config",
				strings.NewReader(`{"`+key+`":"must-not-write"}`))
			w := httptest.NewRecorder()
			handler(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("SetConfig = %d, want 400 — %s", w.Code, w.Body.String())
			}
			var count int
			if err := pool.QueryRow(context.Background(),
				`SELECT count(*) FROM system_config WHERE key = $1`, key,
			).Scan(&count); err != nil {
				t.Fatalf("count escaped key: %v", err)
			}
			if count != 0 {
				t.Fatal("out-of-namespace config key was persisted")
			}
		})
	}
}

func TestADNilWorkerAndReloadBranches(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key LIKE 'ad_sync_%'`)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE 'ad_sync_%'`)
	})

	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{ADSyncEnabled: true})
	enabled := true
	h.SetEnabledResolver(func() bool { return enabled })
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"test": h.TestConnection,
		"sync": h.SyncNow,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			call(rec, httptest.NewRequest(http.MethodPost, "/admin/ad/"+name, nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("nil-worker %s = %d, want 503", name, rec.Code)
			}
		})
	}
	rec := httptest.NewRecorder()
	h.Health(rec, httptest.NewRequest(http.MethodGet, "/admin/ad/health", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"unknown"`) {
		t.Fatalf("nil-worker health = %d %s", rec.Code, rec.Body.String())
	}

	h.SetConfigStore(NewConfigStore(pool, nil, testConfigSecretCodec(t)))
	if err := h.ReloadConfig(ctx); err != nil {
		t.Fatalf("empty AD config reload: %v", err)
	}
	if h.SyncWorker() != nil {
		t.Fatal("empty AD config unexpectedly constructed a worker")
	}

	body := `{"ad_sync_domain":"example.test","ad_sync_ldap_host":"127.0.0.1","ad_sync_password_enc":"secret"}`
	rec = httptest.NewRecorder()
	h.SetConfig(rec, httptest.NewRequest(http.MethodPut, "/admin/ad/config", strings.NewReader(body)))
	if rec.Code != http.StatusNoContent || h.SyncWorker() == nil {
		t.Fatalf("default-interval AD config = %d %s", rec.Code, rec.Body.String())
	}
	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"test": h.TestConnection,
		"sync": h.SyncNow,
	} {
		t.Run("configured-"+name, func(t *testing.T) {
			callRec := httptest.NewRecorder()
			call(callRec, httptest.NewRequest(http.MethodPost, "/admin/ad/"+name, nil))
			if callRec.Code == http.StatusServiceUnavailable {
				t.Fatalf("configured %s still reported no worker", name)
			}
		})
	}
	enabled = false
	if err := h.ReloadConfig(ctx); err != nil {
		t.Fatalf("disabled AD reload: %v", err)
	}
	if h.SyncWorker() != nil {
		t.Fatal("disabled AD feature gate retained a live worker")
	}
}

func TestDirectorySetConfigReportsStoredSecretReloadFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	for _, prefix := range []string{"ad_sync_", "ldap_sync_"} {
		_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
	}
	t.Cleanup(func() {
		for _, prefix := range []string{"ad_sync_", "ldap_sync_"} {
			_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE $1`, prefix+"%")
		}
	})

	writer := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	wrongCodec, err := NewConfigSecretCodec(ConfigSecretKeyring{
		DeploymentID:  testConfigDeploymentID,
		ActiveVersion: 1,
		ActiveKey:     []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatalf("wrong codec: %v", err)
	}

	cases := []struct {
		name   string
		secret string
		body   string
		call   func(*ConfigStore, http.ResponseWriter, *http.Request)
	}{
		{
			name:   "ad",
			secret: "ad_sync_password_enc",
			body:   `{"ad_sync_domain":"example.test"}`,
			call: func(store *ConfigStore, w http.ResponseWriter, r *http.Request) {
				h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{ADSyncEnabled: true})
				h.SetConfigStore(store)
				h.SetConfig(w, r)
			},
		},
		{
			name:   "ldap",
			secret: "ldap_sync_password_enc",
			body:   `{"ldap_sync_host":"127.0.0.1"}`,
			call: func(store *ConfigStore, w http.ResponseWriter, r *http.Request) {
				h := NewLDAPHandler(pool, testsupport.TestLogger())
				h.SetConfigStore(store)
				h.SetConfig(w, r)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := writer.SetKey(ctx, tc.secret, ConfigValue{
				Value:     json.RawMessage(`"secret"`),
				Encrypted: true,
			}, "test"); err != nil {
				t.Fatalf("seed %s secret: %v", tc.name, err)
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/admin/"+tc.name+"/config", strings.NewReader(tc.body))
			tc.call(NewConfigStore(pool, nil, wrongCodec), rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("wrong-key reload = %d, want 500 (%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDirectoryReloadFailsOnClosedPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	if err := NewADHandler(pool, testsupport.TestLogger(), &config.Config{ADSyncEnabled: true}).ReloadConfig(context.Background()); err == nil {
		t.Fatal("AD reload succeeded on a closed pool")
	}
	ldap := NewLDAPHandler(pool, testsupport.TestLogger())
	ldap.SetConfigStore(store)
	if err := ldap.ReloadConfig(context.Background()); err == nil {
		t.Fatal("LDAP reload succeeded on a closed pool")
	}
}

func TestADReloadReportsDiscoveryFailureWithoutOverrideHost(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "ad_sync_domain"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	if err := store.SetKey(ctx, key, ConfigValue{
		Value: json.RawMessage(`"invalid."`),
	}, "test"); err != nil {
		t.Fatalf("seed invalid discovery domain: %v", err)
	}
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{ADSyncEnabled: true})
	h.SetConfigStore(store)
	if err := h.ReloadConfig(ctx); err == nil {
		t.Fatal("AD reload ignored domain discovery failure")
	}
}

func TestDirectoryHandlersWireNormalizedSourcesInEitherOrder(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	store := identitysource.NewStore(pool)
	logger := testsupport.TestLogger()

	for _, sourceFirst := range []bool{true, false} {
		t.Run("ad/source-first="+strconv.FormatBool(sourceFirst), func(t *testing.T) {
			h := NewADHandler(pool, logger, &config.Config{})
			worker := ad.NewSyncWorker(nil, pool, logger, 15)
			if sourceFirst {
				h.SetIdentitySourceStore(store)
				h.setSyncWorker(worker)
			} else {
				h.setSyncWorker(worker)
				h.SetIdentitySourceStore(store)
			}
			if h.SyncWorker() != worker {
				t.Fatal("AD handler did not retain the normalized worker")
			}
		})

		t.Run("ldap/source-first="+strconv.FormatBool(sourceFirst), func(t *testing.T) {
			client := ldapsync.NewClient("127.0.0.1", 636, true, "", "", "dc=example,dc=test")
			if err := client.SetSubjectAttribute("entryUUID"); err != nil {
				t.Fatalf("configure LDAP subject: %v", err)
			}
			h := NewLDAPHandler(pool, logger)
			worker := ldapsync.NewSyncWorker(client, pool, logger, 15)
			if sourceFirst {
				h.SetIdentitySourceStore(store)
				h.SetSyncWorker(worker)
			} else {
				h.SetSyncWorker(worker)
				h.SetIdentitySourceStore(store)
			}
			if h.SyncWorker() != worker {
				t.Fatal("LDAP handler did not retain the normalized worker")
			}
		})
	}
}

func TestDirectoryHandlersNilWorkerLifecycleIsSafe(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	adHandler := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	adHandler.StartSync(ctx)
	adHandler.StopSync()

	ldapHandler := NewLDAPHandler(pool, testsupport.TestLogger())
	ldapHandler.StartSync(ctx)
	ldapHandler.StopSync()

	client := ldapsync.NewClient("127.0.0.1", 636, true, "", "", "dc=example,dc=test")
	enabledLDAPHandler := NewLDAPHandler(pool, testsupport.TestLogger())
	enabledLDAPHandler.SetSyncWorker(ldapsync.NewSyncWorker(client, pool, testsupport.TestLogger(), 15))
	enabledLDAPHandler.StartSync(ctx)
	enabledLDAPHandler.StopSync()
}

func TestADRuntimeResolverAndEmptyDomainReload(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := NewADHandler(pool, testsupport.TestLogger(), &config.Config{})
	client, err := ad.NewConfiguredClient(ad.ClientConfig{
		Host: "127.0.0.1", Port: 1, Transport: "ldaps",
		BaseDN: "dc=example,dc=test", SubjectAttribute: "objectGUID",
	}, testsupport.TestLogger())
	if err != nil {
		t.Fatal(err)
	}
	worker := ad.NewSyncWorker(client, pool, testsupport.TestLogger(), 15)
	h.setSyncWorker(worker)
	h.SetEnabledResolver(func() bool { return true })
	h.StartSync(ctx)
	h.StopSync()

	_, _ = pool.Exec(context.Background(),
		`DELETE FROM system_config WHERE key LIKE 'ad_sync_%'`)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key LIKE 'ad_sync_%'`)
	})
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	if err := store.SetKey(context.Background(), "ad_sync_interval_min", ConfigValue{
		Value: json.RawMessage(`"15"`),
	}, "test"); err != nil {
		t.Fatal(err)
	}
	h.SetConfigStore(store)
	if err := h.ReloadConfig(context.Background()); err != nil {
		t.Fatalf("reload without AD domain: %v", err)
	}
	if h.SyncWorker() != nil {
		t.Fatal("AD reload without domain retained a worker")
	}
}

func TestLDAPReloadRejectsInvalidRuntimeConfiguration(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	h := NewLDAPHandler(pool, testsupport.TestLogger())
	h.SetConfigStore(store)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'`)
	})

	cases := []struct {
		name   string
		values map[string]string
	}{
		{
			name: "enabled flag",
			values: map[string]string{
				"ldap_sync_enabled": "sometimes",
				"ldap_sync_host":    "127.0.0.1",
			},
		},
		{
			name: "TLS mode",
			values: map[string]string{
				"ldap_sync_enabled": "true",
				"ldap_sync_host":    "127.0.0.1",
				"ldap_sync_tls":     "sometimes",
			},
		},
		{
			name: "user filter",
			values: map[string]string{
				"ldap_sync_enabled":     "true",
				"ldap_sync_host":        "127.0.0.1",
				"ldap_sync_user_filter": "(",
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, _ = pool.Exec(ctx,
				`DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'`)
			for key, value := range test.values {
				if err := store.SetKey(ctx, key, ConfigValue{
					Value: json.RawMessage(strconv.Quote(value)),
				}, "test"); err != nil {
					t.Fatalf("seed %s: %v", key, err)
				}
			}
			if err := h.ReloadConfig(ctx); err == nil {
				t.Fatal("invalid LDAP runtime configuration unexpectedly loaded")
			}
			if h.SyncWorker() != nil {
				t.Fatal("invalid LDAP runtime configuration retained a worker")
			}
		})
	}
}

func TestLDAPReloadRejectsInvalidSubjectAttribute(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'`)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'`)
	})

	store := NewConfigStore(pool, nil, testConfigSecretCodec(t))
	for key, value := range map[string]string{
		"ldap_sync_enabled":           "true",
		"ldap_sync_host":              "127.0.0.1",
		"ldap_sync_subject_attribute": "not an attribute",
	} {
		if err := store.SetKey(ctx, key, ConfigValue{Value: json.RawMessage(strconv.Quote(value))}, "test"); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	h := NewLDAPHandler(pool, testsupport.TestLogger())
	h.SetConfigStore(store)
	if err := h.ReloadConfig(ctx); err == nil {
		t.Fatal("LDAP reload accepted an invalid subject attribute")
	}
}
