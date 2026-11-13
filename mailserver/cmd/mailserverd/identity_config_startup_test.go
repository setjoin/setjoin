package main

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

// TestIdentityDirectoryWorkersStartAfterSecretGate is a source-level ordering
// guard for the upgrade boundary. A directory Run loop must not begin before
// legacy plaintext is upgraded and every existing envelope is authenticated.
func TestIdentityDirectoryWorkersStartAfterSecretGate(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	text := string(source)
	gate := strings.Index(text, "store.EnsureSecretEncryption")
	if gate < 0 {
		t.Fatal("connector-secret startup gate is missing")
	}
	runSeams := []string{`startWorker(ctx, "ldap-sync", adminLDAPH.StartSync)`, `startWorker(ctx, "ad-sync", adminADH.StartSync)`}
	for _, runSeam := range runSeams {
		position := strings.Index(text, runSeam)
		if position < 0 {
			t.Fatalf("directory worker controller seam %q is missing", runSeam)
		}
		if position < gate {
			t.Fatalf("directory worker starts before connector-secret gate: gate=%d run=%d", gate, position)
		}
	}
}

func identityConfigForTest() *config.Config {
	cfg := &config.Config{
		IdentityConfigSecretKeyVersion: 1,
	}
	cfg.DBEncryptionKey = "0123456789abcdef0123456789abcdef"
	cfg.CryptoProfile = cryptokey.ProfileStandard
	return cfg
}

func TestConfigureIdentityDirectorySuccessAndInputFailures(t *testing.T) {
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

	logger := testsupport.TestLogger()
	adHandler := admin.NewADHandler(pool, logger, &config.Config{})
	ldapHandler := admin.NewLDAPHandler(pool, logger)
	effects, secrets, upgraded, err := configureIdentityDirectory(
		ctx, pool, identityConfigForTest(), adHandler, ldapHandler, logger,
	)
	if err != nil {
		t.Fatalf("configure identity directory: %v", err)
	}
	if effects == nil || secrets == nil || upgraded != 0 {
		t.Fatalf("configure result effects=%v secrets=%v upgraded=%d", effects, secrets, upgraded)
	}

	rec := httptest.NewRecorder()
	adHandler.SetConfig(rec, httptest.NewRequest(
		http.MethodPut,
		"/admin/ad/config",
		strings.NewReader(`{"ad_sync_display_name":"test"}`),
	))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("configured store is not active: %d %s", rec.Code, rec.Body.String())
	}

	for name, configure := range map[string]func() *httptest.ResponseRecorder{
		"ad": func() *httptest.ResponseRecorder {
			first := httptest.NewRecorder()
			adHandler.SetConfig(first, httptest.NewRequest(http.MethodPut, "/admin/ad/config", strings.NewReader(
				`{"ad_sync_domain":"example.test","ad_sync_ldap_host":"127.0.0.1:1","ad_sync_password_enc":"secret"}`,
			)))
			if first.Code != http.StatusNoContent {
				t.Fatalf("activate AD worker: %d %s", first.Code, first.Body.String())
			}
			second := httptest.NewRecorder()
			adHandler.SetConfig(second, httptest.NewRequest(http.MethodPut, "/admin/ad/config", strings.NewReader(
				`{"ad_sync_display_name":"trigger-existing-worker"}`,
			)))
			return second
		},
		"ldap": func() *httptest.ResponseRecorder {
			first := httptest.NewRecorder()
			ldapHandler.SetConfig(first, httptest.NewRequest(http.MethodPut, "/admin/ldap/config", strings.NewReader(
				`{"ldap_sync_host":"127.0.0.1","ldap_sync_port":"1","ldap_sync_bind_dn":"cn=svc","ldap_sync_password_enc":"secret","ldap_sync_base_dn":"dc=example,dc=test","ldap_sync_subject_attribute":"entryUUID"}`,
			)))
			if first.Code != http.StatusNoContent {
				t.Fatalf("activate LDAP worker: %d %s", first.Code, first.Body.String())
			}
			second := httptest.NewRecorder()
			ldapHandler.SetConfig(second, httptest.NewRequest(http.MethodPut, "/admin/ldap/config", strings.NewReader(
				`{"ldap_sync_display_name":"trigger-existing-worker"}`,
			)))
			return second
		},
	} {
		t.Run("effect-"+name, func(t *testing.T) {
			result := configure()
			if result.Code != http.StatusNoContent {
				t.Fatalf("trigger %s effect: %d %s", name, result.Code, result.Body.String())
			}
		})
	}
	// The registry deliberately launches non-blocking syncs; give the loopback
	// refusal enough time to execute both error paths before this test returns.
	time.Sleep(100 * time.Millisecond)

	for name, mutate := range map[string]func(*config.Config){
		"zero-version": func(cfg *config.Config) {
			cfg.IdentityConfigSecretKeyVersion = 0
		},
		"oversized-version": func(cfg *config.Config) {
			cfg.IdentityConfigSecretKeyVersion = int(math.MaxUint32) + 1
		},
		"bad-retiring-keyring": func(cfg *config.Config) {
			cfg.IdentityConfigSecretRetiringKeys = "[]"
		},
		"short-active-key": func(cfg *config.Config) {
			cfg.IdentityConfigSecretKey = "short"
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := identityConfigForTest()
			mutate(cfg)
			if _, _, _, err := configureIdentityDirectory(ctx, pool, cfg, adHandler, ldapHandler, logger); err == nil {
				t.Fatal("invalid connector-secret configuration was accepted")
			}
		})
	}
}

func TestConfigureIdentityDirectoryDatabaseAndEnvelopeFailures(t *testing.T) {
	logger := testsupport.TestLogger()

	closed := testsupport.OpenTestPool(t)
	closed.Close()
	if _, _, _, err := configureIdentityDirectory(
		context.Background(),
		closed,
		identityConfigForTest(),
		admin.NewADHandler(closed, logger, &config.Config{}),
		admin.NewLDAPHandler(closed, logger),
		logger,
	); err == nil {
		t.Fatal("closed database was accepted")
	}

	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	const key = "ldap_sync_password_enc"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key)
	})
	codec, err := admin.NewConfigSecretCodec(admin.ConfigSecretKeyring{
		DeploymentID:  testIdentityDeploymentID(t, pool),
		ActiveVersion: 1,
		ActiveKey:     []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		ActiveProfile: cryptokey.ProfileStandard,
	})
	if err != nil {
		t.Fatalf("writer codec: %v", err)
	}
	if err := admin.NewConfigStore(pool, nil, codec).SetKey(ctx, key, admin.ConfigValue{
		Value:     []byte(`"secret"`),
		Encrypted: true,
	}, "test"); err != nil {
		t.Fatalf("seed encrypted secret: %v", err)
	}
	if _, _, _, err := configureIdentityDirectory(
		ctx,
		pool,
		identityConfigForTest(),
		admin.NewADHandler(pool, logger, &config.Config{}),
		admin.NewLDAPHandler(pool, logger),
		logger,
	); err == nil {
		t.Fatal("wrong connector-secret key was accepted")
	}
}

func TestConfigureIdentityDirectoryToleratesStoredActivationFailures(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	keys := map[string]string{
		"ad_sync_domain":              "invalid.",
		"ldap_sync_host":              "127.0.0.1",
		"ldap_sync_subject_attribute": "not an attribute",
		"ldap_sync_interval_min":      "15",
		"ldap_sync_auto_create_depts": "false",
		"ldap_sync_user_filter":       "(objectClass=person)",
	}
	for key, value := range keys {
		if _, err := pool.Exec(ctx, `
			INSERT INTO system_config(key,value,encrypted)
			VALUES($1,to_jsonb($2::text),false)
			ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=false`,
			key, value,
		); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	t.Cleanup(func() {
		for key := range keys {
			_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key=$1`, key)
		}
	})

	logger := testsupport.TestLogger()
	effects, _, _, err := configureIdentityDirectory(
		ctx, pool, identityConfigForTest(),
		admin.NewADHandler(pool, logger, &config.Config{}),
		admin.NewLDAPHandler(pool, logger),
		logger,
	)
	if err != nil || effects == nil {
		t.Fatalf("stored activation failures should remain non-fatal: effects=%v err=%v", effects, err)
	}
}

func testIdentityDeploymentID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var deploymentID string
	if err := pool.QueryRow(
		context.Background(),
		`SELECT value #>> '{}' FROM system_config WHERE key = 'identity.deployment_id'`,
	).Scan(&deploymentID); err != nil {
		t.Fatalf("load deployment ID: %v", err)
	}
	return deploymentID
}
