package federation

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/pgnotify"
)

type recordingConfigListener struct {
	channel      string
	handler      pgnotify.NotifyHandler
	reconnect    func(context.Context) error
	subscribeErr error
}

func (l *recordingConfigListener) OnReconnect(refresh func(context.Context) error) {
	l.reconnect = refresh
}

func (l *recordingConfigListener) SubscribeDurable(
	_ context.Context,
	channel string,
	handler pgnotify.NotifyHandler,
) (int, error) {
	l.channel = channel
	l.handler = handler
	return 7, l.subscribeErr
}

func TestOIDCListenForChangesRegistersDurableReload(t *testing.T) {
	wantErr := errors.New("initial LISTEN failed")
	listener := &recordingConfigListener{subscribeErr: wantErr}

	err := (&OIDCRPProvider{}).ListenForChanges(t.Context(), listener, slog.Default())
	if !errors.Is(err, wantErr) {
		t.Fatalf("ListenForChanges error = %v, want %v", err, wantErr)
	}
	assertDurableConfigRegistration(t, listener)
	listener.handler(&pgconn.Notification{Payload: `{`})
}

func TestSAMLListenForChangesRegistersDurableReload(t *testing.T) {
	wantErr := errors.New("initial LISTEN failed")
	listener := &recordingConfigListener{subscribeErr: wantErr}

	err := (&SAMLSPRegistry{}).ListenForChanges(t.Context(), listener, slog.Default())
	if !errors.Is(err, wantErr) {
		t.Fatalf("ListenForChanges error = %v, want %v", err, wantErr)
	}
	assertDurableConfigRegistration(t, listener)
	listener.handler(&pgconn.Notification{Payload: `{`})
}

func assertDurableConfigRegistration(t *testing.T, listener *recordingConfigListener) {
	t.Helper()
	if listener.channel != "config_changed" {
		t.Fatalf("subscription channel = %q, want config_changed", listener.channel)
	}
	if listener.handler == nil {
		t.Fatal("durable notification handler was not registered")
	}
	if listener.reconnect == nil {
		t.Fatal("authoritative reconnect refresh was not registered")
	}
}

func TestIsOIDCConfigNotification(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("a", 201)
	for _, tc := range []struct {
		key  string
		want bool
	}{
		{"auth_methods", true},
		{"oidc_rp", true},
		{"oidc_provider_workforce_config", true},
		{"oidc_provider_cn-prod_config", true},
		{"oidc_provider__config", false},
		{"oidc_provider_workforce", false},
		{"provider_workforce_config", false},
		{"oidc_provider_bad\nname_config", false},
		{"oidc_provider_" + longName + "_config", false},
	} {
		t.Run(tc.key, func(t *testing.T) {
			if got := isOIDCConfigNotification(tc.key); got != tc.want {
				t.Fatalf("isOIDCConfigNotification(%q)=%v want %v",
					tc.key, got, tc.want)
			}
		})
	}
}

func TestOIDCReplaceProvidersFailClosed(t *testing.T) {
	t.Parallel()
	p := &OIDCRPProvider{providers: map[string]*oidcProviderConfig{
		"revoked": {name: "revoked"},
	}}
	p.replaceProviders(nil)
	if got := p.Provider("revoked"); got != nil {
		t.Fatalf("revoked provider survived fail-closed replacement: %#v", got)
	}
}

func TestSAMLReplaceEntriesFailClosed(t *testing.T) {
	t.Parallel()
	r := &SAMLSPRegistry{entries: map[string]*samlspRegistration{
		"revoked": {IDPEntityID: "revoked"},
	}}
	r.replaceEntries(nil)
	if got := r.Registration("revoked"); got != nil {
		t.Fatalf("revoked registration survived fail-closed replacement: %#v", got)
	}
}

func TestOIDCInitialListenRefreshDropsStaleProvidersOnPartialFailure(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	name := "broken-" + uuid.NewString()
	key := "oidc_provider_" + name + "_config"
	sealed, err := SealOIDCClientSecret("secret", testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO system_config(key,value,encrypted)
		VALUES(
			$1,
			jsonb_build_object(
				'name',$2::text,'enabled',true,'provider_url','http://invalid.example',
				'client_id','client','client_secret',$3::text,
				'redirect_url','https://setjoin.example/callback'
			),
			true
		)`, key, name, sealed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM system_config WHERE key=$1`, key)
	})

	p := &OIDCRPProvider{
		pool:      pool,
		ctx:       t.Context(),
		masterKey: testMasterKey,
		providers: map[string]*oidcProviderConfig{
			"revoked-stale": {name: "revoked-stale"},
		},
	}
	listener := &recordingConfigListener{}
	err = p.ListenForChanges(t.Context(), listener, slog.Default())
	if err == nil {
		t.Fatal("malformed provider did not fail the initial authoritative refresh")
	}
	assertDurableConfigRegistration(t, listener)
	if got := p.Provider("revoked-stale"); got != nil {
		t.Fatalf("stale provider survived initial refresh failure: %#v", got)
	}
	if got := p.Provider(name); got != nil {
		t.Fatalf("invalid provider was admitted: %#v", got)
	}
	listener.handler(&pgconn.Notification{Payload: `{"key":"auth_methods"}`})
}

func TestOIDCProviderDiscoveryFailureUsesGuardedRPConstruction(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	name := "unreachable-" + uuid.NewString()
	key := "oidc_provider_" + name + "_config"
	sealed, err := SealOIDCClientSecret("secret", testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO system_config(key,value,encrypted)
		VALUES(
			$1,
			jsonb_build_object(
				'name',$2::text,'enabled',true,'provider_url','https://192.0.2.1',
				'client_id','client','client_secret',$3::text,
				'redirect_url','https://setjoin.example/callback'
			),
			true
		)`, key, name, sealed); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key=$1`, key)
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	provider, err := NewOIDCRPProvider(ctx, pool, testMasterKey)
	if err == nil {
		t.Fatal("unreachable OIDC discovery unexpectedly succeeded")
	}
	if provider == nil || provider.Provider(name) != nil {
		t.Fatalf("failed discovery did not install a fail-closed provider snapshot: %#v", provider)
	}
}

func TestConfigListenersReloadHealthyEmptySnapshotsOnNotification(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(t.Context(),
		`DELETE FROM system_config WHERE key LIKE 'oidc_provider_broken-%_config'`); err != nil {
		t.Fatal(err)
	}

	oidc := &OIDCRPProvider{pool: pool, ctx: t.Context()}
	oidcListener := &recordingConfigListener{}
	if err := oidc.ListenForChanges(t.Context(), oidcListener, slog.Default()); err != nil {
		t.Fatalf("OIDC initial load: %v", err)
	}
	oidcListener.handler(&pgconn.Notification{Payload: `{"key":"oidc_rp"}`})

	saml := &SAMLSPRegistry{pool: pool, ctx: t.Context()}
	samlListener := &recordingConfigListener{}
	if err := saml.ListenForChanges(t.Context(), samlListener, slog.Default()); err != nil {
		t.Fatalf("SAML initial load: %v", err)
	}
	samlListener.handler(&pgconn.Notification{Payload: `{"key":"saml_sp"}`})
	if len(oidc.Providers()) != 0 || len(saml.Entries()) != 0 {
		t.Fatalf("empty snapshots were not retained: oidc=%d saml=%d",
			len(oidc.Providers()), len(saml.Entries()))
	}
}
