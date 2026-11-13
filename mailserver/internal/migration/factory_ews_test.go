package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// seedEWSGlobalConfig replaces the ews.global system_config row with an
// encrypted profile and restores the prior row (or its absence) on cleanup,
// mirroring the save/restore pattern in factory_security_test.go.
func seedEWSGlobalConfig(t *testing.T, pool *pgxpool.Pool, o *Orchestrator, global GlobalEWSConfig) {
	t.Helper()
	ctx := context.Background()

	var oldValue json.RawMessage
	var oldEncrypted bool
	var had bool
	if err := pool.QueryRow(ctx, `SELECT value, encrypted FROM system_config WHERE key='ews.global'`).Scan(&oldValue, &oldEncrypted); err == nil {
		had = true
	}
	t.Cleanup(func() {
		if had {
			_, _ = pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=EXCLUDED.encrypted`, oldValue, oldEncrypted)
		} else {
			_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key='ews.global'`)
		}
	})

	systemKey, err := DeriveKey(o.encryptionRoot, "system")
	if err != nil {
		t.Fatal(err)
	}
	encryptedGlobal, err := EncryptConfigAny(global, systemKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := json.Marshal(map[string]string{"_enc": base64.StdEncoding.EncodeToString(encryptedGlobal)})
	if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value,encrypted) VALUES('ews.global',$1,true) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, encrypted=true`, wrapper); err != nil {
		t.Fatal(err)
	}
}

// TestEWSFactoryImpersonationIsAdminOptIn pins the impersonation gate
// (ewsFactory.merge): the per-job ExchangeImpersonation principal is copied
// into the effective connector ONLY when the administrator explicitly opted
// the global profile into impersonation mode. Every other AuthMode — the
// per_user default and the legacy empty value — drops the selector, so the
// connector never emits an impersonation header for it. The admin path
// (AdminAPI.Start stores ImpersonateAs=SourceEmail) keeps working: in
// impersonation mode the selector survives the merge and
// EWSConnector.impersonationHeader emits it as ConnectingSID/PrimarySmtpAddress.
func TestEWSFactoryImpersonationIsAdminOptIn(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "factory-ews-root", testsupport.TestLogger(), ctx, nil)

	const adminSourceEmail = "source@corp.example"
	globalBase := GlobalEWSConfig{
		ServerURL: "https://exchange.internal/EWS/Exchange.asmx",
		Username:  "svc-migration",
		Password:  "svc-secret",
	}

	cases := []struct {
		name              string
		authMode          string
		job               MigrationEWSConfig
		wantImpersonateAs string
	}{
		{
			name:              "impersonation mode (admin path) keeps the per-job principal",
			authMode:          EWSAuthModeImpersonation,
			job:               MigrationEWSConfig{ServerURL: globalBase.ServerURL, ImpersonateAs: adminSourceEmail},
			wantImpersonateAs: adminSourceEmail,
		},
		{
			name:     "per_user mode drops the per-job principal",
			authMode: EWSAuthModePerUser,
			job:      MigrationEWSConfig{ServerURL: globalBase.ServerURL, ImpersonateAs: adminSourceEmail},
		},
		{
			name:     "legacy empty auth mode never grants impersonation",
			authMode: "",
			job:      MigrationEWSConfig{ServerURL: globalBase.ServerURL, ImpersonateAs: adminSourceEmail},
		},
		{
			name:     "impersonation mode without a selector stays on the service account",
			authMode: EWSAuthModeImpersonation,
			job:      MigrationEWSConfig{ServerURL: globalBase.ServerURL},
		},
		{
			name:     "per_user mode overlays caller credentials without a principal",
			authMode: EWSAuthModePerUser,
			job:      MigrationEWSConfig{ServerURL: globalBase.ServerURL, Username: "alice@corp.example", Password: "alice-pw", ImpersonateAs: adminSourceEmail},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global := globalBase
			global.AuthMode = tc.authMode
			seedEWSGlobalConfig(t, pool, o, global)

			merged, err := (ewsFactory{o}).merge(&MigrationJobConfig{SourceType: "ews", SelfService: CredentialProvenance(false), EWS: &tc.job})
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			cfg, ok := merged.(*EWSConfig)
			if !ok {
				t.Fatalf("merge type = %T, want *EWSConfig", merged)
			}
			if cfg.ImpersonateAs != tc.wantImpersonateAs {
				t.Fatalf("ImpersonateAs = %q, want %q (authMode=%q)", cfg.ImpersonateAs, tc.wantImpersonateAs, tc.authMode)
			}

			// Sink assertion: the header is emitted exactly when the merged
			// connector carries a principal (ews_client.go impersonationHeader).
			conn := NewEWSConnector(*cfg)
			header := conn.impersonationHeader()
			if tc.wantImpersonateAs == "" {
				if header != "" {
					t.Fatalf("impersonation header emitted without a principal: %q", header)
				}
				if conn.requestHeaders() != `<t:RequestServerVersion Version="Exchange2016"/>` {
					t.Fatalf("request headers must not carry ExchangeImpersonation: %q", conn.requestHeaders())
				}
			} else {
				want := `<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>` + tc.wantImpersonateAs + `</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>`
				if !strings.Contains(header, want) {
					t.Fatalf("impersonation header = %q, want it to contain %q", header, want)
				}
			}

			// per_user credential overlay stays intact (never replaced by the
			// impersonation path).
			if tc.authMode == EWSAuthModePerUser && tc.job.Username != "" {
				if cfg.Username != tc.job.Username || cfg.Password != tc.job.Password {
					t.Fatalf("per_user overlay lost: username=%q password set=%v", cfg.Username, cfg.Password != "")
				}
			}
		})
	}
}

// TestEWSFactoryImpersonationVsSourceIdentityFlag names the
// feature.mail_migration_source_identity toggle explicitly: that flag gates
// source-identity binding/resume (orchestrator.go flag selection), NOT the
// impersonation header emission — header emission is qualified solely by the
// global AuthMode at the ewsFactory merge gate. The matrix pins both flag
// states so a future flag rewiring of the impersonation gate fails loudly.
func TestEWSFactoryImpersonationVsSourceIdentityFlag(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "factory-ews-flag-root", testsupport.TestLogger(), ctx, nil)

	const selector = "source@corp.example"
	for _, flagOn := range []bool{true, false} {
		name := "flag_OFF"
		if flagOn {
			name = "flag_ON"
		}
		t.Run(name, func(t *testing.T) {
			testsupport.SetFeatureToggleForTest(t, pool, "feature.mail_migration_source_identity", flagOn)

			// per_user (the new empty-save default): principal never emitted,
			// regardless of flag state.
			seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
				ServerURL: "https://exchange.internal/EWS/Exchange.asmx",
				Username:  "svc-migration",
				Password:  "svc-secret",
				AuthMode:  EWSAuthModePerUser,
			})
			job := MigrationEWSConfig{ServerURL: "https://exchange.internal/EWS/Exchange.asmx", ImpersonateAs: selector}
			merged, err := (ewsFactory{o}).merge(&MigrationJobConfig{SourceType: "ews", SelfService: CredentialProvenance(false), EWS: &job})
			if err != nil {
				t.Fatalf("merge(per_user): %v", err)
			}
			if cfg := merged.(*EWSConfig); cfg.ImpersonateAs != "" {
				t.Fatalf("flag %s: per_user mode emitted impersonation principal %q", name, cfg.ImpersonateAs)
			}

			// Explicit admin impersonation opt-in: principal still emitted,
			// regardless of flag state.
			seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
				ServerURL: "https://exchange.internal/EWS/Exchange.asmx",
				Username:  "svc-migration",
				Password:  "svc-secret",
				AuthMode:  EWSAuthModeImpersonation,
			})
			merged, err = (ewsFactory{o}).merge(&MigrationJobConfig{SourceType: "ews", SelfService: CredentialProvenance(false), EWS: &job})
			if err != nil {
				t.Fatalf("merge(impersonation): %v", err)
			}
			if cfg := merged.(*EWSConfig); cfg.ImpersonateAs != selector {
				t.Fatalf("flag %s: impersonation mode lost admin principal: got %q, want %q", name, cfg.ImpersonateAs, selector)
			}
		})
	}
}

// capturedEWSConfigs records every EWSConfig that reached the connector
// constructor while the newEWSConnector seam is overridden.
var capturedEWSConfigs []EWSConfig

// captureEWSConnector redirects the ewsFactory connector seam to a
// credential-capturing fake: it records the exact EWSConfig handed to the
// constructor AND returns the real connector, so the emitted
// ExchangeImpersonation header can be asserted as the sink. The override is
// restored on cleanup.
func captureEWSConnector(t *testing.T) {
	t.Helper()
	orig := newEWSConnector
	newEWSConnector = func(cfg EWSConfig) SourceSession {
		capturedEWSConfigs = append(capturedEWSConfigs, cfg)
		return NewEWSConnector(cfg)
	}
	t.Cleanup(func() {
		newEWSConnector = orig
		capturedEWSConfigs = nil
	})
}

// TestEWSFactorySelfServiceCredentialsAtConnectorBoundary pins the self-service
// credential boundary at the CONNECTOR boundary (the constructor seam), across
// both global AuthModes and both feature.mail_migration_source_identity flag
// states (the flag gates source-identity binding, never credentials):
//
//   - A self-service job (MigrationJobConfig.SelfService, the marker
//     user.StartMigration stores) is built with the CALLER'S username/password
//     ONLY. The shared service account's global username/password is never
//     inherited — inheriting it with no impersonation selector would read the
//     SHARED account's own mailbox into the caller's mailbox — and any crafted
//     per-job impersonation principal is dropped.
//   - The admin-owned network policy layering stays: the global profile still
//     donates the immutable origin, the TLS floor (InsecureSkipVerify) and the
//     private-network exceptions to the self-service connector.
//   - A self-service job without complete caller credentials is refused
//     fail-closed before the constructor runs (no shared credential ever
//     reaches the connector boundary).
//   - The admin path is unchanged: impersonation mode carries the global
//     service-account credentials plus the per-job principal; per_user mode
//     overlays the target's own credentials.
func TestEWSFactorySelfServiceCredentialsAtConnectorBoundary(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "factory-ews-selfsvc-root", testsupport.TestLogger(), ctx, nil)
	captureEWSConnector(t)

	const (
		globalURL   = "https://exchange.internal/EWS/Exchange.asmx"
		svcUser     = "svc-migration"
		svcPass     = "svc-secret"
		callerUser  = "alice@corp.example"
		callerPass  = "alice-pw"
		adminSource = "source@corp.example"
		targetUser  = "target@corp.example"
		targetPass  = "target-pw"
	)
	globalProfile := func(authMode string) GlobalEWSConfig {
		return GlobalEWSConfig{
			ServerURL:          globalURL,
			Username:           svcUser,
			Password:           svcPass,
			AuthMode:           authMode,
			InsecureSkipVerify: true, // explicit admin TLS-floor donation
			PrivateHosts:       []string{"exchange.internal"},
			PrivateCIDRs:       []string{"10.0.0.0/8"},
		}
	}
	create := func(t *testing.T, job MigrationJobConfig) (SourceSession, error) {
		t.Helper()
		capturedEWSConfigs = nil
		enc, err := EncryptConfigAny(job, o.encryptionKey)
		if err != nil {
			t.Fatalf("encrypt job config: %v", err)
		}
		return (ewsFactory{o}).Create(ctx, 1, enc, job.UseGlobalAuth)
	}
	lastCaptured := func(t *testing.T) EWSConfig {
		t.Helper()
		if len(capturedEWSConfigs) != 1 {
			t.Fatalf("connector constructor invoked %d times, want exactly 1", len(capturedEWSConfigs))
		}
		return capturedEWSConfigs[0]
	}

	for _, flagOn := range []bool{false, true} {
		flagName := "flag_OFF"
		if flagOn {
			flagName = "flag_ON"
		}
		for _, authMode := range []string{EWSAuthModePerUser, EWSAuthModeImpersonation} {
			t.Run(flagName+"/"+authMode, func(t *testing.T) {
				testsupport.SetFeatureToggleForTest(t, pool, "feature.mail_migration_source_identity", flagOn)
				seedEWSGlobalConfig(t, pool, o, globalProfile(authMode))

				// 1+2+3+5. Self-service with complete caller credentials: the
				// connector gets caller creds only, no principal, full policy.
				job := MigrationJobConfig{
					SourceType:    "ews",
					UseGlobalAuth: true,
					SelfService:   CredentialProvenance(true),
					EWS: &MigrationEWSConfig{
						ServerURL:     globalURL,
						Username:      callerUser,
						Password:      callerPass,
						ImpersonateAs: adminSource, // crafted selector must be dropped
					},
				}
				sess, err := create(t, job)
				if err != nil {
					t.Fatalf("self-service create: %v", err)
				}
				cfg := lastCaptured(t)
				if cfg.Username != callerUser || cfg.Password != callerPass {
					t.Fatalf("connector auth = %q/%v, want caller creds %q/%v (no shared-cred inheritance)",
						cfg.Username, cfg.Password != "", callerUser, true)
				}
				if cfg.Username == svcUser || cfg.Password == svcPass {
					t.Fatalf("shared service-account credentials reached the connector boundary")
				}
				if cfg.ImpersonateAs != "" {
					t.Fatalf("self-service connector carries an impersonation principal: %q", cfg.ImpersonateAs)
				}
				// Policy layering survives the credential strip.
				if cfg.ServerURL != globalURL || !cfg.InsecureSkipVerify ||
					len(cfg.PrivateHosts) != 1 || len(cfg.PrivateCIDRs) != 1 {
					t.Fatalf("admin network policy lost on self-service path: %+v", cfg)
				}
				// Sink: no ExchangeImpersonation is ever emitted for the caller.
				conn := sess.(*EWSConnector)
				if conn.impersonationHeader() != "" {
					t.Fatalf("impersonation header emitted for self-service job: %q", conn.impersonationHeader())
				}
				if conn.requestHeaders() != `<t:RequestServerVersion Version="Exchange2016"/>` {
					t.Fatalf("self-service request headers must not carry ExchangeImpersonation: %q", conn.requestHeaders())
				}

				// 1 (factory backstop). URL-only self-service job: refused
				// before the constructor — the shared credentials never reach
				// the connector boundary.
				bare := MigrationJobConfig{
					SourceType:    "ews",
					UseGlobalAuth: true,
					SelfService:   CredentialProvenance(true),
					EWS:           &MigrationEWSConfig{ServerURL: globalURL},
				}
				if _, err := create(t, bare); err == nil || !strings.Contains(err.Error(), "requires the caller's username and password") {
					t.Fatalf("URL-only self-service job err = %v, want caller-credential refusal", err)
				}
				if len(capturedEWSConfigs) != 0 {
					t.Fatalf("connector constructed %d times despite missing caller credentials", len(capturedEWSConfigs))
				}

				// 6. Admin path unchanged, per global AuthMode.
				capturedEWSConfigs = nil
				if authMode == EWSAuthModeImpersonation {
					adminJob := MigrationJobConfig{
						SourceType:    "ews",
						UseGlobalAuth: true,
						SelfService:   CredentialProvenance(false),
						EWS:           &MigrationEWSConfig{ServerURL: globalURL, ImpersonateAs: adminSource},
					}
					if _, err := create(t, adminJob); err != nil {
						t.Fatalf("admin impersonation create: %v", err)
					}
					cfg := lastCaptured(t)
					if cfg.Username != svcUser || cfg.Password != svcPass || cfg.ImpersonateAs != adminSource {
						t.Fatalf("admin impersonation path changed: %+v", cfg)
					}
					adminConn := NewEWSConnector(cfg)
					want := `<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>` + adminSource + `</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>`
					if !strings.Contains(adminConn.impersonationHeader(), want) {
						t.Fatalf("admin impersonation header lost: %q", adminConn.impersonationHeader())
					}
				} else {
					adminJob := MigrationJobConfig{
						SourceType:    "ews",
						UseGlobalAuth: true,
						SelfService:   CredentialProvenance(false),
						EWS:           &MigrationEWSConfig{ServerURL: globalURL, Username: targetUser, Password: targetPass},
					}
					if _, err := create(t, adminJob); err != nil {
						t.Fatalf("admin per_user create: %v", err)
					}
					cfg := lastCaptured(t)
					if cfg.Username != targetUser || cfg.Password != targetPass || cfg.ImpersonateAs != "" {
						t.Fatalf("admin per_user overlay changed: %+v", cfg)
					}
				}
			})
		}
	}
}

// legacyEWSJobJSON is the plaintext shape of an encrypted job config created
// BEFORE the SelfService provenance marker existed: no self_service key at
// all, use_global_auth set (the shape that enters the global merge on
// resume), and a per-job EWS section carrying a crafted override/principal
// that a merge must never be allowed to reinterpret.
const legacyEWSJobJSON = `{"source_type":"ews","use_global_auth":true,"ews":{"serverURL":"https://exchange.internal/EWS/Exchange.asmx","username":"attacker-crafted","password":"attacker-crafted","impersonateAs":"source@corp.example"}}`

// TestEWSFactoryLegacyJobWithoutProvenanceFailsClosed pins the Astra r13
// finding: encrypted jobs created before the SelfService provenance marker
// deserialize with SelfService == nil and must FAIL CLOSED at resolve — they
// previously fell into the admin merge branch and RETAINED the shared
// service-account's global credentials. The test resumes the job exactly as
// the orchestrator does (createConnector over the stored ciphertext) against
// an impersonation-mode global profile, i.e. the maximally harmful legacy
// shape, and asserts:
//
//   - the resume fails with the exact re-create-the-job error,
//   - no connector is ever constructed (no global credential, no crafted
//     per-job override, and no principal reaches the connector boundary),
//   - a post-marker admin job with EXPLICIT self_service:false keeps the
//     global-credential + impersonation behavior unchanged,
//   - a post-marker self-service job with EXPLICIT self_service:true keeps
//     the caller-credentials behavior unchanged.
func TestEWSFactoryLegacyJobWithoutProvenanceFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	o := NewOrchestrator(pool, nil, "", "factory-ews-legacy-root", testsupport.TestLogger(), ctx, nil)
	captureEWSConnector(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.mail_migration_source_identity", false)

	const (
		globalURL  = "https://exchange.internal/EWS/Exchange.asmx"
		svcUser    = "svc-migration"
		svcPass    = "svc-secret"
		callerUser = "alice@corp.example"
		callerPass = "alice-pw"
		adminSrc   = "source@corp.example"
	)
	seedEWSGlobalConfig(t, pool, o, GlobalEWSConfig{
		ServerURL: globalURL,
		Username:  svcUser,
		Password:  svcPass,
		AuthMode:  EWSAuthModeImpersonation,
	})

	// encryptRaw seals a legacy-shaped raw JSON blob exactly as producers did
	// before the marker existed (and with an explicit marker for the controls).
	encryptRaw := func(t *testing.T, raw string) []byte {
		t.Helper()
		enc, err := EncryptConfigAny(json.RawMessage(raw), o.encryptionKey)
		if err != nil {
			t.Fatalf("encrypt raw job config: %v", err)
		}
		return enc
	}
	onlyCaptured := func(t *testing.T) EWSConfig {
		t.Helper()
		if len(capturedEWSConfigs) != 1 {
			t.Fatalf("connector constructor invoked %d times, want exactly 1", len(capturedEWSConfigs))
		}
		return capturedEWSConfigs[0]
	}

	// 1. Legacy job (no self_service key): resume must fail closed.
	legacyEnc := encryptRaw(t, legacyEWSJobJSON)
	if _, err := o.createConnector(ctx, 42, "ews", legacyEnc); err == nil {
		t.Fatalf("legacy EWS job without provenance resumed successfully; want fail-closed error")
	} else if !strings.Contains(err.Error(), "legacy migration job predates credential provenance; re-create the job") {
		t.Fatalf("legacy resume err = %v, want exact provenance refusal", err)
	}
	if len(capturedEWSConfigs) != 0 {
		t.Fatalf("connector constructed %d times for a legacy job; global credentials must never reach the boundary", len(capturedEWSConfigs))
	}

	// The merge itself refuses before any branch is taken: the crafted
	// per-job override and principal cannot steer the outcome.
	if _, err := (ewsFactory{o}).merge(&MigrationJobConfig{SourceType: "ews", EWS: &MigrationEWSConfig{ServerURL: globalURL, Username: "attacker-crafted", ImpersonateAs: adminSrc}}); err == nil ||
		!strings.Contains(err.Error(), "legacy migration job predates credential provenance; re-create the job") {
		t.Fatalf("merge without provenance err = %v, want fail-closed refusal", err)
	}

	// 2. Control: explicit self_service:false (AdminAPI.Start provenance) —
	// global credentials + impersonation work exactly as before.
	adminEnc := encryptRaw(t, `{"source_type":"ews","use_global_auth":true,"self_service":false,"ews":{"serverURL":"`+globalURL+`","impersonateAs":"`+adminSrc+`"}}`)
	capturedEWSConfigs = nil
	sess, err := o.createConnector(ctx, 43, "ews", adminEnc)
	if err != nil {
		t.Fatalf("explicit-admin create: %v", err)
	}
	adminCfg := onlyCaptured(t)
	if adminCfg.Username != svcUser || adminCfg.Password != svcPass || adminCfg.ImpersonateAs != adminSrc {
		t.Fatalf("explicit-admin provenance lost global creds/principal: %+v", adminCfg)
	}
	if sess == nil {
		t.Fatalf("explicit-admin resume returned no session")
	}

	// 3. Control: explicit self_service:true — caller-credentials path
	// unchanged; the crafted principal and the shared account stay out.
	selfSvcEnc := encryptRaw(t, `{"source_type":"ews","use_global_auth":true,"self_service":true,"ews":{"serverURL":"`+globalURL+`","username":"`+callerUser+`","password":"`+callerPass+`","impersonateAs":"`+adminSrc+`"}}`)
	capturedEWSConfigs = nil
	if _, err := o.createConnector(ctx, 44, "ews", selfSvcEnc); err != nil {
		t.Fatalf("explicit self-service create: %v", err)
	}
	svcCfg := onlyCaptured(t)
	if svcCfg.Username != callerUser || svcCfg.Password != callerPass || svcCfg.ImpersonateAs != "" {
		t.Fatalf("explicit self-service provenance changed caller-creds path: %+v", svcCfg)
	}
	if svcCfg.Username == svcUser || svcCfg.Password == svcPass {
		t.Fatalf("shared service-account credentials reached the connector boundary")
	}
}
