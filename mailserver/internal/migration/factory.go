package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"setjoin.com/shared/ssrf"
)

// ConnectorFactory builds a Connector for one migration source type. Each
// implementation owns its own config-merge (global defaults ⊕ per-job
// overrides), decrypt, and auth strategy, so the orchestrator's createConnector
// is a pure dispatch over sourceType — no per-connector special-casing.
//
// configEnc is the job's encrypted source config (migration_jobs.source_config_enc).
// useGlobalAuth selects whether to overlay the per-job config on the shared
// system_config defaults for this source.
type ConnectorFactory interface {
	Create(ctx context.Context, jobID int64, configEnc []byte, useGlobalAuth bool) (SourceSession, error)
}

// resolveConfig is the shared merge round-trip every factory reuses: it decrypts
// the job config, and when useGlobalAuth is set, overlays it on the global
// defaults via the source-specific merge, then re-encrypts so the caller can
// decrypt into its concrete connector config exactly as before. When global auth
// is not used it returns the raw job config bytes unchanged.
//
// merge is supplied by the factory and owns the source-specific global-config
// read + override semantics.
func (o *Orchestrator) resolveConfig(
	configEnc []byte,
	useGlobalAuth bool,
	merge func(jobCfg *MigrationJobConfig) (interface{}, error),
) ([]byte, error) {
	var jobCfg MigrationJobConfig
	if err := DecryptConfigAny(configEnc, o.encryptionKey, &jobCfg); err != nil {
		return nil, fmt.Errorf("decrypt job config: %w", err)
	}

	if !useGlobalAuth {
		// No global merge: the factory decrypts the resolved bytes straight
		// into its BARE connector config, but producers (user.StartMigration,
		// AdminAPI.Start) store the MigrationJobConfig wrapper — so unwrap the
		// inner config here. A legacy bare-config blob (no wrapper fields)
		// passes through unchanged.
		if inner := jobCfg.innerConfig(); inner != nil {
			reEnc, err := EncryptConfigAny(inner, o.encryptionKey)
			if err != nil {
				return nil, fmt.Errorf("re-encrypt job config: %w", err)
			}
			return reEnc, nil
		}
		return configEnc, nil
	}

	merged, err := merge(&jobCfg)
	if err != nil {
		return nil, fmt.Errorf("merge global config: %w", err)
	}

	reEnc, err := EncryptConfigAny(merged, o.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("re-encrypt merged config: %w", err)
	}
	return reEnc, nil
}

// innerConfig returns the wrapped per-source config, or nil when the blob was
// not the MigrationJobConfig wrapper (legacy bare configs decode to all-nil).
func (c *MigrationJobConfig) innerConfig() interface{} {
	switch {
	case c.IMAP != nil:
		return c.IMAP
	case c.EWS != nil:
		return c.EWS
	case c.M365 != nil:
		return c.M365
	}
	return nil
}

// imapFactory builds an IMAP connector. Global merge reads imap.defaults
// (plaintext) and overlays host/port/tls/credentials.
type imapFactory struct{ o *Orchestrator }

func (f imapFactory) Create(_ context.Context, _ int64, configEnc []byte, useGlobalAuth bool) (SourceSession, error) {
	resolved, err := f.o.resolveConfig(configEnc, useGlobalAuth, f.merge)
	if err != nil {
		return nil, err
	}
	var imapCfg IMAPConfig
	if err := DecryptConfigAny(resolved, f.o.encryptionKey, &imapCfg); err != nil {
		return nil, fmt.Errorf("decrypt imap config: %w", err)
	}
	if !useGlobalAuth {
		// Bare-path containment: the private-network exception policy is
		// administrator-owned. Every entry point (start, resume, dial) rebuilds
		// the connector here, so a persisted job whose config carries
		// caller-manufactured PrivateHosts/PrivateCIDRs fails closed at
		// reconstruction instead of dialing with a user-owned allowlist.
		if err := RejectUserSuppliedPrivatePolicy(imapCfg.PrivateHosts, imapCfg.PrivateCIDRs); err != nil {
			return nil, err
		}
	}
	return NewIMAPConnector(imapCfg), nil
}

func (f imapFactory) merge(jobCfg *MigrationJobConfig) (interface{}, error) {
	var value json.RawMessage
	err := f.o.pool.QueryRow(f.o.ctx,
		`SELECT value FROM system_config WHERE key = 'imap.defaults'`,
	).Scan(&value)
	if err != nil {
		return nil, fmt.Errorf("no global IMAP config in system_config: %w", err)
	}
	var global GlobalIMAPConfig
	if err := json.Unmarshal(value, &global); err != nil {
		return nil, fmt.Errorf("parse global IMAP config: %w", err)
	}

	cfg := IMAPConfig{
		Host:         global.Host,
		Port:         global.Port,
		TLSMode:      global.TLSMode,
		PrivateHosts: append([]string(nil), global.PrivateHosts...),
		PrivateCIDRs: append([]string(nil), global.PrivateCIDRs...),
	}
	if jobCfg.IMAP != nil {
		if jobCfg.IMAP.Host != "" {
			cfg.Host = jobCfg.IMAP.Host
		}
		if jobCfg.IMAP.Port != 0 {
			cfg.Port = jobCfg.IMAP.Port
		}
		if jobCfg.IMAP.TLSMode != "" {
			cfg.TLSMode = jobCfg.IMAP.TLSMode
		}
		// Per-user jobs may choose an approved public origin, but may not
		// manufacture private-network exceptions. Those come only from the
		// administrator-owned global source profile above.
		if jobCfg.IMAP.Credentials.Username != "" {
			cfg.Credentials = jobCfg.IMAP.Credentials
		}
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("IMAP host is required")
	}
	return &cfg, nil
}

// ewsFactory builds an EWS connector. Global merge reads the encrypted ews.global
// wrapper, decrypts it with the system key, and overlays per-user/impersonation
// overrides gated by the global authMode.
type ewsFactory struct{ o *Orchestrator }

func (f ewsFactory) Create(_ context.Context, _ int64, configEnc []byte, useGlobalAuth bool) (SourceSession, error) {
	resolved, err := f.o.resolveConfig(configEnc, useGlobalAuth, f.merge)
	if err != nil {
		return nil, err
	}
	var ewsCfg EWSConfig
	if err := DecryptConfigAny(resolved, f.o.encryptionKey, &ewsCfg); err != nil {
		return nil, fmt.Errorf("decrypt ews config: %w", err)
	}
	if !useGlobalAuth {
		// Bare-path containment: same administrator-ownership rule as the IMAP
		// factory — a per-job private-network exception is rejected at
		// reconstruction, before any policy is compiled for the connector.
		if err := RejectUserSuppliedPrivatePolicy(ewsCfg.PrivateHosts, ewsCfg.PrivateCIDRs); err != nil {
			return nil, err
		}
	}
	// Scheme-only guard on the admin-set source URL (rejects file/ftp/gopher/…);
	// internal IPs are intentionally allowed — on-prem Exchange is an
	// admin-trusted, internal-allowed migration source. See validateEWSServerURL.
	policy, err := ssrf.CompilePrivatePolicy(ewsCfg.PrivateHosts, ewsCfg.PrivateCIDRs)
	if err != nil {
		return nil, fmt.Errorf("invalid EWS source policy: %w", err)
	}
	if err := validateEWSServerURL(ewsCfg.ServerURL, policy); err != nil {
		return nil, fmt.Errorf("invalid EWS server URL: %w", err)
	}
	return newEWSConnector(ewsCfg), nil
}

// newEWSConnector is the ewsFactory connector-construction seam. Production
// resolves to NewEWSConnector; tests substitute a credential-capturing fake to
// assert the exact auth material that reaches the connector boundary.
var newEWSConnector = func(cfg EWSConfig) SourceSession {
	return NewEWSConnector(cfg)
}

func (f ewsFactory) merge(jobCfg *MigrationJobConfig) (interface{}, error) {
	var value json.RawMessage
	var encrypted bool
	err := f.o.pool.QueryRow(f.o.ctx,
		`SELECT value, encrypted FROM system_config WHERE key = 'ews.global'`,
	).Scan(&value, &encrypted)
	if err != nil {
		return nil, fmt.Errorf("no global EWS config: %w", err)
	}
	if !encrypted {
		return nil, fmt.Errorf("EWS global config is not encrypted")
	}

	var wrapper struct {
		Enc string `json:"_enc"`
	}
	if err := json.Unmarshal(value, &wrapper); err != nil {
		return nil, fmt.Errorf("parse EWS config wrapper: %w", err)
	}
	encBytes, err := base64.StdEncoding.DecodeString(wrapper.Enc)
	if err != nil {
		return nil, fmt.Errorf("decode EWS config: %w", err)
	}

	systemKey, _ := DeriveKey(f.o.encryptionRoot, "system")
	var global GlobalEWSConfig
	if err := DecryptConfigAny(encBytes, systemKey, &global); err != nil {
		return nil, fmt.Errorf("decrypt global EWS config: %w", err)
	}

	// The global profile donates the ADMIN-owned network policy to every job:
	// the immutable approved origin, the TLS floor (InsecureSkipVerify stays an
	// explicit admin opt-in) and the private-network exceptions. The global
	// username/password seed the base so the ADMIN path (which authenticates
	// with the shared service account) is unchanged; the SelfService branch
	// below overwrites them with the caller's own credentials before the
	// connector is built.
	cfg := EWSConfig{
		ServerURL:          global.ServerURL,
		Username:           global.Username,
		Password:           global.Password,
		InsecureSkipVerify: global.InsecureSkipVerify,
		PrivateHosts:       append([]string(nil), global.PrivateHosts...),
		PrivateCIDRs:       append([]string(nil), global.PrivateCIDRs...),
	}
	// Credential provenance gate: global credentials are inherited ONLY from a
	// job whose config carries an EXPLICIT SelfService value. A nil pointer
	// means the encrypted config predates the marker, so the route that
	// created it — and therefore whose credentials may apply — is unknown.
	// Guessing here previously let resumed legacy jobs fall into the admin
	// branch below and silently RETAIN the shared service-account
	// credentials, so we fail closed instead: no merge, no connector.
	if jobCfg.SelfService == nil {
		return nil, fmt.Errorf("legacy migration job predates credential provenance; re-create the job")
	}
	if *jobCfg.SelfService {
		// Self-service credential boundary: the connector authenticates as
		// the CALLER, never as the shared service account. The global
		// username/password are overwritten unconditionally and any crafted
		// impersonation principal is dropped — inheriting the shared
		// credentials with no impersonation selector would read the SHARED
		// account's own mailbox into the caller's mailbox. Ingress
		// (user.StartMigration) requires complete caller credentials and
		// rejects impersonateAs; this fail-closed backstop covers legacy job
		// rows and any future producer that forgets the marker.
		if jobCfg.EWS == nil || jobCfg.EWS.Username == "" || jobCfg.EWS.Password == "" {
			return nil, fmt.Errorf("self-service EWS migration requires the caller's username and password")
		}
		cfg.Username = jobCfg.EWS.Username
		cfg.Password = jobCfg.EWS.Password
		cfg.ImpersonateAs = ""
	} else if jobCfg.EWS != nil {
		// Admin path (AdminAPI.Start, unchanged): the shared service account's
		// credentials stay on their immutable approved origin. A per-job
		// override must never redirect them to another host. Impersonation
		// (acting AS another mailbox with the service account) is emitted only
		// when the administrator explicitly opted the global profile into
		// impersonation mode; any other AuthMode — including the per_user
		// default — drops the per-job selector.
		if global.AuthMode == EWSAuthModePerUser && jobCfg.EWS.Username != "" {
			cfg.Username = jobCfg.EWS.Username
			cfg.Password = jobCfg.EWS.Password
		}
		if global.AuthMode == EWSAuthModeImpersonation && jobCfg.EWS.ImpersonateAs != "" {
			cfg.ImpersonateAs = jobCfg.EWS.ImpersonateAs
		}
	}
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("EWS server URL is required")
	}
	return &cfg, nil
}

// m365Factory builds an M365 Graph connector. Global merge reads the encrypted
// m365.app wrapper, decrypts it with the system key, and overlays per-job
// client/tenant overrides.
type m365Factory struct{ o *Orchestrator }

func (f m365Factory) Create(ctx context.Context, _ int64, configEnc []byte, useGlobalAuth bool) (SourceSession, error) {
	resolved, err := f.o.resolveConfig(configEnc, useGlobalAuth, f.merge)
	if err != nil {
		return nil, err
	}
	var m365Cfg MigrationM365Config
	if err := DecryptConfigAny(resolved, f.o.encryptionKey, &m365Cfg); err != nil {
		return nil, fmt.Errorf("decrypt m365 config: %w", err)
	}
	return NewM365Connector(ctx, m365Cfg)
}

func (f m365Factory) merge(jobCfg *MigrationJobConfig) (interface{}, error) {
	var value json.RawMessage
	var encrypted bool
	err := f.o.pool.QueryRow(f.o.ctx,
		`SELECT value, encrypted FROM system_config WHERE key = 'm365.app'`,
	).Scan(&value, &encrypted)
	if err != nil {
		return nil, fmt.Errorf("no global M365 config: %w", err)
	}
	if !encrypted {
		return nil, fmt.Errorf("M365 global config is not encrypted")
	}

	var wrapper struct {
		Enc string `json:"_enc"`
	}
	if err := json.Unmarshal(value, &wrapper); err != nil {
		return nil, fmt.Errorf("parse M365 config wrapper: %w", err)
	}
	encBytes, err := base64.StdEncoding.DecodeString(wrapper.Enc)
	if err != nil {
		return nil, fmt.Errorf("decode M365 config: %w", err)
	}

	systemKey, _ := DeriveKey(f.o.encryptionRoot, "system")
	var cfg MigrationM365Config
	if err := DecryptConfigAny(encBytes, systemKey, &cfg); err != nil {
		return nil, fmt.Errorf("decrypt global M365 config: %w", err)
	}
	if jobCfg.M365 != nil && jobCfg.M365.ClientID != "" {
		cfg.ClientID = jobCfg.M365.ClientID
	}
	if jobCfg.M365 != nil && jobCfg.M365.ClientSecret != "" {
		cfg.ClientSecret = jobCfg.M365.ClientSecret
	}
	if jobCfg.M365 != nil && jobCfg.M365.TenantID != "" {
		cfg.TenantID = jobCfg.M365.TenantID
	}
	if jobCfg.M365 != nil {
		// Source selection is job authority, never a global credential default.
		// Always overlay it even when all OAuth material remains global.
		cfg.SourceEmail = jobCfg.M365.SourceEmail
		cfg.SourceUserID = jobCfg.M365.SourceUserID
	}
	return &cfg, nil
}

// connectorFactories is the source-type → factory dispatch table. The default
// (IMAP) is applied by createConnector for any source type not listed here,
// preserving the prior switch-default behavior.
func (o *Orchestrator) connectorFactories() map[string]ConnectorFactory {
	return map[string]ConnectorFactory{
		"imap": imapFactory{o},
		"ews":  ewsFactory{o},
		"m365": m365Factory{o},
	}
}
