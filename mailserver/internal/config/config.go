package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/knadh/koanf/v2"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/smime"
	sharedcfg "setjoin.com/shared/config"
	"setjoin.com/shared/cryptokey"
)

// Config holds all gateway configuration loaded from environment variables.
// Deploy by setting these vars in systemd units or environment files.
type Config struct {
	sharedcfg.BaseConfig

	// Crypto reloader — hot-swappable at runtime without restart
	CryptoReloader *CryptoReloader

	// Identity connector secret keyring. The active key defaults to
	// DBEncryptionKey so existing deployments gain encryption without a second
	// mandatory secret. Operators may split/rotate it independently by setting
	// the key, incrementing the version, and supplying old version→key entries
	// in the retiring JSON map for the rollback window.
	IdentityConfigSecretKey          string `koanf:"identity.config_secret_key"`
	IdentityConfigSecretKeyVersion   int    `koanf:"identity.config_secret_key_version"`
	IdentityConfigSecretRetiringKeys string `koanf:"identity.config_secret_retiring_keys"`

	// TLS — let's encrypt autocert (optional — uses TLS-ALPN-01 on :443 or HTTP-01 on :80)
	TLSAutocertDomains     string `koanf:"tls.autocert_domains"`     // comma-separated, e.g. "mail.corp.com,imap.corp.com"
	TLSAutocertChallenge   string `koanf:"tls.autocert_challenge"`   // "tls-alpn-01" (443) or "http-01" (80) or "dns-01" (lego)
	TLSAutocertEmail       string `koanf:"tls.autocert_email"`       // Let's Encrypt notification email
	TLSAutocertCacheDir    string `koanf:"tls.autocert_cache_dir"`   // where to persist certs across restarts
	TLSAutocertKeyFile     string `koanf:"tls.autocert_key_file"`    // optional: pre-generated ECDSA P-256 PEM key; autocert reuses it so TLSA SPKI hash is stable across renewals (no TLSA rotation needed)
	TLSAutocertRollout     bool   `koanf:"tls.autocert_rollout"`     // opt-in: use 2xTLSA rolling rollout instead of key reuse
	DNSSECEnabled          bool   `koanf:"dnssec.enabled"`           // default: true (disabled only via DNSSEC_ENABLED=false env)
	DNSSECUpstream         string `koanf:"dnssec.upstream"`          // env: DNSSEC_UPSTREAM — plaintext-UDP upstream resolver "host:port" (empty = built-in default 1.1.1.1:53)
	DNSSECTrustedResolvers string `koanf:"dnssec.trusted_resolvers"` // env: DNSSEC_TRUSTED_RESOLVERS — comma-separated exact "host:port" allowlist whose DNSSEC AD bit is honored (empty = AD never honored, fail-closed default)

	// HTTP mode: "redirect" (default, :80→:443) or "serve" (content on :80, works with or without proxy)
	HTTPMode string `koanf:"http.mode"`

	// Network mode: auto-detected at startup (china/global/airgap/manual).
	// Set via NETWORK_MODE env var or auto-detected by probing external endpoints.
	NetworkMode string `koanf:"network.mode"`

	// Auth login: "email" (default) or "upn" (AD/LDAP). Domain hint for UPN field.
	LoginField      string `koanf:"auth.login_field"`
	LoginDomainHint string `koanf:"auth.login_domain_hint"`

	// -- ACME DNS-01 challenge (lego) --
	TLSDNSProvider  string `koanf:"tls.dns_provider"`  // "cloudflare", "route53", "rfc2136", etc.
	TLSDNSConfig    string `koanf:"tls.dns_config"`    // JSON blob with provider-specific credentials
	TLSDNSResolvers string `koanf:"tls.dns_resolvers"` // comma-separated DNS resolvers for challenge propagation checks (default: system resolvers)

	// Logging
	LogLevel  string `koanf:"log.level"`  // debug, info, warn, error (default: info)
	LogFormat string `koanf:"log.format"` // text or json (default: text)

	// JWT
	JWTExpiry time.Duration `koanf:"jwt.expiry"` // access token TTL (default 1h); informational only, authserver controls TTL
	JWTIssuer string        `koanf:"jwt.issuer"` // expected iss on inbound tokens; MUST equal authserver's jwt.issuer (same JWT_ISSUER env, default "mailserver")
	// MailAttachmentTokenSecret is the optional gateway-only master secret for
	// five-minute attachment transfer tokens. It defaults to JWTSecret so existing
	// installs need no new mandatory secret. PreviousSecret is verification-only
	// during a bounded rolling rotation.
	MailAttachmentTokenSecret         string `koanf:"jwt.mail_attachment_secret"`
	MailAttachmentTokenPreviousSecret string `koanf:"jwt.mail_attachment_previous_secret"`

	// LinkProtectTokenVersion is the current link-protect token key VERSION
	// (MAILSERVERD-004 dual-key overlap rotation): the derivation-label
	// generation new /link-protect tokens are signed under. Version 1 (the
	// default) renders the historical pre-rotation derivation
	// byte-identically, so existing installs rotate nothing until an operator
	// bumps it. LinkProtectTokenPreviousSecret is the RETIRING master secret,
	// verification-only during the rotation overlap window: tokens already
	// delivered in live mail were signed under it at Version-1 and keep
	// resolving until the window is drained by removing this secret again.
	LinkProtectTokenVersion        int    `koanf:"jwt.link_protect_token_version"`
	LinkProtectTokenPreviousSecret string `koanf:"jwt.link_protect_token_previous_secret"`

	// Auth server — gateway proxies all /auth/* requests here
	AuthServerURL string `koanf:"authserver.url"` // e.g. http://authserver:8443

	// AuthServerJWKSURL is the authserver first-party JWKS endpoint (ADR-005).
	// When set, the gateway verifies ES256 access tokens against the fetched +
	// cached public keys (dual-verify alongside HS256). When empty, ES256 tokens
	// fail to verify (HS256-only mode) — the gateway never mints tokens, so this
	// is purely a verification capability.
	AuthServerJWKSURL string `koanf:"authserver.jwks_url"` // env: AUTHSERVER_JWKS_URL, e.g. http://authserver:8443/.well-known/jwks.json (the authserver first-party JWKS path)

	// Kerberos / SPNEGO (on-prem AD, Windows domain-joined clients)
	KerberosEnabled bool   `koanf:"kerberos.enabled"`
	KerberosKeytab  string `koanf:"kerberos.keytab"` // path to HTTP service keytab, e.g. /etc/mail/mail.keytab
	KerberosRealm   string `koanf:"kerberos.realm"`  // e.g. COMPANY.COM

	// Object Storage (S3-compatible: MinIO, SeaweedFS, AWS S3, etc.)
	S3Endpoint  string `koanf:"s3.endpoint"`   // env: S3_ENDPOINT (fallback: MINIO_ENDPOINT), default "127.0.0.1:9000"
	S3AccessKey string `koanf:"s3.access_key"` // env: S3_ACCESS_KEY (fallback: MINIO_ACCESS_KEY)
	S3SecretKey string `koanf:"s3.secret_key"` // env: S3_SECRET_KEY (fallback: MINIO_SECRET_KEY)
	S3Bucket    string `koanf:"s3.bucket"`     // env: S3_BUCKET (fallback: MINIO_BUCKET), default "mailblobs"
	S3Secure    bool   `koanf:"s3.secure"`     // env: S3_SECURE (fallback: MINIO_SECURE, strict bool parse — invalid fails startup), default false

	// Blob upload reclamation + per-user storage accounting
	// (D-MAILSERVER-INTERNAL-BLOB-002). The grace window is how long an
	// uploaded-but-never-attached blob stays queued before the cleanup sweeper
	// may reclaim it (arming itself is always ON — that is the remediation).
	// The per-user bound rejects an upload that would push its user's charged
	// blob bytes past the limit; <=0 means enforcement OFF (accounting is
	// still recorded). Both are product/ops settings per the finding row.
	BlobReclaimGraceMinutes int   `koanf:"blob.reclaim_grace_minutes"` // env: BLOB_RECLAIM_GRACE_MINUTES, default 1440 (24h)
	BlobUserQuotaBytes      int64 `koanf:"blob.user_quota_bytes"`      // env: BLOB_USER_QUOTA_BYTES, default 0 (enforcement OFF)

	// Backup (S3/OSS/B2 destination for disaster recovery)
	BackupProvider         string `koanf:"backup.provider"`           // env: BACKUP_PROVIDER — "s3" or "oss". Empty = backups disabled.
	BackupEndpoint         string `koanf:"backup.endpoint"`           // env: BACKUP_ENDPOINT
	BackupRegion           string `koanf:"backup.region"`             // env: BACKUP_REGION, default "us-east-1"
	BackupBucket           string `koanf:"backup.bucket"`             // env: BACKUP_BUCKET
	BackupAccessKey        string `koanf:"backup.access_key"`         // env: BACKUP_ACCESS_KEY
	BackupSecretKey        string `koanf:"backup.secret_key"`         // env: BACKUP_SECRET_KEY
	BackupObjectLock       string `koanf:"backup.object_lock"`        // env: BACKUP_OBJECT_LOCK — governance or compliance
	BackupObjectLockDays   int    `koanf:"backup.object_lock_days"`   // env: BACKUP_OBJECT_LOCK_DAYS, default 30
	BackupReplicaProvider  string `koanf:"backup.replica_provider"`   // env: BACKUP_REPLICA_PROVIDER — s3 or oss. Empty = disabled
	BackupReplicaEndpoint  string `koanf:"backup.replica_endpoint"`   // env: BACKUP_REPLICA_ENDPOINT
	BackupReplicaRegion    string `koanf:"backup.replica_region"`     // env: BACKUP_REPLICA_REGION, default us-east-1
	BackupReplicaBucket    string `koanf:"backup.replica_bucket"`     // env: BACKUP_REPLICA_BUCKET
	BackupReplicaAccessKey string `koanf:"backup.replica_access_key"` // env: BACKUP_REPLICA_ACCESS_KEY
	BackupReplicaSecretKey string `koanf:"backup.replica_secret_key"` // env: BACKUP_REPLICA_SECRET_KEY

	// SMTP / IMAP servers
	SMTPInboundAddr       string `koanf:"smtp.inbound_addr"`        // MTA on port 25 (e.g. ":25")
	SMTPSubmissionAddr    string `koanf:"smtp.submission_addr"`     // MSA on port 587 (e.g. ":587")
	IMAPAddr              string `koanf:"imap.addr"`                // IMAP4 on port 143 (e.g. ":143")
	SMTPInboundTLSEnforce bool   `koanf:"smtp.inbound_tls_enforce"` // require STARTTLS before MAIL FROM (default false)
	SMTPInboundTLSAddr    string `koanf:"smtp.inbound_tls_addr"`    // Implicit TLS on port 465 (e.g. ":465"; empty = disabled)
	IMAPTLSAddr           string `koanf:"imap.tls_addr"`            // Implicit TLS on port 993 (e.g. ":993"; empty = disabled)

	// Connection limits per protocol (0 = unlimited)
	SMTPInboundMaxConns    int `koanf:"smtp.inbound_max_conns"`    // default 200
	SMTPSubmissionMaxConns int `koanf:"smtp.submission_max_conns"` // default 200
	IMAPMaxConns           int `koanf:"imap.max_conns"`            // default 500
	LDAPMaxConns           int `koanf:"ldap.max_conns"`            // default 100

	// Per-user connection quotas (0 = unlimited)
	IMAPPerUserMaxConns int `koanf:"imap.per_user_max_conns"` // default 10
	SMTPPerUserMaxConns int `koanf:"smtp.per_user_max_conns"` // default 5

	// ClamAV
	ClamAVAddr string `koanf:"clamav.addr"` // clamd TCP address, e.g. "127.0.0.1:3310"

	// Milter (external filter appliance, e.g. SpamAssassin via Milter protocol)
	MilterAddress string        `koanf:"smtp.milter.address"` // "127.0.0.1:8891" or unix socket path; empty = disabled
	MilterTimeout time.Duration `koanf:"smtp.milter.timeout"` // default 30s

	// Attachment Sandbox (CAPE behavioral analysis)
	SandboxEnabled  bool          `koanf:"sandbox.enabled"`      // env: SANDBOX_ENABLED
	SandboxCAPEURL  string        `koanf:"sandbox.cape_url"`     // env: SANDBOX_CAPE_URL
	SandboxCAPEKey  string        `koanf:"sandbox.cape_api_key"` // env: SANDBOX_CAPE_API_KEY
	SandboxTimeout  time.Duration `koanf:"sandbox.timeout"`      // env: SANDBOX_TIMEOUT, default 120s
	SandboxFailMode string        `koanf:"sandbox.fail_mode"`    // env: SANDBOX_FAIL_MODE, default "open"

	// LDAP GAL
	LDAPAddr   string `koanf:"ldap.addr"`   // ":389" or empty to disable
	LDAPSAddr  string `koanf:"ldaps.addr"`  // ":636" or empty to disable
	LDAPDomain string `koanf:"ldap.domain"` // base domain for DN construction, e.g. "company.com"

	// Webmail static files
	WebsiteDir string `koanf:"website.dir"` // path to webmail build/ directory (empty = API-only mode)

	// Upload limits
	MaxUploadSize int `koanf:"max.upload_size"` // env: MAX_UPLOAD_SIZE, default 52428800 (50 MB)

	// TLS session ticket key rotation interval (0 = use default 86400s / 24h)
	TLSSessionTicketKeyRotateSecs int `koanf:"tls.session_ticket_key_rotate_secs"`

	// AD Sync
	ADSyncEnabled     bool   `koanf:"ad.sync_enabled"`
	ADSyncDomain      string `koanf:"ad.sync_domain"`
	ADSyncBindDN      string `koanf:"ad.sync_bind_dn"`
	ADSyncPasswordEnc string `koanf:"ad.sync_password_enc"` // AES-256-GCM encrypted
	ADSyncIntervalMin int    `koanf:"ad.sync_interval_min"` // minutes between syncs (default 15)
	ADSyncLDAPHost    string `koanf:"ad.sync_ldap_host"`    // override auto-discovered DC

	// LDAP Sync
	LDAPSyncEnabled          bool   `koanf:"ldap.sync_enabled"`
	LDAPSyncHost             string `koanf:"ldap.sync_host"`
	LDAPSyncPort             int    `koanf:"ldap.sync_port"` // default 636
	LDAPSyncTLS              bool   `koanf:"ldap.sync_tls"`  // true = implicit TLS, false = STARTTLS on 389
	LDAPSyncBindDN           string `koanf:"ldap.sync_bind_dn"`
	LDAPSyncPasswordEnc      string `koanf:"ldap.sync_password_enc"`
	LDAPSyncBaseDN           string `koanf:"ldap.sync_base_dn"`
	LDAPSyncSubjectAttribute string `koanf:"ldap.sync_subject_attribute"`
	LDAPSyncIntervalMin      int    `koanf:"ldap.sync_interval_min"` // default 15
	LDAPSyncAutoDepts        bool   `koanf:"ldap.sync_auto_depts"`

	// Safe Browsing API key for link protection (optional)
	SafeBrowsingAPIKey string `koanf:"safebrowsing.api_key"` // env: SAFEBROWSING_API_KEY

	// Internal domains skipped by link-protect URL rewriter (comma-separated)
	InternalDomains string `koanf:"internal.domains"` // env: INTERNAL_DOMAINS, default: hostname

	// Anti-phishing (Stage 2.4)
	ProtectedDomains       string  `koanf:"protected.domains"`        // env: PROTECTED_DOMAINS, comma-separated high-value domains for lookalike detection
	AntiphishNameThreshold float64 `koanf:"antiphish.name_threshold"` // env: ANTIPHISH_NAME_THRESHOLD, default 0.85
	AntiphishUserCacheTTL  string  `koanf:"antiphish.user_cache_ttl"` // env: ANTIPHISH_USER_CACHE_TTL, default 5m

	// Default admin auto-creation on fresh deployment
	DefaultAdminEmail    string `koanf:"default.admin_email"`    // email for auto-created admin user
	DefaultAdminPassword string `koanf:"default.admin_password"` // plaintext password, bcrypt-hashed on first use

	// WORM immutability (S3 Object Lock compliance mode)
	WORMRetentionDays    int    `koanf:"worm.retention_days"`     // WORM_RETENTION_DAYS, default 2557 (7 years for SEC/FINRA/CFTC)
	WORMMode             string `koanf:"worm.mode"`               // WORM_MODE — "governance" or "compliance". Empty = WORM disabled.
	WORMLegalHoldEnabled bool   `koanf:"worm.legal_hold_enabled"` // WORM_LEGAL_HOLD_ENABLED, default true when WORM_MODE is set

	// SCIM Provisioning (RFC 7644)
	SCIMEnabled       bool   `koanf:"scim.enabled"`        // env: SCIM_ENABLED, default false
	SCIMAuthServerURL string `koanf:"scim.authserver_url"` // env: SCIM_AUTHSERVER_URL, default http://localhost:8443

	// Outbound S/MIME content-encryption algorithm (owner decision A5,
	// S/MIME 4.0). "aes-256-gcm" (default) sends CMS AuthEnvelopedData
	// (RFC 5083); "aes-256-cbc" selects the S/MIME 3.2 EnvelopedData fallback.
	// RECEIVE always accepts both regardless of this setting.
	SMIMEEncryptAlgorithm string `koanf:"smime.encrypt_algorithm"` // env: SMIME_ENCRYPT_ALGORITHM, default "aes-256-gcm"

	// -- ML spam classifier --
	MLSpamEnabled     bool `koanf:"ml_spam.enabled"`      // env: ML_SPAM_ENABLED, default: false (opt-in)
	MLSpamMinSamples  int  `koanf:"ml_spam.min_samples"`  // min samples before scoring (default: 50)
	MLSpamFeatureSize int  `koanf:"ml_spam.feature_size"` // hash space (default: 1048576)

	// -- Pillar C1 DM federation (feature.federation, seeded OFF) --
	// All three of FederationLocalDomain/Cert/Key must be set for
	// cmd/mailserverd to construct+start the federation.Service (the
	// meetCfg.Configured()/LIVEKIT_* static-gate precedent — absent env
	// means no Service at all, never a half-started one). Formalizes the
	// admin_federation.go os.Getenv("FEDERATION_LOCAL_DOMAIN") stopgap that
	// handler's own header named as Task 5's job.
	FederationLocalDomain string `koanf:"federation.local_domain"` // env: FEDERATION_LOCAL_DOMAIN, e.g. mail.corp.com
	FederationListenAddr  string `koanf:"federation.listen_addr"`  // env: FEDERATION_LISTEN_ADDR, s2s TLS listen address, default ":7443"
	FederationCert        string `koanf:"federation.cert"`         // env: FEDERATION_CERT, this domain's s2s leaf certificate (PEM path)
	FederationKey         string `koanf:"federation.key"`          // env: FEDERATION_KEY, this domain's s2s leaf private key (PEM path)
}

// LoadWithKoanf loads config from a YAML file (optional) with env var overrides.
// Falls back to env vars only if configPath is empty. All existing env var names
// continue to work — the layered config merges defaults → YAML → env vars.
func LoadWithKoanf(configPath string) (*Config, error) {
	// Load base config first to get Platform, CryptoProfile, and env-based base defaults.
	baseCfg := sharedcfg.LoadBase()
	baseDefaults := baseCfg
	baseDefaults.ListenAddr = listenAddrFallback(baseDefaults.ListenAddr)
	baseDefaults.Hostname = hostnameFallback(baseDefaults.Hostname)
	baseDefaults.DBMaxConns = dbMaxConnsFallback(baseDefaults.DBMaxConns)

	// Build a flat defaults map with all config key paths.
	// These are the lowest-priority defaults — YAML and env vars override them.
	defaults := map[string]interface{}{
		"http.mode":                            "redirect",
		"network.mode":                         "", // auto-detected at startup if empty
		"identity.config_secret_key":           "",
		"identity.config_secret_key_version":   1,
		"identity.config_secret_retiring_keys": "{}",

		// TLS
		"tls.autocert_domains":               "",
		"tls.autocert_challenge":             "tls-alpn-01",
		"tls.autocert_email":                 "",
		"tls.autocert_cache_dir":             "/var/cache/mailserver/autocert",
		"tls.autocert_key_file":              "",
		"tls.autocert_rollout":               false,
		"tls.session_ticket_key_rotate_secs": 86400,
		"dnssec.enabled":                     true,
		"dnssec.upstream":                    "",
		"dnssec.trusted_resolvers":           "",

		// ACME DNS-01
		"tls.dns_provider":  "",
		"tls.dns_config":    "",
		"tls.dns_resolvers": "",

		// Logging
		"log.level":  "info",
		"log.format": "text",

		// JWT
		"jwt.expiry":                             "1h",
		"jwt.issuer":                             "mailserver", // MUST match authserver's jwt.issuer default
		"jwt.mail_attachment_secret":             "",
		"jwt.mail_attachment_previous_secret":    "",
		"jwt.link_protect_token_version":         1,
		"jwt.link_protect_token_previous_secret": "",

		// Auth server
		"authserver.url":      "http://localhost:8443",
		"authserver.jwks_url": "", // empty ⇒ ES256 verification disabled (HS256-only)

		// Kerberos
		"kerberos.enabled": false,
		"kerberos.keytab":  baseCfg.ConfigDir + "/mail.keytab",
		"kerberos.realm":   "",

		// S3 / MinIO
		"s3.endpoint":   "127.0.0.1:9000",
		"s3.access_key": "",
		"s3.secret_key": "",
		"s3.bucket":     "mailblobs",
		"s3.secure":     false,

		// Blob reclamation/accounting (D-MAILSERVER-INTERNAL-BLOB-002)
		"blob.reclaim_grace_minutes": 1440, // 24h grace before an unattached upload may be reclaimed
		"blob.user_quota_bytes":      int64(0),

		// Backup
		"backup.provider":           "",
		"backup.endpoint":           "",
		"backup.region":             "us-east-1",
		"backup.bucket":             "",
		"backup.access_key":         "",
		"backup.secret_key":         "",
		"backup.object_lock":        "",
		"backup.object_lock_days":   30,
		"backup.replica_provider":   "",
		"backup.replica_endpoint":   "",
		"backup.replica_region":     "us-east-1",
		"backup.replica_bucket":     "",
		"backup.replica_access_key": "",
		"backup.replica_secret_key": "",

		// SMTP / IMAP
		"smtp.inbound_addr":         ":25",
		"smtp.submission_addr":      ":587",
		"smtp.inbound_tls_enforce":  false,
		"smtp.inbound_tls_addr":     "",
		"smtp.inbound_max_conns":    200,
		"smtp.submission_max_conns": 200,
		"smtp.per_user_max_conns":   5,
		"imap.addr":                 ":143",
		"imap.tls_addr":             ":993",
		"imap.max_conns":            500,
		"imap.per_user_max_conns":   10,
		"ldap.max_conns":            100,

		// ClamAV
		"clamav.addr": "",

		// Milter
		"smtp.milter.address": "",
		"smtp.milter.timeout": "30s",

		// Sandbox
		"sandbox.enabled":      false,
		"sandbox.cape_url":     "",
		"sandbox.cape_api_key": "",
		"sandbox.timeout":      "120s",
		"sandbox.fail_mode":    "open",

		// LDAP
		"ldap.addr":   "",
		"ldaps.addr":  "",
		"ldap.domain": "localhost",

		// Webmail
		"website.dir":     "",
		"max.upload_size": 52428800,

		// AD Sync
		"ad.sync_enabled":      false,
		"ad.sync_domain":       "",
		"ad.sync_bind_dn":      "",
		"ad.sync_password_enc": "",
		"ad.sync_interval_min": 15,
		"ad.sync_ldap_host":    "",

		// LDAP Sync
		"ldap.sync_enabled":           false,
		"ldap.sync_host":              "",
		"ldap.sync_port":              636,
		"ldap.sync_tls":               true,
		"ldap.sync_bind_dn":           "",
		"ldap.sync_password_enc":      "",
		"ldap.sync_base_dn":           "",
		"ldap.sync_subject_attribute": "",
		"ldap.sync_interval_min":      15,
		"ldap.sync_auto_depts":        false,

		// Safe Browsing
		"safebrowsing.api_key": "",

		// Internal domains
		"internal.domains": "localhost",

		// Anti-phishing
		"protected.domains":        "",
		"antiphish.name_threshold": 0.85,
		"antiphish.user_cache_ttl": "5m",

		// Default admin
		"default.admin_email":    "admin@mail.local",
		"default.admin_password": "",

		// WORM
		"worm.retention_days":     2557,
		"worm.mode":               "",
		"worm.legal_hold_enabled": false,

		// SCIM
		"scim.enabled":        false,
		"scim.authserver_url": "http://localhost:8443",

		// Outbound S/MIME content encryption (A5): default AES-256-GCM
		// AuthEnvelopedData; "aes-256-cbc" is the S/MIME 3.2 fallback.
		"smime.encrypt_algorithm": "aes-256-gcm",

		// ML spam classifier
		"ml_spam.enabled":      false,
		"ml_spam.min_samples":  50,
		"ml_spam.feature_size": 1048576,

		// Pillar C1 DM federation
		"federation.local_domain": "",
		"federation.listen_addr":  ":7443",
		"federation.cert":         "",
		"federation.key":          "",
	}
	sharedcfg.AddBaseDefaults(defaults, baseDefaults)

	k, err := sharedcfg.Load(defaults, sharedcfg.Options{
		FilePath:  configPath,
		EnvPrefix: "",
		Delimiter: ".",
	})
	if err != nil {
		return nil, err
	}

	cfg := &Config{BaseConfig: sharedcfg.DecodeBase(k, baseCfg.ConfigDir)}

	// Mailserver-specific fields.
	cfg.HTTPMode = k.String("http.mode")
	cfg.NetworkMode = k.String("network.mode")
	cfg.MailAttachmentTokenSecret = k.String("jwt.mail_attachment_secret")
	cfg.MailAttachmentTokenPreviousSecret = k.String("jwt.mail_attachment_previous_secret")
	// MAILSERVERD-004 (P2): k.Int silently maps ANY unparsable value ("bogus",
	// "2.5", "1x") to 0, which the version-1 normalization in Validate would
	// then accept — a typo would silently disable previous-key selection in
	// the middle of a rotation and reject every link already delivered in live
	// mail. Parse the SUPPLIED value strictly instead and refuse startup on
	// garbage; an unset key ("" from defaults) stays 0 and normalizes to 1.
	switch raw := strings.TrimSpace(k.String("jwt.link_protect_token_version")); raw {
	case "":
		cfg.LinkProtectTokenVersion = 0
	default:
		v, perr := strconv.Atoi(raw)
		if perr != nil {
			return nil, fmt.Errorf("JWT_LINK_PROTECT_TOKEN_VERSION: invalid integer %q — it selects the link-protect token key generation (a malformed value must not silently fall back to version 1)", raw)
		}
		cfg.LinkProtectTokenVersion = v
	}
	cfg.LinkProtectTokenPreviousSecret = k.String("jwt.link_protect_token_previous_secret")
	cfg.CryptoReloader = NewCryptoReloader(cfg.CryptoProfile)
	cfg.IdentityConfigSecretKey = k.String("identity.config_secret_key")
	cfg.IdentityConfigSecretKeyVersion = k.Int("identity.config_secret_key_version")
	cfg.IdentityConfigSecretRetiringKeys = k.String("identity.config_secret_retiring_keys")

	cfg.TLSAutocertDomains = k.String("tls.autocert_domains")
	cfg.TLSAutocertChallenge = k.String("tls.autocert_challenge")
	cfg.TLSAutocertEmail = k.String("tls.autocert_email")
	cfg.TLSAutocertCacheDir = k.String("tls.autocert_cache_dir")
	cfg.TLSAutocertKeyFile = k.String("tls.autocert_key_file")
	cfg.TLSAutocertRollout = k.Bool("tls.autocert_rollout")
	cfg.DNSSECEnabled = k.Bool("dnssec.enabled")
	cfg.DNSSECUpstream = k.String("dnssec.upstream")
	cfg.DNSSECTrustedResolvers = k.String("dnssec.trusted_resolvers")

	// ACME DNS-01
	cfg.TLSDNSProvider = k.String("tls.dns_provider")
	cfg.TLSDNSConfig = k.String("tls.dns_config")
	cfg.TLSDNSResolvers = k.String("tls.dns_resolvers")

	cfg.LogLevel = k.String("log.level")
	cfg.LogFormat = k.String("log.format")

	cfg.JWTExpiry = koanfDuration(k, "jwt.expiry", 1*time.Hour)
	cfg.JWTIssuer = k.String("jwt.issuer")
	cfg.AuthServerURL = k.String("authserver.url")
	cfg.AuthServerJWKSURL = k.String("authserver.jwks_url")

	cfg.KerberosEnabled = k.Bool("kerberos.enabled")
	cfg.KerberosRealm = k.String("kerberos.realm")
	if v := k.String("kerberos.keytab"); v != "" {
		cfg.KerberosKeytab = v
	}

	// S3 — with MINIO_* fallback for legacy env vars.
	cfg.S3Endpoint = k.String("s3.endpoint")
	if v := os.Getenv("MINIO_ENDPOINT"); cfg.S3Endpoint == "127.0.0.1:9000" && v != "" {
		cfg.S3Endpoint = v
	}
	cfg.S3AccessKey = k.String("s3.access_key")
	if v := os.Getenv("MINIO_ACCESS_KEY"); cfg.S3AccessKey == "" && v != "" {
		cfg.S3AccessKey = v
	}
	cfg.S3SecretKey = k.String("s3.secret_key")
	if v := os.Getenv("MINIO_SECRET_KEY"); cfg.S3SecretKey == "" && v != "" {
		cfg.S3SecretKey = v
	}
	cfg.S3Bucket = k.String("s3.bucket")
	if v := os.Getenv("MINIO_BUCKET"); cfg.S3Bucket == "mailblobs" && v != "" {
		cfg.S3Bucket = v
	}
	cfg.S3Secure = k.Bool("s3.secure")
	// Invalid security-relevant values fail LOUDLY rather than silently
	// disabling object-store TLS (D-MAILSERVER-INTERNAL-CONFIG-002): an
	// unparseable MINIO_SECURE is a startup error naming the key, never a
	// silent fall-through to the insecure default.
	if v := os.Getenv("MINIO_SECURE"); v != "" {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			return nil, fmt.Errorf("MINIO_SECURE: invalid boolean %q (want true/false) — refusing to guess the object-store TLS posture", v)
		}
		cfg.S3Secure = b
	}

	// Blob reclamation/accounting (D-MAILSERVER-INTERNAL-BLOB-002)
	cfg.BlobReclaimGraceMinutes = k.Int("blob.reclaim_grace_minutes")
	cfg.BlobUserQuotaBytes = k.Int64("blob.user_quota_bytes")

	// Backup
	cfg.BackupProvider = k.String("backup.provider")
	cfg.BackupEndpoint = k.String("backup.endpoint")
	cfg.BackupRegion = k.String("backup.region")
	cfg.BackupBucket = k.String("backup.bucket")
	cfg.BackupAccessKey = k.String("backup.access_key")
	cfg.BackupSecretKey = k.String("backup.secret_key")
	cfg.BackupObjectLock = k.String("backup.object_lock")
	cfg.BackupObjectLockDays = k.Int("backup.object_lock_days")
	cfg.BackupReplicaProvider = k.String("backup.replica_provider")
	cfg.BackupReplicaEndpoint = k.String("backup.replica_endpoint")
	cfg.BackupReplicaRegion = k.String("backup.replica_region")
	cfg.BackupReplicaBucket = k.String("backup.replica_bucket")
	cfg.BackupReplicaAccessKey = k.String("backup.replica_access_key")
	cfg.BackupReplicaSecretKey = k.String("backup.replica_secret_key")

	// SMTP / IMAP
	cfg.SMTPInboundAddr = k.String("smtp.inbound_addr")
	cfg.SMTPSubmissionAddr = k.String("smtp.submission_addr")
	cfg.IMAPAddr = k.String("imap.addr")
	cfg.SMTPInboundTLSEnforce = k.Bool("smtp.inbound_tls_enforce")
	cfg.SMTPInboundTLSAddr = k.String("smtp.inbound_tls_addr")
	cfg.IMAPTLSAddr = k.String("imap.tls_addr")
	cfg.SMTPInboundMaxConns = k.Int("smtp.inbound_max_conns")
	cfg.SMTPSubmissionMaxConns = k.Int("smtp.submission_max_conns")
	cfg.IMAPMaxConns = k.Int("imap.max_conns")
	cfg.LDAPMaxConns = k.Int("ldap.max_conns")
	cfg.IMAPPerUserMaxConns = k.Int("imap.per_user_max_conns")
	cfg.SMTPPerUserMaxConns = k.Int("smtp.per_user_max_conns")

	// ClamAV
	cfg.ClamAVAddr = k.String("clamav.addr")

	// Milter
	cfg.MilterAddress = k.String("smtp.milter.address")
	cfg.MilterTimeout = koanfDuration(k, "smtp.milter.timeout", 30*time.Second)

	// Sandbox
	cfg.SandboxEnabled = k.Bool("sandbox.enabled")
	cfg.SandboxCAPEURL = k.String("sandbox.cape_url")
	cfg.SandboxCAPEKey = k.String("sandbox.cape_api_key")
	cfg.SandboxTimeout = koanfDuration(k, "sandbox.timeout", 120*time.Second)
	cfg.SandboxFailMode = k.String("sandbox.fail_mode")

	// LDAP
	cfg.LDAPAddr = k.String("ldap.addr")
	cfg.LDAPSAddr = k.String("ldaps.addr")
	cfg.LDAPDomain = k.String("ldap.domain")

	// Webmail
	cfg.WebsiteDir = k.String("website.dir")
	cfg.MaxUploadSize = k.Int("max.upload_size")
	cfg.TLSSessionTicketKeyRotateSecs = k.Int("tls.session_ticket_key_rotate_secs")

	// AD Sync
	cfg.ADSyncEnabled = k.Bool("ad.sync_enabled")
	cfg.ADSyncDomain = k.String("ad.sync_domain")
	cfg.ADSyncBindDN = k.String("ad.sync_bind_dn")
	cfg.ADSyncPasswordEnc = k.String("ad.sync_password_enc")
	cfg.ADSyncIntervalMin = k.Int("ad.sync_interval_min")
	cfg.ADSyncLDAPHost = k.String("ad.sync_ldap_host")

	// LDAP Sync
	cfg.LDAPSyncEnabled = k.Bool("ldap.sync_enabled")
	cfg.LDAPSyncHost = k.String("ldap.sync_host")
	cfg.LDAPSyncPort = k.Int("ldap.sync_port")
	cfg.LDAPSyncTLS = k.Bool("ldap.sync_tls")
	cfg.LDAPSyncBindDN = k.String("ldap.sync_bind_dn")
	cfg.LDAPSyncPasswordEnc = k.String("ldap.sync_password_enc")
	cfg.LDAPSyncBaseDN = k.String("ldap.sync_base_dn")
	cfg.LDAPSyncSubjectAttribute = k.String("ldap.sync_subject_attribute")
	cfg.LDAPSyncIntervalMin = k.Int("ldap.sync_interval_min")
	cfg.LDAPSyncAutoDepts = k.Bool("ldap.sync_auto_depts")

	// Safe Browsing
	cfg.SafeBrowsingAPIKey = k.String("safebrowsing.api_key")

	// Internal domains — fall back to hostname if INTERNAL_DOMAINS is not explicitly set.
	cfg.InternalDomains = k.String("internal.domains")
	if _, ok := os.LookupEnv("INTERNAL_DOMAINS"); !ok {
		if h := os.Getenv("HOSTNAME"); h != "" && cfg.InternalDomains == "localhost" {
			cfg.InternalDomains = h
		}
	}

	// Anti-phishing
	cfg.ProtectedDomains = k.String("protected.domains")
	cfg.AntiphishNameThreshold = parseFloatDefault(k.String("antiphish.name_threshold"), 0.85)
	cfg.AntiphishUserCacheTTL = k.String("antiphish.user_cache_ttl")

	// Default admin
	cfg.DefaultAdminEmail = k.String("default.admin_email")
	cfg.DefaultAdminPassword = k.String("default.admin_password")

	// WORM
	cfg.WORMRetentionDays = k.Int("worm.retention_days")
	cfg.WORMMode = k.String("worm.mode")
	cfg.WORMLegalHoldEnabled = k.Bool("worm.legal_hold_enabled")
	if _, ok := os.LookupEnv("WORM_LEGAL_HOLD_ENABLED"); !ok {
		cfg.WORMLegalHoldEnabled = cfg.WORMMode != ""
	}

	// SCIM
	cfg.SCIMEnabled = k.Bool("scim.enabled")
	cfg.SMIMEEncryptAlgorithm = k.String("smime.encrypt_algorithm")
	cfg.SCIMAuthServerURL = k.String("scim.authserver_url")

	// ML spam classifier
	cfg.MLSpamEnabled = k.Bool("ml_spam.enabled")
	cfg.MLSpamMinSamples = k.Int("ml_spam.min_samples")
	cfg.MLSpamFeatureSize = k.Int("ml_spam.feature_size")

	// Pillar C1 DM federation
	cfg.FederationLocalDomain = strings.ToLower(strings.TrimSpace(k.String("federation.local_domain")))
	cfg.FederationListenAddr = k.String("federation.listen_addr")
	cfg.FederationCert = k.String("federation.cert")
	cfg.FederationKey = k.String("federation.key")

	// Post-processing: ensure defaults for critical fields.
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":80"
	}
	if cfg.Hostname == "" {
		cfg.Hostname = "localhost"
	}
	if cfg.DBMaxConns == 0 {
		cfg.DBMaxConns = 50
	}
	if cfg.ADSyncIntervalMin <= 0 {
		cfg.ADSyncIntervalMin = 15
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// listenAddrFallback returns the listen address default.
func listenAddrFallback(v string) string {
	if v == "" {
		return ":80"
	}
	return v
}

// hostnameFallback returns the hostname default.
func hostnameFallback(v string) string {
	if v == "" {
		return "localhost"
	}
	return v
}

// dbMaxConnsFallback returns the DB max connections default.
func dbMaxConnsFallback(v int) int {
	if v == 0 {
		return 50
	}
	return v
}

// Load is the backward-compatible entry point. When no YAML file is found,
// it falls through to env vars — exactly the current behavior.
// Set SETJOIN_CONFIG env var to point to a config.yaml file.
func Load() (*Config, error) {
	configPath := os.Getenv("SETJOIN_CONFIG")
	return LoadWithKoanf(configPath)
}

func (c *Config) Validate() error {
	if err := sharedcfg.ValidateBase(c.BaseConfig); err != nil {
		return err
	}
	for envName, secret := range map[string]string{
		"JWT_MAIL_ATTACHMENT_SECRET":             c.MailAttachmentTokenSecret,
		"JWT_MAIL_ATTACHMENT_PREVIOUS_SECRET":    c.MailAttachmentTokenPreviousSecret,
		"JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET": c.LinkProtectTokenPreviousSecret,
	} {
		if secret == "" {
			continue
		}
		minSecret := 32
		if c.CryptoProfile == cryptokey.ProfileSMx {
			minSecret = 16
		}
		if len(secret) < minSecret {
			return fmt.Errorf("%s must be at least %d characters for profile %s", envName, minSecret, c.CryptoProfile)
		}
	}
	// MAILSERVERD-004: the link-protect token key version is a generation
	// counter. An unset version (0) normalizes to the pre-rotation version 1 —
	// the zero-value and legacy-config equivalent (same normalization the
	// ADSyncIntervalMin default applies). A NEGATIVE version is never a
	// legitimate spelling: it would silently derive an unlabelled key no other
	// component computes, so refuse startup instead. (Malformed non-integer
	// spellings never reach here — Load parses the supplied value strictly.)
	if c.LinkProtectTokenVersion == 0 {
		c.LinkProtectTokenVersion = 1
	}
	if c.LinkProtectTokenVersion < 0 {
		return fmt.Errorf("JWT_LINK_PROTECT_TOKEN_VERSION must be >= 1 (got %d) — it selects the link-protect token key generation", c.LinkProtectTokenVersion)
	}
	// A previous secret is only meaningful when the current version HAS a
	// previous generation: TokenKeys verifies the retiring secret at Version-1
	// and never at version 1 itself, so pairing it with version 1 would leave
	// dead configuration that LOOKS like an open overlap window while every
	// old-key link is already being rejected. Refuse the mismatched pairing.
	if c.LinkProtectTokenPreviousSecret != "" && c.LinkProtectTokenVersion == 1 {
		return fmt.Errorf("JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET is set but JWT_LINK_PROTECT_TOKEN_VERSION=1 has no previous generation — bump the version (rotating the gateway secret at the same time) to open the overlap window, or remove the previous secret")
	}
	if c.ADSyncIntervalMin <= 0 {
		c.ADSyncIntervalMin = 15
	}
	if c.TLSAutocertDomains != "" && c.TLSAutocertChallenge == "http-01" {
		slog.Warn("TLS: using HTTP-01 challenge on port 80", "domain", c.TLSAutocertDomains)
	}
	if c.S3AccessKey == "" || c.S3SecretKey == "" {
		return fmt.Errorf("MINIO_ACCESS_KEY and MINIO_SECRET_KEY must be set")
	}
	// Security-value validation (D-MAILSERVER-INTERNAL-CONFIG-002): TLS-off on a
	// non-loopback object store is at least a loud operator-visible warning, and
	// an unknown sandbox fail-mode spelling must not silently widen to fail-open.
	if !c.S3Secure && !isLoopbackListener(c.S3Endpoint) {
		slog.Warn("S3_SECURE=false on a non-loopback endpoint — object-store traffic is unencrypted",
			"endpoint", c.S3Endpoint,
			"fix", "set MINIO_SECURE=true unless TLS terminates locally in front of the object store")
	}
	if err := c.sandboxFailModeValid(); err != nil {
		return err
	}
	if err := c.smimeEncryptAlgorithmValid(); err != nil {
		return err
	}
	if err := c.backupObjectLockHonest(); err != nil {
		return err
	}
	if c.SMTPInboundAddr == "" && c.SMTPSubmissionAddr == "" && c.IMAPAddr == "" {
		return fmt.Errorf("at least one of SMTP_INBOUND_ADDR, SMTP_SUBMISSION_ADDR, or IMAP_ADDR must be set")
	}
	if c.IMAPAddr != "" && (c.TLSCertFile == "" || c.TLSKeyFile == "") && !isLoopbackListener(c.IMAPAddr) {
		return fmt.Errorf("TLS_CERT and TLS_KEY are required when IMAP_ADDR listens beyond loopback; IMAP authentication must not be exposed without STARTTLS")
	}
	if c.SMTPSubmissionAddr != "" && (c.TLSCertFile == "" || c.TLSKeyFile == "") && !isLoopbackListener(c.SMTPSubmissionAddr) {
		return fmt.Errorf("TLS_CERT and TLS_KEY are required when SMTP_SUBMISSION_ADDR listens beyond loopback; submission authentication must not be exposed without STARTTLS")
	}
	return nil
}

// LinkProtectTokenKeys returns the versioned link-protect token key set
// (MAILSERVERD-004 dual-key overlap rotation) built from this config: the
// gateway master secret (JWTSecret) at the configured version is the CURRENT
// signing/verification key, and the optional previous secret — when the
// rotation overlap window is open — verifies tokens at Version-1 only. This
// is the single config→keys conversion the mailserverd wiring consumes, so
// the env spellings and the derivation contract cannot drift apart. The key
// set is normalized (an unset version clamps to 1) so every Config shape —
// including ones that never ran Validate — yields a well-formed key set.
func (c *Config) LinkProtectTokenKeys() linkprotect.TokenKeys {
	return linkprotect.NewTokenKeys(
		[]byte(c.JWTSecret),
		[]byte(c.LinkProtectTokenPreviousSecret),
		c.LinkProtectTokenVersion,
	)
}

// sandboxFailModeValid reports whether the configured sandbox fail mode is one
// of the documented spellings (D-MAILSERVER-INTERNAL-CONFIG-002): "", "open",
// or "closed". Any other value must refuse startup — the fail-mode consumer
// treats everything != "closed" as fail-open, so a typo would silently widen
// the sandbox's failure posture.
func (c *Config) sandboxFailModeValid() error {
	switch c.SandboxFailMode {
	case "", "open", "closed":
		return nil
	default:
		return fmt.Errorf("SANDBOX_FAIL_MODE must be \"open\" or \"closed\" (got %q) — an unknown spelling must not fail open", c.SandboxFailMode)
	}
}

// smimeEncryptAlgorithmValid reports whether the outbound S/MIME content-
// encryption algorithm (owner decision A5) is a supported selection. The
// default "aes-256-gcm" sends RFC 5083 AuthEnvelopedData; "aes-256-cbc" is the
// S/MIME 3.2 fallback. An unknown spelling must refuse startup rather than let
// the smime package silently keep its previous default — the wire format peers
// see would change based on a typo.
func (c *Config) smimeEncryptAlgorithmValid() error {
	switch smime.EncryptAlgorithm(c.SMIMEEncryptAlgorithm) {
	case "", smime.AlgorithmAES256GCM, smime.AlgorithmAES256CBC:
		return nil
	default:
		return fmt.Errorf("SMIME_ENCRYPT_ALGORITHM must be %q or %q (got %q)",
			smime.AlgorithmAES256GCM, smime.AlgorithmAES256CBC, c.SMIMEEncryptAlgorithm)
	}
}

// backupObjectLockHonest refuses a BACKUP_OBJECT_LOCK selection the active
// backup writer cannot honor (ER5 occ_c878e94c624b5cc673f6bb8c,
// protection-mechanism-failure.backup-object-lock-config). The fields are
// parsed and defaulted here, but nothing consumes them: the backup driver
// wiring passes no Object Lock configuration to the backup store, and
// backup.Store explicitly never sets per-object retention — so a set value is
// DEAD protection config: the operator believes backup objects are WORM-locked
// while nothing enforces it. Same posture as SANDBOX_FAIL_MODE and
// SMIME_ENCRYPT_ALGORITHM: an advertised protection that would silently not
// apply must refuse startup instead. BACKUP_OBJECT_LOCK_DAYS alone stays
// allowed — without a mode there is no lock configured and no promise made.
// Lifting this refusal belongs to the change that actually wires the mode into
// the backup bucket's Object Lock configuration.
func (c *Config) backupObjectLockHonest() error {
	if c.BackupObjectLock == "" {
		return nil
	}
	return fmt.Errorf("BACKUP_OBJECT_LOCK %q is not enforced by the active backup writer — the backup store's Object Lock configuration is not wired, so accepting it would promise WORM protection that never applies; remove the setting (the PRIMARY bucket's WORM posture is governed by WORM_MODE) until the backup driver consumes it", c.BackupObjectLock)
}

func isLoopbackListener(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// koanfDuration reads a duration from koanf, falling back to def on empty or parse failure.
func koanfDuration(k *koanf.Koanf, key string, def time.Duration) time.Duration {
	v := k.String(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// parseFloatDefault parses a float64 from s, returning def if s is empty or invalid.
func parseFloatDefault(s string, def float64) float64 {
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

// ValidateEncryptionKey checks that the encryption key is set and meets minimum
// security requirements. In production, refuses to start without a key.
// In dev mode (SETJOIN_DEV=true), generates an ephemeral key with a warning.
func (c *Config) ValidateEncryptionKey() error {
	if len(c.DBEncryptionKey) == 0 {
		if os.Getenv("SETJOIN_DEV") == "true" {
			// Dev mode: generate ephemeral key with loud warning
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return fmt.Errorf("crypto/rand failed generating ephemeral encryption key: %w", err)
			}
			c.DBEncryptionKey = hex.EncodeToString(key)
			slog.Warn("DEV MODE: ephemeral encryption key generated. Data will be unreadable after restart.",
				"set", "SETJOIN_DEV=true",
				"fix", "set DB_ENCRYPTION_KEY for persistent encryption",
			)
			return nil
		}
		return fmt.Errorf("DB_ENCRYPTION_KEY is required for encryption at rest. " +
			"Generate one with: mailctl key generate. " +
			"For dev only: SETJOIN_DEV=true to auto-generate ephemeral key.")
	}

	// Minimum key length: 32 hex chars = 16 bytes = 128 bits (SM4 minimum)
	if len(c.DBEncryptionKey) < 32 {
		return fmt.Errorf("DB_ENCRYPTION_KEY must be at least 32 hex characters (16 bytes)")
	}

	return nil
}
