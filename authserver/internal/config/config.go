package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/knadh/koanf/v2"
	sharedcfg "setjoin.com/shared/config"
	"setjoin.com/shared/cryptokey"
)

// Config holds all environment-driven configuration for the auth server.
// koanf tags document the dotted key paths used in config.yaml and env vars.
// The first underscore in an env var name becomes a dot for nesting:
//
//	JWT_EXPIRY → jwt.expiry
//	THREAT_SPRAY_WINDOW_SECS → threat.spray_window_secs
//
// Deeper nesting uses double underscores: TLS__AUTOCERT__DOMAINS → tls.autocert.domains.
type Config struct {
	sharedcfg.BaseConfig

	// -- JWT --
	JWTExpiry        time.Duration `koanf:"jwt.expiry"`         // access token TTL (default 1h)
	JWTRefreshExpiry time.Duration `koanf:"jwt.refresh_expiry"` // refresh token TTL (default 30d)
	CaptchaSecret    string        `koanf:"captcha.secret"`     // CAPTCHA token signing key (defaults to jwt.secret)
	JWTIssuer        string        `koanf:"jwt.issuer"`         // iss claim; must match gateway's expected issuer (default "mailserver")
	// JWTSigningAlg selects the first-party token signing algorithm (ADR-005):
	// "HS256" (default, conservative) or "ES256" (asymmetric, DB-keystore).
	// ES256 issuance flips on only after the gateway can verify it via the JWKS.
	JWTSigningAlg string `koanf:"jwt.signing_alg"`

	// -- WebAuthn --
	WebAuthnRPID          string `koanf:"webauthn.rp_id"`     // WEBAUTHN_RP_ID
	WebAuthnRPDisplayName string `koanf:"webauthn.rp_name"`   // WEBAUTHN_RP_NAME
	WebAuthnRPOrigin      string `koanf:"webauthn.rp_origin"` // WEBAUTHN_RP_ORIGIN

	// -- Internal API --
	// InternalAPIKey gates the gateway-facing control surfaces: token
	// introspection/revocation, POST /auth/scim/disable (gateway-driven
	// session revocation on user disable/delete) and POST /admin/reload.
	// validate() requires it only when AD sync is configured, but the
	// scim-disable and reload routes are REGISTERED at boot only when the key
	// is non-empty — a deployment that consumes those surfaces must always set
	// it; authserverd logs a loud startup warning naming the skipped routes
	// when it is empty (D-AUTHSERVER-INTERNAL-CONFIG-003). The inverted arm
	// lives here: a key set with no connector configured (its only
	// config-visible consumer) earns a loud topology WARN so an unused shared
	// secret never sits silently in the deployment.
	InternalAPIKey string `koanf:"internal.api_key"` // shared secret for gateway <-> auth server

	// -- Threat Detection --
	GeoIPDBPath       string `koanf:"geoip_db.path"`       // MaxMind GeoLite2 .mmdb file path
	GeoBlockCountries string `koanf:"geo.block_countries"` // comma-separated country codes to block (e.g. "CN,RU,KP")

	// Threat detection thresholds — tunable without binary rebuild (restart required)
	ThreatSprayWindowSecs   int `koanf:"threat.spray_window_secs"`   // window for spray detection (default 300)
	ThreatSprayMaxUsers     int `koanf:"threat.spray_max_users"`     // max unique usernames before spray lockout (default 5)
	ThreatSprayLockoutMins  int `koanf:"threat.spray_lockout_mins"`  // lockout duration after spray detected (default 30)
	ThreatCaptchaWindowMins int `koanf:"threat.captcha_window_mins"` // failure window triggering CAPTCHA (default 5)
	ThreatCaptchaThreshold  int `koanf:"threat.captcha_threshold"`   // failures in window before CAPTCHA required (default 3)
	ThreatTarpitWindowMins  int `koanf:"threat.tarpit_window_mins"`  // failure window triggering tarpit (default 15)
	ThreatTarpitThreshold   int `koanf:"threat.tarpit_threshold"`    // failures in window before tarpit applied (default 3)
	ThreatRateLimitPerMin   int `koanf:"threat.rate_limit_per_min"`  // max auth requests per IP per minute (default 20)

	// -- Feature toggles --
	KerberosEnabled            bool   `koanf:"kerberos.enabled"`      // KERBEROS_ENABLED
	SAMLEnabled                bool   `koanf:"saml.enabled"`          // SAML_ENABLED
	OIDCEnabled                bool   `koanf:"oidc.enabled"`          // OIDC_ENABLED
	OIDCProviderEnabled        bool   `koanf:"oidc_provider.enabled"` // OIDC_PROVIDER_ENABLED
	OIDCProviderPrivateKeyFile string `koanf:"oidc_provider.private_key_file"`
	OIDCProviderPublicKeyFile  string `koanf:"oidc_provider.public_key_file"`
	OIDCProviderAllowedOrigins string `koanf:"oidc_provider.allowed_origins"` // comma-separated browser origins; own HTTPS origin is always allowed
	ADSyncEnabled              bool   `koanf:"ad_sync.enabled"`               // AD_SYNC_ENABLED
	ThreatFeedEnabled          bool   `koanf:"threat_feed.enabled"`           // THREAT_FEED_ENABLED
	GeoBlockEnabled            bool   `koanf:"geo_block.enabled"`             // GEO_BLOCK_ENABLED
	SprayDetectEnabled         bool   `koanf:"spray_detect.enabled"`          // SPRAY_DETECT_ENABLED
	CaptchaEnabled             bool   `koanf:"captcha.enabled"`               // CAPTCHA_ENABLED
	TarpitEnabled              bool   `koanf:"tarpit.enabled"`                // TARPIT_ENABLED

	// -- SAML 2.0 (SP cert/key files shared across all IdP registrations) --
	SAMLCertFile string `koanf:"saml.cert_file"` // SAML_CERT_FILE — SP signing cert (PEM)
	SAMLKeyFile  string `koanf:"saml.key_file"`  // SAML_KEY_FILE — SP signing key (PEM)

	// -- JIT Provisioning --
	JITEnabled bool `koanf:"jit.enabled"` // JIT_ENABLED

	// SSOAllowSuperAdminMapping opts in to letting an admin-configured IdP
	// group->role mapping grant super_admin. Default false (safe): the SSO role
	// ceiling caps group-mapped roles at user_admin unless an operator
	// explicitly flips this on. SSO_ALLOW_SUPER_ADMIN_MAPPING.
	SSOAllowSuperAdminMapping bool `koanf:"sso.allow_super_admin_mapping"`

	// AuthTrustProxy opts in to honoring X-Forwarded-Proto from ANY peer (not
	// just loopback or an allowlisted proxy) when deciding the session cookie's
	// Secure attribute — for topologies where the TLS-terminating gateway isn't
	// reachable through any configured trust boundary. Default false: the
	// standard single-node deploy (gateway proxies to authserver over
	// 127.0.0.1) needs no config at all — see isTrustedProxyPeer in
	// internal/handlers/auth.go. AUTH_TRUST_PROXY.
	AuthTrustProxy bool `koanf:"auth.trust_proxy"`

	// AuthTrustedProxyCIDRs is the explicit trusted-proxy allowlist for
	// forwarded-header trust (X-Forwarded-Proto → session-cookie Secure):
	// comma-separated CIDR ranges whose peers may set the header, e.g.
	// "10.0.8.0/24,fd7a::/48". Default empty = loopback-only trust — since
	// AUTHSERVERD-005 finding 3 a private-range peer is NOT implicitly trusted;
	// loopback peers always are. validate() refuses entries that are not valid
	// CIDRs (a bare proxy IP must be spelled with its /32 or /128 suffix) and
	// the default routes 0.0.0.0/0 and ::/0, which would silently hand client
	// identity to the entire internet. AUTH_TRUSTED_PROXY_CIDRS /
	// YAML auth.trusted_proxy_cidrs.
	AuthTrustedProxyCIDRs string `koanf:"auth.trusted_proxy_cidrs"`

	// ListenAddrExplicit records that the listen address was EXPLICITLY
	// configured — LISTEN_ADDR in the environment, or a listen.addr key in the
	// YAML file — as opposed to falling through to the compiled ":8443"
	// default. Presence is captured at load because value-equality against the
	// default cannot distinguish an operator's deliberate ":8443" from an
	// unconfigured one (AUTHSERVERD-005 finding 1): cmd/authserverd uses this
	// to let an explicit address — even one equal to the default — win over
	// the AUTHSERVER_URL listen derivation. No koanf tag: never decoded from
	// config, computed in LoadWithKoanf.
	ListenAddrExplicit bool

	// -- Push MFA (Web Push VAPID) --
	VAPIDPrivateKey string `koanf:"vapid.private_key"` // VAPID_PRIVATE_KEY
	VAPIDSubject    string `koanf:"vapid.subject"`     // VAPID_SUBJECT

	// -- AD Sync --
	ADSyncDomain      string `koanf:"ad_sync.domain"`       // AD_SYNC_DOMAIN
	ADSyncBindDN      string `koanf:"ad_sync.bind_dn"`      // AD_SYNC_BIND_DN
	ADSyncPasswordEnc string `koanf:"ad_sync.password_enc"` // AD_SYNC_PASSWORD_ENC (AES-256-GCM encrypted)
	ADSyncIntervalMin int    `koanf:"ad_sync.interval_min"` // AD_SYNC_INTERVAL_MIN (default 15)
	ADSyncLDAPHost    string `koanf:"ad_sync.ldap_host"`    // AD_SYNC_LDAP_HOST
}

// LoadWithKoanf loads config from a YAML file (optional) with env var overrides.
// Falls back to env vars only if configPath is empty. All existing env var names
// continue to work — the layered config merges defaults → YAML → env vars.
func LoadWithKoanf(configPath string) (*Config, error) {
	// Load base config first for Platform, CryptoProfile, and env-based base defaults.
	baseCfg := sharedcfg.LoadBase()
	baseDefaults := baseCfg
	baseDefaults.ListenAddr = listenAddrFallback(baseDefaults.ListenAddr)
	baseDefaults.Hostname = hostnameFallback(baseDefaults.Hostname)
	baseDefaults.DBMaxConns = dbMaxConnsFallback(baseDefaults.DBMaxConns)

	// Build a flat defaults map with all config key paths.
	// These are the lowest-priority defaults — YAML and env vars override them.
	defaults := map[string]interface{}{
		// -- JWT --
		"jwt.expiry":         "1h",
		"jwt.refresh_expiry": "720h",
		"jwt.issuer":         "mailserver",
		"jwt.signing_alg":    "HS256",

		// -- CAPTCHA secret (defaults to jwt.secret at post-processing) --
		"captcha.secret": "",

		// -- WebAuthn --
		"webauthn.rp_id":     "localhost",
		"webauthn.rp_name":   "SetJoin",
		"webauthn.rp_origin": "http://localhost:8080",

		// -- Internal API --
		"internal.api_key": "",

		// -- Threat Detection --
		"geoip_db.path":       baseCfg.ConfigDir + "/GeoLite2-City.mmdb",
		"geo.block_countries": "",

		// Threat thresholds
		"threat.spray_window_secs":   300,
		"threat.spray_max_users":     5,
		"threat.spray_lockout_mins":  30,
		"threat.captcha_window_mins": 5,
		"threat.captcha_threshold":   3,
		"threat.tarpit_window_mins":  15,
		"threat.tarpit_threshold":    3,
		"threat.rate_limit_per_min":  20,

		// -- Feature toggles --
		"kerberos.enabled":               false,
		"saml.enabled":                   false,
		"oidc.enabled":                   false,
		"oidc_provider.enabled":          false,
		"oidc_provider.private_key_file": "/opt/setjoin/oidc_key.pem",
		"oidc_provider.public_key_file":  "/opt/setjoin/oidc_pub.pem",
		"oidc_provider.allowed_origins":  "",
		"ad_sync.enabled":                false,
		"threat_feed.enabled":            true,
		"geo_block.enabled":              true,
		"spray_detect.enabled":           true,
		"captcha.enabled":                true,
		"tarpit.enabled":                 true,

		// -- SAML 2.0 --
		"saml.cert_file": "",
		"saml.key_file":  "",

		// -- JIT --
		"jit.enabled":                   false,
		"sso.allow_super_admin_mapping": false,

		// -- Trust boundary --
		"auth.trust_proxy":         false,
		"auth.trusted_proxy_cidrs": "",

		// -- Push MFA --
		"vapid.private_key": "",
		"vapid.subject":     "mailto:admin@localhost",

		// -- AD Sync --
		"ad_sync.domain":       "",
		"ad_sync.bind_dn":      "",
		"ad_sync.password_enc": "",
		"ad_sync.interval_min": 15,
		"ad_sync.ldap_host":    "",
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

	// Presence capture for listen.addr (AUTHSERVERD-005 finding 1). LISTEN_ADDR
	// is present exactly when LoadBase captured a non-empty value (verbatim,
	// before the service fallback below re-applies it); YAML presence needs its
	// own proof because the defaults layer seeds every key into the merged
	// projection.
	cfg.ListenAddrExplicit = baseCfg.ListenAddr != ""
	if configPath != "" {
		inYAML, err := listenAddrSetInYAML(configPath, defaults)
		if err != nil {
			return nil, err
		}
		cfg.ListenAddrExplicit = cfg.ListenAddrExplicit || inYAML
	}

	// -- JWT --
	cfg.JWTExpiry, err = koanfDuration(k, "jwt.expiry", 1*time.Hour)
	if err != nil {
		return nil, err
	}
	cfg.JWTRefreshExpiry, err = koanfDuration(k, "jwt.refresh_expiry", 720*time.Hour)
	if err != nil {
		return nil, err
	}
	cfg.JWTIssuer = k.String("jwt.issuer")
	cfg.JWTSigningAlg = k.String("jwt.signing_alg")

	// -- CAPTCHA secret — derived from the JWT secret via domain-separated
	// HKDF when not explicitly set (D-AUTHSERVER-CMD-AUTHSERVERD-004): the
	// previous raw JWT_SECRET reuse broke key-purpose separation. The derived
	// key signs captcha challenge tokens only (shared/threat HMAC-SHA256) and
	// shares no raw key material with JWT issuance; set CAPTCHA_SECRET to use
	// a fully independent secret instead.
	cfg.CaptchaSecret = k.String("captcha.secret")
	if cfg.CaptchaSecret == "" {
		cfg.CaptchaSecret = string(cryptokey.DeriveEncryptionKey([]byte(cfg.JWTSecret), "mailserver-captcha-token-v1", baseCfg.CryptoProfile))
	}

	// -- WebAuthn --
	cfg.WebAuthnRPID = k.String("webauthn.rp_id")
	cfg.WebAuthnRPDisplayName = k.String("webauthn.rp_name")
	cfg.WebAuthnRPOrigin = k.String("webauthn.rp_origin")

	// -- Internal API --
	cfg.InternalAPIKey = k.String("internal.api_key")

	// -- Threat Detection --
	cfg.GeoIPDBPath = k.String("geoip_db.path")
	cfg.GeoBlockCountries = k.String("geo.block_countries")

	cfg.ThreatSprayWindowSecs = k.Int("threat.spray_window_secs")
	cfg.ThreatSprayMaxUsers = k.Int("threat.spray_max_users")
	cfg.ThreatSprayLockoutMins = k.Int("threat.spray_lockout_mins")
	cfg.ThreatCaptchaWindowMins = k.Int("threat.captcha_window_mins")
	cfg.ThreatCaptchaThreshold = k.Int("threat.captcha_threshold")
	cfg.ThreatTarpitWindowMins = k.Int("threat.tarpit_window_mins")
	cfg.ThreatTarpitThreshold = k.Int("threat.tarpit_threshold")
	cfg.ThreatRateLimitPerMin = k.Int("threat.rate_limit_per_min")

	// -- Feature toggles --
	cfg.KerberosEnabled = k.Bool("kerberos.enabled")
	cfg.SAMLEnabled = k.Bool("saml.enabled")
	cfg.OIDCEnabled = k.Bool("oidc.enabled")
	cfg.OIDCProviderEnabled = k.Bool("oidc_provider.enabled")
	cfg.OIDCProviderPrivateKeyFile = k.String("oidc_provider.private_key_file")
	cfg.OIDCProviderPublicKeyFile = k.String("oidc_provider.public_key_file")
	cfg.OIDCProviderAllowedOrigins = k.String("oidc_provider.allowed_origins")
	cfg.ADSyncEnabled = k.Bool("ad_sync.enabled")
	cfg.ThreatFeedEnabled = k.Bool("threat_feed.enabled")
	cfg.GeoBlockEnabled = k.Bool("geo_block.enabled")
	cfg.SprayDetectEnabled = k.Bool("spray_detect.enabled")
	cfg.CaptchaEnabled = k.Bool("captcha.enabled")
	cfg.TarpitEnabled = k.Bool("tarpit.enabled")

	// -- SAML 2.0 --
	cfg.SAMLCertFile = k.String("saml.cert_file")
	cfg.SAMLKeyFile = k.String("saml.key_file")

	// -- JIT --
	cfg.JITEnabled = k.Bool("jit.enabled")
	cfg.SSOAllowSuperAdminMapping = k.Bool("sso.allow_super_admin_mapping")

	// -- Trust boundary --
	cfg.AuthTrustProxy = k.Bool("auth.trust_proxy")
	cfg.AuthTrustedProxyCIDRs = k.String("auth.trusted_proxy_cidrs")

	// -- Push MFA --
	cfg.VAPIDPrivateKey = k.String("vapid.private_key")
	cfg.VAPIDSubject = k.String("vapid.subject")

	// -- AD Sync --
	cfg.ADSyncDomain = k.String("ad_sync.domain")
	cfg.ADSyncBindDN = k.String("ad_sync.bind_dn")
	cfg.ADSyncPasswordEnc = k.String("ad_sync.password_enc")
	cfg.ADSyncIntervalMin = k.Int("ad_sync.interval_min")
	cfg.ADSyncLDAPHost = k.String("ad_sync.ldap_host")

	// Post-processing: ensure defaults for critical fields.
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	if cfg.Hostname == "" {
		cfg.Hostname = "localhost"
	}
	if cfg.DBMaxConns == 0 {
		cfg.DBMaxConns = 25
	}
	if cfg.ADSyncIntervalMin <= 0 {
		cfg.ADSyncIntervalMin = 15
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultListenAddr is the UNCONFIGURED listen address: loopback-scoped. The
// old wildcard ":8443" default made a standalone authserver with no TLS pair
// serve bearer credentials, passwords, and every /auth route in cleartext on
// ALL interfaces by default (the gateway topology is unaffected — it derives
// its listen address from AUTHSERVER_URL, or sets LISTEN_ADDR explicitly, both
// of which still win). An operator who genuinely wants an external bind sets
// LISTEN_ADDR/listen.addr; with TLS configured any interface is accepted.
const defaultListenAddr = "127.0.0.1:8443"

// listenAddrFallback returns the listen address default for authserver.
func listenAddrFallback(v string) string {
	if v == "" {
		return defaultListenAddr
	}
	return v
}

// listenAddrSetInYAML reports whether the YAML config file explicitly carries
// a listen.addr key. The merged koanf instance cannot answer this — the
// defaults layer seeds every key, so Exists is true regardless — so the file's
// presence is proven with a defaults-free reload in which the key can only
// exist if the file set it: applyEnvOverrides only overrides keys that already
// exist, so with listen.addr removed from the defaults the environment layer
// cannot seed it either (the same file-layer presence detection shared/config
// uses for IdentityCriticalKeys). The file has already parsed successfully in
// the primary load, so the reload cannot fail for a new reason; the only
// visible side effect is a repeated permissive-file WARN when the config file
// is group/world-readable or a symlink — a misconfiguration worth repeating.
func listenAddrSetInYAML(configPath string, defaults map[string]interface{}) (bool, error) {
	presenceDefaults := make(map[string]interface{}, len(defaults))
	for key, value := range defaults {
		if key == "listen.addr" {
			continue
		}
		presenceDefaults[key] = value
	}
	k, err := sharedcfg.Load(presenceDefaults, sharedcfg.Options{
		FilePath:  configPath,
		EnvPrefix: "",
		Delimiter: ".",
	})
	if err != nil {
		return false, fmt.Errorf("listen.addr presence check failed: %w", err)
	}
	return k.Exists("listen.addr"), nil
}

// validateTrustedProxyCIDRs enforces the auth.trusted_proxy_cidrs allowlist
// contract (AUTHSERVERD-005 finding 3): every comma-separated entry must be a
// valid CIDR — a bare proxy IP must be spelled with its /32 or /128 suffix so
// an accidentally widened range can never masquerade as a host — and the
// default routes 0.0.0.0/0 / ::/0 are refused outright, since trusting the
// whole internet as the proxy boundary silently defeats the trust model.
// Empty entries between commas are tolerated, matching the
// OIDC_PROVIDER_ALLOWED_ORIGINS list style.
func validateTrustedProxyCIDRs(raw string) error {
	if raw == "" {
		return nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return fmt.Errorf("AUTH_TRUSTED_PROXY_CIDRS entry %q is not a valid CIDR range (append /32 for a single IPv4 host, /128 for IPv6)", entry)
		}
		if ipNet.String() == "0.0.0.0/0" || ipNet.String() == "::/0" {
			return fmt.Errorf("AUTH_TRUSTED_PROXY_CIDRS entry %q trusts the entire internet as proxy peers — list the proxy's actual network(s) instead", entry)
		}
	}
	return nil
}

// hostnameFallback returns the hostname default.
func hostnameFallback(v string) string {
	if v == "" {
		return "localhost"
	}
	return v
}

// listenHost extracts the host part of a listen address ("127.0.0.1:8443",
// ":8443", "[::1]:8443", "localhost:8443"). An empty host (":8443") means
// every interface — reported as "" so the cleartext validation can treat it as
// the widest possible bind.
func listenHost(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// isLoopbackHostname reports whether host is a name that resolves to the
// machine itself without configuration (the literal "localhost" family). Any
// other name is treated as a real interface and requires TLS.
func isLoopbackHostname(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// dbMaxConnsFallback returns the DB max connections default for authserver.
func dbMaxConnsFallback(v int) int {
	if v == 0 {
		return 25
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

func (c *Config) validate() error {
	if err := sharedcfg.ValidateBase(c.BaseConfig); err != nil {
		return err
	}
	// Runtime revocation enforcement rows retain a 31-day compatibility
	// window. Keeping first-party access JWTs at or below 30 days makes that
	// bound authoritative while preserving the 1-hour production default.
	if c.JWTExpiry <= 0 || c.JWTExpiry > 30*24*time.Hour {
		return fmt.Errorf("JWT_EXPIRY must be greater than zero and no more than 720h")
	}
	if c.JWTRefreshExpiry <= 0 {
		return fmt.Errorf("JWT_REFRESH_EXPIRY must be greater than zero")
	}
	// Threat detection tunables (D-AUTHSERVER-INTERNAL-CONFIG-002): these gate
	// brute-force defenses (spray lockout, CAPTCHA, tarpit, per-IP rate limit).
	// A zero/negative value silently disables its control and an absurd upper
	// value is almost always an operator typo — fail startup loudly naming the
	// offending key instead of silently degrading the defense.
	for _, t := range []struct {
		name string
		val  int
		max  int
	}{
		{"THREAT_SPRAY_WINDOW_SECS", c.ThreatSprayWindowSecs, 30 * 24 * 60 * 60},
		{"THREAT_SPRAY_MAX_USERS", c.ThreatSprayMaxUsers, 1000000},
		{"THREAT_SPRAY_LOCKOUT_MINS", c.ThreatSprayLockoutMins, 30 * 24 * 60},
		{"THREAT_CAPTCHA_WINDOW_MINS", c.ThreatCaptchaWindowMins, 30 * 24 * 60},
		{"THREAT_CAPTCHA_THRESHOLD", c.ThreatCaptchaThreshold, 100000},
		{"THREAT_TARPIT_WINDOW_MINS", c.ThreatTarpitWindowMins, 30 * 24 * 60},
		{"THREAT_TARPIT_THRESHOLD", c.ThreatTarpitThreshold, 100000},
		{"THREAT_RATE_LIMIT_PER_MIN", c.ThreatRateLimitPerMin, 1000000},
	} {
		if t.val < 1 || t.val > t.max {
			return fmt.Errorf("%s must be between 1 and %d (got %d)", t.name, t.max, t.val)
		}
	}
	if c.adSyncConfigured() && c.InternalAPIKey == "" {
		return fmt.Errorf("INTERNAL_API_KEY is required")
	}
	// AUTHSERVERD-005 finding 3: the trusted-proxy allowlist is a security
	// boundary — a malformed entry must refuse startup, never silently narrow
	// (or widen) the trust set (fail-loud config posture,
	// D-AUTHSERVER-INTERNAL-CONFIG-002).
	if err := validateTrustedProxyCIDRs(c.AuthTrustedProxyCIDRs); err != nil {
		return err
	}
	// Insecure-transport posture: a cleartext (no TLS pair) listener on a
	// non-loopback interface serves passwords, bearer/refresh tokens, and every
	// /auth route unencrypted to the network it binds. The OIDC allowed-origins
	// rule below already requires HTTPS except for loopback origins — the
	// server's own bind follows the same rule, refusing startup with the two
	// remediation paths (bind loopback for a gateway-proxied deployment, or
	// configure TLS_CERT/TLS_KEY) instead of silently booting wide open. An
	// empty host (":8443") is the WILDCARD bind — every interface — and is
	// treated as non-loopback.
	if c.TLSCertFile == "" {
		host := listenHost(c.ListenAddr)
		if host == "" || (!net.ParseIP(host).IsLoopback() && !isLoopbackHostname(host)) {
			return fmt.Errorf("LISTEN_ADDR %q binds beyond loopback without TLS — bind 127.0.0.1 (or ::1) for a gateway-proxied deployment, or set TLS_CERT/TLS_KEY", c.ListenAddr)
		}
	}
	if c.OIDCProviderEnabled &&
		(c.OIDCProviderPrivateKeyFile == "" ||
			c.OIDCProviderPublicKeyFile == "" ||
			c.OIDCProviderPrivateKeyFile == c.OIDCProviderPublicKeyFile) {
		return fmt.Errorf("OIDC provider key files must be non-empty and distinct")
	}
	if c.OIDCProviderEnabled {
		for _, raw := range strings.Split(c.OIDCProviderAllowedOrigins, ",") {
			origin := strings.TrimSpace(strings.TrimRight(raw, "/"))
			if origin == "" {
				continue
			}
			u, err := url.Parse(origin)
			if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(origin, "*") {
				return fmt.Errorf("OIDC_PROVIDER_ALLOWED_ORIGINS must contain exact origins without paths, queries, userinfo, or wildcards")
			}
			loopback := u.Hostname() == "localhost"
			if ip := net.ParseIP(u.Hostname()); ip != nil {
				loopback = ip.IsLoopback()
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
				return fmt.Errorf("OIDC_PROVIDER_ALLOWED_ORIGINS requires HTTPS except for loopback development origins")
			}
		}
	}
	// D-AUTHSERVER-INTERNAL-CONFIG-003, inverted arm: a key set with no
	// connector configured has no consumer in the current topology. This is
	// the mirror of the loud empty-key WARN in authserverd (which names the
	// routes skipped when the key is empty): here the key EXISTS but nothing
	// config-visible consumes it — the AD-sync connector is the only config
	// element coupled to the key (the requirement arm above), and the gateway
	// control surfaces only matter when some internal consumer presents the
	// key. Emit after all hard validations so the signal fires exactly for
	// configs that boot (and for every successful reload re-reading the
	// topology). A WARN, not an error: presenting the key out-of-config
	// (gateway introspection/revocation) stays legitimate.
	if c.InternalAPIKey != "" && !c.adSyncConfigured() {
		slog.Warn("INTERNAL_API_KEY is set but no connector is configured to consume it — the key serves no purpose in the current topology",
			"key", "INTERNAL_API_KEY",
			"consumers", "none configured: AD sync (the only config-level INTERNAL_API_KEY consumer; required arm above) is not enabled",
			"consequence", "the shared secret is loaded but unused; keep it only if an internal API consumer presents it out-of-config (gateway token introspection/revocation, POST /auth/scim/disable, POST /admin/reload), otherwise unset it to shrink the deployed secret surface")
	}
	return nil
}

// adSyncConfigured reports whether the AD directory connector is configured —
// the one config-level consumer that makes INTERNAL_API_KEY required (the
// requirement arm in validate). The local connector is unconditional and
// consumes no key; SAML/OIDC/Kerberos are auth protocols, not directory
// connectors, so they contribute nothing to this topology signal.
func (c *Config) adSyncConfigured() bool {
	return c.ADSyncEnabled && c.ADSyncDomain != ""
}

// koanfDuration reads a duration from koanf. Empty values fall back to def;
// a non-empty unparseable value is an operator error and is rejected naming
// the offending key rather than silently substituted with the default
// (fail-loud config posture, D-AUTHSERVER-INTERNAL-CONFIG-002 — a silently
// discarded TTL tightening must never look like a successful reload).
func koanfDuration(k *koanf.Koanf, key string, def time.Duration) (time.Duration, error) {
	v := k.String(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s must be a valid duration (e.g. \"1h\", \"720h\"), got %q", durationEnvName(key), v)
	}
	return d, nil
}

// durationEnvName maps a dotted koanf key to the env var name operators see
// (jwt.refresh_expiry -> JWT_REFRESH_EXPIRY).
func durationEnvName(key string) string {
	return strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
}
