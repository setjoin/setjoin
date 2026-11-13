package config

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/knadh/koanf/v2"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/envutil"
	"setjoin.com/shared/exchangeartifact"
)

type BaseConfig struct {
	ListenAddr     string `koanf:"listen.addr"`
	Hostname       string `koanf:"hostname"`
	TLSCertFile    string `koanf:"tls.cert"`
	TLSKeyFile     string `koanf:"tls.key"`
	DatabaseDSN    string `koanf:"db.dsn"`
	DatabaseDirect string `koanf:"db.direct_dsn"`
	// DatabaseWorker is the setjoin_worker (BYPASSRLS) pool DSN — the cross-tenant
	// carve-outs (inbound delivery, the cron worker, journaling, admin) connect on
	// it. Defaults to DB_DSN, so until the native-RLS flip behavior is identical.
	DatabaseWorker string `koanf:"db.worker_dsn"`
	// DatabaseOwner is the setjoin_owner DSN — partition/DDL runs as owner so new
	// partitions are owner-owned (no owner-bypass hole; native-RLS fork 1). Defaults
	// to DB_DSN, so until the flip behavior is identical.
	DatabaseOwner   string `koanf:"db.owner_dsn"`
	DBMaxConns      int    `koanf:"db.max_conns"`
	DBEncryptionKey string `koanf:"db.encryption_key"`
	// ExchangeArtifactMaxEnvelope overrides the exchangeartifact envelope
	// ceiling in bytes (EXCHANGEARTIFACT_MAX_ENVELOPE / YAML
	// exchangeartifact.max_envelope). 0 = unset, which keeps the shipped
	// DefaultMaxEnvelope (1 GiB). Configured values must be positive and at
	// least exchangeartifact.MinMaxEnvelope; ValidateBase refuses smaller
	// ones, and anything above exchangeartifact.MaxSettableEnvelope.
	ExchangeArtifactMaxEnvelope int `koanf:"exchangeartifact.max_envelope"`

	// exchangeArtifactMaxEnvelopeRaw preserves the exchangeartifact.max_envelope
	// value verbatim as last seen by the env parser or the koanf merge —
	// including values that failed to parse. Malformed operator input must
	// never collapse into the 0 "unset" sentinel and silently restore the
	// shipped default (EXCHANGEARTIFACT-003 r2 fail-closed finding): the raw
	// string is carried through parse → AddBaseDefaults → merge → DecodeBase
	// so ValidateBase can refuse it at boot. Empty string is the only "not
	// configured" state. AddBaseDefaults seeds this verbatim value as the
	// defaults-layer projection, so the field must be set whenever
	// ExchangeArtifactMaxEnvelope is meaningful.
	exchangeArtifactMaxEnvelopeRaw string
	// AuditHMACKey keys the admin_audit_log hash chain (V087, audit chain V3):
	// each pool connection sets it as the app.audit_hmac_key GUC at connect
	// time, so audit_row_hash writes HMAC-SHA256 checksums instead of plain
	// sha256. Empty = the chain falls back to unkeyed V2 behavior (upgrade-safe
	// for on-prem operators; the servers WARN loudly at boot). Never stored in
	// the DB.
	AuditHMACKey      string                  `koanf:"audit.hmac_key"`
	JWTSecret         string                  `koanf:"jwt.secret"`
	CryptoProfile     cryptokey.CryptoProfile `koanf:"crypto.algorithm_profile"` // CRYPTO_ALGORITHM_PROFILE: standard | smx | hybrid
	SM2PrivateKeyFile string                  `koanf:"sm2.private_key_file"`     // SM2_PRIVATE_KEY_FILE: PEM path for SM2 signing key
	ConfigDir         string                  `koanf:"-"`                        // per-OS config dir (build-tagged defaultConfigDir); not from env
}

func LoadBase() BaseConfig {
	maxEnvelope, maxEnvelopeRaw := parseExchangeArtifactMaxEnvelope()
	return BaseConfig{
		ListenAddr: envutil.Getenv("LISTEN_ADDR", ""),
		// HOSTNAME is machine-populated in most runtimes (Docker sets it to
		// the container ID), so it seeds only the DEFAULT layer here — YAML
		// still overrides it, and the env layer's re-application of HOSTNAME
		// over YAML is governed by the explicit IdentityFileAuthority gate
		// and the IdentityCriticalKeys compatibility list (koanf.go).
		Hostname:          envutil.Getenv("HOSTNAME", ""),
		TLSCertFile:       envutil.Getenv("TLS_CERT", ""),
		TLSKeyFile:        envutil.Getenv("TLS_KEY", ""),
		DatabaseDSN:       envutil.Getenv("DB_DSN", ""),
		DatabaseDirect:    envutil.Getenv("DB_DIRECT_DSN", envutil.Getenv("DB_DSN", "")),
		DatabaseWorker:    envutil.Getenv("DB_WORKER_DSN", envutil.Getenv("DB_DSN", "")),
		DatabaseOwner:     envutil.Getenv("DB_OWNER_DSN", envutil.Getenv("DB_DSN", "")),
		DBMaxConns:        parseDBMaxConns(),
		DBEncryptionKey:   envutil.Getenv("DB_ENCRYPTION_KEY", ""),
		AuditHMACKey:      envutil.Getenv("AUDIT_HMAC_KEY", ""),
		JWTSecret:         envutil.Getenv("JWT_SECRET", ""),
		CryptoProfile:     cryptokey.CryptoProfile(envutil.Getenv("CRYPTO_ALGORITHM_PROFILE", "standard")),
		SM2PrivateKeyFile: envutil.Getenv("SM2_PRIVATE_KEY_FILE", ""),
		ConfigDir:         defaultConfigDir(),

		ExchangeArtifactMaxEnvelope:    maxEnvelope,
		exchangeArtifactMaxEnvelopeRaw: maxEnvelopeRaw,
	}
}

// parseDBMaxConns reads DB_MAX_CONNS loudly. An unset variable is the normal
// "use the service default" case and stays silent; a variable that is SET but
// not a positive integer is operator error that previously vanished into the
// 0 → consumer-fallback path (or a negative → OpenPool's own floor) with no
// signal. The substituted outcome is unchanged and safe — only the
// diagnostics change: the invalid value is named at WARN so the operator can
// tell their intended pool size from the effective one.
func parseDBMaxConns() int {
	raw := envutil.Getenv("DB_MAX_CONNS", "")
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		slog.Warn("config: DB_MAX_CONNS is not a positive integer; using the service default pool size",
			"raw", raw)
		return 0
	}
	return n
}

// parseExchangeArtifactMaxEnvelope reads EXCHANGEARTIFACT_MAX_ENVELOPE
// fail-closed. Unset (empty) is the normal "use the shipped 1 GiB default"
// case and yields the (0, "") unset marker. A value that is set but malformed
// is NOT substituted with the default (EXCHANGEARTIFACT-003 r2: invalid input
// must surface as a load/validation error): the parsed value drops to the 0
// placeholder while the verbatim raw string is preserved, seeded into the
// merged layers by AddBaseDefaults, and refused by ValidateBase at boot.
// Range validation (>= exchangeartifact.MinMaxEnvelope, <=
// exchangeartifact.MaxSettableEnvelope) happens in ValidateBase, which also
// covers YAML-sourced values that never pass through this parser.
func parseExchangeArtifactMaxEnvelope() (int, string) {
	raw := envutil.Getenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "")
	n, _ := parseMaxEnvelopeValue(raw)
	return n, raw
}

// parseMaxEnvelopeValue is the strict parser shared by the environment
// variable and the merged koanf value: "" is genuinely unset and returns the
// 0 marker with no error; anything else must be a positive integer or it is
// an explicit error. It never substitutes a fallback, so a malformed or
// out-of-range operator value can always be traced to a boot refusal instead
// of a silent default.
func parseMaxEnvelopeValue(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("exchangeartifact.max_envelope: %q is not a valid byte count", raw)
	}
	if n <= 0 {
		return 0, fmt.Errorf("exchangeartifact.max_envelope: %d is not a positive byte count", n)
	}
	return n, nil
}

// AddBaseDefaults projects every YAML/environment-backed BaseConfig field into
// the shared koanf keyspace. Services pass their own listen/hostname/pool-size
// defaults in c; the projection itself owns no service policy.
func AddBaseDefaults(defaults map[string]interface{}, c BaseConfig) {
	defaults["listen.addr"] = c.ListenAddr
	defaults["hostname"] = c.Hostname
	defaults["tls.cert"] = c.TLSCertFile
	defaults["tls.key"] = c.TLSKeyFile
	defaults["db.dsn"] = c.DatabaseDSN
	defaults["db.direct_dsn"] = c.DatabaseDirect
	defaults["db.worker_dsn"] = c.DatabaseWorker
	defaults["db.owner_dsn"] = c.DatabaseOwner
	defaults["db.max_conns"] = c.DBMaxConns
	defaults["db.encryption_key"] = c.DBEncryptionKey
	// The envelope ceiling is projected as the verbatim raw string (empty =
	// unset) rather than the parsed int: a malformed operator value must
	// survive into the merged layers so DecodeBase/ValidateBase can refuse it
	// at boot instead of being flattened to the 0 unset marker here.
	defaults["exchangeartifact.max_envelope"] = c.exchangeArtifactMaxEnvelopeRaw
	defaults["audit.hmac_key"] = c.AuditHMACKey
	defaults["jwt.secret"] = c.JWTSecret
	defaults["crypto.algorithm_profile"] = string(c.CryptoProfile)
	defaults["sm2.private_key_file"] = c.SM2PrivateKeyFile
}

// koanfString reads a merged config value verbatim: "" when no layer set the
// key, the string value when one did, and the canonical string form of
// non-string scalars (YAML integers). k.String is deliberately not used: it
// renders a key absent from every layer as "<nil>", which a strict parser
// would mistake for malformed operator input and refuse.
func koanfString(k *koanf.Koanf, key string) string {
	v := k.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// DecodeBase performs the inverse common projection after defaults, YAML, and
// environment layers have been merged. Role-specific DSNs retain the historic
// empty-means-DB_DSN fallback. The exchangeartifact envelope ceiling is
// decoded strictly: a merged value that is present but malformed keeps the 0
// placeholder value with its raw string preserved for ValidateBase to refuse
// — it is never silently treated as unset.
func DecodeBase(k *koanf.Koanf, configDir string) BaseConfig {
	maxEnvelopeRaw := koanfString(k, "exchangeartifact.max_envelope")
	maxEnvelope, _ := parseMaxEnvelopeValue(maxEnvelopeRaw)
	c := BaseConfig{
		ListenAddr:        k.String("listen.addr"),
		Hostname:          k.String("hostname"),
		TLSCertFile:       k.String("tls.cert"),
		TLSKeyFile:        k.String("tls.key"),
		DatabaseDSN:       k.String("db.dsn"),
		DatabaseDirect:    k.String("db.direct_dsn"),
		DatabaseWorker:    k.String("db.worker_dsn"),
		DatabaseOwner:     k.String("db.owner_dsn"),
		DBMaxConns:        k.Int("db.max_conns"),
		DBEncryptionKey:   k.String("db.encryption_key"),
		AuditHMACKey:      k.String("audit.hmac_key"),
		JWTSecret:         k.String("jwt.secret"),
		CryptoProfile:     cryptokey.CryptoProfile(k.String("crypto.algorithm_profile")),
		SM2PrivateKeyFile: k.String("sm2.private_key_file"),
		ConfigDir:         configDir,

		ExchangeArtifactMaxEnvelope:    maxEnvelope,
		exchangeArtifactMaxEnvelopeRaw: maxEnvelopeRaw,
	}
	if c.DatabaseDirect == "" {
		c.DatabaseDirect = c.DatabaseDSN
	}
	if c.DatabaseWorker == "" {
		c.DatabaseWorker = c.DatabaseDSN
	}
	if c.DatabaseOwner == "" {
		c.DatabaseOwner = c.DatabaseDSN
	}
	return c
}

func ValidateBase(c BaseConfig) error {
	if c.DatabaseDSN == "" {
		return fmt.Errorf("DB_DSN is required")
	}
	if c.CryptoProfile != "" && c.CryptoProfile != cryptokey.ProfileStandard && c.CryptoProfile != cryptokey.ProfileSMx && c.CryptoProfile != cryptokey.ProfileHybrid {
		return fmt.Errorf("CRYPTO_ALGORITHM_PROFILE must be standard, smx, or hybrid")
	}

	// Minimum key length adapts to crypto profile
	minSecret := 32
	if c.CryptoProfile == cryptokey.ProfileSMx {
		minSecret = 16
	}
	if len(c.JWTSecret) < minSecret {
		return fmt.Errorf("JWT_SECRET must be at least %d characters for profile %s", minSecret, c.CryptoProfile)
	}
	if c.DBEncryptionKey != "" && c.CryptoProfile == cryptokey.ProfileSMx && len(c.DBEncryptionKey) < 16 {
		return fmt.Errorf("DB_ENCRYPTION_KEY must be at least 16 characters for profile smx")
	}
	if c.DBEncryptionKey != "" && c.CryptoProfile != cryptokey.ProfileSMx && len(c.DBEncryptionKey) < 32 {
		return fmt.Errorf("DB_ENCRYPTION_KEY must be at least 32 characters or empty")
	}
	// AuditHMACKey keys the admin_audit_log V3 HMAC chain; EnforceAuditCutover
	// permanently activates that mode with this key. Strength is enforced
	// CUTOVER-STATE-AWARE there, not here: a weak key must never cause a FIRST
	// activation of audit V3, but an install that already activated under a
	// weak key must keep booting on that same deployed key so its historical
	// v3: rows continue to verify (approved pre/post-cutover compatibility
	// matrix, med-audit-key-validation-b1r2-013). The audit_chain_cutover
	// singleton is not observable at config-validation time, so a weak key
	// surfaces here as an operator-visible warning and the cutover gate in
	// shared/pgxutil refuses the weak first activation. Empty stays legal
	// (upgrade-safe unkeyed V2 fallback with a loud boot WARN).
	if c.AuditHMACKey != "" && len(c.AuditHMACKey) < minSecret {
		slog.Warn("AUDIT_HMAC_KEY is below the configured strength floor",
			"floor", minSecret,
			"crypto_profile", string(c.CryptoProfile),
			"length", len(c.AuditHMACKey),
			"consequence", "startup will be REFUSED if this is a first activation of audit V3; an install that already activated audit V3 continues on this key with this warning")
	}

	// SM2 key required for smx profile
	if c.CryptoProfile == cryptokey.ProfileSMx && c.SM2PrivateKeyFile == "" {
		return fmt.Errorf("SM2_PRIVATE_KEY_FILE is required for profile smx")
	}

	// The artifact envelope ceiling is optional ("" / 0 = shipped 1 GiB
	// default). Validation is fail-closed in both directions: a configured
	// value that is malformed — preserved verbatim through parse and merge,
	// never silently collapsed into the 0 unset marker — is refused with the
	// parse error, and a parseable value outside
	// [MinMaxEnvelope, MaxSettableEnvelope] is refused so it can neither
	// strand legitimate bundles behind confusing client-side rejections nor
	// overflow the package's downstream length arithmetic.
	if c.exchangeArtifactMaxEnvelopeRaw != "" {
		if _, err := parseMaxEnvelopeValue(c.exchangeArtifactMaxEnvelopeRaw); err != nil {
			return err
		}
	}
	if c.ExchangeArtifactMaxEnvelope != 0 {
		if c.ExchangeArtifactMaxEnvelope < exchangeartifact.MinMaxEnvelope {
			return fmt.Errorf("EXCHANGEARTIFACT_MAX_ENVELOPE must be at least %d bytes", exchangeartifact.MinMaxEnvelope)
		}
		if c.ExchangeArtifactMaxEnvelope > exchangeartifact.MaxSettableEnvelope {
			return fmt.Errorf("EXCHANGEARTIFACT_MAX_ENVELOPE must be at most %d bytes", exchangeartifact.MaxSettableEnvelope)
		}
	}

	if (c.TLSCertFile != "") != (c.TLSKeyFile != "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must both be set or both empty")
	}
	return nil
}
