package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/knadh/koanf/v2"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/exchangeartifact"
)

func TestBaseConfigKoanfProjection_AllFields(t *testing.T) {
	want := BaseConfig{
		ListenAddr: ":9443", Hostname: "mail.example.test",
		TLSCertFile: "/tls/cert", TLSKeyFile: "/tls/key",
		DatabaseDSN: "postgres://app", DatabaseDirect: "postgres://direct",
		DatabaseWorker: "postgres://worker", DatabaseOwner: "postgres://owner",
		DBMaxConns: 37, DBEncryptionKey: "encryption", AuditHMACKey: "audit",
		JWTSecret: "jwt", CryptoProfile: cryptokey.ProfileHybrid,
		SM2PrivateKeyFile: "/keys/sm2", ConfigDir: "/etc/setjoin",
		ExchangeArtifactMaxEnvelope:    256 << 20,
		exchangeArtifactMaxEnvelopeRaw: strconv.Itoa(256 << 20),
	}
	defaults := map[string]interface{}{}
	AddBaseDefaults(defaults, want)
	var taggedKeys []string
	typ := reflect.TypeOf(BaseConfig{})
	for i := 0; i < typ.NumField(); i++ {
		if key := typ.Field(i).Tag.Get("koanf"); key != "" && key != "-" {
			taggedKeys = append(taggedKeys, key)
		}
	}
	var projectedKeys []string
	for key := range defaults {
		projectedKeys = append(projectedKeys, key)
	}
	sort.Strings(taggedKeys)
	sort.Strings(projectedKeys)
	if !reflect.DeepEqual(projectedKeys, taggedKeys) {
		t.Fatalf("AddBaseDefaults keys = %v, BaseConfig tagged fields = %v; update the common projection", projectedKeys, taggedKeys)
	}
	k := koanf.New(".")
	for key, value := range defaults {
		if err := k.Set(key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	got := DecodeBase(k, want.ConfigDir)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DecodeBase(AddBaseDefaults()) = %#v, want %#v", got, want)
	}
}

func TestDecodeBase_EmptyRoleDSNsFallBackToAppDSN(t *testing.T) {
	k := koanf.New(".")
	_ = k.Set("db.dsn", "postgres://app")
	_ = k.Set("crypto.algorithm_profile", "standard")
	got := DecodeBase(k, "/config")
	if got.DatabaseDirect != got.DatabaseDSN || got.DatabaseWorker != got.DatabaseDSN || got.DatabaseOwner != got.DatabaseDSN {
		t.Fatalf("role DSNs = direct %q worker %q owner %q, want %q", got.DatabaseDirect, got.DatabaseWorker, got.DatabaseOwner, got.DatabaseDSN)
	}
}

// TestLoadBase_WorkerOwnerDefaultToDBDSN pins the native-RLS W1b INERT contract:
// with DB_WORKER_DSN / DB_OWNER_DSN unset, both DatabaseWorker and DatabaseOwner
// fall back to DB_DSN (so an unconfigured deploy opens the same single pool — the
// main.go alias path — byte-identical to pre-W1b behavior).
func TestLoadBase_WorkerOwnerDefaultToDBDSN(t *testing.T) {
	// t.Setenv first (blocks t.Parallel + auto-restores), then Unsetenv so the keys
	// are absent — an empty value would still be treated as missing by envutil.Getenv,
	// but Unsetenv is the precise "not configured" state we assert against.
	t.Setenv("DB_WORKER_DSN", "")
	os.Unsetenv("DB_WORKER_DSN")
	t.Setenv("DB_OWNER_DSN", "")
	os.Unsetenv("DB_OWNER_DSN")
	t.Setenv("DB_DSN", "postgres://localhost/main")

	cfg := LoadBase()
	if cfg.DatabaseDSN != "postgres://localhost/main" {
		t.Fatalf("DatabaseDSN = %q, want postgres://localhost/main", cfg.DatabaseDSN)
	}
	if cfg.DatabaseWorker != cfg.DatabaseDSN {
		t.Errorf("DatabaseWorker = %q, want it to default to DB_DSN %q", cfg.DatabaseWorker, cfg.DatabaseDSN)
	}
	if cfg.DatabaseOwner != cfg.DatabaseDSN {
		t.Errorf("DatabaseOwner = %q, want it to default to DB_DSN %q", cfg.DatabaseOwner, cfg.DatabaseDSN)
	}
}

// TestLoadBase_WorkerOwnerExplicit pins that when DB_WORKER_DSN / DB_OWNER_DSN are
// set they take the explicit value (the split-pool flip state), independent of DB_DSN.
func TestLoadBase_WorkerOwnerExplicit(t *testing.T) {
	t.Setenv("DB_DSN", "postgres://localhost/main")
	t.Setenv("DB_WORKER_DSN", "postgres://localhost/worker")
	t.Setenv("DB_OWNER_DSN", "postgres://localhost/owner")

	cfg := LoadBase()
	if cfg.DatabaseWorker != "postgres://localhost/worker" {
		t.Errorf("DatabaseWorker = %q, want postgres://localhost/worker", cfg.DatabaseWorker)
	}
	if cfg.DatabaseOwner != "postgres://localhost/owner" {
		t.Errorf("DatabaseOwner = %q, want postgres://localhost/owner", cfg.DatabaseOwner)
	}
	if cfg.DatabaseWorker == cfg.DatabaseDSN || cfg.DatabaseOwner == cfg.DatabaseDSN {
		t.Error("explicit worker/owner DSNs must not collapse to DB_DSN")
	}
}

func TestValidateBase_EmptyDatabaseDSN(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN: "",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
	}
	err := ValidateBase(cfg)
	if err == nil {
		t.Error("expected error for empty DB_DSN, got nil")
	}
}

func TestValidateBase_RejectsUnknownCryptoProfile(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN:   "postgres://localhost/db",
		JWTSecret:     "this-is-at-least-32-characters-long!!!",
		CryptoProfile: cryptokey.CryptoProfile("typo"),
	}
	if err := ValidateBase(cfg); err == nil {
		t.Fatal("expected unknown crypto profile to fail validation")
	}
}

func TestValidateBase_ShortJWTSecret(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "short",
	}
	err := ValidateBase(cfg)
	if err == nil {
		t.Error("expected error for JWT_SECRET < 32 chars, got nil")
	}
}

func TestValidateBase_ValidConfig(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN:     "postgres://localhost/db",
		JWTSecret:       "this-is-at-least-32-characters-long!!!",
		DBEncryptionKey: "12345678901234567890123456789012",
	}
	err := ValidateBase(cfg)
	if err != nil {
		t.Errorf("expected no error for valid config, got: %v", err)
	}
}

func TestValidateBase_EmptyEncryptionKeyOK(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN:     "postgres://localhost/db",
		JWTSecret:       "this-is-at-least-32-characters-long!!!",
		DBEncryptionKey: "",
	}
	err := ValidateBase(cfg)
	if err != nil {
		t.Errorf("expected no error when DB_ENCRYPTION_KEY is empty, got: %v", err)
	}
}

func TestValidateBase_BadEncryptionKeyLength(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN:     "postgres://localhost/db",
		JWTSecret:       "this-is-at-least-32-characters-long!!!",
		DBEncryptionKey: "too-short",
	}
	err := ValidateBase(cfg)
	if err == nil {
		t.Error("expected error for DB_ENCRYPTION_KEY shorter than 32 chars, got nil")
	}
}

// TestValidateBase_BootstrappedKey verifies that a 64-char hex key (generated
// by BootstrapSecrets via genHex(32) → hex.EncodeToString → 64 chars) passes
// validation. The old != 32 check rejected these keys, preventing first-boot start.
func TestValidateBase_BootstrappedKey(t *testing.T) {
	// genHex(32) produces a 64-char hex string — simulate it with 64 'a' chars.
	key64 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg := BaseConfig{
		DatabaseDSN:     "postgres://localhost/db",
		JWTSecret:       "this-is-at-least-32-characters-long!!!",
		DBEncryptionKey: key64,
	}
	if err := ValidateBase(cfg); err != nil {
		t.Errorf("ValidateBase rejected 64-char bootstrapped key: %v", err)
	}
}

func TestValidateBase_MismatchedTLS(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
		TLSCertFile: "/path/cert.pem",
		TLSKeyFile:  "",
	}
	err := ValidateBase(cfg)
	if err == nil {
		t.Error("expected error for TLS_CERT without TLS_KEY, got nil")
	}

	cfg2 := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
		TLSCertFile: "",
		TLSKeyFile:  "/path/key.pem",
	}
	err = ValidateBase(cfg2)
	if err == nil {
		t.Error("expected error for TLS_KEY without TLS_CERT, got nil")
	}
}

func TestValidateBase_BothTLSOK(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
		TLSCertFile: "/path/cert.pem",
		TLSKeyFile:  "/path/key.pem",
	}
	err := ValidateBase(cfg)
	if err != nil {
		t.Errorf("expected no error with both TLS files set, got: %v", err)
	}
}

func TestValidateBase_NoTLSOK(t *testing.T) {
	cfg := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
		TLSCertFile: "",
		TLSKeyFile:  "",
	}
	err := ValidateBase(cfg)
	if err != nil {
		t.Errorf("expected no error with no TLS files set, got: %v", err)
	}
}

func TestParseDBMaxConns(t *testing.T) {
	t.Setenv("DB_MAX_CONNS", "")
	if got := parseDBMaxConns(); got != 0 {
		t.Errorf("unset DB_MAX_CONNS = %d, want 0 (silent service default)", got)
	}

	t.Setenv("DB_MAX_CONNS", "42")
	if got := parseDBMaxConns(); got != 42 {
		t.Errorf("DB_MAX_CONNS=42 → %d, want 42", got)
	}

	for _, bad := range []string{"abc", "-5", "0", "9 9"} {
		t.Setenv("DB_MAX_CONNS", bad)
		if got := parseDBMaxConns(); got != 0 {
			t.Errorf("DB_MAX_CONNS=%q → %d, want 0 with a loud warning", bad, got)
		}
	}
}

func TestParseExchangeArtifactMaxEnvelope(t *testing.T) {
	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "")
	if got, raw := parseExchangeArtifactMaxEnvelope(); got != 0 || raw != "" {
		t.Errorf("unset EXCHANGEARTIFACT_MAX_ENVELOPE = (%d, %q), want (0, \"\") — the shipped 1 GiB default marker", got, raw)
	}

	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "1073741824")
	if got, raw := parseExchangeArtifactMaxEnvelope(); got != 1<<30 || raw != "1073741824" {
		t.Errorf("EXCHANGEARTIFACT_MAX_ENVELOPE=1073741824 → (%d, %q), want (%d, \"1073741824\")", got, raw, 1<<30)
	}

	// Fail-closed (r2): a set-but-malformed value must NOT collapse into the
	// unset marker. The parsed value drops to the 0 placeholder and the
	// verbatim raw string is preserved so ValidateBase refuses it at boot —
	// never a silent fallback to the shipped default.
	for _, bad := range []string{"abc", "-5", "0", "9 9", "99999999999999999999"} {
		t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", bad)
		got, raw := parseExchangeArtifactMaxEnvelope()
		if got != 0 || raw != bad {
			t.Errorf("EXCHANGEARTIFACT_MAX_ENVELOPE=%q → (%d, %q), want (0, %q) with the raw preserved for boot refusal", bad, got, raw, bad)
		}
		if _, err := parseMaxEnvelopeValue(raw); err == nil {
			t.Errorf("parseMaxEnvelopeValue(%q) accepted; want an explicit error", raw)
		}
	}

	// The unset string is the only non-error input to the strict parser.
	if _, err := parseMaxEnvelopeValue(""); err != nil {
		t.Errorf("parseMaxEnvelopeValue(\"\") = %v, want the unset no-error case", err)
	}
}

// TestLoadBase_ExchangeArtifactMaxEnvelopeUnset pins that an unset
// EXCHANGEARTIFACT_MAX_ENVELOPE decodes as the 0 "unset" marker — the
// exchanged default (1 GiB) is applied at the init seam, not in LoadBase.
func TestLoadBase_ExchangeArtifactMaxEnvelopeUnset(t *testing.T) {
	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "")
	os.Unsetenv("EXCHANGEARTIFACT_MAX_ENVELOPE")
	if got := LoadBase().ExchangeArtifactMaxEnvelope; got != 0 {
		t.Fatalf("unconfigured ExchangeArtifactMaxEnvelope = %d, want 0", got)
	}
}

func TestLoadBase_ExchangeArtifactMaxEnvelopeSet(t *testing.T) {
	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "268435456") // 256 MiB
	if got := LoadBase().ExchangeArtifactMaxEnvelope; got != 256<<20 {
		t.Fatalf("ExchangeArtifactMaxEnvelope = %d, want %d", got, 256<<20)
	}
}

func TestValidateBase_MaxEnvelope(t *testing.T) {
	base := BaseConfig{
		DatabaseDSN: "postgres://localhost/db",
		JWTSecret:   "this-is-at-least-32-characters-long!!!",
	}
	// Unset stays legal (shipped default).
	cfg := base
	if err := ValidateBase(cfg); err != nil {
		t.Errorf("unset ExchangeArtifactMaxEnvelope rejected: %v", err)
	}
	// At or above the floor is legal.
	cfg = base
	cfg.ExchangeArtifactMaxEnvelope = exchangeartifact.MinMaxEnvelope
	if err := ValidateBase(cfg); err != nil {
		t.Errorf("floor-equal ExchangeArtifactMaxEnvelope rejected: %v", err)
	}
	// Below the floor is refused at boot (covers YAML-sourced values that
	// never pass through the env parser).
	for _, bad := range []int{-1, 1, exchangeartifact.MinMaxEnvelope - 1} {
		cfg = base
		cfg.ExchangeArtifactMaxEnvelope = bad
		if err := ValidateBase(cfg); err == nil {
			t.Errorf("ValidateBase accepted ExchangeArtifactMaxEnvelope=%d; want rejection", bad)
		}
	}
	// Above the platform-safe maximum is refused: accepted limits must never
	// overflow the package's downstream bound arithmetic (r2).
	cfg = base
	cfg.ExchangeArtifactMaxEnvelope = exchangeartifact.MaxSettableEnvelope + 1
	if err := ValidateBase(cfg); err == nil {
		t.Error("ValidateBase accepted ExchangeArtifactMaxEnvelope above MaxSettableEnvelope; want rejection")
	}
	// The overflow-safe edge itself is legal.
	cfg = base
	cfg.ExchangeArtifactMaxEnvelope = exchangeartifact.MaxSettableEnvelope
	cfg.exchangeArtifactMaxEnvelopeRaw = strconv.FormatInt(exchangeartifact.MaxSettableEnvelope, 10)
	if err := ValidateBase(cfg); err != nil {
		t.Errorf("ValidateBase rejected MaxSettableEnvelope: %v", err)
	}
	// Malformed values preserved verbatim through parse/merge are refused
	// with an explicit error, including an explicit zero and values beyond
	// int64 range (r2 fail-closed: never a silent default substitution).
	for _, badRaw := range []string{"abc", "-5", "0", "9 9", "99999999999999999999"} {
		cfg = base
		cfg.exchangeArtifactMaxEnvelopeRaw = badRaw
		if err := ValidateBase(cfg); err == nil {
			t.Errorf("ValidateBase accepted malformed raw exchangeartifact.max_envelope %q; want explicit error", badRaw)
		}
	}
}

// TestExchangeArtifactConfigPath_FailClosed drives the complete config path —
// parse (LoadBase) → defaults projection (AddBaseDefaults) → merge (Load) →
// decode (DecodeBase) → validate (ValidateBase) → init
// (InitExchangeArtifactMaxEnvelope) — and pins the r2 fail-closed contract: a
// malformed EXCHANGEARTIFACT_MAX_ENVELOPE produces an explicit validation
// error (never a silent restore of the 1 GiB default) whether it arrives via
// the environment, the defaults projection, or a YAML file, while the unset
// path still converges to the shipped default through the init seam and a
// configured value still overrides it.
func TestExchangeArtifactConfigPath_FailClosed(t *testing.T) {
	t.Cleanup(func() { _ = exchangeartifact.SetMaxEnvelope(exchangeartifact.DefaultMaxEnvelope) })
	// Satisfy the unrelated validation gates so the merged config reaches the
	// envelope checks: the path under test is parse → merge → validate →
	// init, not the DSN/secret floors.
	t.Setenv("DB_DSN", "postgres://localhost/config-path-test")
	t.Setenv("JWT_SECRET", "this-is-at-least-32-characters-long!!!")

	// Malformed environment value through the full merged path.
	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "not-a-number")
	parsed := LoadBase()
	if parsed.ExchangeArtifactMaxEnvelope != 0 || parsed.exchangeArtifactMaxEnvelopeRaw != "not-a-number" {
		t.Fatalf("parse step = (%d, %q), want (0, \"not-a-number\")", parsed.ExchangeArtifactMaxEnvelope, parsed.exchangeArtifactMaxEnvelopeRaw)
	}
	defaults := map[string]interface{}{}
	AddBaseDefaults(defaults, parsed)
	k, err := Load(defaults, Options{})
	if err != nil {
		t.Fatalf("merge step: %v", err)
	}
	verr := ValidateBase(DecodeBase(k, t.TempDir()))
	if verr == nil {
		t.Fatal("validate step accepted a malformed EXCHANGEARTIFACT_MAX_ENVELOPE; want an explicit error")
	}
	if !strings.Contains(verr.Error(), "not-a-number") {
		t.Errorf("validation error %q does not name the malformed value", verr)
	}

	// Defense in depth: even with the environment layer out of the picture,
	// the defaults projection carries the malformed raw into the merge, so
	// the refusal does not depend on the env layer re-applying the value.
	os.Unsetenv("EXCHANGEARTIFACT_MAX_ENVELOPE")
	defaultsOnly := map[string]interface{}{}
	AddBaseDefaults(defaultsOnly, parsed)
	k2, err := Load(defaultsOnly, Options{})
	if err != nil {
		t.Fatalf("merge step (defaults only): %v", err)
	}
	if err := ValidateBase(DecodeBase(k2, t.TempDir())); err == nil {
		t.Fatal("validate step accepted a malformed envelope ceiling seeded only through the defaults layer")
	}

	// A malformed YAML-sourced value (which never passes through the env
	// parser) is refused the same way. The historic k.Int decoding turned
	// exactly this input into the 0 unset marker.
	yamlPath := filepath.Join(t.TempDir(), "config.yaml")
	yamlBody := "exchangeartifact:\n  max_envelope: \"1 GiB\"\n"
	if err := os.WriteFile(yamlPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatal(err)
	}
	yamlDefaults := map[string]interface{}{}
	AddBaseDefaults(yamlDefaults, LoadBase())
	k3, err := Load(yamlDefaults, Options{FilePath: yamlPath})
	if err != nil {
		t.Fatalf("merge step (YAML): %v", err)
	}
	if err := ValidateBase(DecodeBase(k3, t.TempDir())); err == nil {
		t.Fatal("validate step accepted a malformed YAML exchangeartifact.max_envelope; want an explicit error")
	}

	// The unset path still converges: validation passes and the init seam
	// re-applies the shipped 1 GiB default (unset behavior preserved).
	unsetParsed := LoadBase()
	if unsetParsed.ExchangeArtifactMaxEnvelope != 0 || unsetParsed.exchangeArtifactMaxEnvelopeRaw != "" {
		t.Fatalf("unset parse step = (%d, %q), want (0, \"\")", unsetParsed.ExchangeArtifactMaxEnvelope, unsetParsed.exchangeArtifactMaxEnvelopeRaw)
	}
	unsetDefaults := map[string]interface{}{}
	AddBaseDefaults(unsetDefaults, unsetParsed)
	k4, err := Load(unsetDefaults, Options{})
	if err != nil {
		t.Fatalf("merge step (unset): %v", err)
	}
	unsetCfg := DecodeBase(k4, t.TempDir())
	if err := ValidateBase(unsetCfg); err != nil {
		t.Fatalf("unset path failed validation: %v", err)
	}
	if err := InitExchangeArtifactMaxEnvelope(unsetCfg.ExchangeArtifactMaxEnvelope); err != nil {
		t.Fatalf("init step (unset): %v", err)
	}
	if got := exchangeartifact.MaxEnvelope(); got != exchangeartifact.DefaultMaxEnvelope {
		t.Fatalf("unset init left MaxEnvelope = %d, want the shipped default %d", got, exchangeartifact.DefaultMaxEnvelope)
	}

	// A configured value still wins through the full path.
	t.Setenv("EXCHANGEARTIFACT_MAX_ENVELOPE", "268435456")
	cfgDefaults := map[string]interface{}{}
	AddBaseDefaults(cfgDefaults, LoadBase())
	k5, err := Load(cfgDefaults, Options{})
	if err != nil {
		t.Fatalf("merge step (configured): %v", err)
	}
	cfg := DecodeBase(k5, t.TempDir())
	if err := ValidateBase(cfg); err != nil {
		t.Fatalf("configured path failed validation: %v", err)
	}
	if err := InitExchangeArtifactMaxEnvelope(cfg.ExchangeArtifactMaxEnvelope); err != nil {
		t.Fatalf("init step (configured): %v", err)
	}
	if got := exchangeartifact.MaxEnvelope(); got != 256<<20 {
		t.Fatalf("configured init left MaxEnvelope = %d, want %d", got, 256<<20)
	}
}
