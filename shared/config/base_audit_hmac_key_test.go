package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"setjoin.com/shared/cryptokey"
)

// med-audit-key-validation-b1r2-013: AuditHMACKey strength is enforced
// cutover-state-aware at EnforceAuditCutover (shared/pgxutil), per the approved
// pre/post-cutover compatibility matrix. The audit_chain_cutover singleton is
// not observable at config-validation time, so ValidateBase accepts a weak
// nonempty key with an operator-visible warning (an install that already
// activated audit V3 under a weak key must keep booting on that key so its
// historical v3: rows keep verifying) while the cutover gate refuses the weak
// FIRST activation. Empty stays legal: the chain falls back to unkeyed V2
// (upgrade-safe for existing installs).

// captureSlog redirects the default logger into a buffer for warning assertions.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// Compatibility cell 4 (weak post-cutover) plus the validation-time warning:
// a weak nonempty AUDIT_HMAC_KEY is NOT a validation failure — rejecting it
// unconditionally would brick already-activated weak-key installs — but the
// operator must see the warning before the cutover gate decides.
func TestValidateBase_WeakAuditHMACKeyWarnsButDoesNotReject(t *testing.T) {
	buf := captureSlog(t)
	cfg := BaseConfig{
		DatabaseDSN:   "postgres://localhost/db",
		JWTSecret:     "this-is-at-least-32-characters-long!!!",
		CryptoProfile: cryptokey.ProfileStandard,
		AuditHMACKey:  "short",
	}
	if err := ValidateBase(cfg); err != nil {
		t.Fatalf("weak AUDIT_HMAC_KEY must not fail validation (cutover gate owns the pre/post decision), got: %v", err)
	}
	if !strings.Contains(buf.String(), "AUDIT_HMAC_KEY") {
		t.Fatalf("expected an operator-visible AUDIT_HMAC_KEY warning, got log: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "floor=32") {
		t.Fatalf("expected the standard-profile floor (32) in the warning, got log: %q", buf.String())
	}
}

// Same compatibility branch under the smx profile floor (16).
func TestValidateBase_WeakAuditHMACKeySMxFloorWarned(t *testing.T) {
	buf := captureSlog(t)
	cfg := BaseConfig{
		DatabaseDSN:       "postgres://localhost/db",
		JWTSecret:         "at-least-16-chars",
		CryptoProfile:     cryptokey.ProfileSMx,
		SM2PrivateKeyFile: "/keys/sm2.pem",
		AuditHMACKey:      strings.Repeat("k", 15), // one below the 16-char smx floor
	}
	if err := ValidateBase(cfg); err != nil {
		t.Fatalf("weak AUDIT_HMAC_KEY must not fail validation on smx either, got: %v", err)
	}
	if !strings.Contains(buf.String(), "floor=16") {
		t.Fatalf("expected the smx floor (16) in the warning, got log: %q", buf.String())
	}
}

// Compatibility cell 5/6 (adequate key): the floor is met, so no audit-key
// warning may fire.
func TestValidateBase_AuditHMACKeyAtFloorAccepted(t *testing.T) {
	buf := captureSlog(t)
	standard := BaseConfig{
		DatabaseDSN:  "postgres://localhost/db",
		JWTSecret:    "this-is-at-least-32-characters-long!!!",
		AuditHMACKey: strings.Repeat("a", 32),
	}
	if err := ValidateBase(standard); err != nil {
		t.Fatalf("expected 32-char AUDIT_HMAC_KEY to pass on standard profile, got: %v", err)
	}
	smx := BaseConfig{
		DatabaseDSN:       "postgres://localhost/db",
		JWTSecret:         "at-least-16-chars",
		CryptoProfile:     cryptokey.ProfileSMx,
		SM2PrivateKeyFile: "/keys/sm2.pem",
		AuditHMACKey:      strings.Repeat("a", 16),
	}
	if err := ValidateBase(smx); err != nil {
		t.Fatalf("expected 16-char AUDIT_HMAC_KEY to pass on smx profile, got: %v", err)
	}
	if strings.Contains(buf.String(), "AUDIT_HMAC_KEY") {
		t.Fatalf("floor-satisfying AUDIT_HMAC_KEY must not warn, got log: %q", buf.String())
	}
}

// Existing-install compatibility arm (cells 1/2 pre-cutover side): an install
// that never set AUDIT_HMAC_KEY runs the unkeyed V2 fallback — validation must
// keep accepting it (and stay silent about the audit key) so upgrades do not
// brick. Post-cutover absence is refused by EnforceAuditCutover.
func TestValidateBase_EmptyAuditHMACKeyStillValid(t *testing.T) {
	buf := captureSlog(t)
	cfg := BaseConfig{
		DatabaseDSN:  "postgres://localhost/db",
		JWTSecret:    "this-is-at-least-32-characters-long!!!",
		AuditHMACKey: "",
	}
	if err := ValidateBase(cfg); err != nil {
		t.Fatalf("expected empty AUDIT_HMAC_KEY to remain valid (unkeyed V2 fallback), got: %v", err)
	}
	if strings.Contains(buf.String(), "AUDIT_HMAC_KEY") {
		t.Fatalf("empty AUDIT_HMAC_KEY is a supported state and must not warn here, got log: %q", buf.String())
	}
}

// Existing installs already running an acceptable (bootstrapped 64-char hex
// style) audit key must be unaffected by the floor.
func TestValidateBase_BootstrappedStyleAuditHMACKeyAccepted(t *testing.T) {
	buf := captureSlog(t)
	cfg := BaseConfig{
		DatabaseDSN:  "postgres://localhost/db",
		JWTSecret:    "this-is-at-least-32-characters-long!!!",
		AuditHMACKey: strings.Repeat("a", 64),
	}
	if err := ValidateBase(cfg); err != nil {
		t.Fatalf("expected 64-char AUDIT_HMAC_KEY to pass unchanged, got: %v", err)
	}
	if strings.Contains(buf.String(), "AUDIT_HMAC_KEY") {
		t.Fatalf("bootstrapped-style AUDIT_HMAC_KEY must not warn, got log: %q", buf.String())
	}
}
