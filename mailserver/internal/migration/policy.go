package migration

import (
	"errors"
	"fmt"

	"setjoin.com/shared/ssrf"
)

// Migration sources dial administrator- or caller-named destinations, so the
// private-network exception policy (PrivateHosts/PrivateCIDRs) has a single
// ownership rule: the allowlist content is ADMINISTRATOR-owned and reaches a
// connector only through the global source profile merge (factory.go). A
// caller-manufactured exception is rejected at every entry point —
// self-service start, connection test, and the connector factories that
// reconstruct persisted jobs on start/resume/dial — while the permanent
// denials inside the shared policy layer (loopback, link-local/metadata,
// multicast, CGNAT, …) can never be allowlisted by anyone (ssrf.go).

// ErrUserSuppliedPrivatePolicy is returned when a migration config carries a
// caller-manufactured private-network exception. It is rejected (not silently
// stripped) so the producer knows the fields are not honored.
var ErrUserSuppliedPrivatePolicy = errors.New("migration private-network policy is administrator-owned; per-job privateHosts/privateCIDRs are not accepted")

// RejectUserSuppliedPrivatePolicy fails when a caller-supplied migration
// config carries PrivateHosts/PrivateCIDRs exceptions, and returns nil for a
// policy-free config. It is the bare-path containment used by both the
// self-service handlers (ingress rejection) and the connector factories
// (fail-closed reconstruction of persisted bare-path jobs on start, resume
// and dial — a stored policy can no longer be honored after the fix, and the
// operator re-admits such jobs under an admin profile or cancels them).
func RejectUserSuppliedPrivatePolicy(hosts, cidrs []string) error {
	if len(hosts) == 0 && len(cidrs) == 0 {
		return nil
	}
	return ErrUserSuppliedPrivatePolicy
}

// ValidateGlobalIMAPProfile validates an administrator-supplied global IMAP
// source profile at save time, applying the same rules the IMAP connector
// factory and dialer enforce at connector construction: a host must be
// present, the TLS mode must be one the dialer implements, and the
// private-network policy must compile — which permanently rejects loopback,
// link-local/metadata and other non-RFC1918/ULA ranges, so a malformed or
// unsafe profile can never be stored for later jobs to inherit.
func ValidateGlobalIMAPProfile(cfg GlobalIMAPConfig) error {
	if cfg.Host == "" {
		return errors.New("host is required")
	}
	switch cfg.TLSMode {
	case "tls", "starttls", "none":
	default:
		return fmt.Errorf("unsupported tls_mode %q (must be tls, starttls, or none)", cfg.TLSMode)
	}
	if _, err := ssrf.CompilePrivatePolicy(cfg.PrivateHosts, cfg.PrivateCIDRs); err != nil {
		return fmt.Errorf("invalid private-network policy: %w", err)
	}
	return nil
}

// ValidateGlobalEWSProfile validates an administrator-supplied global EWS
// source profile at save time with exactly the checks ewsFactory applies at
// connector construction: the private-network policy must compile (permanent
// denials included) and the server URL must be https and acceptable under the
// compiled policy, so save-time rejection replaces the deferred connector
// construction failure for a profile that could never build a connector.
func ValidateGlobalEWSProfile(cfg GlobalEWSConfig) error {
	policy, err := ssrf.CompilePrivatePolicy(cfg.PrivateHosts, cfg.PrivateCIDRs)
	if err != nil {
		return fmt.Errorf("invalid private-network policy: %w", err)
	}
	if err := validateEWSServerURL(cfg.ServerURL, policy); err != nil {
		return fmt.Errorf("invalid serverURL: %w", err)
	}
	return nil
}
