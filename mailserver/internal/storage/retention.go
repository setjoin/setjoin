package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Retention policy interface ────────────────────────────────────────────

// RetentionPolicy enforces immutability, retention, and legal hold on objects.
// WORM (Write Once Read Many) is the first implementation. Future policies
// (auto-tiering, geo-replication rules) implement this same interface.
type RetentionPolicy interface {
	// Apply enforces the policy on a newly written object.
	Apply(ctx context.Context, key string) error

	// Verify checks that the policy is active on an existing object.
	Verify(ctx context.Context, key string) (*RetentionStatus, error)

	// Release attempts to remove retention. Compliance mode returns ErrImmutable.
	// Governance mode permits release with BypassGovernanceRetention.
	Release(ctx context.Context, key string) error

	// Info returns human-readable policy metadata for admin dashboards.
	Info() RetentionInfo
}

// ── Sentinel errors ───────────────────────────────────────────────────────

// ErrImmutable is returned when an operation is rejected because the object
// is protected by a compliance-mode retention policy that cannot be bypassed.
var ErrImmutable = errors.New("storage: object is immutable under compliance-mode retention")

// ── Policy metadata ───────────────────────────────────────────────────────

// RetentionInfo describes a retention policy for admin dashboards.
type RetentionInfo struct {
	Type        string // "worm_s3_object_lock", "legal_hold_db", "physical_worm"
	Mode        string // "compliance" or "governance"
	Description string
}

// ── WORM Retention Policy ─────────────────────────────────────────────────

// WORMRetentionPolicy enforces S3 Object Lock compliance-mode immutability.
// It depends on the segregated Retention capability, not the full Driver: a
// policy can only be applied on a backend that actually supports object lock.
type WORMRetentionPolicy struct {
	retention  Retention
	mode       string
	retainDays int
	pool       *pgxpool.Pool // optional, for legal hold DB lookups
}

// NewWORMRetentionPolicy creates a WORM policy using the given Retention
// capability. pool may be nil if legal hold integration is not required.
//
// A storage.Driver value is accepted only if it also satisfies Retention; use
// RetentionOf to obtain the Retention from a Driver and detect unsupported
// backends explicitly before constructing the policy.
func NewWORMRetentionPolicy(retention Retention, mode string, retainDays int, pool *pgxpool.Pool) *WORMRetentionPolicy {
	return &WORMRetentionPolicy{
		retention:  retention,
		mode:       mode,
		retainDays: retainDays,
		pool:       pool,
	}
}

// Apply enforces the WORM policy on a newly written object by setting
// the S3 Object Lock retention until date.
func (p *WORMRetentionPolicy) Apply(ctx context.Context, key string) error {
	if p.mode == "" || p.retainDays <= 0 {
		return nil // WORM not configured
	}
	retainUntil := time.Now().AddDate(0, 0, p.retainDays)
	return p.retention.PutObjectRetention(ctx, key, p.mode, retainUntil)
}

// Verify checks the object's current retention status.
func (p *WORMRetentionPolicy) Verify(ctx context.Context, key string) (*RetentionStatus, error) {
	return p.retention.GetObjectRetention(ctx, key)
}

// Release attempts to remove retention from an object.
// Compliance mode always returns ErrImmutable (even root cannot delete).
// Governance mode removes the retention lock via PutObjectRetention with
// a zero retain-until date (BypassGovernanceRetention header is set by the
// S3 driver for governance mode calls).
func (p *WORMRetentionPolicy) Release(ctx context.Context, key string) error {
	if p.mode == "compliance" {
		return ErrImmutable
	}
	// Governance mode: remove retention by setting a zero-date lock.
	// The S3 driver applies BypassGovernanceRetention for governance mode.
	return p.retention.PutObjectRetention(ctx, key, p.mode, time.Time{})
}

// Info returns policy metadata for admin dashboards.
func (p *WORMRetentionPolicy) Info() RetentionInfo {
	return RetentionInfo{
		Type:        "worm_s3_object_lock",
		Mode:        p.mode,
		Description: "S3 Object Lock " + p.mode + " mode — " + retentionDescription(p.mode, p.retainDays),
	}
}

func retentionDescription(mode string, days int) string {
	if mode == "compliance" {
		return "non-erasable, non-rewritable. No principal can delete locked objects. Required for SEC 17a-4(f)."
	}
	return "governance mode with bypass capability. Use compliance mode for regulatory mandates."
}

// ── Retention Policy Registry ─────────────────────────────────────────────

// RetentionPolicyRegistry composes multiple RetentionPolicy instances and
// applies them in registration order.
type RetentionPolicyRegistry struct {
	policies []RetentionPolicy

	// legalHold is the object-lock backend used for per-object legal holds
	// (eDiscovery litigation hold → S3 Object Lock legal hold). It is separate
	// from the WORM retention policies above: retention has a fixed expiry,
	// legal hold is toggled on/off independently.
	legalHold Retention
	// legalHoldEnabled gates SetLegalHold; when false it no-ops.
	legalHoldEnabled bool
}

// NewRetentionPolicyRegistry creates a registry with the given policies.
func NewRetentionPolicyRegistry(policies ...RetentionPolicy) *RetentionPolicyRegistry {
	return &RetentionPolicyRegistry{policies: policies}
}

// ApplyAll runs Apply on every policy in order. Stops at the first error.
func (r *RetentionPolicyRegistry) ApplyAll(ctx context.Context, key string) error {
	for _, p := range r.policies {
		if err := p.Apply(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

// VerifyAll runs Verify on every policy in order. Returns all statuses.
func (r *RetentionPolicyRegistry) VerifyAll(ctx context.Context, key string) ([]*RetentionStatus, error) {
	var out []*RetentionStatus
	for _, p := range r.policies {
		status, err := p.Verify(ctx, key)
		if err != nil {
			return nil, err
		}
		out = append(out, status)
	}
	return out, nil
}

// SetLegalHoldBackend wires the object-lock backend and enable flag used by
// SetLegalHold. Called at startup from InitWORM.
func (r *RetentionPolicyRegistry) SetLegalHoldBackend(backend Retention, enabled bool) {
	r.legalHold = backend
	r.legalHoldEnabled = enabled
}

// SetLegalHold sets ("ON") or clears ("OFF") the object legal hold on key.
// No-ops when legal hold is disabled or no backend is wired, so callers need
// not check first.
func (r *RetentionPolicyRegistry) SetLegalHold(ctx context.Context, key string, on bool) error {
	if !r.legalHoldEnabled || r.legalHold == nil {
		return nil
	}
	status := "OFF"
	if on {
		status = "ON"
	}
	return r.legalHold.PutObjectLegalHold(ctx, key, status)
}

// LegalHoldEnabled reports whether object legal hold is active.
func (r *RetentionPolicyRegistry) LegalHoldEnabled() bool {
	return r.legalHoldEnabled
}

// Infos returns metadata for all registered policies.
func (r *RetentionPolicyRegistry) Infos() []RetentionInfo {
	var out []RetentionInfo
	for _, p := range r.policies {
		out = append(out, p.Info())
	}
	return out
}
