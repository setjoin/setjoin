package authn

// possession.go — storage authority for the first-factor possession gate
// (retired-docs:verification/2026-09-23-possession-scheme-v7.md §1, §2).
//
// The proof grant is one row in the V271 transport table
// mfa_reauth_step_ups, extended by V272 with the full tuple (§1.1):
// operation, target_ref, proof_method, proving_factor_id,
// bound_factor_generation, token_scope, refresh_family_id. Unchanged V271
// semantics are preserved: hash-only storage, one live row per user
// (issuance deletes prior rows), the expires_at guard, and single-use
// DELETE ... RETURNING consumption.
//
// Every transaction that issues, consumes, or mutates factor state follows
// the canonical lock order (§2.2): person fence → users row fence → factor
// rows → proof-artifact rows, holding to commit — and runs the durable
// revocation recheck (the IsRevoked watermark semantics of
// shared/threat/denylist.go, mirrored in SQL) after the fence and before
// any state change.
//
// Fail-closed everywhere: any mismatch is a refusal, nothing partial
// commits, and unknown bookkeeping state aborts the transaction.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Operation kinds (§1.3). Typed discriminator constants, never bare strings.
const (
	OperationTOTPEnroll           = "totp.enroll"
	OperationTOTPReplace          = "totp.replace"
	OperationWebAuthnRegister     = "webauthn.register"
	OperationWebAuthnRevoke       = "webauthn.revoke"
	OperationRecoveryRegenerate   = "recovery.regenerate"
	OperationDeviceRegisterNative = "device.register.native"
	OperationBootstrapTOTPEnroll  = "bootstrap.totp.enroll"
)

// sessionScopeOperations are the grant kinds issuable under session scope.
// bootstrap.totp.enroll is mfa_pending-scope only (§3.2 T1 parity).
var sessionScopeOperations = map[string]bool{
	OperationTOTPEnroll:           true,
	OperationTOTPReplace:          true,
	OperationWebAuthnRegister:     true,
	OperationWebAuthnRevoke:       true,
	OperationRecoveryRegenerate:   true,
	OperationDeviceRegisterNative: true,
}

// ValidSessionScopeOperation reports whether operation may be issued under
// session scope (POST /auth/mfa/reauth, POST /auth/mfa/possession/totp,
// assertion begin/finish with a bearer).
func ValidSessionScopeOperation(operation string) bool {
	return sessionScopeOperations[operation]
}

// Proof methods (§1.1): how a grant was earned.
const (
	ProofMethodPassword  = "password"
	ProofMethodTOTP      = "totp"
	ProofMethodWebAuthn  = "webauthn_uv"
	ProofScopeSession    = "session"
	ProofScopeMFAPending = "mfa_pending"
)

// possessionMaxFailures / possessionLockDuration mirror the existing TOTP
// budget constants' values (totp.go: totpMaxFailures / totpLockDuration).
const (
	possessionMaxFailures  = 5
	possessionLockDuration = 15 * time.Minute
)

// GrantStore is the exported tx/pool seam for possession statements.
// Transactions hold the §2.2 fences; the pool is only used by thin wrappers
// that begin one.
type GrantStore interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// possessionStore is the internal alias (every statement below takes it).
type possessionStore = GrantStore

// Grant is the full proof-grant tuple as stored (§1.1).
type Grant struct {
	TokenHash             string
	UserID                int64
	SessionJTI            string
	Operation             string
	TargetRef             *string
	ProofMethod           string
	ProvingFactorID       []byte
	BoundFactorGeneration int64
	TokenScope            string
	RefreshFamilyID       *string
	ExpiresAt             time.Time
}

// grantPredicate names the tuple a peek/consume must match. Zero-value
// members are compared only when Include* is set, so each endpoint states
// exactly the binding it enforces (§1.1 consumption re-validates the FULL
// tuple; nothing partial commits).
type GrantPredicate struct {
	TokenHash     string
	UserID        int64
	SessionJTI    string
	Operation     string
	TargetRef     *string // compared IS NOT DISTINCT FROM when TargetBound
	TargetBound   bool
	TokenScope    string
	RefreshFamily *string // compared IS NOT DISTINCT FROM when FamilyBound
	FamilyBound   bool
}

// ErrGrantRequired is the sentinel for a missing/expired/mismatched grant
// (the typed 403 reauth_required contract).
var ErrGrantRequired = errors.New("possession proof grant required")

// GrantMismatchError marks a present-but-mismatched tuple: per §1.7 the
// refusal DELETES the outstanding grant (GRANT_LIVE gated-arm mismatch →
// DEAD), so the caller can distinguish replay of a dead proof from a
// missing one.
type GrantMismatchError struct{ Reason string }

func (e *GrantMismatchError) Error() string {
	if e == nil || e.Reason == "" {
		return "possession proof grant mismatch"
	}
	return "possession proof grant mismatch: " + e.Reason
}

// --- §2.2 canonical fences ---

// PersonFence acquires identity_auth_person_fence — the per-user advisory
// transaction lock the session-revocation boundary already takes. v4 unified
// the fence: revocation and factor-state work serialize on the SAME lock
// first, so a committed revocation is always visible to a later
// issuance/consumption and vice versa.
func PersonFence(ctx context.Context, q possessionStore, userID int64) error {
	_, err := q.Exec(ctx, `SELECT identity_auth_person_fence($1)`, userID)
	if err != nil {
		return fmt.Errorf("person fence: %w", err)
	}
	return nil
}

// UsersFence locks the users row FOR NO KEY UPDATE (the mode
// ConfirmTOTP/ConfirmTOTPEnrollmentTx already use) and returns the current
// factor_generation. A missing row (deleted user) fails closed.
func UsersFence(ctx context.Context, q possessionStore, userID int64) (generation int64, err error) {
	err = q.QueryRow(ctx,
		`SELECT factor_generation FROM users WHERE id = $1 FOR NO KEY UPDATE`,
		userID,
	).Scan(&generation)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, errors.New("user unavailable for factor work")
		}
		return 0, fmt.Errorf("users fence: %w", err)
	}
	return generation, nil
}

// DurableRevocationRecheck mirrors the EXISTING enforcement semantics of
// SessionDenylist.IsRevoked (shared/threat/denylist.go:82-99) INSIDE the
// issuance/consumption transaction (§2.2). scope='all' is an ISSUANCE-TIME
// WATERMARK: it denies every token whose iat <= not_before (boundary
// inclusive) and denies nothing issued strictly after; a NULL/missing iat
// fails CLOSED. jti/family rows are exact, iat-independent matches.
// family may be "" (mfa_pending scope); iat nil means the claim was absent.
func DurableRevocationRecheck(ctx context.Context, q possessionStore, userID int64, family, jti string, iat *time.Time) (bool, error) {
	var revoked bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM session_revocations
		    WHERE user_id = $1
		      AND (expires_at IS NULL OR expires_at > now())
		      AND (
		            (scope = 'jti'       AND jti = $3)
		            OR (scope = 'family' AND family_id = $2)
		            OR (scope = 'all'
		                AND ($4::timestamptz IS NULL OR $4 <= not_before))
		      )
		 )`,
		userID, family, jti, iat,
	).Scan(&revoked)
	if err != nil {
		return false, fmt.Errorf("durable revocation recheck: %w", err)
	}
	return revoked, nil
}

// --- §1.2 cohort classification ---

// Cohort is the possession-gate cohort classification (§1.2), derived at
// issuance from schema state — never stored, never influenced by attempt
// outcomes.
type Cohort int

const (
	// CohortC1: possession-capable (enabled TOTP or a non-revoked UV-capable
	// credential) — a possession proof is required.
	CohortC1 Cohort = iota
	// CohortC2: factor-holder without UV proof — password step-up grant plus
	// an upgrade prompt. A documented cohort, not a silent pass.
	CohortC2
	// CohortC3: zero-factor — password step-up (the V271 bootstrap contract).
	CohortC3
)

// ClassifyCohort evaluates the cohort INSIDE the caller's transaction (the
// caller holds the §2.2 fences). Read failure fails closed via error.
func ClassifyCohort(ctx context.Context, q possessionStore, userID int64) (Cohort, error) {
	var possessionCapable, hasFactor bool
	err := q.QueryRow(ctx,
		`SELECT COALESCE(u.totp_enabled, FALSE)
		        OR EXISTS (SELECT 1 FROM passkey_credentials pc
		                    WHERE pc.user_id = u.id AND pc.revoked_at IS NULL
		                      AND pc.uv_capable),
		        COALESCE(u.totp_enabled, FALSE)
		        OR COALESCE(u.push_mfa_enabled, FALSE)
		        OR u.webauthn_credentials <> '[]'::jsonb
		        OR EXISTS (SELECT 1 FROM passkey_credentials pc
		                    WHERE pc.user_id = u.id AND pc.revoked_at IS NULL)
		   FROM users u WHERE u.id = $1`,
		userID,
	).Scan(&possessionCapable, &hasFactor)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CohortC3, errors.New("user unavailable for cohort classification")
		}
		return CohortC3, fmt.Errorf("cohort classification: %w", err)
	}
	switch {
	case possessionCapable:
		return CohortC1, nil
	case hasFactor:
		return CohortC2, nil
	default:
		return CohortC3, nil
	}
}

// --- §1.1 grant issuance ---

// reauthTokenEntropy mints a fresh opaque token; only its SHA-256 hash is
// stored (the V271 posture).
func mintReauthToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	return token, ReauthTokenHash(token), nil
}

// ReauthTokenHash is the exported store-side SHA-256 of a presented raw
// token (mirrors the handlers' reauthTokenHash; issuance and consumption
// must hash the same bytes).
func ReauthTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IssueSessionGrant mints a session-scope grant: an opaque reauth_token is
// returned once and only its SHA-256 hash is stored, bound to {user, access
// JTI, refresh family, operation, target, proof method, proving factor, the
// factor_generation observed INSIDE the caller's transaction}. Any prior
// grant rows for the user are deleted first (the one-live-row convention).
func IssueSessionGrant(ctx context.Context, q possessionStore, userID int64, sessionJTI, refreshFamily, operation string, targetRef *string, proofMethod string, provingFactorID []byte, ttl time.Duration) (string, error) {
	// A session claim without a refresh family binds NULL (the §1.1 column
	// contract) — never an empty string, so the NULL-safe consumption
	// comparison compares like with like.
	var family any
	if refreshFamily != "" {
		family = refreshFamily
	}
	token, hash, err := mintReauthToken()
	if err != nil {
		return "", fmt.Errorf("grant token entropy: %w", err)
	}
	if _, err := q.Exec(ctx,
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
	); err != nil {
		return "", fmt.Errorf("grant prior-row cleanup: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'session', $8, now() + make_interval(secs => $9))`,
		hash, userID, sessionJTI, operation, targetRef,
		proofMethod, provingFactorID, family, ttl.Seconds(),
	); err != nil {
		return "", fmt.Errorf("grant insert: %w", err)
	}
	return token, nil
}

// IssueMFAPendingGrant stores an mfa_pending-scope grant whose presentation
// secret IS the presented mfa_token: the hash binding is SHA-256 of exactly
// the bytes the login returned and the client presents (§1.5.1 step 5), so
// issuance and consumption agree by construction and no second secret is
// minted. refresh_family_id is NULL for this scope.
func IssueMFAPendingGrant(ctx context.Context, q possessionStore, userID int64, pendingJTI, mfaTokenHash, operation string, proofMethod string, provingFactorID []byte, ttl time.Duration) error {
	if _, err := q.Exec(ctx,
		`DELETE FROM mfa_reauth_step_ups WHERE user_id = $1`, userID,
	); err != nil {
		return fmt.Errorf("grant prior-row cleanup: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO mfa_reauth_step_ups
		   (token_hash, user_id, session_jti, operation, target_ref,
		    proof_method, proving_factor_id, bound_factor_generation,
		    token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, NULL, $5, $6,
		         (SELECT factor_generation FROM users WHERE id = $2),
		         'mfa_pending', NULL, now() + make_interval(secs => $7))`,
		mfaTokenHash, userID, pendingJTI, operation,
		proofMethod, provingFactorID, ttl.Seconds(),
	); err != nil {
		return fmt.Errorf("grant insert: %w", err)
	}
	return nil
}

// PeekGrant validates a grant WITHOUT consuming it (the begin arms), under
// the caller's fences. The generation equality rides in the same statement
// so the compare happens against the fenced users row.
func PeekGrant(ctx context.Context, q possessionStore, p GrantPredicate) (Grant, error) {
	return queryGrant(ctx, q, peekGrantSQL, p)
}

// $5/$8 are "constrain" flags: when false the target/family member is NOT
// filtered (an unconstrained peek); when true the column must IS-NOT-
// DISTINCT-FROM the bound value (NULL-safe exact match).
const peekGrantSQL = `SELECT token_hash, user_id, session_jti, operation, target_ref,
	       proof_method, proving_factor_id, bound_factor_generation,
	       token_scope, refresh_family_id, expires_at
	  FROM mfa_reauth_step_ups
	 WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
	   AND operation = $4
	   AND ($5 = false OR target_ref IS NOT DISTINCT FROM $6)
	   AND token_scope = $7
	   AND ($8 = false OR refresh_family_id IS NOT DISTINCT FROM $9)
	   AND expires_at > now()
	   AND bound_factor_generation = (SELECT factor_generation FROM users WHERE id = $2)`

const consumeGrantSQL = `DELETE FROM mfa_reauth_step_ups
	 WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
	   AND operation = $4
	   AND ($5 = false OR target_ref IS NOT DISTINCT FROM $6)
	   AND token_scope = $7
	   AND ($8 = false OR refresh_family_id IS NOT DISTINCT FROM $9)
	   AND expires_at > now()
	   AND bound_factor_generation = (SELECT factor_generation FROM users WHERE id = $2)
	 RETURNING token_hash, user_id, session_jti, operation, target_ref,
	           proof_method, proving_factor_id, bound_factor_generation,
	           token_scope, refresh_family_id, expires_at`

func queryGrant(ctx context.Context, q possessionStore, sql string, p GrantPredicate) (Grant, error) {
	// A session claim without a refresh family binds NULL in the grant row;
	// normalize so the NULL-safe comparison compares like with like.
	if p.FamilyBound && p.RefreshFamily != nil && *p.RefreshFamily == "" {
		p.RefreshFamily = nil
	}
	var g Grant
	err := q.QueryRow(ctx, sql,
		p.TokenHash, p.UserID, p.SessionJTI, p.Operation,
		p.TargetBound, p.TargetRef, p.TokenScope,
		p.FamilyBound, p.RefreshFamily,
	).Scan(&g.TokenHash, &g.UserID, &g.SessionJTI, &g.Operation,
		&g.TargetRef, &g.ProofMethod, &g.ProvingFactorID,
		&g.BoundFactorGeneration, &g.TokenScope, &g.RefreshFamilyID,
		&g.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Grant{}, classifyGrantMiss(ctx, q, p)
		}
		return Grant{}, fmt.Errorf("grant lookup: %w", err)
	}
	return g, nil
}

// classifyGrantMiss distinguishes "no row at all" (the plain
// reauth_required answer) from "a row exists but the tuple/generation
// mismatched" — the §1.7 mismatch refusal that DELETES the outstanding
// grant (GRANT_LIVE gated-arm mismatch → DEAD). Both surface as refusals;
// the mismatch variant additionally kills the row so a dead proof can never
// be retried into a different endpoint.
func classifyGrantMiss(ctx context.Context, q possessionStore, p GrantPredicate) error {
	var exact bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM mfa_reauth_step_ups
		    WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
		      AND expires_at > now()
		 )`,
		p.TokenHash, p.UserID, p.SessionJTI,
	).Scan(&exact)
	if err == nil && exact {
		tag, delErr := q.Exec(ctx,
			`DELETE FROM mfa_reauth_step_ups
			  WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3`,
			p.TokenHash, p.UserID, p.SessionJTI)
		if delErr != nil {
			return fmt.Errorf("grant mismatch cleanup: %w", delErr)
		}
		if tag.RowsAffected() > 0 {
			return &GrantMismatchError{Reason: "operation/target/scope/generation mismatch"}
		}
	}
	return ErrGrantRequired
}

// ConsumeGrant is the single-use proof: the DELETE ... RETURNING means
// exactly one concurrent caller can consume a grant; every other caller
// gets zero rows (replay refused). Generation equality is enforced in the
// same statement against the fenced users row.
func ConsumeGrant(ctx context.Context, q possessionStore, p GrantPredicate) (Grant, error) {
	return queryGrant(ctx, q, consumeGrantSQL, p)
}

// BindGrantTarget performs the §1.6 ONE-TIME atomic binding: the
// `target_ref IS NULL` guard under the row lock means exactly one begin can
// bind a given grant. Returns (false, nil) when the grant is already bound
// (the caller applies the resume/409 rules), (false, err) on mismatch/death.
func BindGrantTarget(ctx context.Context, q possessionStore, tokenHash string, userID int64, sessionJTI, targetRef string) (bool, error) {
	var bound string
	err := q.QueryRow(ctx,
		`UPDATE mfa_reauth_step_ups
		    SET target_ref = $4
		  WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
		    AND expires_at > now() AND target_ref IS NULL
		  RETURNING token_hash`,
		tokenHash, userID, sessionJTI, targetRef,
	).Scan(&bound)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguish already-bound (resume/409 territory) from dead grant.
			var live, boundAlready bool
			if err := q.QueryRow(ctx,
				`SELECT EXISTS (
				   SELECT 1 FROM mfa_reauth_step_ups
				    WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
				      AND expires_at > now()
				 ),
				 EXISTS (
				   SELECT 1 FROM mfa_reauth_step_ups
				    WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
				      AND expires_at > now() AND target_ref IS NOT NULL
				 )`,
				tokenHash, userID, sessionJTI,
			).Scan(&live, &boundAlready); err != nil {
				return false, fmt.Errorf("grant binding state: %w", err)
			}
			if live && boundAlready {
				return false, nil
			}
			return false, ErrGrantRequired
		}
		return false, fmt.Errorf("grant binding: %w", err)
	}
	return true, nil
}

// ProvingFactorStillEnabled re-validates the proving factor at consumption
// (§1.1): totp grants require the enabled factor; webauthn_uv grants require
// the proving credential to be non-revoked. password grants have no proving
// factor row.
func ProvingFactorStillEnabled(ctx context.Context, q possessionStore, g Grant) (bool, error) {
	switch g.ProofMethod {
	case ProofMethodTOTP:
		var enabled bool
		err := q.QueryRow(ctx,
			`SELECT COALESCE(totp_enabled, FALSE) FROM users WHERE id = $1`,
			g.UserID,
		).Scan(&enabled)
		if err != nil {
			return false, fmt.Errorf("proving factor check: %w", err)
		}
		return enabled, nil
	case ProofMethodWebAuthn:
		if len(g.ProvingFactorID) == 0 {
			return false, nil
		}
		var live bool
		err := q.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM passkey_credentials
			    WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
			 )`,
			g.ProvingFactorID, g.UserID,
		).Scan(&live)
		if err != nil {
			return false, fmt.Errorf("proving factor check: %w", err)
		}
		return live, nil
	default:
		return true, nil
	}
}

// DeleteGrantsForFactor is the best-effort immediate cleanup a revocation
// path runs in its own transaction (§2.5): outstanding grants proven by the
// revoked credential die with it.
func DeleteGrantsForFactor(ctx context.Context, q possessionStore, userID int64, credentialID []byte) error {
	_, err := q.Exec(ctx,
		`DELETE FROM mfa_reauth_step_ups
		  WHERE user_id = $1 AND proving_factor_id = $2`,
		userID, credentialID,
	)
	if err != nil {
		return fmt.Errorf("grant factor cleanup: %w", err)
	}
	return nil
}

// --- §2.3 failure budgets (password / webauthn_uv; totp stays on its own
// existing users columns) ---

// BudgetState is the persisted counter pair for one possession proof method.
type BudgetState struct {
	FailedAttempts int
	LockedUntil    *time.Time
}

// Locked reports whether the budget is currently locked at time now.
func (s BudgetState) Locked(now time.Time) bool {
	return s.LockedUntil != nil && s.LockedUntil.After(now)
}

// LoadPossessionBudget reads the counter pair for method under the caller's
// users fence. method is ProofMethodPassword or ProofMethodWebAuthn.
func LoadPossessionBudget(ctx context.Context, q possessionStore, method string, userID int64) (BudgetState, error) {
	triesCol, lockCol, err := budgetColumns(method)
	if err != nil {
		return BudgetState{}, err
	}
	var s BudgetState
	err = q.QueryRow(ctx,
		`SELECT COALESCE(`+triesCol+`, 0), `+lockCol+` FROM users WHERE id = $1`,
		userID,
	).Scan(&s.FailedAttempts, &s.LockedUntil)
	if err != nil {
		return BudgetState{}, fmt.Errorf("possession budget load: %w", err)
	}
	return s, nil
}

// RecordPossessionFailure increments the counter for method as ONE atomic
// statement (§2.3 — the specified form; also the repair shape for the
// read-then-write lost update). The WHERE guard means locked refusals never
// increment: when the budget is already locked the statement matches zero
// rows and (false, nil) is returned — a refusal, not a failure increment.
// The caller holds the users fence, so the read-modify cycle serializes.
func RecordPossessionFailure(ctx context.Context, q possessionStore, method string, userID int64) (locked bool, err error) {
	triesCol, lockCol, err := budgetColumns(method)
	if err != nil {
		return false, err
	}
	var attempts int
	var lockedUntil *time.Time
	err = q.QueryRow(ctx,
		`UPDATE users
		    SET `+triesCol+` = `+triesCol+` + 1,
		        `+lockCol+` =
		          CASE WHEN `+triesCol+` + 1 >= $2
		               THEN now() + make_interval(secs => $3)
		               ELSE `+lockCol+` END
		  WHERE id = $1
		    AND (`+lockCol+` IS NULL OR `+lockCol+` <= now())
		  RETURNING `+triesCol+`, `+lockCol,
		userID, possessionMaxFailures, possessionLockDuration.Seconds(),
	).Scan(&attempts, &lockedUntil)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Locked budget (or deleted user — the fence read already refused
			// that): refused bookkeeping, never an increment.
			return true, nil
		}
		return false, fmt.Errorf("possession budget increment: %w", err)
	}
	return lockedUntil != nil, nil
}

// ResetPossessionBudget clears the counter pair for method in the same
// issuance/consumption transaction as the success (§2.3). A reset failure
// rolls the whole transaction back — there is no accepted-alongside-a-reset-
// error state.
func ResetPossessionBudget(ctx context.Context, q possessionStore, method string, userID int64) error {
	triesCol, lockCol, err := budgetColumns(method)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx,
		`UPDATE users SET `+triesCol+` = 0, `+lockCol+` = NULL WHERE id = $1`,
		userID,
	); err != nil {
		return fmt.Errorf("possession budget reset: %w", err)
	}
	return nil
}

func budgetColumns(method string) (tries, lock string, err error) {
	switch method {
	case ProofMethodPassword:
		return "possession_password_failed_attempts", "possession_password_locked_until", nil
	case ProofMethodWebAuthn:
		return "possession_webauthn_failed_attempts", "possession_webauthn_locked_until", nil
	default:
		return "", "", fmt.Errorf("no possession budget columns for proof method %q", method)
	}
}

// --- §1.4 webauthn ceremony store ---

// Ceremony is one live webauthn_ceremonies row (§1.4).
type Ceremony struct {
	ChallengeHash   string
	UserID          int64
	Kind            string // 'registration' | 'management_assertion'
	Operation       string
	TargetRef       *string
	SessionJTI      string
	TokenScope      string
	RefreshFamilyID *string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

// CeremonyTTL mirrors the grant bound: 5 minutes.
const CeremonyTTL = 5 * time.Minute

// CreateCeremony inserts a ceremony row after deleting the user's prior
// same-kind rows (one live ceremony per user+kind; the V250 cleanup
// convention). The caller's transaction holds the §2.2 fences and has
// already validated {cohort, budget, token admission, operation/target}.
func CreateCeremony(ctx context.Context, q possessionStore, c Ceremony) error {
	if _, err := q.Exec(ctx,
		`DELETE FROM webauthn_ceremonies WHERE user_id = $1 AND kind = $2`,
		c.UserID, c.Kind,
	); err != nil {
		return fmt.Errorf("ceremony prior-row cleanup: %w", err)
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO webauthn_ceremonies
		   (challenge_hash, user_id, kind, operation, target_ref,
		    session_jti, token_scope, refresh_family_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))`,
		c.ChallengeHash, c.UserID, c.Kind, c.Operation, c.TargetRef,
		c.SessionJTI, c.TokenScope, c.RefreshFamilyID, CeremonyTTL.Seconds(),
	); err != nil {
		return fmt.Errorf("ceremony insert: %w", err)
	}
	return nil
}

// PeekCeremony returns the user's newest live ceremony row of kind, without
// consuming it. Zero rows → ErrGrantRequired (the reauth_required answer
// names the ceremony-specific remediation).
func PeekCeremony(ctx context.Context, q possessionStore, userID int64, kind, tokenScope, sessionJTI string) (Ceremony, error) {
	var c Ceremony
	err := q.QueryRow(ctx,
		`SELECT challenge_hash, user_id, kind, operation, target_ref,
		        session_jti, token_scope, refresh_family_id, created_at, expires_at
		   FROM webauthn_ceremonies
		  WHERE user_id = $1 AND kind = $2 AND token_scope = $3
		    AND session_jti = $4 AND expires_at > now()
		  ORDER BY created_at DESC
		  LIMIT 1`,
		userID, kind, tokenScope, sessionJTI,
	).Scan(&c.ChallengeHash, &c.UserID, &c.Kind, &c.Operation, &c.TargetRef,
		&c.SessionJTI, &c.TokenScope, &c.RefreshFamilyID, &c.CreatedAt, &c.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Ceremony{}, ErrGrantRequired
		}
		return Ceremony{}, fmt.Errorf("ceremony lookup: %w", err)
	}
	return c, nil
}

// ConsumeCeremony is the single-use ceremony proof (DELETE ... RETURNING):
// one replayed ceremony can never produce two credentials/grants.
func ConsumeCeremony(ctx context.Context, q possessionStore, userID int64, kind, tokenScope, sessionJTI, challengeHash string) (Ceremony, error) {
	var c Ceremony
	err := q.QueryRow(ctx,
		`DELETE FROM webauthn_ceremonies
		  WHERE user_id = $1 AND kind = $2 AND token_scope = $3
		    AND session_jti = $4 AND challenge_hash = $5 AND expires_at > now()
		  RETURNING challenge_hash, user_id, kind, operation, target_ref,
		            session_jti, token_scope, refresh_family_id, created_at, expires_at`,
		userID, kind, tokenScope, sessionJTI, challengeHash,
	).Scan(&c.ChallengeHash, &c.UserID, &c.Kind, &c.Operation, &c.TargetRef,
		&c.SessionJTI, &c.TokenScope, &c.RefreshFamilyID, &c.CreatedAt, &c.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Ceremony{}, ErrGrantRequired
		}
		return Ceremony{}, fmt.Errorf("ceremony consume: %w", err)
	}
	return c, nil
}

// --- §1.6 totp_pending_enrollments ---

// PendingTOTPEnrollment is one staged TOTP enrollment (§1.6): its own UUID,
// the staged secret, and the JTI provenance of the token that ran setup.
type PendingTOTPEnrollment struct {
	ID          string
	UserID      int64
	StagedByJTI string
	StagedVia   string
	ExpiresAt   time.Time
}

// PendingTOTPTTL bounds abandonment: 15 minutes.
const PendingTOTPTTL = 15 * time.Minute

// StagePendingTOTPEnrollment writes the staged secret as its own row
// (AES-encrypted via pgcrypto with the pool's app.encryption_key, the same
// posture as users.totp_secret_enc). Each setup mints a NEW id — repeated
// setup is INSERT ... ON CONFLICT (user_id) DO UPDATE (returning the fresh
// id), so the previous enrollment ID stops resolving the moment a newer
// setup commits ("latest secret wins" is preserved at the storage layer,
// without ever touching the ACTIVE factor).
func StagePendingTOTPEnrollment(ctx context.Context, q possessionStore, userID int64, secret, stagedByJTI, stagedVia string) (string, error) {
	var id string
	err := q.QueryRow(ctx,
		`INSERT INTO totp_pending_enrollments
		   (user_id, secret_enc, staged_by_jti, staged_via, expires_at)
		 VALUES ($1, pgp_sym_encrypt($2, current_setting('app.encryption_key')),
		         $3, $4, now() + make_interval(secs => $5))
		 ON CONFLICT (user_id) DO UPDATE
		    SET id = gen_random_uuid(),
		        secret_enc = EXCLUDED.secret_enc,
		        staged_by_jti = EXCLUDED.staged_by_jti,
		        staged_via = EXCLUDED.staged_via,
		        created_at = now(),
		        expires_at = EXCLUDED.expires_at
		 RETURNING id`,
		userID, secret, stagedByJTI, stagedVia, PendingTOTPTTL.Seconds(),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("stage pending totp: %w", err)
	}
	return id, nil
}

// ReadPendingTOTPEnrollment fetches the live pending row for the confirm
// arm, secret decrypted. Identity is the full tuple {id, user,
// staged_by_jti}: every stale combination (old grant/new ID, dead ID,
// another session's staging) refuses by construction.
func ReadPendingTOTPEnrollment(ctx context.Context, q possessionStore, userID int64, id, stagedByJTI string) (secret string, p PendingTOTPEnrollment, err error) {
	err = q.QueryRow(ctx,
		`SELECT id, user_id, staged_by_jti, staged_via, expires_at,
		        pgp_sym_decrypt(secret_enc::bytea, current_setting('app.encryption_key'))
		   FROM totp_pending_enrollments
		  WHERE id = $1 AND user_id = $2 AND staged_by_jti = $3 AND expires_at > now()`,
		id, userID, stagedByJTI,
	).Scan(&p.ID, &p.UserID, &p.StagedByJTI, &p.StagedVia, &p.ExpiresAt, &secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", PendingTOTPEnrollment{}, ErrGrantRequired
		}
		return "", PendingTOTPEnrollment{}, fmt.Errorf("pending totp lookup: %w", err)
	}
	return secret, p, nil
}

// DeletePendingTOTPEnrollment removes the staged row (cancellation or the
// promotion's in-tx delete). Deleting it — or letting expires_at lapse —
// leaves the ACTIVE factor untouched (§2.2: the repair of today's
// overwrite-on-setup behavior).
func DeletePendingTOTPEnrollment(ctx context.Context, q possessionStore, userID int64, id string) error {
	_, err := q.Exec(ctx,
		`DELETE FROM totp_pending_enrollments WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("delete pending totp: %w", err)
	}
	return nil
}
