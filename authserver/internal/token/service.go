// Package token provides token lifecycle management for the auth server.
//
// TokenService is the cohesive owner of the first-party token lifecycle —
// issue, validate, introspect, refresh, and revoke. It composes the signing
// core (JWTProvider, which still owns sign()/Validate() and the ADR-005 KeySet
// dual-verify) with the DB token store (oauth_tokens). Callers that previously
// reached for the package-level token functions go through the service instead,
// so there is exactly ONE place a first-party token is revoked.
package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/toggle"
)

// TokenService owns the first-party token lifecycle. It wraps the signing core
// (*JWTProvider) and the oauth_tokens store (*pgxpool.Pool), and is the single
// seam through which tokens are issued, validated, introspected, refreshed, and
// revoked.
//
// Revocation unification (deliverable 2): every path that revokes a first-party
// token — the RFC 7009 /auth/revoke handler, refresh-token reuse-detection, and
// the logout/password-change/SCIM flows — funnels through this type's
// Revoke* methods, which are the only callers of the revoke SQL primitives in
// refresh.go. No handler re-implements the revoke SQL.
type TokenService struct {
	jwt     *JWTProvider
	pool    *pgxpool.Pool
	toggles *toggle.FeatureFlags
}

// NewTokenService composes the signing core with the oauth_tokens store.
// toggles gates the feature.user_risk risk-claim propagation in the refresh path;
// nil toggles is safe (feature treated as off).
func NewTokenService(jwt *JWTProvider, pool *pgxpool.Pool, toggles *toggle.FeatureFlags) *TokenService {
	return &TokenService{jwt: jwt, pool: pool, toggles: toggles}
}

// JWT exposes the signing/validation core for callers that still need the
// provider directly (issuance sites in the handlers, middleware). The KeySet /
// ES256 dual-verify (ADR-005) lives entirely inside JWTProvider and is reached
// only through it — the service never re-implements signing or verification.
func (s *TokenService) JWT() *JWTProvider { return s.jwt }

// Pool exposes the underlying oauth_tokens store for the few read paths (e.g.
// introspection options) that need it; mutations go through the methods below.
func (s *TokenService) Pool() *pgxpool.Pool { return s.pool }

// ── Validate / Introspect (read) ──────────────────────────────────────────

// Validate parses and verifies a JWT (signature, issuer, audience), delegating
// to the signing core. ADR-005 ES256 dual-verify is preserved exactly.
func (s *TokenService) Validate(tokenStr string) (*Claims, error) {
	return s.jwt.Validate(tokenStr)
}

// Introspect returns the RFC 7662 field set for a token held in oauth_tokens.
// Unknown/revoked/expired/disabled tokens yield {active:false} (no oracle).
func (s *TokenService) Introspect(ctx context.Context, tokenStr string, opts IntrospectOptions) (*IntrospectResponse, error) {
	return Introspect(ctx, s.pool, tokenStr, opts)
}

// ── Issue (new-session mint — the seven login-shaped flows) ──────────────

// IssueInput carries every input Issue needs, made EXPLICIT — the former
// issueTokensWithFactors consumed some of these via a request-context stash
// (caLoginExtras). HTTP-flow concerns (cookie persistence, sign-in recording,
// the fail-closed domain-scope resolution) stay with the HTTP adapter; this
// struct is the resolved result of those, not the request.
type IssueInput struct {
	UserID  int64
	Email   string
	IsAdmin bool

	// Factors are the RFC 8176 AMR codes the session satisfied (pwd/otp/hwk/…).
	// The access token's acr/amr are derived inside Issue via
	// jwtutil.AuthContextFromFactors (incl. the mfa/aal2 marker at ≥2 factors).
	Factors []string

	// Optional claims, resolved by the caller. DomainScope resolution is
	// FAIL-CLOSED at the caller (permissions.MintDomainScope error ⇒ no token);
	// Issue never substitutes a global scope.
	Device      *jwtutil.DeviceClaim
	Risk        *jwtutil.RiskClaim
	DomainScope *int64

	// CA-3a extras: cnf (token-binding) and sif (sign-in frequency, seconds).
	// Nil values are omitted from the JWT (omitempty) — byte-compatible with a
	// mint that never had them.
	Cnf *jwtutil.ConfirmationClaim
	SIF *int64

	// AccountType is the minted acct claim ("" = member,
	// jwtutil.AccountTypeGuest = guest) — derived by the caller from the
	// guest_accounts satellite via is_guest_account(), never from request input.
	AccountType string
}

// IssueResult is the minted pair. ExpiresIn is the access-token TTL in seconds
// (what the HTTP layer reports as expires_in and uses for the cookie Max-Age).
type IssueResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

// ErrIssueStore marks a failure persisting the refresh-token row (as opposed to
// a signing/mint failure), so the HTTP adapter keeps its distinct 500 details.
var ErrIssueStore = errors.New("refresh token store failed")

// Issue mints an access+refresh pair for a NEW session — the single issuance
// seam behind the seven login-shaped flows (password login, SSO, TOTP, backup
// code, device MFA-approve, WebAuthn, push) — and persists the refresh token's
// oauth_tokens row WITH its family_id: the same UUID the refresh JWT carries as
// its fam claim, generated once here so the persisted family can never drift
// from the claim. previous_token_hash is NULL on this row by design — it IS the
// family anchor; rotation (refresh.go issueAndStore) reads the parent's
// family_id and inherits it, so the whole chain stays anchored to the login.
// (Before this seam existed, the login-path insert dropped family_id entirely:
// the anchor row had NULL family, hop one started a fresh family, and the
// JWT's login-minted fam claim was never persisted.)
func (s *TokenService) Issue(ctx context.Context, in IssueInput) (*IssueResult, error) {
	return s.issue(ctx, s.pool, in)
}

// IssueTx is Issue with refresh-family persistence bound to a caller-owned
// transaction. Identity admission callers use it while holding the same
// per-person database fence as authority transitions, so the admission check
// and token anchor cannot be separated by a transition commit.
func (s *TokenService) IssueTx(ctx context.Context, tx pgx.Tx, in IssueInput) (*IssueResult, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: nil issuance transaction", ErrIssueStore)
	}
	return s.issue(ctx, tx, in)
}

func (s *TokenService) issue(ctx context.Context, store db, in IssueInput) (*IssueResult, error) {
	authCtx := jwtutil.AuthContextFromFactors(in.Factors...)
	var authTime *int64
	if in.SIF != nil {
		value := time.Now().Unix()
		authTime = &value
	}
	familyID := uuid.New().String()
	// IssueAccessCA with nil cnf/sif is byte-compatible with IssueAccessFull
	// (omitempty), so all seven flows share this one mint call.
	access, err := s.jwt.IssueAccessCAFamilySession(in.UserID, in.Email, in.IsAdmin, in.Device, nil, in.Risk, in.DomainScope, authCtx, in.Cnf, in.SIF, authTime, familyID, in.AccountType)
	if err != nil {
		return nil, err
	}

	// The refresh token also carries cnf (not just the access token) so rotation
	// (refresh.go issueAndStore) can read the bound jkt back off THIS token's own
	// claims and keep the whole chain bound — see IssueRefreshWithFamilyAndCnf.
	refresh, err := s.jwt.IssueRefreshWithFamilySession(
		in.UserID, in.Email, familyID, in.Cnf, in.Device, in.SIF, authTime,
	)
	if err != nil {
		return nil, err
	}

	if _, err := store.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', now() + make_interval(secs => $3), $4::uuid)`,
		in.UserID, tokenHash(refresh), int64(s.jwt.RefreshExpiry().Seconds()), familyID,
	); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIssueStore, err)
	}

	return &IssueResult{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int64(s.jwt.AccessExpiry().Seconds()),
	}, nil
}

// ── Refresh (rotate) ──────────────────────────────────────────────────────

// Refresh validates, rotates, and re-issues a refresh token. On suspicious
// reuse it revokes every token for the user — through this same service's
// revoke primitive (see refresh.go), so reuse-detection shares the one
// revocation seam.
func (s *TokenService) Refresh(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	return RefreshTokens(ctx, s.pool, s.jwt, s.toggles, refreshToken)
}

// ── Revoke (the unified seam — deliverable 2) ─────────────────────────────

// RevokeByToken revokes the single oauth_tokens row matching the presented
// token string, scoped to the authenticated OAuth client (RFC 7009 §2.1). It is
// the by-token revocation entry point shared by the /auth/revoke handler.
// Idempotent; never widens what is revoked beyond the client's own (or
// NULL-client) tokens.
func (s *TokenService) RevokeByToken(ctx context.Context, tokenStr, clientID string) error {
	return RevokeByToken(ctx, s.pool, tokenStr, clientID)
}

// RevokeAllForUser revokes every active token for a user (logout, refresh
// reuse-detection, SCIM disable).
func (s *TokenService) RevokeAllForUser(ctx context.Context, userID int64) error {
	_, err := RevokeAndNotifyTx(ctx, s.pool, userID, 0, "token_revoke_all")
	return err
}

// RevokeAllForUserTx revokes every active token for a user inside an existing
// transaction (password change / forgot-password reset, which revoke atomically
// with the password write).
func (s *TokenService) RevokeAllForUserTx(ctx context.Context, tx pgx.Tx, userID int64) error {
	_, err := revokeAndNotifyExistingTx(ctx, tx, userID, 0, "credential_change")
	return err
}
