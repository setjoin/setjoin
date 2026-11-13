// Package token provides token lifecycle management for the auth server.
// This file implements refresh token rotation with theft detection.
package token

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
)

// db is a minimal querier interface satisfied by both *pgxpool.Pool and pgx.Tx.
type db interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const rotationGrace = 30 * time.Second

// RefreshResult contains the tokens issued after a refresh rotation.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

// RefreshTokens validates the refresh JWT, checks the oauth_tokens table,
// rotates the token (marks old row rotated_at, inserts new with previous_token_hash),
// and issues a new access+refresh pair.
//
// Grace window: if the token was rotated within the last 30 seconds the request
// is treated as a client retry rather than theft. All tokens are preserved and a
// fresh pair is issued from the current valid token in the chain.
// readRisk reads user_risk for userID and maps it to a JWT Risk claim.
// Nil toggles or a disabled toggle returns nil (fail-open: never blocks issuance).
// ponytail: used by both refresh branches before issueAndStore; a read error is
// fail-open (scorer hiccup must not prevent token rotation).
func readRisk(ctx context.Context, pool *pgxpool.Pool, toggles *toggle.FeatureFlags, userID int64) *jwtutil.RiskClaim {
	if toggles == nil || !toggles.IsEnabled(toggle.FeatureUserRisk) {
		return nil
	}
	var score int
	var level string
	var signalsJSON []byte
	err := dbscope.RunUserScoped(ctx, pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT score, level, signals FROM user_risk WHERE user_id = $1`, userID,
		).Scan(&score, &level, &signalsJSON)
	})
	if err != nil {
		return nil // no row or transient error: fail-open
	}
	var signals []string
	json.Unmarshal(signalsJSON, &signals) //nolint:errcheck
	return threat.RiskFromRow(score, level, signals)
}

func RefreshTokens(ctx context.Context, pool *pgxpool.Pool, jwt *JWTProvider, toggles *toggle.FeatureFlags, refreshToken string) (*RefreshResult, error) {
	claims, err := jwt.Validate(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	if claims.Type != TypeRefresh {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	hash := tokenHash(refreshToken)

	// Begin transaction; FOR UPDATE serializes concurrent refreshes of the
	// same token so at most one request creates a successor.
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("transaction start failed: %w", err)
	}
	defer tx.Rollback(ctx) // no-op if already committed or rolled back

	// Every refresh rotation publishes a new credential anchor. Acquire the
	// per-person mint fence before any oauth_tokens row lock so a concurrent
	// all-session revocation has one total order with both the parent rotation
	// and successor insert.
	if _, err := tx.Exec(ctx,
		`SELECT identity_auth_person_fence($1)`,
		claims.UserID,
	); err != nil {
		slog.ErrorContext(ctx, "refresh token mint fence failed",
			"user_id", claims.UserID, "err", err)
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	var rotatedAt *time.Time
	var revokedAt *time.Time
	var expiresAt time.Time
	var tokenUserID int64
	err = tx.QueryRow(ctx,
		`SELECT user_id, expires_at, revoked_at, rotated_at
		 FROM oauth_tokens WHERE token_hash = $1 FOR UPDATE`,
		hash,
	).Scan(&tokenUserID, &expiresAt, &revokedAt, &rotatedAt)

	if err != nil {
		tx.Rollback(ctx)
		var successorExists bool
		pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM oauth_tokens WHERE previous_token_hash = $1 AND revoked_at IS NULL)`,
			hash,
		).Scan(&successorExists)
		if successorExists {
			RevokeAllTokens(ctx, pool, claims.UserID)
			return nil, fmt.Errorf("suspicious token reuse detected — all tokens revoked")
		}
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	// A valid signed token and its durable anchor must name the same principal.
	// Treat any mismatch as integrity corruption, revoke that exact anchor, and
	// fail closed without issuing a successor or revealing which side differed.
	if tokenUserID != claims.UserID {
		slog.ErrorContext(ctx, "refresh token principal mismatch",
			"claim_user_id", claims.UserID, "anchor_user_id", tokenUserID)
		if _, err := tx.Exec(ctx,
			`UPDATE oauth_tokens
			    SET revoked_at=COALESCE(revoked_at,statement_timestamp())
			  WHERE token_hash=$1`,
			hash,
		); err != nil {
			return nil, fmt.Errorf("refresh token revoked or expired")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("refresh token revoked or expired")
		}
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	var admissionAllowed bool
	if err := tx.QueryRow(ctx,
		`SELECT identity_transition_admission_allowed($1)`,
		claims.UserID,
	).Scan(&admissionAllowed); err != nil || !admissionAllowed {
		if err != nil {
			slog.ErrorContext(ctx, "refresh identity admission check failed",
				"user_id", claims.UserID, "err", err)
		}
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	// Grace window: token was rotated recently — likely a client retry.
	// Keep the transaction; lock the successor row with FOR UPDATE to serialize
	// concurrent grace-window requests so at most one successor is created.
	if rotatedAt != nil {
		if time.Since(*rotatedAt) <= rotationGrace {
			var successorHash []byte
			var successorUserID int64
			var successorEmail string
			var successorAdmin bool
			var successorEnabled bool
			var successorGuest bool
			// is_admin DERIVED from a governed, unexpired admin_role_assignments row,
			// NOT the vestigial users.is_admin column (BUG 003 / RBAC cut-over) — so a
			// refreshed access token reflects the user's current governed admin status,
			// matching the mint-path derivation in handlers (isAdminExprSQL) and the
			// gateway's chain.go enforcement. FOR UPDATE locks the oauth_tokens row
			// only (the EXISTS subquery is a read; refresh tokens carry no aggregate).
			// u.enabled is checked below (BUG: a disabled/suspended user's refresh
			// chain previously rotated forever — nothing on this path consulted
			// users.enabled, so any admin/SCIM disable of a live session left it
			// working indefinitely).
			successorErr := tx.QueryRow(ctx,
				`SELECT ot.token_hash, u.id, u.email,
				        EXISTS(SELECT 1 FROM admin_role_assignments ara
				                WHERE ara.user_id = u.id
				                  AND (ara.expires_at IS NULL OR ara.expires_at > now())),
				        u.enabled,
				        is_guest_account(u.id)
				 FROM oauth_tokens ot
				 JOIN users u ON u.id = ot.user_id
				 WHERE ot.family_id::text = $1 AND ot.rotated_at IS NULL
				   AND ot.revoked_at IS NULL AND ot.expires_at > now()
				 ORDER BY ot.id DESC
				 LIMIT 1
				 FOR UPDATE OF ot`,
				claims.FamilyID,
			).Scan(&successorHash, &successorUserID, &successorEmail, &successorAdmin, &successorEnabled, &successorGuest)
			if successorErr == nil && successorUserID != tokenUserID {
				slog.ErrorContext(ctx, "refresh successor principal mismatch",
					"parent_user_id", tokenUserID,
					"successor_user_id", successorUserID)
				return nil, fmt.Errorf("refresh token revoked or expired")
			}
			if successorErr == nil && !successorEnabled {
				// Refuse rotation for a disabled user. Revoke the family and return
				// the SAME error shape as an invalid/expired token — no oracle that
				// would let a client distinguish "disabled" from "invalid".
				tx.Rollback(ctx)
				RevokeAllTokens(ctx, pool, successorUserID)
				return nil, fmt.Errorf("refresh token revoked or expired")
			}
			if successorErr == nil {
				// The re-issue must extend the CURRENT chain tip, not fork it.
				// Passing the PARENT hash here inserted a SECOND active child of
				// the same parent on every grace-window retry — two live refresh
				// chains from one presentation (refresh-token-grace-successor-fork).
				// The successor row is locked FOR UPDATE above, so: mark it rotated
				// and mint the fresh pair as ITS successor (previous_token_hash =
				// successor hash). The family stays linear, reuse detection still
				// fires once the grace window closes, and CleanupRotatedTokens reaps
				// the superseded hop like any other rotation.
				if _, err := tx.Exec(ctx,
					`UPDATE oauth_tokens SET rotated_at = now() WHERE token_hash = $1`,
					successorHash,
				); err != nil {
					return nil, fmt.Errorf("grace successor rotation failed: %w", err)
				}
				risk := readRisk(ctx, pool, toggles, successorUserID)
				result, err := issueAndStore(
					ctx, tx, jwt, successorUserID, successorEmail, successorAdmin,
					accountTypeFor(successorGuest), successorHash, risk, claims.Cnf,
					claims.Device, claims.SignInFreq, claims.SessionAuthTime,
				)
				if err != nil {
					return nil, err
				}
				pwhash.LogAuthEvent(ctx, pool, pwhash.AuthEvent{
					UserID: &successorUserID, Event: "login", Provider: "jwt", Email: successorEmail,
				}, nil)
				if err := tx.Commit(ctx); err != nil {
					return nil, fmt.Errorf("commit failed: %w", err)
				}
				return result, nil
			}
		}
		tx.Rollback(ctx)
		RevokeAllTokens(ctx, pool, claims.UserID)
		return nil, fmt.Errorf("suspicious token reuse detected — all tokens revoked")
	}

	// Normal path: under FOR UPDATE lock. Verify active, then atomically
	// rotate + insert successor.
	if revokedAt != nil || expiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	var email string
	var isAdmin bool
	var enabled bool
	var isGuest bool
	// is_admin DERIVED from a governed, unexpired admin_role_assignments row (BUG
	// 003 / RBAC cut-over) — see the grace-window branch above. enabled is
	// checked below (see the enabled note in the grace-window branch above).
	if err := tx.QueryRow(ctx,
		`SELECT email,
		        EXISTS(SELECT 1 FROM admin_role_assignments ara
		                WHERE ara.user_id = users.id
		                  AND (ara.expires_at IS NULL OR ara.expires_at > now())),
		        enabled,
		        is_guest_account(users.id)
		 FROM users WHERE id = $1`,
		tokenUserID,
	).Scan(&email, &isAdmin, &enabled, &isGuest); err != nil {
		return nil, fmt.Errorf("user lookup failed: %w", err)
	}

	if !enabled {
		// Refuse rotation for a disabled user. Revoke the family and return the
		// SAME error shape an invalid/expired refresh token gets — no oracle.
		tx.Rollback(ctx)
		RevokeAllTokens(ctx, pool, tokenUserID)
		return nil, fmt.Errorf("refresh token revoked or expired")
	}

	tx.Exec(ctx, `UPDATE oauth_tokens SET rotated_at = now() WHERE token_hash = $1`, hash)

	risk := readRisk(ctx, pool, toggles, tokenUserID)
	result, err := issueAndStore(
		ctx, tx, jwt, tokenUserID, email, isAdmin, accountTypeFor(isGuest),
		hash, risk, claims.Cnf, claims.Device, claims.SignInFreq,
		claims.SessionAuthTime,
	)
	if err != nil {
		return nil, err
	}
	pwhash.LogAuthEvent(ctx, pool, pwhash.AuthEvent{
		UserID: &tokenUserID, Event: "login", Provider: "jwt", Email: email,
	}, nil)

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit failed: %w", err)
	}
	return result, nil
}

// issueAndStore mints a new access+refresh pair and persists the refresh token.
// It reads the parent token's family_id from oauth_tokens (added in Task 3,
// V025; inert uuid column) and threads it into the successor token + DB row,
// keeping the entire rotation chain in a single refresh family (CA-3 substrate;
// no enforcement here — CA-3 consumes it for live revocation).
//
// cnf is the CA-3a token-binding claim read off the PRESENTED refresh token's
// own (already-validated) claims by the two RefreshTokens call sites — not
// re-derived here. Re-embedding it into both the new access token and the
// successor refresh token is the fix for a real gap: without it, a
// DPoP-bound session silently became unbound on its first refresh (the access
// token's cnf just... stopped being there, and nothing downstream noticed
// because verification is opt-in/report_only today — see feature.cae_runtime).
func issueAndStore(
	ctx context.Context,
	conn db,
	jwt *JWTProvider,
	userID int64,
	email string,
	isAdmin bool,
	accountType string,
	prevHash []byte,
	risk *jwtutil.RiskClaim,
	cnf *jwtutil.ConfirmationClaim,
	device *jwtutil.DeviceClaim,
	sif, authTime *int64,
) (*RefreshResult, error) {
	// Read the parent's family_id so rotation inherits it.
	// A real DB error (not just a missing/NULL row) is logged at warn level;
	// control flow is unchanged — we fall through to a fresh family either way.
	var parentFamily *string
	if err := conn.QueryRow(ctx,
		`SELECT family_id::text FROM oauth_tokens WHERE token_hash = $1`,
		prevHash,
	).Scan(&parentFamily); err != nil {
		// pgx.ErrNoRows is unexpected here (prevHash was just validated under
		// FOR UPDATE lock) but is harmless — a fresh family will be generated.
		// Any other error (connection drop, schema change) is surfaced as a warn
		// so it doesn't silently masquerade as a legitimate NULL-family case.
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.WarnContext(ctx, "issueAndStore: parent family_id scan failed; starting fresh family",
				"err", err)
		}
	}

	if sif != nil && authTime == nil {
		// Compatibility for a refresh token minted during a rolling upgrade:
		// preserve the oldest time that token can prove instead of resetting the
		// SIF window at rotation.
		value := time.Now().Unix()
		authTime = &value
	}
	// Determine the family for the successor: inherit from parent, or generate
	// a fresh UUID here (before calling IssueRefreshWithFamily) so the same
	// value is passed to the access JWT, refresh JWT, and DB row — no
	// sign→parse round-trip and no family-revocation blind spot.
	var newFamily string
	if parentFamily != nil && *parentFamily != "" {
		newFamily = *parentFamily
	} else {
		newFamily = uuid.New().String()
	}

	accessToken, err := jwt.IssueAccessCAFamilySession(
		userID, email, isAdmin, device, nil, risk, nil, AuthContext{},
		cnf, sif, authTime, newFamily, accountType,
	)
	if err != nil {
		return nil, err
	}

	newRefresh, err := jwt.IssueRefreshWithFamilySession(
		userID, email, newFamily, cnf, device, sif, authTime,
	)
	if err != nil {
		return nil, err
	}

	_, err = conn.Exec(ctx,
		`INSERT INTO oauth_tokens (user_id, token_hash, token_type, previous_token_hash, expires_at, family_id)
		 VALUES ($1, $2, 'refresh', $3, now() + make_interval(secs => $4), $5::uuid)`,
		userID, tokenHash(newRefresh), prevHash, jwt.refreshExpiry.Seconds(), newFamily,
	)
	if err != nil {
		return nil, err
	}
	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		ExpiresIn:    int64(jwt.accessExpiry.Seconds()),
	}, nil
}

// RevokeAllTokens revokes every active token for a user.
func RevokeAllTokens(ctx context.Context, pool *pgxpool.Pool, userID int64) error {
	_, err := RevokeAndNotifyTx(ctx, pool, userID, 0, "token_revoke_all")
	return err
}

// RevokeByToken revokes the single oauth_tokens row matching the presented
// token string (access or refresh), looked up by its SHA-256 hash. It is the
// RFC 7009 revocation primitive: idempotent (revoking an already-revoked or
// unknown token is a no-op and not an error), and it never reveals whether the
// token existed. token_type_hint is intentionally ignored — the hash lookup is
// type-agnostic, so a wrong or absent hint cannot prevent revocation.
//
// clientID is the authenticated requesting client. Per RFC 7009 §2.1 the
// authorization server MUST verify that the token was issued to the client
// making the revocation request: the UPDATE only matches rows whose client_id
// equals clientID, so a client cannot revoke another client's tokens. Rows with
// a NULL client_id (tokens minted with no OAuth client — e.g. the internal API
// key / first-party flows) are revocable by any authenticated caller, since
// there is no owning client to scope them to. Passing an empty clientID (the
// internal-API-key caller, which is not an OAuth client) likewise only reaches
// the NULL-client rows. The cross-client mismatch stays a no-op, preserving
// idempotency and the no-oracle guarantee.
func RevokeByToken(ctx context.Context, pool *pgxpool.Pool, token, clientID string) error {
	var client any
	if clientID != "" {
		client = clientID
	}
	_, err := pool.Exec(ctx,
		`UPDATE oauth_tokens SET revoked_at = now()
		 WHERE token_hash = $1 AND revoked_at IS NULL
		 AND (client_id = $2 OR client_id IS NULL)`, tokenHash(token), client)
	return err
}

// revokeAndNotifyExistingTx applies the complete all-session revocation boundary
// inside a caller-owned transaction. Password changes and recovery resets use
// this form so the credential write, OAuth revocation, CAE denylist event,
// pending identity-link elevation invalidation, and runtime-session cleanup
// either commit together or all roll back.
func revokeAndNotifyExistingTx(
	ctx context.Context,
	tx pgx.Tx,
	userID, createdBy int64,
	reason string,
) (int64, error) {
	// NULL createdBy = system/self; 0 is not a valid user_id.
	var createdByArg any
	if createdBy != 0 {
		createdByArg = createdBy
	}
	var id int64
	if err := tx.QueryRow(ctx,
		`SELECT revoke_user_sessions($1, 'all', $2, $3, NULL, NULL)`,
		userID, reason, createdByArg,
	).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// RevokeAndNotifyTx revokes all OAuth tokens for a user AND records the CAE
// critical-event in one transaction: oauth_tokens.revoked_at flip + a
// session_revocations(scope='all') row + the fixed 'session_revoke' app_notify
// (so the gateway denylist and open WS tabs cut the session in near-real-time).
// Returns the new revocation id. createdBy is the admin actor (0 ⇒ system/self).
func RevokeAndNotifyTx(ctx context.Context, pool *pgxpool.Pool, userID, createdBy int64, reason string) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	id, err := revokeAndNotifyExistingTx(ctx, tx, userID, createdBy, reason)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return id, nil
}

// CleanupRotatedTokens deletes rotated token rows older than twice the grace window.
// Call periodically (e.g. every minute) from a background goroutine.
func CleanupRotatedTokens(ctx context.Context, pool *pgxpool.Pool) {
	pool.Exec(ctx,
		`DELETE FROM oauth_tokens WHERE rotated_at IS NOT NULL AND rotated_at < now() - make_interval(secs => $1)`,
		int64((2 * rotationGrace).Seconds()))
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// HashTokenHex returns the hex-encoded SHA-256 hash of a token string.
// Used for single-use token replay prevention.
func HashTokenHex(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// accountTypeFor maps the is_guest_account() satellite fact to the minted
// acct claim value ("" for members — omitempty keeps member tokens
// byte-identical to pre-G0 mints).
func accountTypeFor(isGuest bool) string {
	if isGuest {
		return jwtutil.AccountTypeGuest
	}
	return ""
}
