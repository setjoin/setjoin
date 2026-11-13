package federation

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/envutil"
)

// oidcTokenStore owns every read and mutation of the oidc_tokens table for the
// OP (Wave 3 split of the OPStorage god-object). It is the single seam through
// which OIDC access/refresh tokens are created, rotated, looked up, and
// REVOKED — so the OP's revocation path no longer re-implements token SQL
// inline. The zitadel op.Storage token methods on OPStorage delegate here
// verbatim, preserving behavior exactly.
//
// (oidc_tokens is a distinct table from oauth_tokens — the first-party token
// store owned by TokenService. The two stores serve different protocols; this
// type is the OIDC-side equivalent single revoke owner.)
type oidcTokenStore struct {
	pool *pgxpool.Pool
}

func newOIDCTokenStore(pool *pgxpool.Pool) *oidcTokenStore {
	return &oidcTokenStore{pool: pool}
}

// oidcRefreshTokenTTL is the refresh token's own lifetime — deliberately NOT
// the same value as the access token's expires_at (5 min, createAccessToken
// below): a refresh token exists precisely so a client can mint a new access
// token after the short one expires, so its clock must be independent.
// Mirrors the first-party JWTRefreshExpiry default (720h/30d, config.go).
const oidcRefreshTokenTTL = 30 * 24 * time.Hour

// createAccessToken inserts a new access token row (5-minute TTL) and returns
// its id + expiry. Delegates to the querier-parameterized form so the rotation
// transaction reuses the exact same insert.
func (s *oidcTokenStore) createAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	return s.createAccessTokenOn(ctx, s.pool, request)
}

// createAccessAndRefreshTokens mints an access token, attaches a fresh refresh
// token hash, and rotates (revokes) the presented refresh token.
//
// The rotation is ATOMIC under a row lock on the presented refresh token's
// anchor row (SELECT ... FOR UPDATE inside one transaction): two concurrent
// refreshes with the same refresh token serialize, and the loser finds its row
// already revoked and fails instead of minting a parallel successor. The
// previous best-effort, autocommit UPDATE (revocation error ignored, no lock,
// no transaction) let both requests through tokenRequestByRefreshToken's
// revoked_at IS NULL read and mint two live successors from one presented
// token — concurrent replay with zero detection.
func (s *oidcTokenStore) createAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	// Fresh grant (no refresh token to rotate): no contention window.
	if currentRefreshToken == "" {
		r := s.createAccessAndRefreshInTx(ctx, s.pool, request, "")
		if r.err != nil {
			return "", "", time.Time{}, r.err
		}
		return r.accessID, r.refreshToken, r.expiry, nil
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer tx.Rollback(ctx)

	oldHash := sha256Hex(currentRefreshToken)
	// Lock the presented token's anchor row. A missing/unexpired-checked row
	// (unknown, revoked, or refresh-expired) means the token must not rotate:
	// either a stale token or a concurrent winner already revoked it.
	var lockedID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM oidc_tokens
		 WHERE refresh_token_hash = $1 AND user_id = $2
		 AND revoked_at IS NULL AND refresh_expires_at > now()
		 LIMIT 1
		 FOR UPDATE`,
		oldHash, request.GetSubject(),
	).Scan(&lockedID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", time.Time{}, fmt.Errorf("refresh token no longer active: %w", op.ErrInvalidRefreshToken)
		}
		return "", "", time.Time{}, fmt.Errorf("lock refresh token: %w", err)
	}

	result := s.createAccessAndRefreshInTx(ctx, tx, request, oldHash)
	if err := result.err; err != nil {
		return "", "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", time.Time{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	return result.accessID, result.refreshToken, result.expiry, nil
}

// rotationResult carries the minted token identifiers out of
// createAccessAndRefreshInTx.
type rotationResult struct {
	accessID     string
	refreshToken string
	expiry       time.Time
	err          error
}

// createAccessAndRefreshInTx performs the mint + attach + revoke steps on the
// given querier (the pooled pool for a fresh grant, or the rotation
// transaction). oldHash is empty when there is no predecessor to revoke; the
// revocation UPDATE's result is CHECKED — a failed revocation must abort the
// grant, never silently leave the predecessor active.
func (s *oidcTokenStore) createAccessAndRefreshInTx(ctx context.Context, q dbQuerier, request op.TokenRequest, oldHash string) rotationResult {
	accessID, exp, err := s.createAccessTokenOn(ctx, q, request)
	if err != nil {
		return rotationResult{err: err}
	}

	refreshToken := hex32()
	refreshHash := sha256Hex(refreshToken)

	if _, err := q.Exec(ctx,
		`UPDATE oidc_tokens SET refresh_token_hash = $2, refresh_expires_at = $3 WHERE id = $1`,
		accessID, refreshHash, time.Now().Add(oidcRefreshTokenTTL),
	); err != nil {
		return rotationResult{err: fmt.Errorf("set refresh hash: %w", err)}
	}

	// Refresh token rotation: revoke the old refresh token for this subject.
	// Same transaction, same lock — the predecessor can never stay active
	// alongside its successor.
	if oldHash != "" {
		if _, err := q.Exec(ctx,
			`UPDATE oidc_tokens SET revoked_at = now()
			 WHERE refresh_token_hash = $1 AND user_id = $2 AND revoked_at IS NULL`,
			oldHash, request.GetSubject(),
		); err != nil {
			return rotationResult{err: fmt.Errorf("revoke rotated refresh token: %w", err)}
		}
	}

	return rotationResult{accessID: accessID, refreshToken: refreshToken, expiry: exp}
}

// dbQuerier is the Exec/QueryRow surface shared by *pgxpool.Pool and pgx.Tx.
type dbQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// createAccessTokenOn inserts a new access token row (5-minute TTL) on the
// given querier and returns its id + expiry.
func (s *oidcTokenStore) createAccessTokenOn(ctx context.Context, q dbQuerier, request op.TokenRequest) (string, time.Time, error) {
	id := envutil.RandomID()
	exp := time.Now().Add(5 * time.Minute)

	userID := request.GetSubject()
	clientID := extractClientID(request)

	_, err := q.Exec(ctx,
		`INSERT INTO oidc_tokens (id, client_id, user_id, subject, scopes, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, clientID, userID, userID, request.GetScopes(), exp,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("create access token: %w", err)
	}
	return id, exp, nil
}

// tokenRequestByRefreshToken resolves an active refresh token into the auth
// request the token grant needs.
func (s *oidcTokenStore) tokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	hash := sha256Hex(refreshToken)
	var req storedAuthRequest
	err := s.pool.QueryRow(ctx,
		`SELECT t.id, t.client_id, t.user_id, t.scopes, t.expires_at
		 FROM oidc_tokens t
		 WHERE t.refresh_token_hash = $1 AND t.revoked_at IS NULL
		 AND t.refresh_expires_at > now()
		 LIMIT 1`, hash,
	).Scan(&req.id, &req.clientID, &req.userID, &req.scopes, &req.expiresAt)
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	req.nonce = "" // nonce not stored for refresh tokens
	return &req, nil
}

// terminateSession revokes every active token for a (user, client) pair.
func (s *oidcTokenStore) terminateSession(ctx context.Context, userID, clientID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE oidc_tokens SET revoked_at = now()
		 WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
		userID, clientID)
	return err
}

// revoke is the single OIDC-token revocation primitive (the third revocation
// path of the Wave 3 unification). It revokes by refresh-token hash OR access
// token id, scoped to the requesting client so a client cannot revoke another
// client's tokens.
//
// RFC 7009 §2.2: revocation is idempotent — an unknown token, an
// already-revoked token, or another client's token (which the client_id scope
// filters out) is NOT an error; the endpoint must still return 200. So a
// zero-row UPDATE is success (nil); only a real DB failure is a server error
// (which the OP layer maps to a 5xx). Returning an error on no-match would both
// break the idempotency contract and leak a token-state oracle.
func (s *oidcTokenStore) revoke(ctx context.Context, tokenOrTokenID, clientID string) *oidc.Error {
	hash := sha256Hex(tokenOrTokenID)
	if _, err := s.pool.Exec(ctx,
		`UPDATE oidc_tokens SET revoked_at = now()
		 WHERE (refresh_token_hash = $1 OR id = $2)
		 AND client_id = $3
		 AND revoked_at IS NULL`,
		hash, tokenOrTokenID, clientID); err != nil {
		return oidc.ErrServerError().WithDescription("token revocation failed")
	}
	return nil
}

// refreshTokenInfo returns (userID, tokenID) for an active refresh token owned
// by the client.
func (s *oidcTokenStore) refreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	hash := sha256Hex(token)
	var userID, tokenID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id::TEXT, id FROM oidc_tokens
		 WHERE refresh_token_hash = $1 AND client_id = $2 AND revoked_at IS NULL
		 AND refresh_expires_at > now()`,
		hash, clientID,
	).Scan(&userID, &tokenID)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return userID, tokenID, nil
}

// scopesForToken was the revocation-blind scopes read its callers (UserInfo)
// used before the UserInfo acceptance path was bound to scopesForActiveToken.
// It is deliberately gone: its only remaining shape is the revocation-checked
// scopesForActiveToken below, so no future caller can re-introduce a
// revoked-token acceptance path through this store.

// scopesForActiveToken is scopesForToken's introspection-path twin: the token
// presented to /introspect has already had its signature and expiration
// verified by the zitadel op library (VerifyAccessToken/CheckExpiration, run
// before SetIntrospectionFromToken is ever called) — but that verification is
// purely cryptographic and knows nothing about revocation, which lives only in
// this DB row. Without this check a revoked access token introspects as
// active forever (the bug this closes). Returns an error — which the caller
// must propagate so the library reports {"active":false} per RFC 7662 §2.2 —
// for an unknown OR revoked token.
func (s *oidcTokenStore) scopesForActiveToken(ctx context.Context, tokenID string) ([]string, error) {
	var scopes []string
	var revokedAt *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT scopes, revoked_at FROM oidc_tokens WHERE id = $1`, tokenID,
	).Scan(&scopes, &revokedAt); err != nil {
		return nil, fmt.Errorf("introspection token lookup: %w", err)
	}
	if revokedAt != nil {
		return nil, fmt.Errorf("token revoked")
	}
	return scopes, nil
}

// ── user claim reads (users table, for userinfo/scope expansion) ──────────

// userClaims reads only the authenticated OP subject under the same
// app.current_user_id transaction scope used by first-party token issuance.
// The explicit id predicate is the R1 ownership filter; RunUserScoped makes the
// query work under the constrained FORCE-RLS runtime role.
func (s *oidcTokenStore) userClaims(ctx context.Context, subject string) (email, name string, err error) {
	userID, parseErr := strconv.ParseInt(subject, 10, 64)
	if parseErr != nil || userID <= 0 {
		return "", "", fmt.Errorf("invalid OIDC subject")
	}
	err = dbscope.RunUserScoped(ctx, s.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT email, COALESCE(NULLIF(display_name, ''), email)
			   FROM users
			  WHERE id = $1`,
			userID,
		).Scan(&email, &name)
	})
	if err != nil {
		return "", "", fmt.Errorf("read OIDC subject claims: %w", err)
	}
	return email, name, nil
}

// GCExpiredOIDCTokens deletes oidc_tokens rows that can no longer authenticate
// anything: the access token (expires_at) is past, and either there was never
// a refresh token attached or its own expiry (refresh_expires_at) has also
// passed, or the row was explicitly revoked. Mirrors token.CleanupRotatedTokens
// (the first-party oauth_tokens GC) — same shape, called from the same
// minute ticker in cmd/authserverd/main.go. A revoked row is kept briefly (the
// grace window CleanupRotatedTokens also uses) rather than deleted instantly,
// so a racing introspect/refresh request sees "revoked" not "unknown".
func GCExpiredOIDCTokens(ctx context.Context, pool *pgxpool.Pool) {
	pool.Exec(ctx,
		`DELETE FROM oidc_tokens
		 WHERE expires_at < now() - interval '5 minutes'
		 AND (refresh_expires_at IS NULL OR refresh_expires_at < now())
		 AND (revoked_at IS NULL OR revoked_at < now() - interval '5 minutes')`)
}
