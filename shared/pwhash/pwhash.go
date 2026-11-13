// Package pwhash provides bcrypt and SM3 password hashing and verification.
// Shared by both authserver and mailserver gateway.
package pwhash

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/validate"
)

// User is the resolved user record after password verification.
type User struct {
	ID                 int64
	Email              string
	DisplayName        string
	IsAdmin            bool
	TOTPEnabled        bool
	MustChangePassword bool
	MFAExempt          bool
}

var ErrInvalidCredentials = errors.New("invalid credentials")

// PasswordMaxBytes is the longest plaintext accepted by every password-hash
// path in a standard Setjoin installation. bcrypt's limit is bytes, not
// Unicode code points; publishing and enforcing the exact boundary avoids a
// late bcrypt error turning an otherwise valid password form into a 500.
// Keep the cross-profile contract at the shared standard-profile floor until
// every credential writer has migrated away from direct bcrypt calls.
const PasswordMaxBytes = validate.PasswordMaxBytes

// activeProfile controls password hashing algorithm selection.
// Defaults to ProfileStandard (bcrypt). Set once at startup via SetCryptoProfile.
var activeProfile = cryptokey.ProfileStandard

// SetCryptoProfile sets the active crypto profile for password hashing.
// Called once at startup by both authserver and gateway main().
func SetCryptoProfile(p cryptokey.CryptoProfile) {
	activeProfile = p
}

// CryptoProfile returns the currently active crypto profile for password hashing.
func CryptoProfile() cryptokey.CryptoProfile {
	return activeProfile
}

// HashPasswordWithProfile generates a hash using the configured profile.
// Standard → bcrypt. SMx or Hybrid → SM3 (PBKDF2-HMAC-SM3 at 100k iterations).
func HashPasswordWithProfile(password string) (string, error) {
	if len([]byte(password)) > PasswordMaxBytes {
		return "", bcrypt.ErrPasswordTooLong
	}
	if activeProfile == cryptokey.ProfileSMx || activeProfile == cryptokey.ProfileHybrid {
		return HashPasswordSM3(password)
	}
	return HashPassword(password)
}

// VerifyPasswordHash dispatches on the stored hash format. Credential writers
// and password-history checks must use this seam so a runtime crypto-profile
// switch does not make previously written SM3 hashes unverifiable.
func VerifyPasswordHash(hash, password string) error {
	if IsSM3Hash(hash) {
		return VerifyPasswordSM3(hash, password)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// ErrCredentialHashFormat rejects a stored credential hash that is not in the
// format its writer emits.
var ErrCredentialHashFormat = errors.New("pwhash: credential hash is not in the accepted format")

// VerifyCredentialHash verifies a NON-password credential hash — single-use
// TOTP backup codes and SCIM bearer tokens — against a candidate secret.
// Unlike VerifyPasswordHash this arm is deliberately bcrypt-only: those
// credentials have always been written bcrypt (authn.newBackupCodes, SCIM
// token mint) and, unlike login passwords, no SMx-profile dispatch exists for
// them — routing them through the password seam would silently widen their
// accepted domain to SM3-formatted values they were never stored as. A stored
// value in any other format (including $sm3$) is ErrCredentialHashFormat.
func VerifyCredentialHash(hash, secret string) error {
	if IsSM3Hash(hash) {
		return ErrCredentialHashFormat
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
}

// authCache caches recent successful auth results to absorb reconnect storms
// (IMAP/SMTP clients re-auth frequently; bcrypt is deliberately expensive).
//
// The key folds in the STORED HASH (not just the password): a password change or
// admin reset produces a new hash, hence a new key, hence a cache MISS — so the
// changed credential takes effect immediately and the OLD password stops working
// at once. (Keying on the password alone — the prior bug — left the old
// credential valid for the full TTL after a reset, the exact window that matters
// when locking out a compromised account.) TTL: 60s; sync.Map for low contention.
var authCache sync.Map

// authCacheKey derives the cache key for a verified (email, stored-hash, password)
// triple. It depends on the stored hash so any credential rotation invalidates the
// entry; the password component is a one-way slug (never the raw password).
func authCacheKey(email, storedHash, password string) string {
	return email + ":" + hashSlug(storedHash) + ":" + hashSlug(password)
}

type cacheEntry struct {
	user      *User
	expiresAt time.Time
}

// GovernedAdminExpr is the SQL that qualifies the legacy users.is_admin flag
// with a live governed admin_role_assignments row — the single authority axis
// of the RBAC cut-over (V011 backfill / V023 drop_admin_role; the same rule
// permissions.ResolveAuthority enforces: expires_at honored,
// admin_assignment_active eligibility). broken-authorization closure
// occ_7512aa859c19ceb6691b64c7: the bare legacy flag alone must not establish
// admin anywhere this shared seam feeds (gateway Claims.IsAdmin drives, among
// others, the rule-template visibility bypass in the mail console), so a
// flagged-but-ungoverned user now reads as a non-admin here, exactly as it
// already does at every permission-checked console route.
//
// Exported so the other raw-is_admin auth seams reuse the ONE expression
// instead of drifting copies: mailserver/internal/auth's kerberos
// (lookupByKerberosPrincipal) and certificate (lookupByCertSubject) lookups
// interpolate it verbatim — the query must alias `users` as `u`.
const GovernedAdminExpr = `u.is_admin AND EXISTS (
           SELECT 1 FROM admin_role_assignments ara
           WHERE ara.user_id = u.id
             AND (ara.expires_at IS NULL OR ara.expires_at > now())
             AND admin_assignment_active(ara.eligible, ara.activated_until)
       )`

// CheckPassword validates email+password against the stored hash in PostgreSQL.
// Dispatches on hash prefix: $sm3$ → SM3 verify, $2a$/$2b$/$2y$ → bcrypt verify.
// Results are cached for 60 seconds to absorb reconnect storms.
//
// The surfaced User.IsAdmin is the GOVERNED admin signal (legacy flag + live
// admin_role_assignments row), not the raw users.is_admin column — see
// governedAdminExpr.
func CheckPassword(ctx context.Context, pool *pgxpool.Pool, email, password string) (*User, error) {
	var hash string
	var u User
	err := pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, `+GovernedAdminExpr+`,
		 u.totp_enabled, u.must_change_password, u.mfa_exempt, u.password_hash
		 FROM users u
		 JOIN domains d ON d.id = u.domain_id
		 WHERE u.email = $1 AND u.enabled = TRUE`,
		email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin,
		&u.TOTPEnabled, &u.MustChangePassword, &u.MFAExempt, &hash)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if hash == "" {
		return nil, ErrInvalidCredentials
	}

	// Fast path: cached recent auth for this email + current-hash + password.
	cacheKey := authCacheKey(email, hash, password)
	if entry, ok := authCache.Load(cacheKey); ok {
		if e, ok := entry.(cacheEntry); ok && time.Now().Before(e.expiresAt) {
			return e.user, nil
		}
		authCache.Delete(cacheKey)
	}

	// Dispatch on hash type: SM3 ($sm3$) or bcrypt ($2a$ / $2b$ / $2y$)
	if err := VerifyPasswordHash(hash, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Self-heal below-floor hashes (D-SHARED-PWHASH-V-004): NeedsRehash flags
	// a stored hash written under a weaker policy (bcrypt cost below the
	// shared floor / SM3 iterations below floor). Previously this package
	// exposed NeedsRehash without any production caller, so below-floor or
	// cross-profile hashes persisted indefinitely after successful auth. The
	// credential just verified, so transparently upgrade it through the ONE
	// hash seam — the same self-heal the authserver local connector performs
	// on its path (D-AUTHSERVER-INTERNAL-CONNECTOR-006). The UPDATE is guarded
	// on the exact hash we verified — it acts as the row version, so a
	// concurrent credential rotation is never clobbered (the guarded write
	// touches zero rows and we stay silent: the caller's password was verified
	// against the CURRENT hash either way). Best-effort by design: the login
	// itself already succeeded, so a failed upgrade write (transient error)
	// must not fail the verification.
	if NeedsRehash(hash) {
		if upgraded, err := HashPasswordWithProfile(password); err == nil {
			_, _ = pool.Exec(ctx, //nolint:errcheck // best-effort self-heal; verification already succeeded
				`UPDATE users SET password_hash = $1 WHERE email = $2 AND password_hash = $3`,
				upgraded, email, hash)
		}
	}

	authCache.Store(cacheKey, cacheEntry{&u, time.Now().Add(60 * time.Second)})
	return &u, nil
}

// minBcryptCost is the strength floor: a stored bcrypt hash below this cost is
// outdated and should be transparently re-hashed after a successful login.
const minBcryptCost = bcrypt.DefaultCost

// NeedsRehash reports whether a stored hash is below the current strength floor
// (bcrypt cost / SM3 iterations) and should be re-hashed after the next successful
// CheckPassword. False for an unparseable hash (the verify path rejects those).
// Callers SHOULD, on true, re-hash with HashPasswordWithProfile and persist — a
// hash stored with too few rounds still verifies, but must not stay weak (downgrade
// defense).
func NeedsRehash(hash string) bool {
	if IsSM3Hash(hash) {
		return sm3IterationsBelowFloor(hash)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return false
	}
	return cost < minBcryptCost
}

func hashSlug(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:8])
}

// HashPassword generates a bcrypt hash from a plaintext password.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// LookupByEmail returns a user record without checking credentials.
// User.IsAdmin is the governed admin signal — see governedAdminExpr.
func LookupByEmail(ctx context.Context, pool *pgxpool.Pool, email string) (*User, error) {
	var u User
	err := pool.QueryRow(ctx,
		`SELECT u.id, u.email, u.display_name, `+GovernedAdminExpr+`, u.totp_enabled
		 FROM users u WHERE u.email = $1 AND u.enabled = TRUE`,
		email,
	).Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin, &u.TOTPEnabled)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return &u, nil
}
