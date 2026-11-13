// Package local provides a connector backed by the local PostgreSQL users table.
// Used as the default identity source when no external directory is configured.
package local

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/authserver/internal/connector"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pwhash"
)

// Connector verifies passwords against the local users table.
type Connector struct {
	id   int64
	pool *pgxpool.Pool
}

// Factory is the local-PG connector factory. main() registers it explicitly on
// its connector.ConnectorManager (no import-side-effect init()).
func Factory(ctx context.Context, id int64, config map[string]interface{}, attrMap map[string]string) (connector.Connector, error) {
	pool, ok := config["pool"].(*pgxpool.Pool)
	if !ok {
		return nil, fmt.Errorf("local connector requires a *pgxpool.Pool in config")
	}
	return &Connector{id: id, pool: pool}, nil
}

func (c *Connector) ID() int64    { return c.id }
func (c *Connector) Type() string { return "local" }

// dummyEqualWorkHash is a fixed bcrypt DefaultCost hash of an unreachable
// dummy secret ("setjoin-equal-work-dummy-credential" — no submitted password
// ever matches it). Credential paths verify against it on the user-miss branch
// so the found and not-found branches perform the same hash work and stay
// time-indistinguishable (D-AUTHSERVER-INTERNAL-CONNECTOR-005).
const dummyEqualWorkHash = "$2a$10$9Pw2edJ.86vmMKitp1zjFekt1ycMeRq0E4sD7LsXsM7Gd1Liz2pBG"

func (c *Connector) HealthCheck(ctx context.Context) error {
	return c.pool.Ping(ctx)
}

func (c *Connector) VerifyPassword(ctx context.Context, extID, password string) error {
	var hash string
	// Canonicalize the lookup key through the one match-side seam before binding
	// $1, keeping the predicate `email = $1` (AGENTS.md:325 — "$1 from
	// CanonicalizeAddress at every consumer"). extID is already canonical today
	// (Identity.ExternalID ← LookupByAddress → users.email), so this is
	// defense-in-depth, not a live fix; it removes the lone case-sensitive sibling
	// on the connector path. Strictly safe: users_email_lower_idx UNIQUE on
	// lower(email) means a folded match reaches exactly the one owner row.
	err := c.pool.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1 AND enabled = TRUE`, identity.CanonicalizeAddress(extID).String()).Scan(&hash)
	if err != nil {
		// Equal-work miss branch (D-AUTHSERVER-INTERNAL-CONNECTOR-005): burn the
		// same hash-verify cost a found user would pay, then return the ONE
		// uniform credential error — missing/disabled and wrong-password are
		// indistinguishable to the caller.
		_ = pwhash.VerifyPasswordHash(dummyEqualWorkHash, password)
		return pwhash.ErrInvalidCredentials
	}
	if err := pwhash.VerifyPasswordHash(hash, password); err != nil {
		return pwhash.ErrInvalidCredentials
	}
	// Self-heal below-floor hashes (D-AUTHSERVER-INTERNAL-CONNECTOR-006):
	// pwhash.NeedsRehash flags a stored hash written under a weaker policy
	// (bcrypt cost below the shared floor / SM3 iterations below floor). The
	// credential just verified, so transparently upgrade it through the ONE
	// hash seam. The UPDATE is guarded on the exact hash we verified — it acts
	// as the row version, so a concurrent credential rotation is never
	// clobbered (the guarded write touches zero rows and we stay silent: the
	// caller's password was verified against the CURRENT hash either way).
	// Best-effort by design: the login itself already succeeded, so a failed
	// upgrade write (transient error) must not fail the verification.
	if pwhash.NeedsRehash(hash) {
		if upgraded, err := pwhash.HashPasswordWithProfile(password); err == nil {
			_, _ = c.pool.Exec(ctx, //nolint:errcheck // best-effort self-heal; verification already succeeded
				`UPDATE users SET password_hash = $1 WHERE email = $2 AND password_hash = $3`,
				upgraded, identity.CanonicalizeAddress(extID).String(), hash)
		}
	}
	return nil
}

// ChangePassword verifies the old password and writes the new hash.
//
// HANDLER-INTERNAL-ONLY credential seam (D-AUTHSERVER-INTERNAL-CONNECTOR-004):
// this method intentionally performs ONLY the mechanical verify+write. The
// full credential-mutation control chain — identity_auth_local_mint_fence,
// password-history check/insert/trim, and token revocation
// (RevokeAllForUserTx) — is composed transactionally around the same
// users.password_hash write in handlers/auth.go ChangePassword, and every
// production caller MUST go through that handler chain. Do not wire this
// method into any new non-HTTP (sync/backfill) caller without first moving
// that chain into a shared credential-write seam both paths call; doing so
// would silently drop token revocation, reuse-policy enforcement, and the
// concurrent-mutation fence.
func (c *Connector) ChangePassword(ctx context.Context, extID, oldPassword, newPassword string) error {
	// Canonicalize ONCE and bind the same value to the SELECT ($1) and the UPDATE
	// ($2) so the row the old password verifies against is exactly the row the new
	// hash is written to. Keeping the two predicates identical is load-bearing: a
	// folded SELECT with an un-folded UPDATE would verify the right row then write
	// zero rows (silent no-op). The rows_affected == 1 assertion below catches that
	// whole zero/multi-row class loudly. Strictly safe via users_email_lower_idx.
	canon := identity.CanonicalizeAddress(extID).String()

	// One transaction with SELECT ... FOR UPDATE (predicate parity,
	// D-AUTHSERVER-INTERNAL-CONNECTOR-003): the verification WHERE
	// `email = $1 AND enabled = TRUE` is byte-identical to the UPDATE's, and
	// the row lock serializes against a concurrent disable between verify and
	// write — under READ COMMITTED a racing disable makes the SELECT re-check
	// fail, so a disabled account's credential can never be rotated here.
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op if already committed

	var hash string
	if err := tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE email = $1 AND enabled = TRUE FOR UPDATE`, canon).Scan(&hash); err != nil {
		// Equal-work miss branch, same doctrine as VerifyPassword
		// (D-AUTHSERVER-INTERNAL-CONNECTOR-005): identical hash work and the
		// one uniform credential error on both miss (not found/disabled) and
		// wrong-old-password outcomes.
		_ = pwhash.VerifyPasswordHash(dummyEqualWorkHash, oldPassword)
		return pwhash.ErrInvalidCredentials
	}
	if err := pwhash.VerifyPasswordHash(hash, oldPassword); err != nil {
		return pwhash.ErrInvalidCredentials
	}
	var newHash string
	// Single hash-policy seam (D-AUTHSERVER-INTERNAL-CONNECTOR-006): the new
	// hash is produced ONLY through pwhash.HashPasswordWithProfile — the same
	// profile-driven seam every other credential writer uses. The former
	// direct-bcrypt branch (with its env-downgradable BCRYPT_COST knob that
	// bypassed the shared strength floor) is gone; under the standard profile
	// the seam itself emits bcrypt at the shared floor cost.
	newHash, err = pwhash.HashPasswordWithProfile(newPassword)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE email = $2 AND enabled = TRUE`, newHash, canon)
	if err != nil {
		return err
	}
	// Structural guard: a single-row identity UPDATE must touch exactly one row.
	// Zero rows means the write missed its target (predicate drift / mid-flight
	// row change) and the password silently did NOT change — fail loudly instead.
	if n := tag.RowsAffected(); n != 1 {
		return fmt.Errorf("change password: expected to update exactly 1 row, updated %d", n)
	}
	return tx.Commit(ctx)
}

// LookupByAddress resolves a person by ANY of their addresses (the
// resolve_identity seam, ADR-004): `users.email` ∪ `aliases.email` ∪
// `users.ad_upn`, case-insensitive, via connector.ResolveIdentitySQL. The
// returned Identity.Email is the person's canonical primary (`users.email`), not
// whichever address the caller passed, so a UPN/alias lookup still yields the
// stable identity.
func (c *Connector) LookupByAddress(ctx context.Context, address string) (*connector.Identity, error) {
	var id int64
	var email, displayName, givenName, surname string
	// Canonicalize the caller address through the one match-side seam (same as
	// resolveUserByAddress + NormalizeAndValidate) before binding $1, so a UPN /
	// alias carrying whitespace or display-name form resolves the existing person
	// rather than match-missing. A bare UPN / Kerberos principal is preserved
	// (CanonicalizeAddress doesn't reject non-addresses) so it still hits ad_upn.
	err := c.pool.QueryRow(ctx,
		`SELECT u.id, u.email, coalesce(u.display_name, ''),
		        coalesce(u.first_name, ''), coalesce(u.last_name, '')`+
			connector.ResolveIdentitySQL, identity.CanonicalizeAddress(address).String(),
	).Scan(&id, &email, &displayName, &givenName, &surname)
	if err != nil {
		return nil, err
	}
	return &connector.Identity{
		ExternalID:  email,
		Email:       email,
		DisplayName: displayName,
		GivenName:   givenName,
		Surname:     surname,
		Attributes:  map[string]string{"user_id": fmt.Sprint(id)},
	}, nil
}
