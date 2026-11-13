// Package authn provides WebAuthn (passkey), push MFA, and backup code
// authentication methods for the auth server.
package authn

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/identity"
)

// PasskeyProvider wraps go-webauthn with the normalized passkey_credentials table.
type PasskeyProvider struct {
	wauth *webauthn.WebAuthn
	pool  *pgxpool.Pool

	// decoySecret keys the deterministic decoy credential IDs returned by
	// BeginLogin for unknown / credential-less accounts. It is a per-process
	// random value: stable within the process (so repeated probes for the same
	// email yield identical allowCredentials, defeating enumeration) yet
	// unpredictable to an attacker. Never persisted.
	decoySecret []byte
}

// NewPasskeyProvider creates a WebAuthn provider using the normalized schema.
func NewPasskeyProvider(pool *pgxpool.Pool, rpID, rpDisplayName, rpOrigin string) (*PasskeyProvider, error) {
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{rpOrigin},
	})
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("passkey: failed to seed decoy secret: %w", err)
	}
	return &PasskeyProvider{wauth: w, pool: pool, decoySecret: secret}, nil
}

// --- Registration ---

// BeginRegistration returns creation options and session data for registering a new passkey.
func (p *PasskeyProvider) BeginRegistration(ctx context.Context, userID int64) ([]byte, []byte, error) {
	wu, err := p.loadUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	options, sd, err := p.wauth.BeginRegistration(wu)
	if err != nil {
		return nil, nil, err
	}
	optJSON, _ := json.Marshal(options)
	sessJSON, _ := json.Marshal(sd)
	return optJSON, sessJSON, nil
}

// FinishRegistration validates the attestation and persists the credential.
func (p *PasskeyProvider) FinishRegistration(ctx context.Context, userID int64, sessionData []byte, r *http.Request) error {
	wu, err := p.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sessionData, &sd); err != nil {
		return err
	}
	cred, err := p.wauth.FinishRegistration(wu, sd, r)
	if err != nil {
		return err
	}
	return p.persistCredential(ctx, userID, cred)
}

// --- Login ---

// BeginLogin returns assertion options for a passkey login attempt.
//
// To prevent user enumeration, the response is uniform whether or not the
// account exists or has a registered passkey: unknown / credential-less
// accounts receive a plausible decoy assertion (deterministic per email, real
// random challenge) that is byte-shape-indistinguishable from a real one. The
// decoy carries userID 0, so the subsequent FinishLogin fails authentically —
// exactly as a wrong assertion against a real account would. Callers must NOT
// special-case the returned userID in client-visible ways.
func (p *PasskeyProvider) BeginLogin(ctx context.Context, email string) (int64, []byte, []byte, error) {
	// Canonicalize at the provider boundary so BOTH the DB lookup AND the decoy
	// HMAC see the same value. This fixes a live bug: the handler feeds RAW
	// r.URL.Query().Get("email"), so a mixed-case passkey user (Alice@Corp.com)
	// match-missed the lower(email)-unique row, fell into the decoy path, and could
	// never start a real assertion. Canonicalizing here resolves the owner row;
	// feeding the same value to beginDecoyLogin also makes Alice@x and alice@x yield
	// the SAME decoy credential ID (minor enumeration-hardening win). Strictly safe:
	// users_email_lower_idx UNIQUE on lower(email) → one owner row, never a sibling.
	email = identity.CanonicalizeAddress(email).String()
	var userID int64
	err := p.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 AND enabled = TRUE`, email,
	).Scan(&userID)
	if err != nil {
		return p.beginDecoyLogin(email)
	}

	wu, err := p.loadUser(ctx, userID)
	if err != nil {
		// Treat any load failure (including a user with no active credentials)
		// as a decoy so the response shape never reveals account state.
		return p.beginDecoyLogin(email)
	}
	if len(wu.WebAuthnCredentials()) == 0 {
		return p.beginDecoyLogin(email)
	}

	options, sd, err := p.wauth.BeginLogin(wu)
	if err != nil {
		return p.beginDecoyLogin(email)
	}
	optJSON, _ := json.Marshal(options)
	sessJSON, _ := json.Marshal(sd)
	return userID, optJSON, sessJSON, nil
}

// beginDecoyLogin produces a plausible assertion for a non-existent or
// credential-less account. It runs through the same go-webauthn BeginLogin code
// path as a real login (so the assertion + session JSON shape is identical),
// using a synthetic user whose single credential ID is HMAC(decoySecret, email)
// — stable per email within the process, unpredictable to an attacker. The
// returned userID is 0; FinishLogin will fail to load that user and reject the
// assertion, matching a genuine failed login.
func (p *PasskeyProvider) beginDecoyLogin(email string) (int64, []byte, []byte, error) {
	mac := hmac.New(sha256.New, p.decoySecret)
	mac.Write([]byte(email))
	credID := mac.Sum(nil)

	wu := &passkeyUser{
		id:          0,
		email:       email,
		displayName: email,
		userHandle:  hmacBytes(p.decoySecret, append([]byte("uh:"), email...)),
		credentials: []webauthn.Credential{{
			ID:              credID,
			AttestationType: "none",
			Transport:       []protocol.AuthenticatorTransport{},
		}},
	}
	options, sd, err := p.wauth.BeginLogin(wu)
	if err != nil {
		return 0, nil, nil, err
	}
	optJSON, _ := json.Marshal(options)
	sessJSON, _ := json.Marshal(sd)
	return 0, optJSON, sessJSON, nil
}

// hmacBytes returns HMAC-SHA256(key, msg).
func hmacBytes(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// FinishLogin verifies the assertion and updates the credential's sign count.
func (p *PasskeyProvider) FinishLogin(ctx context.Context, userID int64, sessionData []byte, r *http.Request) error {
	wu, err := p.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sessionData, &sd); err != nil {
		return err
	}
	cred, err := p.wauth.FinishLogin(wu, sd, r)
	if err != nil {
		return err
	}
	// Update sign count and last_used_at
	_, err = p.pool.Exec(ctx,
		`UPDATE passkey_credentials SET sign_count = $1, last_used_at = now() WHERE id = $2 AND user_id = $3`,
		cred.Authenticator.SignCount, cred.ID, userID,
	)
	return err
}

// --- Credential management ---

// RevokeCredential marks a single passkey as revoked.
func (p *PasskeyProvider) RevokeCredential(ctx context.Context, credentialID []byte, userID int64) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		credentialID, userID,
	)
	return err
}

// NameCredential sets a human-readable name for a passkey.
func (p *PasskeyProvider) NameCredential(ctx context.Context, credentialID []byte, userID int64, deviceName string) error {
	_, err := p.pool.Exec(ctx,
		`UPDATE passkey_credentials SET device_name = $1 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL`,
		deviceName, credentialID, userID,
	)
	return err
}

// --- Internal ---

// passkeyUser implements webauthn.User backed by users + passkey_credentials tables.
type passkeyUser struct {
	id          int64
	email       string
	displayName string
	credentials []webauthn.Credential
	userHandle  []byte
}

func (u *passkeyUser) WebAuthnID() []byte {
	if len(u.userHandle) > 0 {
		return u.userHandle
	}
	return []byte(fmt.Sprintf("%d", u.id))
}
func (u *passkeyUser) WebAuthnName() string                       { return u.email }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *passkeyUser) WebAuthnIcon() string                       { return "" }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (p *PasskeyProvider) loadUser(ctx context.Context, userID int64) (*passkeyUser, error) {
	var u passkeyUser
	var handle []byte
	err := p.pool.QueryRow(ctx,
		`SELECT id, email, display_name, webauthn_user_handle FROM users WHERE id = $1 AND enabled = TRUE`,
		userID,
	).Scan(&u.id, &u.email, &u.displayName, &handle)
	if err != nil {
		return nil, err
	}

	// Generate random handle if not set — preserve-and-return (r3 defect 7):
	// the read+set is ONE conditional statement, so a concurrent initializer's
	// committed winner is returned to this caller instead of overwritten. The
	// historical shape wrote its candidate unconditionally after reading NULL,
	// letting a login begin clobber the handle a concurrent registration had
	// already committed its credential under.
	if len(handle) == 0 {
		candidate := make([]byte, 32)
		if _, err := rand.Read(candidate); err != nil {
			return nil, fmt.Errorf("webauthn: generate user handle: %w", err)
		}
		if err := p.pool.QueryRow(ctx,
			`UPDATE users SET webauthn_user_handle = COALESCE(webauthn_user_handle, $1)
			  WHERE id = $2
			  RETURNING webauthn_user_handle`,
			candidate, userID,
		).Scan(&handle); err != nil {
			return nil, fmt.Errorf("webauthn: persist user handle: %w", err)
		}
	}
	u.userHandle = handle

	// Load credentials from normalized table
	rows, err := p.pool.Query(ctx,
		`SELECT id, public_key, attestation_type, sign_count
		 FROM passkey_credentials
		 WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cred webauthn.Credential
		if err := rows.Scan(&cred.ID, &cred.PublicKey, &cred.AttestationType, &cred.Authenticator.SignCount); err != nil {
			return nil, err
		}
		u.credentials = append(u.credentials, cred)
	}
	return &u, rows.Err()
}

func (p *PasskeyProvider) persistCredential(ctx context.Context, userID int64, cred *webauthn.Credential) error {
	// passkey_credentials PK is (id) alone, and the credential id is chosen by the
	// authenticator — an attacker with a virtual authenticator can force a
	// collision with a VICTIM's credential id (victim ids leak via the
	// unauthenticated login-begin allowCredentials). The DO UPDATE must therefore
	// be scoped to the registering user: WHERE ... user_id = EXCLUDED.user_id makes
	// a cross-user collision a no-op (0 rows) instead of clobbering the victim's
	// public_key — the passkey-takeover root cause. uv_capable persists the
	// attestation's user-verified flag (possession scheme v7 §1.2) — the cohort
	// classification input; same-ID re-registration re-persists it.
	tag, err := p.pool.Exec(ctx,
		`INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, device_name, created_at, uv_capable)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (id) DO UPDATE SET public_key = $3, sign_count = $5, last_used_at = now(), uv_capable = $8
		 WHERE passkey_credentials.user_id = EXCLUDED.user_id`,
		cred.ID, userID, cred.PublicKey, cred.AttestationType,
		cred.Authenticator.SignCount, "", time.Now(), cred.Flags.UserVerified,
	)
	if err != nil {
		return err
	}
	// 0 rows == the conflict row belongs to another user (the scoped DO UPDATE
	// filtered it out). Surface it as an error so the attacker can't silently
	// no-op a registration either.
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("passkey: credential id already registered to another account")
	}
	return nil
}

// HasCredentials returns true if the user has any active passkeys.
func (p *PasskeyProvider) HasCredentials(ctx context.Context, userID int64) bool {
	var exists bool
	p.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM passkey_credentials WHERE user_id = $1 AND revoked_at IS NULL)`,
		userID,
	).Scan(&exists)
	return exists
}
