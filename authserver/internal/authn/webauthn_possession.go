package authn

// webauthn_possession.go — ceremony-backed WebAuthn primitives for the
// first-factor possession gate (scheme v7 §1.4, §2.2).
//
// The management-assertion ceremony is a dedicated begin/finish pair, NOT
// login: begin mints assertion options with userVerification:'required'
// SERVER-SIDE and the caller stores a webauthn_ceremonies row keyed by the
// SHA-256 of the issued challenge (hash-only storage, mirroring the grant
// table). Finish re-derives the challenge from the presented assertion,
// proves it against the stored hash, and validates the assertion through the
// SAME go-webauthn config (RPID/RPOrigins) the login path uses — plus an
// explicit UV check, because the ceremony is a possession proof.
//
// Registration ceremonies reuse the wa_reg_sess cookie as TRANSPORT while
// the ceremony row is the AUTHORITY: CompleteRegistrationTx consumes nothing
// itself, but gives the caller everything (credential ID, UV flag) needed to
// consume the ceremony + grant rows and persist the credential inside one
// fenced transaction (§2.2).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

// ValidateCredentialOwnershipOnStore delegates to the package-level
// user-scoped ownership check (the provider seam the possession-begin
// interface exposes).
func (p *PasskeyProvider) ValidateCredentialOwnership(ctx context.Context, q GrantStore, userID int64, credentialID []byte) error {
	return ValidateCredentialOwnership(ctx, q, userID, credentialID)
}

// ChallengeHash binds a ceremony to its issued challenge: SHA-256 over the
// base64url challenge string exactly as go-webauthn minted it.
func ChallengeHash(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])
}

// userReadStore is the statement surface the ceremony user loads need.
// Satisfied by pgx.Tx (the caller's fenced transaction — the production path)
// and by pool handles. r2 defect 2: these reads MUST ride the caller's
// transaction — the ceremony paths run INSIDE transactions holding the §2.2
// fences, and a pool-issued read needs a SECOND pooled connection while the
// caller holds its own; at pool saturation every ceremony holder waits for a
// connection another holder owns → self-deadlock.
type userReadStore interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// loadUserReadOnly is loadUser WITHOUT the lazily-generating webauthn user
// handle: the ceremony paths run INSIDE transactions holding the users row
// fence (§2.2), and the historical handle-backfill UPDATE — issued through
// the pool while the fence is held on a second connection — would deadlock
// against itself. WebAuthnID falls back to the numeric id when the handle is
// unset, which is self-consistent within one ceremony. Production users get
// their durable handle minted by the LOGIN path (which runs unfenced).
// The read rides q — the CALLER'S transaction — so it never needs a second
// pooled connection (r2 defect 2).
func (p *PasskeyProvider) loadUserReadOnly(ctx context.Context, q userReadStore, userID int64) (*passkeyUser, error) {
	return p.loadUserReadOnlyFiltered(ctx, q, userID, false)
}

// loadUVUserReadOnly is the PASSKEY-PROOF loader (§1.2/§4.4 case 4 — opus r1
// finding 1): identical to loadUserReadOnly, but the credential list filters
// to `uv_capable AND revoked_at IS NULL`. A credential classified non-UV can
// never take part in a webauthn_uv ceremony: begin's allow list never
// advertises it, and a finish presenting it fails the re-derived allow-list
// check. Login and registration loaders are deliberately unchanged.
func (p *PasskeyProvider) loadUVUserReadOnly(ctx context.Context, q userReadStore, userID int64) (*passkeyUser, error) {
	return p.loadUserReadOnlyFiltered(ctx, q, userID, true)
}

func (p *PasskeyProvider) loadUserReadOnlyFiltered(ctx context.Context, q userReadStore, userID int64, uvCapableOnly bool) (*passkeyUser, error) {
	var u passkeyUser
	var handle []byte
	err := q.QueryRow(ctx,
		`SELECT id, email, display_name, webauthn_user_handle FROM users WHERE id = $1 AND enabled = TRUE`,
		userID,
	).Scan(&u.id, &u.email, &u.displayName, &handle)
	if err != nil {
		return nil, err
	}
	u.userHandle = handle

	uvFilter := ""
	if uvCapableOnly {
		uvFilter = ` AND uv_capable = TRUE`
	}
	rows, err := q.Query(ctx,
		`SELECT id, public_key, attestation_type, sign_count
		 FROM passkey_credentials
		 WHERE user_id = $1 AND revoked_at IS NULL`+uvFilter, userID)
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

// BeginManagementAssertion mints PublicKeyCredentialRequestOptions for the
// management-assertion ceremony with userVerification:'required' forced
// server-side (existing BeginLogin supplies no UV requirement; the ceremony
// is a separate begin/finish pair, not login). It returns the options JSON
// and the SHA-256 of the issued challenge for the ceremony row. No session
// cookie exists for this ceremony — the server-side row is the authority.
// tx is the caller's FENCED transaction: the user load rides it (r2 defect 2)
// so begin never needs a second pooled connection while holding the fence.
func (p *PasskeyProvider) BeginManagementAssertion(ctx context.Context, tx pgx.Tx, userID int64) (optionsJSON []byte, challengeHashHex string, err error) {
	wu, err := p.loadUVUserReadOnly(ctx, tx, userID)
	if err != nil {
		return nil, "", fmt.Errorf("management assertion: load user: %w", err)
	}
	// Allow list = the user's LIVE UV-CAPABLE credentials only (§1.2): a
	// non-UV credential is never advertised as a proof key. When the account
	// is C1 through ANOTHER method (e.g. TOTP) and holds no live UV
	// credential, the ceremony still exists — a finish is evaluated and
	// budget-accounted — but the options advertise NO proof key and every
	// assertion refuses at the finish's re-derived empty allow list
	// (BeginLogin refuses to mint for a credential-less user, so the
	// discoverable shape supplies the well-formed options skeleton).
	uvRequired := webauthn.WithUserVerification(protocol.UserVerificationRequirement(protocol.VerificationRequired))
	var options *protocol.CredentialAssertion
	var sd *webauthn.SessionData
	var beginErr error
	if len(wu.credentials) == 0 {
		options, sd, beginErr = p.wauth.BeginDiscoverableLogin(uvRequired)
	} else {
		options, sd, beginErr = p.wauth.BeginLogin(wu, uvRequired)
	}
	if beginErr != nil {
		return nil, "", fmt.Errorf("management assertion: begin: %w", beginErr)
	}
	optJSON, err := json.Marshal(options)
	if err != nil {
		return nil, "", err
	}
	return optJSON, ChallengeHash(sd.Challenge), nil
}

// ErrManagementAssertionMalformed classifies a finish body that does not
// parse as a WebAuthn assertion (opus r1 finding 4 — the machinery-vs-
// observation split): the proof was never EVALUATED, so the caller answers
// a malformed-request refusal — no webauthn_uv counter, the ceremony
// survives. Distinct from verification failures (parsed but wrong), which
// are evaluated and DO count.
var ErrManagementAssertionMalformed = errors.New("management assertion: malformed assertion body")

// ValidateManagementAssertion verifies a management-assertion finish body
// against the ceremony's stored challenge hash:
//
//   - parse the assertion (go-webauthn wire format);
//   - prove the presented challenge against the stored SHA-256 (the row
//     stores the hash, never the challenge);
//   - rebuild the SessionData the ceremony was minted with (challenge from
//     the PROVEN parsed response, UV required, the user's live UV-CAPABLE
//     credential allow-list re-derived at finish — a credential revoked
//     between begin and finish therefore refuses, and a credential
//     classified non-UV can never prove, §1.2/§4.4 case 4);
//   - run go-webauthn's ValidateLogin (origin/RP/challenge/UV per config)
//     and additionally assert the user-verified flag explicitly: the
//     ceremony is a possession proof, UV is the proof.
//
// It is pure verification: every durable write belongs to the caller's
// fenced transaction. Returns the proving credential's raw ID. tx is the
// caller's fenced transaction — the user load rides it (r2 defect 2), never
// the pool.
func (p *PasskeyProvider) ValidateManagementAssertion(ctx context.Context, tx pgx.Tx, userID int64, storedChallengeHash string, body []byte) (credentialID []byte, err error) {
	wu, err := p.loadUVUserReadOnly(ctx, tx, userID)
	if err != nil {
		return nil, fmt.Errorf("management assertion: load user: %w", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManagementAssertionMalformed, err)
	}
	// Challenge-hash proof: the ceremony row is keyed by SHA-256 of the
	// issued challenge; the assertion must present exactly that challenge.
	presented := parsed.Response.CollectedClientData.Challenge
	if ChallengeHash(presented) != storedChallengeHash {
		return nil, fmt.Errorf("management assertion: challenge does not match any live ceremony")
	}
	allowed := make([][]byte, 0, len(wu.credentials))
	for _, c := range wu.credentials {
		allowed = append(allowed, c.ID)
	}
	sd := webauthn.SessionData{
		Challenge:            presented,
		UserID:               wu.WebAuthnID(),
		AllowedCredentialIDs: allowed,
		UserVerification:     protocol.UserVerificationRequirement(protocol.VerificationRequired),
	}
	cred, err := p.wauth.ValidateLogin(wu, sd, parsed)
	if err != nil {
		return nil, fmt.Errorf("management assertion: %w", err)
	}
	if cred == nil || !cred.Flags.UserVerified {
		return nil, fmt.Errorf("management assertion: user verification required")
	}
	return cred.ID, nil
}

// BeginRegistrationCeremony mints creation options for a GATED registration
// begin and returns the session JSON (the wa_reg_sess transport, unchanged)
// plus the challenge hash the caller binds into the ceremony row and the
// grant's one-time target_ref (§1.6).
//
// The caller's FENCED transaction is required: when the user has no
// webauthn_user_handle yet, this ceremony MINTS one and persists it through
// the transaction BEFORE producing the options (r1 defect 7 / fix plan 3 —
// the historical read-only fallback presented the numeric user ID, and the
// ordinary login path then minted a DIFFERENT random handle, so every real
// browser's registration-to-login failed the user-handle check). Login's
// lazy mint then observes the persisted handle and both paths agree.
func (p *PasskeyProvider) BeginRegistrationCeremony(ctx context.Context, tx pgx.Tx, userID int64) (optionsJSON, sessionJSON []byte, challengeHashHex string, err error) {
	wu, err := loadUserForRegistrationTx(ctx, tx, userID)
	if err != nil {
		return nil, nil, "", err
	}
	options, sd, err := p.wauth.BeginRegistration(wu)
	if err != nil {
		return nil, nil, "", err
	}
	optJSON, err1 := json.Marshal(options)
	sessJSON, err2 := json.Marshal(sd)
	if err1 != nil || err2 != nil {
		return nil, nil, "", fmt.Errorf("registration ceremony encode: %v %v", err1, err2)
	}
	return optJSON, sessJSON, ChallengeHash(sd.Challenge), nil
}

// loadUserForRegistrationTx loads the user and its live credentials through
// the caller's transaction (which already holds the §2.2 users row fence, so
// reading through it cannot deadlock), minting and PERSISTING a random
// 32-byte webauthn_user_handle when none is set. The persisted handle is the
// stable WebAuthn ID every later ceremony and login must present.
func loadUserForRegistrationTx(ctx context.Context, tx pgx.Tx, userID int64) (*passkeyUser, error) {
	var u passkeyUser
	var handle []byte
	if err := tx.QueryRow(ctx,
		`SELECT id, email, display_name, webauthn_user_handle FROM users WHERE id = $1 AND enabled = TRUE`,
		userID,
	).Scan(&u.id, &u.email, &u.displayName, &handle); err != nil {
		return nil, err
	}
	if len(handle) == 0 {
		handle = make([]byte, 32)
		if _, err := rand.Read(handle); err != nil {
			return nil, fmt.Errorf("registration handle mint: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET webauthn_user_handle = $1 WHERE id = $2`,
			handle, userID,
		); err != nil {
			return nil, fmt.Errorf("registration handle persist: %w", err)
		}
	}
	u.userHandle = handle

	rows, err := tx.Query(ctx,
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

// ChallengeHashFromSessionJSON extracts the challenge hash from the
// registration session JSON the begin arm stored in the wa_reg_sess cookie,
// so the finish arm can locate/consume the ceremony row and match the
// grant's target_ref without storing the challenge itself.
func ChallengeHashFromSessionJSON(sessionJSON []byte) (string, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sd); err != nil {
		return "", err
	}
	return ChallengeHash(sd.Challenge), nil
}

// VerifyRegistrationCredential validates the attestation against the
// ceremony session WITHOUT writing anything (r1 defect 1 repair — §2.2
// authorization ordering: verification and the ceremony/grant consumption
// run BEFORE the credential row is persisted, so a refused finish can never
// commit the passkey). Returns the verified credential, including the
// attestation's user-verified flag the caller persists as uv_capable (§1.2:
// new registrations persist the flag; same-ID re-registration re-persists
// it, §4.4 case 4f).
func (p *PasskeyProvider) VerifyRegistrationCredential(ctx context.Context, tx pgx.Tx, userID int64, sessionJSON, body []byte) (*webauthn.Credential, error) {
	wu, err := p.loadUserReadOnly(ctx, tx, userID)
	if err != nil {
		return nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &sd); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return p.wauth.CreateCredential(wu, sd, parsed)
}

// PersistRegistrationCredentialTx persists a credential already verified by
// VerifyRegistrationCredential INSIDE the caller's fenced transaction — the
// finish arm's third step (verify → consume ceremony + grant → persist),
// the same cross-user collision scoping (WHERE user_id =
// EXCLUDED.user_id) plus the uv_capable persistence from the attestation's
// user-verified flag.
func (p *PasskeyProvider) PersistRegistrationCredentialTx(ctx context.Context, tx pgx.Tx, userID int64, cred *webauthn.Credential) error {
	return p.persistCredentialTx(ctx, tx, userID, cred)
}

// persistCredentialTx is persistCredential on the caller's transaction —
// the same cross-user collision scoping (WHERE user_id = EXCLUDED.user_id)
// plus the uv_capable persistence from the attestation's user-verified flag.
func (p *PasskeyProvider) persistCredentialTx(ctx context.Context, tx pgx.Tx, userID int64, cred *webauthn.Credential) error {
	tag, err := tx.Exec(ctx,
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
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("passkey: credential id already registered to another account")
	}
	return nil
}

// RevokeCredentialTx revokes a single passkey INSIDE the caller's fenced
// transaction (§2.2: the consume-vs-revoke race closure — the historical
// bare pool-level UPDATE gains the person+users fences and the generation
// bump its caller applies in the same transaction). Returns whether a live
// row was revoked.
func (p *PasskeyProvider) RevokeCredentialTx(ctx context.Context, tx pgx.Tx, credentialID []byte, userID int64) (bool, error) {
	tag, err := tx.Exec(ctx,
		`UPDATE passkey_credentials SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		credentialID, userID,
	)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ValidateCredentialOwnership is the §3.2 T4 user-scoped issuance-time
// target check (R1/R2): {exists, owned by the admission user, not revoked}.
// One refusal shape — no credential-existence oracle. Pure SQL: every
// issuer (reauth, possession/totp, assertion begin) runs it INSIDE its
// issuance/begin transaction; no WebAuthn library state required.
func ValidateCredentialOwnership(ctx context.Context, q GrantStore, userID int64, credentialID []byte) error {
	var live bool
	err := q.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM passkey_credentials
		    WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
		 )`,
		credentialID, userID,
	).Scan(&live)
	if err != nil {
		return fmt.Errorf("credential ownership check: %w", err)
	}
	if !live {
		return fmt.Errorf("credential ownership check: unknown, foreign, or revoked target")
	}
	return nil
}
