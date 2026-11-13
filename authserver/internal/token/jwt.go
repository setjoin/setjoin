package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

// SigningAlg selects the algorithm sign() uses for first-party tokens.
// HS256 stays the conservative default (ADR-005 dual-verify migration: the
// gateway must be able to verify ES256 before issuance flips). ES256 is opted in
// via JWT_SIGNING_ALG once a KeySet is loaded.
type SigningAlg string

const (
	SigningAlgHS256 SigningAlg = "HS256"
	SigningAlgES256 SigningAlg = "ES256"
)

// ParseSigningAlg normalizes a config string to a SigningAlg, defaulting to
// HS256 for empty/unknown values (fail-conservative: never silently pick the
// newer path on a typo).
func ParseSigningAlg(s string) SigningAlg {
	if SigningAlg(s) == SigningAlgES256 {
		return SigningAlgES256
	}
	return SigningAlgHS256
}

type TokenType = jwtutil.TokenType
type Claims = jwtutil.Claims

const (
	TypeAccess              = jwtutil.TypeAccess
	TypeMFAPending          = jwtutil.TypeMFAPending
	TypeRefresh             = jwtutil.TypeRefresh
	TypeForcePasswordChange = jwtutil.TypeForcePasswordChange
	TypePasswordReset       = jwtutil.TypePasswordReset
)

// Authentication Method Reference values (RFC 8176), re-exported so handlers
// name the factor they satisfied without importing jwtutil directly.
const (
	AMRPassword     = jwtutil.AMRPassword
	AMROTP          = jwtutil.AMROTP
	AMRHardwareKey  = jwtutil.AMRHardwareKey
	AMRSoftwareKey  = jwtutil.AMRSoftwareKey
	AMRUserPresence = jwtutil.AMRUserPresence
	AMRMultiFactor  = jwtutil.AMRMultiFactor
)

const (
	kidHMAC = "authserver-hmac-1"
	kidSM2  = "authserver-sm2-1"
)

const audience = "mailserver-gateway"

// JWTProvider issues and validates JWTs. Issuance uses one of HS256 / SM2 /
// ES256 (the signingAlg selector + crypto profile decide which); Validate
// dual-verifies all three by header alg + kid, so a migration never has a window
// where a freshly-issued token can't be verified (ADR-005).
type JWTProvider struct {
	secret        []byte
	sm2Key        *ecdsa.PrivateKey // nil for standard/hybrid profiles (HS256 fallback)
	profile       cryptokey.CryptoProfile
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string

	// keySet is the ES256 asymmetric keystore (ADR-005). Optional: nil keeps the
	// provider HS256/SM2-only. When non-nil, Validate accepts ES256 tokens by
	// kid, and (if signingAlg==ES256) sign() emits ES256.
	keySet     *KeySet
	signingAlg SigningAlg

	// verifierCache is the shared verify path, built once (keySet/sm2Key/issuer
	// are fixed by the time the first token is validated). Its ES256 lookup reads
	// p.keySet live, so key rotation is picked up without a rebuild.
	verifierOnce  sync.Once
	verifierCache *jwtutil.Verifier
}

// NewJWTProvider creates a JWT provider with the given secret, optional SM2 key, and TTLs.
// signingAlg defaults to HS256; ES256 issuance additionally requires a KeySet
// (set via WithKeySet) — without one, sign() falls back to HS256.
func NewJWTProvider(secret string, sm2Key *ecdsa.PrivateKey, profile cryptokey.CryptoProfile, accessExpiry, refreshExpiry time.Duration, issuer string) *JWTProvider {
	return &JWTProvider{
		secret:        []byte(secret),
		sm2Key:        sm2Key,
		profile:       profile,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		issuer:        issuer,
		signingAlg:    SigningAlgHS256,
	}
}

// WithKeySet attaches the ES256 keystore and selects the issuance algorithm.
// It returns the same provider for chaining at construction. Passing
// SigningAlgES256 with a nil keySet is treated as HS256 (fail-conservative:
// never claim to issue ES256 without a key to sign with).
func (p *JWTProvider) WithKeySet(ks *KeySet, alg SigningAlg) *JWTProvider {
	p.keySet = ks
	if alg == SigningAlgES256 && ks != nil {
		if _, _, ok := ks.ActiveSigner(); ok {
			p.signingAlg = SigningAlgES256
		} else {
			p.signingAlg = SigningAlgHS256
		}
	} else {
		p.signingAlg = SigningAlgHS256
	}
	return p
}

// SigningAlg reports the algorithm sign() will use for new tokens.
func (p *JWTProvider) SigningAlg() SigningAlg { return p.signingAlg }

// Issuer returns the iss claim used when signing tokens.
func (p *JWTProvider) Issuer() string { return p.issuer }

// Audience returns the aud claim stamped into every issued token (the gateway).
func (p *JWTProvider) Audience() string { return audience }

// AccessExpiry returns the access token TTL.
func (p *JWTProvider) AccessExpiry() time.Duration { return p.accessExpiry }

// RefreshExpiry returns the refresh token TTL.
func (p *JWTProvider) RefreshExpiry() time.Duration { return p.refreshExpiry }

// AuthContext carries the authentication-context (acr/amr) an access token
// should advertise — the AAL reached and the methods actually performed.
// The zero value (empty/nil) emits no acr/amr, keeping callers that do not
// track factors fully backward-compatible.
type AuthContext = jwtutil.AuthContext

// IssueAccess issues a standard access token (1h TTL by default).
func (p *JWTProvider) IssueAccess(userID int64, email string, isAdmin bool) (string, error) {
	return p.IssueAccessWithDevice(userID, email, isAdmin, nil, nil, nil, nil)
}

// IssueAccessWithDevice issues an access token with optional device, MAM, risk,
// and domain scope claims. Nil pointers are omitted from the JWT (omitempty).
// It carries no authentication-context claims; use IssueAccessFull to set
// acr/amr at the MFA-aware issuance sites.
func (p *JWTProvider) IssueAccessWithDevice(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64) (string, error) {
	return p.IssueAccessFull(userID, email, isAdmin, device, mam, risk, domainScope, AuthContext{})
}

// IssueAccessFull issues an access token with the full claim set, including the
// authentication-context (acr/amr). An empty AuthContext leaves acr/amr unset
// (omitempty), so existing callers are unaffected. The token carries no
// admin_role ("role") claim — the RBAC cut-over dropped users.admin_role;
// authorization flows from the resolved Permissions set, not an enum.
// Every access token carries a unique jti (CA-3 per-session denylist substrate;
// inert until CA-3 — minted here so the field is always present).
func (p *JWTProvider) IssueAccessFull(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64, authCtx AuthContext) (string, error) {
	return p.issueAccessSigned(userID, email, isAdmin, device, mam, risk, domainScope, authCtx, nil, nil, nil, "", "")
}

// IssueAccessCA is IssueAccessFull + CA-3a cnf (token-binding) and sif
// (sign-in-frequency) claims. Called from the login handler when CA policy
// provides these extras. Nil cnf/sif are omitted (omitempty) so this is
// byte-compatible with IssueAccessFull when both are nil and accountType is "".
// ponytail: wraps issueAccessSigned to avoid duplicating the sign body.
func (p *JWTProvider) IssueAccessCA(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64, authCtx AuthContext, cnf *jwtutil.ConfirmationClaim, sif *int64, accountType string) (string, error) {
	return p.IssueAccessCASession(userID, email, isAdmin, device, mam, risk, domainScope, authCtx, cnf, sif, nil, accountType)
}

// IssueAccessCASession preserves the authentication timestamp that owns a
// refresh family. A nil authTime on a SIF-constrained initial mint defaults to
// now; rotation passes the original value back unchanged.
func (p *JWTProvider) IssueAccessCASession(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64, authCtx AuthContext, cnf *jwtutil.ConfirmationClaim, sif, authTime *int64, accountType string) (string, error) {
	return p.IssueAccessCAFamilySession(userID, email, isAdmin, device, mam, risk, domainScope, authCtx, cnf, sif, authTime, "", accountType)
}

// IssueAccessCAFamilySession binds an access token to the same immutable
// refresh-family identifier as its paired refresh token. Callers that do not
// create a refresh family keep using IssueAccessCASession and emit no fam claim.
func (p *JWTProvider) IssueAccessCAFamilySession(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64, authCtx AuthContext, cnf *jwtutil.ConfirmationClaim, sif, authTime *int64, familyID, accountType string) (string, error) {
	return p.issueAccessSigned(userID, email, isAdmin, device, mam, risk, domainScope, authCtx, cnf, sif, authTime, familyID, accountType)
}

func (p *JWTProvider) issueAccessSigned(userID int64, email string, isAdmin bool, device *jwtutil.DeviceClaim, mam *jwtutil.MAMClaim, risk *jwtutil.RiskClaim, domainScope *int64, authCtx AuthContext, cnf *jwtutil.ConfirmationClaim, sif, authTime *int64, familyID, accountType string) (string, error) {
	now := time.Now()
	if sif != nil && authTime == nil {
		value := now.Unix()
		authTime = &value
	}
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("jti generation: %w", err)
	}
	return p.sign(&jwtutil.Claims{
		UserID:          userID,
		Email:           email,
		IsAdmin:         isAdmin,
		AccountType:     accountType,
		Type:            jwtutil.TypeAccess,
		JTI:             hex.EncodeToString(jtiBytes),
		FamilyID:        familyID,
		Device:          device,
		MAM:             mam,
		Risk:            risk,
		DomainScope:     domainScope,
		ACR:             authCtx.ACR,
		AMR:             authCtx.AMR,
		Cnf:             cnf,
		SignInFreq:      sif,
		SessionAuthTime: authTime,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
}

// IssueMFAPending issues a 5-minute MFA-pending token used at the TOTP step.
// The first factor is assumed to be a password (AMRPassword): every login path
// that reaches MFA has already verified the password. The factor is carried in
// the token's AMR so the second-factor verify handler can append its own method
// and derive the final acr/amr for the access token it issues.
func (p *JWTProvider) IssueMFAPending(userID int64, email string) (string, error) {
	return p.IssueMFAPendingWithIdentityFence(userID, email, nil, jwtutil.AMRPassword)
}

// IssueMFAPendingWithAMR issues an MFA-pending token recording the factor(s)
// already satisfied (e.g. AMRHardwareKey when a passkey login routes into a
// second factor). Empty values are ignored.
func (p *JWTProvider) IssueMFAPendingWithAMR(userID int64, email string, amr ...string) (string, error) {
	return p.IssueMFAPendingWithIdentityFence(userID, email, nil, amr...)
}

// IssueMFAPendingWithIdentityFence binds a federated first factor to the exact
// normalized source/link generations that must still authorize completion.
// A nil fence preserves local and legacy challenge compatibility.
func (p *JWTProvider) IssueMFAPendingWithIdentityFence(
	userID int64,
	email string,
	fence *jwtutil.IdentityFenceClaim,
	amr ...string,
) (string, error) {
	return p.IssueMFAPendingWithFences(userID, email, fence, "", amr...)
}

// IssueMFAPendingWithFences carries both federated-identity and local
// credential-version proof across a multi-step authentication flow.
func (p *JWTProvider) IssueMFAPendingWithFences(
	userID int64,
	email string,
	identityFence *jwtutil.IdentityFenceClaim,
	credentialFence string,
	amr ...string,
) (string, error) {
	token, _, err := p.IssueMFAPendingWithFencesJTI(userID, email, identityFence, credentialFence, "", amr...)
	return token, err
}

// IssueMFAPendingWithFencesJTI signs an MFA-pending token with a SUPPLIED
// JTI and returns both. The bootstrap grant issuance contract (possession
// scheme v7 §1.5.1) needs the JTI BEFORE any DB write: the caller generates
// the JTI first, inserts the grant bound to it in the same transaction it
// commits the token's return against, and only then is a token that exists
// on the wire covered by a committed grant row. An empty jti generates a
// random one (the historical behaviour, preserved byte-identically by the
// IssueMFAPending* wrappers).
func (p *JWTProvider) IssueMFAPendingWithFencesJTI(
	userID int64,
	email string,
	identityFence *jwtutil.IdentityFenceClaim,
	credentialFence string,
	jti string,
	amr ...string,
) (token string, jtiOut string, err error) {
	now := time.Now()
	cleaned := make([]string, 0, len(amr))
	for _, m := range amr {
		if m != "" {
			cleaned = append(cleaned, m)
		}
	}
	// Random jti per mint (same uniqueness discipline as refresh tokens): every
	// other claim is second-resolution, so two MFA steps completed in the same
	// second produced byte-identical MFA-pending tokens — indistinguishable
	// sessions, which matters wherever a server-side fence keys on the exact
	// token string (e.g. the push-challenge session binding).
	if jti == "" {
		jtiBytes := make([]byte, 16)
		if _, err := rand.Read(jtiBytes); err != nil {
			return "", "", fmt.Errorf("mfa-pending jti generation: %w", err)
		}
		jti = hex.EncodeToString(jtiBytes)
	}
	signed, err := p.sign(&jwtutil.Claims{
		UserID:          userID,
		Email:           email,
		Type:            jwtutil.TypeMFAPending,
		JTI:             jti,
		AMR:             cleaned,
		IdentityFence:   identityFence,
		CredentialFence: credentialFence,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

// IssueForcePasswordChange issues a 5-minute token for the password change flow.
func (p *JWTProvider) IssueForcePasswordChange(userID int64, email string) (string, error) {
	return p.issueShortLived(userID, email, jwtutil.TypeForcePasswordChange)
}

// IssuePasswordReset issues a 5-minute JWT for the forgot-password flow.
// The jti claim is used for single-use tracking.
func (p *JWTProvider) IssuePasswordReset(userID int64, email string) (string, error) {
	now := time.Now()
	jtiBytes := make([]byte, 32)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("jti generation: %w", err)
	}
	return p.sign(&jwtutil.Claims{
		UserID: userID,
		Email:  email,
		Type:   jwtutil.TypePasswordReset,
		JTI:    hex.EncodeToString(jtiBytes),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
}

// IssueRefresh issues a long-lived refresh token (30d TTL by default) with a
// freshly generated family_id (UUID v4). Call this on new logins; use
// IssueRefreshWithFamily during rotation to inherit the parent token's family
// (CA-3 substrate; inert until CA-3 — the claim is minted here so it is always
// present in the chain).
func (p *JWTProvider) IssueRefresh(userID int64, email string) (string, error) {
	return p.IssueRefreshWithFamily(userID, email, uuid.New().String())
}

// IssueRefreshWithFamily issues a long-lived refresh token carrying the provided
// familyID claim. Used during rotation to carry the parent token's family_id
// forward; IssueRefresh calls this with a freshly generated family for new logins.
func (p *JWTProvider) IssueRefreshWithFamily(userID int64, email, familyID string) (string, error) {
	return p.IssueRefreshWithFamilyAndCnf(userID, email, familyID, nil)
}

// IssueRefreshWithFamilyAndCnf is IssueRefreshWithFamily plus the CA-3a cnf
// (token-binding) claim. Embedding cnf on the REFRESH token (not just the
// access token) is what lets rotation (internal/token/refresh.go issueAndStore)
// read the bound jkt straight off the presented refresh token's own validated
// claims and carry it forward into both the new access token and the successor
// refresh token — mirroring how family_id already rides the refresh JWT rather
// than needing a new oauth_tokens column. Nil cnf is byte-compatible with
// IssueRefreshWithFamily (omitempty).
func (p *JWTProvider) IssueRefreshWithFamilyAndCnf(userID int64, email, familyID string, cnf *jwtutil.ConfirmationClaim) (string, error) {
	return p.IssueRefreshWithFamilySession(userID, email, familyID, cnf, nil, nil, nil)
}

// IssueRefreshWithFamilySession preserves the security controls established at
// authentication across every refresh rotation. authTime is the immutable
// start of the family, not this refresh token's iat.
func (p *JWTProvider) IssueRefreshWithFamilySession(
	userID int64,
	email, familyID string,
	cnf *jwtutil.ConfirmationClaim,
	device *jwtutil.DeviceClaim,
	sif, authTime *int64,
) (string, error) {
	now := time.Now()
	// Every refresh token carries a fresh random jti (the same uniqueness
	// discipline IssueAccessFull/IssueImpersonation already apply): every other
	// claim is second-resolution and deterministic for a given family state, so
	// two rotations (or a mint + a grace-window re-issue) landing in the same
	// second under HS256 produced BYTE-IDENTICAL tokens — the "new" bearer
	// secret preserved the old one verbatim and rotation was a no-op for an
	// attacker holding the previous token. The random jti makes each mint a
	// distinct credential string (and thus a distinct oauth_tokens hash).
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("refresh jti generation: %w", err)
	}
	return p.sign(&jwtutil.Claims{
		UserID:          userID,
		Email:           email,
		Type:            jwtutil.TypeRefresh,
		JTI:             hex.EncodeToString(jtiBytes),
		FamilyID:        familyID,
		Cnf:             cnf,
		Device:          device,
		SignInFreq:      sif,
		SessionAuthTime: authTime,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(p.refreshExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
}

// IssueImpersonation issues a short-lived access token for a target user
// as if issued by an admin. The act (actor) claim records who performed
// the impersonation (RFC 8693). TTL is 15 minutes to limit exposure.
// Every access token carries a unique jti (CA-3 per-session denylist substrate;
// inert until CA-3 — minted here so the field is always present, matching IssueAccessFull).
// accountType carries the target's acct claim forward (derived by the caller
// from is_guest_account()) — impersonating a guest yields a guest-claimed
// token; the chain.AuthenticateRequest satellite belt would force it anyway.
func (p *JWTProvider) IssueImpersonation(targetUserID int64, targetEmail string, adminActorID int64, accountType string) (string, error) {
	now := time.Now()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("jti generation: %w", err)
	}
	return p.sign(&jwtutil.Claims{
		UserID:       targetUserID,
		Email:        targetEmail,
		IsAdmin:      false,
		AccountType:  accountType,
		Type:         jwtutil.TypeAccess,
		JTI:          hex.EncodeToString(jtiBytes),
		AdminActorID: &adminActorID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(targetUserID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
}

// issueShortLived issues a 5-minute JWT for MFA or password change.
func (p *JWTProvider) issueShortLived(userID int64, email string, typ jwtutil.TokenType) (string, error) {
	now := time.Now()
	return p.sign(&jwtutil.Claims{
		UserID: userID,
		Email:  email,
		Type:   typ,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Subject:   strconv.FormatInt(userID, 10),
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
}

// Validate parses and verifies a JWT. Returns Claims on success.
// Validates signature, issuer/audience, and temporal claims ONLY — it is the
// crypto layer, deliberately stateless. Session acceptance semantics (revocation
// via the CA-3a denylist, DPoP proof-of-possession for cnf-bound tokens) are
// enforced by the acceptance path in BearerAuthenticator.Authenticate
// (authenticator.go), the single funnel every authserver route authenticates
// through. Dual-verifies by header alg+kid: ES256 (against the loaded JWKS,
// ADR-005), SM2 (hybrid/SMx), and HS256 — so migration windows never reject a
// freshly issued token. Each kid binds to one alg; a header alg disagreeing with
// the kid's registered alg is rejected (RFC 8725 alg-confusion closure). Never
// accepts alg "none".
func (p *JWTProvider) Validate(tokenStr string) (*jwtutil.Claims, error) {
	return p.verifier().Validate(tokenStr)
}

// verifier lazily builds the single shared verify path (jwtutil.Verifier),
// replacing this provider's former hand-rolled dispatch keyfunc so it can never
// drift from the gateway's. Built once — keySet/sm2Key/issuer are all fixed by
// the time the first token is validated. The ES256 lookup closure reads p.keySet
// LIVE (and pins registeredAlg==ES256, the alg-confusion guard the keyset carries
// per-kid), so key rotation is picked up without a rebuild.
func (p *JWTProvider) verifier() *jwtutil.Verifier {
	p.verifierOnce.Do(func() {
		var sm2Pub *ecdsa.PublicKey
		if p.sm2Key != nil {
			sm2Pub = &p.sm2Key.PublicKey
		}
		var keyByKID func(string) (*ecdsa.PublicKey, bool)
		if p.keySet != nil {
			keyByKID = func(kid string) (*ecdsa.PublicKey, bool) {
				pub, registeredAlg, ok := p.keySet.VerifierByKID(kid)
				return pub, ok && registeredAlg == algES256
			}
		}
		p.verifierCache = jwtutil.NewVerifier(p.secret, sm2Pub, keyByKID, p.issuer, audience, kidHMAC)
	})
	return p.verifierCache
}

func (p *JWTProvider) sign(claims *jwtutil.Claims) (string, error) {
	// ES256 (ADR-005): opted in via signingAlg + a loaded KeySet with an active
	// signer. Stamped with the active key's kid so the verifier resolves the
	// public key from the published JWKS.
	if p.signingAlg == SigningAlgES256 && p.keySet != nil {
		kid, key, ok := p.keySet.ActiveSigner()
		if ok {
			token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			token.Header["kid"] = kid
			return token.SignedString(key)
		}
		// No active signer despite the selector: fall through to HS256 rather
		// than fail issuance (matches WithKeySet's conservative default).
	}
	if p.profile == cryptokey.ProfileSMx && p.sm2Key != nil {
		token := jwt.NewWithClaims(&cryptokey.SigningMethodSM2{}, claims)
		token.Header["kid"] = kidSM2
		return token.SignedString(p.sm2Key)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = kidHMAC
	return token.SignedString(p.secret)
}
