package auth

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

type TokenType = jwtutil.TokenType
type Claims = jwtutil.Claims

const (
	TypeAccess              = jwtutil.TypeAccess
	TypeMFAPending          = jwtutil.TypeMFAPending
	TypeRefresh             = jwtutil.TypeRefresh
	TypeForcePasswordChange = jwtutil.TypeForcePasswordChange
	TypePasswordReset       = jwtutil.TypePasswordReset
)

const audience = "mailserver-gateway"

// kidHMAC is the authserver's HS256 kid — the gateway is verify-only for every
// NORMAL session/access/refresh token, so it accepts only this kid for those.
const kidHMAC = "authserver-hmac-1"

// kidDriveNative is the gateway's OWN kid, used for exactly one purpose: the
// Drive P1 native-token bridge (IssueDriveNativeToken below). It is deliberately
// a DIFFERENT string from the retired "mailserver-hmac-1" general-issuance kid
// (arch A7 removed IssueAccess/Refresh/MFAPending/… as dead code and added
// TestJWTRejectsSelfIssuedKID to keep that kid rejected forever) — this is not
// a resurrection of that general capability, it is one narrow, scoped,
// single-caller signer sharing the same secret. A token with this kid always
// carries a non-empty Scp, so chain.go's scope-containment guard confines it
// to the one surface it names even if the mint logic itself had a bug.
const kidDriveNative = "mailserver-drive-native-1"

// kidMailAttachment signs only five-minute, one-blob transfer credentials.
// Keeping a distinct kid makes accidental widening or signer reuse visible in
// tests and incident evidence.
const kidMailAttachment = "mailserver-mail-attachment-1"

const mailAttachmentTokenTTL = 5 * time.Minute

// es256Verifier resolves an ES256 verification key by kid. It is satisfied by
// the JWKS client (*JWKSClient.KeyByKID) in production and by a stub in tests.
// nil means ES256 verification is disabled (HS256-only mode) — ES256 tokens then
// fail to verify, never panic.
type es256Verifier interface {
	KeyByKID(kid string) (*ecdsa.PublicKey, bool)
}

// JWTProvider VERIFIES first-party JWTs at the gateway — the authserver is the
// sole minter of every NORMAL session/access/refresh token. It verifies HS256,
// SM2, AND ES256 via the single shared jwtutil.Verifier: HS256 against the
// shared secret, SM2 against the shared SM2 public key, ES256 against the
// authserver JWKS (ADR-005 dual-verify — a rollout is never a flag day). The
// former general self-issuance path (IssueAccess/Refresh/MFAPending/…, kid
// "mailserver-hmac-1") was dead code and has been removed — permanently, per
// TestJWTRejectsSelfIssuedKID. IssueDriveNativeToken below is a narrow,
// single-purpose exception added for the Drive P1 native-token bridge; it
// mints under its OWN distinct kid (kidDriveNative), never the retired one.
type JWTProvider struct {
	secret                   []byte
	attachmentSecret         []byte
	attachmentPreviousSecret []byte
	sm2Key                   *ecdsa.PrivateKey // nil for standard profile; held only for its SM2 public half
	jwks                     es256Verifier     // nil ⇒ ES256 verification disabled (HS256-only)
	issuer                   string

	verifierOnce            sync.Once
	verifierCache           *jwtutil.Verifier
	attachmentVerifierCache []*jwtutil.Verifier
}

// NewJWTProvider builds the gateway's verify-only provider. issuer is the exact
// iss every inbound token must carry — it MUST equal the authserver's jwt.issuer
// (both read the same JWT_ISSUER env; see config), closing the former hard-coded
// "mailserver" const that could silently drift from a re-issued authserver.
func NewJWTProvider(secret string, sm2Key *ecdsa.PrivateKey, issuer string) *JWTProvider {
	secretBytes := []byte(secret)
	return &JWTProvider{
		secret:           secretBytes,
		attachmentSecret: cryptokey.DeriveMailAttachmentTokenKey(secretBytes),
		sm2Key:           sm2Key,
		issuer:           issuer,
	}
}

// SetMailAttachmentSecret replaces the default JWTSecret-derived attachment
// key with an independently rotatable gateway-only master secret. Empty keeps
// the backwards-compatible derived default. Call before the first Validate.
func (p *JWTProvider) SetMailAttachmentSecret(secret string) {
	if secret != "" {
		p.attachmentSecret = cryptokey.DeriveMailAttachmentTokenKey([]byte(secret))
	}
}

// SetMailAttachmentPreviousSecret installs the retiring gateway secret used
// only by the dedicated attachment-token verifier. Call it during startup,
// before the first Validate. It never changes the key used to mint new tokens.
func (p *JWTProvider) SetMailAttachmentPreviousSecret(secret string) {
	if secret == "" {
		return
	}
	derived := cryptokey.DeriveMailAttachmentTokenKey([]byte(secret))
	if bytes.Equal(derived, p.attachmentSecret) {
		return
	}
	p.attachmentPreviousSecret = derived
}

// SetES256Verifier installs the ES256 verification source (the JWKS client).
// Called at wiring time when AUTHSERVER_JWKS_URL is configured; when left unset,
// ES256 tokens simply fail to verify (HS256-only mode). Must be called before the
// first Validate (the verifier is built once, lazily).
func (p *JWTProvider) SetES256Verifier(v es256Verifier) { p.jwks = v }

// Validate parses and cryptographically verifies a JWT, returning its Claims.
// It does NOT check revocation (access tokens are short-lived; refresh tokens are
// tracked authserver-side) — see the shared jwtutil.Verifier for the crypto rules.
func (p *JWTProvider) Validate(tokenStr string) (*jwtutil.Claims, error) {
	parsed, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("auth: inspect jwt header: %w", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	if kid != kidMailAttachment {
		return p.verifier().Validate(tokenStr)
	}
	var lastErr error
	for _, verifier := range p.attachmentVerifiers() {
		claims, validateErr := verifier.Validate(tokenStr)
		if validateErr == nil {
			return claims, nil
		}
		lastErr = validateErr
	}
	return nil, fmt.Errorf("auth: attachment token validation failed: %w", lastErr)
}

// IssueDriveNativeToken mints a short-lived HS256 JWT for the Drive P1
// native-token bridge (POST /api/drive/native-token). A packaged native
// client (Electron main process, no renderer/window, no server-origin cookie)
// needs a credential it can hold outside the browser session; an
// already-authenticated web/API request mints itself this scoped mirror
// rather than re-implementing auth. See kidDriveNative for why this does not
// reopen the general self-issuance path arch A7 deliberately removed.
//
// from's JTI and FamilyID are carried forward UNCHANGED (never a fresh one)
// so the CA-3a runtime-access denylist revokes the derived token WITH the
// session it was minted from — killing the web session kills every native
// mirror derived from it. Cnf is never copied (the derived token is unbound —
// a main-process fetch with the window closed has no renderer to sign a DPoP
// proof, see shared/middleware/runtime_access.go's binding branch) and scope
// is always set, which is the OTHER half of the containment: chain.go's
// AuthenticateRequest rejects a non-empty Scp on any request path that
// doesn't start with "/"+scope.
func (p *JWTProvider) IssueDriveNativeToken(from *jwtutil.Claims, scope string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	now := time.Now()
	expiresAt = now.Add(ttl)
	claims := &jwtutil.Claims{
		UserID:      from.UserID,
		Email:       from.Email,
		Type:        jwtutil.TypeAccess,
		JTI:         from.JTI,
		FamilyID:    from.FamilyID,
		Scp:         scope,
		AccountType: from.AccountType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kidDriveNative
	token, err = tok.SignedString(p.secret)
	return token, expiresAt, err
}

// IssueMailAttachmentToken mints a one-blob credential with a fresh JTI while
// retaining the originating session family and exact origin JTI/iat inside the
// signed attachment binding. The accepting handler rechecks both the derived
// token (middleware) and the origin session (live database authority) on every
// Range request. The five-minute lifetime and surface scope are not caller
// configurable.
func (p *JWTProvider) IssueMailAttachmentToken(from *jwtutil.Claims, binding jwtutil.AttachmentTransferClaim) (token string, expiresAt time.Time, err error) {
	if from == nil || from.Type != jwtutil.TypeAccess || from.JTI == "" || from.IssuedAt == nil {
		return "", time.Time{}, errors.New("mail attachment token requires an issued access session with jti")
	}
	if binding.OriginJTI != "" || binding.OriginIssuedAt != 0 {
		return "", time.Time{}, errors.New("mail attachment origin is server-derived")
	}
	binding.OriginJTI = from.JTI
	binding.OriginIssuedAt = from.IssuedAt.Unix()

	now := time.Now()
	expiresAt = now.Add(mailAttachmentTokenTTL)
	claims := &jwtutil.Claims{
		UserID:      from.UserID,
		Email:       from.Email,
		Type:        jwtutil.TypeAccess,
		JTI:         uuid.NewString(),
		FamilyID:    from.FamilyID,
		Scp:         "mail-attachment",
		AccountType: from.AccountType,
		Device:      from.Device,
		Attachment:  &binding,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    p.issuer,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kidMailAttachment
	token, err = tok.SignedString(p.attachmentSecret)
	return token, expiresAt, err
}

// verifier lazily builds the single shared verify path. Built once — secret,
// sm2Key, jwks, and issuer are all fixed by wiring time, before the first token
// is validated.
func (p *JWTProvider) verifier() *jwtutil.Verifier {
	p.verifierOnce.Do(func() {
		var sm2Pub *ecdsa.PublicKey
		if p.sm2Key != nil {
			sm2Pub = &p.sm2Key.PublicKey
		}
		var keyByKID func(string) (*ecdsa.PublicKey, bool)
		if p.jwks != nil {
			keyByKID = p.jwks.KeyByKID
		}
		p.verifierCache = jwtutil.NewVerifier(p.secret, sm2Pub, keyByKID, p.issuer, audience, kidHMAC, kidDriveNative)
		p.attachmentVerifierCache = []*jwtutil.Verifier{
			jwtutil.NewVerifier(p.attachmentSecret, nil, nil, p.issuer, audience, kidMailAttachment),
		}
		if len(p.attachmentPreviousSecret) != 0 {
			p.attachmentVerifierCache = append(p.attachmentVerifierCache,
				jwtutil.NewVerifier(p.attachmentPreviousSecret, nil, nil, p.issuer, audience, kidMailAttachment))
		}
	})
	return p.verifierCache
}

func (p *JWTProvider) attachmentVerifiers() []*jwtutil.Verifier {
	p.verifier()
	return p.attachmentVerifierCache
}
