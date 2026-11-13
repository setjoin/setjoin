package federation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"setjoin.com/shared/envutil"
	"setjoin.com/shared/jwtutil"
)

// ── OP Storage ────────────────────────────────────────────────────────

// OPStorage implements zitadel's op.Storage backed by PostgreSQL. Post Wave 3,
// it is a thin coordinator over three cohesive collaborators, each owning one
// concern:
//
//   - clients  (*oidcClientStore)  — oidc_clients reads + client authentication
//   - tokens   (*oidcTokenStore)   — every oidc_tokens read/mutation, incl. the
//     single OIDC-token revoke seam
//   - signing  (*oidcSigningAdapter) — the RS256 key material (op.SigningKey/KeySet)
//
// OPStorage itself retains only the oidc_auth_requests coordination (which has
// to assemble zitadel's request types) and delegates the interface methods to
// the collaborators verbatim, so behavior is identical to the pre-split god-object.
type OPStorage struct {
	pool    *pgxpool.Pool
	clients *oidcClientStore
	tokens  *oidcTokenStore
	signing *oidcSigningAdapter
}

func NewOPStorage(pool *pgxpool.Pool, keyMgr *OIDCKeyManager) *OPStorage {
	return &OPStorage{
		pool:    pool,
		clients: newOIDCClientStore(pool),
		tokens:  newOIDCTokenStore(pool),
		signing: newOIDCSigningAdapter(keyMgr),
	}
}

// authContextForOPSession resolves the (acr, amr) the resource owner's OP
// session satisfied. The OP authorize flow proceeds only on an authenticated
// session whose floor is a verified password, so the floor is aal1 / [pwd].
//
// An RP MAY request a higher assurance via the acr_values parameter; we do NOT
// up-claim to satisfy it (a token must never assert an AAL the session did not
// reach). Honoring acr_values=aal2 means forcing the user through a second
// factor in the OP login UI and recording the performed methods here — wired
// when that login UI captures the factor set. Until then we return the truthful
// floor, which a relying party requiring aal2 will (correctly) reject.
func authContextForOPSession(_ *oidc.AuthRequest) (acr string, amr []string) {
	return jwtutil.ACRAAL1, []string{jwtutil.AMRPassword}
}

// ── AuthStorage ────────────────────────────────────────────────────────

func (s *OPStorage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	reqID := envutil.RandomID()
	req := (&storedAuthRequest{
		id:                  reqID,
		clientID:            authReq.ClientID,
		redirectURI:         authReq.RedirectURI,
		state:               authReq.State,
		nonce:               authReq.Nonce,
		scopes:              authReq.Scopes,
		codeChallenge:       authReq.CodeChallenge,
		codeChallengeMethod: string(authReq.CodeChallengeMethod),
		authTime:            time.Time{},
		done:                false,
	}).withAuthContext(authContextForOPSession(authReq))

	_, err := s.pool.Exec(ctx,
		`INSERT INTO oidc_auth_requests (id, client_id, redirect_uri, state, nonce,
		 code_challenge, code_challenge_method, scopes, user_id, expires_at,
		 done, auth_time, acr, amr)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,$9,FALSE,NULL,NULL,'{}')`,
		req.id, req.clientID, req.redirectURI, req.state, req.nonce,
		req.codeChallenge, req.codeChallengeMethod, req.scopes, time.Now().Add(10*time.Minute),
	)
	return req, err
}

func (s *OPStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	var req storedAuthRequest
	err := s.pool.QueryRow(ctx,
		`SELECT id, client_id, redirect_uri, state, nonce,
		        code_challenge, code_challenge_method, scopes,
		        COALESCE(user_id::text, ''), expires_at, done,
		        COALESCE(auth_time, created_at), COALESCE(acr, ''), amr
		 FROM oidc_auth_requests WHERE id = $1 AND expires_at > now()`, id,
	).Scan(&req.id, &req.clientID, &req.redirectURI, &req.state, &req.nonce,
		&req.codeChallenge, &req.codeChallengeMethod, &req.scopes, &req.userID,
		&req.expiresAt, &req.done, &req.authTime, &req.acr, &req.amr)
	if err != nil {
		return nil, fmt.Errorf("auth request not found: %w", err)
	}
	return &req, nil
}

// CompleteAuthRequest binds one short-lived OP request exactly once to the
// authenticated Setjoin session. A replay must not overwrite the original
// auth_time, ACR, or AMR before the code is exchanged.
func (s *OPStorage) CompleteAuthRequest(
	ctx context.Context,
	id string,
	userID int64,
	authTime time.Time,
	acr string,
	amr []string,
) error {
	if id == "" || userID <= 0 {
		return fmt.Errorf("invalid OIDC authorization completion")
	}
	if authTime.IsZero() {
		authTime = time.Now()
	}
	if acr == "" {
		acr = jwtutil.ACRAAL1
	}
	if amr == nil {
		amr = []string{}
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE oidc_auth_requests
		    SET user_id = $2,
		        done = TRUE,
		        auth_time = $3,
		        acr = $4,
		        amr = $5
		  WHERE id = $1
		    AND expires_at > now()
		    AND done = FALSE
		    AND user_id IS NULL`,
		id, userID, authTime, acr, amr,
	)
	if err != nil {
		return fmt.Errorf("complete OIDC authorization request: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("OIDC authorization request is missing, expired, or already bound")
	}
	return nil
}

// authorizationCodeDigest keeps bearer authorization codes out of the
// short-lived request table. The code still has to be presented verbatim to
// the token endpoint, but a database read cannot recover it.
func authorizationCodeDigest(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

// AuthRequestByCode atomically looks up and consumes the authorization code.
// It uses SELECT FOR UPDATE + DELETE in a single transaction so that two
// concurrent POST /token calls with the same code cannot both succeed.
// After this call succeeds, the code is consumed and DeleteAuthRequest is a no-op.
func (s *OPStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	if code == "" {
		return nil, fmt.Errorf("auth request not found: empty authorization code")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth request by code begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var req storedAuthRequest
	err = tx.QueryRow(ctx,
		`SELECT id, client_id, redirect_uri, state, nonce,
		        code_challenge, code_challenge_method, scopes,
		        COALESCE(user_id::text, ''), expires_at, done,
		        COALESCE(auth_time, created_at), COALESCE(acr, ''), amr
		 FROM oidc_auth_requests
		 WHERE code_hash = $1 AND expires_at > now() AND done = TRUE
		 FOR UPDATE`, authorizationCodeDigest(code),
	).Scan(&req.id, &req.clientID, &req.redirectURI, &req.state, &req.nonce,
		&req.codeChallenge, &req.codeChallengeMethod, &req.scopes, &req.userID,
		&req.expiresAt, &req.done, &req.authTime, &req.acr, &req.amr)
	if err != nil {
		return nil, fmt.Errorf("auth request not found: %w", err)
	}

	// Consume the code immediately — delete the row while holding the lock.
	_, err = tx.Exec(ctx, `DELETE FROM oidc_auth_requests WHERE id = $1`, req.id)
	if err != nil {
		return nil, fmt.Errorf("delete auth request: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit auth request consumption: %w", err)
	}
	return &req, nil
}

func (s *OPStorage) SaveAuthCode(ctx context.Context, id, code string) error {
	if id == "" || code == "" {
		return fmt.Errorf("invalid authorization code binding")
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE oidc_auth_requests
		    SET code_hash = $2
		  WHERE id = $1
		    AND expires_at > now()
		    AND done = TRUE
		    AND code_hash IS NULL`,
		id, authorizationCodeDigest(code),
	)
	if err != nil {
		return fmt.Errorf("save authorization code: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("authorization request is missing, expired, incomplete, or already has a code")
	}
	return nil
}

// DeleteAuthRequest is a no-op: the auth code is already consumed atomically
// in AuthRequestByCode (SELECT FOR UPDATE + DELETE in a single transaction).
func (s *OPStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	return nil
}

// Token operations delegate to the oidc_tokens store — the single owner of that
// table (Wave 3). OPStorage no longer holds any oidc_tokens SQL itself.

func (s *OPStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	return s.tokens.createAccessToken(ctx, request)
}

func (s *OPStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	return s.tokens.createAccessAndRefreshTokens(ctx, request, currentRefreshToken)
}

func (s *OPStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	return s.tokens.tokenRequestByRefreshToken(ctx, refreshToken)
}

func (s *OPStorage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return s.tokens.terminateSession(ctx, userID, clientID)
}

// RevokeToken funnels the OIDC OP's revocation through the token store's single
// revoke seam (the third revocation path of the Wave 3 unification). userID is
// part of zitadel's signature but the scoping is by client_id, exactly as before.
func (s *OPStorage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	return s.tokens.revoke(ctx, tokenOrTokenID, clientID)
}

func (s *OPStorage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	return s.tokens.refreshTokenInfo(ctx, clientID, token)
}

func (s *OPStorage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.signing.signingKey(), nil
}

func (s *OPStorage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return s.signing.signatureAlgorithms(), nil
}

func (s *OPStorage) KeySet(ctx context.Context) ([]op.Key, error) {
	return s.signing.keySet(), nil
}

// ── OPStorage ──────────────────────────────────────────────────────────

// Client operations delegate to the oidc_clients store — the single owner of
// that table + client authentication (Wave 3).

func (s *OPStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	return s.clients.getClient(ctx, clientID)
}

func (s *OPStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	return s.clients.authorize(ctx, clientID, clientSecret)
}

func (s *OPStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	var needEmail, needProfile bool
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userinfo.Subject = userID
		case oidc.ScopeEmail:
			needEmail = true
		case oidc.ScopeProfile:
			needProfile = true
		}
	}
	if needEmail || needProfile {
		email, name, err := s.tokens.userClaims(ctx, userID)
		if err != nil {
			return err
		}
		if needEmail {
			userinfo.Email = email
			userinfo.EmailVerified = oidc.Bool(true)
		}
		if needProfile {
			userinfo.Name = name
		}
	}
	return nil
}

func (s *OPStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	// The UserInfo acceptance path consults the SAME durable revocation check
	// the introspection path uses (scopesForActiveToken): a revoked (or unknown)
	// access token must not keep serving identity claims from /userinfo after
	// /revoke or a terminateSession — the DB row is the only revocation record,
	// and the library's cryptographic verification cannot see it. The returned
	// error makes the zitadel handler reject the UserInfo request.
	scopes, err := s.tokens.scopesForActiveToken(ctx, tokenID)
	if err != nil {
		return err
	}
	userinfo.Subject = subject
	var needEmail, needProfile bool
	for _, scope := range scopes {
		switch scope {
		case "email":
			needEmail = true
		case "profile":
			needProfile = true
		}
	}
	if needEmail || needProfile {
		email, name, err := s.tokens.userClaims(ctx, subject)
		if err != nil {
			return err
		}
		applyUserinfoClaims(userinfo, needEmail, needProfile, email, name)
	}
	return nil
}

func applyUserinfoClaims(
	userinfo *oidc.UserInfo,
	needEmail, needProfile bool,
	email, name string,
) {
	if needEmail {
		userinfo.Email = email
		userinfo.EmailVerified = true
	}
	if needProfile {
		userinfo.Name = name
	}
}

func (s *OPStorage) SetIntrospectionFromToken(ctx context.Context, introspect *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	scopes, err := s.tokens.scopesForActiveToken(ctx, tokenID)
	if err != nil {
		// A non-nil error here (unknown or revoked token) is how the caller
		// (zitadel's Introspect handler, token_intospection.go) is told to
		// respond {"active":false} instead of setting Active=true.
		return err
	}
	introspect.Active = true
	introspect.Subject = subject
	introspect.ClientID = clientID
	introspect.Scope = scopes
	return nil
}

func (s *OPStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

func (s *OPStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *OPStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

func (s *OPStorage) Health(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// ── Client type ──────────────────────────────────────────────────────

type storedClient struct {
	id, name, secretHash     string
	redirectURIs, grantTypes []string
	scopes                   []string
	enabled                  bool
	clientType               string // "public" or "confidential" (default confidential)
	cachedGrantTypes         []oidc.GrantType
}

func (c *storedClient) GetID() string                    { return c.id }
func (c *storedClient) RedirectURIs() []string           { return c.redirectURIs }
func (c *storedClient) PostLogoutRedirectURIs() []string { return nil }

func (c *storedClient) isPublic() bool { return c.clientType == "public" }

func (c *storedClient) ApplicationType() op.ApplicationType {
	if c.isPublic() {
		return op.ApplicationTypeNative
	}
	return op.ApplicationTypeWeb
}

func (c *storedClient) AuthMethod() oidc.AuthMethod {
	if c.isPublic() {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}
func (c *storedClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *storedClient) preComputeGrants() {
	out := make([]oidc.GrantType, 0, len(c.grantTypes))
	for _, t := range c.grantTypes {
		switch t {
		case "authorization_code":
			out = append(out, oidc.GrantTypeCode)
		case "refresh_token":
			out = append(out, oidc.GrantTypeRefreshToken)
		}
	}
	if len(out) == 0 {
		out = []oidc.GrantType{oidc.GrantTypeCode}
	}
	c.cachedGrantTypes = out
}

func (c *storedClient) GrantTypes() []oidc.GrantType {
	if c.cachedGrantTypes == nil {
		c.preComputeGrants()
	}
	return c.cachedGrantTypes
}
func (c *storedClient) LoginURL(requestID string) string {
	return "/auth/oidc/op/complete?id=" + url.QueryEscape(requestID)
}
func (c *storedClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *storedClient) IDTokenLifetime() time.Duration      { return 5 * time.Minute }
func (c *storedClient) DevMode() bool                       { return false }
func (c *storedClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return passthroughOIDCScopes
}
func (c *storedClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return passthroughOIDCScopes
}
func (c *storedClient) IsScopeAllowed(scope string) bool {
	for _, s := range c.scopes {
		if s == scope {
			return true
		}
	}
	return false
}
func (c *storedClient) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *storedClient) ClockSkew() time.Duration             { return 0 }

// zitadel calls both scope-restriction callbacks unconditionally. Returning a
// nil callback panics during token exchange; this client already enforces its
// registered allow-list at authorization time, so the token-stage callback is
// the identity function.
func passthroughOIDCScopes(scopes []string) []string {
	return scopes
}

// ── AuthRequest / TokenRequest type ──────────────────────────────────

type storedAuthRequest struct {
	id, clientID, redirectURI, state, nonce string
	codeChallenge, codeChallengeMethod      string
	scopes                                  []string
	userID                                  string
	authTime                                time.Time
	expiresAt                               time.Time
	done                                    bool

	// acr/amr: the authentication context the session satisfied. Reported via
	// GetACR/GetAMR into the id_token. Empty values fall back to the aal1/[pwd]
	// floor the OP authorize flow guarantees.
	acr string
	amr []string
}

// op.AuthRequest
func (r *storedAuthRequest) GetID() string          { return r.id }
func (r *storedAuthRequest) GetClientID() string    { return r.clientID }
func (r *storedAuthRequest) GetRedirectURI() string { return r.redirectURI }
func (r *storedAuthRequest) GetState() string       { return r.state }
func (r *storedAuthRequest) GetNonce() string       { return r.nonce }
func (r *storedAuthRequest) GetScopes() []string    { return r.scopes }
func (r *storedAuthRequest) GetResponseType() oidc.ResponseType {
	return oidc.ResponseTypeCode
}
func (r *storedAuthRequest) GetResponseMode() oidc.ResponseMode { return "" }

// GetACR / GetAMR feed the id_token's acr/amr claims (OIDC Core §2).
//
// The OP authorize flow only proceeds once the resource owner has an
// authenticated session, whose floor is a verified password. We therefore
// report at least aal1 / [pwd] rather than the empty values the zitadel
// interface defaults to, so relying parties receive a truthful authentication
// context. When a flow records stronger factors (set via withAuthContext), those
// are reflected instead — never weaker than what the session actually satisfied.
func (r *storedAuthRequest) GetACR() string {
	if r.acr != "" {
		return r.acr
	}
	return jwtutil.ACRAAL1
}

func (r *storedAuthRequest) GetAMR() []string {
	if len(r.amr) > 0 {
		return r.amr
	}
	return []string{jwtutil.AMRPassword}
}

// withAuthContext records the authentication context (acr/amr) the resource
// owner's session satisfied for this auth request, so the id_token reflects the
// factors actually performed. Empty values fall back to the aal1/[pwd] floor.
func (r *storedAuthRequest) withAuthContext(acr string, amr []string) *storedAuthRequest {
	r.acr = acr
	r.amr = amr
	return r
}
func (r *storedAuthRequest) GetAudience() []string  { return nil }
func (r *storedAuthRequest) GetAuthTime() time.Time { return r.authTime }
func (r *storedAuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if r.codeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: r.codeChallenge, Method: oidc.CodeChallengeMethodS256}
}
func (r *storedAuthRequest) GetSubject() string { return r.userID }
func (r *storedAuthRequest) Done() bool         { return r.done }

// userID accessor for internal use
func (r *storedAuthRequest) GetUserID() string { return r.userID }

// op.TokenRequest
func (r *storedAuthRequest) SetCurrentScopes(scopes []string) { r.scopes = scopes }

// ── Helpers ───────────────────────────────────────────────────────────

// extractClientID extracts the client ID from a TokenRequest that also
// satisfies the AuthRequest interface.
func extractClientID(request op.TokenRequest) string {
	if ar, ok := request.(interface{ GetClientID() string }); ok {
		return ar.GetClientID()
	}
	return ""
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// hex32 returns a hex-encoded 32-byte random identifier (refresh secret), used
// by the oidc_tokens store. The 16-byte case (token ids) uses envutil.RandomID.
func hex32() string { return hex.EncodeToString(randomBytes(32)) }

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
