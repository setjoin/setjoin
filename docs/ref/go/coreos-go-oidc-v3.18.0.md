package oidc // import "github.com/coreos/go-oidc/v3/oidc"

Package oidc implements OpenID Connect client logic for the golang.org/x/oauth2
package.

CONSTANTS

const (
	RS256 = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256 = "ES256" // ECDSA using P-256 and SHA-256
	ES384 = "ES384" // ECDSA using P-384 and SHA-384
	ES512 = "ES512" // ECDSA using P-521 and SHA-512
	PS256 = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
	EdDSA = "EdDSA" // Ed25519 using SHA-512
)
    JOSE asymmetric signing algorithm values as defined by RFC 7518

    see: https://tools.ietf.org/html/rfc7518#section-3.1

const (
	// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
	ScopeOpenID = "openid"

	// ScopeOfflineAccess is an optional scope defined by OpenID Connect for requesting
	// OAuth2 refresh tokens.
	//
	// Support for this scope differs between OpenID Connect providers. For instance
	// Google rejects it, favoring appending "access_type=offline" as part of the
	// authorization request instead.
	//
	// See: https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	ScopeOfflineAccess = "offline_access"
)

FUNCTIONS

func ClientContext(ctx context.Context, client *http.Client) context.Context
    ClientContext returns a new Context that carries the provided HTTP client.

    This method sets the same context key used by the golang.org/x/oauth2
    package, so the returned context works for that package too.

        myClient := &http.Client{}
        ctx := oidc.ClientContext(parentContext, myClient)

        // This will use the custom client
        provider, err := oidc.NewProvider(ctx, "https://accounts.example.com")

func InsecureIssuerURLContext(ctx context.Context, issuerURL string) context.Context
    InsecureIssuerURLContext allows discovery to work when the issuer_url
    reported by upstream is mismatched with the discovery URL. This is meant for
    integration with off-spec providers such as Azure.

        discoveryBaseURL := "https://login.microsoftonline.com/organizations/v2.0"
        issuerURL := "https://login.microsoftonline.com/my-tenantid/v2.0"

        ctx := oidc.InsecureIssuerURLContext(parentContext, issuerURL)

        // Provider will be discovered with the discoveryBaseURL, but use issuerURL
        // for future issuer validation.
        provider, err := oidc.NewProvider(ctx, discoveryBaseURL)

    This is insecure because validating the correct issuer is critical for
    multi-tenant providers. Any overrides here MUST be carefully reviewed.

func Nonce(nonce string) oauth2.AuthCodeOption
    Nonce returns an auth code option which requires the ID Token created by the
    OpenID Connect provider to contain the specified nonce.


TYPES

type Config struct {
	// Expected audience of the token. For a majority of the cases this is expected to be
	// the ID of the client that initialized the login flow. It may occasionally differ if
	// the provider supports the authorizing party (azp) claim.
	//
	// If not provided, users must explicitly set SkipClientIDCheck.
	ClientID string
	// If specified, only this set of algorithms may be used to sign the JWT.
	//
	// If the IDTokenVerifier is created from a provider with (*Provider).Verifier, this
	// defaults to the set of algorithms the provider supports. Otherwise this values
	// defaults to RS256.
	SupportedSigningAlgs []string

	// If true, no ClientID check performed. Must be true if ClientID field is empty.
	SkipClientIDCheck bool
	// If true, token expiry is not checked.
	SkipExpiryCheck bool

	// SkipIssuerCheck is intended for specialized cases where the the caller wishes to
	// defer issuer validation. When enabled, callers MUST independently verify the Token's
	// Issuer is a known good value.
	//
	// Mismatched issuers often indicate client mis-configuration. If mismatches are
	// unexpected, evaluate if the provided issuer URL is incorrect instead of enabling
	// this option.
	SkipIssuerCheck bool

	// Time function to check Token expiry. Defaults to time.Now
	Now func() time.Time

	// InsecureSkipSignatureCheck causes this package to skip JWT signature validation.
	// It's intended for special cases where providers (such as Azure), use the "none"
	// algorithm.
	//
	// This option can only be enabled safely when the ID Token is received directly
	// from the provider after the token exchange.
	//
	// This option MUST NOT be used when receiving an ID Token from sources other
	// than the token endpoint.
	InsecureSkipSignatureCheck bool
}
    Config is the configuration for an IDTokenVerifier.

type IDToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// A unique string which identifies the end user.
	Subject string

	// Expiry of the token. Ths package will not process tokens that have
	// expired unless that validation is explicitly turned off.
	Expiry time.Time
	// When the token was issued by the provider.
	IssuedAt time.Time

	// Initial nonce provided during the authentication redirect.
	//
	// This package does NOT provided verification on the value of this field
	// and it's the user's responsibility to ensure it contains a valid value.
	Nonce string

	// at_hash claim, if set in the ID token. Callers can verify an access token
	// that corresponds to the ID token using the VerifyAccessToken method.
	AccessTokenHash string

	// Has unexported fields.
}
    IDToken is an OpenID Connect extension that provides a predictable
    representation of an authorization event.

    The ID Token only holds fields OpenID Connect requires. To access additional
    claims returned by the server, use the Claims method.

func (i *IDToken) Claims(v interface{}) error
    Claims unmarshals the raw JSON payload of the ID Token into a provided
    struct.

        idToken, err := idTokenVerifier.Verify(rawIDToken)
        if err != nil {
        	// handle error
        }
        var claims struct {
        	Email         string `json:"email"`
        	EmailVerified bool   `json:"email_verified"`
        }
        if err := idToken.Claims(&claims); err != nil {
        	// handle error
        }

func (i *IDToken) VerifyAccessToken(accessToken string) error
    VerifyAccessToken verifies that the hash of the access token that
    corresponds to the iD token matches the hash in the id token.
    It returns an error if the hashes don't match. It is the caller's
    responsibility to ensure that the optional access token hash
    is present for the ID token before calling this method. See
    https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

type IDTokenVerifier struct {
	// Has unexported fields.
}
    IDTokenVerifier provides verification for ID Tokens.

func NewVerifier(issuerURL string, keySet KeySet, config *Config) *IDTokenVerifier
    NewVerifier returns a verifier manually constructed from a key set and
    issuer URL.

    It's easier to use provider discovery to construct an IDTokenVerifier than
    creating one directly. This method is intended to be used with provider that
    don't support metadata discovery, or avoiding round trips when the key set
    URL is already known.

    This constructor can be used to create a verifier directly using the issuer
    URL and JSON Web Key Set URL without using discovery:

        keySet := oidc.NewRemoteKeySet(ctx, "https://www.googleapis.com/oauth2/v3/certs")
        verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)

    Or a static key set (e.g. for testing):

        keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{pub1, pub2}}
        verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)

func (v *IDTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*IDToken, error)
    Verify parses a raw ID Token, verifies it's been signed by the provider,
    performs any additional checks depending on the Config, and returns the
    payload.

    Verify does NOT do nonce validation, which is the callers responsibility.

    See: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
        if err != nil {
            // handle error
        }

        // Extract the ID Token from oauth2 token.
        rawIDToken, ok := oauth2Token.Extra("id_token").(string)
        if !ok {
            // handle error
        }

        token, err := verifier.Verify(ctx, rawIDToken)

type KeySet interface {
	// VerifySignature parses the JSON web token, verifies the signature, and returns
	// the raw payload. Header and claim fields are validated by other parts of the
	// package. For example, the KeySet does not need to check values such as signature
	// algorithm, issuer, and audience since the IDTokenVerifier validates these values
	// independently.
	//
	// If VerifySignature makes HTTP requests to verify the token, it's expected to
	// use any HTTP client associated with the context through ClientContext.
	VerifySignature(ctx context.Context, jwt string) (payload []byte, err error)
}
    KeySet is a set of publc JSON Web Keys that can be used to validate the
    signature of JSON web tokens. This is expected to be backed by a remote
    key set through provider metadata discovery or an in-memory set of keys
    delivered out-of-band.

type Provider struct {
	// Has unexported fields.
}
    Provider represents an OpenID Connect server's configuration.

func NewProvider(ctx context.Context, issuer string) (*Provider, error)
    NewProvider uses the OpenID Connect discovery mechanism to construct a
    Provider. The issuer is the URL identifier for the service. For example:
    "https://accounts.google.com" or "https://login.salesforce.com".

    OpenID Connect providers that don't implement discovery or host the
    discovery document at a non-spec complaint path (such as requiring a URL
    parameter), should use ProviderConfig instead.

    See: https://openid.net/specs/openid-connect-discovery-1_0.html

func (p *Provider) Claims(v interface{}) error
    Claims unmarshals raw fields returned by the server during discovery.

        var claims struct {
            ScopesSupported []string `json:"scopes_supported"`
            ClaimsSupported []string `json:"claims_supported"`
        }

        if err := provider.Claims(&claims); err != nil {
            // handle unmarshaling error
        }

    For a list of fields defined by the OpenID Connect spec see:
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

func (p *Provider) Endpoint() oauth2.Endpoint
    Endpoint returns the OAuth2 auth and token endpoints for the given provider.

func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*UserInfo, error)
    UserInfo uses the token source to query the provider's user info endpoint.

func (p *Provider) UserInfoEndpoint() string
    UserInfoEndpoint returns the OpenID Connect userinfo endpoint for the given
    provider.

func (p *Provider) Verifier(config *Config) *IDTokenVerifier
    Verifier returns an IDTokenVerifier that uses the provider's key set to
    verify JWTs.

    The returned verifier uses a background context for all requests to the
    upstream JWKs endpoint. To control that context, use VerifierContext
    instead.

func (p *Provider) VerifierContext(ctx context.Context, config *Config) *IDTokenVerifier
    VerifierContext returns an IDTokenVerifier that uses the provider's key set
    to verify JWTs. As opposed to Verifier, the context is used to configure
    requests to the upstream JWKs endpoint. The provided context's cancellation
    is ignored.

type ProviderConfig struct {
	// IssuerURL is the identity of the provider, and the string it uses to sign
	// ID tokens with. For example "https://accounts.google.com". This value MUST
	// match ID tokens exactly.
	IssuerURL string `json:"issuer"`
	// AuthURL is the endpoint used by the provider to support the OAuth 2.0
	// authorization endpoint.
	AuthURL string `json:"authorization_endpoint"`
	// TokenURL is the endpoint used by the provider to support the OAuth 2.0
	// token endpoint.
	TokenURL string `json:"token_endpoint"`
	// DeviceAuthURL is the endpoint used by the provider to support the OAuth 2.0
	// device authorization endpoint.
	DeviceAuthURL string `json:"device_authorization_endpoint"`
	// UserInfoURL is the endpoint used by the provider to support the OpenID
	// Connect UserInfo flow.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	UserInfoURL string `json:"userinfo_endpoint"`
	// JWKSURL is the endpoint used by the provider to advertise public keys to
	// verify issued ID tokens. This endpoint is polled as new keys are made
	// available.
	JWKSURL string `json:"jwks_uri"`

	// Algorithms, if provided, indicate a list of JWT algorithms allowed to sign
	// ID tokens. If not provided, this defaults to the algorithms advertised by
	// the JWK endpoint, then the set of algorithms supported by this package.
	Algorithms []string `json:"id_token_signing_alg_values_supported"`
}
    ProviderConfig allows direct creation of a Provider from metadata
    configuration. This is intended for interop with providers that don't
    support discovery, or host the JSON discovery document at an off-spec path.

    The ProviderConfig struct specifies JSON struct tags to support document
    parsing.

        // Directly fetch the metadata document.
        resp, err := http.Get("https://login.example.com/custom-metadata-path")
        if err != nil {
        	// ...
        }
        defer resp.Body.Close()

        // Parse config from JSON metadata.
        config := &oidc.ProviderConfig{}
        if err := json.NewDecoder(resp.Body).Decode(config); err != nil {
        	// ...
        }
        p := config.NewProvider(context.Background())

    For providers that implement discovery, use NewProvider instead.

    See: https://openid.net/specs/openid-connect-discovery-1_0.html

func (p *ProviderConfig) NewProvider(ctx context.Context) *Provider
    NewProvider initializes a provider from a set of endpoints, rather than
    through discovery.

    The provided context is only used for http.Client configuration through
    ClientContext, not cancelation.

type RemoteKeySet struct {
	// Has unexported fields.
}
    RemoteKeySet is a KeySet implementation that validates JSON web tokens
    against a jwks_uri endpoint.

func NewRemoteKeySet(ctx context.Context, jwksURL string) *RemoteKeySet
    NewRemoteKeySet returns a KeySet that can validate JSON web tokens by using
    HTTP GETs to fetch JSON web token sets hosted at a remote URL. This is
    automatically used by NewProvider using the URLs returned by OpenID Connect
    discovery, but is exposed for providers that don't support discovery or to
    prevent round trips to the discovery URL.

    The returned KeySet is a long lived verifier that caches keys based on any
    keys change. Reuse a common remote key set instead of creating new ones as
    needed.

func (r *RemoteKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error)
    VerifySignature validates a payload against a signature from the jwks_uri.

    Users MUST NOT call this method directly and should use an IDTokenVerifier
    instead. This method skips critical validations such as 'alg' values and is
    only exported to implement the KeySet interface.

type StaticKeySet struct {
	// PublicKeys used to verify the JWT. Supported types are *rsa.PublicKey and
	// *ecdsa.PublicKey.
	PublicKeys []crypto.PublicKey
}
    StaticKeySet is a verifier that validates JWT against a static set of public
    keys.

func (s *StaticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error)
    VerifySignature compares the signature against a static set of public keys.

type TokenExpiredError struct {
	// Expiry is the time when the token expired.
	Expiry time.Time
}
    TokenExpiredError indicates that Verify failed because the token was
    expired. This error does NOT indicate that the token is not also invalid for
    other reasons. Other checks might have failed if the expiration check had
    not failed.

func (e *TokenExpiredError) Error() string

type UserInfo struct {
	Subject       string `json:"sub"`
	Profile       string `json:"profile"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	// Has unexported fields.
}
    UserInfo represents the OpenID Connect userinfo claims.

func (u *UserInfo) Claims(v interface{}) error
    Claims unmarshals the raw JSON object claims into the provided object.

