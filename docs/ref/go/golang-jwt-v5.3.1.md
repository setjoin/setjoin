package jwt // import "github.com/golang-jwt/jwt/v5"

Package jwt is a Go implementation of JSON Web Tokens:
http://self-issued.info/docs/draft-jones-json-web-token.html

See README.md for more info.

CONSTANTS

const UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"

VARIABLES

var (
	ErrNotECPublicKey  = errors.New("key is not a valid ECDSA public key")
	ErrNotECPrivateKey = errors.New("key is not a valid ECDSA private key")
)
var (
	ErrNotEdPrivateKey = errors.New("key is not a valid Ed25519 private key")
	ErrNotEdPublicKey  = errors.New("key is not a valid Ed25519 public key")
)
var (
	ErrInvalidKey                = errors.New("key is invalid")
	ErrInvalidKeyType            = errors.New("key is of invalid type")
	ErrHashUnavailable           = errors.New("the requested hash function is unavailable")
	ErrTokenMalformed            = errors.New("token is malformed")
	ErrTokenUnverifiable         = errors.New("token is unverifiable")
	ErrTokenSignatureInvalid     = errors.New("token signature is invalid")
	ErrTokenRequiredClaimMissing = errors.New("token is missing required claim")
	ErrTokenInvalidAudience      = errors.New("token has invalid audience")
	ErrTokenExpired              = errors.New("token is expired")
	ErrTokenUsedBeforeIssued     = errors.New("token used before issued")
	ErrTokenInvalidIssuer        = errors.New("token has invalid issuer")
	ErrTokenInvalidSubject       = errors.New("token has invalid subject")
	ErrTokenNotValidYet          = errors.New("token is not valid yet")
	ErrTokenInvalidId            = errors.New("token has invalid id")
	ErrTokenInvalidClaims        = errors.New("token has invalid claims")
	ErrInvalidType               = errors.New("invalid type for claim")
)
var (
	ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	ErrNotRSAPrivateKey    = errors.New("key is not a valid RSA private key")
	ErrNotRSAPublicKey     = errors.New("key is not a valid RSA public key")
)
var (
	// Sadly this is missing from crypto/ecdsa compared to crypto/rsa
	ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")
)
var (
	ErrEd25519Verification = errors.New("ed25519: verification error")
)
var MarshalSingleStringAsArray = true
    MarshalSingleStringAsArray modifies the behavior of the ClaimStrings type,
    especially its MarshalJSON function.

    If it is set to true (the default), it will always serialize the type as
    an array of strings, even if it just contains one element, defaulting
    to the behavior of the underlying []string. If it is set to false,
    it will serialize to a single string, if it contains one element. Otherwise,
    it will serialize to an array of strings.

var NoneSignatureTypeDisallowedError error
var TimePrecision = time.Second
    TimePrecision sets the precision of times and dates within this library.
    This has an influence on the precision of times when comparing expiry or
    other related time fields. Furthermore, it is also the precision of times
    when serializing.

    For backwards compatibility the default precision is set to seconds, so that
    no fractional timestamps are generated.

var SigningMethodNone *signingMethodNone
    SigningMethodNone implements the none signing method. This is required by
    the spec but you probably should never use it.


FUNCTIONS

func GetAlgorithms() (algs []string)
    GetAlgorithms returns a list of registered "alg" names

func Parse(tokenString string, keyFunc Keyfunc, options ...ParserOption) (*Token, error)
    Parse parses, validates, verifies the signature and returns the
    parsed token. keyFunc will receive the parsed token and should return
    the cryptographic key for verifying the signature. The caller is
    strongly encouraged to set the WithValidMethods option to validate
    the 'alg' claim in the token matches the expected algorithm.
    For more details about the importance of validating the 'alg' claim, see
    https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

func ParseECPrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error)
    ParseECPrivateKeyFromPEM parses a PEM encoded Elliptic Curve Private Key
    Structure

func ParseECPublicKeyFromPEM(key []byte) (*ecdsa.PublicKey, error)
    ParseECPublicKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 public key

func ParseEdPrivateKeyFromPEM(key []byte) (crypto.PrivateKey, error)
    ParseEdPrivateKeyFromPEM parses a PEM-encoded Edwards curve private key

func ParseEdPublicKeyFromPEM(key []byte) (crypto.PublicKey, error)
    ParseEdPublicKeyFromPEM parses a PEM-encoded Edwards curve public key

func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error)
    ParseRSAPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key

func ParseRSAPrivateKeyFromPEMWithPassword(key []byte, password string) (*rsa.PrivateKey, error)
    ParseRSAPrivateKeyFromPEMWithPassword parses a PEM encoded PKCS1 or PKCS8
    private key protected with password

    Deprecated: This function is deprecated and should not be used anymore.
    It uses the deprecated x509.DecryptPEMBlock function, which was
    deprecated since RFC 1423 is regarded insecure by design. Unfortunately,
    there is no alternative in the Go standard library for now. See
    https://github.com/golang/go/issues/8860.

func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error)
    ParseRSAPublicKeyFromPEM parses a certificate or a PEM encoded PKCS1 or PKIX
    public key

func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, options ...ParserOption) (*Token, error)
    ParseWithClaims is a shortcut for NewParser().ParseWithClaims().

    Note: If you provide a custom claim implementation that embeds one of the
    standard claims (such as RegisteredClaims), make sure that a) you either
    embed a non-pointer version of the claims or b) if you are using a pointer,
    allocate the proper memory for it before passing in the overall claims,
    otherwise you might run into a panic.

func RegisterSigningMethod(alg string, f func() SigningMethod)
    RegisterSigningMethod registers the "alg" name and a factory function
    for signing method. This is typically done during init() in the method's
    implementation


TYPES

type ClaimStrings []string
    ClaimStrings is basically just a slice of strings, but it can be either
    serialized from a string array or just a string. This type is necessary,
    since the "aud" claim can either be a single string or an array.

func (s ClaimStrings) MarshalJSON() (b []byte, err error)

func (s *ClaimStrings) UnmarshalJSON(data []byte) (err error)

type Claims interface {
	GetExpirationTime() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (ClaimStrings, error)
}
    Claims represent any form of a JWT Claims Set according to
    https://datatracker.ietf.org/doc/html/rfc7519#section-4. In order
    to have a common basis for validation, it is required that an
    implementation is able to supply at least the claim names provided in
    https://datatracker.ietf.org/doc/html/rfc7519#section-4.1 namely `exp`,
    `iat`, `nbf`, `iss`, `sub` and `aud`.

type ClaimsValidator interface {
	Claims
	Validate() error
}
    ClaimsValidator is an interface that can be implemented by custom
    claims who wish to execute any additional claims validation based on
    application-specific logic. The Validate function is then executed in
    addition to the regular claims validation and any error returned is appended
    to the final validation result.

        type MyCustomClaims struct {
            Foo string `json:"foo"`
            jwt.RegisteredClaims
        }

        func (m MyCustomClaims) Validate() error {
            if m.Foo != "bar" {
                return errors.New("must be foobar")
            }
            return nil
        }

type Keyfunc func(*Token) (any, error)
    Keyfunc will be used by the Parse methods as a callback function to supply
    the key for verification. The function receives the parsed, but unverified
    Token. This allows you to use properties in the Header of the token (such as
    `kid`) to identify which key to use.

    The returned any may be a single key or a VerificationKeySet containing
    multiple keys.

type MapClaims map[string]any
    MapClaims is a claims type that uses the map[string]any for JSON decoding.
    This is the default claims type if you don't supply one

func (m MapClaims) GetAudience() (ClaimStrings, error)
    GetAudience implements the Claims interface.

func (m MapClaims) GetExpirationTime() (*NumericDate, error)
    GetExpirationTime implements the Claims interface.

func (m MapClaims) GetIssuedAt() (*NumericDate, error)
    GetIssuedAt implements the Claims interface.

func (m MapClaims) GetIssuer() (string, error)
    GetIssuer implements the Claims interface.

func (m MapClaims) GetNotBefore() (*NumericDate, error)
    GetNotBefore implements the Claims interface.

func (m MapClaims) GetSubject() (string, error)
    GetSubject implements the Claims interface.

type NumericDate struct {
	time.Time
}
    NumericDate represents a JSON numeric date value, as referenced at
    https://datatracker.ietf.org/doc/html/rfc7519#section-2.

func NewNumericDate(t time.Time) *NumericDate
    NewNumericDate constructs a new *NumericDate from a standard library
    time.Time struct. It will truncate the timestamp according to the precision
    specified in TimePrecision.

func (date NumericDate) MarshalJSON() (b []byte, err error)
    MarshalJSON is an implementation of the json.RawMessage interface and
    serializes the UNIX epoch represented in NumericDate to a byte array,
    using the precision specified in TimePrecision.

func (date *NumericDate) UnmarshalJSON(b []byte) (err error)
    UnmarshalJSON is an implementation of the json.RawMessage interface and
    deserializes a NumericDate from a JSON representation, i.e. a json.Number.
    This number represents an UNIX epoch with either integer or non-integer
    seconds.

type Parser struct {
	// Has unexported fields.
}

func NewParser(options ...ParserOption) *Parser
    NewParser creates a new Parser with the specified options

func (p *Parser) DecodeSegment(seg string) ([]byte, error)
    DecodeSegment decodes a JWT specific base64url encoding. This function will
    take into account whether the Parser is configured with additional options,
    such as WithStrictDecoding or WithPaddingAllowed.

func (p *Parser) Parse(tokenString string, keyFunc Keyfunc) (*Token, error)
    Parse parses, validates, verifies the signature and returns the parsed
    token. keyFunc will receive the parsed token and should return the key for
    validating.

func (p *Parser) ParseUnverified(tokenString string, claims Claims) (token *Token, parts []string, err error)
    ParseUnverified parses the token but does not validate the signature.

    WARNING: Don't use this method unless you know what you're doing.

    It's only ever useful in cases where you know the signature is valid (since
    it has already been or will be checked elsewhere in the stack) and you want
    to extract values from it.

func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error)
    ParseWithClaims parses, validates, and verifies like Parse, but supplies
    a default object implementing the Claims interface. This provides default
    values which can be overridden and allows a caller to use their own type,
    rather than the default MapClaims implementation of Claims.

    Note: If you provide a custom claim implementation that embeds one of the
    standard claims (such as RegisteredClaims), make sure that a) you either
    embed a non-pointer version of the claims or b) if you are using a pointer,
    allocate the proper memory for it before passing in the overall claims,
    otherwise you might run into a panic.

type ParserOption func(*Parser)
    ParserOption is used to implement functional-style options that modify the
    behavior of the parser.

func WithAllAudiences(aud ...string) ParserOption
    WithAllAudiences configures the validator to require all the specified
    audiences in the `aud` claim. Validation will fail if the specified
    audiences are not listed in the token or the `aud` claim is missing.
    Duplicates within the list are de-duplicated since internally, we use a map
    to look up the audiences.

    NOTE: While the `aud` claim is OPTIONAL in a JWT, the handling of it is
    application-specific. Since this validation API is helping developers in
    writing secure application, we decided to REQUIRE the existence of the
    claim, if an audience is expected.

func WithAudience(aud ...string) ParserOption
    WithAudience configures the validator to require any of the specified
    audiences in the `aud` claim. Validation will fail if the audience is not
    listed in the token or the `aud` claim is missing.

    NOTE: While the `aud` claim is OPTIONAL in a JWT, the handling of it is
    application-specific. Since this validation API is helping developers in
    writing secure application, we decided to REQUIRE the existence of the
    claim, if an audience is expected.

func WithExpirationRequired() ParserOption
    WithExpirationRequired returns the ParserOption to make exp claim required.
    By default exp claim is optional.

func WithIssuedAt() ParserOption
    WithIssuedAt returns the ParserOption to enable verification of issued-at.

func WithIssuer(iss string) ParserOption
    WithIssuer configures the validator to require the specified issuer in the
    `iss` claim. Validation will fail if a different issuer is specified in the
    token or the `iss` claim is missing.

    NOTE: While the `iss` claim is OPTIONAL in a JWT, the handling of it is
    application-specific. Since this validation API is helping developers in
    writing secure application, we decided to REQUIRE the existence of the
    claim, if an issuer is expected.

func WithJSONNumber() ParserOption
    WithJSONNumber is an option to configure the underlying JSON parser with
    UseNumber.

func WithLeeway(leeway time.Duration) ParserOption
    WithLeeway returns the ParserOption for specifying the leeway window.

func WithNotBeforeRequired() ParserOption
    WithNotBeforeRequired returns the ParserOption to make nbf claim required.
    By default nbf claim is optional.

func WithPaddingAllowed() ParserOption
    WithPaddingAllowed will enable the codec used for decoding JWTs to allow
    padding. Note that the JWS RFC7515 states that the tokens will utilize a
    Base64url encoding with no padding. Unfortunately, some implementations
    of JWT are producing non-standard tokens, and thus require support for
    decoding.

func WithStrictDecoding() ParserOption
    WithStrictDecoding will switch the codec used for decoding JWTs into strict
    mode. In this mode, the decoder requires that trailing padding bits are
    zero, as described in RFC 4648 section 3.5.

func WithSubject(sub string) ParserOption
    WithSubject configures the validator to require the specified subject in the
    `sub` claim. Validation will fail if a different subject is specified in the
    token or the `sub` claim is missing.

    NOTE: While the `sub` claim is OPTIONAL in a JWT, the handling of it is
    application-specific. Since this validation API is helping developers in
    writing secure application, we decided to REQUIRE the existence of the
    claim, if a subject is expected.

func WithTimeFunc(f func() time.Time) ParserOption
    WithTimeFunc returns the ParserOption for specifying the time func.
    The primary use-case for this is testing. If you are looking for a way to
    account for clock-skew, WithLeeway should be used instead.

func WithValidMethods(methods []string) ParserOption
    WithValidMethods is an option to supply algorithm methods that the
    parser will check. Only those methods will be considered valid. It is
    heavily encouraged to use this option in order to prevent attacks such as
    https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.

func WithoutClaimsValidation() ParserOption
    WithoutClaimsValidation is an option to disable claims validation. This
    option should only be used if you exactly know what you are doing.

type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}
    RegisteredClaims are a structured version of the JWT Claims Set,
    restricted to Registered Claim Names, as referenced at
    https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

    This type can be used on its own, but then additional private and public
    claims embedded in the JWT will not be parsed. The typical use-case
    therefore is to embedded this in a user-defined claim type.

    See examples for how to use this with your own claim types.

func (c RegisteredClaims) GetAudience() (ClaimStrings, error)
    GetAudience implements the Claims interface.

func (c RegisteredClaims) GetExpirationTime() (*NumericDate, error)
    GetExpirationTime implements the Claims interface.

func (c RegisteredClaims) GetIssuedAt() (*NumericDate, error)
    GetIssuedAt implements the Claims interface.

func (c RegisteredClaims) GetIssuer() (string, error)
    GetIssuer implements the Claims interface.

func (c RegisteredClaims) GetNotBefore() (*NumericDate, error)
    GetNotBefore implements the Claims interface.

func (c RegisteredClaims) GetSubject() (string, error)
    GetSubject implements the Claims interface.

type SigningMethod interface {
	Verify(signingString string, sig []byte, key any) error // Returns nil if signature is valid
	Sign(signingString string, key any) ([]byte, error)     // Returns signature or error
	Alg() string                                            // returns the alg identifier for this method (example: 'HS256')
}
    SigningMethod can be used add new methods for signing or verifying tokens.
    It takes a decoded signature as an input in the Verify function and produces
    a signature in Sign. The signature is then usually base64 encoded as part of
    a JWT.

func GetSigningMethod(alg string) (method SigningMethod)
    GetSigningMethod retrieves a signing method from an "alg" string

type SigningMethodECDSA struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}
    SigningMethodECDSA implements the ECDSA family of signing methods. Expects
    *ecdsa.PrivateKey for signing and *ecdsa.PublicKey for verification

var (
	SigningMethodES256 *SigningMethodECDSA
	SigningMethodES384 *SigningMethodECDSA
	SigningMethodES512 *SigningMethodECDSA
)
    Specific instances for EC256 and company

func (m *SigningMethodECDSA) Alg() string

func (m *SigningMethodECDSA) Sign(signingString string, key any) ([]byte, error)
    Sign implements token signing for the SigningMethod. For this signing
    method, key must be an ecdsa.PrivateKey struct

func (m *SigningMethodECDSA) Verify(signingString string, sig []byte, key any) error
    Verify implements token verification for the SigningMethod. For this verify
    method, key must be an ecdsa.PublicKey struct

type SigningMethodEd25519 struct{}
    SigningMethodEd25519 implements the EdDSA family. Expects ed25519.PrivateKey
    for signing and ed25519.PublicKey for verification

var (
	SigningMethodEdDSA *SigningMethodEd25519
)
    Specific instance for EdDSA

func (m *SigningMethodEd25519) Alg() string

func (m *SigningMethodEd25519) Sign(signingString string, key any) ([]byte, error)
    Sign implements token signing for the SigningMethod. For this signing
    method, key must be an ed25519.PrivateKey

func (m *SigningMethodEd25519) Verify(signingString string, sig []byte, key any) error
    Verify implements token verification for the SigningMethod. For this verify
    method, key must be an ed25519.PublicKey

type SigningMethodHMAC struct {
	Name string
	Hash crypto.Hash
}
    SigningMethodHMAC implements the HMAC-SHA family of signing methods. Expects
    key type of []byte for both signing and validation

var (
	SigningMethodHS256  *SigningMethodHMAC
	SigningMethodHS384  *SigningMethodHMAC
	SigningMethodHS512  *SigningMethodHMAC
	ErrSignatureInvalid = errors.New("signature is invalid")
)
    Specific instances for HS256 and company

func (m *SigningMethodHMAC) Alg() string

func (m *SigningMethodHMAC) Sign(signingString string, key any) ([]byte, error)
    Sign implements token signing for the SigningMethod. Key must be []byte.

    Note it is not advised to provide a []byte which was converted
    from a 'human readable' string using a subset of ASCII characters.
    To maximize entropy, you should ideally be providing a []byte key
    which was produced from a cryptographically random source, e.g.
    crypto/rand. Additional information about this, and why we intentionally
    are not supporting string as a key can be found on our usage guide
    https://golang-jwt.github.io/jwt/usage/signing_methods/.

func (m *SigningMethodHMAC) Verify(signingString string, sig []byte, key any) error
    Verify implements token verification for the SigningMethod. Returns nil if
    the signature is valid. Key must be []byte.

    Note it is not advised to provide a []byte which was converted
    from a 'human readable' string using a subset of ASCII characters.
    To maximize entropy, you should ideally be providing a []byte key
    which was produced from a cryptographically random source, e.g.
    crypto/rand. Additional information about this, and why we intentionally
    are not supporting string as a key can be found on our usage guide
    https://golang-jwt.github.io/jwt/usage/signing_methods/#signing-methods-and-key-types.

type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}
    SigningMethodRSA implements the RSA family of signing methods. Expects
    *rsa.PrivateKey for signing and *rsa.PublicKey for validation

var (
	SigningMethodRS256 *SigningMethodRSA
	SigningMethodRS384 *SigningMethodRSA
	SigningMethodRS512 *SigningMethodRSA
)
    Specific instances for RS256 and company

func (m *SigningMethodRSA) Alg() string

func (m *SigningMethodRSA) Sign(signingString string, key any) ([]byte, error)
    Sign implements token signing for the SigningMethod For this signing method,
    must be an *rsa.PrivateKey structure.

func (m *SigningMethodRSA) Verify(signingString string, sig []byte, key any) error
    Verify implements token verification for the SigningMethod For this signing
    method, must be an *rsa.PublicKey structure.

type SigningMethodRSAPSS struct {
	*SigningMethodRSA
	Options *rsa.PSSOptions
	// VerifyOptions is optional. If set overrides Options for rsa.VerifyPPS.
	// Used to accept tokens signed with rsa.PSSSaltLengthAuto, what doesn't follow
	// https://tools.ietf.org/html/rfc7518#section-3.5 but was used previously.
	// See https://github.com/dgrijalva/jwt-go/issues/285#issuecomment-437451244 for details.
	VerifyOptions *rsa.PSSOptions
}
    SigningMethodRSAPSS implements the RSAPSS family of signing methods signing
    methods

var (
	SigningMethodPS256 *SigningMethodRSAPSS
	SigningMethodPS384 *SigningMethodRSAPSS
	SigningMethodPS512 *SigningMethodRSAPSS
)
    Specific instances for RS/PS and company.

func (m *SigningMethodRSAPSS) Sign(signingString string, key any) ([]byte, error)
    Sign implements token signing for the SigningMethod. For this signing
    method, key must be an rsa.PrivateKey struct

func (m *SigningMethodRSAPSS) Verify(signingString string, sig []byte, key any) error
    Verify implements token verification for the SigningMethod. For this verify
    method, key must be an rsa.PublicKey struct

type Token struct {
	Raw       string         // Raw contains the raw token.  Populated when you [Parse] a token
	Method    SigningMethod  // Method is the signing method used or to be used
	Header    map[string]any // Header is the first segment of the token in decoded form
	Claims    Claims         // Claims is the second segment of the token in decoded form
	Signature []byte         // Signature is the third segment of the token in decoded form.  Populated when you [Parse] or sign a token
	Valid     bool           // Valid specifies if the token is valid.  Populated when you [Parse] a token
}
    Token represents a JWT Token. Different fields will be used depending on
    whether you're creating or parsing/verifying a token.

func New(method SigningMethod, opts ...TokenOption) *Token
    New creates a new Token with the specified signing method and an empty map
    of claims. Additional options can be specified, but are currently unused.

func NewWithClaims(method SigningMethod, claims Claims, opts ...TokenOption) *Token
    NewWithClaims creates a new Token with the specified signing method and
    claims. Additional options can be specified, but are currently unused.

func (*Token) EncodeSegment(seg []byte) string
    EncodeSegment encodes a JWT specific base64url encoding with padding
    stripped. In the future, this function might take into account a
    TokenOption. Therefore, this function exists as a method of Token, rather
    than a global function.

func (t *Token) SignedString(key any) (string, error)
    SignedString creates and returns a complete, signed JWT. The token is
    signed using the SigningMethod specified in the token. Please refer to
    https://golang-jwt.github.io/jwt/usage/signing_methods/#signing-methods-and-key-types
    for an overview of the different signing methods and their respective key
    types.

func (t *Token) SigningString() (string, error)
    SigningString generates the signing string. This is the most expensive
    part of the whole deal. Unless you need this for something special, just go
    straight for the SignedString.

type TokenOption func(*Token)
    TokenOption is a reserved type, which provides some forward compatibility,
    if we ever want to introduce token creation-related options.

type Validator struct {
	// Has unexported fields.
}
    Validator is the core of the new Validation API. It is automatically used by
    a Parser during parsing and can be modified with various parser options.

    The NewValidator function should be used to create an instance of this
    struct.

func NewValidator(opts ...ParserOption) *Validator
    NewValidator can be used to create a stand-alone validator with the supplied
    options. This validator can then be used to validate already parsed claims.

    Note: Under normal circumstances, explicitly creating a validator is not
    needed and can potentially be dangerous; instead functions of the Parser
    class should be used.

    The Validator is only checking the *validity* of the claims, such as its
    expiration time, but it does NOT perform *signature verification* of the
    token.

func (v *Validator) Validate(claims Claims) error
    Validate validates the given claims. It will also perform any custom
    validation if claims implements the ClaimsValidator interface.

    Note: It will NOT perform any *signature verification* on the token that
    contains the claims and expects that the [Claim] was already successfully
    verified.

type VerificationKey interface {
	crypto.PublicKey | []uint8
}
    VerificationKey represents a public or secret key for verifying a token's
    signature.

type VerificationKeySet struct {
	Keys []VerificationKey
}
    VerificationKeySet is a set of public or secret keys. It is used by the
    parser to verify a token.

