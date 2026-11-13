package samlsp // import "github.com/crewjam/saml/samlsp"

Package samlsp provides helpers that can be used to protect web services using
SAML.

VARIABLES

var ErrNoSession = errors.New("saml: session not present")
    ErrNoSession is the error returned when the remote user does not have a
    session


FUNCTIONS

func AttributeFromContext(ctx context.Context, name string) string
    AttributeFromContext is a convenience method that returns the named
    attribute from the session, if available.

func ContextWithSession(ctx context.Context, session Session) context.Context
    ContextWithSession returns a new context with session associated

func DefaultOnError(w http.ResponseWriter, _ *http.Request, err error)
    DefaultOnError is the default ErrorFunction implementation. It prints an
    message via the standard log package and returns a simple text "Forbidden"
    message to the user.

func DefaultServiceProvider(opts Options) saml.ServiceProvider
    DefaultServiceProvider returns the default saml.ServiceProvider for the
    provided options.

func FetchMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error)
    FetchMetadata returns metadata from an IDP metadata URL.

func ParseMetadata(data []byte) (*saml.EntityDescriptor, error)
    ParseMetadata parses arbitrary SAML IDP metadata.

    Note: this is needed because IDP metadata is sometimes wrapped in
    an <EntitiesDescriptor>, and sometimes the top level element is an
    <EntityDescriptor>.

func RequireAttribute(name, value string) func(http.Handler) http.Handler
    RequireAttribute returns a middleware function that requires that the SAML
    attribute `name` be set to `value`. This can be used to require that a
    remote user be a member of a group. It relies on the Claims assigned to to
    the context in RequireAccount.


TYPES

type AssertionHandler interface {
	HandleAssertion(assertion *saml.Assertion) error
}
    AssertionHandler is an interface implemented by types that can handle
    assertions and add extra functionality

type Attributes map[string][]string
    Attributes is a map of attributes provided in the SAML assertion

func (a Attributes) Get(key string) string
    Get returns the first attribute named `key` or an empty string if no such
    attributes is present.

type CookieRequestTracker struct {
	ServiceProvider *saml.ServiceProvider
	NamePrefix      string
	Codec           TrackedRequestCodec
	MaxAge          time.Duration
	RelayStateFunc  func(w http.ResponseWriter, r *http.Request) string
	SameSite        http.SameSite
}
    CookieRequestTracker tracks requests by setting a uniquely named cookie for
    each request.

func DefaultRequestTracker(opts Options, serviceProvider *saml.ServiceProvider) CookieRequestTracker
    DefaultRequestTracker returns a new RequestTracker for the provided options,
    a CookieRequestTracker which uses cookies to track pending requests.

func (t CookieRequestTracker) GetTrackedRequest(r *http.Request, index string) (*TrackedRequest, error)
    GetTrackedRequest returns a pending tracked request.

func (t CookieRequestTracker) GetTrackedRequests(r *http.Request) []TrackedRequest
    GetTrackedRequests returns all the pending tracked requests

func (t CookieRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error
    StopTrackingRequest stops tracking the SAML request given by index, which is
    a string previously returned from TrackRequest

func (t CookieRequestTracker) TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (string, error)
    TrackRequest starts tracking the SAML request with the given ID. It returns
    an `index` that should be used as the RelayState in the SAMl request flow.

type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Path     string
	Codec    SessionCodec
}
    CookieSessionProvider is an implementation of SessionProvider that stores
    session tokens in an HTTP cookie.

func DefaultSessionProvider(opts Options) CookieSessionProvider
    DefaultSessionProvider returns the default SessionProvider for the provided
    options, a CookieSessionProvider configured to store sessions in a cookie.

func (c CookieSessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error
    CreateSession is called when we have received a valid SAML assertion and
    should create a new session and modify the http response accordingly, e.g.
    by setting a cookie.

func (c CookieSessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error
    DeleteSession is called to modify the response such that it removed the
    current session, e.g. by deleting a cookie.

func (c CookieSessionProvider) GetSession(r *http.Request) (Session, error)
    GetSession returns the current Session associated with the request,
    or ErrNoSession if there is no valid session.

type ErrorFunction func(w http.ResponseWriter, r *http.Request, err error)
    ErrorFunction is a callback that is invoked to return an error to the web
    user.

type JWTSessionClaims struct {
	jwt.StandardClaims
	Attributes  Attributes `json:"attr"`
	SAMLSession bool       `json:"saml-session"`
}
    JWTSessionClaims represents the JWT claims in the encoded session

func (c JWTSessionClaims) GetAttributes() Attributes
    GetAttributes implements SessionWithAttributes. It returns the SAMl
    attributes.

type JWTSessionCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           crypto.Signer
}
    JWTSessionCodec implements SessionCoded to encode and decode Sessions from
    the corresponding JWT.

func DefaultSessionCodec(opts Options) JWTSessionCodec
    DefaultSessionCodec returns the default SessionCodec for the provided
    options, a JWTSessionCodec configured to issue signed tokens.

func (c JWTSessionCodec) Decode(signed string) (Session, error)
    Decode parses the serialized session that may have been returned by Encode
    and returns a Session.

func (c JWTSessionCodec) Encode(s Session) (string, error)
    Encode returns a serialized version of the Session.

    The provided session must be a JWTSessionClaims, otherwise this function
    will panic.

func (c JWTSessionCodec) New(assertion *saml.Assertion) (Session, error)
    New creates a Session from the SAML assertion.

    The returned Session is a JWTSessionClaims.

type JWTTrackedRequestClaims struct {
	jwt.RegisteredClaims
	TrackedRequest
	SAMLAuthnRequest bool `json:"saml-authn-request"`
}
    JWTTrackedRequestClaims represents the JWT claims for a tracked request.

type JWTTrackedRequestCodec struct {
	SigningMethod jwt.SigningMethod
	Audience      string
	Issuer        string
	MaxAge        time.Duration
	Key           crypto.Signer
}
    JWTTrackedRequestCodec encodes TrackedRequests as signed JWTs

func DefaultTrackedRequestCodec(opts Options) JWTTrackedRequestCodec
    DefaultTrackedRequestCodec returns a new TrackedRequestCodec for the
    provided options, a JWTTrackedRequestCodec that uses a JWT to encode
    TrackedRequests.

func (s JWTTrackedRequestCodec) Decode(signed string) (*TrackedRequest, error)
    Decode returns a Tracked request from an encoded string.

func (s JWTTrackedRequestCodec) Encode(value TrackedRequest) (string, error)
    Encode returns an encoded string representing the TrackedRequest.

type Middleware struct {
	ServiceProvider  saml.ServiceProvider
	OnError          func(w http.ResponseWriter, r *http.Request, err error)
	Binding          string // either saml.HTTPPostBinding or saml.HTTPRedirectBinding
	ResponseBinding  string // either saml.HTTPPostBinding or saml.HTTPArtifactBinding
	RequestTracker   RequestTracker
	Session          SessionProvider
	AssertionHandler AssertionHandler
}
    Middleware implements middleware than allows a web application to support
    SAML.

    It implements http.Handler so that it can provide the metadata and ACS
    endpoints, typically /saml/metadata and /saml/acs, respectively.

    It also provides middleware RequireAccount which redirects users to the auth
    process if they do not have session credentials.

    When redirecting the user through the SAML auth flow, the middleware assigns
    a temporary cookie with a random name beginning with "saml_". The value of
    the cookie is a signed JSON Web Token containing the original URL requested
    and the SAML request ID. The random part of the name corresponds to the
    RelayState parameter passed through the SAML flow.

    When validating the SAML response, the RelayState is used to look up the
    correct cookie, validate that the SAML request ID, and redirect the user
    back to their original URL.

    Sessions are established by issuing a JSON Web Token (JWT) as a session
    cookie once the SAML flow has succeeded. The JWT token contains the
    authenticated attributes from the SAML assertion.

    When the middleware receives a request with a valid session JWT it extracts
    the SAML attributes and modifies the http.Request object adding a Context
    object to the request context that contains attributes from the initial SAML
    assertion.

    When issuing JSON Web Tokens, a signing key is required. Because the SAML
    service provider already has a private key, we borrow that key to sign the
    JWTs as well.

func New(opts Options) (*Middleware, error)
    New creates a new Middleware with the default providers for the given
    options.

    You can customize the behavior of the middleware in more detail by replacing
    and/or changing Session, RequestTracker, and ServiceProvider in the returned
    Middleware.

func (m *Middleware) CreateSessionFromAssertion(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion, redirectURI string)
    CreateSessionFromAssertion is invoked by ServeHTTP when we have a new,
    valid SAML assertion.

func (m *Middleware) HandleStartAuthFlow(w http.ResponseWriter, r *http.Request)
    HandleStartAuthFlow is called to start the SAML authentication process.

func (m *Middleware) RequireAccount(handler http.Handler) http.Handler
    RequireAccount is HTTP middleware that requires that each request be
    associated with a valid session. If the request is not associated with a
    valid session, then rather than serve the request, the middleware redirects
    the user to start the SAML auth flow.

func (m *Middleware) ServeACS(w http.ResponseWriter, r *http.Request)
    ServeACS handles requests for the SAML ACS endpoint.

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request)
    ServeHTTP implements http.Handler and serves the SAML-specific HTTP
    endpoints on the URIs specified by m.ServiceProvider.MetadataURL and
    m.ServiceProvider.AcsURL.

func (m *Middleware) ServeMetadata(w http.ResponseWriter, _ *http.Request)
    ServeMetadata handles requests for the SAML metadata endpoint.

type NopAssertionHandler struct{}
    NopAssertionHandler is an implementation of AssertionHandler that does
    nothing.

func DefaultAssertionHandler(_ Options) NopAssertionHandler
    DefaultAssertionHandler returns the default AssertionHandler for the
    provided options, a NopAssertionHandler configured to do nothing.

func (as NopAssertionHandler) HandleAssertion(_ *saml.Assertion) error
    HandleAssertion is called and passed a SAML assertion. This implementation
    does nothing.

type Options struct {
	EntityID              string
	URL                   url.URL
	Key                   crypto.Signer
	Certificate           *x509.Certificate
	Intermediates         []*x509.Certificate
	HTTPClient            *http.Client
	AllowIDPInitiated     bool
	DefaultRedirectURI    string
	IDPMetadata           *saml.EntityDescriptor
	SignRequest           bool
	UseArtifactResponse   bool
	ForceAuthn            bool // TODO(ross): this should be *bool
	RequestedAuthnContext *saml.RequestedAuthnContext
	CookieSameSite        http.SameSite
	CookieName            string
	RelayStateFunc        func(w http.ResponseWriter, r *http.Request) string
	LogoutBindings        []string
}
    Options represents the parameters for creating a new middleware

type RequestTracker interface {
	// TrackRequest starts tracking the SAML request with the given ID. It returns an
	// `index` that should be used as the RelayState in the SAMl request flow.
	TrackRequest(w http.ResponseWriter, r *http.Request, samlRequestID string) (index string, err error)

	// StopTrackingRequest stops tracking the SAML request given by index, which is a string
	// previously returned from TrackRequest
	StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error

	// GetTrackedRequests returns all the pending tracked requests
	GetTrackedRequests(r *http.Request) []TrackedRequest

	// GetTrackedRequest returns a pending tracked request.
	GetTrackedRequest(r *http.Request, index string) (*TrackedRequest, error)
}
    RequestTracker tracks pending authentication requests.

    There are two main reasons for this:

     1. When the middleware initiates an authentication request it must track
        the original URL in order to redirect the user to the right place after
        the authentication completes.

     2. After the authentication completes, we want to ensure that the user
        presenting the assertion is actually the one the request it, to mitigate
        request forgeries.

type Session interface{}
    Session is an interface implemented to contain a session.

func SessionFromContext(ctx context.Context) Session
    SessionFromContext returns the session associated with ctx, or nil if no
    session are associated

type SessionCodec interface {
	// New creates a Session from the SAML assertion.
	New(assertion *saml.Assertion) (Session, error)

	// Encode returns a serialized version of the Session.
	//
	// Note: When implementing this function, it is reasonable to expect that
	// Session is of the exact type returned by New(), and panic if it is not.
	Encode(s Session) (string, error)

	// Decode parses the serialized session that may have been returned by Encode
	// and returns a Session.
	Decode(string) (Session, error)
}
    SessionCodec is an interface to convert SAML assertions to a Session.
    The default implementation uses JWTs, JWTSessionCodec.

type SessionProvider interface {
	// CreateSession is called when we have received a valid SAML assertion and
	// should create a new session and modify the http response accordingly, e.g. by
	// setting a cookie.
	CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error

	// DeleteSession is called to modify the response such that it removed the current
	// session, e.g. by deleting a cookie.
	DeleteSession(w http.ResponseWriter, r *http.Request) error

	// GetSession returns the current Session associated with the request, or
	// ErrNoSession if there is no valid session.
	GetSession(r *http.Request) (Session, error)
}
    SessionProvider is an interface implemented by types that can
    track the active session of a user. The default implementation is
    CookieSessionProvider

type SessionWithAttributes interface {
	Session
	GetAttributes() Attributes
}
    SessionWithAttributes is a session that can expose the attributes provided
    by the SAML identity provider.

type TrackedRequest struct {
	Index         string `json:"-"`
	SAMLRequestID string `json:"id"`
	URI           string `json:"uri"`
}
    TrackedRequest holds the data we store for each pending request.

type TrackedRequestCodec interface {
	// Encode returns an encoded string representing the TrackedRequest.
	Encode(value TrackedRequest) (string, error)

	// Decode returns a Tracked request from an encoded string.
	Decode(signed string) (*TrackedRequest, error)
}
    TrackedRequestCodec handles encoding and decoding of a TrackedRequest.

