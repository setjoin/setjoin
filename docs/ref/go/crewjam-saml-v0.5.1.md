package saml // import "github.com/crewjam/saml"

Package saml contains a partial implementation of the SAML standard in golang.
SAML is a standard for identity federation, i.e. either allowing a third
party to authenticate your users or allowing third parties to rely on us to
authenticate their users.

# Introduction

In SAML parlance an Identity Provider (IDP) is a service that knows how to
authenticate users. A Service Provider (SP) is a service that delegates
authentication to an IDP. If you are building a service where users log in
with someone else's credentials, then you are a Service Provider. This package
supports implementing both service providers and identity providers.

The core package contains the implementation of SAML. The package samlsp
provides helper middleware suitable for use in Service Provider applications.
The package samlidp provides a rudimentary IDP service that is useful for
testing or as a starting point for other integrations.

# Breaking Changes

Version 0.4.0 introduces a few breaking changes to the _samlsp_ package in order
to make the package more extensible, and to clean up the interfaces a bit.
The default behavior remains the same, but you can now provide interface
implementations of _RequestTracker_ (which tracks pending requests), _Session_
(which handles maintaining a session) and _OnError_ which handles reporting
errors.

Public fields of _samlsp.Middleware_ have changed, so some usages may require
adjustment. See [issue 231](https://github.com/crewjam/saml/issues/231) for
details.

The option to provide an IDP metadata URL has been deprecated. Instead,
we recommend that you use the `FetchMetadata()` function, or fetch the metadata
yourself and use the new `ParseMetadata()` function, and pass the metadata in
_samlsp.Options.IDPMetadata_.

Similarly, the _HTTPClient_ field is now deprecated because it was only used for
fetching metdata, which is no longer directly implemented.

The fields that manage how cookies are set are deprecated as well. To customize
how cookies are managed, provide custom implementation of _RequestTracker_
and/or _Session_, perhaps by extending the default implementations.

The deprecated fields have not been removed from the Options structure, but will
be in future.

In particular we have deprecated the following fields in _samlsp.Options_:

- `Logger` - This was used to emit errors while validating, which is an
anti-pattern. - `IDPMetadataURL` - Instead use `FetchMetadata()` - `HTTPClient`
- Instead pass httpClient to FetchMetadata - `CookieMaxAge` - Instead assign a
custom CookieRequestTracker or CookieSessionProvider - `CookieName` - Instead
assign a custom CookieRequestTracker or CookieSessionProvider - `CookieDomain`
- Instead assign a custom CookieRequestTracker or CookieSessionProvider
- `CookieDomain` - Instead assign a custom CookieRequestTracker or
CookieSessionProvider

# Getting Started as a Service Provider

Let us assume we have a simple web application to protect. We'll modify this
application so it uses SAML to authenticate users.

```golang package main

import (

    "fmt"
    "net/http"

)

    func hello(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, World!")
    }

    func main() {
        app := http.HandlerFunc(hello)
        http.Handle("/hello", app)
        http.ListenAndServe(":8000", nil)
    }

```

Each service provider must have an self-signed X.509 key pair established.
You can generate your own with something like this:

    openssl req -x509 -newkey rsa:2048 -keyout myservice.key -out myservice.cert -days 365 -nodes -subj "/CN=myservice.example.com"

We will use `samlsp.Middleware` to wrap the endpoint we want to protect.
Middleware provides both an `http.Handler` to serve the SAML specific URLs and
a set of wrappers to require the user to be logged in. We also provide the URL
where the service provider can fetch the metadata from the IDP at startup.
In our case, we'll use [samltest.id](https://samltest.id/), an identity provider
designed for testing.

```golang package main

import (

    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "net/http"
    "net/url"

    "github.com/crewjam/saml/samlsp"

)

    func hello(w http.ResponseWriter, r *http.Request) {
    	fmt.Fprintf(w, "Hello, %s!", samlsp.Token(r.Context()).Attributes.Get("cn"))
    }

    func main() {
    	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
    	if err != nil {
    		panic(err) // TODO handle error
    	}
    	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
    	if err != nil {
    		panic(err) // TODO handle error
    	}

    	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
    	if err != nil {
    		panic(err) // TODO handle error
    	}

    	rootURL, err := url.Parse("http://localhost:8000")
    	if err != nil {
    		panic(err) // TODO handle error
    	}

    	samlSP, _ := samlsp.New(samlsp.Options{
    		URL:            *rootURL,
    		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
    		Certificate:    keyPair.Leaf,
    		IDPMetadataURL: idpMetadataURL,
    	})
    	app := http.HandlerFunc(hello)
    	http.Handle("/hello", samlSP.RequireAccount(app))
    	http.Handle("/saml/", samlSP)
    	http.ListenAndServe(":8000", nil)
    }

```

Next we'll have to register our service provider with the identity
provider to establish trust from the service provider to the IDP. For
[samltest.id](https://samltest.id/), you can do something like:

    mdpath=saml-test-$USER-$HOST.xml
    curl localhost:8000/saml/metadata > $mdpath

Navigate to https://samltest.id/upload.php and upload the file you fetched.

Now you should be able to authenticate. The flow should look like this:

1. You browse to `localhost:8000/hello`

1. The middleware redirects you to
`https://samltest.id/idp/profile/SAML2/Redirect/SSO`

1. samltest.id prompts you for a username and password.

1. samltest.id returns you an HTML document which contains an HTML form setup
to POST to `localhost:8000/saml/acs`. The form is automatically submitted if you
have javascript enabled.

1. The local service validates the response, issues a session cookie, and
redirects you to the original URL, `localhost:8000/hello`.

1. This time when `localhost:8000/hello` is requested there is a valid session
and so the main content is served.

# Getting Started as an Identity Provider

Please see `example/idp/` for a substantially complete example of how to use the
library and helpers to be an identity provider.

# Support

The SAML standard is huge and complex with many dark corners and strange,
unused features. This package implements the most commonly used subset of these
features required to provide a single sign on experience. The package supports
at least the subset of SAML known as [interoperable SAML](http://saml2int.org).

This package supports the Web SSO profile. Message flows from the service
provider to the IDP are supported using the HTTP Redirect binding and the HTTP
POST binding. Message flows from the IDP to the service provider are supported
via the HTTP POST binding.

The package can produce signed SAML assertions, and can validate both signed and
encrypted SAML assertions.

# RelayState

The _RelayState_ parameter allows you to pass user state information across
the authentication flow. The most common use for this is to allow a user to
request a deep link into your site, be redirected through the SAML login flow,
and upon successful completion, be directed to the originally requested link,
rather than the root.

Unfortunately, _RelayState_ is less useful than it could be. Firstly, it is
not authenticated, so anything you supply must be signed to avoid XSS or CSRF.
Secondly, it is limited to 80 bytes in length, which precludes signing. (See
section 3.6.3.1 of SAMLProfiles.)

# References

The SAML specification is a collection of PDFs (sadly):

- [SAMLCore](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
defines data types.

-
[SAMLBindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
defines the details of the HTTP requests in play.

-
[SAMLProfiles](http://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
describes data flows.

-
[SAMLConformance](http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)
includes a support matrix for various parts of the protocol.

[SAMLtest](https://samltest.id/) is a testing ground for SAML service and
identity providers.

# Security Issues

Please do not report security issues in the issue tracker.
Rather, please contact me directly at ross@kndr.org ([PGP Key
`78B6038B3B9DFB88`](https://keybase.io/crewjam)).

CONSTANTS

const (

	// StatusRequester means the request could not be performed due to an error on the part of the requester.
	StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"

	// StatusResponder means the request could not be performed due to an error on the part of the SAML responder or SAML authority.
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"

	// StatusVersionMismatch means the SAML responder could not process the request because the version of the request message was incorrect.
	StatusVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

	// StatusAuthnFailed means the responding provider was unable to successfully authenticate the principal.
	StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"

	// StatusInvalidAttrNameOrValue means Unexpected or invalid content was encountered within a <saml:Attribute> or <saml:AttributeValue> element.
	StatusInvalidAttrNameOrValue = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"

	// StatusInvalidNameIDPolicy means the responding provider cannot or will not support the requested name identifier policy.
	StatusInvalidNameIDPolicy = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"

	// StatusNoAuthnContext means the specified authentication context requirements cannot be met by the responder.
	StatusNoAuthnContext = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"

	// StatusNoAvailableIDP is used by an intermediary to indicate that none of the supported identity provider <Loc> elements in an <IDPList> can be resolved or that none of the supported identity providers are available.
	StatusNoAvailableIDP = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"

	// StatusNoPassive means Indicates the responding provider cannot authenticate the principal passively, as has been requested.
	StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive" //nolint:gosec

	// StatusNoSupportedIDP is used by an intermediary to indicate that none of the identity providers in an <IDPList> are supported by the intermediary.
	StatusNoSupportedIDP = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"

	// StatusPartialLogout is used by a session authority to indicate to a session participant that it was not able to propagate logout to all other session participants.
	StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"

	// StatusProxyCountExceeded means Indicates that a responding provider cannot authenticate the principal directly and is not permitted to proxy the request further.
	StatusProxyCountExceeded = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"

	// StatusRequestDenied means the SAML responder or SAML authority is able to process the request but has chosen not to respond. This status code MAY be used when there is concern about the security context of the request message or the sequence of request messages received from a particular requester.
	StatusRequestDenied = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"

	// StatusRequestUnsupported means the SAML responder or SAML authority does not support the request.
	StatusRequestUnsupported = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"

	// StatusRequestVersionDeprecated means the SAML responder cannot process any requests with the protocol version specified in the request.
	StatusRequestVersionDeprecated = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated" //nolint:gosec

	// StatusRequestVersionTooHigh means the SAML responder cannot process the request because the protocol version specified in the request message is a major upgrade from the highest protocol version supported by the responder.
	StatusRequestVersionTooHigh = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"

	// StatusRequestVersionTooLow means the SAML responder cannot process the request because the protocol version specified in the request message is too low.
	StatusRequestVersionTooLow = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"

	// StatusResourceNotRecognized means the resource value provided in the request message is invalid or unrecognized.
	StatusResourceNotRecognized = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"

	// StatusTooManyResponses means the response message would contain more elements than the SAML responder is able to return.
	StatusTooManyResponses = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"

	// StatusUnknownAttrProfile means an entity that has no knowledge of a particular attribute profile has been presented with an attribute means drawn from that profile.
	StatusUnknownAttrProfile = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"

	// StatusUnknownPrincipal means the responding provider does not recognize the principal specified or implied by the request.
	StatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"

	// StatusUnsupportedBinding means the SAML responder cannot properly fulfill the request using the protocol binding specified in the request.
	StatusUnsupportedBinding = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
)
const DefaultCacheDuration = time.Hour * 24 * 1
    DefaultCacheDuration is how long we ask the IDP to cache the SP metadata.

const DefaultValidDuration = time.Hour * 24 * 2
    DefaultValidDuration is how long we assert that the SP metadata is valid.

const HTTPArtifactBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
    HTTPArtifactBinding is the official URN for the HTTP-Artifact binding
    (transport)

const HTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTPPostBinding is the official URN for the HTTP-POST binding (transport)

const HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    HTTPRedirectBinding is the official URN for the HTTP-Redirect binding
    (transport)

const SOAPBinding = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
    SOAPBinding is the official URN for the SOAP binding (transport)

const SOAPBindingV1 = "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding"
    SOAPBindingV1 is the URN for the SOAP binding in SAML 1.0


VARIABLES

var Clock *dsig.Clock
    Clock is assigned to dsig validation and signing contexts if it is not nil,
    otherwise the default clock is used.

var MaxClockSkew = time.Second * 180
    MaxClockSkew allows for leeway for clock skew between the IDP and SP when
    validating assertions. It defaults to 180 seconds (matches shibboleth).

var MaxIssueDelay = time.Second * 90
    MaxIssueDelay is the longest allowed time between when a SAML assertion is
    issued by the IDP and the time it is received by ParseResponse. This is used
    to prevent old responses from being replayed (while allowing for some clock
    drift between the SP and IDP).

var Metadata = struct{}{}
    Metadata as been renamed to EntityDescriptor

    This change was made to be consistent with the rest of the API which uses
    names from the SAML specification for types.

    This is a tombstone to help you discover this fact. You should update
    references to saml.Metadata to be saml.EntityDescriptor.

var RandReader = rand.Reader
    RandReader is the io.Reader that produces cryptographically random bytes
    when they are need by the library. The default value is rand.Reader,
    but it can be replaced for testing.

var StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
    StatusSuccess means the request succeeded. Additional information MAY be
    returned in the <StatusMessage> and/or <StatusDetail> elements.

    TODO(ross): this value is mostly constant, but is mutated in tests. Fix the
    hacky test so this can be const.

var TimeNow = func() time.Time { return time.Now().UTC() }
    TimeNow is a function that returns the current time. The default value is
    time.Now, but it can be replaced for testing.


FUNCTIONS

func GetSigningContext(sp *ServiceProvider) (*dsig.SigningContext, error)
    GetSigningContext returns a dsig.SigningContext initialized based on the
    Service Provider's configuration


TYPES

type AffiliationDescriptor struct {
	AffiliationOwnerID string        `xml:"affiliationOwnerID,attr"`
	ID                 string        `xml:",attr"`
	ValidUntil         time.Time     `xml:"validUntil,attr,omitempty"`
	CacheDuration      time.Duration `xml:"cacheDuration,attr"`
	Signature          *etree.Element
	AffiliateMembers   []string        `xml:"AffiliateMember"`
	KeyDescriptors     []KeyDescriptor `xml:"KeyDescriptor"`
}
    AffiliationDescriptor represents the SAML AffiliationDescriptor object.

    See http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
    §2.5

type ArtifactResolve struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Artifact     string `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
}
    ArtifactResolve represents the SAML object of the same name.

func (r *ArtifactResolve) Element() *etree.Element
    Element returns an etree.Element representing the object in XML form.

func (r *ArtifactResolve) MarshalXML(e *xml.Encoder, _ xml.StartElement) error
    MarshalXML implements xml.Marshaler

func (r *ArtifactResolve) SoapRequest() *etree.Element
    SoapRequest returns a SOAP Envelope contining the ArtifactResolve request

func (r *ArtifactResolve) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
    UnmarshalXML implements xml.Unmarshaler

type ArtifactResponse struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	ID           string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Status       Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	Response     Response `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
}
    ArtifactResponse represents the SAML object of the same name.

func (r *ArtifactResponse) Element() *etree.Element
    Element returns an etree.Element representing the object in XML form.

func (r *ArtifactResponse) MarshalXML(e *xml.Encoder, _ xml.StartElement) error
    MarshalXML implements xml.Marshaler

func (r *ArtifactResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
    UnmarshalXML implements xml.Unmarshaler

type Assertion struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID           string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Version      string    `xml:",attr"`
	Issuer       Issuer    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *etree.Element
	Subject      *Subject
	Conditions   *Conditions
	// Advice *Advice
	// Statements []Statement
	AuthnStatements []AuthnStatement `xml:"AuthnStatement"`
	// AuthzDecisionStatements []AuthzDecisionStatement
	AttributeStatements []AttributeStatement `xml:"AttributeStatement"`
}
    Assertion represents the SAML element Assertion.

    See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    §2.3.3

func (a *Assertion) Element() *etree.Element
    Element returns an etree.Element representing the object in XML form.

func (a *Assertion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error
    UnmarshalXML implements xml.Unmarshaler

type AssertionAttribute struct {
	FriendlyName string
	Name         string
	Value        string
}
    AssertionAttribute represents an attribute of the user extracted from a SAML
    Assertion.

type AssertionAttributes []AssertionAttribute
    AssertionAttributes is a list of AssertionAttribute

func (aa AssertionAttributes) Get(name string) *AssertionAttribute
    Get returns the assertion attribute whose Name or FriendlyName matches name,
    or nil if no matching attribute is found.

type AssertionMaker interface {
	// MakeAssertion constructs an assertion from session and the request and
	// assigns it to req.Assertion.
	MakeAssertion(req *IdpAuthnRequest, session *Session) error
}
    AssertionMaker is an interface used by IdentityProvider to
    construct the assertion for a request. The default implementation is
    DefaultAssertionMaker, which is used if not AssertionMaker is specified.

type Attribute struct {
	FriendlyName string           `xml:",attr"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr"`
	Values       []AttributeValue `xml:"AttributeValue"`
}
    Attribute represents the SAML element Attribute.
