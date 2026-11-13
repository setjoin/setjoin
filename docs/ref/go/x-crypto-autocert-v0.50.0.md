package autocert // import "golang.org/x/crypto/acme/autocert"

Package autocert provides automatic access to certificates from Let's Encrypt
and any other ACME-based CA.

This package is a work in progress and makes no API stability promises.

CONSTANTS

const DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
    DefaultACMEDirectory is the default ACME Directory URL used when the
    Manager's Client is nil.


VARIABLES

var ErrCacheMiss = errors.New("acme/autocert: certificate cache miss")
    ErrCacheMiss is returned when a certificate is not found in cache.


FUNCTIONS

func AcceptTOS(tosURL string) bool
    AcceptTOS is a Manager.Prompt function that always returns true to indicate
    acceptance of the CA's Terms of Service during account registration.

func NewListener(domains ...string) net.Listener
    NewListener returns a net.Listener that listens on the standard TLS port
    (443) on all interfaces and returns *tls.Conn connections with LetsEncrypt
    certificates for the provided domain or domains.

    It enables one-line HTTPS servers:

        log.Fatal(http.Serve(autocert.NewListener("example.com"), handler))

    NewListener is a convenience function for a common configuration. More
    complex or custom configurations can use the autocert.Manager type instead.

    Use of this function implies acceptance of the LetsEncrypt Terms of Service.
    If domains is not empty, the provided domains are passed to HostWhitelist.
    If domains is empty, the listener will do LetsEncrypt challenges for any
    requested domain, which is not recommended.

    Certificates are cached in a "golang-autocert" directory under an operating
    system-specific cache or temp directory. This may not be suitable for
    servers spanning multiple machines.

    The returned listener uses a *tls.Config that enables HTTP/2, and should
    only be used with servers that support HTTP/2.

    The returned Listener also enables TCP keep-alives on the accepted
    connections. The returned *tls.Conn are returned before their TLS handshake
    has completed.


TYPES

type Cache interface {
	// Get returns a certificate data for the specified key.
	// If there's no such key, Get returns ErrCacheMiss.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put stores the data in the cache under the specified key.
	// Underlying implementations may use any data storage format,
	// as long as the reverse operation, Get, results in the original data.
	Put(ctx context.Context, key string, data []byte) error

	// Delete removes a certificate data from the cache under the specified key.
	// If there's no such key in the cache, Delete returns nil.
	Delete(ctx context.Context, key string) error
}
    Cache is used by Manager to store and retrieve previously obtained
    certificates and other account data as opaque blobs.

    Cache implementations should not rely on the key naming pattern. Keys can
    include any printable ASCII characters, except the following: \/:*?"<>|

type DirCache string
    DirCache implements Cache using a directory on the local filesystem.
    If the directory does not exist, it will be created with 0700 permissions.

func (d DirCache) Delete(ctx context.Context, name string) error
    Delete removes the specified file name.

func (d DirCache) Get(ctx context.Context, name string) ([]byte, error)
    Get reads a certificate data from the specified file name.

func (d DirCache) Put(ctx context.Context, name string, data []byte) error
    Put writes the certificate data to the specified file name. The file will be
    created with 0600 permissions.

type HostPolicy func(ctx context.Context, host string) error
    HostPolicy specifies which host names the Manager is allowed to respond to.
    It returns a non-nil error if the host should be rejected. The returned
    error is accessible via tls.Conn.Handshake and its callers. See Manager's
    HostPolicy field and GetCertificate method docs for more details.

func HostWhitelist(hosts ...string) HostPolicy
    HostWhitelist returns a policy where only the specified host names are
    allowed. Only exact matches are currently supported. Subdomains, regexp or
    wildcard will not match.

    Note that all hosts will be converted to Punycode via idna.Lookup.ToASCII so
    that Manager.GetCertificate can handle the Unicode IDN and mixedcase hosts
    correctly. Invalid hosts will be silently ignored.

type Manager struct {
	// Prompt specifies a callback function to conditionally accept a CA's Terms of Service (TOS).
	// The registration may require the caller to agree to the CA's TOS.
	// If so, Manager calls Prompt with a TOS URL provided by the CA. Prompt should report
	// whether the caller agrees to the terms.
	//
	// To always accept the terms, the callers can use AcceptTOS.
	Prompt func(tosURL string) bool

	// Cache optionally stores and retrieves previously-obtained certificates
	// and other state. If nil, certs will only be cached for the lifetime of
	// the Manager. Multiple Managers can share the same Cache.
	//
	// Using a persistent Cache, such as DirCache, is strongly recommended.
	Cache Cache

	// HostPolicy controls which domains the Manager will attempt
	// to retrieve new certificates for. It does not affect cached certs.
	//
	// If non-nil, HostPolicy is called before requesting a new cert.
	// If nil, all hosts are currently allowed. This is not recommended,
	// as it opens a potential attack where clients connect to a server
	// by IP address and pretend to be asking for an incorrect host name.
	// Manager will attempt to obtain a certificate for that host, incorrectly,
	// eventually reaching the CA's rate limit for certificate requests
	// and making it impossible to obtain actual certificates.
	//
	// See GetCertificate for more details.
	HostPolicy HostPolicy

	// RenewBefore optionally specifies how early certificates should
	// be renewed before they expire.
	//
	// If zero, they're renewed at the lesser of 30 days or
	// 1/3 of the certificate lifetime.
	RenewBefore time.Duration

	// Client is used to perform low-level operations, such as account registration
	// and requesting new certificates.
	//
	// If Client is nil, a zero-value acme.Client is used with DefaultACMEDirectory
	// as the directory endpoint.
	// If the Client.Key is nil, a new ECDSA P-256 key is generated and,
	// if Cache is not nil, stored in cache.
	//
	// Mutating the field after the first call of GetCertificate method will have no effect.
	Client *acme.Client

	// Email optionally specifies a contact email address.
	// This is used by CAs, such as Let's Encrypt, to notify about problems
	// with issued certificates.
	//
	// If the Client's account key is already registered, Email is not used.
	Email string

	// ForceRSA used to make the Manager generate RSA certificates. It is now ignored.
	//
	// Deprecated: the Manager will request the correct type of certificate based
	// on what each client supports.
	ForceRSA bool

	// ExtraExtensions are used when generating a new CSR (Certificate Request),
	// thus allowing customization of the resulting certificate.
	// For instance, TLS Feature Extension (RFC 7633) can be used
	// to prevent an OCSP downgrade attack.
	//
	// The field value is passed to crypto/x509.CreateCertificateRequest
	// in the template's ExtraExtensions field as is.
	ExtraExtensions []pkix.Extension

	// ExternalAccountBinding optionally represents an arbitrary binding to an
	// account of the CA to which the ACME server is tied.
	// See RFC 8555, Section 7.3.4 for more details.
	ExternalAccountBinding *acme.ExternalAccountBinding

	// Has unexported fields.
}
    Manager is a stateful certificate manager built on top of acme.Client.
    It obtains and refreshes certificates automatically using "tls-alpn-01" or
    "http-01" challenge types, as well as providing them to a TLS server via
    tls.Config.

    You must specify a cache implementation, such as DirCache, to reuse obtained
    certificates across program restarts. Otherwise your server is very likely
    to exceed the certificate issuer's request rate limits.

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
    GetCertificate implements the tls.Config.GetCertificate hook. It provides a
    TLS certificate for hello.ServerName host, including answering tls-alpn-01
    challenges. All other fields of hello are ignored.

    If m.HostPolicy is non-nil, GetCertificate calls the policy before
    requesting a new cert. A non-nil error returned from m.HostPolicy halts TLS
    negotiation. The error is propagated back to the caller of GetCertificate
    and is user-visible. This does not affect cached certs. See HostPolicy field
    description for more details.

    If GetCertificate is used directly, instead of via Manager.TLSConfig,
    package users will also have to add acme.ALPNProto to NextProtos for
    tls-alpn-01, or use HTTPHandler for http-01.

func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler
    HTTPHandler configures the Manager to provision ACME "http-01" challenge
    responses. It returns an http.Handler that responds to the challenges and
    must be running on port 80. If it receives a request that is not an ACME
    challenge, it delegates the request to the optional fallback handler.

    If fallback is nil, the returned handler redirects all GET and HEAD
    requests to the default TLS port 443 with 302 Found status code, preserving
    the original request path and query. It responds with 400 Bad Request to
    all other HTTP methods. The fallback is not protected by the optional
    HostPolicy.

    Because the fallback handler is run with unencrypted port 80 requests,
    the fallback should not serve TLS-only requests.

    If HTTPHandler is never called, the Manager will only use the "tls-alpn-01"
    challenge for domain verification.

func (m *Manager) Listener() net.Listener
    Listener listens on the standard TLS port (443) on all interfaces and
    returns a net.Listener returning *tls.Conn connections.

    The returned listener uses a *tls.Config that enables HTTP/2, and should
    only be used with servers that support HTTP/2.

    The returned Listener also enables TCP keep-alives on the accepted
    connections. The returned *tls.Conn are returned before their TLS handshake
    has completed.

    Unlike NewListener, it is the caller's responsibility to initialize the
    Manager m's Prompt, Cache, HostPolicy, and other desired options.

func (m *Manager) TLSConfig() *tls.Config
    TLSConfig creates a new TLS config suitable for net/http.Server servers,
    supporting HTTP/2 and the tls-alpn-01 ACME challenge type.

