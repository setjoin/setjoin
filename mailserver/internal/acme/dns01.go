// Package acme manages TLS certificates via ACME (lego) with the challenge
// type chosen by the deployment: dns-01, http-01 or tls-alpn-01.
//
// Lifecycle invariant (ACME-001/ACME-002 remediation): certificate issuance
// happens ONLY in the managed background loop started by LegoManager.Start —
// for EVERY configured challenge type. GetCertificate is serving-only — it
// never issues, never registers an ACME account, and returns (nil, nil) for
// anything it cannot serve from cache so the tls.Config fallback chain
// (autocert cache / static cert) handles the handshake. No handshake path may
// issue certificates; a challenge the managed loop cannot cover must fail
// loudly at startup, never silently lose issuance.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// Managed challenge types (LegoConfig.Challenge). An empty config value
// resolves to ChallengeDNS01 (the historical default).
const (
	ChallengeDNS01     = "dns-01"
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"
)

const (
	// renewBefore is how long before NotAfter the managed loop renews a cert.
	renewBefore = 30 * 24 * time.Hour
	// checkInterval is the managed renewal loop cadence. With a 30-day
	// renew-before window this leaves ~60 chances to renew before expiry.
	checkInterval = 12 * time.Hour
	// maxRenewAttempts bounds obtain retries per renewal round; the next
	// tick starts a fresh round.
	maxRenewAttempts = 3
	// accountKeyFileName is the default account-key file under CacheDir when
	// LegoConfig.KeyFile is unset.
	accountKeyFileName = "account.key"
)

// LegoConfig holds parameters for the Lego-based ACME client.
type LegoConfig struct {
	Domains  []string // domains to obtain certs for
	Email    string   // ACME account email
	CacheDir string   // cert cache directory
	// Challenge selects the managed challenge type: "dns-01" (default),
	// "http-01" or "tls-alpn-01". The managed loop covers whichever is
	// configured; unsupported values fail construction (fail loud).
	Challenge   string         // challenge type ("" → dns-01)
	ProviderCfg ProviderConfig // DNS provider config (dns-01 only)
	// KeyFile optionally points at the persisted ACME ACCOUNT key (ECDSA
	// P-256 PEM). A stable account key keeps account registration stable
	// across restarts. When unset, the key is generated once and persisted
	// to <CacheDir>/account.key.
	KeyFile    string
	CADirURL   string       // ACME directory URL (defaults to LE production)
	HTTPClient *http.Client // optional: ACME transport override (used by offline tests)
}

// LegoManager obtains and renews certificates via ACME with the configured
// managed challenge (dns-01, http-01 or tls-alpn-01).
//
// Serving: GetCertificate is a drop-in for tls.Config.GetCertificate and is
// serving-only (cache + NotAfter validity + SNI allowlist).
// Issuance: Start runs the managed renewal loop — the only code path that
// calls obtain.
type LegoManager struct {
	config    LegoConfig
	cache     *DirCache
	provider  registration.User
	logger    *slog.Logger
	client    *lego.Client
	challenge string

	// In-process challenge responders (nil unless that challenge is the
	// configured one). lego's solver calls Present/CleanUp on them during
	// validation; the app's own :80 / :443 servers expose the responses, so
	// no extra listener ever competes for the ACME ports.
	http01 *http01TokenStore
	alpn01 *alpnCertStore

	// mu serializes registration + obtain. GetCertificate deliberately does
	// NOT take mu: a multi-minute DNS-01 renewal must never block serving.
	mu      sync.Mutex
	regDone bool

	// accountKeyPath is where the ACME account key is persisted.
	accountKeyPath string

	// allow is the normalized set of serve/issue domains (SNI allowlist).
	allow map[string]struct{}

	// flight guards the managed renewal round: at most one issuance round at
	// a time; post-gate staleness recheck makes concurrent triggers no-ops.
	flightMu sync.Mutex
	issuing  bool
	started  bool

	// Tunables (defaults in NewLegoManager; overridable in tests).
	now           func() time.Time
	renewBefore   time.Duration
	checkInterval time.Duration
	maxAttempts   int
	backoffFn     func(attempt int) time.Duration

	// registerFn/issueFn default to the lego client and are seams for offline
	// tests (counted fake issuer / fake registration). issueFn receives the
	// ctx governing the round and the fully-built ObtainRequest (including
	// the reused certificate key) so fakes can honor both.
	registerFn func(ctx context.Context) error
	issueFn    func(ctx context.Context, req certificate.ObtainRequest) (*certificate.Resource, error)
}

// NewLegoManager creates a Lego-based ACME client for the configured managed
// challenge. Unsupported challenge values and wildcard domains under
// http-01/tls-alpn-01 fail construction — the managed loop is the only
// issuance path, so a challenge it cannot run must stop startup, not silence.
func NewLegoManager(cfg LegoConfig) (*LegoManager, error) {
	if len(cfg.Domains) == 0 {
		return nil, fmt.Errorf("acme/dns01: at least one domain is required")
	}
	if cfg.CacheDir == "" {
		return nil, fmt.Errorf("acme/dns01: cache dir is required")
	}
	if cfg.Email == "" {
		return nil, fmt.Errorf("acme/dns01: email is required")
	}
	challenge := cfg.Challenge
	if challenge == "" {
		challenge = ChallengeDNS01
	}

	cache := &DirCache{Dir: cfg.CacheDir}

	// Load or generate-and-persist the ACME account key so account
	// registration is stable across restarts (ACME account reuse).
	accountKeyPath := cfg.KeyFile
	if accountKeyPath == "" {
		accountKeyPath = filepath.Join(cfg.CacheDir, accountKeyFileName)
	}
	accountKey, err := loadOrCreateAccountKey(accountKeyPath)
	if err != nil {
		return nil, err
	}

	user := &acmeUser{email: cfg.Email, key: accountKey}

	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.CADirURL
	if legoCfg.CADirURL == "" {
		legoCfg.CADirURL = lego.LEDirectoryProduction
	}
	if cfg.HTTPClient != nil {
		legoCfg.HTTPClient = cfg.HTTPClient
	}
	legoCfg.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("acme/dns01: create lego client: %w", err)
	}

	// Wire the challenge provider for the CONFIGURED challenge through the
	// managed loop. http-01/tls-alpn-01 use in-process responders mounted on
	// the app's own servers; dns-01 uses the configured DNS provider. Any
	// other value fails construction: the managed loop is the only issuance
	// path, so an uncoverable challenge must stop startup, not silence.
	switch challenge {
	case ChallengeDNS01:
		dnsProvider, err := NewDNSProvider(cfg.ProviderCfg)
		if err != nil {
			return nil, fmt.Errorf("acme/dns01: %w", err)
		}
		if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
			return nil, fmt.Errorf("acme/dns01: set DNS provider: %w", err)
		}
	case ChallengeHTTP01, ChallengeTLSALPN01:
		for _, d := range cfg.Domains {
			if strings.HasPrefix(normalizeSNI(d), "*.") {
				return nil, fmt.Errorf("acme/dns01: wildcard domain %q requires the %s challenge (configured: %s)", d, ChallengeDNS01, challenge)
			}
		}
	default:
		return nil, fmt.Errorf("acme/dns01: unsupported challenge %q (supported: %s, %s, %s)", cfg.Challenge, ChallengeDNS01, ChallengeHTTP01, ChallengeTLSALPN01)
	}

	allow := make(map[string]struct{}, len(cfg.Domains))
	for _, d := range cfg.Domains {
		allow[normalizeSNI(d)] = struct{}{}
	}

	m := &LegoManager{
		config:         cfg,
		cache:          cache,
		provider:       user,
		client:         client,
		challenge:      challenge,
		logger:         slog.Default().With("component", "acme_managed", "challenge", challenge),
		accountKeyPath: accountKeyPath,
		allow:          allow,
		now:            time.Now,
		renewBefore:    renewBefore,
		checkInterval:  checkInterval,
		maxAttempts:    maxRenewAttempts,
		backoffFn:      defaultBackoff,
	}
	switch challenge {
	case ChallengeHTTP01:
		m.http01 = &http01TokenStore{tokens: map[string]string{}}
		if err := client.Challenge.SetHTTP01Provider(m.http01); err != nil {
			return nil, fmt.Errorf("acme/dns01: set HTTP-01 provider: %w", err)
		}
	case ChallengeTLSALPN01:
		m.alpn01 = &alpnCertStore{certs: map[string]*tls.Certificate{}}
		if err := client.Challenge.SetTLSALPN01Provider(m.alpn01); err != nil {
			return nil, fmt.Errorf("acme/dns01: set TLS-ALPN-01 provider: %w", err)
		}
	}

	return m, nil
}

// Challenge returns the resolved managed challenge type.
func (m *LegoManager) Challenge() string { return m.challenge }

// HTTP01Handler wraps the app's :80 handler so ACME servers can fetch
// HTTP-01 challenge responses at /.well-known/acme-challenge/{token} while
// every other request flows to next. Mounting it is required when the
// configured challenge is http-01; without it the managed loop cannot
// complete validation. Non-http-01 managers return next unchanged.
func (m *LegoManager) HTTP01Handler(next http.Handler) http.Handler {
	if m.http01 == nil {
		return next
	}
	return m.http01.handler(next)
}

// TLSALPNConfigFor returns a one-shot tls.Config serving the pending
// TLS-ALPN-01 challenge certificate when hello offers the acme-tls/1 ALPN
// protocol and a challenge is pending for its SNI; nil otherwise (the caller
// must fall through to its base config). Wire it from tls.Config's
// GetConfigForClient so the challenge is answered on the EXISTING :443
// listener instead of a competing one.
func (m *LegoManager) TLSALPNConfigFor(hello *tls.ClientHelloInfo) *tls.Config {
	if m.alpn01 == nil {
		return nil
	}
	return m.alpn01.configFor(hello)
}

// loadOrCreateAccountKey loads the ECDSA P-256 account key from path, or
// generates one and persists it atomically so restarts reuse the same ACME
// account (no re-registration, stable account URL).
func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path from admin config (KeyFile) or cache dir, not request input
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("acme/dns01: account key %s is not PEM", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("acme/dns01: parse account key %s: %w", path, err)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("acme/dns01: read account key %s: %w", path, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("acme/dns01: generate account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("acme/dns01: marshal account key: %w", err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, blob, 0600); err != nil {
		return nil, fmt.Errorf("acme/dns01: persist account key %s: %w", path, err)
	}
	return key, nil
}

// normalizeSNI lowercases and trims surrounding whitespace plus one trailing
// dot (DNS names are case-insensitive; RFC 6066 §3 SNI hostnames may carry a
// fully-qualified trailing dot).
func normalizeSNI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.TrimSuffix(name, ".")
}

// certKey maps a normalized SNI to its cache key: the exact configured domain,
// or the wildcard entry covering it ("*.example.com" covers one label). The
// second return is false when the SNI is not in the allowlist.
func (m *LegoManager) certKey(domain string) (string, bool) {
	if _, ok := m.allow[domain]; ok {
		return domain, true
	}
	if i := strings.IndexByte(domain, '.'); i > 0 {
		wild := "*" + domain[i:]
		if _, ok := m.allow[wild]; ok {
			return wild, true
		}
	}
	return "", false
}

// register performs ACME account registration. With a persisted account key,
// re-running this against the directory returns the existing account rather
// than creating a new one. Caller must hold m.mu.
func (m *LegoManager) register(ctx context.Context) error {
	if m.registerFn != nil {
		return m.registerFn(ctx)
	}
	reg, err := m.client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("acme/dns01: register: %w", err)
	}
	m.provider.(*acmeUser).registration = reg
	m.logger.Info("ACME account registered", "domains", m.config.Domains)
	return nil
}

// GetCertificate returns a cached, currently-valid certificate for the given
// server name. It NEVER issues and NEVER registers (managed-loop-only, ACME-001):
// unknown/unconfigured SNI, empty SNI, cold cache, corrupt blob and expired
// certs all return (nil, nil) so the tls.Config fallback chain
// (autocert cache → static cert) handles the handshake.
func (m *LegoManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := normalizeSNI(hello.ServerName)
	if sni == "" {
		return nil, nil
	}
	key, ok := m.certKey(sni)
	if !ok {
		return nil, nil
	}

	blob, err := m.cache.Get(key)
	if err != nil {
		return nil, nil // cold cache: the managed loop owns issuance
	}
	cert, err := parseCertBlob(blob)
	if err != nil {
		m.logger.Warn("cached certificate unusable; managed loop will reissue", "domain", key, "error", err)
		return nil, nil
	}
	if !m.now().Before(cert.Leaf.NotAfter) {
		// Expired: never serve it. The managed loop renews 30 days early;
		// reaching here means renewal has been failing.
		m.logger.Warn("cached certificate expired; not serving", "domain", key, "not_after", cert.Leaf.NotAfter)
		return nil, nil
	}
	return cert, nil
}

// parseCertBlob parses the stored key+chain PEM blob into a tls.Certificate
// with Leaf populated.
func parseCertBlob(blob []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(blob, blob)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return nil, errors.New("empty certificate chain")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// Start launches the managed certificate lifecycle: a background loop that
// obtains (DNS-01) any configured certificate that is missing or within the
// renew-before window, then re-checks every checkInterval. It must be called
// explicitly at startup — never from a handshake. Calling Start more than
// once is a no-op.
func (m *LegoManager) Start(ctx context.Context) {
	m.flightMu.Lock()
	if m.started {
		m.flightMu.Unlock()
		return
	}
	m.started = true
	m.flightMu.Unlock()

	go m.run(ctx)
}

func (m *LegoManager) run(ctx context.Context) {
	m.renewIfNeeded(ctx) // initial pass: cold cache or near-expiry → obtain now
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.renewIfNeeded(ctx)
		}
	}
}

// renewIfNeeded runs one managed renewal round if any configured domain lacks
// a usable cached cert or is inside the renew-before window. Single-flight:
// concurrent triggers collapse into the in-flight round, and the post-gate
// staleness recheck makes triggers racing a completing round no-ops.
func (m *LegoManager) renewIfNeeded(ctx context.Context) {
	if !m.anyStale() {
		return
	}

	m.flightMu.Lock()
	if m.issuing {
		m.flightMu.Unlock()
		return
	}
	m.issuing = true
	m.flightMu.Unlock()
	defer func() {
		m.flightMu.Lock()
		m.issuing = false
		m.flightMu.Unlock()
	}()

	// Post-gate recheck: a round completing concurrently may have refreshed
	// the cache while we raced for the flight gate.
	domain, ok := m.firstStale()
	if !ok {
		return
	}

	// One obtain issues the multi-SAN cert for ALL configured domains and
	// caches it under each, so one round covers the whole set.
	if err := m.renewWithRetry(ctx, domain); err != nil {
		m.logger.Warn("managed certificate renewal failed; will retry next check",
			"domain", domain, "attempts", m.maxAttempts, "error", err)
	}
}

func (m *LegoManager) anyStale() bool {
	_, ok := m.firstStale()
	return ok
}

func (m *LegoManager) firstStale() (string, bool) {
	for _, d := range m.config.Domains {
		if m.needsRenewal(d) {
			return d, true
		}
	}
	return "", false
}

// needsRenewal reports whether domain's cached certificate is missing,
// unparsable, or expires within the renew-before window.
func (m *LegoManager) needsRenewal(domain string) bool {
	key, ok := m.certKey(normalizeSNI(domain))
	if !ok {
		return false
	}
	blob, err := m.cache.Get(key)
	if err != nil {
		return true // cold cache
	}
	cert, err := parseCertBlob(blob)
	if err != nil {
		return true // corrupt cache
	}
	return m.now().Add(m.renewBefore).After(cert.Leaf.NotAfter)
}

// renewWithRetry issues a certificate for the configured domains, retrying
// failed attempts with bounded backoff and jitter until success, the attempt
// cap, or ctx cancellation.
func (m *LegoManager) renewWithRetry(ctx context.Context, domain string) error {
	var lastErr error
	for attempt := 0; attempt < m.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := m.obtain(ctx, domain); err == nil {
			return nil
		} else {
			lastErr = err
			m.logger.Warn("certificate obtain attempt failed",
				"domain", domain, "attempt", attempt+1, "error", err)
		}
		wait := m.backoffFn(attempt)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

// defaultBackoff returns 30s doubling to a 1h cap, with up to 20% jitter so
// flapping ACME/DNS providers are not hit by synchronized retries.
func defaultBackoff(attempt int) time.Duration {
	const base = 30 * time.Second
	const max = time.Hour
	d := base
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	jitter, err := crand.Int(crand.Reader, big.NewInt(int64(d/5)+1))
	if err != nil {
		return d // jitter is best-effort
	}
	return d - time.Duration(jitter.Int64())
}

// obtainBounded runs an issuance call that cannot honor ctx by itself — lego
// v4's Certificate.Obtain takes no ctx parameter — bounded by the round ctx:
// the call runs in a goroutine and select picks between its completion and
// ctx.Done(). A cancelled round returns ctx.Err() immediately; the buffered
// result channel lets the abandoned call unwind safely (lego's Obtain always
// eventually returns) while its late resource is discarded — publication
// happens only in the completion branch, never for an abandoned round.
func obtainBounded(ctx context.Context, issue func() (*certificate.Resource, error)) (*certificate.Resource, error) {
	type outcome struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan outcome, 1) // buffered: the abandoned issuer never blocks
	go func() {
		res, err := issue()
		ch <- outcome{res: res, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case out := <-ch:
		return out.res, out.err
	}
}

// obtain performs a fresh certificate issuance for the configured domains via
// the configured managed challenge and atomically caches the result under
// every configured domain. ctx governs the round: it is checked before work,
// bounds the issuance call itself, and is re-checked immediately before
// publication (the publication fence). ONLY the managed renewal path calls
// this — never a handshake.
func (m *LegoManager) obtain(ctx context.Context, domain string) (*tls.Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure account is registered before obtaining a cert. register does not
	// re-acquire m.mu, so no unlock dance here.
	if !m.regDone {
		if err := m.register(ctx); err != nil {
			return nil, err
		}
		m.regDone = true
	}

	// Certificate-key stability: when a previous certificate for these
	// domains is cached, reissue with ITS private key (lego honors
	// ObtainRequest.PrivateKey) so the SPKI hash — and with it the DANE-EE
	// (3 1 1) TLSA record — stays valid across renewals. Cold cache → nil →
	// lego generates a fresh key for the first issuance.
	req := certificate.ObtainRequest{
		Domains:    m.config.Domains,
		Bundle:     true,
		PrivateKey: m.existingCertKey(),
	}

	var (
		res *certificate.Resource
		err error
	)
	if m.issueFn != nil {
		res, err = obtainBounded(ctx, func() (*certificate.Resource, error) {
			return m.issueFn(ctx, req)
		})
	} else {
		// lego v4's Obtain has no ctx parameter: bound it with the round ctx
		// so a cancelled round is abandoned instead of blocking on (and then
		// publishing) a completion that arrived after shutdown.
		res, err = obtainBounded(ctx, func() (*certificate.Resource, error) {
			return m.client.Certificate.Obtain(req)
		})
	}
	if err != nil {
		return nil, err // includes ctx cancellation surfaced by the seams
	}

	// Publication fence: cancellation that lands while issuance unwinds —
	// including a completion racing the ctx.Done() branch of the select —
	// must never publish the abandoned round's certificate. Publication
	// happens only for a round whose ctx is still live after issuance.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Cache key+chain concatenated so tls.X509KeyPair(blob, blob) succeeds on
	// restart. Same blob format as autocert (key PEM first, then chain PEM).
	// Put is atomic (temp+rename) per the renewal idempotency contract.
	blob := append(res.PrivateKey, res.Certificate...) //nolint:gocritic // fresh Resource-owned slices; concat is intentional
	// Publish under NORMALIZED keys (lowercase, no trailing dot) so serving
	// lookups, lifecycle checks and the monitor probe all hit the same file.
	// A failed Put is surfaced, not suppressed: a certificate that is not
	// durably cached must fail the round so it is retried, never silently
	// lost on restart.
	var putErrs []error
	for _, d := range m.config.Domains {
		key := normalizeSNI(d)
		if putErr := m.cache.Put(key, blob); putErr != nil {
			m.logger.Error("cert cache put failed", "domain", key, "error", putErr)
			putErrs = append(putErrs, fmt.Errorf("cache put %q: %w", key, putErr))
		}
	}
	if len(putErrs) > 0 {
		return nil, errors.Join(putErrs...)
	}

	tlsCert, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse obtained cert: %w", err)
	}

	m.logger.Info("certificate obtained via managed loop", "domain", domain, "domains", m.config.Domains)
	return &tlsCert, nil
}

// existingCertKey returns the private key of the currently cached certificate
// for the configured domains (the stored blob is key PEM + chain PEM), or nil
// when no cached key exists (first issuance) or it cannot be parsed.
func (m *LegoManager) existingCertKey() crypto.PrivateKey {
	for _, d := range m.config.Domains {
		blob, err := m.cache.Get(normalizeSNI(d))
		if err != nil {
			continue
		}
		cert, err := parseCertBlob(blob)
		if err != nil || cert.PrivateKey == nil {
			continue
		}
		return cert.PrivateKey
	}
	return nil
}

// acmeUser implements registration.User for Lego.
type acmeUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// http01PathPrefix is where ACME servers look for HTTP-01 responses
// (RFC 8555 §8.3).
const http01PathPrefix = "/.well-known/acme-challenge/"

// http01TokenStore is an in-process HTTP-01 challenge responder. lego's
// solver calls Present/CleanUp around validation; the app's own :80 server
// exposes the tokens through handler — no second listener competes for
// port 80.
type http01TokenStore struct {
	mu     sync.Mutex
	tokens map[string]string // token → keyAuth
}

func (s *http01TokenStore) Present(_, token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = keyAuth
	return nil
}

func (s *http01TokenStore) CleanUp(_, token, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

// handler answers /.well-known/acme-challenge/{token} from the pending
// tokens; every other request (and unknown tokens) flows to next so the app
// keeps serving on :80 during validation.
func (s *http01TokenStore) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, http01PathPrefix) {
			token := strings.TrimPrefix(r.URL.Path, http01PathPrefix)
			s.mu.Lock()
			keyAuth, ok := s.tokens[token]
			s.mu.Unlock()
			if ok {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(keyAuth))
				return
			}
		}
		if next != nil {
			next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// alpnCertStore is an in-process TLS-ALPN-01 challenge responder. Present
// builds the acmeValidation-v1 certificate (via lego's exported helper) and
// the app's :443 tls.Config exposes it through configFor — no competing
// listener on port 443.
type alpnCertStore struct {
	mu    sync.Mutex
	certs map[string]*tls.Certificate // normalized domain → challenge cert
}

func (s *alpnCertStore) Present(domain, _, keyAuth string) error {
	cert, err := tlsalpn01.ChallengeCert(domain, keyAuth)
	if err != nil {
		return fmt.Errorf("acme/dns01: build tls-alpn-01 challenge cert for %s: %w", domain, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certs[normalizeSNI(domain)] = cert
	return nil
}

func (s *alpnCertStore) CleanUp(domain, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.certs, normalizeSNI(domain))
	return nil
}

// configFor returns a minimal tls.Config answering the ACME-TLS/1 handshake
// (RFC 8737 §6.2) for hello, or nil when hello is not an ALPN validation for
// a domain with a pending challenge — callers fall through to the base
// config. Returned for one handshake at a time; lego serializes validation.
func (s *alpnCertStore) configFor(hello *tls.ClientHelloInfo) *tls.Config {
	if !offersALPN(hello, tlsalpn01.ACMETLS1Protocol) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cert, ok := s.certs[normalizeSNI(hello.ServerName)]
	if !ok {
		return nil
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{tlsalpn01.ACMETLS1Protocol},
	}
}

func offersALPN(hello *tls.ClientHelloInfo, proto string) bool {
	for _, p := range hello.SupportedProtos {
		if p == proto {
			return true
		}
	}
	return false
}
