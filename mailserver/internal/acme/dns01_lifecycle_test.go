package acme

// Lifecycle tests for the managed ACME contract (ACME-001/ACME-002):
//
//	GetCertificate is serving-only (never issues, never registers);
//	issuance happens exclusively in the managed loop started by Start;
//	renewal triggers 30 days before NotAfter with single-flight dedup;
//	cache replacement is atomic; the ACME account key persists across
//	restarts so accounts are not re-registered.
//
// All tests run offline via the registerFn/issueFn seams and an injectable
// now-func; no real ACME/DNS traffic.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/go-acme/lego/v4/certificate"
)

const testDomain = "mail.example.com"

// ─── test infrastructure ─────────────────────────────────────────────────────

// fakeClock is an injectable now-func used instead of time.Now.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// issueController is a counted fake issuer: it replaces the lego Obtain call.
// It receives the ctx governing the round and the built ObtainRequest so
// tests can assert ctx threading and certificate-key reuse.
type issueController struct {
	mu      sync.Mutex
	calls   int
	res     *certificate.Resource
	block   chan struct{} // nil = return immediately; else first call waits
	entered chan struct{} // closed on first issue call
	once    sync.Once
}

func newIssueController(res *certificate.Resource) *issueController {
	return &issueController{res: res, entered: make(chan struct{})}
}

func (c *issueController) issue(ctx context.Context, _ certificate.ObtainRequest) (*certificate.Resource, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	c.once.Do(func() { close(c.entered) })
	if c.block != nil {
		<-c.block
	}
	_ = ctx
	return c.res, nil
}

func (c *issueController) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// regCounter counts DISTINCT account keys presented for ACME registration —
// a stable persisted key re-registers as the same account (creations stays 1).
type regCounter struct {
	mu        sync.Mutex
	creations int
	keys      map[string]struct{}
}

func newRegCounter() *regCounter { return &regCounter{keys: map[string]struct{}{}} }

// observe returns a registerFn bound to a manager: each registration presents
// that manager's account key to the counter.
func (r *regCounter) observe(mgr *LegoManager) func(context.Context) error {
	return func(context.Context) error {
		fp := fingerprintKey(mgr.provider.GetPrivateKey())
		r.mu.Lock()
		defer r.mu.Unlock()
		if _, ok := r.keys[fp]; !ok {
			r.creations++
			r.keys[fp] = struct{}{}
		}
		return nil
	}
}

func (r *regCounter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.creations
}

func fingerprintKey(v crypto.PrivateKey) string {
	key, ok := v.(*ecdsa.PrivateKey)
	if !ok {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// genTestCert mints a self-signed PEM cert/key pair in lego Resource form
// with a fresh ECDSA key.
func genTestCert(t *testing.T, domains []string, notAfter time.Time) *certificate.Resource {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return genTestCertWithKey(t, domains, notAfter, key)
}

// genTestCertWithKey mints a self-signed PEM cert/key pair in lego Resource
// form bound to the GIVEN key — used to prove renewal honors a reused key.
func genTestCertWithKey(t *testing.T, domains []string, notAfter time.Time, key *ecdsa.PrivateKey) *certificate.Resource {
	t.Helper()
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	return &certificate.Resource{
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// spkiHash returns the SHA-256 over the key's SPKI DER — exactly the value a
// DANE-EE (3 1 1) TLSA record pins. Equal hashes across renewals mean TLSA
// records stay valid (certificate-key stability).
func spkiHash(t *testing.T, key crypto.PrivateKey) string {
	t.Helper()
	var pub crypto.PublicKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	default:
		t.Fatalf("unsupported key type %T", key)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// pemKey parses a PEM private key block (EC/PKCS1/PKCS8) into a crypto key.
func pemKey(t *testing.T, pemBytes []byte) crypto.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block in private key")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k
	}
	t.Fatal("unparsable private key PEM")
	return nil
}

func blobOf(res *certificate.Resource) []byte {
	return append(append([]byte{}, res.PrivateKey...), res.Certificate...)
}

// newDirectoryServer serves a minimal local ACME directory so lego client
// construction has somewhere to point; no real ACME traffic ever happens
// (issueFn/registerFn fakes).
func newDirectoryServer(t *testing.T) (url string, client *http.Client) {
	t.Helper()
	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			http.NotFound(w, r)
			return
		}
		baseURL := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   baseURL + "/new-nonce",
			"newAccount": baseURL + "/new-account",
			"newOrder":   baseURL + "/new-order",
			"revokeCert": baseURL + "/revoke-cert",
			"keyChange":  baseURL + "/key-change",
			"meta":       map[string]any{},
		}); err != nil {
			t.Errorf("encode ACME directory: %v", err)
		}
	}))
	t.Cleanup(directory.Close)
	return directory.URL + "/directory", directory.Client()
}

func newTestManager(t *testing.T, cacheDir, keyFile string) *LegoManager {
	t.Helper()
	return newTestManagerChallenge(t, cacheDir, keyFile, ChallengeDNS01)
}

func newTestManagerChallenge(t *testing.T, cacheDir, keyFile, challenge string) *LegoManager {
	t.Helper()
	dirURL, dirClient := newDirectoryServer(t)

	cfg := LegoConfig{
		Domains:    []string{testDomain},
		Email:      "admin@example.com",
		CacheDir:   cacheDir,
		KeyFile:    keyFile,
		Challenge:  challenge,
		CADirURL:   dirURL,
		HTTPClient: dirClient,
	}
	if challenge == "" || challenge == ChallengeDNS01 {
		cfg.ProviderCfg = ProviderConfig{Provider: "cloudflare", Config: `{"CF_API_TOKEN":"test"}`}
	}
	mgr, err := NewLegoManager(cfg)
	if err != nil {
		t.Fatalf("NewLegoManager(%s): %v", challenge, err)
	}
	mgr.checkInterval = time.Hour // tests only exercise the initial pass
	mgr.backoffFn = func(int) time.Duration { return time.Millisecond }
	return mgr
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func helloFor(name string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: name}
}

// ─── 1. serving-only: unknown SNI never issues ──────────────────────────────

func TestGetCertificate_ServingOnly_UnknownSNI(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	ctrl := newIssueController(nil) // would fail loudly if ever called
	reg := newRegCounter()
	mgr.issueFn = ctrl.issue
	mgr.registerFn = reg.observe(mgr)

	for _, sni := range []string{
		"evil.example.net",      // unconfigured domain
		"EVIL.Example.NET.",     // case/trailing-dot variants stay unconfigured
		"sub.mail.example.com",  // not covered (no wildcard configured)
		"mail.example.com.evil", // suffix attack
	} {
		cert, err := mgr.GetCertificate(helloFor(sni))
		if cert != nil || err != nil {
			t.Fatalf("SNI %q: expected (nil, nil) fallback signal, got (%v, %v)", sni, cert, err)
		}
	}
	// Empty SNI is also a fallback pass-through, never an issuance.
	if cert, err := mgr.GetCertificate(helloFor("")); cert != nil || err != nil {
		t.Fatalf("empty SNI: expected (nil, nil), got (%v, %v)", cert, err)
	}
	// Cold configured domain: still serving-only — managed loop owns issuance.
	if cert, err := mgr.GetCertificate(helloFor(testDomain)); cert != nil || err != nil {
		t.Fatalf("cold configured domain: expected (nil, nil), got (%v, %v)", cert, err)
	}

	if got := ctrl.count(); got != 0 {
		t.Fatalf("obtain called %d times from handshake lookups; must be 0", got)
	}
	if got := reg.count(); got != 0 {
		t.Fatalf("register called %d times from handshake lookups; must be 0", got)
	}

	// Warm cache (as the managed loop would leave it): a NORMALIZED SNI
	// (mixed case + trailing dot) serves from cache with zero issuance.
	res := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	if err := mgr.cache.Put(testDomain, blobOf(res)); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	cert, err := mgr.GetCertificate(helloFor("Mail.Example.COM."))
	if err != nil || cert == nil {
		t.Fatalf("configured SNI with warm cache: expected served cert, got (%v, %v)", cert, err)
	}
	if cert.Leaf == nil || len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != testDomain {
		t.Fatalf("served cert does not match configured domain: %v", cert.Leaf)
	}
	if got := ctrl.count(); got != 0 {
		t.Fatalf("serving from cache triggered obtain %d times; must be 0", got)
	}
}

// ─── 2. managed Start: cold cache → exactly one issuance, cached, served ────

func TestManagedStart_ColdCache_SingleIssuance(t *testing.T) {
	dir := t.TempDir()
	mgr := newTestManager(t, dir, "")

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	reg := newRegCounter()
	mgr.issueFn = ctrl.issue
	mgr.registerFn = reg.observe(mgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx)
	waitFor(t, 2*time.Second, func() bool {
		_, err := mgr.cache.Get(testDomain)
		return err == nil
	}, "managed loop to populate the cache")

	if got := ctrl.count(); got != 1 {
		t.Fatalf("expected exactly ONE issuance for a cold cache, got %d", got)
	}
	if got := reg.count(); got != 1 {
		t.Fatalf("expected exactly ONE account registration, got %d", got)
	}

	// Give the loop a beat: no second issuance, no re-registration.
	time.Sleep(30 * time.Millisecond)
	if got := ctrl.count(); got != 1 {
		t.Fatalf("issuance repeated: %d rounds", got)
	}

	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil {
		t.Fatalf("post-Start GetCertificate: expected served cert, got (%v, %v)", cert, err)
	}
	if cert.Leaf == nil {
		t.Fatal("served cert has no parsed leaf")
	}
	if !cert.Leaf.NotAfter.After(time.Now()) {
		t.Fatalf("served cert is not the freshly issued one (NotAfter %v)", cert.Leaf.NotAfter)
	}
}

// ─── 3. single-flight: double Start / concurrent triggers → one issuance ────

func TestManagedStart_SingleFlight(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	ctrl.block = make(chan struct{})
	mgr.issueFn = ctrl.issue
	mgr.registerFn = newRegCounter().observe(mgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr.Start(ctx) // initial pass enters issue and blocks
	<-ctrl.entered // one issuance round is in flight
	mgr.Start(ctx) // double Start must be a no-op (no second loop)

	// Concurrent triggers while the round is in flight must all collapse.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.renewIfNeeded(ctx)
		}()
	}
	wg.Wait()

	if got := ctrl.count(); got != 1 {
		t.Fatalf("concurrent triggers produced %d issuances; single-flight requires 1", got)
	}

	close(ctrl.block)
	waitFor(t, 2*time.Second, func() bool {
		_, err := mgr.cache.Get(testDomain)
		return err == nil
	}, "blocked issuance to complete")
	if got := ctrl.count(); got != 1 {
		t.Fatalf("issuance count drifted after completion: %d", got)
	}

	// A trigger after completion sees a fresh cache and issues nothing.
	mgr.renewIfNeeded(ctx)
	if got := ctrl.count(); got != 1 {
		t.Fatalf("post-completion trigger issued again: %d", got)
	}
}

// ─── 4. expired cache: renewed by the managed loop, never by a handshake ────

func TestExpiredCachedCert_ManagedRenewalOnly(t *testing.T) {
	clock := newFakeClock(time.Now())
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.now = clock.Now

	expired := genTestCert(t, []string{testDomain}, clock.Now().Add(-time.Hour))
	if err := mgr.cache.Put(testDomain, blobOf(expired)); err != nil {
		t.Fatalf("seed expired cache: %v", err)
	}

	fresh := genTestCert(t, []string{testDomain}, clock.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	ctrl.block = make(chan struct{})
	mgr.issueFn = ctrl.issue
	mgr.registerFn = newRegCounter().observe(mgr)

	// Pre-Start: the expired cert is NOT served, and the handshake lookup
	// issues nothing (serving-only invariant).
	if cert, err := mgr.GetCertificate(helloFor(testDomain)); cert != nil || err != nil {
		t.Fatalf("expired cached cert must not be served, got (%v, %v)", cert, err)
	}
	if got := ctrl.count(); got != 0 {
		t.Fatalf("handshake lookup on expired cache issued %d times; must be 0", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	<-ctrl.entered // managed loop is renewing

	// A handshake arriving DURING the managed renewal neither issues nor
	// serves anything.
	if cert, err := mgr.GetCertificate(helloFor(testDomain)); cert != nil || err != nil {
		t.Fatalf("handshake during renewal must get (nil, nil), got (%v, %v)", cert, err)
	}
	if got := ctrl.count(); got != 1 {
		t.Fatalf("issuance triggered outside the managed loop: %d calls", got-1)
	}

	close(ctrl.block)
	waitFor(t, 2*time.Second, func() bool {
		cert, err := mgr.GetCertificate(helloFor(testDomain))
		return err == nil && cert != nil
	}, "renewed cert to be served")
	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil || cert.Leaf == nil {
		t.Fatalf("renewed serve failed: (%v, %v)", cert, err)
	}
	if !cert.Leaf.NotAfter.After(clock.Now()) {
		t.Fatalf("served cert is not the managed renewal (%v)", cert.Leaf.NotAfter)
	}
	if got := ctrl.count(); got != 1 {
		t.Fatalf("issuance count is %d; the entire flow must issue exactly once", got)
	}
}

// TestRenewalWindow_Boundary pins the 30-day renew-before window on the
// injectable clock: fresh-enough certs are left alone, certs inside the
// window are renewed by the managed round.
func TestRenewalWindow_Boundary(t *testing.T) {
	clock := newFakeClock(time.Now())
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.now = clock.Now

	outside := genTestCert(t, []string{testDomain}, clock.Now().Add(31*24*time.Hour))
	if err := mgr.cache.Put(testDomain, blobOf(outside)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if mgr.needsRenewal(testDomain) {
		t.Fatal("cert with 31 days left must not need renewal (30d window)")
	}

	// Advance past the window boundary: 31d - 16d = 15d left → renew.
	clock.Advance(16 * 24 * time.Hour)
	if !mgr.needsRenewal(testDomain) {
		t.Fatal("cert with 15 days left must need renewal (30d window)")
	}

	renewed := genTestCert(t, []string{testDomain}, clock.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(renewed)
	mgr.issueFn = ctrl.issue
	mgr.registerFn = newRegCounter().observe(mgr)

	mgr.renewIfNeeded(context.Background())
	if got := ctrl.count(); got != 1 {
		t.Fatalf("expected one managed issuance inside the window, got %d", got)
	}
	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil {
		t.Fatalf("renewed cert not served: (%v, %v)", cert, err)
	}
	// Clock-based re-check after renewal: nothing stale remains.
	mgr.renewIfNeeded(context.Background())
	if got := ctrl.count(); got != 1 {
		t.Fatalf("renewal not idempotent after success: %d issuances", got)
	}
}

// ─── 5. atomic cache: interrupted write leaves the previous blob intact ─────

func TestDirCachePut_AtomicOnInterruptedWrite(t *testing.T) {
	dir := t.TempDir()
	cache := &DirCache{Dir: dir}

	if err := cache.Put(testDomain, []byte("previous-good-blob")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	orig := writePayload
	writePayload = func(*os.File, []byte) error { return errors.New("injected interrupted write") }
	defer func() { writePayload = orig }()

	if err := cache.Put(testDomain, []byte("new-blob")); err == nil {
		t.Fatal("expected the injected write error to surface")
	}

	got, err := cache.Get(testDomain)
	if err != nil || string(got) != "previous-good-blob" {
		t.Fatalf("interrupted write corrupted the cache: got %q, err %v", got, err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read cache dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected exactly the one cache file, got %v (orphan temp files break atomicity)", names)
	}

	// First-ever write interrupted: no partial file may appear.
	if err := cache.Put("other.example.com", []byte("x")); err == nil {
		t.Fatal("expected injected write error")
	}
	if _, err := cache.Get("other.example.com"); !os.IsNotExist(err) {
		t.Fatalf("interrupted first write left a partial blob: %v", err)
	}
}

// ─── 6. account key persists: restart does not re-register ──────────────────

func TestAccountKeyPersistence_NoReregistration(t *testing.T) {
	t.Run("explicit KeyFile", func(t *testing.T) {
		shared := t.TempDir()
		keyPath := filepath.Join(shared, "acme-account.pem")
		reg := newRegCounter()

		mgrA := newTestManager(t, shared, keyPath)
		resA := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
		ctrlA := newIssueController(resA)
		mgrA.issueFn = ctrlA.issue
		mgrA.registerFn = reg.observe(mgrA)
		mgrA.renewIfNeeded(context.Background())
		if got := reg.count(); got != 1 {
			t.Fatalf("first boot: expected 1 account registration, got %d", got)
		}
		if _, err := os.Stat(keyPath); err != nil {
			t.Fatalf("account key not persisted to KeyFile: %v", err)
		}
		fpA := fingerprintKey(mgrA.provider.GetPrivateKey())

		// "Restart": a fresh manager over the same paths must reuse the
		// persisted account key — no new ACME account creation.
		mgrB := newTestManager(t, shared, keyPath)
		resB := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
		ctrlB := newIssueController(resB)
		mgrB.issueFn = ctrlB.issue
		mgrB.registerFn = reg.observe(mgrB)
		mgrB.renewIfNeeded(context.Background())

		if got := reg.count(); got != 1 {
			t.Fatalf("restart created a NEW ACME account (%d registrations with distinct keys); key persistence is broken", got)
		}
		if fp := fingerprintKey(mgrB.provider.GetPrivateKey()); fp != fpA {
			t.Fatal("restart loaded a different account key than the persisted one")
		}
	})

	t.Run("default path under CacheDir", func(t *testing.T) {
		dir := t.TempDir()
		mgr := newTestManager(t, dir, "") // KeyFile unset
		res := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
		ctrl := newIssueController(res)
		mgr.issueFn = ctrl.issue
		mgr.registerFn = newRegCounter().observe(mgr)
		mgr.renewIfNeeded(context.Background())
		if _, err := os.Stat(filepath.Join(dir, accountKeyFileName)); err != nil {
			t.Fatalf("account key not persisted to default path: %v", err)
		}
	})
}

// ─── 7. monitor probe observes the real cert ────────────────────────────────

// TestMonitorProbe_ObservesRealCert pins the cert_monitor probe contract from
// cmd/mailserverd: the probe passes a REAL configured SNI (not an empty one),
// and the serving-only GetCertificate then returns the managed cert with a
// parsed leaf — so CertMonitor records non-empty server names instead of
// "no TLS certificates loaded".
func TestMonitorProbe_ObservesRealCert(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")

	// Before the managed loop has issued anything there is honestly nothing
	// to observe — the probe returning empty is correct, not a wiring bug.
	if cert, err := mgr.GetCertificate(helloFor(testDomain)); cert != nil || err != nil {
		t.Fatalf("cold cache probe must observe nothing, got (%v, %v)", cert, err)
	}

	res := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(res)
	mgr.issueFn = ctrl.issue
	mgr.registerFn = newRegCounter().observe(mgr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx)
	// Wait for the full round — cert cached, not just issuance started.
	waitFor(t, 2*time.Second, func() bool {
		_, err := mgr.cache.Get(testDomain)
		return err == nil
	}, "managed issuance to land in the cache")

	// The fixed probe: real configured SNI → real cert with server names.
	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil {
		t.Fatalf("probe with real SNI observed no cert: (%v, %v)", cert, err)
	}
	if cert.Leaf == nil {
		t.Fatal("observed cert has no parsed leaf; cert_monitor would see no server names")
	}
	found := false
	for _, name := range cert.Leaf.DNSNames {
		if name == testDomain {
			found = true
		}
	}
	if !found {
		t.Fatalf("cert_monitor would observe server names %v; want %q", cert.Leaf.DNSNames, testDomain)
	}

	// The empty-SNI hello — the OLD probe — observes nothing. This is exactly
	// why the monitor was rewired to real server names.
	if cert, err := mgr.GetCertificate(helloFor("")); cert != nil || err != nil {
		t.Fatalf("empty-SNI probe must observe nothing, got (%v, %v)", cert, err)
	}
}

// ─── 8. round-3: monitor probe cannot panic on a synthetic hello ─────────────

// TestServeFromAutocertCache_SyntheticHelloNoPanic pins the startup-panic fix:
// the cert_monitor probe builds synthetic tls.ClientHelloInfo values whose
// Context() is nil. autocert.DirCache.Get dereferences ctx.Done() — a nil ctx
// panicked startup. ServeFromAutocertCache (which replaced main.go's
// autocertCached closure) must substitute a background context and serve the
// cached cert. Test would panic, not fail, on regression.
func TestServeFromAutocertCache_SyntheticHelloNoPanic(t *testing.T) {
	dir := t.TempDir()
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(testDomain, "old.example.com"),
		Cache:      autocert.DirCache(dir),
	}

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	if err := mgr.Cache.Put(context.Background(), testDomain, blobOf(fresh)); err != nil {
		t.Fatalf("seed autocert cache: %v", err)
	}

	// Synthetic hello (nil Context — exactly what main.go's monitor builds):
	// must NOT panic and must observe the real cert.
	cert := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: testDomain})
	if cert == nil || cert.Leaf == nil {
		t.Fatal("monitor probe with synthetic hello observed no cert from the autocert cache")
	}
	if cert.Leaf.VerifyHostname(testDomain) != nil {
		t.Fatalf("observed cert does not match %s", testDomain)
	}

	// Unknown SNI: nil (host whitelist), still no panic.
	if got := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: "evil.example.net"}); got != nil {
		t.Fatal("unknown SNI must not be served from the autocert cache")
	}
	// Expired cached cert: nil, still no panic.
	expired := genTestCert(t, []string{"old.example.com"}, time.Now().Add(-time.Hour))
	if err := mgr.Cache.Put(context.Background(), "old.example.com", blobOf(expired)); err != nil {
		t.Fatalf("seed expired autocert cache: %v", err)
	}
	if got := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: "old.example.com"}); got != nil {
		t.Fatal("expired cached cert must not be served")
	}
	// nil manager / empty SNI: nil, no panic.
	if got := ServeFromAutocertCache(nil, &tls.ClientHelloInfo{ServerName: testDomain}); got != nil {
		t.Fatal("nil manager must serve nothing")
	}
	if got := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{}); got != nil {
		t.Fatal("empty SNI must serve nothing")
	}
}

// ─── 9. round-3: http-01 runs in the managed loop ────────────────────────────

func TestManagedIssuance_HTTP01Challenge(t *testing.T) {
	mgr := newTestManagerChallenge(t, t.TempDir(), "", ChallengeHTTP01)
	if mgr.Challenge() != ChallengeHTTP01 {
		t.Fatalf("challenge not resolved to http-01: %q", mgr.Challenge())
	}

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	reg := newRegCounter()
	mgr.issueFn = ctrl.issue
	mgr.registerFn = reg.observe(mgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx) // managed loop must cover http-01 exactly like dns-01
	waitFor(t, 2*time.Second, func() bool {
		_, err := mgr.cache.Get(testDomain)
		return err == nil
	}, "http-01 managed issuance to land in the cache")
	if got := ctrl.count(); got != 1 {
		t.Fatalf("http-01 managed issuance called %d times; want 1", got)
	}
	cert, err := mgr.GetCertificate(helloFor(testDomain))
	if err != nil || cert == nil {
		t.Fatalf("http-01 issued cert not served: (%v, %v)", cert, err)
	}

	// The :80 responder: present → served, cleanup → passthrough.
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("app"))
	})
	h := mgr.HTTP01Handler(next)

	passthrough := func(what string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nothing/here", nil))
		if rec.Code != http.StatusTeapot || rec.Body.String() != "app" {
			t.Fatalf("%s: expected app passthrough, got (%d, %q)", what, rec.Code, rec.Body.String())
		}
	}
	passthrough("before present")

	if err := mgr.http01.Present(testDomain, "token-1", "keyAuth-1"); err != nil {
		t.Fatalf("http-01 Present: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/token-1", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "keyAuth-1" {
		t.Fatalf("http-01 challenge response wrong: (%d, %q)", rec.Code, rec.Body.String())
	}
	if err := mgr.http01.CleanUp(testDomain, "token-1", ""); err != nil {
		t.Fatalf("http-01 CleanUp: %v", err)
	}
	passthrough("after cleanup")

	// A manager without the http-01 challenge must not swallow :80 traffic.
	dnsMgr := newTestManager(t, t.TempDir(), "")
	if h := dnsMgr.HTTP01Handler(next); h == nil {
		t.Fatal("HTTP01Handler must never return nil")
	}
}

// ─── 10. round-3: tls-alpn-01 runs in the managed loop ───────────────────────

func TestManagedIssuance_TLSALPN01Challenge(t *testing.T) {
	mgr := newTestManagerChallenge(t, t.TempDir(), "", ChallengeTLSALPN01)
	if mgr.Challenge() != ChallengeTLSALPN01 {
		t.Fatalf("challenge not resolved to tls-alpn-01: %q", mgr.Challenge())
	}

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	reg := newRegCounter()
	mgr.issueFn = ctrl.issue
	mgr.registerFn = reg.observe(mgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr.Start(ctx) // managed loop must cover tls-alpn-01 exactly like dns-01
	waitFor(t, 2*time.Second, func() bool {
		_, err := mgr.cache.Get(testDomain)
		return err == nil
	}, "tls-alpn-01 managed issuance to land in the cache")
	if got := ctrl.count(); got != 1 {
		t.Fatalf("tls-alpn-01 managed issuance called %d times; want 1", got)
	}
	if cert, err := mgr.GetCertificate(helloFor(testDomain)); err != nil || cert == nil {
		t.Fatalf("tls-alpn-01 issued cert not served: (%v, %v)", cert, err)
	}

	// :443 responder via GetConfigForClient: pending challenge + acme-tls/1
	// ALPN → one-shot challenge config; anything else → nil (base config).
	if err := mgr.alpn01.Present(testDomain, "tok", "keyAuth-alpn"); err != nil {
		t.Fatalf("tls-alpn-01 Present: %v", err)
	}
	hello := &tls.ClientHelloInfo{
		ServerName:        testDomain,
		SupportedProtos:   []string{"h2", "acme-tls/1"},
		SupportedVersions: []uint16{tls.VersionTLS13},
	}
	chalCfg := mgr.TLSALPNConfigFor(hello)
	if chalCfg == nil || len(chalCfg.Certificates) != 1 {
		t.Fatal("tls-alpn-01 challenge config not returned for acme-tls/1 hello")
	}
	if len(chalCfg.NextProtos) != 1 || chalCfg.NextProtos[0] != "acme-tls/1" {
		t.Fatalf("challenge config NextProtos = %v; want [acme-tls/1]", chalCfg.NextProtos)
	}
	chalCert := chalCfg.Certificates[0]
	if chalCert.Leaf == nil && len(chalCert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(chalCert.Certificate[0])
		if err != nil {
			t.Fatalf("parse challenge leaf: %v", err)
		}
		chalCert.Leaf = leaf
	}
	if chalCert.Leaf == nil || chalCert.Leaf.VerifyHostname(testDomain) != nil {
		t.Fatal("challenge cert does not match the validated domain")
	}
	// RFC 8737: the cert must carry the acmeIdentifier extension
	// (1.3.6.1.5.5.7.1.31) — else the ACME server rejects the response.
	acmeExtOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	hasExt := false
	for _, ext := range chalCert.Leaf.Extensions {
		if ext.Id.Equal(acmeExtOID) {
			hasExt = true
		}
	}
	if !hasExt {
		t.Fatal("challenge cert missing acmeValidation-v1 extension")
	}

	// No ALPN offered, or foreign SNI → base config.
	if got := mgr.TLSALPNConfigFor(&tls.ClientHelloInfo{ServerName: testDomain, SupportedProtos: []string{"h2"}}); got != nil {
		t.Fatal("config returned for a hello without acme-tls/1")
	}
	if got := mgr.TLSALPNConfigFor(&tls.ClientHelloInfo{ServerName: "evil.example.net", SupportedProtos: []string{"acme-tls/1"}}); got != nil {
		t.Fatal("config returned for an unconfigured SNI")
	}
	if err := mgr.alpn01.CleanUp(testDomain, "tok", ""); err != nil {
		t.Fatalf("tls-alpn-01 CleanUp: %v", err)
	}
	if got := mgr.TLSALPNConfigFor(hello); got != nil {
		t.Fatal("challenge config returned after CleanUp")
	}
}

// ─── 11. round-3: fail-loud for challenges the managed loop cannot cover ─────

func TestNewLegoManager_FailLoud(t *testing.T) {
	t.Run("unsupported challenge value", func(t *testing.T) {
		dirURL, dirClient := newDirectoryServer(t)
		_, err := NewLegoManager(LegoConfig{
			Domains:    []string{testDomain},
			Email:      "admin@example.com",
			CacheDir:   t.TempDir(),
			Challenge:  "carrier-pigeon-01",
			CADirURL:   dirURL,
			HTTPClient: dirClient,
		})
		if err == nil {
			t.Fatal("unsupported challenge must fail construction (it can never issue)")
		}
		if !strings.Contains(err.Error(), "carrier-pigeon-01") {
			t.Fatalf("error must name the bad challenge: %v", err)
		}
	})

	t.Run("wildcard domain with http-01", func(t *testing.T) {
		dirURL, dirClient := newDirectoryServer(t)
		_, err := NewLegoManager(LegoConfig{
			Domains:    []string{"*.example.com"},
			Email:      "admin@example.com",
			CacheDir:   t.TempDir(),
			Challenge:  ChallengeHTTP01,
			CADirURL:   dirURL,
			HTTPClient: dirClient,
		})
		if err == nil {
			t.Fatal("wildcard + http-01 must fail construction (needs dns-01)")
		}
	})

	t.Run("empty challenge defaults to dns-01", func(t *testing.T) {
		mgr := newTestManagerChallenge(t, t.TempDir(), "", "")
		if mgr.Challenge() != ChallengeDNS01 {
			t.Fatalf("empty challenge must resolve to dns-01, got %q", mgr.Challenge())
		}
	})
}

// ─── 12. round-3: active issuance honors cancellation (ctx threading) ────────

func TestObtain_CancellationAbortsIssuance(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	entered := make(chan struct{})
	returned := make(chan struct{})
	var once sync.Once
	var issueCalls int32
	var seenCtx context.Context
	mgr.issueFn = func(ctx context.Context, _ certificate.ObtainRequest) (*certificate.Resource, error) {
		atomic.AddInt32(&issueCalls, 1)
		seenCtx = ctx // must be the manager's ctx, not context.Background()
		once.Do(func() { close(entered) })
		<-ctx.Done() // hold the issuance open until cancelled
		defer close(returned)
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	mgr.Start(ctx)
	<-entered // issuance round is in flight
	cancel()

	<-returned // the aborted obtain unwound through the manager's ctx
	waitFor(t, 2*time.Second, func() bool {
		return seenCtx != nil && seenCtx.Err() != nil
	}, "the manager's context to reach the issuer seam")

	// The manager's live ctx — not context.Background() — was threaded in.
	if !errors.Is(seenCtx.Err(), context.Canceled) {
		t.Fatalf("issuer seam saw %v; want the cancelled manager ctx", seenCtx.Err())
	}
	// Aborted round must not publish anything.
	if _, err := mgr.cache.Get(testDomain); !os.IsNotExist(err) {
		t.Fatalf("cancelled obtain published a cert: %v", err)
	}
	// Cancellation stops the retry loop: no further attempts after the abort.
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&issueCalls); got != 1 {
		t.Fatalf("issue called %d times after cancellation; want no retry", got)
	}

	// A renewWithRetry with an already-cancelled ctx must not issue at all.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := mgr.renewWithRetry(ctx2, testDomain); !errors.Is(err, context.Canceled) {
		t.Fatalf("renewWithRetry(cancelled) = %v; want context.Canceled", err)
	}
	if got := atomic.LoadInt32(&issueCalls); got != 1 {
		t.Fatalf("pre-cancelled round issued %d extra times", got-1)
	}
}

// ─── 13. round-3: failed attempts retry with backoff ─────────────────────────

func TestObtain_RetriesWithBackoffThenSucceeds(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	attempts := 0
	backoffs := 0
	mgr.backoffFn = func(int) time.Duration { backoffs++; return time.Millisecond }
	mgr.issueFn = func(_ context.Context, _ certificate.ObtainRequest) (*certificate.Resource, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("transient DNS provider failure")
		}
		return fresh, nil
	}

	mgr.renewIfNeeded(context.Background())
	if attempts != 2 || backoffs != 1 {
		t.Fatalf("expected fail → backoff → success (2 attempts, 1 backoff), got %d attempts / %d backoffs", attempts, backoffs)
	}
	if _, err := mgr.cache.Get(testDomain); err != nil {
		t.Fatalf("successful retry did not publish: %v", err)
	}
}

// ─── 14. round-3: renewal reuses the certificate key (TLSA stability) ────────

func TestRenewal_ReuseCertificateKey_TLSAStability(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	// Warm cache: a previously issued cert with key K1.
	initial := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	if err := mgr.cache.Put(normalizeSNI(testDomain), blobOf(initial)); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	seedHash := spkiHash(t, pemKey(t, initial.PrivateKey))

	var reusedKeyHash string
	mgr.issueFn = func(_ context.Context, req certificate.ObtainRequest) (*certificate.Resource, error) {
		if req.PrivateKey == nil {
			return nil, errors.New("renewal MUST pass the existing certificate key for TLSA stability")
		}
		reusedKeyHash = spkiHash(t, req.PrivateKey)
		// Honor the reuse like a real CA: new cert, SAME key.
		reused, ok := req.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			// Return (not t.Fatalf): the fake runs on the bounded issuance
			// goroutine, where a Fatal would strand the round's select.
			return nil, fmt.Errorf("reused key is %T; want *ecdsa.PrivateKey", req.PrivateKey)
		}
		return genTestCertWithKey(t, []string{testDomain}, time.Now().Add(180*24*time.Hour), reused), nil
	}

	if err := mgr.renewWithRetry(context.Background(), testDomain); err != nil {
		t.Fatalf("managed renewal round failed: %v", err)
	}

	if reusedKeyHash != seedHash {
		t.Fatal("renewal presented a DIFFERENT key than the cached certificate — DANE TLSA (3 1 1) records would break")
	}
	// The freshly renewed blob must still carry the same key on disk.
	renewedBlob, err := mgr.cache.Get(normalizeSNI(testDomain))
	if err != nil {
		t.Fatalf("renewed blob missing: %v", err)
	}
	renewed, err := parseCertBlob(renewedBlob)
	if err != nil {
		t.Fatalf("parse renewed blob: %v", err)
	}
	if got := spkiHash(t, renewed.PrivateKey); got != seedHash {
		t.Fatal("published renewed cert does not carry the reused key")
	}

	// Cold cache (no previous cert): the issuer gets a nil key → fresh key.
	mgr2 := newTestManager(t, t.TempDir(), "")
	mgr2.registerFn = newRegCounter().observe(mgr2)
	var coldReq certificate.ObtainRequest
	cold := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	mgr2.issueFn = func(_ context.Context, req certificate.ObtainRequest) (*certificate.Resource, error) {
		coldReq = req
		return cold, nil
	}
	mgr2.renewIfNeeded(context.Background())
	if coldReq.PrivateKey != nil {
		t.Fatal("first issuance must NOT force a key (nil lets the CA/lego generate one)")
	}
}

// ─── 15. round-3: publication failures surface and retry ─────────────────────

func TestObtain_CachePublicationFailureSurfacedAndRetried(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	// Block the NORMALIZED cache path with a directory: Put's rename fails
	// for every attempt.
	blocked := mgr.cache.certPath(normalizeSNI(testDomain))
	if err := os.MkdirAll(blocked, 0700); err != nil {
		t.Fatalf("block cache path: %v", err)
	}

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	ctrl := newIssueController(fresh)
	mgr.issueFn = ctrl.issue

	err := mgr.renewWithRetry(context.Background(), testDomain)
	if err == nil {
		t.Fatal("cache publication failure must surface, not be suppressed")
	}
	if !strings.Contains(err.Error(), "cache put") {
		t.Fatalf("error must identify the failed publication: %v", err)
	}
	if got := ctrl.count(); got != mgr.maxAttempts {
		t.Fatalf("publication failure must retry with backoff: %d attempts, want %d", got, mgr.maxAttempts)
	}

	// Unblock: the next managed round succeeds and the cert is durably cached.
	if err := os.Remove(blocked); err != nil {
		t.Fatalf("unblock cache path: %v", err)
	}
	if err := mgr.renewWithRetry(context.Background(), testDomain); err != nil {
		t.Fatalf("recovery round failed: %v", err)
	}
	if _, err := mgr.cache.Get(normalizeSNI(testDomain)); err != nil {
		t.Fatalf("recovered publication missing: %v", err)
	}
}

// ─── 16. round-3: publication keys are normalized (lowercase, no dot) ────────

func TestObtain_PublishesNormalizedDomainKeys(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	// Configured with mixed case + trailing dot: publication must land under
	// the normalized key so serving and lifecycle checks find the blob.
	mgr.config.Domains = []string{"Mail.Example.COM."}

	fresh := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	mgr.issueFn = newIssueController(fresh).issue

	if err := mgr.renewWithRetry(context.Background(), testDomain); err != nil {
		t.Fatalf("managed round failed: %v", err)
	}
	if _, err := mgr.cache.Get("mail.example.com"); err != nil {
		t.Fatalf("blob not published under the normalized key: %v", err)
	}
	// Serving path and lifecycle checks agree on the same file.
	if cert, err := mgr.GetCertificate(helloFor("MAIL.Example.COM.")); err != nil || cert == nil {
		t.Fatalf("normalized SNI not served: (%v, %v)", cert, err)
	}
	if mgr.needsRenewal("mail.example.com") {
		t.Fatal("lifecycle check does not see the normalized publication (would reissue forever)")
	}
}

// ─── 17. round-4: a cancelled round is abandoned, never published ─────────────

// gatingRoundTripper blocks the first ACME protocol call (/new-nonce, the
// first HTTP request lego's Obtain issues after construction) until released,
// modelling the multi-minute production issuance that keeps running after the
// governing round ctx is cancelled. Non-challenge traffic (the directory
// fetch at client construction) passes straight through.
type gatingRoundTripper struct {
	entered chan struct{}
	release chan struct{}
	base    http.RoundTripper
	once    sync.Once
}

func (g *gatingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/new-nonce") {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	return g.base.RoundTrip(r)
}

// TestObtain_CancelledRound_NeverPublishesLateSuccess pins the r13 HOLD fix:
// an issuance call that ignores ctx (exactly lego's ctx-less Obtain) and
// returns SUCCESS after the round was cancelled must be abandoned — the
// cancelled round surfaces only the cancellation sentinel and the late
// resource is never published into the cache.
func TestObtain_CancelledRound_NeverPublishesLateSuccess(t *testing.T) {
	mgr := newTestManager(t, t.TempDir(), "")
	mgr.registerFn = newRegCounter().observe(mgr)

	late := genTestCert(t, []string{testDomain}, time.Now().Add(90*24*time.Hour))
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	mgr.issueFn = func(context.Context, certificate.ObtainRequest) (*certificate.Resource, error) {
		once.Do(func() { close(entered) })
		<-release // ctx deliberately ignored: models lego's ctx-less Obtain
		return late, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	roundErr := make(chan error, 1)
	go func() { roundErr <- mgr.renewWithRetry(ctx, testDomain) }()

	<-entered // issuance is in flight
	cancel()  // cancel the round while the issuer is still delayed

	// The cancelled caller is abandoned promptly: the only surfaced error is
	// the sentinel cancellation — never the late issuer success.
	select {
	case err := <-roundErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled round surfaced %v; want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled caller left waiting for the in-flight issuance")
	}

	// The delayed issuer eventually "succeeds": a late success must never be
	// published for the abandoned round.
	close(release)
	time.Sleep(30 * time.Millisecond)
	if _, err := mgr.cache.Get(normalizeSNI(testDomain)); !os.IsNotExist(err) {
		t.Fatalf("late-arriving success was published after cancellation: %v", err)
	}
}

// TestObtain_ProductionLegoObtain_BoundedByRoundContext exercises the
// PRODUCTION branch (issueFn nil) that r13 flagged: the real lego Obtain,
// which has no ctx parameter, must be bounded by the round ctx — a cancelled
// round returns immediately instead of blocking on lego, and nothing the
// abandoned Obtain does afterwards reaches the cache.
func TestObtain_ProductionLegoObtain_BoundedByRoundContext(t *testing.T) {
	dirURL, dirClient := newDirectoryServer(t)
	base := dirClient.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	gate := &gatingRoundTripper{entered: make(chan struct{}), release: make(chan struct{}), base: base}

	mgr, err := NewLegoManager(LegoConfig{
		Domains:     []string{testDomain},
		Email:       "admin@example.com",
		CacheDir:    t.TempDir(),
		Challenge:   ChallengeDNS01,
		ProviderCfg: ProviderConfig{Provider: "cloudflare", Config: `{"CF_API_TOKEN":"test"}`},
		CADirURL:    dirURL,
		HTTPClient:  &http.Client{Transport: gate}, // issueFn stays nil → production Obtain
	})
	if err != nil {
		t.Fatalf("NewLegoManager: %v", err)
	}
	mgr.checkInterval = time.Hour
	mgr.backoffFn = func(int) time.Duration { return time.Millisecond }
	mgr.registerFn = newRegCounter().observe(mgr) // fake registration; Obtain owns the first HTTP call

	ctx, cancel := context.WithCancel(context.Background())
	roundErr := make(chan error, 1)
	go func() { roundErr <- mgr.renewWithRetry(ctx, testDomain) }()

	<-gate.entered // lego Obtain is mid-flight inside its first ACME HTTP call
	cancel()

	// The cancelled caller must not wait out the production Obtain.
	select {
	case err := <-roundErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled production round surfaced %v; want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("production Obtain is not bounded by the round ctx (caller blocked on lego)")
	}

	// Whatever the abandoned Obtain concludes after release, the abandoned
	// round must not publish.
	close(gate.release)
	time.Sleep(30 * time.Millisecond)
	if _, err := mgr.cache.Get(normalizeSNI(testDomain)); !os.IsNotExist(err) {
		t.Fatalf("abandoned production Obtain published a cert: %v", err)
	}
}
