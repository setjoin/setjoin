package ad

// CONNECTOR-001 flag-matrix acceptance tests (L2-C3, manifest Items 1 + r2
// adjudications): certificate and hostname verification are UNCONDITIONAL —
// the AD_SKIP_TLS_VERIFY env kill switch was REMOVED, not replaced (a
// replacement dev bypass is adjudicated out of scope).
//
//   T1  untrusted / self-signed / wrong-host / expired servers → connect error
//   T2  no bypass input exists (no env read remains) — config-shape + source
//       scan; setting the retired env var changes nothing
//   T3  TLS < 1.2 offered → handshake refused (MinVersion pinned)
//   T4  LDAPS to a plaintext endpoint → connect error (no implicit downgrade)
//   T5  ServerName explicitly derived from the configured host, asserted in
//       the verified-handshake test (server captures the ClientHello)
//   T6  lives in mailserver/internal/ad (client pin, no fix) — its guard
//       asserts the mailserver tls.Config carries no InsecureSkipVerify and
//       the transport/Bind gates hold.
//
// Handshake tests run a REAL in-process TLS listener and the real
// ldap.DialTLS path; the dialTLS seam only redirects the dial and (where a
// custom trust anchor is unavoidable — system roots cannot trust ephemeral
// test CAs) injects the test CA pool. It never touches ServerName,
// MinVersion, or InsecureSkipVerify, and the production-config shape is
// separately asserted unmodified.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"setjoin.com/authserver/internal/connector"
)

// ── test PKI helpers ───────────────────────────────────────────────────────

// testCA is an ephemeral certificate authority for the in-process LDAPS
// server. Its key and cert never leave the test process.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key := mustECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// issue mints a server certificate under the CA. notBefore/notAfter allow the
// expired-cert arm; dnsNames/ips drive hostname verification.
func (ca *testCA) issue(t *testing.T, dnsNames []string, ips []net.IP, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key := mustECDSAKey(t)
	template := &x509.Certificate{
		SerialNumber:          mustSerial(t),
		Subject:               pkix.Name{CommonName: firstOr(dnsNames, "ldap.test")},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
	}
}

func mustECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func mustSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	return n
}

func firstOr(names []string, fallback string) string {
	if len(names) > 0 {
		return names[0]
	}
	return fallback
}

// ── in-process servers ─────────────────────────────────────────────────────

// ldapsTestServer is a real TLS listener presenting the given certificate.
// It captures each ClientHello so tests can assert the ServerName and
// offered versions the connector actually sent (T5).
type ldapsTestServer struct {
	addr string // host:port to dial

	mu        sync.Mutex
	hellos    []*tls.ClientHelloInfo
	helloSeen chan struct{}
}

func startTestLDAPSServer(t *testing.T, cert tls.Certificate, mutate ...func(*tls.Config)) *ldapsTestServer {
	t.Helper()
	srv := &ldapsTestServer{helloSeen: make(chan struct{}, 8)}
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
	}
	base.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		srv.mu.Lock()
		srv.hellos = append(srv.hellos, hi)
		srv.mu.Unlock()
		select {
		case srv.helloSeen <- struct{}{}:
		default:
		}
		return nil, nil // present the base config
	}
	for _, m := range mutate {
		m(base)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsLn := tls.NewListener(ln, base)
	srv.addr = ln.Addr().String()
	t.Cleanup(func() { _ = tlsLn.Close() })
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				// Serve until the client closes; the first Read drives the
				// TLS handshake server-side.
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 16)
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						return
					}
				}
			}()
		}
	}()
	return srv
}

// waitHello waits for one captured ClientHello (the handshake happened) and
// returns it.
func (s *ldapsTestServer) waitHello(t *testing.T) *tls.ClientHelloInfo {
	t.Helper()
	select {
	case <-s.helloSeen:
	case <-time.After(10 * time.Second):
		t.Fatal("no TLS ClientHello reached the test server")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hellos[len(s.hellos)-1]
}

// startPlaintextServer listens raw TCP and speaks NO TLS — the T4 shape
// (LDAPS client against a plaintext endpoint). Writing non-TLS bytes makes
// the client handshake fail deterministically instead of hanging.
func startPlaintextServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = conn.Write([]byte("* OK plaintext, not TLS\r\n"))
				_ = conn.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// ── dial seam helpers ──────────────────────────────────────────────────────

// captureConfig swaps the dial seam for one that records the connector-built
// *tls.Config and fails the dial (no network I/O). The recorded config IS the
// flag-matrix surface; verification semantics are asserted on it unmodified.
func captureConfig(t *testing.T) <-chan *tls.Config {
	t.Helper()
	ch := make(chan *tls.Config, 4)
	orig := dialTLS
	t.Cleanup(func() { dialTLS = orig })
	dialTLS = func(_ string, _ string, cfg *tls.Config) (*ldap.Conn, error) {
		ch <- cfg
		return nil, errors.New("test seam: no dial")
	}
	return ch
}

// trustTestCA swaps the dial seam for one that dials targetAddr with the
// connector-built config CLONED to add the test CA as trust anchor. The clone
// keeps ServerName, MinVersion, and (absent) InsecureSkipVerify exactly as
// the connector built them — only the root pool is ephemeral-test-specific.
func trustTestCA(t *testing.T, ca *testCA, targetAddr string) {
	t.Helper()
	orig := dialTLS
	t.Cleanup(func() { dialTLS = orig })
	dialTLS = func(network, _ string, cfg *tls.Config) (*ldap.Conn, error) {
		clone := cfg.Clone()
		clone.RootCAs = x509.NewCertPool()
		clone.RootCAs.AddCert(ca.cert)
		return orig(network, targetAddr, clone)
	}
}

// ── T2 / T5 config-shape ───────────────────────────────────────────────────

// TestConnectBuildsUnconditionallyVerifiedTLSConfig pins the production
// config shape: hostname verification on (ServerName derived from the
// configured host, explicitly, no implicit fallback), MinVersion TLS 1.2, NO
// InsecureSkipVerify — and no surviving reaction to the retired env kill
// switch (T2: "no such input exists / no env read remains").
func TestConnectBuildsUnconditionallyVerifiedTLSConfig(t *testing.T) {
	t.Setenv("AD_SKIP_TLS_VERIFY", "true") // must be inert: the knob is gone

	ch := captureConfig(t)
	c := &Connector{host: "directory.test"}
	if _, err := c.connect(); err == nil {
		t.Fatal("seam-dial must fail, proving connect() ran through the seam")
	}
	var cfg *tls.Config
	select {
	case cfg = <-ch:
	default:
		t.Fatal("connect() never built a tls.Config")
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true — the CONNECTOR-001 contract forbids any skip path")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %v, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ServerName != "directory.test" {
		t.Errorf("ServerName = %q, want explicitly derived \"directory.test\"", cfg.ServerName)
	}

	// Host with an explicit port: ServerName is the host portion, not the
	// address, not the port.
	ch2 := captureConfig(t)
	c2 := &Connector{host: "127.0.0.1:1636"}
	if _, err := c2.connect(); err == nil {
		t.Fatal("seam-dial must fail, proving connect() ran through the seam")
	}
	var cfg2 *tls.Config
	select {
	case cfg2 = <-ch2:
	default:
		t.Fatal("connect() never built a tls.Config (port arm)")
	}
	if cfg2.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true on the explicit-port arm")
	}
	if cfg2.ServerName != "127.0.0.1" {
		t.Errorf("ServerName = %q, want host portion \"127.0.0.1\"", cfg2.ServerName)
	}
}

// TestConnectNoBypassInputRemains is the source-shape half of T2: no file in
// the connector package reads the retired AD_SKIP_TLS_VERIFY environment
// variable or any os.Getenv at all (the connector has no env-shaped config).
// Test sources are excluded from the scan: this file itself names the retired
// knob in a t.Setenv to assert its inertness, which is assertion material, not
// a config input (same non-test-sources shape as the instantiation guards).
func TestConnectNoBypassInputRemains(t *testing.T) {
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve package dir: %v", err)
	}
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := v.X.(*ast.Ident); ok && id.Name == "os" && v.Sel.Name == "Getenv" {
					t.Errorf("%s: os.Getenv call — the AD connector must not read the environment", e.Name())
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING && strings.Contains(v.Value, "AD_SKIP_TLS_VERIFY") {
					t.Errorf("%s: literal mentions the retired AD_SKIP_TLS_VERIFY knob", e.Name())
				}
			}
			return true
		})
	}
}

// ── T1 verification arms (real handshakes) ─────────────────────────────────

// TestConnectRefusesUntrustedSelfSignedServer (T1): the server presents a
// certificate from a CA the process does not trust — the production config
// (system roots, no seam changes) must fail the handshake.
func TestConnectRefusesUntrustedSelfSignedServer(t *testing.T) {
	ca := newTestCA(t, "ephemeral test ca")
	srv := startTestLDAPSServer(t, ca.issue(t, []string{"directory.test"}, []net.IP{net.ParseIP("127.0.0.1")},
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))

	c := &Connector{host: srv.addr}
	_, err := c.connect()
	if err == nil {
		t.Fatal("connect succeeded against an untrusted CA — verification was skipped")
	}
	var authErr x509.UnknownAuthorityError
	if !errors.As(err, &authErr) {
		t.Errorf("err = %v, want x509.UnknownAuthorityError", err)
	}
}

// TestConnectRefusesExpiredCertificate (T1): an expired certificate fails
// validation even when its chain would otherwise be trusted.
func TestConnectRefusesExpiredCertificate(t *testing.T) {
	ca := newTestCA(t, "ephemeral test ca")
	srv := startTestLDAPSServer(t, ca.issue(t, []string{"directory.test"}, nil,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))

	trustTestCA(t, ca, srv.addr)
	c := &Connector{host: "directory.test"}
	_, err := c.connect()
	if err == nil {
		t.Fatal("connect succeeded with an expired certificate")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want an expiry verification failure", err)
	}
}

// TestConnectRefusesWrongHostname (T1): the certificate is valid and trusted
// but names a different host than the configured one — hostname verification
// must fail. The client's ServerName here is the dial host "127.0.0.1",
// proving the derived ServerName is actually enforced.
func TestConnectRefusesWrongHostname(t *testing.T) {
	ca := newTestCA(t, "ephemeral test ca")
	srv := startTestLDAPSServer(t, ca.issue(t, []string{"directory.test"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))

	trustTestCA(t, ca, srv.addr)
	c := &Connector{host: srv.addr} // ServerName = 127.0.0.1, cert says directory.test
	_, err := c.connect()
	if err == nil {
		t.Fatal("connect succeeded with a hostname mismatch")
	}
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) {
		t.Errorf("err = %v, want x509.HostnameError", err)
	}
}

// ── T5 verified handshake with explicit ServerName ─────────────────────────

// TestConnectVerifiedHandshakeSendsConfiguredServerName is the positive arm
// of the matrix: with a trusted chain and a matching name the handshake
// SUCCEEDS — and the server observes the ClientHello carrying exactly the
// configured host as ServerName. The dial address is 127.0.0.1 while the
// configured host is "directory.test", so success is only possible because
// ServerName was set explicitly (the implicit dial-address fallback would
// verify against "127.0.0.1" and fail). The client also offers no TLS version
// below 1.2 (T3's flip side, observed server-side).
func TestConnectVerifiedHandshakeSendsConfiguredServerName(t *testing.T) {
	ca := newTestCA(t, "ephemeral test ca")
	// Certificate names directory.test ONLY (no IP SAN): verification must go
	// through the explicit ServerName, not the dial address.
	srv := startTestLDAPSServer(t, ca.issue(t, []string{"directory.test"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))

	trustTestCA(t, ca, srv.addr)
	c := &Connector{host: "directory.test"}
	conn, err := c.connect()
	if err != nil {
		t.Fatalf("verified handshake failed: %v", err)
	}
	_ = conn.Close()

	hi := srv.waitHello(t)
	if hi.ServerName != "directory.test" {
		t.Errorf("ClientHello ServerName = %q, want the configured host \"directory.test\"", hi.ServerName)
	}
	for _, v := range hi.SupportedVersions {
		if v < tls.VersionTLS12 {
			t.Errorf("client offered TLS version %#x below the pinned MinVersion", v)
		}
	}
}

// ── T3 / T4 downgrade arms ─────────────────────────────────────────────────

// TestConnectRefusesTLSBelow12 (T3): a server offering only TLS ≤ 1.1 is
// refused — MinVersion TLS 1.2 is pinned on the client.
func TestConnectRefusesTLSBelow12(t *testing.T) {
	ca := newTestCA(t, "ephemeral test ca")
	srv := startTestLDAPSServer(t, ca.issue(t, []string{"directory.test"}, nil,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)),
		func(cfg *tls.Config) { cfg.MaxVersion = tls.VersionTLS11 })

	c := &Connector{host: srv.addr}
	_, err := c.connect()
	if err == nil {
		t.Fatal("connect succeeded against a TLS 1.1-only server")
	}
}

// TestConnectRefusesPlaintextEndpoint (T4): pointing the LDAPS connector at a
// non-TLS endpoint is a connect error — no implicit downgrade, no fallback.
func TestConnectRefusesPlaintextEndpoint(t *testing.T) {
	addr := startPlaintextServer(t)
	c := &Connector{host: addr}
	_, err := c.connect()
	if err == nil {
		t.Fatal("connect succeeded against a plaintext endpoint")
	}
}

// ── Item 4 (authserver arm): registered-not-instantiated guard ─────────────

// authserverModuleRoot resolves the authserver module root, failing closed if
// the workspace layout moved (internal/connector/ad → authserver root).
func authserverModuleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine working directory: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("authserver module root not found at %s (layout changed?): %v", root, err)
	}
	return root
}

// TestGuard_AdConnectorNeverInstantiated pins CONNECTOR-001's dormancy
// premise: at HEAD the AD factory is REGISTERED on the connector manager but
// never Created — CachedGet("ad") stays nil and the password write-back
// no-ops. Any new Create(..., "ad", ...) call site fails this guard, so a
// wiring change cannot silently start instantiating the connector without
// re-running the TLS matrix review. (Mirrors the C1 ownership-guard pattern:
// AST-level scan of non-test authserver sources.)
func TestGuard_AdConnectorNeverInstantiated(t *testing.T) {
	root := authserverModuleRoot(t)
	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".") {
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, rel+": source does not parse — guard fails closed: "+err.Error())
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Create" {
				return true
			}
			// The connector type is a string argument of the call — the ctx
			// argument sits before it, so scan every argument position.
			for _, arg := range call.Args {
				lit, ok := arg.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if strings.Trim(lit.Value, "`\"") == "ad" {
					violations = append(violations, rel+": connector manager Create(..., \"ad\", ...) call site — "+
						"the AD connector is registered-but-never-instantiated by contract; CachedGet(\"ad\") must stay nil "+
						"until an instantiation is reviewed with the CONNECTOR-001 TLS matrix holding")
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("source scan failed: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// TestGuard_MainWarmsOnlyLocalConnector pins the startup wiring: the ONLY
// string-typed Create call in cmd/authserverd/main.go warms "local".
func TestGuard_MainWarmsOnlyLocalConnector(t *testing.T) {
	mainGo := filepath.Join(authserverModuleRoot(t), "cmd", "authserverd", "main.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGo, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	var warmed []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Create" {
			return true
		}
		// The connector type is a string argument of the call — the ctx
		// argument sits before it, so scan every argument position. A Create
		// with no string-literal type (dynamic wiring) records "" so this
		// guard fails and the wiring gets reviewed, not waved through.
		typ := ""
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING {
				typ = strings.Trim(lit.Value, "`\"")
				break
			}
		}
		warmed = append(warmed, typ)
		return true
	})
	if len(warmed) != 1 || warmed[0] != "local" {
		t.Errorf("main.go Create warm-ups = %v, want exactly [local] — the AD connector must stay unwarmed", warmed)
	}
}

// TestGuard_CachedGetAdNilUntilInstantiated pins the manager seam the write-back
// depends on: registering a factory never instantiates anything, so
// CachedGet("ad") is nil (the write-back no-ops) until a real Create ran.
func TestGuard_CachedGetAdNilUntilInstantiated(t *testing.T) {
	m := connector.NewManager()
	m.Register("ad", Factory)
	if got := m.CachedGet("ad"); got != nil {
		t.Fatalf("CachedGet(\"ad\") = %v before any Create, want nil", got)
	}
	if _, err := m.Create(context.Background(), "ad", 1,
		map[string]interface{}{"host": "directory.test", "bind_dn": "cn=svc,dc=test"}, nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got := m.CachedGet("ad"); got == nil {
		t.Fatal("CachedGet(\"ad\") = nil after Create — the nil-before-instantiation contract is not what this test measured")
	}
}
