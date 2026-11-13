package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// testLogger discards output — these tests assert on returned errors, not
// log lines.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// genCA/issueLeaf generate certs in-process — the R1 real-stranger shape of
// testharness/gen-certs.sh (one CA per domain, no cross-signing) without
// shelling out to openssl, so these tests run in any sandbox.

type genCA struct {
	cert *x509.Certificate
	priv ed25519.PrivateKey
}

func newCA(t *testing.T, cn string) genCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return genCA{cert: cert, priv: priv}
}

// issueLeaf issues a leaf certificate signed by ca, asserting sanDomain as
// its DNS SAN — deliberately allowed to diverge from ca's own CN, so tests
// can construct an "impostor" leaf (a domain's SAN forged under the WRONG
// CA).
func issueLeaf(t *testing.T, ca genCA, sanDomain string) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: sanDomain},
		DNSNames:     []string{sanDomain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.priv)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func onFlags() *toggle.FeatureFlags {
	return toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: true})
}

// TestDialRejectsWrongTrustAnchor is the real R1 test (dialer side): a
// server claiming to be alpha.test presents a leaf issued by bravo's CA
// (an impostor — bravo could sign anything it wants) instead of alpha's
// real CA. The dialer's allow-list row pins alpha's REAL CA as the anchor,
// so Dial must reject before any msg frame flows.
func TestDialRejectsWrongTrustAnchor(t *testing.T) {
	alphaCA := newCA(t, "alpha.test-CA")
	bravoCA := newCA(t, "bravo.test-CA")
	impostorLeaf := issueLeaf(t, bravoCA, "alpha.test") // signed by the WRONG CA

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsConn := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{impostorLeaf},
			ClientAuth:   tls.NoClientCert,
			MinVersion:   tls.VersionTLS13,
		})
		_ = tlsConn.Handshake() // expected to fail once the dialer's VerifyPeerCertificate rejects
	}()

	clientLeaf := issueLeaf(t, alphaCA, "dialer.test") // the dialer's own identity — irrelevant to this test
	endpoint := PeerEndpoint{Domain: "alpha.test", Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	anchor := Anchor{CACert: alphaCA.cert} // the dialer's allow-list row pins alpha's REAL CA

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, onFlags(), endpoint, clientLeaf, anchor, Hello{FromDomain: "dialer.test", Ver: 1})
	<-serverDone

	if !errors.Is(err, ErrPeerAnchorMismatch) {
		t.Fatalf("Dial error = %v, want ErrPeerAnchorMismatch", err)
	}
}

// TestListenRejectsWrongClientAnchor mirrors the above on the LISTEN side —
// the one place E1 can silently degrade into "any valid-looking cert gets a
// stream" if the Dial-side check alone were relied on. A dialer asserts
// hello.FromDomain="bravo.test" but its client certificate is signed by
// charlie's CA. The listener's allow-list row for bravo.test pins bravo's
// REAL CA, so AcceptStream must reject after the hello, before any other
// frame is processed.
func TestListenRejectsWrongClientAnchor(t *testing.T) {
	bravoCA := newCA(t, "bravo.test-CA")
	charlieCA := newCA(t, "charlie.test-CA")
	listenerLeaf := issueLeaf(t, bravoCA, "listener.test") // the listener's own identity — irrelevant to this test
	impostorClientLeaf := issueLeaf(t, charlieCA, "bravo.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	lookup := AnchorLookup(func(_ context.Context, domain string) (Anchor, bool, error) {
		if domain == "bravo.test" {
			return Anchor{CACert: bravoCA.cert}, true, nil // the REAL bravo anchor pinned on the listener's allow-list row
		}
		return Anchor{}, false, nil
	})

	serverTLSCfg := &tls.Config{Certificates: []tls.Certificate{listenerLeaf}}

	acceptErrCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			acceptErrCh <- err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Zero-value pool: the wrong-anchor rejection fires inside
		// verifyAgainstAnchor, BEFORE authorizePeer is ever reached — no DB
		// call happens on this path, so no real pool is needed here (the one
		// place E1's anchor check must win regardless of E4's authorize gate).
		_, err = AcceptStream(ctx, conn, serverTLSCfg, lookup, Hello{FromDomain: "listener.test", Ver: 1}, pgxutil.WorkerPool{}, "dm")
		acceptErrCh <- err
	}()

	clientTLSCfg := &tls.Config{
		Certificates:       []tls.Certificate{impostorClientLeaf},
		InsecureSkipVerify: true, // this test isn't exercising the DIALER's own anchor check — only proving the LISTEN side rejects the impostor client
	}
	conn, dialErr := tls.Dial("tcp", ln.Addr().String(), clientTLSCfg)
	if dialErr == nil {
		// RequireAnyClientCert accepts any client cert at the TLS layer — the
		// forged hello is what AcceptStream must catch, post-handshake.
		_ = WriteFrame(conn, Frame{Kind: KindHello, Payload: mustJSON(Hello{FromDomain: "bravo.test", Ver: 1})})
		conn.Close()
	}

	err = <-acceptErrCh
	if !errors.Is(err, ErrPeerAnchorMismatch) {
		t.Fatalf("AcceptStream error = %v, want ErrPeerAnchorMismatch", err)
	}
}

// TestHandshakeHappyPath proves the mirror-image positive case: two
// strangers with NO shared CA (alpha's own CA, bravo's own CA), each
// pinning the OTHER's real anchor on their respective allow-list row,
// complete a mutually cert-authenticated handshake and can exchange frames
// in both directions. Since federation_peer_authorize (Task 3/E4) now runs
// on bravo's Listen/AcceptStream side after the anchor check, this test is
// DB-backed (testsupport.OpenTestPool, skips without DB_DSN) and seeds a
// real enabled federation_allowlist row for alpha.test before dialing.
func TestHandshakeHappyPath(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx0 := context.Background()
	if _, err := pool.Exec(ctx0,
		`INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled)
		 VALUES ('alpha.test', 'stream_test.go fixture', 'dm', true)
		 ON CONFLICT (peer_domain) DO UPDATE SET scope='dm', enabled=true`); err != nil {
		t.Fatalf("seed federation_allowlist: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx0, `DELETE FROM federation_allowlist WHERE peer_domain = 'alpha.test'`) //nolint:errcheck
	})
	workerPool := pgxutil.WorkerPool{Pool: pool}

	alphaCA := newCA(t, "alpha.test-CA")
	bravoCA := newCA(t, "bravo.test-CA")
	alphaLeaf := issueLeaf(t, alphaCA, "alpha.test")
	bravoLeaf := issueLeaf(t, bravoCA, "bravo.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	lookup := AnchorLookup(func(_ context.Context, domain string) (Anchor, bool, error) {
		if domain == "alpha.test" {
			return Anchor{CACert: alphaCA.cert}, true, nil
		}
		return Anchor{}, false, nil
	})

	flags := onFlags()
	streamCh := make(chan *PeerStream, 1)
	errCh := make(chan error, 1)
	serverTLSCfg := &tls.Config{Certificates: []tls.Certificate{bravoLeaf}}

	go func() {
		err := Listen(context.Background(), flags, ln, serverTLSCfg, lookup, Hello{FromDomain: "bravo.test", Ver: 1}, workerPool, "dm", testLogger(), func(s *PeerStream) {
			streamCh <- s
		})
		if err != nil {
			errCh <- err
		}
	}()

	endpoint := PeerEndpoint{Domain: "bravo.test", Target: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	anchor := Anchor{CACert: bravoCA.cert}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientStream, err := Dial(ctx, flags, endpoint, alphaLeaf, anchor, Hello{FromDomain: "alpha.test", Ver: 1})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer clientStream.Close()

	if clientStream.Hello.FromDomain != "bravo.test" {
		t.Fatalf("client-side peer hello FromDomain = %q, want bravo.test", clientStream.Hello.FromDomain)
	}

	var serverStream *PeerStream
	select {
	case serverStream = <-streamCh:
	case err := <-errCh:
		t.Fatalf("Listen: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server-side stream")
	}
	defer serverStream.Close()

	if serverStream.Domain != "alpha.test" {
		t.Fatalf("server-side stream domain = %q, want alpha.test", serverStream.Domain)
	}

	// Prove frames actually flow, both directions, post-handshake.
	if err := clientStream.WriteFrame(Frame{Kind: KindMsg, StanzaID: "s1", Payload: mustJSON(map[string]string{"body": "hi"})}); err != nil {
		t.Fatalf("client WriteFrame: %v", err)
	}
	f, err := serverStream.ReadFrame()
	if err != nil {
		t.Fatalf("server ReadFrame: %v", err)
	}
	if f.Kind != KindMsg || f.StanzaID != "s1" {
		t.Fatalf("server received frame %+v, want kind=msg stanzaId=s1", f)
	}

	if err := serverStream.WriteFrame(Frame{Kind: KindAck, StanzaID: "s1"}); err != nil {
		t.Fatalf("server WriteFrame: %v", err)
	}
	ack, err := clientStream.ReadFrame()
	if err != nil {
		t.Fatalf("client ReadFrame: %v", err)
	}
	if ack.Kind != KindAck || ack.StanzaID != "s1" {
		t.Fatalf("client received frame %+v, want kind=ack stanzaId=s1", ack)
	}
}

// TestFederationDisabledNoops pins D11: with feature.federation OFF, Dial
// returns ErrFederationDisabled without ever touching the network — the
// gate this package's half of Task 2's "no-op when OFF" requirement
// depends on already existing and being exercised now, not left unverified
// until the sender lands.
func TestFederationDisabledNoops(t *testing.T) {
	flags := toggle.NewTestFlags(map[string]bool{toggle.FeatureFederation: false})
	_, err := Dial(context.Background(), flags, PeerEndpoint{Domain: "alpha.test", Target: "127.0.0.1", Port: 1}, tls.Certificate{}, Anchor{}, Hello{})
	if !errors.Is(err, ErrFederationDisabled) {
		t.Fatalf("Dial error = %v, want ErrFederationDisabled", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	err = Listen(context.Background(), flags, ln, &tls.Config{}, nil, Hello{}, pgxutil.WorkerPool{}, "dm", testLogger(), func(*PeerStream) {
		t.Fatal("onStream must never be called while feature.federation is OFF")
	})
	if !errors.Is(err, ErrFederationDisabled) {
		t.Fatalf("Listen error = %v, want ErrFederationDisabled", err)
	}
}
