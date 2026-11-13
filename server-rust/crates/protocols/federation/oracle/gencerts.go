//go:build ignore

// gencerts writes the fixed fixture identities the listener oracle uses:
// per-domain CAs with no cross-signing, plus deliberately broken leaves.
// Usage: go run gencerts.go <out-dir>. Fixture keys protect nothing.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type ca struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func genKey(kind string) (crypto.Signer, crypto.PublicKey) {
	switch kind {
	case "ed25519":
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		return priv, pub
	case "p256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, &k.PublicKey
	case "rsa":
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		return k, &k.PublicKey
	}
	panic(kind)
}

func writePEM(path, typ string, der []byte) {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
		panic(err)
	}
}

func newCA(dir, name, kind string) ca {
	key, pub := genKey(kind)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name + "-CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().AddDate(100, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		panic(err)
	}
	writePEM(filepath.Join(dir, "ca-"+name+".crt"), "CERTIFICATE", der)
	c, _ := x509.ParseCertificate(der)
	return ca{cert: c, key: key}
}

func leaf(dir, file string, issuer ca, san, kind string, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time) {
	key, pub := genKey(kind)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: san},
		DNSNames:     []string{san},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, pub, issuer.key)
	if err != nil {
		panic(err)
	}
	writePEM(filepath.Join(dir, file+".crt"), "CERTIFICATE", der)
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	writePEM(filepath.Join(dir, file+".key"), "PRIVATE KEY", kd)
}

func main() {
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	now := time.Now()
	nb, na := now.Add(-24*time.Hour), now.AddDate(100, 0, 0)
	// Algorithms and EKU shapes vary on purpose: alpha ed25519/no EKU, bravo
	// P-256/server+client, charlie RSA/emailProtection only (Go accepts any EKU).
	zulu := newCA(dir, "zulu", "ed25519")
	alpha := newCA(dir, "alpha", "ed25519")
	bravo := newCA(dir, "bravo", "p256")
	charlie := newCA(dir, "charlie", "rsa")
	leaf(dir, "zulu", zulu, "zulu.test", "ed25519", nil, nb, na)
	leaf(dir, "alpha", alpha, "alpha.test", "ed25519", nil, nb, na)
	leaf(dir, "bravo", bravo, "bravo.test", "p256", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nb, na)
	leaf(dir, "charlie", charlie, "charlie.test", "rsa", []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, nb, na)
	// alpha.test's SAN under bravo's CA: the impostor.
	leaf(dir, "impostor", bravo, "alpha.test", "ed25519", nil, nb, na)
	leaf(dir, "expired", alpha, "alpha.test", "ed25519", nil, now.AddDate(-3, 0, 0), now.AddDate(-2, 0, 0))
	leaf(dir, "wrongsan", alpha, "other.test", "ed25519", nil, nb, na)
	leaf(dir, "notyet", alpha, "alpha.test", "ed25519", nil, now.AddDate(1, 0, 0), now.AddDate(2, 0, 0))
	// A domain no allow-list row exists for, with a valid cert of its own.
	unknown := newCA(dir, "unknown", "ed25519")
	leaf(dir, "unknown", unknown, "unknown.test", "ed25519", nil, nb, na)
	fmt.Println("wrote", dir)
}
