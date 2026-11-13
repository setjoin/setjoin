package smime

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// generateTestECDSACert builds a self-signed certificate with an ECDSA public
// key — the receive/recipient shape the encrypt path must reject (RSA-only
// KeyTransRecipientInfo).
func generateTestECDSACert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ecdsa-recipient@example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestEncryptWithAlgorithm_UnknownAlgorithmRejected(t *testing.T) {
	cert, _ := generateTestCert(t)
	if _, err := EncryptWithAlgorithm("aes-128-quantum", []byte("hi"), []*x509.Certificate{cert}); err == nil {
		t.Fatal("unknown algorithm accepted, want error")
	}
}

func TestEncryptWithAlgorithm_RequiresRecipientCertificate(t *testing.T) {
	for _, alg := range []EncryptAlgorithm{AlgorithmAES256GCM, AlgorithmAES256CBC} {
		if _, err := EncryptWithAlgorithm(alg, []byte("hi"), nil); err == nil {
			t.Errorf("%s: encrypting without recipients accepted, want error", alg)
		}
	}
}

func TestEncryptWithAlgorithm_NonRSARecipientRejected(t *testing.T) {
	ecCert := generateTestECDSACert(t)
	for _, alg := range []EncryptAlgorithm{AlgorithmAES256GCM, AlgorithmAES256CBC} {
		if _, err := EncryptWithAlgorithm(alg, []byte("hi"), []*x509.Certificate{ecCert}); err == nil {
			t.Errorf("%s: ECDSA recipient accepted, want RSA-only error", alg)
		}
	}
}

func TestBuildRecipientInfos_NonRSAPublicKeyRejected(t *testing.T) {
	ecCert := generateTestECDSACert(t)
	if _, err := buildRecipientInfos(make([]byte, aesSessionKeyLen), []*x509.Certificate{ecCert}); err == nil {
		t.Fatal("buildRecipientInfos accepted a non-RSA recipient, want error")
	}
}

var _ = crypto.SHA256 // keep crypto imported for the ecdsa helper

// --- parseEnvelopedAny / authDecryptBody fail-closed arms ---

// mustContentInfoDER marshals a CMS ContentInfo with the given content type
// and raw inner content.
func mustContentInfoDER(t *testing.T, contentType asn1.ObjectIdentifier, inner []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(cmsContentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseEnvelopedAny_MalformedAuthEnvelopedData(t *testing.T) {
	der := mustContentInfoDER(t, oidAuthEnvelopedData, []byte{0xFF, 0x00, 0x02})
	if _, err := parseEnvelopedAny(der); err == nil {
		t.Fatal("malformed AuthEnvelopedData accepted, want parse error")
	}
}

func TestParseEnvelopedAny_MalformedEnvelopedData(t *testing.T) {
	der := mustContentInfoDER(t, oidData, []byte{0xFF, 0x00, 0x02})
	if _, err := parseEnvelopedAny(der); err == nil {
		t.Fatal("malformed EnvelopedData accepted, want parse error")
	}
}

func TestAuthDecryptBody_GCMParameterArms(t *testing.T) {
	validMAC := make([]byte, gcmICVLen)

	// Parameters carried in the RawValue.Bytes fallback slot (no FullBytes).
	fallbackParams, err := asn1.Marshal(cmsGCMParameters{Nonce: make([]byte, gcmNonceLen), ICVLen: gcmICVLen})
	if err != nil {
		t.Fatal(err)
	}
	aedFallback := cmsAuthEnvelopedData{
		AuthEncryptedContentInfo: cmsEncryptedContentInfo{
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Parameters: asn1.RawValue{Bytes: fallbackParams},
			},
		},
		MAC: validMAC,
	}
	// The zero key fails GCM authentication — which proves the fallback slot
	// was honored: parameters parsed, nonce length accepted, and the failure
	// happens at the AEAD open, not at a parameter arm.
	if _, err := authDecryptBody(aedFallback, make([]byte, aesSessionKeyLen)); err == nil {
		t.Error("zero session key unexpectedly authenticated")
	}

	// Unparseable GCM parameters.
	aedBadParams := cmsAuthEnvelopedData{
		AuthEncryptedContentInfo: cmsEncryptedContentInfo{
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Parameters: asn1.RawValue{FullBytes: []byte{0xFF, 0x00}},
			},
		},
		MAC: validMAC,
	}
	if _, err := authDecryptBody(aedBadParams, make([]byte, aesSessionKeyLen)); err == nil {
		t.Error("unparseable GCM parameters accepted, want error")
	}

	// Wrong nonce length.
	badNonce, err := asn1.Marshal(cmsGCMParameters{Nonce: make([]byte, 4), ICVLen: gcmICVLen})
	if err != nil {
		t.Fatal(err)
	}
	aedNonce := cmsAuthEnvelopedData{
		AuthEncryptedContentInfo: cmsEncryptedContentInfo{
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Parameters: asn1.RawValue{FullBytes: badNonce},
			},
		},
		MAC: validMAC,
	}
	if _, err := authDecryptBody(aedNonce, make([]byte, aesSessionKeyLen)); err == nil {
		t.Error("short GCM nonce accepted, want error")
	}

	// ICV outside 12..16.
	shortMAC, _ := asn1.Marshal(cmsGCMParameters{Nonce: make([]byte, gcmNonceLen), ICVLen: gcmICVLen})
	aedTag := cmsAuthEnvelopedData{
		AuthEncryptedContentInfo: cmsEncryptedContentInfo{
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Parameters: asn1.RawValue{FullBytes: shortMAC},
			},
		},
		MAC: make([]byte, 4),
	}
	if _, err := authDecryptBody(aedTag, make([]byte, aesSessionKeyLen)); err == nil {
		t.Error("short GCM ICV accepted, want error")
	}

	// Non-AES key length is rejected by the cipher constructor.
	if _, err := authDecryptBody(aedFallback, []byte{0x01, 0x02}); err == nil {
		t.Error("short session key accepted, want cipher error")
	}
}

func TestAuthAttrsAAD_TagRewrite(t *testing.T) {
	// Present attrs must be re-tagged from IMPLICIT [1] (0xA1) to SET OF (0x31).
	attrs := asn1.RawValue{FullBytes: []byte{0xA1, 0x02, 0x01, 0x00}}
	aad, err := authAttrsAAD(attrs)
	if err != nil {
		t.Fatalf("authAttrsAAD: %v", err)
	}
	if aad[0] != 0x31 || len(aad) != len(attrs.FullBytes) {
		t.Errorf("aad = % x, want the same TLV with a 0x31 tag", aad)
	}

	// Any other leading tag is an asn1 misconfiguration: fail closed.
	if _, err := authAttrsAAD(asn1.RawValue{FullBytes: []byte{0x31, 0x00}}); err == nil {
		t.Error("wrong authAttrs tag accepted, want error")
	}
}
