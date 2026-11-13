package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// genCertKeySerial builds a self-signed RSA cert with the given serial so that
// distinct candidates are distinguishable by RecipientInfo.IssuerAndSerialNumber.
// (generateTestCert hard-codes serial 1, so A/B/C built with it would collide.)
func genCertKeySerial(t *testing.T, serial int64) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(serial),
		Subject:        pkix.Name{CommonName: "k" + string(rune('0'+serial)) + "@example.com"},
		NotBefore:      time.Now().Add(-time.Minute),
		NotAfter:       time.Now().Add(time.Hour),
		EmailAddresses: []string{"k@example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// encryptToDER encrypts plaintext to certs and returns the bare DER ContentInfo
// (strips Encrypt's MIME wrapper + base64), the shape DecryptMulti consumes.
func encryptToDER(t *testing.T, plaintext []byte, certs ...*x509.Certificate) []byte {
	t.Helper()
	enc, err := Encrypt(plaintext, certs)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b64 := string(enc[strings.Index(string(enc), "\r\n\r\n")+4:])
	der, err := base64Decode(stripCR(b64))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	return der
}

// envelopeView is a content-type-agnostic mutable view over Encrypt's DER
// output — since A5 the default is AuthEnvelopedData (GCM) with EnvelopedData
// (CBC) as the explicit fallback, and the padding-oracle probes must mutate the
// same fields (a RecipientInfo's EncryptedKey, the encrypted body) in either.
// recipientInfos and body alias the decoded struct's backing data, so in-place
// edits (zeroing key bytes) need no setter; body is a pointer for replacement.
type envelopeView struct {
	contentType    asn1.ObjectIdentifier
	recipientInfos []cmsRecipientInfo
	body           *[]byte
	mac            *[]byte // AuthEnvelopedData only (nil for EnvelopedData)
	auth           any     // *cmsAuthEnvelopedData or *cmsEnvelopedData, for encode
}

func parseEnvelopeAny(t *testing.T, der []byte) envelopeView {
	t.Helper()
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatalf("parse ContentInfo: %v", err)
	}
	if ci.ContentType.Equal(oidAuthEnvelopedData) {
		var aed cmsAuthEnvelopedData
		if _, err := asn1.Unmarshal(ci.Content.Bytes, &aed); err != nil {
			t.Fatalf("parse AuthEnvelopedData: %v", err)
		}
		return envelopeView{
			contentType:    ci.ContentType,
			recipientInfos: aed.RecipientInfos,
			body:           &aed.AuthEncryptedContentInfo.EncryptedContent,
			mac:            &aed.MAC,
			auth:           &aed,
		}
	}
	var env cmsEnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &env); err != nil {
		t.Fatalf("parse EnvelopedData: %v", err)
	}
	return envelopeView{
		contentType:    ci.ContentType,
		recipientInfos: env.RecipientInfos,
		body:           &env.EncryptedContentInfo.EncryptedContent,
		auth:           &env,
	}
}

// encode re-marshals the view preserving the original outer content type
// (mirroring Encrypt's ContentInfo wrapping for either variant).
func (v envelopeView) encode(t *testing.T) []byte {
	t.Helper()
	var envBytes []byte
	var err error
	switch body := v.auth.(type) {
	case *cmsAuthEnvelopedData:
		envBytes, err = asn1.Marshal(*body)
	case *cmsEnvelopedData:
		envBytes, err = asn1.Marshal(*body)
	default:
		t.Fatalf("unknown envelope body type %T", v.auth)
	}
	if err != nil {
		t.Fatalf("marshal envelope body: %v", err)
	}
	der, err := asn1.Marshal(cmsContentInfo{
		ContentType: v.contentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: envBytes, IsCompound: true},
	})
	if err != nil {
		t.Fatalf("marshal ContentInfo: %v", err)
	}
	return der
}

// TestDecryptMulti_NoPaddingOracle is the Bleichenbacher regression guard: a
// chosen ciphertext with INVALID PKCS#1 v1.5 padding and one with VALID padding
// (real session key recovered) but an otherwise-failing unwrap MUST yield the
// SAME observable outcome — ErrNoMatchingKey — so no padding-validity signal
// leaks to the caller (jmap maps ErrNoMatchingKey → "wrong_key", anything else →
// "error"; pre-fix the valid-padding probe returned a non-ErrNoMatchingKey error,
// i.e. the oracle). Runs against BOTH outbound content types: the A5 default
// AuthEnvelopedData (GCM) and the CBC fallback.
func TestDecryptMulti_NoPaddingOracle(t *testing.T) {
	for _, alg := range []EncryptAlgorithm{AlgorithmAES256GCM, AlgorithmAES256CBC} {
		t.Run(string(alg), func(t *testing.T) {
			restore := setEncryptAlgorithmForTest(t, alg)
			defer restore()

			victimCert, victimKey := genCertKeySerial(t, 11)
			keys := []DecryptKey{{Cert: victimCert, Key: victimKey}}

			plaintext := []byte("oracle target body\r\n")
			good := encryptToDER(t, plaintext, victimCert)

			// Faithful-round-trip sanity: an unmodified re-marshal still decrypts, so any
			// difference below is the mutation, not encode.
			if pt, err := DecryptMulti(parseEnvelopeAny(t, good).encode(t), keys); err != nil || string(pt) != string(plaintext) {
				t.Fatalf("re-marshal round-trip broke decrypt: pt=%q err=%v", pt, err)
			}

			// Both probes share a body that cannot decrypt (4 bytes — not a CBC
			// block multiple, and shorter than any GCM ciphertext+tag), so the ONLY
			// variable is RSA padding validity of the RecipientInfo.
			probe := func(mutate func(*envelopeView)) error {
				view := parseEnvelopeAny(t, good)
				*view.body = []byte{0xde, 0xad, 0xbe, 0xef}
				mutate(&view)
				_, err := DecryptMulti(view.encode(t), keys)
				return err
			}

			// (A) INVALID padding: a zeroed EncryptedKey unwraps to a non-conforming block,
			// so DecryptPKCS1v15SessionKey keeps the random fallback (no error).
			errInvalidPad := probe(func(v *envelopeView) {
				for i := range v.recipientInfos[0].EncryptedKey {
					v.recipientInfos[0].EncryptedKey[i] = 0
				}
			})
			// (B) VALID padding: RecipientInfo untouched, the real session key is recovered
			// — yet the body still fails. The two MUST be indistinguishable.
			errValidPad := probe(func(*envelopeView) {})

			// (C) a genuine non-match (encrypted to a serial we don't hold).
			otherCert, _ := genCertKeySerial(t, 99)
			_, errNoMatch := DecryptMulti(encryptToDER(t, plaintext, otherCert), keys)

			for name, err := range map[string]error{
				"invalid-padding":          errInvalidPad,
				"valid-padding-bad-unwrap": errValidPad,
				"no-matching-serial":       errNoMatch,
			} {
				if !errors.Is(err, ErrNoMatchingKey) {
					t.Errorf("%s: got %v, want ErrNoMatchingKey (states must be indistinguishable)", name, err)
				}
			}
		})
	}
}

func TestDecryptMulti_PicksMatchingKeyAmongMany(t *testing.T) {
	certA, keyA := genCertKeySerial(t, 11)
	certB, keyB := genCertKeySerial(t, 22)
	certC, keyC := genCertKeySerial(t, 33)

	plaintext := []byte("rollover secret\r\nline two\r\n")
	der := encryptToDER(t, plaintext, certB) // encrypted ONLY to B

	got, err := DecryptMulti(der, []DecryptKey{
		{Cert: certA, Key: keyA},
		{Cert: certB, Key: keyB},
		{Cert: certC, Key: keyC},
	})
	if err != nil {
		t.Fatalf("DecryptMulti: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decryption mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptMulti_NoMatchReturnsErrNoMatchingKey(t *testing.T) {
	certA, _ := genCertKeySerial(t, 11)
	certB, keyB := genCertKeySerial(t, 22)
	certC, keyC := genCertKeySerial(t, 33)

	der := encryptToDER(t, []byte("for A only\r\n"), certA) // only A

	_, err := DecryptMulti(der, []DecryptKey{
		{Cert: certB, Key: keyB},
		{Cert: certC, Key: keyC},
	})
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("want ErrNoMatchingKey, got %v", err)
	}
}

func TestDecryptMulti_EmptyKeysIsErr(t *testing.T) {
	certA, _ := genCertKeySerial(t, 11)
	der := encryptToDER(t, []byte("body\r\n"), certA)

	if _, err := DecryptMulti(der, nil); err == nil {
		t.Fatal("DecryptMulti(der, nil) must return an error")
	}
}

func TestDecryptMulti_ParseErrorDistinctFromNoMatch(t *testing.T) {
	certA, keyA := genCertKeySerial(t, 11)
	// Garbage DER → a parse error, NOT ErrNoMatchingKey.
	_, err := DecryptMulti([]byte{0x01, 0x02, 0x03, 0x04}, []DecryptKey{{Cert: certA, Key: keyA}})
	if err == nil {
		t.Fatal("malformed CMS must error")
	}
	if errors.Is(err, ErrNoMatchingKey) {
		t.Fatal("a parse error must be distinct from ErrNoMatchingKey")
	}
}

// TestDecrypt_StillWorks is the regression guard: the single-key Decrypt path is
// unchanged after extracting decryptBody.
func TestDecrypt_StillWorks(t *testing.T) {
	cert, key := generateTestCert(t)
	plaintext := []byte("single-key round-trip still works\r\n")
	der := encryptToDER(t, plaintext, cert)

	got, err := Decrypt(der, cert, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("mismatch: got %q, want %q", got, plaintext)
	}
}

// TestDecodeEnvelopedDER covers the helper jmap decrypt-on-read uses to turn the
// stored EnvelopedData MIME artifact (Encrypt's own output shape) into bare DER.
func TestDecodeEnvelopedDER(t *testing.T) {
	cert, key := generateTestCert(t)
	plaintext := []byte("decode helper body\r\n")
	wire, err := Encrypt(plaintext, []*x509.Certificate{cert}) // full MIME+base64 artifact
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	der, err := DecodeEnvelopedDER(wire)
	if err != nil {
		t.Fatalf("DecodeEnvelopedDER: %v", err)
	}
	got, err := DecryptMulti(der, []DecryptKey{{Cert: cert, Key: key}})
	if err != nil {
		t.Fatalf("DecryptMulti after DecodeEnvelopedDER: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("mismatch: got %q, want %q", got, plaintext)
	}
}

// TestDecodeEnvelopedDER_RawDERPassthrough: a bare DER (no MIME headers, no
// base64) is returned as-is — openssl `cms -encrypt -outform DER` emits this.
func TestDecodeEnvelopedDER_RawDERPassthrough(t *testing.T) {
	cert, key := generateTestCert(t)
	plaintext := []byte("raw der passthrough\r\n")
	der := encryptToDER(t, plaintext, cert) // already bare DER

	out, err := DecodeEnvelopedDER(der)
	if err != nil {
		t.Fatalf("DecodeEnvelopedDER(rawDER): %v", err)
	}
	got, err := DecryptMulti(out, []DecryptKey{{Cert: cert, Key: key}})
	if err != nil {
		t.Fatalf("DecryptMulti: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("mismatch: got %q, want %q", got, plaintext)
	}
}
