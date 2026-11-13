package smime

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

// EncryptAlgorithm names the content-encryption algorithm Encrypt uses for a
// message body (owner decision A5 — S/MIME 4.0 / RFC 8551):
//
//   - AlgorithmAES256GCM ("aes-256-gcm", the DEFAULT) encrypts the content with
//     AES-256-GCM and wraps it as CMS AuthEnvelopedData (RFC 5083) — the
//     authenticated-encryption content type GCM requires (the authentication
//     tag rides in the AuthEnvelopedData `mac` field, which plain EnvelopedData
//     cannot carry).
//   - AlgorithmAES256CBC ("aes-256-cbc") is the S/MIME 3.2 fallback: AES-256-CBC
//     inside plain RFC 5652 EnvelopedData, byte-compatible with pre-A5 senders.
type EncryptAlgorithm string

const (
	AlgorithmAES256GCM EncryptAlgorithm = "aes-256-gcm"
	AlgorithmAES256CBC EncryptAlgorithm = "aes-256-cbc"
)

// gcmICVLen is the AES-GCM authentication-tag (ICV) length we EMIT, in octets.
// RFC 5084 gives GCMParameters aes-ICVlen a DEFAULT of 12, so a 16-octet (full
// 128-bit) tag MUST be declared explicitly in the parameters — we do, matching
// what openssl emits for `cms -encrypt -aes-256-gcm`.
const gcmICVLen = 16

// gcmNonceLen is the AES-GCM nonce length we emit and accept. RFC 5084
// recommends 12 octets; openssl and every mainstream CMS implementation use 12.
const gcmNonceLen = 12

// defaultEncryptAlgorithm holds the process-wide outbound algorithm. GCM is the
// owner-decision default; cmd/mailserverd overrides it at startup (and on
// config reload) from the smime.encrypt_algorithm config key for deployments
// that need the CBC fallback. The atomic keeps Encrypt race-free for concurrent
// submissions.
var defaultEncryptAlgorithm atomic.Value // stores EncryptAlgorithm

func init() {
	defaultEncryptAlgorithm.Store(AlgorithmAES256GCM)
}

// DefaultEncryptAlgorithm returns the algorithm Encrypt will use when no
// explicit algorithm is passed. Always a validated EncryptAlgorithm (the setter
// rejects unknown values), defaulting to AlgorithmAES256GCM.
func DefaultEncryptAlgorithm() EncryptAlgorithm {
	if a, ok := defaultEncryptAlgorithm.Load().(EncryptAlgorithm); ok {
		return a
	}
	return AlgorithmAES256GCM
}

// SetDefaultEncryptAlgorithm installs the process-wide outbound algorithm used
// by Encrypt. Empty selects the GCM default; an unknown value is rejected
// WITHOUT changing the previous setting so a bad config key can never silently
// downgrade (or break) outbound encryption.
func SetDefaultEncryptAlgorithm(alg EncryptAlgorithm) error {
	switch alg {
	case "":
		defaultEncryptAlgorithm.Store(AlgorithmAES256GCM)
		return nil
	case AlgorithmAES256GCM, AlgorithmAES256CBC:
		defaultEncryptAlgorithm.Store(alg)
		return nil
	default:
		return fmt.Errorf("smime: unknown encrypt algorithm %q (want %q or %q)",
			alg, AlgorithmAES256GCM, AlgorithmAES256CBC)
	}
}

// Encrypt creates a CMS message for the given plaintext and recipient
// certificates using the configured default algorithm (AES-256-GCM
// AuthEnvelopedData since owner decision A5 — see DefaultEncryptAlgorithm).
// Returns the raw mime body (application/pkcs7-mime, base64-encoded DER).
func Encrypt(plaintext []byte, certs []*x509.Certificate) ([]byte, error) {
	return EncryptWithAlgorithm(DefaultEncryptAlgorithm(), plaintext, certs)
}

// EncryptWithAlgorithm is Encrypt with the content-encryption algorithm chosen
// explicitly: AlgorithmAES256GCM produces RFC 5083 AuthEnvelopedData,
// AlgorithmAES256CBC produces legacy RFC 5652/3565 EnvelopedData.
func EncryptWithAlgorithm(alg EncryptAlgorithm, plaintext []byte, certs []*x509.Certificate) ([]byte, error) {
	switch alg {
	case AlgorithmAES256GCM:
		return encryptAuthEnvelopedGCM(plaintext, certs)
	case AlgorithmAES256CBC:
		return encryptEnvelopedCBC(plaintext, certs)
	default:
		return nil, fmt.Errorf("smime: unknown encrypt algorithm %q (want %q or %q)",
			alg, AlgorithmAES256GCM, AlgorithmAES256CBC)
	}
}

// encryptAuthEnvelopedGCM builds CMS AuthEnvelopedData (RFC 5083) with
// AES-256-GCM content encryption (RFC 5084):
//
//   - the content-encryption key is a fresh random AES-256 key per message,
//     RSA-wrapped (KeyTransRecipientInfo, identical to the EnvelopedData path);
//   - GCM runs with a random 12-octet nonce and a 16-octet tag; per RFC 5083
//     §2.2 the ciphertext goes in authEncryptedContentInfo.encryptedContent and
//     the tag goes in the SEPARATE mac field (NOT appended to the ciphertext —
//     that RFC 5084 tag-appended form is for the standalone content types);
//   - no authAttrs (legal because the inner content type is id-data), so the
//     AAD input is empty (RFC 5083 §2.2 "zero bits");
//   - GCMParameters carries the nonce and the explicit aes-ICVlen=16 (16 is not
//     the RFC 5084 DEFAULT of 12, so it must not be omitted).
//
// Verified against the openssl 3.6.4 `cms -encrypt -aes-256-gcm` oracle: the
// DER field-for-field shape matches (version 0, RSA RecipientInfos, aes-256-gcm
// + GCMParameters{nonce, 16}, [0] primitive ciphertext, 16-byte mac).
func encryptAuthEnvelopedGCM(plaintext []byte, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("smime: at least one recipient certificate required")
	}

	sessionKey, err := randomSessionKey()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcmNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil) // ciphertext || 16-byte tag
	if len(sealed) < gcmICVLen {
		return nil, errors.New("smime: gcm sealed output shorter than tag")
	}
	//nolint:gosec // G115: len(sealed) >= gcmICVLen (16) so the difference is non-negative
	ciphertext, tag := sealed[:len(sealed)-gcmICVLen], sealed[len(sealed)-gcmICVLen:]

	recipientInfos, err := buildRecipientInfos(sessionKey, certs)
	if err != nil {
		return nil, err
	}

	paramsDER, err := asn1.Marshal(cmsGCMParameters{Nonce: nonce, ICVLen: gcmICVLen})
	if err != nil {
		return nil, err
	}

	authEnvelopedData := cmsAuthEnvelopedData{
		Version:        0,
		RecipientInfos: recipientInfos,
		AuthEncryptedContentInfo: cmsEncryptedContentInfo{
			ContentType: oidData,
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Algorithm:  oidAES256GCM,
				Parameters: asn1.RawValue{FullBytes: paramsDER},
			},
			EncryptedContent: ciphertext,
		},
		MAC: tag,
	}

	envBytes, err := asn1.Marshal(authEnvelopedData)
	if err != nil {
		return nil, err
	}

	contentInfo := cmsContentInfo{
		ContentType: oidAuthEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: envBytes, IsCompound: true},
	}

	der, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, err
	}

	return wrapPKCS7MIME("authEnveloped-data", der), nil
}

// encryptEnvelopedCBC is the S/MIME 3.2 fallback: AES-256-CBC inside plain
// RFC 5652/3565 EnvelopedData — byte-compatible with pre-A5 output (the
// smime-type=enveloped-data wire form external MUAs already decrypt).
func encryptEnvelopedCBC(plaintext []byte, certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("smime: at least one recipient certificate required")
	}

	// Generate random 256-bit AES session key
	sessionKey, err := randomSessionKey()
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt content with AES-256-CBC
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	recipientInfos, err := buildRecipientInfos(sessionKey, certs)
	if err != nil {
		return nil, err
	}

	// RFC 3565 §4.1: for AES-CBC the IV is carried in the contentEncryptionAlgorithm
	// PARAMETERS as a DER OCTET STRING — NOT prepended to the encrypted content.
	// Prepending the IV (the old behaviour) made openssl read a zero IV from the
	// (absent) parameters and decrypt our IV block as ciphertext → 16 garbage
	// bytes ahead of the real plaintext.
	ivOctetString, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	envelopedData := cmsEnvelopedData{
		Version:        0,
		RecipientInfos: recipientInfos,
		EncryptedContentInfo: cmsEncryptedContentInfo{
			ContentType: oidData,
			ContentEncryptionAlgorithm: algorithmIdentifier{
				Algorithm:  oidAES256CBC,
				Parameters: asn1.RawValue{FullBytes: ivOctetString},
			},
			EncryptedContent: ciphertext,
		},
	}

	envBytes, err := asn1.Marshal(envelopedData)
	if err != nil {
		return nil, err
	}

	contentInfo := cmsContentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: envBytes, IsCompound: true},
	}

	der, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, err
	}

	return wrapPKCS7MIME("enveloped-data", der), nil
}

// randomSessionKey generates the 256-bit content-encryption key. The fixed
// length is also load-bearing for receive: it is the length of the random
// fallback buffer the Bleichenbacher countermeasure in Decrypt/DecryptMulti
// hands to rsa.DecryptPKCS1v15SessionKey (see aesSessionKeyLen).
func randomSessionKey() ([]byte, error) {
	sessionKey := make([]byte, aesSessionKeyLen)
	if _, err := io.ReadFull(rand.Reader, sessionKey); err != nil {
		return nil, err
	}
	return sessionKey, nil
}

// buildRecipientInfos RSA-wraps the content-encryption key for each recipient
// certificate (RFC 5652 KeyTransRecipientInfo, version 0). Shared by the GCM
// and CBC builders — both content types use the identical RecipientInfos SET.
func buildRecipientInfos(sessionKey []byte, certs []*x509.Certificate) ([]cmsRecipientInfo, error) {
	var recipientInfos []cmsRecipientInfo
	for _, cert := range certs {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("smime: recipient certificate must have RSA public key")
		}
		encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("smime: failed to encrypt session key: %w", err)
		}
		recipientInfos = append(recipientInfos, cmsRecipientInfo{
			Version: 0,
			IssuerAndSerialNumber: cmsIssuerAndSerial{
				// Use FullBytes: cert.RawIssuer is complete DER (0x30 SEQUENCE).
				// {Class:0, Bytes:x} would add a spurious UNIVERSAL primitive tag-0 header.
				Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
				Serial: cert.SerialNumber,
			},
			KeyEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption},
			EncryptedKey:           encryptedKey,
		})
	}
	return recipientInfos, nil
}

// wrapPKCS7MIME frames a DER ContentInfo as the application/pkcs7-mime body
// Encrypt emits, with the smime-type discriminating enveloped-data (CBC) from
// authEnveloped-data (GCM).
func wrapPKCS7MIME(smimeType string, der []byte) []byte {
	return []byte(
		"Content-Type: application/pkcs7-mime; smime-type=" + smimeType + "; name=\"smime.p7m\"\r\n" +
			"Content-Transfer-Encoding: base64\r\n" +
			"\r\n" +
			base64Encode(der) + "\r\n",
	)
}
