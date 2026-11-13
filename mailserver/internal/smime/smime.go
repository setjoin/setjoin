package smime

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	encoding_base64 "encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// CMS OIDs
var (
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidContentType       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES256CBC         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES256GCM         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	oidAuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
)

// aesSessionKeyLen is the fixed AES-256-CBC content-encryption key length. It is
// also the length of the random fallback buffer the Bleichenbacher countermeasure
// in Decrypt/DecryptMulti hands to rsa.DecryptPKCS1v15SessionKey: a fixed length
// is required so a chosen-ciphertext probe can never learn the unwrap's outcome
// from the key length.
const aesSessionKeyLen = 32

// --- ASN.1 CMS structures ---

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContent     encapsulatedContentInfo
	Certificates     rawCertificates `asn1:"set,optional,tag:0"`
	CRLs             []asn1.RawValue `asn1:"set,optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

// rawCertificates holds X.509 certificates as raw ASN.1 values.
type rawCertificates []asn1.RawValue

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type encapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// cmsIssuerAndSerial is RFC 5652 IssuerAndSerialNumber.
// Issuer must be set with FullBytes (cert.RawIssuer is complete DER starting
// with 0x30 SEQUENCE) so encoding/asn1 embeds it verbatim.
type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// cmsSignerInfo mirrors RFC 5652 SignerInfo. For version=1 (the only variant we
// produce) the sid field is IssuerAndSerialNumber encoded directly as a SEQUENCE
// — no context tag wrapper. The old cmsSignerIdentifier indirection was wrong:
// it added a spurious [0] wrapper that openssl and other MUAs reject.
type cmsSignerInfo struct {
	Version            int
	Sid                cmsIssuerAndSerial
	DigestAlgorithm    algorithmIdentifier
	SignedAttributes   []cmsAttribute `asn1:"set,optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttributes []cmsAttribute `asn1:"set,optional,tag:1"`
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type cmsEnvelopedData struct {
	Version              int
	RecipientInfos       []cmsRecipientInfo `asn1:"set"`
	EncryptedContentInfo cmsEncryptedContentInfo
}

// cmsAuthEnvelopedData is RFC 5083 AuthEnvelopedData — the content type that
// carries authenticated-encryption algorithms (AES-GCM) whose authentication
// tag cannot ride in plain EnvelopedData. Field-for-field like EnvelopedData
// except: the tag goes in the dedicated mac OCTET STRING (NOT appended to the
// ciphertext) and the optional attrs are authAttrs [1] / unauthAttrs [2].
// RecipientInfos is IDENTICAL to the EnvelopedData variant, so the RSA
// session-key unwrap code is shared.
type cmsAuthEnvelopedData struct {
	Version                  int
	OriginatorInfo           asn1.RawValue      `asn1:"optional,tag:0"` // never emitted by us
	RecipientInfos           []cmsRecipientInfo `asn1:"set"`
	AuthEncryptedContentInfo cmsEncryptedContentInfo
	AuthAttrs                asn1.RawValue `asn1:"optional,tag:1"` // never emitted by us (id-data ⇒ optional)
	MAC                      []byte
	UnauthAttrs              asn1.RawValue `asn1:"optional,tag:2"` // never emitted by us
}

// cmsGCMParameters is RFC 5084 GCMParameters — the parameters of the AES-GCM
// content-encryption algorithm. aes-ICVlen DEFAULTs to 12 (so it is omitted
// when 12 and MUST be present when we emit the full 16-octet tag).
type cmsGCMParameters struct {
	Nonce  []byte
	ICVLen int `asn1:"optional,default:12"`
}

// cmsRecipientInfo is RFC 5652 KeyTransRecipientInfo (version 0 variant). The
// rid field is RecipientIdentifier, a CHOICE whose default alternative is
// issuerAndSerialNumber — an UNTAGGED SEQUENCE. The [0] context tag is the OTHER
// alternative (subjectKeyIdentifier), so tagging this field broke openssl: it
// expects a bare SEQUENCE for PKCS7_ISSUER_AND_SERIAL and got a [0] wrapper.
type cmsRecipientInfo struct {
	Version                int
	IssuerAndSerialNumber  cmsIssuerAndSerial
	KeyEncryptionAlgorithm algorithmIdentifier
	EncryptedKey           []byte
}

type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm algorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,implicit"`
}

// ParseCert parses a PEM-encoded X.509 certificate.
func ParseCert(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("smime: failed to decode PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKey parses a PEM-encoded private key (PKCS#1 RSA or PKCS#8).
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("smime: failed to decode PEM private key")
	}
	// Try PKCS#8 first (modern format)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	// Try PKCS#1 (legacy RSA)
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	// Try EC
	return x509.ParseECPrivateKey(block.Bytes)
}

// Verify checks a detached CMS SignedData signature over the given content.
// content is the raw data that was signed (the first part of multipart/signed).
// signatureDER is the DER-encoded PKCS#7 signature (the second part).
// Returns the signer's certificate, or an error if verification fails.
func Verify(content, signatureDER []byte) (*x509.Certificate, error) {
	var contentInfo cmsContentInfo
	if _, err := asn1.Unmarshal(signatureDER, &contentInfo); err != nil {
		return nil, fmt.Errorf("smime: failed to parse CMS wrapper: %w", err)
	}

	var signedData cmsSignedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, fmt.Errorf("smime: failed to parse SignedData: %w", err)
	}

	// Extract signer certificate. Each element c is a RawValue whose FullBytes
	// is the complete DER (0x30 SEQUENCE ... ) for the certificate — try FullBytes
	// first (correct for certs embedded via {FullBytes:cert.Raw}), then fall back
	// to c.Bytes for older messages embedded via the now-fixed {Class:0, Bytes:x}.
	if len(signedData.Certificates) == 0 {
		return nil, errors.New("smime: no certificate in SignedData")
	}
	var cert *x509.Certificate
	for _, c := range signedData.Certificates {
		if len(c.FullBytes) > 0 {
			cert, _ = x509.ParseCertificate(c.FullBytes)
		}
		if cert == nil {
			cert, _ = x509.ParseCertificate(c.Bytes)
		}
		if cert != nil {
			break
		}
	}
	if cert == nil {
		return nil, errors.New("smime: failed to parse signer certificate")
	}

	for _, si := range signedData.SignerInfos {
		// Get the hash algorithm
		if !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
			continue
		}
		// RFC 5652 §5.4: verify over DER SET encoding (tag 0x31), matching Sign().
		attrSetDER, err := marshalAttrsAsSET(si.SignedAttributes)
		if err != nil {
			return nil, err
		}

		// Verify signature over signed attributes SET
		hash := sha256.Sum256(attrSetDER)
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("smime: unsupported signer key type %T (only RSA supported)", cert.PublicKey)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], si.Signature); err != nil {
			return nil, fmt.Errorf("smime: signature verification failed: %w", err)
		}

		// Require a non-empty SignedAttributes set AND a messageDigest attribute
		// that binds the signature to the content. Without this check a SignedData
		// with signed attributes but no messageDigest would verify with the body
		// completely unbound (security defect).
		if len(si.SignedAttributes) == 0 {
			return nil, errors.New("smime: no signed attributes (content not bound)")
		}
		digestVerified := false
		for _, attr := range si.SignedAttributes {
			if attr.Type.Equal(oidMessageDigest) && len(attr.Values) > 0 {
				var digest []byte
				// With FullBytes encoding, attr.Values[0].FullBytes = DER OCTET STRING;
				// with the legacy Bytes encoding, attr.Values[0].Bytes = DER OCTET STRING.
				// Try FullBytes first, fall back to Bytes for backward compat.
				decodeFrom := attr.Values[0].FullBytes
				if len(decodeFrom) == 0 {
					decodeFrom = attr.Values[0].Bytes
				}
				if _, derr := asn1.Unmarshal(decodeFrom, &digest); derr != nil {
					return nil, fmt.Errorf("smime: bad messageDigest attribute: %w", derr)
				}
				contentHash := sha256.Sum256(content)
				if string(digest) != string(contentHash[:]) {
					return nil, errors.New("smime: message digest mismatch")
				}
				digestVerified = true
			}
		}
		if !digestVerified {
			return nil, errors.New("smime: missing messageDigest attribute (content not bound)")
		}
		return cert, nil
	}
	return nil, errors.New("smime: no signer info verified")
}

// Sign creates a detached CMS SignedData signature over content using the given
// certificate and private key. Returns a DER-encoded PKCS#7 signature.
func Sign(content []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		// Try to extract RSA key from interface
		return nil, errors.New("smime: only RSA private keys are supported for signing")
	}

	contentHash := sha256.Sum256(content)

	// Build issuer/serial with signed attributes
	signingTime, _ := asn1.Marshal(time.Now().UTC())
	msgDigest, _ := asn1.Marshal(contentHash[:])

	// Each attribute value is already complete DER (OID, UTCTime, OCTET STRING).
	// Use FullBytes so encoding/asn1 embeds them verbatim — {Bytes:x} would add
	// a spurious UNIVERSAL primitive tag-0 header that openssl rejects.
	signedAttrs := []cmsAttribute{
		{Type: oidContentType, Values: []asn1.RawValue{{FullBytes: mustMarshal(oidData)}}},
		{Type: oidSigningTime, Values: []asn1.RawValue{{FullBytes: signingTime}}},
		{Type: oidMessageDigest, Values: []asn1.RawValue{{FullBytes: msgDigest}}},
	}

	// RFC 5652 §5.4: sign over the DER encoding of the SignedAttributes SET
	// (tag 0x31). The SignedAttributes are stored in the CMS with [0] (tag 0xa0),
	// but the digest is over the SET encoding with tag replaced by 0x31.
	attrSetDER, err := marshalAttrsAsSET(signedAttrs)
	if err != nil {
		return nil, err
	}

	// Sign
	hash := sha256.Sum256(attrSetDER)
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("smime: signing failed: %w", err)
	}

	// cert.RawIssuer is complete DER (Name SEQUENCE, starting with 0x30).
	// Use FullBytes so encoding/asn1 embeds it verbatim — {Class:0, Bytes:x}
	// would add a spurious UNIVERSAL primitive tag-0 header that openssl rejects.
	signerInfo := cmsSignerInfo{
		Version: 1,
		Sid: cmsIssuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: cert.RawIssuer},
			Serial: cert.SerialNumber,
		},
		DigestAlgorithm: algorithmIdentifier{Algorithm: oidSHA256},
		SignedAttributes: func() []cmsAttribute {
			return signedAttrs
		}(),
		SignatureAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption},
		Signature:          signature,
	}

	signedData := cmsSignedData{
		Version:          1,
		DigestAlgorithms: []algorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContent: encapsulatedContentInfo{
			ContentType: oidData,
		},
		Certificates: rawCertificates{{FullBytes: cert.Raw}},
		SignerInfos:  []cmsSignerInfo{signerInfo},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, err
	}

	contentInfo := cmsContentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: signedDataBytes, IsCompound: true},
	}

	return asn1.Marshal(contentInfo)
}

// SignMessage produces a full S/MIME signed message (multipart/signed).
func SignMessage(rawBody []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	sig, err := Sign(rawBody, cert, key)
	if err != nil {
		return nil, err
	}

	sigHash := sha256.Sum256(sig)
	boundary := fmt.Sprintf("smime-sig-%x", sigHash[:8])
	var b strings.Builder
	// Replace the original Content-Type with multipart/signed
	b.WriteString("Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"" + boundary + "\"\r\n")
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.Write(rawBody)
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	b.WriteString(base64Encode(sig))
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String()), nil
}

// Decrypt decrypts a CMS EnvelopedData OR AuthEnvelopedData message using the
// recipient's certificate and private key. EnvelopedData (S/MIME 3.2 AES-CBC)
// stays mandatory-to-accept for backward compatibility; AuthEnvelopedData
// (S/MIME 4.0 AES-GCM) is what current peers send. ciphertextDER is the
// DER-encoded PKCS#7 ContentInfo (see DecodeEnvelopedDER for the MIME form).
func Decrypt(ciphertextDER []byte, cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	env, err := parseEnvelopedAny(ciphertextDER)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("smime: only RSA private keys supported for decryption")
	}

	// Find the recipient info matching our certificate and unwrap the session key.
	// Bleichenbacher countermeasure: see DecryptMulti — DecryptPKCS1v15SessionKey
	// never signals PKCS#1 v1.5 padding validity, so a chosen-ciphertext probe
	// cannot tell a padding failure from a wrong session key (both fall through
	// to the same "recipient not found" result).
	for _, ri := range env.recipientInfos {
		if ri.IssuerAndSerialNumber.Serial.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		sessionKey := make([]byte, aesSessionKeyLen)
		if _, err := rand.Read(sessionKey); err != nil {
			return nil, fmt.Errorf("smime: session-key fallback rng: %w", err)
		}
		// On padding failure this leaves sessionKey at the random fallback (no
		// error); a returned error is only a structural (wrong-length) ciphertext,
		// which is padding-independent and already known to the sender.
		if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, rsaKey, ri.EncryptedKey, sessionKey); err != nil {
			continue
		}
		if pt, err := env.decrypt(sessionKey); err == nil {
			return pt, nil
		}
	}
	return nil, errors.New("smime: recipient not found in EnvelopedData")
}

// decryptBody applies the recovered AES session key to the EnvelopedData's
// encrypted content (RFC 3565 §4.1: AES-CBC, IV in the algorithm parameters as a
// DER OCTET STRING — not prepended to the content) and unpads it. Shared by the
// single-key Decrypt and the multi-key DecryptMulti so the body-decrypt path is
// identical for both (no behaviour change to Decrypt).
//
// CBC remains mandatory-to-accept on receive (S/MIME 3.2 backward-compat
// mandate) even though send now defaults to GCM; an AuthEnvelopedData body is
// routed to authDecryptBody by parseEnvelopedAny instead, so reaching here with
// a non-CBC algorithm identifier means a malformed/foreign message — fail it
// rather than silently CBC-decrypting garbage.
func decryptBody(env cmsEnvelopedData, sessionKey []byte) ([]byte, error) {
	if !env.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("smime: unsupported content-encryption algorithm %v (EnvelopedData requires AES-256-CBC)",
			env.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
	}
	var iv []byte
	ivParams := env.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters
	ivDER := ivParams.FullBytes
	if len(ivDER) == 0 {
		ivDER = ivParams.Bytes
	}
	if _, err := asn1.Unmarshal(ivDER, &iv); err != nil {
		return nil, fmt.Errorf("smime: failed to parse content-encryption IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("smime: bad IV length %d (want %d)", len(iv), aes.BlockSize)
	}

	enc := env.EncryptedContentInfo.EncryptedContent
	if len(enc) == 0 || len(enc)%aes.BlockSize != 0 {
		return nil, errors.New("smime: encrypted content length is not a block multiple")
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(enc))
	mode.CryptBlocks(plaintext, enc)

	return pkcs7Unpad(plaintext)
}

// --- helpers ---

func mustMarshal(v any) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

// marshalAttrsAsSET encodes attrs as a DER SET (tag 0x31), as required by
// RFC 5652 §5.4 for the SignedAttributes digest. encoding/asn1 does not
// support direct SET marshaling of a slice, so we marshal a SEQUENCE{SET}
// wrapper and extract the inner SET bytes.
func marshalAttrsAsSET(attrs []cmsAttribute) ([]byte, error) {
	seqSet, err := asn1.Marshal(struct {
		Attrs []cmsAttribute `asn1:"set"`
	}{Attrs: attrs})
	if err != nil {
		return nil, err
	}
	// Unmarshal the outer SEQUENCE to obtain its Bytes (= the SET tag+len+content).
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(seqSet, &raw); err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - (len(data) % blockSize)
	//nolint:gosec // G115: n is in [1, blockSize] (AES block 16) — always fits in a byte
	pad := bytesRepeat(byte(n), n)
	return append(data, pad...)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("smime: empty data")
	}
	n := int(data[len(data)-1])
	if n > len(data) || n > aes.BlockSize || n == 0 {
		return nil, errors.New("smime: invalid PKCS#7 padding")
	}
	for i := len(data) - n; i < len(data); i++ {
		if data[i] != byte(n) {
			return nil, errors.New("smime: invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-n], nil
}

// base64Encode encodes data as RFC 2045 MIME base64: standard alphabet, padded
// with '=' to a multiple of 4, and line-wrapped at 64 characters with CRLF.
// This format is required for the SMIME multipart/signed body so that openssl
// and external MUAs (Outlook, Thunderbird) can parse the signature part.
func base64Encode(data []byte) string {
	const lineLen = 64
	encoded := encoding_base64.StdEncoding.EncodeToString(data)
	var out strings.Builder
	for len(encoded) > lineLen {
		out.WriteString(encoded[:lineLen])
		out.WriteString("\r\n")
		encoded = encoded[lineLen:]
	}
	if len(encoded) > 0 {
		out.WriteString(encoded)
		out.WriteString("\r\n")
	}
	return out.String()
}
