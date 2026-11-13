package smime

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"fmt"
)

// envelopeBody is the content-type-agnostic view Decrypt/DecryptMulti consume
// after parseEnvelopedAny: the same RFC 5652 RecipientInfos both content types
// carry (so the Bleichenbacher-hardened RSA session-key unwrap is shared), plus
// a decrypt closure that applies a recovered session key to THIS message's
// body — AES-CBC pkcs7 unpadding for EnvelopedData, GCM tag verification for
// AuthEnvelopedData. A wrong/garbage key makes decrypt fail either way, which
// keeps the "no matching key" collapse intact for both content types.
type envelopeBody struct {
	recipientInfos []cmsRecipientInfo
	decrypt        func(sessionKey []byte) ([]byte, error)
}

// parseEnvelopedAny parses the DER CMS ContentInfo that Decrypt/DecryptMulti
// consume into the content-type-agnostic envelopeBody view. It accepts both:
//
//   - RFC 5652 EnvelopedData (id-envelopedData 1.2.840.113549.1.7.3) — the
//     S/MIME 3.2 CBC form we still EMIT under the CBC fallback and MUST still
//     RECEIVE (backward-compat mandate: pre-A5 messages and external senders
//     stay readable forever); and
//   - RFC 5083 AuthEnvelopedData (id-smime-ct-authEnvelopedData
//     1.2.840.113549.1.9.16.1.23) — the S/MIME 4.0 GCM form Encrypt now emits
//     by default and external S/MIME 4.0 senders use.
//
// Only a malformed-CMS parse error is returned distinctly, BEFORE any key
// matching — preserving the "corrupt blob" vs "you don't hold the key"
// separation that DecryptMulti's callers (and tests) rely on. An unknown outer
// content type (signed-data, data, ...) is a parse error, not ErrNoMatchingKey.
func parseEnvelopedAny(ciphertextDER []byte) (envelopeBody, error) {
	var contentInfo cmsContentInfo
	if _, err := asn1.Unmarshal(ciphertextDER, &contentInfo); err != nil {
		return envelopeBody{}, fmt.Errorf("smime: failed to parse CMS: %w", err)
	}
	if contentInfo.ContentType.Equal(oidAuthEnvelopedData) {
		var aed cmsAuthEnvelopedData
		if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &aed); err != nil {
			return envelopeBody{}, fmt.Errorf("smime: failed to parse AuthEnvelopedData: %w", err)
		}
		return envelopeBody{
			recipientInfos: aed.RecipientInfos,
			decrypt: func(sessionKey []byte) ([]byte, error) {
				return authDecryptBody(aed, sessionKey)
			},
		}, nil
	}
	// id-envelopedData and every legacy/foreign variant: the RFC 5652 parse is
	// the historical behaviour (a non-EnvelopedData body fails here exactly as
	// it always has).
	var env cmsEnvelopedData
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &env); err != nil {
		return envelopeBody{}, fmt.Errorf("smime: failed to parse EnvelopedData: %w", err)
	}
	return envelopeBody{
		recipientInfos: env.RecipientInfos,
		decrypt: func(sessionKey []byte) ([]byte, error) {
			return decryptBody(env, sessionKey)
		},
	}, nil
}

// authDecryptBody applies the recovered AES session key to RFC 5083
// AuthEnvelopedData content: AES-256-GCM open with the tag from the dedicated
// mac field. On success the GCM tag has verified the ciphertext (and any
// authAttrs) — there is no separate padding/format check to pass, unlike CBC.
//
// AAD rules (RFC 5083 §2.2): we never emit authAttrs and the common case is
// none, meaning "zero bits" of AAD; if a peer includes them, the AAD is the
// authAttrs DER encoding with the IMPLICIT [1] tag replaced by a universal
// SET OF tag (same length and content octets).
func authDecryptBody(aed cmsAuthEnvelopedData, sessionKey []byte) ([]byte, error) {
	var params cmsGCMParameters
	paramsDER := aed.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.FullBytes
	if len(paramsDER) == 0 {
		paramsDER = aed.AuthEncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes
	}
	if _, err := asn1.Unmarshal(paramsDER, &params); err != nil {
		return nil, fmt.Errorf("smime: failed to parse GCM parameters: %w", err)
	}
	if len(params.Nonce) != gcmNonceLen {
		return nil, fmt.Errorf("smime: bad GCM nonce length %d (want %d)", len(params.Nonce), gcmNonceLen)
	}

	tag := aed.MAC
	// RFC 5084 enumerates aes-ICVlen values 12..16; a shorter tag is not an
	// AES-GCM CMS ICV, a longer one cannot exist for 128-bit GCM.
	if len(tag) < 12 || len(tag) > gcmICVLen {
		return nil, fmt.Errorf("smime: bad GCM ICV length %d (want 12..%d)", len(tag), gcmICVLen)
	}

	aad, err := authAttrsAAD(aed.AuthAttrs)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, len(tag))
	if err != nil {
		return nil, err
	}
	// Go's AEAD Open expects ciphertext||tag concatenated — in the AuthEnvelopedData
	// shape the two arrive in separate fields, so rejoin them here.
	return gcm.Open(nil, params.Nonce, append(append([]byte{}, aed.AuthEncryptedContentInfo.EncryptedContent...), tag...), aad)
}

// authAttrsAAD implements the RFC 5083 §2.2 AAD rule for the optional
// authAttrs: absent (the zero RawValue) ⇒ nil AAD ("zero bits"); present ⇒ the
// same TLV with the IMPLICIT [1] context tag (0xA1) swapped for the universal
// SET OF tag (0x31) — length and content octets untouched.
func authAttrsAAD(authAttrs asn1.RawValue) ([]byte, error) {
	if len(authAttrs.FullBytes) == 0 {
		return nil, nil
	}
	der := authAttrs.FullBytes
	if der[0] != 0xa1 {
		// We only parse [1] IMPLICIT, so anything else would be an asn1
		// misconfiguration, not a peer input; fail closed.
		return nil, fmt.Errorf("smime: unexpected authAttrs tag 0x%02x", der[0])
	}
	out := append([]byte{}, der...)
	out[0] = 0x31
	return out, nil
}
