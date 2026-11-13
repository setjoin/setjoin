package handlers

// webauthn_software_authenticator_test.go — a minimal SOFTWARE WEBAUTHN
// AUTHENTICATOR for the possession gate's cryptographic acceptance cases
// (r1 receipt defects 1 and 5; scheme v7 §4 "real signed
// assertion/attestation test fixtures"). It implements just enough of the
// CTAP2/U2F wire protocol for this suite:
//
//   - ES256 (COSE AlgES256, P-256) credential keys, ASN.1 DER signatures;
//   - "none"-format attestation objects (self-attested, no attestation
//     statement — the format the library's zero-config RP accepts);
//   - user-verified (UV+UP) authenticator data with the AT flag and the
//     attested credential data for registration, without it for assertions;
//   - monotonically increasing sign counts (the library's UpdateCounter
//     contract) and a stable per-authenticator user handle the tests pin
//     against users.webauthn_user_handle (defect 7's stable-handle contract).
//
// The encoder emits exactly the CBOR subset the wire needs (RFC 8949);
// go-webauthn's parser accepts it because the server decodes the same
// structures in production.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	"fmt"
)

// softwareAuthenticator holds one credential's keys and mutable state.
type softwareAuthenticator struct {
	priv      *ecdsa.PrivateKey
	credID    []byte
	signCount uint32
	rpID      string
	origin    string
	// The §4 flags option (opus r1 finding 3): the attestation and assertion
	// UV flags are individually configurable (default TRUE) so the
	// missing-UV refusal (§4.2 TestMissingUVRefused), the non-UV cohort
	// cases (§1.2, §4.4 case 4f) and the same-ID replacement
	// reclassification run against real wire bytes instead of being
	// inexpressible (the previous fixture always set UV).
	attestationUV bool
	assertionUV   bool
}

// newSoftwareAuthenticator mints an authenticator bound to the harness RP.
func newSoftwareAuthenticator(rpID, origin string) (*softwareAuthenticator, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("software authenticator key: %w", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("software authenticator credential id: %w", err)
	}
	return &softwareAuthenticator{
		priv: priv, credID: credID, rpID: rpID, origin: origin,
		attestationUV: true, assertionUV: true,
	}, nil
}

// SetAssertionUV overrides the UV flag the NEXT assertions carry (§4: the
// missing-UV assertion must be a real UP-only wire fixture).
func (a *softwareAuthenticator) SetAssertionUV(uv bool) { a.assertionUV = uv }

// SetAttestationUV overrides the UV flag the NEXT attestations carry (§4.4
// case 4f: a non-UV same-ID replacement must re-persist uv_capable=false).
func (a *softwareAuthenticator) SetAttestationUV(uv bool) { a.attestationUV = uv }

// cosePublicKey encodes the EC2 COSE_Key the attested credential data
// carries: {1: EC2, 3: ES256, -1: P-256, -2: x, -3: y}.
func (a *softwareAuthenticator) cosePublicKey() []byte {
	x := a.priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	out := []byte{0xa5}                 // map(5)
	out = append(out, 0x01, 0x02)       // 1: 2 (EC2)
	out = append(out, 0x03, 0x26)       // 3: -7 (ES256)
	out = append(out, 0x20, 0x01)       // -1: 1 (P-256)
	out = append(out, 0x21, 0x58, 0x20) // -2: bytes(32)
	out = append(out, x...)
	out = append(out, 0x22, 0x58, 0x20) // -3: bytes(32)
	out = append(out, y...)
	return out
}

// authenticatorData builds the authenticator data structure: rpIdHash ||
// flags || signCount, plus the attested credential data
// (aaguid || credIdLen || credId || COSE key) when the AT flag is set.
func (a *softwareAuthenticator) authenticatorData(flags byte, attested bool) []byte {
	rpHash := sha256.Sum256([]byte(a.rpID))
	ad := make([]byte, 0, 32+1+4+16+2+len(a.credID)+77)
	ad = append(ad, rpHash[:]...)
	ad = append(ad, flags)
	a.signCount++
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], a.signCount)
	ad = append(ad, ctr[:]...)
	if attested {
		ad = append(ad, make([]byte, 16)...) // AAGUID: zeros (uuid.Nil)
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(a.credID)))
		ad = append(ad, l...)
		ad = append(ad, a.credID...)
		ad = append(ad, a.cosePublicKey()...)
	}
	return ad
}

// AttestationResponse builds a webauthn.create registration response body
// ("none" attestation, UV asserted) for the given challenge. The returned
// bytes are exactly what a browser POSTs to the registration finish arm.
func (a *softwareAuthenticator) AttestationResponse(challenge string) ([]byte, error) {
	cdj, err := json.Marshal(map[string]any{
		"type":      "webauthn.create",
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		return nil, err
	}
	// Flags: UP (0x01) | UV (0x04, when asserted) | AT (0x40).
	uvFlag := byte(0x00)
	if a.attestationUV {
		uvFlag = 0x04
	}
	ad := a.authenticatorData(0x01|uvFlag|0x40, true)
	att := []byte{0xa3}                                              // map(3)
	att = append(att, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e') // "fmt": "none"
	att = append(att, 0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0) // "attStmt": {}
	att = append(att, 0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a')  // "authData":
	switch n := len(ad); {
	case n < 256:
		att = append(att, 0x58, byte(n))
	default:
		att = append(att, 0x59, byte(n>>8), byte(n))
	}
	att = append(att, ad...)

	id := base64RawURL(a.credID)
	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64RawURL(att),
			"clientDataJSON":    base64RawURL(cdj),
		},
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

// AssertionResponse builds a webauthn.get authentication response body
// signed with the credential key over authData || SHA-256(clientDataJSON).
// userHandle is the handle bytes the authenticator persists from the
// registration ceremony (the stable-handle contract: it presents exactly
// what registration bound).
func (a *softwareAuthenticator) AssertionResponse(challenge string, userHandle []byte) ([]byte, error) {
	cdj, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": challenge,
		"origin":    a.origin,
	})
	if err != nil {
		return nil, err
	}
	// Flags: UP (0x01) | UV (0x04, when asserted) — no attested credential
	// data.
	uvFlag := byte(0x00)
	if a.assertionUV {
		uvFlag = 0x04
	}
	ad := a.authenticatorData(0x01|uvFlag, false)
	cdHash := sha256.Sum256(cdj)
	sigInput := append(ad, cdHash[:]...) //nolint:gocritic // the wire's signature input is this exact concatenation
	digest := sha256.Sum256(sigInput)
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		return nil, err
	}
	id := base64RawURL(a.credID)
	body, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64RawURL(ad),
			"clientDataJSON":    base64RawURL(cdj),
			"signature":         base64RawURL(sig),
			"userHandle":        base64RawURL(userHandle),
		},
	})
	if err != nil {
		return nil, err
	}
	return body, nil
}

// base64RawURL is the wire encoding every WebAuthn JSON field uses.
func base64RawURL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
