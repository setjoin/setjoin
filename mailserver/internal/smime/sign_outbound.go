package smime

import (
	"bytes"
	"strings"
)

// Sign-failure reason markers. These are the stable, machine-readable strings the
// EmailSubmission/set handler surfaces as per-creationId notCreated[*].type entries
// so the webmail compose UX can explain why a requested S/MIME signature was not
// applied. Keep these in sync with the compose-side handling.
const (
	// ReasonNoCert: signing was requested but the user has no usable S/MIME cert.
	ReasonNoCert = "smime_no_cert"
	// ReasonNoMatchingCert: the user has certs but none binds the From address.
	ReasonNoMatchingCert = "smime_no_matching_cert"
	// ReasonSignFailed: a cert matched but the key/cert was unusable or signing
	// errored (e.g. a non-RSA key, an unparseable PEM, or a crypto failure).
	ReasonSignFailed = "smime_sign_failed"

	// Encrypt-failure reason markers (SP1 Phase 3). Encryption fails CLOSED: any
	// of these drops the creation (notCreated), nothing is sent, never plaintext.

	// ReasonEncryptNoCert: encryption was requested but no usable encryption cert
	// is available for one or more RECIPIENTS (or the encrypt itself failed).
	ReasonEncryptNoCert = "smime_encrypt_no_cert"
	// ReasonEncryptNoSenderCert: no usable encrypt-to-self cert for the SENDER.
	ReasonEncryptNoSenderCert = "smime_encrypt_no_sender_cert"
	// ReasonEncryptNoJournalCert: journaling is required for the sender's domain
	// but no journal cert is configured — so the archived copy could not be made
	// readable. Fail closed rather than journal plaintext or skip the archive.
	ReasonEncryptNoJournalCert = "smime_encrypt_no_journal_cert"
)

// SignCandidate is one of a user's S/MIME certs: the cleartext certificate PEM and
// the DECRYPTED private-key PEM (the caller is responsible for the pgp_sym_decrypt).
// IsDefault mirrors user_smime_certs.is_default and is used only as a tie-breaker
// when more than one candidate binds the From address.
type SignCandidate struct {
	CertPEM   []byte
	KeyPEM    []byte
	IsDefault bool
}

// ResolveAndSign selects the candidate whose certificate binds fromAddr (preferring
// the default on a tie), then signs rawMessage and returns the full S/MIME signed
// message bytes. It mirrors OutboundWorker.signSMIME byte-handling EXACTLY so that
// external MUAs (Outlook, Thunderbird) accept the signature: headers are split off
// at the first CRLFCRLF and only the body is passed to SignMessage.
//
// reason is "" on success, otherwise one of:
//   - ReasonNoCert         — no candidates at all
//   - ReasonNoMatchingCert — candidates exist but none binds fromAddr
//   - ReasonSignFailed     — a candidate matched but its key/cert was unusable or
//     signing errored (non-RSA key, unparseable PEM, crypto failure)
//
// On any non-success the returned signed slice is nil. ResolveAndSign never panics.
func ResolveAndSign(candidates []SignCandidate, fromAddr string, rawMessage []byte) (signed []byte, reason string) {
	if len(candidates) == 0 {
		return nil, ReasonNoCert
	}

	// Resolve by From↔SAN match. Prefer a default cert on a tie; otherwise take
	// the first matching candidate. A candidate whose cert PEM is unparseable
	// simply cannot match (and is skipped) — it never aborts resolution.
	var chosen *SignCandidate
	for i := range candidates {
		cert, err := ParseCert(candidates[i].CertPEM)
		if err != nil {
			continue
		}
		if !CertMatchesEmail(cert, fromAddr) {
			continue
		}
		if chosen == nil {
			chosen = &candidates[i]
			continue
		}
		// On a tie (multiple binding certs), prefer the default.
		if candidates[i].IsDefault && !chosen.IsDefault {
			chosen = &candidates[i]
		}
	}
	if chosen == nil {
		return nil, ReasonNoMatchingCert
	}

	// A matched cert that then fails to load/sign is a sign failure (not a
	// no-cert): the user has a binding cert, we just can't use it.
	cert, err := ParseCert(chosen.CertPEM)
	if err != nil {
		return nil, ReasonSignFailed
	}
	key, err := ParsePrivateKey(chosen.KeyPEM)
	if err != nil {
		return nil, ReasonSignFailed
	}

	// Mirror outbound.go signSMIME: split headers at the first CRLFCRLF and pass
	// only the body to SignMessage (which re-wraps it as multipart/signed and
	// supplies its own headers). The exact split byte-for-byte is load-bearing
	// for MUA acceptance — do NOT reorder or trim.
	body := rawMessage
	if idx := bytes.Index(rawMessage, []byte("\r\n\r\n")); idx >= 0 {
		body = rawMessage[idx+4:]
	}
	out, err := SignMessage(body, cert, key)
	if err != nil {
		return nil, ReasonSignFailed
	}
	return out, ""
}

// IsSignedMessage reports whether raw is already an S/MIME signed message, so the
// caller can skip re-signing an already-signed draft. It inspects only the top-level
// Content-Type header (the bytes before the first blank line): a multipart/signed
// part (protocol="application/pkcs7-signature") or an application/pkcs7-mime with
// smime-type=signed-data. An enveloped-data (encrypted) message is NOT signed.
func IsSignedMessage(raw []byte) bool {
	// Restrict to the header block to avoid matching body content.
	header := raw
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		header = raw[:idx]
	} else if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		header = raw[:idx]
	}
	lower := strings.ToLower(string(header))
	ctIdx := strings.Index(lower, "content-type:")
	if ctIdx < 0 {
		return false
	}
	ct := lower[ctIdx:]
	if strings.Contains(ct, "multipart/signed") {
		return true
	}
	if strings.Contains(ct, "application/pkcs7-mime") && strings.Contains(ct, "signed-data") {
		return true
	}
	return false
}
