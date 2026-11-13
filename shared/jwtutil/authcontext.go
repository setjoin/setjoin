package jwtutil

import "sort"

// AuthContext is the (acr, amr) pair an issued token should advertise. The zero
// value (empty ACR, nil AMR) emits nothing, so issuance sites that do not track
// factors stay backward-compatible.
type AuthContext struct {
	ACR string
	AMR []string
}

// AuthContextFromFactors builds an AuthContext from the authentication methods a
// session satisfied, deriving the AAL and the "mfa" marker via DeriveAuthContext.
func AuthContextFromFactors(methods ...string) AuthContext {
	acr, amr := DeriveAuthContext(methods...)
	return AuthContext{ACR: acr, AMR: amr}
}

// Authentication-context vocabulary for the acr/amr claims.
//
// AMR values follow RFC 8176 ("Authentication Method Reference Values").
// ACR values follow the NIST SP 800-63B Authenticator Assurance Levels, which
// is the convention OIDC deployments most commonly publish in
// acr_values_supported. We keep the surface deliberately small — only the
// methods this server can actually perform — so a token never claims an AMR the
// auth flow did not satisfy.
const (
	// ── AMR (RFC 8176) — methods actually performed ──

	// AMRPassword: a password was verified (RFC 8176 "pwd").
	AMRPassword = "pwd"
	// AMROTP: a one-time passcode was verified — TOTP/HOTP (RFC 8176 "otp").
	AMROTP = "otp"
	// AMRHardwareKey: proof-of-possession of a hardware-backed key —
	// WebAuthn / FIDO2 passkey (RFC 8176 "hwk").
	AMRHardwareKey = "hwk"
	// AMRSoftwareKey: proof-of-possession of a software-secured key —
	// the closest RFC 8176 value for our number-matching push approval, whose
	// challenge is bound to a key/nonce held by an enrolled device rather than a
	// dedicated hardware authenticator (RFC 8176 "swk"). Push is therefore
	// reported as AMRSoftwareKey + AMRUserPresence (a human confirmed the prompt).
	AMRSoftwareKey = "swk"
	// AMRUserPresence: a human confirmed their presence at the authenticator —
	// the number-match tap on a push challenge (RFC 8176 "user").
	AMRUserPresence = "user"
	// AMRMultiFactor: set when two or more distinct factors were satisfied
	// (RFC 8176 "mfa"). Derived, never supplied directly by a single method.
	AMRMultiFactor = "mfa"

	// ── ACR — NIST SP 800-63B Authenticator Assurance Levels ──

	// ACRAAL1: single-factor authentication (e.g. password only).
	ACRAAL1 = "aal1"
	// ACRAAL2: multi-factor authentication — two distinct factors satisfied.
	ACRAAL2 = "aal2"
)

// nonMFAMethods are AMR values that, on their own, do not constitute a distinct
// authentication factor for the "≥2 factors ⇒ mfa/aal2" derivation. AMRUserPresence
// is a property of a push approval, not a standalone factor — it always accompanies
// AMRSoftwareKey — so counting it would double-count the single push factor.
var nonMFAMethods = map[string]struct{}{
	AMRUserPresence: {},
	AMRMultiFactor:  {},
}

// DeriveAuthContext computes the (acr, amr) pair for a token from the set of
// authentication methods a session satisfied. It is a pure function — no I/O,
// no clock — so it is exhaustively unit-testable and is the single place the
// "what AAL did we reach" decision is made.
//
// Behavior:
//   - The returned amr is the deduplicated input (insertion order is irrelevant;
//     output is sorted for determinism), with "mfa" appended when two or more
//     *distinct factors* were satisfied.
//   - acr is "aal2" when "mfa" was derived, otherwise "aal1".
//   - Empty input yields ("", nil): a flow that records no methods stays
//     backward-compatible (no acr/amr emitted at all).
func DeriveAuthContext(methods ...string) (acr string, amr []string) {
	if len(methods) == 0 {
		return "", nil
	}

	seen := make(map[string]struct{}, len(methods))
	distinctFactors := 0
	for _, m := range methods {
		if m == "" {
			continue
		}
		if _, dup := seen[m]; dup {
			continue
		}
		seen[m] = struct{}{}
		if _, nonFactor := nonMFAMethods[m]; !nonFactor {
			distinctFactors++
		}
	}
	if len(seen) == 0 {
		return "", nil
	}

	multiFactor := distinctFactors >= 2
	if multiFactor {
		seen[AMRMultiFactor] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)

	if multiFactor {
		return ACRAAL2, out
	}
	return ACRAAL1, out
}

// ACRSatisfies reports whether a token's acr meets a required acr. The only
// ordered relationship we enforce is the AAL ladder: an aal2 token satisfies a
// requirement of aal1 or aal2; an aal1 token satisfies only aal1. An empty
// requirement is satisfied by anything (no constraint). An unknown/non-AAL
// required value is satisfied only by an exact string match, so a custom acr a
// deployment defines is never silently downgraded.
func ACRSatisfies(tokenACR, requiredACR string) bool {
	if requiredACR == "" {
		return true
	}
	reqRank, reqIsAAL := aalRank(requiredACR)
	if !reqIsAAL {
		return tokenACR == requiredACR
	}
	tokRank, tokIsAAL := aalRank(tokenACR)
	if !tokIsAAL {
		return false
	}
	return tokRank >= reqRank
}

// aalRank returns the numeric assurance rank of an AAL string and whether the
// string was a recognized AAL value.
func aalRank(acr string) (int, bool) {
	switch acr {
	case ACRAAL1:
		return 1, true
	case ACRAAL2:
		return 2, true
	default:
		return 0, false
	}
}
