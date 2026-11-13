package identity

import (
	"fmt"
	"net/mail"
	"strings"

	"setjoin.com/shared/validate"
)

// CanonicalAddress is a string that has PROVABLY passed through
// CanonicalizeAddress. The underlying value is unexported and there is no
// exported way to construct one outside this package — CanonicalizeAddress (and
// NormalizeAndValidate, which wraps it) is the SOLE minter. This makes "an
// address was canonicalized" a COMPILE-TIME obligation, not a convention: a
// write boundary whose parameter is CanonicalAddress cannot be fed a raw string
// (u.UPN, u.Email, an operator-typed value) — that fails to compile. It is the
// sound enforcement the grep writer-guard only approximates (the grep misses
// laundered writes, new address columns, and query-builder paths; the type does
// not). Pass it to a SQL bind via .String().
//
// Zero value: CanonicalAddress{} stringifies to "" — the canonical form of an
// empty/blank input (CanonicalizeAddress("") == ""), so a zero value is a
// legitimate "no address" sentinel, never an un-canonicalized smuggled string.
type CanonicalAddress struct {
	v string
}

// String returns the canonical address as a plain string, for SQL binds and
// logging. This is the ONLY exit from the newtype; everything upstream of it is
// type-guaranteed canonical.
func (c CanonicalAddress) String() string { return c.v }

// CanonicalizeAddress is the MATCHING-side canonicalizer for the one identity
// seam: it computes the canonical input form an address is compared by, so the
// value that resolves an existing person (the match key) is byte-identical to
// the value the provision path would write (NormalizeAndValidate's output).
// That equality is what makes the duplicate-JIT-on-normalization bug class
// (ARCH-004 normalization axis) structurally un-writable.
//
// It is the SOLE minter of CanonicalAddress (the only function that can produce
// the unexported underlying value), so a CanonicalAddress in hand is proof its
// content passed through exactly this fold.
//
// It does EXACTLY three things, in order:
//  1. trim surrounding whitespace,
//  2. ASCII-fold lower (A–Z → a–z ONLY — deliberately NOT unicode strings.ToLower,
//     to avoid the Turkish dotted/dotless-I and ß folding hazards),
//  3. RFC-5322 display-name strip (`"Name" <user@domain>` → `user@domain`),
//     applied ONLY when net/mail.ParseAddress succeeds.
//
// It NEVER rejects and NEVER returns an error. A value that does not parse as an
// address — a bare UPN (`alice@corp`, no dot), a Kerberos principal
// (`alice/admin@CORP`), or outright garbage — is returned trimmed+ASCII-folded
// so it can still resolve against `ad_upn` / `aliases`. Matching therefore can
// NOT be gated on validate.ValidateEmail (that is the provision side's job).
//
// Boundary (CONTEXT.md "Directory scope / identity resolution"): ASCII-fold only,
// audit-gated. IDN/punycode + Unicode NFC normalization are DEFERRED to a future
// writer-first migration; this function is the documented seam they will extend,
// not a place to add Unicode folding piecemeal.
//
// Idempotent: CanonicalizeAddress(CanonicalizeAddress(x).String()) == CanonicalizeAddress(x).
func CanonicalizeAddress(raw string) CanonicalAddress {
	s := asciiFoldLower(strings.TrimSpace(raw))
	// Display-name strip ONLY when it parses as an RFC-5322 address. A bare UPN
	// or Kerberos principal won't parse-strip (correct — they pass through), and
	// garbage won't either. ParseAddress can re-introduce no casing because the
	// input is already ASCII-folded, so the result stays canonical & idempotent.
	if addr, err := mail.ParseAddress(s); err == nil && addr.Address != "" {
		return CanonicalAddress{v: addr.Address}
	}
	return CanonicalAddress{v: s}
}

// NormalizeAndValidate is the PROVISIONING-side seam: CanonicalizeAddress + the
// shared validate.ValidateEmail gate + the RFC 2142 reserved-local-part gate.
// Every path that WRITES an IdP/connector address into users.email (JIT create,
// returning-user email update) routes through it, so hostile input
// (header-injection, control chars, non-addresses) is rejected before a write
// while a valid address is canonicalized to exactly CanonicalizeAddress's
// output.
//
// The reserved-local-part gate (validate.IsReservedEmailAddress) additionally
// refuses RFC 2142 system names (postmaster, abuse, ...) — quoting or
// display-name decoration of the input cannot bypass it, because the gate runs
// on the canonical form. An SSO subject, admin entry, or CSV row claiming a
// privileged local-part is rejected here, at the one provisioning seam, rather
// than per-handler.
//
// Invariant (pinned by TestNormalizeAndValidate_IsCanonicalizePrefix): when this
// succeeds, its output == CanonicalizeAddress(raw). The match key and the
// provision key cannot disagree about a person's canonical address.
//
// Returns CanonicalAddress (the validated provisioning key) so a write boundary
// can demand the type and reject a raw string at compile time. On rejection it
// returns the zero CanonicalAddress (.String() == "") and a non-nil error — a
// *validate.ValidationError (RESERVED_NAME) wrapped for the reserved gate, so
// HTTP callers that errors.As ValidationError surface a clean 400.
func NormalizeAndValidate(raw string) (CanonicalAddress, error) {
	canon := CanonicalizeAddress(raw)
	if err := validate.ValidateEmail(canon.String()); err != nil {
		return CanonicalAddress{}, fmt.Errorf("sso_email_rejected_invalid: %w", err)
	}
	if validate.IsReservedEmailAddress(canon.String()) {
		return CanonicalAddress{}, fmt.Errorf("sso_email_rejected_reserved: %w",
			validate.NewValidationError("email", "email local-part is reserved (RFC 2142)", "RESERVED_NAME"))
	}
	return canon, nil
}

// ValidatedAddress is a CanonicalAddress that has ADDITIONALLY passed
// validate.ValidateEmail on its canonical form — proof, at COMPILE time, that
// an address is both canonical AND a structurally-valid RFC-5321 email. It is a
// strictly stronger obligation than CanonicalAddress: CanonicalizeAddress mints
// a CanonicalAddress with NO validation (a bare UPN, a Kerberos principal, even
// garbage is returned canonicalized so it can still resolve against
// ad_upn/aliases), so a parameter typed CanonicalAddress proves only "folded",
// never "valid". ProvisionAccountParams.Email is ValidatedAddress precisely so a
// provisioning caller cannot bind an unvalidated address: it must route through
// ValidateAndCanonicalizeEmail (which validates) — that is the compile-time
// "MUST validate on provision" gate this type exists for.
//
// The underlying string is unexported; the ONLY two mints are
// ValidateAndCanonicalizeEmail (the validating path, for operator/admin input)
// and CanonicalAddress.AssumeValidated (the named, validation-FREE directory
// escape — see its doc). .String() is the sole exit, .Canonical() the projection
// back to the weaker type.
//
// Zero value: ValidatedAddress{} stringifies to "" — a legitimate "no address"
// sentinel, never a smuggled un-validated string.
type ValidatedAddress struct {
	v string
}

// String returns the validated, canonical address as a plain string, for SQL
// binds and logging. This is the ONLY exit from the newtype.
func (a ValidatedAddress) String() string { return a.v }

// Canonical projects a ValidatedAddress down to the weaker CanonicalAddress
// (every validated address is by construction also canonical). Lets provisioning
// code that only needs the canonical view read it without re-canonicalizing.
func (a ValidatedAddress) Canonical() CanonicalAddress { return CanonicalAddress{v: a.v} }

// ValidateAndCanonicalizeEmail is the VALIDATING mint of ValidatedAddress:
// CanonicalizeAddress + validate.ValidateEmail on the canonical form. It is the
// path operator/admin-supplied addresses take to reach provisioning — header
// injection, control chars, and non-RFC inputs (incl. a bare UPN with no dot in
// the domain) are rejected before any ValidatedAddress exists.
//
// Implemented over NormalizeAndValidate (the single validation definition — no
// second copy of the canonicalize+validate logic), so the invariant
// "ValidateAndCanonicalizeEmail(x).String() == CanonicalizeAddress(x).String()"
// holds by construction (pinned by TestValidateAndCanonicalizeEmail_IsCanonicalizePrefix):
// the validated provision key and the match key never drift.
//
// On rejection returns the zero ValidatedAddress (.String() == "") + a non-nil error.
func ValidateAndCanonicalizeEmail(raw string) (ValidatedAddress, error) {
	canon, err := NormalizeAndValidate(raw)
	if err != nil {
		return ValidatedAddress{}, err
	}
	return ValidatedAddress{v: canon.String()}, nil
}

// AssumeValidated lifts a CanonicalAddress to a ValidatedAddress WITHOUT running
// validate.ValidateEmail. This is the SINGLE named, validation-free path to a
// ValidatedAddress, reserved for TRUSTED DIRECTORY sources (AD/LDAP sync) whose
// `mail` attribute may legitimately not pass RFC-5321 — a bare UPN (`alice@corp`,
// no dot), a Kerberos-style principal — yet must still be writable, exactly as
// the pre-ValidatedAddress directory path accepted them. Directory sync therefore
// stays VALIDATION-FREE (its observable behavior is byte-identical: the same
// CanonicalizeAddress fold, no new rejection) while still satisfying the
// ProvisionAccountParams.Email type gate.
//
// Do NOT use this for operator/admin/SSO input — that input MUST go through
// ValidateAndCanonicalizeEmail so a non-address is rejected. This method is the
// deliberate, grep-able escape (one call site per directory connector), the
// directory-trust analogue of CanonicalizeAddress being the documented escape
// from a raw string.
func (c CanonicalAddress) AssumeValidated() ValidatedAddress { return ValidatedAddress{v: c.v} }

// asciiFoldLower lowercases ASCII A–Z ONLY, leaving every other byte (including
// all non-ASCII bytes of a multi-byte UTF-8 rune) untouched. This is the pinned
// fold for identity matching — see CanonicalizeAddress for why unicode ToLower
// is deliberately avoided.
func asciiFoldLower(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + ('a' - 'A')
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}
