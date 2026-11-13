package validate

import (
	"net/mail"
	"strings"
	"unicode/utf8"
)

// EmailOption configures ValidateEmail behavior.
type EmailOption func(*emailOptions)

type emailOptions struct {
	smtpUTF8 bool
}

// WithSMTPUTF8 controls whether non-ASCII local-parts are allowed per RFC 6531.
// When false (default), non-ASCII local-parts are rejected with SMTPUTF8_REQUIRED.
// When true, UTF-8 local-parts are accepted per RFC 6531 section 3.3.
func WithSMTPUTF8(enabled bool) EmailOption {
	return func(o *emailOptions) {
		o.smtpUTF8 = enabled
	}
}

// ValidateEmail validates an email address per RFC 5321 section 4.1.2
// (Mailbox = Local-part "@" Domain) and section 4.5.3.1.1/4.5.3.1.3.
//
// Checks:
//   - Not empty
//   - Total length <= 254 chars (RFC 5321 section 4.5.3.1.3: path max 256 minus "<>" brackets)
//   - Parseable by net/mail.ParseAddress
//   - No control characters (0x00-0x1F, 0x7F)
//   - No consecutive dots in local-part
//   - No leading/trailing dots in local-part
//   - Domain contains at least one dot
//   - No IP domain literals ("[...]" — explicit deny: no MTA lane delivers them)
//   - Domain does not contain underscore
//   - Non-ASCII local-part only when SMTPUTF8 enabled (RFC 6531 section 3.2)
func ValidateEmail(email string, opts ...EmailOption) error {
	o := emailOptions{}
	for _, opt := range opts {
		opt(&o)
	}

	if email == "" {
		return NewValidationError("email", "email must not be empty", "EMPTY_EMAIL")
	}

	if len(email) > 254 {
		return NewValidationError("email", "email exceeds 254 characters", "EMAIL_TOO_LONG")
	}

	// Check for control characters before parsing.
	for i := 0; i < len(email); i++ {
		b := email[i]
		if b < 0x20 || b == 0x7F {
			return NewValidationError("email", "email contains control character", "CONTROL_CHAR")
		}
	}

	// Check for dot issues in local-part before ParseAddress,
	// since ParseAddress rejects these with a generic error.
	// Find the (last) @ to identify the local-part.
	rawAt := strings.LastIndex(email, "@")
	if rawAt >= 1 {
		rawLocal := email[:rawAt]
		if strings.Contains(rawLocal, "..") {
			return NewValidationError("email", "local-part contains consecutive dots", "DOT_SEQUENCE")
		}
		if strings.HasPrefix(rawLocal, ".") {
			return NewValidationError("email", "local-part starts with a dot", "DOT_SEQUENCE")
		}
		if strings.HasSuffix(rawLocal, ".") {
			return NewValidationError("email", "local-part ends with a dot", "DOT_SEQUENCE")
		}
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		// Also try with angle brackets if not present.
		if !strings.HasPrefix(email, "<") {
			addr2, err2 := mail.ParseAddress("<" + email + ">")
			if err2 != nil {
				return NewValidationError("email", "invalid email format", "INVALID_EMAIL")
			}
			addr = addr2
		} else {
			return NewValidationError("email", "invalid email format", "INVALID_EMAIL")
		}
	}

	address := addr.Address
	if address == "" {
		return NewValidationError("email", "invalid email format", "INVALID_EMAIL")
	}

	// Split into local-part and domain.
	atIdx := strings.LastIndex(address, "@")
	if atIdx < 1 || atIdx == len(address)-1 {
		return NewValidationError("email", "invalid email format", "INVALID_EMAIL")
	}

	localPart := address[:atIdx]
	domain := address[atIdx+1:]

	// SMTPUTF8: non-ASCII local-part requires SMTPUTF8 extension.
	if !o.smtpUTF8 && !isASCII(localPart) {
		return NewValidationError("email", "non-ASCII local-part requires SMTPUTF8", "SMTPUTF8_REQUIRED")
	}

	// Domain checks.
	if err := validateEmailDomain(domain); err != nil {
		return err
	}

	return nil
}

// validateEmailDomain performs domain-specific checks for email addresses.
func validateEmailDomain(domain string) error {
	if len(domain) > 255 {
		return NewValidationError("email", "domain exceeds 255 characters", "EMAIL_TOO_LONG")
	}

	// Domain literals ([127.0.0.1], [IPv6:::1]) are an EXPLICIT deny, not an
	// accident of the dot rule. Delivery to a bracketed literal requires the
	// RFC 5321 §5.1 special-casing that no MTA lane in this repo implements —
	// MX resolution of a literal fails on every resolver — so structural
	// acceptance here would diverge from delivery reality (accept at validation,
	// fail at delivery). Previously [127.0.0.1] passed via the "contains a dot"
	// rule while [IPv6:::1] failed: an inconsistent, undocumented accident.
	if strings.HasPrefix(domain, "[") && strings.HasSuffix(domain, "]") {
		return NewValidationError("email", "IP domain literals are not supported", "DOMAIN_LITERAL")
	}

	// Domain must contain at least one dot (unqualified not allowed for email).
	if !strings.Contains(domain, ".") {
		return NewValidationError("email", "domain must contain at least one dot", "INVALID_DOMAIN")
	}

	// Underscore not allowed in domain per RFC 5321 section 4.1.2.
	if strings.Contains(domain, "_") {
		return NewValidationError("email", "domain contains underscore", "INVALID_DOMAIN")
	}

	return nil
}

// CanonicalEmail is the value-returning validation primitive: it validates
// email exactly like ValidateEmail and returns the canonical RFC 5322 address
// form that passed — mail.ParseAddress's Address, with any display-name,
// comment, or surrounding-whitespace decoration stripped and the angle-addr
// resolved. Writers must persist THIS value, not the raw input: an error-only
// ValidateEmail call followed by storing the request string re-introduces
// display-name/quoted-local/comment forms into storage (the raw input and the
// validated value diverge).
//
// med-shard2-008 r2: the returned value is always itself a valid address. A
// quoted-string local-part is de-quoted by mail.ParseAddress, which can turn
// an ACCEPTED input into a form that fails this same validator
// (`"first last"@example.com` parses to `first last@example.com`). When the
// de-quoted form no longer validates, the required quoting is preserved: the
// local-part is re-quoted (RFC 5322 quoted-string, escaping `"` and `\`) and
// the restored form must pass the validator or the input is rejected. Bare
// dot-atom local-parts — including de-quoted UNNECESSARY quoting
// (`"bob"@corp.example` → `bob@corp.example`) — pass unchanged. Consequently
// CanonicalEmail is idempotent on its output and the returned value re-passes
// ValidateEmail with the same options.
//
// The fuller provisioning fold — trim + ASCII-fold lower + this validation —
// lives in shared/identity (CanonicalizeAddress / ValidateAndCanonicalizeEmail);
// operator/admin writers of identity addresses route there. CanonicalEmail is
// the in-package primitive for address columns that need the validated
// canonical form without the identity fold.
//
// On rejection it returns "" and the *ValidationError from ValidateEmail.
func CanonicalEmail(email string, opts ...EmailOption) (string, error) {
	if err := ValidateEmail(email, opts...); err != nil {
		return "", err
	}
	// Mirror ValidateEmail's own parse (including its angle-bracket repair) so
	// the returned value is exactly the address the validation accepted; the
	// guard below can then never fire in practice.
	addr, err := mail.ParseAddress(email)
	if err != nil && !strings.HasPrefix(email, "<") {
		addr, err = mail.ParseAddress("<" + email + ">")
	}
	if err != nil || addr == nil || addr.Address == "" {
		return "", NewValidationError("email", "invalid email format", "INVALID_EMAIL")
	}

	canonical := addr.Address

	// Quoting removal check: only return the de-quoted form when it still
	// validates; otherwise preserve the required quoting (or reject).
	if verr := ValidateEmail(canonical, opts...); verr != nil {
		at := strings.LastIndex(canonical, "@")
		if at < 1 || !localPartNeedsQuoting(canonical[:at]) {
			// Not a quoting artifact — a quoted-string parse cannot have
			// produced it. Reject the transformed value instead of returning
			// one that fails validation.
			return "", NewValidationError("email", "invalid email format", "INVALID_EMAIL")
		}
		canonical = quoteLocalPart(canonical[:at]) + "@" + canonical[at+1:]
		if verr := ValidateEmail(canonical, opts...); verr != nil {
			return "", NewValidationError("email", "invalid email format", "INVALID_EMAIL")
		}
	}
	return canonical, nil
}

// localPartNeedsQuoting reports whether local must be rendered as an RFC 5322
// quoted-string: a bare dot-atom (atext bytes with dot separators, no empty,
// leading, trailing, or repeated dots) is the only local-part form that
// survives mail parsing unchanged, so anything else loses its quoted meaning
// or validity when unquoted.
func localPartNeedsQuoting(local string) bool {
	if local == "" {
		return true
	}
	for i := 0; i < len(local); i++ {
		if b := local[i]; b != '.' && !isAtextByte(b) {
			return true
		}
	}
	return strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..")
}

// isAtextByte reports whether b is in the RFC 5322 section 3.2.3 atext set
// (ASCII printable atom characters).
func isAtextByte(b byte) bool {
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '/', '=', '?', '^', '_', '`', '{', '|', '}', '~':
		return true
	}
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// quoteLocalPart renders local as an RFC 5322 quoted-string, escaping the two
// bytes excluded from qtext (`"` and `\`) as quoted-pairs.
func quoteLocalPart(local string) string {
	escaped := strings.ReplaceAll(local, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

// IsReservedEmailAddress reports whether the address's local-part is an RFC
// 2142 reserved name (postmaster, abuse, ...). The address is evaluated in
// canonical form: display-name/comment decoration is stripped before the
// local-part split, the split is on the LAST '@' (a quoted-string local-part
// may contain '@'; the domain side cannot), and a quoted-string local-part is
// judged by its unquoted content so `"postmaster"@` cannot bypass the gate.
//
// This is the wiring point for privileged provisioning paths: claiming a
// system identity by local-part is a provisioning decision, so paths that
// mint accounts/aliases must call this (directly, or via the shared/identity
// seams that gate through it) in addition to structural validation.
func IsReservedEmailAddress(email string) bool {
	email = strings.TrimSpace(email)
	if addr, err := mail.ParseAddress(email); err == nil && addr.Address != "" {
		email = addr.Address
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	return IsReservedEmailLocalPart(strings.ToLower(email[:at]))
}

// isASCII reports whether s contains only ASCII characters.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
