package validate

import "strings"

// reservedUserNames is the set of RFC 5321/2142 reserved local-parts that
// must not be used as user names. Case-insensitive comparison.
var reservedUserNames = map[string]bool{
	"postmaster":    true,
	"abuse":         true,
	"webmaster":     true,
	"hostmaster":    true,
	"mailer-daemon": true,
	"nobody":        true,
}

// IsReservedUserName reports whether name is an RFC 5321/2142 reserved
// local-part (postmaster, abuse, ...) — case-insensitive. ValidateUserName
// enforces this for bare user names; privileged provisioning paths that only
// see a full email address must gate through IsReservedEmailAddress (or call
// this on the local-part they already split) so the set is wired to every
// write that could claim a system identity, not just the one validator.
func IsReservedUserName(name string) bool {
	return reservedUserNames[strings.ToLower(name)]
}

// IsReservedEmailLocalPart reports whether an email local-part is an RFC 2142
// reserved name. A quoted-string local-part ("postmaster") is evaluated by its
// unquoted content — RFC 5321 section 4.1.2 encodes the same local-part
// sequence either way, so quoting must not bypass the gate.
func IsReservedEmailLocalPart(localPart string) bool {
	return IsReservedUserName(unquoteLocalPart(localPart))
}

// unquoteLocalPart strips one wrapping double-quote pair from a quoted-string
// local-part so policy checks evaluate its unquoted content. A value that is
// not quoted-string wrapped is returned unchanged.
func unquoteLocalPart(localPart string) string {
	if len(localPart) >= 2 && localPart[0] == '"' && localPart[len(localPart)-1] == '"' {
		return localPart[1 : len(localPart)-1]
	}
	return localPart
}

// ValidateUserName validates a user name (the prefix part of an email alias).
//
// Per RFC 5321 section 4.1.2 (Atom = 1*atext) and section 4.5.3.1.1
// (local-part max 64 octets). The allowed character set is restricted to a
// safe SMTP subset: [a-zA-Z0-9._-].
//
// Checks:
//   - Min 1 char, max 64 chars
//   - ASCII only: alphanumeric, dot, hyphen, underscore
//   - No consecutive dots
//   - No leading/trailing dots or hyphens
//   - Not a reserved name (postmaster, abuse, etc.)
//   - No control characters
func ValidateUserName(name string) error {
	if name == "" {
		return NewValidationError("userName", "user name must not be empty", "EMPTY_USER_NAME")
	}

	if len(name) > 64 {
		return NewValidationError("userName", "user name exceeds 64 characters", "USER_NAME_TOO_LONG")
	}

	// Check for control characters.
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b < 0x20 || b == 0x7F {
			return NewValidationError("userName", "user name contains control character", "CONTROL_CHAR")
		}
	}

	// Non-ASCII check.
	if !isASCII(name) {
		return NewValidationError("userName", "user name must be ASCII only", "NON_ASCII")
	}

	// Consecutive dots.
	if strings.Contains(name, "..") {
		return NewValidationError("userName", "user name contains consecutive dots", "DOT_SEQUENCE")
	}

	// Leading dot.
	if strings.HasPrefix(name, ".") {
		return NewValidationError("userName", "user name starts with a dot", "DOT_EDGE")
	}

	// Trailing dot.
	if strings.HasSuffix(name, ".") {
		return NewValidationError("userName", "user name ends with a dot", "DOT_EDGE")
	}

	// Leading hyphen.
	if strings.HasPrefix(name, "-") {
		return NewValidationError("userName", "user name starts with a hyphen", "HYPHEN_EDGE")
	}

	// Trailing hyphen.
	if strings.HasSuffix(name, "-") {
		return NewValidationError("userName", "user name ends with a hyphen", "HYPHEN_EDGE")
	}

	// Character validation: only [a-zA-Z0-9._-].
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return NewValidationError("userName", "user name contains invalid character", "INVALID_CHAR")
	}

	// Reserved name check (case-insensitive).
	lower := strings.ToLower(name)
	if reservedUserNames[lower] {
		return NewValidationError("userName", "user name is reserved", "RESERVED_NAME")
	}

	return nil
}
