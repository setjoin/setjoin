package validate

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PasswordPolicy defines the requirements for password validation.
type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
	DisallowEmail    string // reject if password contains this email's local-part or domain
}

const (
	defaultMinPasswordLength = 8
	// PasswordMaxBytes is the cross-profile credential-writer ceiling. The
	// standard profile uses bcrypt, whose hard limit is 72 bytes (not runes).
	// Keeping one exported floor makes UI, SQL, admin, and auth writers agree.
	PasswordMaxBytes = 72
)

// ValidatePassword validates a password against the given policy.
//
// Checks (in order):
//   - Not empty
//   - Max encoded length (72 UTF-8 bytes, bcrypt-compatible cross-profile limit)
//   - Min length, counted in Unicode runes (default 8 if not set). Runes, not
//     bytes: the max side must be bytes (bcrypt hashes bytes), but counting the
//     min side in bytes let a multi-byte-script password satisfy the stated
//     minimum with far fewer characters than the policy promises the user.
//   - Character class requirements
//   - Does not contain DisallowEmail local-part or domain (case-insensitive)
//
// Passwords are never logged or included in validation errors.
func ValidatePassword(password string, policy PasswordPolicy) error {
	if password == "" {
		return NewValidationError("password", "password must not be empty", "EMPTY_PASSWORD")
	}

	if len([]byte(password)) > PasswordMaxBytes {
		return NewValidationError("password", "password exceeds 72 UTF-8 bytes", "PASSWORD_TOO_LONG")
	}

	minLen := policy.MinLength
	if minLen < 1 {
		minLen = defaultMinPasswordLength
	}
	// Min length is counted in runes (Unicode code points), the unit a user
	// reads as "characters"; only the max side is bytes (bcrypt's raw limit).
	if utf8.RuneCountInString(password) < minLen {
		return NewValidationError("password", "password too short", "PASSWORD_TOO_SHORT")
	}

	// Character class checks.
	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case isSpecialRune(r):
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		return NewValidationError("password", "password must contain an uppercase letter", "PASSWORD_NO_UPPERCASE")
	}
	if policy.RequireLowercase && !hasLower {
		return NewValidationError("password", "password must contain a lowercase letter", "PASSWORD_NO_LOWERCASE")
	}
	if policy.RequireDigit && !hasDigit {
		return NewValidationError("password", "password must contain a digit", "PASSWORD_NO_DIGIT")
	}
	if policy.RequireSpecial && !hasSpecial {
		return NewValidationError("password", "password must contain a special character", "PASSWORD_NO_SPECIAL")
	}

	// Check if password contains the email local-part or domain.
	if policy.DisallowEmail != "" {
		if passwordContainsEmail(password, policy.DisallowEmail) {
			return NewValidationError("password", "password must not contain your email address", "PASSWORD_CONTAINS_EMAIL")
		}
	}

	return nil
}

// passwordContainsEmail checks case-insensitively whether password contains
// the local-part or domain of the given email address.
//
// The email is evaluated in CANONICAL form, never as the raw caller string:
// net/mail.ParseAddress resolves display-name/comment decoration to the bare
// address first, so an input like `"Bob" <bob@corp.com>` checks bob@corp.com.
// The local-part/domain split is on the LAST '@' — the domain side cannot
// contain '@' while a quoted-string local-part can, so splitting on the first
// '@' mis-parsed quoted-local addresses (`"bo@b"@corp.com`) into a phantom
// local/domain pair. A quoted-string local-part is compared by its unquoted
// content: provisioning stores the unquoted address (bob@corp.com), so a
// password must be checked against bob, not the literal `"bob"` token that
// would silently make the DisallowEmail control inert.
func passwordContainsEmail(password, email string) bool {
	lowerPw := strings.ToLower(password)
	lowerEmail := strings.ToLower(strings.TrimSpace(email))

	// Canonical address: strip display-name/comment decoration when the input
	// parses as an RFC 5322 address; unparseable input falls back to the raw
	// string so the last-'@' split below still sees its best-effort form.
	if addr, err := mail.ParseAddress(lowerEmail); err == nil && addr.Address != "" {
		lowerEmail = strings.ToLower(addr.Address)
	}

	// Check local-part and domain, splitting on the last '@'.
	atIdx := strings.LastIndex(lowerEmail, "@")
	if atIdx < 0 {
		return false
	}
	localPart := unquoteLocalPart(lowerEmail[:atIdx])
	domain := lowerEmail[atIdx+1:]
	if localPart != "" && strings.Contains(lowerPw, localPart) {
		return true
	}
	if domain != "" && strings.Contains(lowerPw, domain) {
		return true
	}
	return false
}

// isSpecialRune reports whether r is a "special" character for password policy:
// punctuation, symbols, or other non-alphanumeric printable ASCII/Unicode.
func isSpecialRune(r rune) bool {
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}
