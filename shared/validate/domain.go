package validate

import "strings"

// ValidateDomain validates a domain name per RFC 1035 hostname rules.
//
// Checks:
//   - Not empty (after trim)
//   - Max 253 chars total
//   - Each label max 63 chars
//   - Labels must not start or end with hyphen
//   - Only alphanumeric, hyphen, and dot allowed
//   - Must contain at least one dot (TLD required)
//   - No control characters or spaces
//
// Note: IDN U-labels are stored as-is; punycode conversion is deferred to DNS time.
func ValidateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return NewValidationError("domain", "domain must not be empty", "EMPTY_DOMAIN")
	}

	if len(domain) > 253 {
		return NewValidationError("domain", "domain exceeds 253 characters", "DOMAIN_TOO_LONG")
	}

	// Check for control characters.
	for i := 0; i < len(domain); i++ {
		b := domain[i]
		if b < 0x20 || b == 0x7F {
			return NewValidationError("domain", "domain contains control character", "CONTROL_CHAR")
		}
	}

	// Must contain at least one dot.
	if !strings.Contains(domain, ".") {
		return NewValidationError("domain", "domain must contain at least one dot", "NO_DOT")
	}

	// Check each label.
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if err := validateDomainLabel(label); err != nil {
			return err
		}
	}

	return nil
}

// validateDomainLabel checks a single domain label per RFC 1035.
func validateDomainLabel(label string) error {
	if label == "" {
		return NewValidationError("domain", "domain label must not be empty", "EMPTY_LABEL")
	}

	if len(label) > 63 {
		return NewValidationError("domain", "domain label exceeds 63 characters", "LABEL_TOO_LONG")
	}

	// Leading hyphen.
	if strings.HasPrefix(label, "-") {
		return NewValidationError("domain", "domain label starts with hyphen", "HYPHEN_EDGE")
	}

	// Trailing hyphen.
	if strings.HasSuffix(label, "-") {
		return NewValidationError("domain", "domain label ends with hyphen", "HYPHEN_EDGE")
	}

	// Only alphanumeric and hyphen allowed (IDN punycode uses a-z, 0-9, -).
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return NewValidationError("domain", "domain label contains invalid character", "INVALID_CHAR")
	}

	return nil
}
