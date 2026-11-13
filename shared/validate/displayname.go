package validate

import "strings"

// ValidateDisplayName validates a display name.
//
// Display names are for human consumption, not protocol. Therefore CJK, emoji,
// Unicode, and diacritics are all allowed.
//
// Checks:
//   - Trim whitespace; reject empty after trim
//   - Max 128 chars
//   - Reject control characters (0x00-0x1F, 0x7F)
func ValidateDisplayName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return NewValidationError("displayName", "display name must not be empty", "EMPTY_DISPLAY_NAME")
	}

	if len(name) > 128 {
		return NewValidationError("displayName", "display name exceeds 128 characters", "DISPLAY_NAME_TOO_LONG")
	}

	for i := 0; i < len(name); i++ {
		b := name[i]
		if b < 0x20 || b == 0x7F {
			return NewValidationError("displayName", "display name contains control character", "CONTROL_CHAR")
		}
	}

	return nil
}
