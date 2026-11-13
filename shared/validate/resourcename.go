package validate

import (
	"strings"
	"unicode/utf8"
)

// ValidateResourceName validates a resource name for folders, departments,
// groups, tags, and other organizational resources.
//
// Checks:
//   - Not empty after trim
//   - Max 128 chars
//   - Valid UTF-8 (stored in Postgres TEXT and echoed into HTML responses)
//   - No "/", "\", or null bytes (no separator smuggling within one level)
//   - Not exactly "." or ".." (Unix filesystem semantics)
//   - No control characters
//   - No Windows reserved device name (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
//   - No trailing dot (trailing spaces are removed by the trim; Windows strips
//     both, silently renaming and enabling lookalike collisions)
//
// Deliberately NOT rejected (documented so the safety claim stays accurate):
// leading "-" and "~", and other shell-significant characters. Current sinks
// are parameterized INSERTs rendered through the Svelte layer's auto-escaping,
// so neither path traversal nor injection is reachable today; a future sink
// that renders names into shell/CLI paths must quote/escape there — this
// validator cannot anticipate that grammar.
func ValidateResourceName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return NewValidationError("name", "resource name must not be empty", "EMPTY_RESOURCE_NAME")
	}

	if len(name) > 128 {
		return NewValidationError("name", "resource name exceeds 128 characters", "NAME_TOO_LONG")
	}

	// Invalid UTF-8 cannot round-trip Postgres TEXT and corrupts byte-vs-rune
	// reasoning in every downstream renderer; reject it explicitly.
	if !utf8.ValidString(name) {
		return NewValidationError("name", "resource name is not valid UTF-8", "INVALID_UTF8")
	}

	// Check for forbidden characters: /, \, null. Check null here before
	// control characters so that null bytes get the more specific code.
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '/' || c == '\\' || c == 0x00 {
			return NewValidationError("name", "resource name contains forbidden character", "FORBIDDEN_CHAR")
		}
		if c < 0x20 || c == 0x7F {
			return NewValidationError("name", "resource name contains control character", "CONTROL_CHAR")
		}
	}

	// Reject "." and ".." exactly.
	if name == "." || name == ".." {
		return NewValidationError("name", "resource name is reserved", "RESERVED_NAME")
	}

	// Windows reserved device names, case-insensitive. These are invalid as
	// filename components on Windows regardless of extension ("CON.txt" opens
	// the console device); rejecting them keeps names portable to any future
	// filesystem sink.
	if isWindowsReservedName(name) {
		return NewValidationError("name", "resource name is a reserved device name", "RESERVED_NAME")
	}

	// Windows strips trailing dots and spaces at the filesystem boundary, so a
	// stored name and a later-extracted filename would silently diverge. The
	// trim above already removed trailing spaces, so only a trailing dot can
	// reach storage — reject it here.
	if name[len(name)-1] == '.' {
		return NewValidationError("name", "resource name ends with a dot", "TRAILING_DOT_OR_SPACE")
	}

	return nil
}

// isWindowsReservedName reports whether s (already trimmed, valid UTF-8) is a
// Windows reserved device name per Microsoft's naming rules (case-insensitive;
// extension suffixes do not rescue a reserved base name).
func isWindowsReservedName(s string) bool {
	// Compare the base name before any extension dot.
	base := s
	if i := strings.IndexByte(s, '.'); i >= 0 {
		base = s[:i]
	}
	switch strings.ToUpper(base) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	}
	return false
}
