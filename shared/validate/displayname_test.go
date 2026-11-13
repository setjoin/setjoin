package validate

import (
	"strings"
	"testing"
)

func TestValidateDisplayName_Valid(t *testing.T) {
	tests := []struct {
		label string
		name  string
	}{
		{"simple", "John Doe"},
		{"cjk", "张三"},
		{"diacritics", "José García"},
		{"parens", "User (Admin)"},
		{"period", "Dr. Smith"},
		{"apostrophe", "O'Brien"},
		{"emoji", "Name with emoji 🎉"},
		{"needs trim", "  needs trim  "},
		{"single char", "A"},
		{"max length", strings.Repeat("a", 128)},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			if err := ValidateDisplayName(tt.name); err != nil {
				t.Errorf("ValidateDisplayName(%q) = %v, want nil", tt.name, err)
			}
		})
	}
}

func TestValidateDisplayName_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		display string
		code    string
	}{
		{"empty", "", "EMPTY_DISPLAY_NAME"},
		{"whitespace only", "   \t  ", "EMPTY_DISPLAY_NAME"},
		{"too long", strings.Repeat("a", 129), "DISPLAY_NAME_TOO_LONG"},
		{"control char null", "bad\x00name", "CONTROL_CHAR"},
		{"control char tab in middle", "bad\tname", "CONTROL_CHAR"},
		{"control char delete", "bad\x7Fname", "CONTROL_CHAR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDisplayName(tt.display)
			if err == nil {
				t.Errorf("ValidateDisplayName(%q) = nil, want error", tt.display)
				return
			}
			ve, ok := err.(*ValidationError)
			if !ok {
				t.Errorf("expected *ValidationError, got %T", err)
				return
			}
			if ve.Code != tt.code {
				t.Errorf("code = %q, want %q", ve.Code, tt.code)
			}
		})
	}
}
