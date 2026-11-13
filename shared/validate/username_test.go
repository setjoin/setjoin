package validate

import (
	"strings"
	"testing"
)

func TestValidateUserName_Valid(t *testing.T) {
	tests := []string{
		"john",
		"john.doe",
		"john_doe",
		"john-doe",
		"a",
		"abc123",
		"first.last",
		"user_name-123",
		"a.b",
		strings.Repeat("a", 64),
	}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ValidateUserName(name); err != nil {
				t.Errorf("ValidateUserName(%q) = %v, want nil", name, err)
			}
		})
	}
}

func TestValidateUserName_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		code     string
	}{
		{"empty", "", "EMPTY_USER_NAME"},
		{"too long", strings.Repeat("a", 65), "USER_NAME_TOO_LONG"},
		{"consecutive dots", "john..doe", "DOT_SEQUENCE"},
		{"leading dot", ".john", "DOT_EDGE"},
		{"trailing dot", "john.", "DOT_EDGE"},
		{"leading hyphen", "-john", "HYPHEN_EDGE"},
		{"trailing hyphen", "john-", "HYPHEN_EDGE"},
		{"reserved postmaster", "postmaster", "RESERVED_NAME"},
		{"reserved Postmaster", "Postmaster", "RESERVED_NAME"},
		{"reserved abuse", "abuse", "RESERVED_NAME"},
		{"reserved webmaster", "webmaster", "RESERVED_NAME"},
		{"reserved hostmaster", "hostmaster", "RESERVED_NAME"},
		{"reserved mailer-daemon", "mailer-daemon", "RESERVED_NAME"},
		{"reserved nobody", "nobody", "RESERVED_NAME"},
		{"non ascii", "用户", "NON_ASCII"},
		{"space", "john doe", "INVALID_CHAR"},
		{"special chars", "john!doe", "INVALID_CHAR"},
		{"control char", "john\x00doe", "CONTROL_CHAR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserName(tt.userName)
			if err == nil {
				t.Errorf("ValidateUserName(%q) = nil, want error", tt.userName)
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
