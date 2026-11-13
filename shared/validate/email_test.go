package validate

import (
	"net/mail"
	"testing"
)

func TestValidateEmail_Valid(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"simple", "user@example.com"},
		{"subdomain", "user@mail.example.com"},
		{"dots in local", "first.last@example.com"},
		{"hyphens in local", "first-last@example.com"},
		{"underscore in local", "first_last@example.com"},
		{"plus addressing", "user+tag@example.com"},
		{"numbers", "user123@example.com"},
		{"single char local", "a@example.com"},
		{"quoted local", `"first last"@example.com`},
		{"angle addr", "<user@example.com>"},
		{"numeric domain label", "user@123test.com"},
		{"hyphenated domain", "user@my-domain.com"},
		{"short tld", "user@example.co"},
		{"long local part near 64", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz@ex.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEmail(tt.email); err != nil {
				t.Errorf("ValidateEmail(%q) = %v, want nil", tt.email, err)
			}
		})
	}
}

func TestValidateEmail_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		email string
		code  string
	}{
		{"empty", "", "EMPTY_EMAIL"},
		{"no at sign", "userexample.com", "INVALID_EMAIL"},
		{"spaces", "user @example.com", "INVALID_EMAIL"},
		{"double at", "user@@example.com", "INVALID_EMAIL"},
		{"leading dot local", ".user@example.com", "DOT_SEQUENCE"},
		{"trailing dot local", "user.@example.com", "DOT_SEQUENCE"},
		{"consecutive dots local", "user..name@example.com", "DOT_SEQUENCE"},
		{"control char null", "user\x00name@example.com", "CONTROL_CHAR"},
		{"control char tab", "user\tname@example.com", "CONTROL_CHAR"},
		{"control char newline", "user\nname@example.com", "CONTROL_CHAR"},
		{"no dot in domain", "user@localhost", "INVALID_DOMAIN"},
		{"underscore in domain", "user@example_com.com", "INVALID_DOMAIN"},
		{"domain too long", tooLongDomain(), "EMAIL_TOO_LONG"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEmail(tt.email)
			if err == nil {
				t.Errorf("ValidateEmail(%q) = nil, want error", tt.email)
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

func TestValidateEmail_TooLong(t *testing.T) {
	// Build an email > 254 chars
	local := "a"
	for len(local) < 250 {
		local += "b"
	}
	email := local + "@example.com"
	if len(email) <= 254 {
		t.Fatalf("test setup: email not long enough: %d", len(email))
	}
	err := ValidateEmail(email)
	if err == nil {
		t.Fatal("expected error for email > 254 chars")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "EMAIL_TOO_LONG" {
		t.Errorf("code = %q, want EMAIL_TOO_LONG", ve.Code)
	}
}

func TestValidateEmail_SMTPUTF8(t *testing.T) {
	// With SMTPUTF8 enabled, non-ASCII local-parts are allowed.
	err := ValidateEmail("用户@example.com", WithSMTPUTF8(true))
	if err != nil {
		t.Errorf("ValidateEmail with SMTPUTF8 = %v, want nil", err)
	}

	// Without SMTPUTF8 (default), non-ASCII local-parts are rejected.
	err = ValidateEmail("用户@example.com")
	if err == nil {
		t.Fatal("expected error for non-ASCII local-part without SMTPUTF8")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "SMTPUTF8_REQUIRED" {
		t.Errorf("code = %q, want SMTPUTF8_REQUIRED", ve.Code)
	}
}

func TestValidateEmail_MultipleAtAfterParse(t *testing.T) {
	// net/mail.ParseAddress can parse "a@b" but also weird forms.
	// When address doesn't match input, we reject.
	err := ValidateEmail("not an email")
	if err == nil {
		t.Fatal("expected error for non-email string")
	}
}

// tooLongDomain builds an email whose domain portion exceeds 255 chars.
func tooLongDomain() string {
	s := "a@"
	// Build a domain label > 255 (exceeds domain max)
	for i := 0; i < 260; i++ {
		s += "x"
	}
	return s
}

// verify net/mail.ParseAddress behaviour for reference.
func TestParseAddress_Behaviour(t *testing.T) {
	addr, err := mail.ParseAddress("<user@example.com>")
	if err != nil {
		t.Fatal(err)
	}
	if addr.Address != "user@example.com" {
		t.Errorf("ParseAddress angle-addr Address = %q", addr.Address)
	}
}

// TestValidateEmail_RejectsDomainLiterals pins the explicit deny for IP domain
// literals (D-SHARED-VALIDATE-004): no MTA lane in this repo implements RFC
// 5321 §5.1 literal routing, so structural acceptance would diverge from
// delivery reality. Previously [127.0.0.1] passed via the dot rule while
// [IPv6:::1] failed — an inconsistent accident, not a decision.
func TestValidateEmail_RejectsDomainLiterals(t *testing.T) {
	// Literals mail.ParseAddress accepts reach validateEmailDomain and must be
	// denied there by the explicit literal check.
	for _, email := range []string{"user@[127.0.0.1]", "user@[192.0.2.10]"} {
		err := ValidateEmail(email)
		if err == nil {
			t.Errorf("ValidateEmail(%q) = nil, want DOMAIN_LITERAL rejection", email)
			continue
		}
		ve, ok := err.(*ValidationError)
		if !ok {
			t.Errorf("ValidateEmail(%q): expected *ValidationError, got %T", email, err)
			continue
		}
		if ve.Code != "DOMAIN_LITERAL" {
			t.Errorf("ValidateEmail(%q) code = %q, want DOMAIN_LITERAL", email, ve.Code)
		}
	}

	// Literals the parser itself rejects must stay rejected (any code).
	for _, email := range []string{"user@[IPv6:::1]", "user@[2001:db8::1]"} {
		if err := ValidateEmail(email); err == nil {
			t.Errorf("ValidateEmail(%q) = nil, want rejection", email)
		}
	}
}
