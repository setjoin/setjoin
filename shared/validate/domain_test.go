package validate

import (
	"strings"
	"testing"
)

func TestValidateDomain_Valid(t *testing.T) {
	tests := []string{
		"example.com",
		"sub.example.com",
		"my-domain.com",
		"test.co.uk",
		"a.co",
		"xn--fsq.com", // IDN punycode
		"a.b",
	}
	for _, domain := range tests {
		t.Run(domain, func(t *testing.T) {
			if err := ValidateDomain(domain); err != nil {
				t.Errorf("ValidateDomain(%q) = %v, want nil", domain, err)
			}
		})
	}
}

func TestValidateDomain_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		code   string
	}{
		{"empty", "", "EMPTY_DOMAIN"},
		{"space only", "   ", "EMPTY_DOMAIN"},
		{"no dot tld", "no-dot", "NO_DOT"},
		{"leading hyphen", "-leading.com", "HYPHEN_EDGE"},
		{"trailing hyphen label", "trailing-.com", "HYPHEN_EDGE"},
		{"hyphen after dot", "a.-b.com", "HYPHEN_EDGE"},
		{"consecutive dots", "example..com", "EMPTY_LABEL"},
		{"underscore", "under_score.com", "INVALID_CHAR"},
		{"space in domain", "hello world.com", "INVALID_CHAR"},
		{"null byte", "x\x00y.com", "CONTROL_CHAR"},
		{"label too long", tooLongLabel(), "LABEL_TOO_LONG"},
		{"domain too long", tooLongDomainStr(), "DOMAIN_TOO_LONG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if err == nil {
				t.Errorf("ValidateDomain(%q) = nil, want error", tt.domain)
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

func TestValidateDomain_SegmentAt63(t *testing.T) {
	// 63-char segment is valid.
	label := strings.Repeat("a", 63)
	domain := label + ".com"
	if err := ValidateDomain(domain); err != nil {
		t.Errorf("ValidateDomain(%q) = %v, want nil", domain, err)
	}
}

func TestValidateDomain_SegmentAt64(t *testing.T) {
	// 64-char segment is invalid.
	label := strings.Repeat("a", 64)
	domain := label + ".com"
	err := ValidateDomain(domain)
	if err == nil {
		t.Fatal("expected error for 64-char label")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "LABEL_TOO_LONG" {
		t.Errorf("code = %q, want LABEL_TOO_LONG", ve.Code)
	}
}

// tooLongLabel returns a domain with a label > 63 chars.
func tooLongLabel() string { return strings.Repeat("a", 64) + ".com" }

// tooLongDomainStr returns a domain > 253 chars.
func tooLongDomainStr() string {
	// Build a domain > 253 chars.
	label := strings.Repeat("a", 50)
	s := label
	for len(s) < 260 {
		s += "." + label
	}
	return s
}
