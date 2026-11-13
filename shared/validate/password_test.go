package validate

import (
	"strings"
	"testing"
)

func TestValidatePassword_Valid(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false,
	}
	tests := []string{
		"Str0ngPass",
		"Abcdefg1",
		"P@ssw0rd!",
		"12345678Aa",
	}
	for i, pw := range tests {
		t.Run("case_"+string(rune('0'+i)), func(t *testing.T) {
			if err := ValidatePassword(pw, policy); err != nil {
				t.Errorf("ValidatePassword(%q) = %v, want nil", pw, err)
			}
		})
	}
}

func TestValidatePassword_TooShort(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8}
	err := ValidatePassword("Ab1!", policy)
	if err == nil {
		t.Fatal("expected error for short password")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_TOO_SHORT" {
		t.Errorf("code = %q, want PASSWORD_TOO_SHORT", ve.Code)
	}
}

func TestValidatePassword_MissingUppercase(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		RequireUppercase: true,
	}
	err := ValidatePassword("alllowercase1", policy)
	if err == nil {
		t.Fatal("expected error for missing uppercase")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_NO_UPPERCASE" {
		t.Errorf("code = %q, want PASSWORD_NO_UPPERCASE", ve.Code)
	}
}

func TestValidatePassword_MissingLowercase(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		RequireLowercase: true,
	}
	err := ValidatePassword("ALLLETTERS1", policy)
	if err == nil {
		t.Fatal("expected error for missing lowercase")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_NO_LOWERCASE" {
		t.Errorf("code = %q, want PASSWORD_NO_LOWERCASE", ve.Code)
	}
}

func TestValidatePassword_MissingDigit(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:    8,
		RequireDigit: true,
	}
	err := ValidatePassword("NoDigitsHere", policy)
	if err == nil {
		t.Fatal("expected error for missing digit")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_NO_DIGIT" {
		t.Errorf("code = %q, want PASSWORD_NO_DIGIT", ve.Code)
	}
}

func TestValidatePassword_MissingSpecial(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:      8,
		RequireSpecial: true,
	}
	err := ValidatePassword("NoSpecial1", policy)
	if err == nil {
		t.Fatal("expected error for missing special")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_NO_SPECIAL" {
		t.Errorf("code = %q, want PASSWORD_NO_SPECIAL", ve.Code)
	}
}

func TestValidatePassword_ContainsEmail(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:     8,
		DisallowEmail: "user@example.com",
	}
	err := ValidatePassword("MyUserPass1", policy)
	if err == nil {
		t.Fatal("expected error for password containing email local-part")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_CONTAINS_EMAIL" {
		t.Errorf("code = %q, want PASSWORD_CONTAINS_EMAIL", ve.Code)
	}
}

func TestValidatePassword_DefaultMinLength(t *testing.T) {
	// MinLength = 0 should default to 8.
	policy := PasswordPolicy{}
	err := ValidatePassword("Ab1", policy)
	if err == nil {
		t.Fatal("expected error for 3-char password with default min 8")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_TOO_SHORT" {
		t.Errorf("code = %q, want PASSWORD_TOO_SHORT", ve.Code)
	}
}

func TestValidatePassword_CaseInsensitiveEmail(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:     8,
		DisallowEmail: "User@Example.Com",
	}
	// "user" (lowercase) should still be rejected.
	err := ValidatePassword("myuserpass1", policy)
	if err == nil {
		t.Fatal("expected error for case-insensitive email match")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_CONTAINS_EMAIL" {
		t.Errorf("code = %q, want PASSWORD_CONTAINS_EMAIL", ve.Code)
	}
}

func TestValidatePassword_DomainPartRejection(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:     8,
		DisallowEmail: "user@example.com",
	}
	// Password containing the full domain should be rejected.
	err := ValidatePassword("myexample.com1", policy)
	if err == nil {
		t.Fatal("expected error for password containing full domain")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_CONTAINS_EMAIL" {
		t.Errorf("code = %q, want PASSWORD_CONTAINS_EMAIL", ve.Code)
	}
}

func TestValidatePassword_MaxLength(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8}
	long := strings.Repeat("A", PasswordMaxBytes) + "b1"
	err := ValidatePassword(long, policy)
	if err == nil {
		t.Fatal("expected error for overly long password")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_TOO_LONG" {
		t.Errorf("code = %q, want PASSWORD_TOO_LONG", ve.Code)
	}
}

func TestValidatePassword_MaxLengthCountsUTF8Bytes(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8}
	long := strings.Repeat("好", 25) + "Aa1!"
	err := ValidatePassword(long, policy)
	if err == nil {
		t.Fatal("expected a multibyte password above the byte ceiling to fail")
	}
	if ve, ok := err.(*ValidationError); !ok || ve.Code != "PASSWORD_TOO_LONG" {
		t.Fatalf("error = %#v, want PASSWORD_TOO_LONG", err)
	}
}

// TestValidatePassword_MinLengthCountsRunes pins the min-length unit: runes
// (the "characters" a user counts), not UTF-8 bytes. A 6-rune CJK password is
// 18 bytes and satisfied the old byte-counted floor of 8 with fewer characters
// than the policy promises (D-SHARED-VALIDATE-005). The max side stays bytes
// (bcrypt hashes bytes; see PasswordMaxBytes).
func TestValidatePassword_MinLengthCountsRunes(t *testing.T) {
	policy := PasswordPolicy{MinLength: 8}

	err := ValidatePassword("你好你你好你", policy) // 6 runes, 18 UTF-8 bytes
	if err == nil {
		t.Fatal("6-rune password must fail a min-8 policy even though it is 18 bytes")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if ve.Code != "PASSWORD_TOO_SHORT" {
		t.Errorf("code = %q, want PASSWORD_TOO_SHORT", ve.Code)
	}

	if err := ValidatePassword("你好你你好你你好", policy); err != nil { // 8 runes
		t.Errorf("8-rune password rejected by min-8 policy: %v", err)
	}
}
