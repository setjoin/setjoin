package pwhash

import (
	"errors"
	"strings"
	"testing"
)

func TestSM3HashAndVerify(t *testing.T) {
	hash, err := HashPasswordSM3("test-password-123")
	if err != nil {
		t.Fatalf("HashPasswordSM3: %v", err)
	}
	if !strings.HasPrefix(hash, "$sm3$") {
		t.Errorf("hash should start with $sm3$: got %q", hash)
	}

	err = VerifyPasswordSM3(hash, "test-password-123")
	if err != nil {
		t.Errorf("VerifyPasswordSM3: valid password failed: %v", err)
	}
}

func TestSM3WrongPassword(t *testing.T) {
	hash, err := HashPasswordSM3("correct-password")
	if err != nil {
		t.Fatalf("HashPasswordSM3: %v", err)
	}

	err = VerifyPasswordSM3(hash, "wrong-password")
	if err != ErrInvalidCredentials {
		t.Errorf("VerifyPasswordSM3 with wrong password: got %v, want ErrInvalidCredentials", err)
	}
}

func TestSM3FormatParsing(t *testing.T) {
	hash, err := HashPasswordSM3("password")
	if err != nil {
		t.Fatalf("HashPasswordSM3: %v", err)
	}

	parts := strings.Split(hash, "$")
	if len(parts) != 5 {
		t.Fatalf("invalid format: %q (len=%d, want 5 parts)", hash, len(parts))
	}
	if parts[0] != "" {
		t.Errorf("expected empty first part: got %q", parts[0])
	}
	if parts[1] != "sm3" {
		t.Errorf("expected sm3 prefix: got %q", parts[1])
	}
	if parts[2] != "100000" {
		t.Errorf("expected 100000 iterations: got %q", parts[2])
	}
	if len(parts[3]) == 0 {
		t.Error("salt should not be empty")
	}
	if len(parts[4]) == 0 {
		t.Error("hash should not be empty")
	}
}

func TestSM3IsSM3Hash(t *testing.T) {
	if IsSM3Hash("$sm3$100000$salt$hash") != true {
		t.Error("IsSM3Hash($sm3$...) should be true")
	}
	if IsSM3Hash("$2a$10$abc123") != false {
		t.Error("IsSM3Hash($2a$...) should be false")
	}
	if IsSM3Hash("") != false {
		t.Error("IsSM3Hash(\"\") should be false")
	}
}

func TestSM3Verify_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{"not sm3 prefix", "$2a$10$salt$hash"},
		{"too few parts", "$sm3$100000$salt"},
		{"too many parts", "$sm3$100000$salt$hash$extra"},
		{"invalid iterations", "$sm3$notanum$salt$hash"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyPasswordSM3(tt.hash, "any"); err == nil {
				t.Error("expected error for invalid format")
			}
		})
	}
}

func TestSM3ConstantTimeComparison(t *testing.T) {
	hash, err := HashPasswordSM3("password")
	if err != nil {
		t.Fatalf("HashPasswordSM3: %v", err)
	}

	if err := VerifyPasswordSM3(hash, "password"); err != nil {
		t.Errorf("correct password should verify: %v", err)
	}

	if err := VerifyPasswordSM3(hash, "password!"); err != ErrInvalidCredentials {
		t.Errorf("wrong password should not verify: got %v", err)
	}
}

func TestSM3DifferentHashes(t *testing.T) {
	h1, _ := HashPasswordSM3("password1")
	h2, _ := HashPasswordSM3("password2")
	if h1 == h2 {
		t.Error("different passwords should produce different hashes")
	}

	h1a, _ := HashPasswordSM3("password1")
	if err := VerifyPasswordSM3(h1, "password1"); err != nil {
		t.Errorf("h1 should verify: %v", err)
	}
	if err := VerifyPasswordSM3(h1a, "password1"); err != nil {
		t.Errorf("h1a should verify: %v", err)
	}
}

func TestVerifyPasswordSM3RejectsDegenerateParses(t *testing.T) {
	good, err := HashPasswordSM3("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPasswordSM3(good, "correct horse"); err != nil {
		t.Fatalf("baseline verify failed: %v", err)
	}
	if err := VerifyPasswordSM3(good, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v, want ErrInvalidCredentials", err)
	}
	// Degenerate-but-parseable forms must fail closed, never compare equal.
	for _, degenerate := range []string{
		"$sm3$0$" + good,  // zero iterations
		"$sm3$-3$" + good, // negative iterations
		"$sm3$100000$$",   // empty salt and digest
		"$sm3$100000$" + strings.SplitN(good, "$", 5)[3] + "$", // empty digest
	} {
		if err := VerifyPasswordSM3(degenerate, "correct horse"); err == nil || errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("degenerate hash %q accepted (err=%v); must fail closed", degenerate, err)
		}
	}
}

func TestSM3IterationsBelowFloorLoudFailsDegenerate(t *testing.T) {
	if !sm3IterationsBelowFloor("$sm3$0$a$b") {
		t.Fatal("zero iterations must report below-floor (loud), not silently fine")
	}
	if !sm3IterationsBelowFloor("$sm3$-5$a$b") {
		t.Fatal("negative iterations must report below-floor (loud)")
	}
	if sm3IterationsBelowFloor("not-a-hash") {
		t.Fatal("unparseable non-sm3 form must stay conservative false")
	}
}
