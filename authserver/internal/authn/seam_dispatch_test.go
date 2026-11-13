package authn

import (
	"os"
	"strings"
	"testing"
)

// TestBackupCodesSourceRoutesVerificationThroughPwhashSeam is the WP1
// regression guard: VerifyBackupCode must compare through the shared pwhash
// credential seam (pwhash.VerifyCredentialHash) and must never reintroduce a
// direct bcrypt.CompareHashAndPassword. The single sanctioned bcrypt use in
// this file is the WRITER (newBackupCodes' GenerateFromPassword); verify-side
// bcrypt calls fail here.
func TestBackupCodesSourceRoutesVerificationThroughPwhashSeam(t *testing.T) {
	src, err := os.ReadFile("backup_codes.go")
	if err != nil {
		t.Fatalf("read backup_codes.go: %v", err)
	}
	text := string(src)
	for line := range strings.SplitSeq(text, "\n") {
		if strings.Contains(line, "CompareHashAndPassword") {
			t.Fatalf("backup_codes.go reintroduced a direct hash comparison (must go through the pwhash credential seam): %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(text, "pwhash.VerifyCredentialHash") {
		t.Fatal("backup_codes.go no longer verifies through pwhash.VerifyCredentialHash")
	}
}
