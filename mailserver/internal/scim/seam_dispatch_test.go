package scim

import (
	"os"
	"strings"
	"testing"
)

// TestServerSourceRoutesVerificationThroughPwhashSeam is the WP1 regression
// guard: authenticateToken must verify tokens through the shared pwhash
// credential seam (bcryptCompare = pwhash.VerifyCredentialHash) and must
// never reintroduce a direct bcrypt call. The wrapper definition is the only
// sanctioned seam binding; any other bcrypt use in server.go fails here.
func TestServerSourceRoutesVerificationThroughPwhashSeam(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	for line := range strings.SplitSeq(string(src), "\n") {
		if strings.Contains(line, "bcrypt.") {
			t.Fatalf("server.go reintroduced a direct bcrypt call (must go through the pwhash credential seam): %s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(string(src), "bcryptCompare = pwhash.VerifyCredentialHash") {
		t.Fatal("server.go no longer binds bcryptCompare to pwhash.VerifyCredentialHash")
	}
}
