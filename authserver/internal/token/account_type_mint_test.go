// account_type_mint_test.go — Guest Accounts P13 minting guard: every
// access-token-minting Claims{} construction in this package sets AccountType,
// and the mint-site inventory itself is guarded — a NEW access-mint site that
// forgets the claim fails this test, not a production incident.
package token

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

func newGuardProvider(t *testing.T) *JWTProvider {
	t.Helper()
	return NewJWTProvider(
		"guard-test-secret-guard-test-secret",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"guard-test-issuer",
	)
}

// Round-trip: each of the package's access mint paths carries acct end to end.
func TestAccessMints_CarryAccountType(t *testing.T) {
	p := newGuardProvider(t)

	tok, err := p.IssueAccessCA(7, "g@x", false, nil, nil, nil, nil, AuthContext{}, nil, nil, jwtutil.AccountTypeGuest)
	if err != nil {
		t.Fatalf("IssueAccessCA: %v", err)
	}
	claims, err := p.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !claims.IsGuest() {
		t.Fatalf("IssueAccessCA dropped AccountType: %+v", claims)
	}

	imp, err := p.IssueImpersonation(7, "g@x", 1, jwtutil.AccountTypeGuest)
	if err != nil {
		t.Fatalf("IssueImpersonation: %v", err)
	}
	ic, err := p.Validate(imp)
	if err != nil {
		t.Fatalf("Validate(imp): %v", err)
	}
	if !ic.IsGuest() {
		t.Fatalf("IssueImpersonation dropped AccountType: %+v", ic)
	}

	// Member mints stay byte-compatible: empty acct is omitted.
	mtok, err := p.IssueAccessFull(7, "m@x", false, nil, nil, nil, nil, AuthContext{})
	if err != nil {
		t.Fatalf("IssueAccessFull: %v", err)
	}
	mc, _ := p.Validate(mtok)
	if mc.AccountType != "" {
		t.Fatalf("member mint carries a non-empty acct: %q", mc.AccountType)
	}
}

// Inventory guard: count TypeAccess Claims literals in the package's non-test
// sources. Exactly the known access-mint sites may exist (issueAccessSigned,
// IssueImpersonation); each must set AccountType. A new site changes the count
// and fails here with instructions.
func TestAccessMintSiteInventory(t *testing.T) {
	src := ""
	for _, f := range []string{"jwt.go", "refresh.go", "service.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src += string(b)
	}
	re := regexp.MustCompile(`(?s)p\.sign\(&jwtutil\.Claims\{.*?\}\)`)
	access := 0
	withAcct := 0
	for _, m := range re.FindAllString(src, -1) {
		if !strings.Contains(m, "TypeAccess") {
			continue
		}
		access++
		if strings.Contains(m, "AccountType") {
			withAcct++
		}
	}
	if access != 2 {
		t.Fatalf("access-token Claims literals = %d, inventory expects 2 (issueAccessSigned, IssueImpersonation). "+
			"New access mint site? Set AccountType there and bump this inventory.", access)
	}
	if withAcct != access {
		t.Fatalf("%d of %d access-mint Claims literals set AccountType — every access mint must (P13)", withAcct, access)
	}
}
