package authn

import (
	"crypto/subtle"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// testTOTPSecret is a fixed base32 secret so codes are deterministic across runs.
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// codeAt returns the expected TOTP code for the test secret at time t.
func codeAt(t *testing.T, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(testTOTPSecret, at, totpValidateOpts)
	if err != nil {
		t.Fatalf("GenerateCodeCustom: %v", err)
	}
	return code
}

// TestValidateTOTPConstantTime_BehaviorUnchanged proves the constant-time
// compare accepts exactly the codes totp.Validate would and rejects the rest,
// i.e. the security fix did not change validation behaviour.
func TestValidateTOTPConstantTime_BehaviorUnchanged(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		code string
		at   time.Time
		want bool
	}{
		{"current code valid", codeAt(t, now), now, true},
		{"previous-window code valid (skew -1)", codeAt(t, now.Add(-30*time.Second)), now, true},
		{"next-window code valid (skew +1)", codeAt(t, now.Add(30*time.Second)), now, true},
		{"out-of-window code rejected", codeAt(t, now.Add(-120*time.Second)), now, false},
		{"wrong code rejected", "000000", now, false},
		{"empty code rejected", "", now, false},
		{"short code rejected", "123", now, false},
		{"long code rejected", "1234567", now, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateTOTPConstantTime(tt.code, testTOTPSecret, tt.at)
			if got != tt.want {
				t.Fatalf("validateTOTPConstantTime(%q) = %v, want %v", tt.code, got, tt.want)
			}
			// Parity with the original validator (totp.Validate) for "now":
			// the fix must accept/reject exactly what the old code did. Note
			// totp.Validate swallows the library's "input length" error and
			// returns false for wrong-length codes — our helper matches that.
			if tt.at.Equal(now) {
				if want := totp.Validate(tt.code, testTOTPSecret); got != want {
					t.Fatalf("constant-time result %v disagrees with totp.Validate %v for %q",
						got, want, tt.code)
				}
			}
		})
	}
}

// TestValidateTOTPConstantTime_WrongCodeNeverMatches fuzzes a window of wrong
// codes near the valid one to ensure off-by-one digit codes never validate
// (guards against a partial / prefix compare).
func TestValidateTOTPConstantTime_WrongCodeNeverMatches(t *testing.T) {
	now := time.Now()
	valid := codeAt(t, now)
	for _, wrong := range []string{
		"00" + valid[2:],
		valid[:5] + "0",
		"0" + valid[:5],
		valid + "0",
	} {
		if wrong == valid {
			continue
		}
		if validateTOTPConstantTime(wrong, testTOTPSecret, now) {
			t.Fatalf("wrong code %q (valid=%q) unexpectedly validated", wrong, valid)
		}
	}
}

// TestTOTPCompareIsConstantTime is a source-level guard proving the app-level
// TOTP compare goes through crypto/subtle.ConstantTimeCompare and never falls
// back to a plain string == on the submitted code. This fails against the old
// implementation (which compared codes with ==) and passes against the fix.
func TestTOTPCompareIsConstantTime(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "totp.go", nil, 0)
	if err != nil {
		t.Fatalf("parse totp.go: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == "validateTOTPConstantTime" {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("validateTOTPConstantTime not found in totp.go")
	}

	usesConstantTime := false
	ast.Inspect(fn, func(n ast.Node) bool {
		// Reject a plain == / != comparison between the submitted code and any
		// expected value — that is the timing leak the fix removes.
		if be, ok := n.(*ast.BinaryExpr); ok {
			if be.Op == token.EQL || be.Op == token.NEQ {
				if identName(be.X) == "code" || identName(be.Y) == "code" ||
					identName(be.X) == "expected" || identName(be.Y) == "expected" {
					t.Errorf("found timing-unsafe %s comparison on the TOTP code", be.Op)
				}
			}
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if identName(sel.X) == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
					usesConstantTime = true
				}
			}
		}
		return true
	})
	if !usesConstantTime {
		t.Error("validateTOTPConstantTime must use subtle.ConstantTimeCompare for the code compare")
	}

	// Sanity: the helper actually imported is the std constant-time primitive.
	if subtle.ConstantTimeCompare([]byte("abc"), []byte("abc")) != 1 ||
		subtle.ConstantTimeCompare([]byte("abc"), []byte("abd")) != 0 {
		t.Fatal("crypto/subtle.ConstantTimeCompare behaving unexpectedly")
	}
}

func identName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// ensure otp import stays referenced even if opts construction changes.
var _ = otp.DigitsSix
