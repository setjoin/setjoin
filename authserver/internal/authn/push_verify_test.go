package authn

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestVerifyChallenge_InvalidNonceUniformError proves the unparseable-nonce path
// (which never reaches the DB) returns the single uniform ErrChallengeInvalid,
// not a distinguishable "invalid nonce" message. Non-skipped: no DB needed.
func TestVerifyChallenge_InvalidNonceUniformError(t *testing.T) {
	p := &NumberMatchPushProvider{} // pool nil — must not be reached for a bad nonce
	err := p.VerifyChallenge(context.Background(), 42, "not-hex-zz", "00")
	if err == nil {
		t.Fatal("a malformed nonce must be rejected")
	}
	if !errors.Is(err, ErrChallengeInvalid) {
		t.Errorf("malformed-nonce error = %q, want the uniform ErrChallengeInvalid", err)
	}
}

// TestVerifyChallenge_QueryScopedByUser is the source-level guard for the
// user-scoping fix: the FOR UPDATE challenge lookup must filter by user_id in
// SQL (so a nonce belonging to another user is never locked or compared), not by
// an after-the-fetch Go comparison. Against the OLD code (WHERE nonce = $1 only,
// then `challenge.UserID != userID` in Go) this fails. The lookup now lives in
// verifyChallengeTx (the transactional core shared with VerifyChallengeWithLockout),
// so the guard also pins that VerifyChallenge delegates to it and cannot bypass
// the scoped query.
func TestVerifyChallenge_QueryScopedByUser(t *testing.T) {
	src := pushFuncBody(t, "verifyChallengeTx")

	if !strings.Contains(src, "user_id = $2") {
		t.Error("verifyChallengeTx's FOR UPDATE lookup must scope by user_id = $2 in SQL")
	}
	// The old post-fetch ownership branch must be gone — ownership is enforced in
	// the query now, so no `challenge.UserID != userID` comparison should remain.
	if strings.Contains(src, "challenge.UserID != userID") ||
		strings.Contains(src, "does not belong to this user") {
		t.Error("verifyChallengeTx must not re-check ownership in Go after the fetch; scope it in the query")
	}
	if !strings.Contains(pushFuncBody(t, "VerifyChallenge"), "verifyChallengeTx") {
		t.Error("VerifyChallenge must delegate to verifyChallengeTx so the scoped lookup cannot be bypassed")
	}
}

// TestVerifyChallenge_UniformErrors is the source-level guard for uniform error
// responses: every failure path (no-row, too-many-attempts, wrong-answer,
// bad-nonce) must return ErrChallengeInvalid, never a distinguishable string a
// caller could relay to differentiate "no such challenge" from "wrong answer".
func TestVerifyChallenge_UniformErrors(t *testing.T) {
	// Walk every return statement of both the wrapper and the transactional
	// core. Any returned error must be either ErrChallengeInvalid, the generic
	// "internal error" (tx begin/commit), or a wrapped internal cause. A
	// distinguishable string literal that names the outcome (e.g. "incorrect
	// challenge code", "no active challenge found") re-opens the oracle.
	banned := []string{
		"no active challenge found",
		"incorrect challenge code",
		"too many failed attempts",
		"challenge does not belong",
		"invalid nonce",
	}
	for _, name := range []string{"VerifyChallenge", "verifyChallengeTx"} {
		scanUniformErrors(t, name, banned)
	}
}

// scanUniformErrors fails the test if the named push.go function contains any
// banned (outcome-revealing) string literal.
func scanUniformErrors(t *testing.T, name string, banned []string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "push.go", nil, 0)
	if err != nil {
		t.Fatalf("parse push.go: %v", err)
	}
	var fn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		if d, ok := n.(*ast.FuncDecl); ok && d.Name.Name == name {
			fn = d
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatalf("%s not found in push.go", name)
	}

	ast.Inspect(fn, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		for _, b := range banned {
			if strings.Contains(lit.Value, b) {
				t.Errorf("%s returns distinguishable message %q — all failures must be uniform ErrChallengeInvalid", name, b)
			}
		}
		return true
	})

	// And the uniform sentinel must actually be referenced.
	if !strings.Contains(pushFuncBody(t, name), "ErrChallengeInvalid") && name == "VerifyChallenge" {
		t.Error("VerifyChallenge must return the uniform ErrChallengeInvalid on failure paths")
	}
}

// TestVerifyChallenge_AnswerComparedConstantTime proves the number-match answer
// is compared with crypto/subtle.ConstantTimeCompare, not a plain ==. The
// compare lives in verifyChallengeTx (shared with the lockout seam), so the
// guard pins it there and pins VerifyChallenge's delegation to it.
func TestVerifyChallenge_AnswerComparedConstantTime(t *testing.T) {
	body := pushFuncBody(t, "verifyChallengeTx")
	if !strings.Contains(body, "ConstantTimeCompare") {
		t.Error("verifyChallengeTx must compare the challenge answer with subtle.ConstantTimeCompare")
	}
	if !strings.Contains(pushFuncBody(t, "VerifyChallenge"), "verifyChallengeTx") {
		t.Error("VerifyChallenge must delegate to verifyChallengeTx so the constant-time compare cannot be bypassed")
	}
}

// pushFuncBody returns a flattened token stream of the named function in push.go
// (identifiers + literals), suitable for substring assertions.
func pushFuncBody(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, "push.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse push.go: %v", err)
	}
	for _, d := range src.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		var sb strings.Builder
		ast.Inspect(fn, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BasicLit:
				sb.WriteString(v.Value)
				sb.WriteString("\n")
			case *ast.Ident:
				sb.WriteString(v.Name)
				sb.WriteString(" ")
			case *ast.SelectorExpr:
				sb.WriteString(v.Sel.Name)
				sb.WriteString(" ")
			}
			return true
		})
		return sb.String()
	}
	t.Fatalf("function %q not found in push.go", name)
	return ""
}
