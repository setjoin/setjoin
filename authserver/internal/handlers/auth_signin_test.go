package handlers

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// issueTokensWithFactors is the single HTTP success funnel; it MUST record a sign-in.
// Guard against a future edit silently dropping the recordSignIn call.
func TestIssueTokensWithFactorsRecordsSignIn(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "auth.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var funnel *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "issueTokensWithFactors" {
			funnel = fn
			break
		}
	}
	if funnel == nil {
		t.Fatal("issueTokensWithFactors not found")
	}

	recordsSignIn := false
	ast.Inspect(funnel.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "RecordSignIn" {
			recordsSignIn = true
			return false
		}
		ident, ok := call.Fun.(*ast.Ident)
		if ok && ident.Name == "recordSignIn" {
			recordsSignIn = true
			return false
		}
		return true
	})
	if !recordsSignIn {
		t.Error("issueTokensWithFactors must record a sign-in (RecordSignIn call missing)")
	}

	// The legacy logLoginEvent must be gone (folded into recordSignIn).
	hasLegacyLogLoginEvent := false
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "logLoginEvent" {
			hasLegacyLogLoginEvent = true
			break
		}
	}
	if hasLegacyLogLoginEvent {
		t.Error("logLoginEvent must be removed (subsumed by recordSignIn)")
	}
}
