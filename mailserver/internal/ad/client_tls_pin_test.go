package ad

// L2-C3 T6 pin (CONNECTOR-001, mailserver arm — manifest r1 Item 1, restated
// binding by r2): the mailserver AD client is already TLS-strict with no knob;
// the package's only job on this side is to PIN that strictness so a skip knob
// cannot be re-introduced silently. The other two T6 required outcomes are
// pinned by pre-existing tests in client_test.go:
//   - NewConfiguredClient rejects transport ∉ {ldaps, starttls}:
//     TestNewConfiguredClientRejectsUnsafeRuntimeShape
//   - Bind without a TLS session refuses before any credential byte:
//     TestBindRefusesPlaintextConnectionBeforeCredentials
// This file adds the third arm: the tls.Config the client builds carries
// NO InsecureSkipVerify — asserted as a source-shape guard over the package's
// non-test sources (mirrors the authserver connector's T2 source scan and the
// instantiation guards), so a skip field cannot reappear in this package
// without this guard failing.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuard_ADClientTLSConfigCarriesNoSkipVerify(t *testing.T) {
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolve package dir: %v", err)
	}
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// An *ast.Ident named InsecureSkipVerify covers every shape the
			// field can take: the composite-literal key (`InsecureSkipVerify:
			// true`), a selector (`cfg.InsecureSkipVerify`), and any local
			// re-declaration of the name.
			if id, ok := n.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
				pos := fset.Position(id.Pos())
				t.Errorf("%s:%d: InsecureSkipVerify appears in the AD client — "+
					"certificate verification is unconditional by contract "+
					"(CONNECTOR-001 T6); a skip knob must not be re-introduced",
					e.Name(), pos.Line)
			}
			return true
		})
	}
}
