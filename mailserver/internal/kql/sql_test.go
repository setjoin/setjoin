// sql_test.go — 2026-07-04 queue-B #2 revert. BuildSQL emitted `@@@`/
// `paradedb.parse('simple', ...)` unconditionally with no fallback; since no
// live baseline ever installs the pg_search/ParadeDB extension, every KQL
// eDiscovery/content-search query threw "schema paradedb does not exist" on
// every deployment. Red-first: these assertions fail against the pre-fix
// sql.go (which emitted "@@@"/"paradedb.parse") and pass against the plain
// GIN + tsquery rewrite ("@@"/"plainto_tsquery").
package kql

import (
	"strings"
	"testing"
)

func assertNoParadeDB(t *testing.T, sql string) {
	t.Helper()
	if strings.Contains(sql, "@@@") {
		t.Errorf("BuildSQL emitted the ParadeDB-only @@@ operator (no fallback, throws without the extension): %q", sql)
	}
	if strings.Contains(sql, "paradedb.") {
		t.Errorf("BuildSQL emitted a paradedb.* call (no fallback, throws without the extension): %q", sql)
	}
	if !strings.Contains(sql, "@@") {
		t.Errorf("BuildSQL should use the plain tsquery @@ operator: %q", sql)
	}
}

func TestBuildSQL_KeywordTerm_UsesPlainGIN(t *testing.T) {
	ast, err := Parse("hello")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sql, args := BuildSQL(ast)
	assertNoParadeDB(t, sql)
	if !strings.Contains(sql, "plainto_tsquery('simple', $1)") {
		t.Errorf("expected plainto_tsquery('simple', $1), got %q", sql)
	}
	if len(args) != 1 || args[0] != "hello" {
		t.Errorf("args = %v, want [hello]", args)
	}
}

func TestBuildSQL_BodyField_UsesPlainGIN(t *testing.T) {
	ast, err := Parse(`body:quarterly`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sql, _ := BuildSQL(ast)
	assertNoParadeDB(t, sql)
	if !strings.Contains(sql, "m.body_tsv @@ plainto_tsquery") {
		t.Errorf("expected m.body_tsv @@ plainto_tsquery(...), got %q", sql)
	}
}

func TestBuildSQL_SubjectField_UsesPlainGIN(t *testing.T) {
	ast, err := Parse(`subject:quarterly`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sql, _ := BuildSQL(ast)
	assertNoParadeDB(t, sql)
	if !strings.Contains(sql, "m.subject_tsv @@ plainto_tsquery") {
		t.Errorf("expected m.subject_tsv @@ plainto_tsquery(...), got %q", sql)
	}
}

func TestBuildSQL_NegatedKeyword_UsesPlainGIN(t *testing.T) {
	ast, err := Parse("NOT hello")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sql, _ := BuildSQL(ast)
	assertNoParadeDB(t, sql)
	if !strings.Contains(sql, "NOT (m.body_tsv @@") {
		t.Errorf("expected negated all-column FTS clause, got %q", sql)
	}
}

func TestBuildSQL_BooleanCombination_UsesPlainGIN(t *testing.T) {
	ast, err := Parse(`from:boss AND (body:quarterly OR subject:report)`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sql, _ := BuildSQL(ast)
	assertNoParadeDB(t, sql)
}
