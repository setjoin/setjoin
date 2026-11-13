package kql

import (
	"regexp"
	"strconv"
	"testing"
)

func TestParseSimpleKeyword(t *testing.T) {
	ast, err := Parse("hello")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast == nil {
		t.Fatal("expected non-nil AST")
	}
	if ast.Op != OpAnd {
		t.Errorf("root Op = %v, want OpAnd", ast.Op)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}
	if ast.Terms[0].Text != "hello" {
		t.Errorf("Terms[0].Text = %q, want %q", ast.Terms[0].Text, "hello")
	}
}

func TestParseAND(t *testing.T) {
	ast, err := Parse("hello AND world")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast.Op != OpAnd {
		t.Errorf("root Op = %v, want OpAnd", ast.Op)
	}
	if len(ast.Terms) != 2 {
		t.Fatalf("len(Terms) = %d, want 2", len(ast.Terms))
	}
	if ast.Terms[0].Text != "hello" {
		t.Errorf("Terms[0].Text = %q, want %q", ast.Terms[0].Text, "hello")
	}
	if ast.Terms[1].Text != "world" {
		t.Errorf("Terms[1].Text = %q, want %q", ast.Terms[1].Text, "world")
	}
}

func TestParseOR(t *testing.T) {
	ast, err := Parse("alpha OR beta")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast.Op != OpOr {
		t.Errorf("root Op = %v, want OpOr", ast.Op)
	}
	if len(ast.Terms) != 2 {
		t.Fatalf("len(Terms) = %d, want 2", len(ast.Terms))
	}
}

func TestParseNOT(t *testing.T) {
	ast, err := Parse("NOT spam")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}
	if !ast.Terms[0].Negate {
		t.Error("expected Terms[0].Negate = true")
	}
	if ast.Terms[0].Text != "spam" {
		t.Errorf("Terms[0].Text = %q, want %q", ast.Terms[0].Text, "spam")
	}
}

func TestParseFieldQualified(t *testing.T) {
	ast, err := Parse("from:alice@example.com")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}
	if ast.Terms[0].Field != "from" {
		t.Errorf("Terms[0].Field = %q, want %q", ast.Terms[0].Field, "from")
	}
	if ast.Terms[0].Text != "alice@example.com" {
		t.Errorf("Terms[0].Text = %q, want %q", ast.Terms[0].Text, "alice@example.com")
	}
}

func TestParseFieldQualifiedQuoted(t *testing.T) {
	ast, err := Parse(`subject:"urgent password reset"`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}
	if ast.Terms[0].Field != "subject" {
		t.Errorf("Terms[0].Field = %q, want %q", ast.Terms[0].Field, "subject")
	}
	if ast.Terms[0].Text != "urgent password reset" {
		t.Errorf("Terms[0].Text = %q, want %q", ast.Terms[0].Text, "urgent password reset")
	}
}

func TestParseParenthesizedGroup(t *testing.T) {
	ast, err := Parse("(hello OR world) AND urgent")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast.Op != OpAnd {
		t.Errorf("root Op = %v, want OpAnd", ast.Op)
	}
	if len(ast.Terms) != 2 {
		t.Fatalf("len(Terms) = %d, want 2 (group + urgent)", len(ast.Terms))
	}
	if ast.Terms[0].Group == nil {
		t.Fatal("expected Terms[0].Group to be non-nil")
	}
	if ast.Terms[0].Group.Op != OpOr {
		t.Errorf("group Op = %v, want OpOr", ast.Terms[0].Group.Op)
	}
	if ast.Terms[1].Text != "urgent" {
		t.Errorf("Terms[1].Text = %q, want %q", ast.Terms[1].Text, "urgent")
	}
}

func TestParseComplexQuery(t *testing.T) {
	ast, err := Parse("from:phish@bad.com AND (urgent OR password) NOT safe")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast.Op != OpAnd {
		t.Errorf("root Op = %v, want OpAnd", ast.Op)
	}
	if len(ast.Terms) != 3 {
		t.Fatalf("len(Terms) = %d, want 3", len(ast.Terms))
	}
	// Term 0: from:phish@bad.com
	if ast.Terms[0].Field != "from" || ast.Terms[0].Text != "phish@bad.com" {
		t.Errorf("Terms[0] = field=%q text=%q, want from/phish@bad.com", ast.Terms[0].Field, ast.Terms[0].Text)
	}
	// Term 1: (urgent OR password)
	if ast.Terms[1].Group == nil || ast.Terms[1].Group.Op != OpOr {
		t.Error("Terms[1] should be an OR group")
	}
	// Term 2: NOT safe
	if !ast.Terms[2].Negate || ast.Terms[2].Text != "safe" {
		t.Errorf("Terms[2] = negate=%v text=%q, want negate=true text=safe", ast.Terms[2].Negate, ast.Terms[2].Text)
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Error("expected error for empty query")
	}
}

func TestParseImplicitAND(t *testing.T) {
	// Terms without explicit operator are ANDed
	ast, err := Parse("hello world urgent")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if ast.Op != OpAnd {
		t.Errorf("root Op = %v, want OpAnd", ast.Op)
	}
	if len(ast.Terms) != 3 {
		t.Fatalf("len(Terms) = %d, want 3", len(ast.Terms))
	}
}

// --- SQL Builder tests ---

func TestBuildSQLSimpleKeyword(t *testing.T) {
	ast, _ := Parse("hello")
	sql, args := BuildSQL(ast)
	if sql == "" {
		t.Fatal("expected non-empty SQL")
	}
	// Should produce FTS clauses for all three tsvector columns
	if !contains(sql, "body_tsv") || !contains(sql, "subject_tsv") || !contains(sql, "from_tsv") {
		t.Errorf("SQL should reference all three tsvector columns, got: %s", sql)
	}
	// 2026-07-04 queue-B #2: plain GIN + tsquery, not the ParadeDB-only @@@/
	// paradedb.parse (which throws — no deployment ever installs pg_search).
	if !contains(sql, "plainto_tsquery") {
		t.Errorf("SQL should use plainto_tsquery, got: %s", sql)
	}
	if !contains(sql, "@@") || contains(sql, "@@@") {
		t.Errorf("SQL should use the plain @@ operator (not ParadeDB's @@@), got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
	if args[0] != "hello" {
		t.Errorf("args[0] = %q, want %q", args[0], "hello")
	}
}

func TestBuildSQLAND(t *testing.T) {
	ast, _ := Parse("hello AND world")
	sql, args := BuildSQL(ast)
	if !contains(sql, "AND") {
		t.Errorf("SQL should contain AND, got: %s", sql)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
}

func TestBuildSQLOR(t *testing.T) {
	ast, _ := Parse("alpha OR beta")
	sql, args := BuildSQL(ast)
	if !contains(sql, "OR") {
		t.Errorf("SQL should contain OR, got: %s", sql)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
}

func TestBuildSQLNOT(t *testing.T) {
	ast, _ := Parse("NOT spam")
	sql, args := BuildSQL(ast)
	if !contains(sql, "NOT") {
		t.Errorf("SQL should contain NOT, got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
}

func TestBuildSQLFromField(t *testing.T) {
	ast, _ := Parse("from:alice@example.com")
	sql, args := BuildSQL(ast)
	if !contains(sql, "ILIKE") || !contains(sql, "from_addr") {
		t.Errorf("SQL should use ILIKE on from_addr, got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
}

func TestBuildSQLDateRange(t *testing.T) {
	ast, _ := Parse("date:2024-01-01..2024-12-31 key")
	sql, args := BuildSQL(ast)
	if !contains(sql, "received_at >=") || !contains(sql, "received_at <=") {
		t.Errorf("SQL should contain date range filters, got: %s", sql)
	}
	// Should have 3 args: $1 for dateFrom, $2 for dateTo, $3 for keyword
	if len(args) < 3 {
		t.Fatalf("len(args) = %d, want at least 3", len(args))
	}
}

func TestBuildSQLMailboxField(t *testing.T) {
	ast, _ := Parse("mailbox:inbox")
	sql, args := BuildSQL(ast)
	if !contains(sql, "email") || !contains(sql, "ILIKE") {
		t.Errorf("SQL should use ILIKE on mailbox email, got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
}

func TestBuildSQLNestedGroup(t *testing.T) {
	ast, _ := Parse("urgent AND (password OR reset)")
	sql, args := BuildSQL(ast)
	if !contains(sql, "AND") && !contains(sql, "OR") {
		t.Errorf("SQL should contain Boolean operators, got: %s", sql)
	}
	if len(args) != 3 {
		t.Fatalf("len(args) = %d, want 3 (urgent, password, reset), got %d", len(args), args)
	}
}

// TestBuildSQLNestedGroupPlaceholders is the regression test for the nested-group
// placeholder-collision bug: BuildSQL restarted argIdx at 1 on each recursive call,
// so inner $N collided with outer $N — `urgent AND (password OR reset)` referenced
// only $1,$2 while args held 3 values, binding the wrong arg and dropping "reset".
// The structural invariant: the set of distinct $N referenced in the SQL must be
// exactly {1..len(args)} — no collision (gap below len), no out-of-range $N.
func TestBuildSQLNestedGroupPlaceholders(t *testing.T) {
	cases := []string{
		"urgent AND (password OR reset)",
		"from:phish@bad.com AND (urgent OR password) NOT safe",
		"(a OR b) AND (c OR d)",
		"a AND (b AND (c OR d))",
	}
	re := regexp.MustCompile(`\$(\d+)`)
	for _, q := range cases {
		ast, _ := Parse(q)
		sql, args := BuildSQL(ast)
		seen := map[int]bool{}
		for _, m := range re.FindAllStringSubmatch(sql, -1) {
			n, _ := strconv.Atoi(m[1])
			seen[n] = true
		}
		if len(seen) != len(args) {
			t.Errorf("%q: distinct placeholders %v != len(args) %d\nSQL=%s args=%v", q, seen, len(args), sql, args)
		}
		for i := 1; i <= len(args); i++ {
			if !seen[i] {
				t.Errorf("%q: arg $%d (%v) never referenced in SQL: %s", q, i, args[i-1], sql)
			}
		}
	}
}

func TestBuildSQLComplex(t *testing.T) {
	ast, _ := Parse("from:phish@bad.com AND (urgent OR password) NOT safe")
	sql, args := BuildSQL(ast)
	if sql == "" {
		t.Fatal("expected non-empty SQL")
	}
	if len(args) != 4 {
		t.Fatalf("len(args) = %d, want 4 (phish@bad.com, urgent, password, safe)", len(args))
	}
	// from field should use ILIKE
	if !contains(sql, "ILIKE") {
		t.Errorf("SQL should contain ILIKE for from: field, got: %s", sql)
	}
}

func TestBuildSQLBodyField(t *testing.T) {
	ast, _ := Parse("body:confidential")
	sql, args := BuildSQL(ast)
	// body field should target body_tsv specifically
	if !contains(sql, "body_tsv") {
		t.Errorf("SQL should target body_tsv for body: field, got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
}

func TestBuildSQLSubjectField(t *testing.T) {
	ast, _ := Parse("subject:invoice")
	sql, args := BuildSQL(ast)
	// subject field should target subject_tsv specifically
	if !contains(sql, "subject_tsv") {
		t.Errorf("SQL should target subject_tsv for subject: field, got: %s", sql)
	}
	if len(args) != 1 {
		t.Fatalf("len(args) = %d, want 1", len(args))
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && searchSubstring(s, substr))
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestParseFieldDateRange(t *testing.T) {
	ast, err := Parse("date:2024-01-01..2024-12-31")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(ast.Terms) != 1 {
		t.Fatalf("len(Terms) = %d, want 1", len(ast.Terms))
	}
	if ast.Terms[0].Field != "date" {
		t.Errorf("Terms[0].Field = %q, want %q", ast.Terms[0].Field, "date")
	}
	if ast.Terms[0].DateFrom == nil || *ast.Terms[0].DateFrom != "2024-01-01" {
		t.Errorf("DateFrom = %v, want 2024-01-01", ast.Terms[0].DateFrom)
	}
	if ast.Terms[0].DateTo == nil || *ast.Terms[0].DateTo != "2024-12-31" {
		t.Errorf("DateTo = %v, want 2024-12-31", ast.Terms[0].DateTo)
	}
}
