package scim

import (
	"testing"
)

func TestParseFilter_eq(t *testing.T) {
	node, err := parseFilter(`userName eq "alice@example.com"`)
	if err != nil {
		t.Fatalf("parseFilter: %v", err)
	}
	if node.Attribute != "userName" {
		t.Errorf("expected attr=userName, got %q", node.Attribute)
	}
	if node.Operator != "eq" {
		t.Errorf("expected op=eq, got %q", node.Operator)
	}
	if node.Value != "alice@example.com" {
		t.Errorf("expected value=alice@example.com, got %q", node.Value)
	}

	where, args, _ := nodeToSQL(node)
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d", len(args))
	}
	if args[0] != "alice@example.com" {
		t.Errorf("expected arg=alice@example.com, got %v", args[0])
	}
	if where != "u.username = $1" {
		t.Errorf("unexpected where: %s", where)
	}
}

func TestParseFilter_co(t *testing.T) {
	node, err := parseFilter(`emails co "acme"`)
	if err != nil {
		t.Fatalf("parseFilter: %v", err)
	}
	if node.Operator != "co" {
		t.Errorf("expected op=co, got %q", node.Operator)
	}
	if node.Value != "acme" {
		t.Errorf("expected value=acme, got %q", node.Value)
	}

	where, args, _ := nodeToSQL(node)
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d", len(args))
	}
	if args[0] != "%acme%" {
		t.Errorf("expected arg=%%acme%%, got %v", args[0])
	}
	if where != "u.email ILIKE $1" {
		t.Errorf("unexpected where: %s", where)
	}
}

func TestParseFilter_sw(t *testing.T) {
	node, err := parseFilter(`displayName sw "John"`)
	if err != nil {
		t.Fatalf("parseFilter: %v", err)
	}
	if node.Operator != "sw" {
		t.Errorf("expected op=sw, got %q", node.Operator)
	}
	if node.Value != "John" {
		t.Errorf("expected value=John, got %q", node.Value)
	}

	where, args, _ := nodeToSQL(node)
	if args[0] != "John%" {
		t.Errorf("expected arg=John%%, got %v", args[0])
	}
	if where != "u.display_name ILIKE $1" {
		t.Errorf("unexpected where: %s", where)
	}
}

func TestParseFilter_pr(t *testing.T) {
	node, err := parseFilter(`externalId pr`)
	if err != nil {
		t.Fatalf("parseFilter: %v", err)
	}
	if node.Operator != "pr" {
		t.Errorf("expected op=pr, got %q", node.Operator)
	}

	where, args, _ := nodeToSQL(node)
	if len(args) != 0 {
		t.Errorf("expected 0 args for pr, got %d", len(args))
	}
	if where != "l.external_subject IS NOT NULL" {
		t.Errorf("unexpected where: %s", where)
	}
}

func TestParseFilter_InvalidOperator(t *testing.T) {
	_, err := parseFilter(`userName gt "test"`)
	if err == nil {
		t.Fatal("expected error for unsupported operator")
	}
}

func TestParseFilter_UnquotedValue(t *testing.T) {
	node, err := parseFilter(`userName eq alice`)
	if err != nil {
		t.Fatalf("parseFilter: %v", err)
	}
	if node.Value != "alice" {
		t.Errorf("expected value=alice, got %q", node.Value)
	}
}

func TestParseFilter_EmptyFilter(t *testing.T) {
	_, err := parseFilter("")
	if err == nil {
		t.Fatal("expected error for empty filter")
	}
}

func TestParseFilter_MissingValue(t *testing.T) {
	_, err := parseFilter(`userName eq`)
	if err == nil {
		t.Fatal("expected error for missing value")
	}
}

// TestAttributeToColumn_Allowlist verifies secret/unknown columns are rejected
// (ok=false) so they cannot be turned into a filter content oracle, while the
// real SCIM attributes stay allowlisted.
func TestAttributeToColumn_Allowlist(t *testing.T) {
	rejected := []string{"password_hash", "totp_secret_enc", "webauthn_credentials", "saml_name_id", "id; DROP"}
	for _, attr := range rejected {
		if _, ok := attributeToColumn(attr); ok {
			t.Errorf("attributeToColumn(%q) = ok, want rejected", attr)
		}
	}

	allowed := []string{"userName", "externalId", "emails", "active"}
	for _, attr := range allowed {
		if _, ok := attributeToColumn(attr); !ok {
			t.Errorf("attributeToColumn(%q) rejected, want allowed", attr)
		}
	}

	if _, _, ok := nodeToSQL(&FilterNode{Attribute: "password_hash", Operator: "pr"}); ok {
		t.Error("nodeToSQL(password_hash pr) = ok, want rejected")
	}
}
