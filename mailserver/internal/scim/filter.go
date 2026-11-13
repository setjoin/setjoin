package scim

import (
	"fmt"
	"strings"
)

// FilterNode is a parsed SCIM filter expression (RFC 7644 §3.4.2.2).
// Supports single-level attribute op "value" expressions. Nested AND/OR not yet supported.
type FilterNode struct {
	Attribute string
	Operator  string
	Value     string
}

// parseFilter parses a SCIM filter string into a FilterNode.
// Supports operators: eq, co, sw, pr
// Handles quoted string values.
func parseFilter(filter string) (*FilterNode, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil, fmt.Errorf("empty filter")
	}

	parts := strings.SplitN(filter, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid filter format: expected 'attribute op value'")
	}

	attr := parts[0]
	op := parts[1]

	switch op {
	case "eq", "co", "sw":
		if len(parts) < 3 {
			return nil, fmt.Errorf("operator %q requires a value", op)
		}
		val := parts[2]
		// Strip surrounding double quotes
		val = strings.TrimSpace(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if val == "" {
			return nil, fmt.Errorf("empty value for operator %q", op)
		}
		return &FilterNode{Attribute: attr, Operator: op, Value: val}, nil

	case "pr":
		return &FilterNode{Attribute: attr, Operator: op}, nil

	default:
		return nil, fmt.Errorf("unsupported operator %q", op)
	}
}

// nodeToSQL translates a FilterNode into a SQL WHERE clause fragment.
// The returned string includes parameterized placeholders ($1, $2, ...).
// The returned args slice contains the values for those placeholders.
func nodeToSQL(node *FilterNode) (where string, args []interface{}, ok bool) {
	// Map SCIM attribute paths to DB columns via a strict allowlist. An unknown
	// attribute is rejected here (ok=false) rather than splicing an arbitrary
	// column name onto the users table — otherwise secret columns
	// (password_hash, totp_secret_enc, …) become eq/co/sw/pr content oracles.
	col, ok := attributeToColumn(node.Attribute)
	if !ok {
		return "", nil, false
	}

	switch node.Operator {
	case "eq":
		return fmt.Sprintf("%s = $1", col), []interface{}{node.Value}, true
	case "co":
		return fmt.Sprintf("%s ILIKE $1", col), []interface{}{"%" + node.Value + "%"}, true
	case "sw":
		return fmt.Sprintf("%s ILIKE $1", col), []interface{}{node.Value + "%"}, true
	case "pr":
		return fmt.Sprintf("%s IS NOT NULL", col), nil, true
	default:
		return "1=1", nil, true
	}
}

// attributeToColumn maps SCIM attribute paths to PostgreSQL column names via a
// strict allowlist. Unknown attributes return ok=false so the caller can reject
// the filter (RFC 7644 invalidFilter) instead of emitting a column for it.
func attributeToColumn(attr string) (string, bool) {
	switch attr {
	case "userName":
		return "u.username", true
	case "externalId":
		return "l.external_subject", true
	case "displayName":
		return "u.display_name", true
	case "name.givenName":
		return "u.first_name", true
	case "name.familyName":
		return "u.last_name", true
	case "emails", "emails.value":
		return "u.email", true
	case "title":
		return "u.job_title", true
	case "phoneNumbers.value":
		return "u.phone", true
	case "active":
		return "u.enabled", true
	case "id":
		return "u.id", true
	default:
		return "", false
	}
}
