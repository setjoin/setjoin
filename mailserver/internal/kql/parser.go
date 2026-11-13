// Package kql provides a Kusto Query Language (KQL)-style parser for
// eDiscovery search. It supports Boolean operators (AND, OR, NOT),
// field-qualified terms (from:, subject:, body:, date:, mailbox:),
// quoted phrases, parenthesized groups, and date ranges.
//
// The parser produces an AST that can be converted to SQL WHERE clauses.
package kql

import (
	"fmt"
	"strings"
	"unicode"
)

// Resource bounds enforced by Parse. They are checked inside the recursive
// descent itself, so any hostile query terminates with a bounded parse error
// instead of exhausting the process on unbounded input (CWE-405) or
// overflowing the parser stack on runaway recursion (CWE-674). HTTP handlers
// translate these errors into a bounded 4xx response; the same caps are
// re-checked at the handler boundary (see Validate and internal/admin) so a
// compliance.write principal — and stored-query re-application per eDiscovery
// fetch — can never reach an unbounded parse.
const (
	// MaxQueryLength caps a query at 4,096 runes after whitespace trimming.
	MaxQueryLength = 4096
	// MaxNestingDepth caps parenthesized group nesting at 32 levels.
	MaxNestingDepth = 32
	// MaxTerms caps the total number of terms across all nesting levels at 128.
	MaxTerms = 128
)

// Operator represents the Boolean operator joining terms.
type Operator int

const (
	OpAnd Operator = iota
	OpOr
)

// Term is a single search term: a keyword, field-qualified value,
// negated term, or nested group.
type Term struct {
	Field    string  // empty = match against body_tsv/subject_tsv/from_tsv
	Text     string  // the search text
	Negate   bool    // preceded by NOT
	Group    *AST    // nested sub-expression
	DateFrom *string // for date:FROM..TO range syntax
	DateTo   *string
}

// AST is the root of a parsed KQL query.
type AST struct {
	Op    Operator
	Terms []Term
}

// Parser holds the state for the recursive-descent parser.
type Parser struct {
	input []rune
	pos   int
	depth int // current parenthesized nesting depth
	terms int // total terms appended across all nesting levels
}

// Parse parses a KQL query string into an AST.
//
// Resource bounds (MaxQueryLength, MaxNestingDepth, MaxTerms) are enforced
// here and during parsing: an over-bound query yields a descriptive bounded
// error, never unbounded recursion or allocation.
func Parse(query string) (*AST, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}
	if len([]rune(query)) > MaxQueryLength {
		return nil, fmt.Errorf("query exceeds maximum length of %d characters", MaxQueryLength)
	}
	p := &Parser{input: []rune(query)}
	ast, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	// If we didn't consume everything, there's trailing garbage.
	p.skipWhitespace()
	if p.pos < len(p.input) {
		return nil, fmt.Errorf("unexpected token at position %d: %q", p.pos, string(p.input[p.pos:]))
	}
	return ast, nil
}

// Validate enforces the resource bounds (MaxQueryLength, MaxNestingDepth,
// MaxTerms) at a handler boundary before a query is executed or stored for
// later re-application. It returns the same bounded errors Parse produces, so
// callers can reject an over-bound query with a 4xx and a descriptive
// message. This is the second enforcement layer: Parse re-checks every cap
// internally on each application, so a query stored before this check existed
// (or inserted directly) is still rejected identically on every re-parse
// instead of aborting the process.
func Validate(query string) error {
	_, err := Parse(query)
	return err
}

func (p *Parser) peek() rune {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *Parser) advance() rune {
	ch := p.peek()
	if ch != 0 {
		p.pos++
	}
	return ch
}

func (p *Parser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(p.input[p.pos]) {
		p.pos++
	}
}

// parseExpression parses a top-level or parenthesized expression.
// It reads terms separated by AND/OR operators.
func (p *Parser) parseExpression() (*AST, error) {
	var terms []Term
	op := OpAnd // default operator

	first, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	p.terms++
	if p.terms > MaxTerms {
		return nil, fmt.Errorf("query exceeds maximum of %d terms", MaxTerms)
	}
	terms = append(terms, first)

	for {
		p.skipWhitespace()
		if p.pos >= len(p.input) {
			break
		}

		// Check for closing paren
		if p.peek() == ')' {
			break
		}

		// Determine operator
		word := p.peekWord()
		upper := strings.ToUpper(word)
		switch upper {
		case "AND":
			if op == OpOr {
				return nil, fmt.Errorf("cannot mix AND and OR at the same level; use parentheses")
			}
			op = OpAnd
			p.consumeWord(word)
		case "OR":
			if op == OpAnd && len(terms) > 1 {
				return nil, fmt.Errorf("cannot mix AND and OR at the same level; use parentheses")
			}
			op = OpOr
			p.consumeWord(word)
		default:
			// Implicit AND
			if op == OpOr {
				return nil, fmt.Errorf("cannot mix AND and OR at the same level; use parentheses")
			}
			op = OpAnd
		}

		p.skipWhitespace()
		if p.pos >= len(p.input) || p.peek() == ')' {
			break
		}

		next, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		p.terms++
		if p.terms > MaxTerms {
			return nil, fmt.Errorf("query exceeds maximum of %d terms", MaxTerms)
		}
		terms = append(terms, next)
	}

	return &AST{Op: op, Terms: terms}, nil
}

// parseTerm parses a single term: field:value, NOT term, quoted string,
// parenthesized group, or bare keyword.
func (p *Parser) parseTerm() (Term, error) {
	p.skipWhitespace()
	if p.pos >= len(p.input) {
		return Term{}, fmt.Errorf("unexpected end of input")
	}

	// NOT prefix
	negate := false
	word := p.peekWord()
	if strings.ToUpper(word) == "NOT" {
		negate = true
		p.consumeWord(word)
		p.skipWhitespace()
		if p.pos >= len(p.input) || p.peek() == ')' {
			return Term{}, fmt.Errorf("expected term after NOT")
		}
	}

	// Parenthesized group
	if p.peek() == '(' {
		p.depth++
		if p.depth > MaxNestingDepth {
			return Term{}, fmt.Errorf("query exceeds maximum nesting depth of %d", MaxNestingDepth)
		}
		p.advance() // consume '('
		group, err := p.parseExpression()
		if err != nil {
			return Term{}, err
		}
		p.skipWhitespace()
		if p.pos >= len(p.input) || p.advance() != ')' {
			return Term{}, fmt.Errorf("expected ')' at position %d", p.pos)
		}
		p.depth--
		return Term{Negate: negate, Group: group}, nil
	}

	// Quoted string
	if p.peek() == '"' {
		text := p.parseQuoted()
		return Term{Negate: negate, Text: text}, nil
	}

	// Field-qualified: field: or field> or field<
	// Also check for field:value where value may be a word or quoted
	field, hasField := p.tryParseField()
	if hasField {
		p.skipWhitespace()
		if p.peek() == '"' {
			text := p.parseQuoted()
			t := Term{Negate: negate, Field: field, Text: text}
			// Handle date range
			if field == "date" {
				from, to := parseDateRange(text)
				t.DateFrom = from
				t.DateTo = to
			}
			return t, nil
		}
		// Parse value until next operator, whitespace, or paren
		val := p.parseBareWord()
		if val == "" {
			return Term{}, fmt.Errorf("expected value after %q:", field)
		}
		t := Term{Negate: negate, Field: field, Text: val}
		if field == "date" {
			from, to := parseDateRange(val)
			t.DateFrom = from
			t.DateTo = to
		}
		return t, nil
	}

	// Bare keyword
	text := p.parseBareWord()
	if text == "" {
		return Term{}, fmt.Errorf("expected term at position %d", p.pos)
	}
	return Term{Negate: negate, Text: text}, nil
}

// tryParseField checks if the current position is a field: prefix and returns
// the field name if so.
func (p *Parser) tryParseField() (string, bool) {
	saved := p.pos
	word := p.peekWord()
	if word == "" {
		return "", false
	}
	// Field names are lowercase alphabetic: from, subject, body, date, mailbox
	if !isAlpha(word) {
		return "", false
	}
	// Check if followed by ':'
	end := saved + len([]rune(word))
	if end >= len(p.input) || p.input[end] != ':' {
		return "", false
	}
	// Consume the field name and the colon
	p.consumeWord(word)
	p.advance() // consume ':'
	return strings.ToLower(word), true
}

// parseBareWord reads characters until a space, operator word, or paren.
func (p *Parser) parseBareWord() string {
	p.skipWhitespace()
	start := p.pos
	for p.pos < len(p.input) {
		ch := p.input[p.pos]
		if unicode.IsSpace(ch) || ch == '(' || ch == ')' || ch == '"' {
			break
		}
		// Stop before AND/OR/NOT keywords
		remaining := string(p.input[p.pos:])
		upper := strings.ToUpper(remaining)
		if strings.HasPrefix(upper, "AND ") || remaining == "AND" ||
			strings.HasPrefix(upper, "OR ") || remaining == "OR" ||
			strings.HasPrefix(upper, "NOT ") || remaining == "NOT" {
			// Check that it's a standalone word, not part of another word
			after := p.pos + 3 // length of AND/OR/NOT
			if after >= len(p.input) || p.pos+2 >= len(p.input) || unicode.IsSpace(p.input[after-1]) || p.input[after-1] == '(' || p.input[after-1] == ')' {
				break
			}
		}
		p.pos++
	}
	if p.pos == start {
		return ""
	}
	return string(p.input[start:p.pos])
}

// parseQuoted reads a double-quoted string, handling backslash escapes.
func (p *Parser) parseQuoted() string {
	p.advance() // consume opening '"'
	var sb strings.Builder
	for p.pos < len(p.input) {
		ch := p.advance()
		if ch == '"' {
			return sb.String()
		}
		if ch == '\\' && p.pos < len(p.input) {
			next := p.advance()
			sb.WriteRune(next)
		} else {
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

// peekWord returns the next contiguous alphabetic string without advancing.
func (p *Parser) peekWord() string {
	start := p.pos
	for start < len(p.input) && unicode.IsSpace(p.input[start]) {
		start++
	}
	end := start
	for end < len(p.input) && isAlphaRune(p.input[end]) {
		end++
	}
	if end == start {
		return ""
	}
	return string(p.input[start:end])
}

// consumeWord advances past the given word (must match).
func (p *Parser) consumeWord(word string) {
	p.skipWhitespace()
	runes := []rune(word)
	for i := 0; i < len(runes) && p.pos < len(p.input); i++ {
		if p.input[p.pos] == runes[i] {
			p.pos++
		} else {
			break
		}
	}
}

// isAlpha returns true if the word consists entirely of ASCII letters.
func isAlpha(s string) bool {
	for _, r := range s {
		if !isAlphaRune(r) {
			return false
		}
	}
	return len(s) > 0
}

func isAlphaRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// parseDateRange splits a value like "2024-01-01..2024-12-31" into from/to.
func parseDateRange(val string) (from, to *string) {
	parts := strings.SplitN(val, "..", 2)
	if len(parts) == 2 {
		f := strings.TrimSpace(parts[0])
		t := strings.TrimSpace(parts[1])
		if f != "" {
			from = &f
		}
		if t != "" {
			to = &t
		}
	}
	// If not a range, it's just a single date (treated as exact match — dateFrom only)
	if from == nil && to == nil && val != "" {
		from = &val
	}
	return
}
