package kql

import (
	"fmt"
	"strings"
)

// BuildSQL converts a parsed AST into a SQL WHERE clause (without the
// leading "WHERE" keyword) and a slice of parameterized arguments.
// The caller can prepend "WHERE " and use $1, $2, ... placeholders.
//
// BuildSQL uses:
//   - plainto_tsquery('simple', $N) against the plain GIN tsvector columns for
//     keyword terms (2026-07-04 queue-B #2 revert: no ParadeDB/BM25 extension
//     is ever installed, so the prior @@@/paradedb.parse syntax threw on every
//     deployment; the AST's own AND/OR/NOT structure already provides the
//     boolean semantics, so each leaf only needs a lexeme/tokenized match —
//     recall over ranking, matching the eDiscovery contract)
//   - ILIKE for field-specific searches (from:, mailbox:)
//   - FTS column targeting for body: and subject: fields
//   - >= / <= for date: range filters
func BuildSQL(ast *AST) (sql string, args []interface{}) {
	argIdx := 1
	return buildSQL(ast, &argIdx)
}

// buildSQL is the recursive core. It threads a shared argIdx so nested groups
// continue placeholder numbering from where the outer call left off — restarting
// at 1 per group (the old bug) made inner $N collide with outer $N, binding the
// wrong args and dropping later values silently.
func buildSQL(ast *AST, argIdx *int) (sql string, args []interface{}) {
	if ast == nil || len(ast.Terms) == 0 {
		return "FALSE", nil
	}

	var parts []string

	for _, term := range ast.Terms {
		clause, termArgs := buildTerm(&term, argIdx)
		if clause != "" {
			parts = append(parts, clause)
			args = append(args, termArgs...)
		}
	}

	if len(parts) == 0 {
		return "FALSE", nil
	}

	joiner := " AND "
	if ast.Op == OpOr {
		joiner = " OR "
	}
	return "(" + strings.Join(parts, joiner) + ")", args
}

func buildTerm(term *Term, argIdx *int) (string, []interface{}) {
	if term.Group != nil {
		inner, innerArgs := buildSQL(term.Group, argIdx)
		if term.Negate {
			return fmt.Sprintf("NOT %s", inner), innerArgs
		}
		return inner, innerArgs
	}

	// Field-specific search
	switch term.Field {
	case "from":
		return buildILIKEClause("m.from_addr", term, argIdx)
	case "mailbox":
		return buildILIKEClause("mb.email", term, argIdx)
	case "subject":
		return buildFTSColumn("m.subject_tsv", term, argIdx)
	case "body":
		return buildFTSColumn("m.body_tsv", term, argIdx)
	case "date":
		return buildDateClause(term, argIdx)
	default:
		// Keyword term: search across all three FTS columns
		return buildAllFTS(term, argIdx)
	}
}

func buildILIKEClause(column string, term *Term, argIdx *int) (string, []interface{}) {
	op := "ILIKE"
	if term.Negate {
		op = "NOT ILIKE"
	}
	ph := fmt.Sprintf("$%d", *argIdx)
	*argIdx++
	return fmt.Sprintf("%s %s '%%%%' || %s || '%%%%'", column, op, ph), []interface{}{term.Text}
}

func buildFTSColumn(column string, term *Term, argIdx *int) (string, []interface{}) {
	op := "@@"
	if term.Negate {
		op = "NOT @@"
	}
	ph := fmt.Sprintf("plainto_tsquery('simple', $%d)", *argIdx)
	*argIdx++
	return fmt.Sprintf("%s %s %s", column, op, ph), []interface{}{term.Text}
}

func buildAllFTS(term *Term, argIdx *int) (string, []interface{}) {
	ph := fmt.Sprintf("plainto_tsquery('simple', $%d)", *argIdx)
	*argIdx++
	clause := fmt.Sprintf(
		"(m.body_tsv @@ %s OR m.subject_tsv @@ %s OR m.from_tsv @@ %s)",
		ph, ph, ph,
	)
	if term.Negate {
		clause = fmt.Sprintf("NOT %s", clause)
	}
	return clause, []interface{}{term.Text}
}

func buildDateClause(term *Term, argIdx *int) (string, []interface{}) {
	var parts []string
	var args []interface{}

	if term.DateFrom != nil {
		ph := fmt.Sprintf("$%d", *argIdx)
		*argIdx++
		parts = append(parts, fmt.Sprintf("m.received_at >= %s", ph))
		args = append(args, *term.DateFrom)
	}
	if term.DateTo != nil {
		ph := fmt.Sprintf("$%d", *argIdx)
		*argIdx++
		parts = append(parts, fmt.Sprintf("m.received_at <= %s", ph))
		args = append(args, *term.DateTo)
	}

	if len(parts) == 0 {
		return "", nil
	}
	if term.Negate {
		return fmt.Sprintf("NOT (%s)", strings.Join(parts, " AND ")), args
	}
	return "(" + strings.Join(parts, " AND ") + ")", args
}
