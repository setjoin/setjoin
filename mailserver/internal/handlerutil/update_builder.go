// Package handlerutil provides shared utilities for HTTP handlers,
// including a safe, allowlist-protected dynamic SQL UPDATE builder.
package handlerutil

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoFields is returned when an UpdateBuilder has no fields set.
var ErrNoFields = errors.New("no fields to update")

// ErrInvalidTable is returned when the table name is not in the allowlist.
var ErrInvalidTable = errors.New("table not in allowlist")

// ErrInvalidColumn is returned when a column name is not in the table's allowlist.
var ErrInvalidColumn = errors.New("column not in allowlist")

// ErrExtraWhereMisbound is returned when the extraWhere fragment's positional
// placeholders cannot bind exactly to the args Build assembles, so an
// ownership filter misbinding or a silently dropped extraArg fails closed
// here instead of executing.
var ErrExtraWhereMisbound = errors.New("extraWhere placeholders do not bind the assembled args")

// ErrRejectedValue is returned by the strict setters when a present field
// value is invalid. Unlike the plain setters, which keep the historical
// absent-field skip semantics, a strict setter never lets an out-of-policy
// value disappear silently from a successful request.
var ErrRejectedValue = errors.New("field value rejected")

// FieldUpdate represents a column name and its value for a dynamic UPDATE query.
type FieldUpdate struct {
	Column string
	Value  interface{}
}

// UpdateBuilder accumulates nullable field updates for a parameterized UPDATE query.
type UpdateBuilder struct {
	updates  []FieldUpdate
	rejected []string
}

// SetStr appends a string field update if the pointer is non-nil and non-empty.
func (b *UpdateBuilder) SetStr(col string, val *string) {
	if val != nil && *val != "" {
		b.updates = append(b.updates, FieldUpdate{col, *val})
	}
}

// SetStrStrict behaves like SetStr but treats a present-but-empty value as a
// rejected field instead of silently dropping it: it records the column and
// returns ErrRejectedValue so handlers can fail the request or report a
// per-field warning. A nil pointer stays an absent field and returns nil.
func (b *UpdateBuilder) SetStrStrict(col string, val *string) error {
	if val == nil {
		return nil
	}
	if *val == "" {
		b.rejected = append(b.rejected, col)
		return fmt.Errorf("%w: %s", ErrRejectedValue, col)
	}
	b.updates = append(b.updates, FieldUpdate{col, *val})
	return nil
}

// Rejected returns the columns whose present-but-invalid values were rejected
// by the strict setters instead of silently dropped.
func (b *UpdateBuilder) Rejected() []string {
	return b.rejected
}

// SetInt appends an int64 field update if the pointer is non-nil.
func (b *UpdateBuilder) SetInt(col string, val *int64) {
	if val != nil {
		b.updates = append(b.updates, FieldUpdate{col, *val})
	}
}

// SetIntMin appends an int64 field if pointer is non-nil and value >= min.
func (b *UpdateBuilder) SetIntMin(col string, val *int64, min int64) {
	if val != nil && *val >= min {
		b.updates = append(b.updates, FieldUpdate{col, *val})
	}
}

// SetBool appends a bool field update if the pointer is non-nil.
func (b *UpdateBuilder) SetBool(col string, val *bool) {
	if val != nil {
		b.updates = append(b.updates, FieldUpdate{col, *val})
	}
}

// SetIntVal appends an int field update if the pointer is non-nil.
func (b *UpdateBuilder) SetIntVal(col string, val *int) {
	if val != nil {
		b.updates = append(b.updates, FieldUpdate{col, *val})
	}
}

// Build validates the table and columns against the allowlist and builds the
// parameterized UPDATE query. Returns the query string, args slice, and any error.
func (b *UpdateBuilder) Build(table, idCol string, id int64, addUpdatedAt bool, extraWhere string, extraArgs ...interface{}) (string, []interface{}, error) {
	if len(b.updates) == 0 {
		return "", nil, ErrNoFields
	}

	allowedCols, ok := allowedColumns[table]
	if !ok {
		return "", nil, fmt.Errorf("%w: %s", ErrInvalidTable, table)
	}

	if !allowedCols[idCol] {
		return "", nil, fmt.Errorf("%w: %s.%s", ErrInvalidColumn, table, idCol)
	}

	for _, u := range b.updates {
		if !allowedCols[u.Column] {
			return "", nil, fmt.Errorf("%w: %s.%s", ErrInvalidColumn, table, u.Column)
		}
	}

	var setClauses []string
	var args []interface{}
	for i, u := range b.updates {
		setClauses = append(setClauses, u.Column+" = $"+strconv.Itoa(i+1))
		args = append(args, u.Value)
	}

	query := "UPDATE " + table + " SET " + strings.Join(setClauses, ", ")
	if addUpdatedAt {
		query += ", updated_at = now()"
	}
	argIdx := len(args) + 1
	args = append(args, id)
	query += " WHERE " + idCol + " = $" + strconv.Itoa(argIdx)
	if extraWhere != "" {
		args = append(args, extraArgs...)
		query += " AND " + extraWhere
	}

	if err := validateExtraWhere(extraWhere, len(extraArgs), len(args)); err != nil {
		return "", nil, err
	}

	return query, args, nil
}

// validateExtraWhere fails closed when the caller-supplied extraWhere
// fragment's positional placeholders cannot bind exactly to the args Build
// assembles. A future caller following a wrong index pattern (for example
// re-using the id placeholder's index for the first extraArg) fails here
// instead of silently misbinding an ownership filter, and extraArgs passed
// without an extraWhere clause are rejected instead of silently dropped.
func validateExtraWhere(extraWhere string, extraArgs, totalArgs int) error {
	if extraWhere == "" {
		if extraArgs > 0 {
			return fmt.Errorf("%w: %d extraArgs passed without an extraWhere clause", ErrExtraWhereMisbound, extraArgs)
		}
		return nil
	}
	maxIdx := 0
	for i := 0; i < len(extraWhere); i++ {
		if extraWhere[i] != '$' {
			continue
		}
		j := i + 1
		for j < len(extraWhere) && extraWhere[j] >= '0' && extraWhere[j] <= '9' {
			j++
		}
		if j == i+1 {
			continue // '$' not followed by digits
		}
		n, convErr := strconv.Atoi(extraWhere[i+1 : j])
		if convErr != nil {
			return fmt.Errorf("%w: %q", ErrExtraWhereMisbound, extraWhere)
		}
		if n > totalArgs {
			return fmt.Errorf("%w: placeholder $%d exceeds the %d bound args", ErrExtraWhereMisbound, n, totalArgs)
		}
		if n > maxIdx {
			maxIdx = n
		}
		i = j - 1
	}
	if extraArgs > 0 && maxIdx != totalArgs {
		return fmt.Errorf("%w: highest referenced placeholder $%d does not bind the %d extraArgs", ErrExtraWhereMisbound, maxIdx, extraArgs)
	}
	return nil
}

// BuildAndExec builds the query and executes it against the provided pool.
func (b *UpdateBuilder) BuildAndExec(ctx context.Context, pool *pgxpool.Pool, table, idCol string, id int64, addUpdatedAt bool, extraWhere string, extraArgs ...interface{}) (pgconn.CommandTag, error) {
	query, args, err := b.Build(table, idCol, id, addUpdatedAt, extraWhere, extraArgs...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	return pool.Exec(ctx, query, args...)
}

// allowedColumns maps table names to the set of allowed column names.
var allowedColumns = map[string]map[string]bool{
	"users": {
		"id":             true,
		"display_name":   true,
		"enabled":        true,
		"is_local_admin": true,
		"updated_at":     true,
	},
	"domains": {
		"id":                   true,
		"name":                 true,
		"is_local":             true,
		"is_primary":           true,
		"catch_all_mailbox_id": true,
		"dmarc_policy":         true,
		"mta_sts_policy":       true,
		"max_message_bytes":    true,
		"quota_bytes":          true,
		"updated_at":           true,
	},
	"departments": {
		"id":         true,
		"name":       true,
		"ldap_ou":    true,
		"parent_id":  true,
		"sort_order": true,
		"updated_at": true,
	},
	"mailboxes": {
		"id":                 true,
		"display_name":       true,
		"quota_bytes":        true,
		"spam_purge_days":    true,
		"deleted_purge_days": true,
		"enabled":            true,
		"litigation_hold":    true,
		"on_hold":            true,
		"sending_quota_day":  true,
		"updated_at":         true,
	},
}
