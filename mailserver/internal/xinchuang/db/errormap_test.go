//go:build xinchuang

package db

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestErrorMapper_PassthroughSQLSTATE pins the BROKEN-ERROR-NORMALIZATION-
// CONTRACT fix: the mapper returns the driver's SQLSTATE verbatim for real
// pg errors (never "" as before) and "" for non-pg errors — no guessed
// mappings. Security-relevant SQLSTATEs are named explicitly.
func TestErrorMapper_PassthroughSQLSTATE(t *testing.T) {
	m := NewErrorMapper("polardb")

	securityRelevant := []string{
		"42501", // insufficient_privilege
		"28000", // invalid_authorization_specification
		"28P01", // invalid_password
		"P0001", // raise_exception (reducer fail-closed gates)
		"23514", // check_violation
		"40001", // serialization_failure
	}
	for _, code := range securityRelevant {
		err := &pgconn.PgError{Code: code, Message: "test"}
		if got := m.MapDBError(err); got != code {
			t.Errorf("MapDBError(SQLSTATE %s) = %q, want verbatim pass-through", code, got)
		}
		// Wrapped errors must resolve identically (errors.As chain).
		wrapped := fmt.Errorf("reducer classify: %w", err)
		if got := m.MapDBError(wrapped); got != code {
			t.Errorf("MapDBError(wrapped %s) = %q, want %s", code, got, code)
		}
	}

	nonPg := []error{
		nil,
		errors.New("context canceled"),
		fmt.Errorf("conn busy: %w", errors.New("driver fault")),
	}
	for _, err := range nonPg {
		if got := m.MapDBError(err); got != "" {
			t.Errorf("MapDBError(%v) = %q, want empty (unknown, fail closed)", err, got)
		}
	}
}
