package db

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// ErrorMapper normalizes database-specific errors into the project's ERRCODE
// contract. PolarDB for PostgreSQL speaks standard PostgreSQL SQLSTATEs
// natively, so the pass-through below IS the mapping: the driver-reported
// code is returned unchanged, never guessed.
type ErrorMapper struct {
	dbType string
}

// NewErrorMapper creates an ErrorMapper for the given database type.
func NewErrorMapper(dbType string) *ErrorMapper {
	return &ErrorMapper{dbType: dbType}
}

// MapDBError extracts the standard PostgreSQL ERRCODE (SQLSTATE) from a
// native driver error. PolarDB for PostgreSQL uses PG error codes natively,
// so the five-character SQLSTATE passes through unmodified.
//
// A nil error, or an error that is not a *pgconn.PgError (context
// cancellation, connection loss, driver-level faults), returns "" — "no
// SQLSTATE to classify" — rather than a fabricated mapping. Callers must
// treat "" as unknown and fail closed.
//
// The code is a string (the SQLSTATE alphabet includes letters), matching
// pgconn.PgError.Code exactly; no int round-trip is involved.
func (m *ErrorMapper) MapDBError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// DbType reports the database type this mapper was created for.
func (m *ErrorMapper) DbType() string {
	return m.dbType
}
