// Package db provides Xinchuang database adapters behind a common interface.
// Build with -tags xinchuang to include domestic DB drivers; default build
// (no tags) uses PostgreSQL only with no additional dependencies.
package db

import (
	"context"
	"database/sql"
	"fmt"
)

// Adapter is the common interface for Xinchuang database drivers.
// All domestic databases implement this interface, wrapping their
// native drivers behind database/sql semantics.
type Adapter interface {
	// Open establishes a connection to the database.
	Open(dsn string) (*sql.DB, error)

	// Ping verifies the connection is alive.
	Ping(ctx context.Context) error

	// DriverName returns the driver name for database/sql registration.
	DriverName() string

	// SupportsNotify returns true if the database supports LISTEN/NOTIFY.
	SupportsNotify() bool

	// ErrorMapper returns the error code normalizer for this database.
	ErrorMapper() *ErrorMapper
}

// Config holds the Xinchuang database configuration.
type Config struct {
	Type string // "polardb", "postgres"
	DSN  string // database connection string (native format)
}

// NewAdapter creates the appropriate adapter for the given database type.
// PolarDB for PostgreSQL uses the standard PostgreSQL adapter — it is 100%
// wire-compatible with PostgreSQL 15.
func NewAdapter(cfg Config) (Adapter, error) {
	switch cfg.Type {
	case "polardb", "postgres", "":
		return newPostgresAdapter(cfg)
	default:
		return nil, fmt.Errorf("xinchuang/db: unknown database type %q", cfg.Type)
	}
}
