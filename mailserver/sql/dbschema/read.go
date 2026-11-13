package dbschema

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the minimal surface ReadCurrentVersion needs — satisfied by
// *pgxpool.Pool, *pgx.Conn, and pgx.Tx. (This is the only pgx-touching part of the
// package; the embed/version functions stay pure-stdlib. Both importers — the
// mailserver gateway and mailctl — already depend on pgx, so this adds no cost.)
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ReadCurrentVersion returns MAX(schema_migrations.version), or 0 when the table
// does not exist yet (an unbaselined database — SQLSTATE 42P01). ANY OTHER error
// is returned to the caller, so a transient DB fault (permission denied,
// connection drop) is NEVER mislabelled as "unbaselined".
//
// This is the ONE read shared by the gateway's refuse-to-start guard, the admin
// SchemaVersionStatus endpoint, and `mailctl schema` — extracted so the three
// cannot diverge on the error path. They did: the admin endpoint silently
// swallowed the Scan error and reported current=0/everything-pending, identical to
// a genuinely empty DB, which could send an operator to re-run the baseline loader
// against a database that was merely momentarily unreachable.
func ReadCurrentVersion(ctx context.Context, q Querier) (int, error) {
	var v int
	if err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return 0, nil // no schema_migrations table = unbaselined DB
		}
		return 0, err
	}
	return v, nil
}
