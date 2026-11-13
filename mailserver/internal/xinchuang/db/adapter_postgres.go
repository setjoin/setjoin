package db

import (
	"context"
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type postgresAdapter struct {
	db     *sql.DB
	mapper *ErrorMapper
}

func newPostgresAdapter(cfg Config) (Adapter, error) {
	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, err
	}
	return &postgresAdapter{db: db, mapper: NewErrorMapper("postgres")}, nil
}

func (a *postgresAdapter) Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	a.db = db
	return db, nil
}

func (a *postgresAdapter) Ping(ctx context.Context) error { return a.db.PingContext(ctx) }
func (a *postgresAdapter) DriverName() string             { return "pgx" }
func (a *postgresAdapter) SupportsNotify() bool           { return true }
func (a *postgresAdapter) ErrorMapper() *ErrorMapper      { return a.mapper }
