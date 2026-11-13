package updater

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/shared/release"
)

type PGMigrationConnection struct {
	conn *pgx.Conn
}

func (db *PGMigrationConnection) FeatureRegistryState(ctx context.Context) (FeatureRegistryState, error) {
	var state FeatureRegistryState
	err := db.conn.QueryRow(ctx, `
		SELECT s.mode,s.registry_digest,
		       count(*) FILTER (WHERE public.feature_registry_classify(t.key)='unknown')
		  FROM public.feature_toggle_registry_state s
		  LEFT JOIN public.feature_toggles t ON true
		 WHERE s.singleton
		 GROUP BY s.mode,s.registry_digest`).Scan(&state.Mode, &state.CatalogDigest, &state.UnknownRows)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return FeatureRegistryState{}, nil
		}
		return FeatureRegistryState{}, fmt.Errorf("read feature registry state: %w", err)
	}
	state.Present = true
	return state, nil
}

func OpenPGMigrationConnection(ctx context.Context, dsn string) (*PGMigrationConnection, error) {
	conn, err := pgx.Connect(ctx, strings.TrimSpace(dsn))
	if err != nil {
		return nil, fmt.Errorf("connect migration owner: %w", err)
	}
	return &PGMigrationConnection{conn: conn}, nil
}

func (db *PGMigrationConnection) Close(ctx context.Context) error {
	if db == nil || db.conn == nil {
		return nil
	}
	return db.conn.Close(ctx)
}

func (db *PGMigrationConnection) CurrentVersion(ctx context.Context) (int, error) {
	var version int
	if err := db.conn.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM public.schema_migrations`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read migration schema version: %w", err)
	}
	return version, nil
}

func (db *PGMigrationConnection) Evidence(ctx context.Context, version int) (*MigrationEvidence, error) {
	var evidence MigrationEvidence
	err := db.conn.QueryRow(ctx, `
		SELECT schema_version,release_id,manifest_digest,migration_id,migration_sha256
		  FROM public.upgrade_schema_migration_evidence
		 WHERE schema_version=$1`, version).Scan(&evidence.Version, &evidence.ReleaseID,
		&evidence.ManifestDigest, &evidence.MigrationID, &evidence.SHA256)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read schema migration evidence: %w", err)
	}
	return &evidence, nil
}

func (db *PGMigrationConnection) Apply(ctx context.Context, migration release.Migration, sql string, evidence MigrationEvidence) error {
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", migration.ID, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("execute migration %s: %w", migration.ID, err)
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0) FROM public.schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("verify migration %s version: %w", migration.ID, err)
	}
	if version != migration.ToSchema {
		return fmt.Errorf("migration %s recorded schema %d, want %d", migration.ID, version, migration.ToSchema)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.upgrade_schema_migration_evidence(
			schema_version,release_id,manifest_digest,migration_id,migration_sha256
		) VALUES($1,$2,$3,$4,$5)`, evidence.Version, evidence.ReleaseID,
		evidence.ManifestDigest, evidence.MigrationID, evidence.SHA256); err != nil {
		return fmt.Errorf("record migration %s evidence: %w", migration.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", migration.ID, err)
	}
	return nil
}
