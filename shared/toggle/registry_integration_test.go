package toggle

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegistryLegacyWriteAndCutoverSerialize(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	const key = "legacy.concurrent_probe"
	cleanupRegistryProbe(t, ctx, pool, key)
	defer cleanupRegistryProbe(t, context.Background(), pool, key)

	// Schedule A: an N-1 statement owns the shared lock first. Cutover must
	// wait, then observe the committed unknown row and fail.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO feature_toggles(key,enabled) VALUES($1,true)`, key); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	cutover := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `SELECT feature_toggle_registry_mode_set('enforce',$1,1,'127.0.0.1','concurrency schedule A')`, RegistryDigest())
		cutover <- err
	}()
	assertStillBlocked(t, cutover, "cutover did not wait behind legacy write")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-cutover; !hasSQLState(err, "BZ262") {
		t.Fatalf("cutover after unknown commit = %v, want BZ262", err)
	}
	assertRegistryInvariant(t, ctx, pool)

	if _, err := pool.Exec(ctx, `SELECT feature_toggle_delete_unknown($1,1,'127.0.0.1','prepare schedule B')`, key); err != nil {
		t.Fatal(err)
	}

	// Schedule B: cutover owns the lock first. The N-1 statement must wait and
	// then be rejected by the row trigger after enforce commits.
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT feature_registry_lock()`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT feature_toggle_registry_mode_set('enforce',$1,1,'127.0.0.1','concurrency schedule B')`, RegistryDigest()); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	legacy := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `INSERT INTO feature_toggles(key,enabled) VALUES($1,true)`, key)
		legacy <- err
	}()
	assertStillBlocked(t, legacy, "legacy write did not wait behind cutover")
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-legacy; !hasSQLState(err, "BZ262") {
		t.Fatalf("legacy write after enforce commit = %v, want BZ262", err)
	}
	assertRegistryInvariant(t, ctx, pool)
}

func TestFeatureFlagsDatabaseLifecycle(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	const unknownKey = "legacy.runtime_reload_probe"
	cleanupRegistryProbe(t, ctx, pool, unknownKey)
	defer cleanupRegistryProbe(t, context.Background(), pool, unknownKey)

	if _, err := pool.Exec(ctx, `
		INSERT INTO feature_toggles(key,enabled)
		VALUES($1,true)
		ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled`, unknownKey); err != nil {
		t.Fatal(err)
	}
	flags, err := New(ctx, pool, map[string]bool{FeatureImap: false})
	if err != nil {
		t.Fatal(err)
	}
	if got := flags.RegistryMode(); got != RegistryObserve {
		t.Fatalf("initial registry mode = %q, want observe", got)
	}
	if got, source := flags.Resolve(FeatureImap); got || source != SourceEnvironment {
		t.Fatalf("environment override = (%v,%s), want (false,environment)", got, source)
	}
	if got, source := flags.Resolve(unknownKey); !got || source != SourceDatabase {
		t.Fatalf("observe unknown row = (%v,%s), want (true,database)", got, source)
	}

	if _, err := pool.Exec(ctx, `SELECT feature_toggle_delete_unknown($1,1,'127.0.0.1','runtime reload lifecycle')`, unknownKey); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT feature_toggle_registry_mode_set('enforce',$1,1,'127.0.0.1','runtime reload lifecycle')`, RegistryDigest()); err != nil {
		t.Fatal(err)
	}
	if err := flags.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := flags.RegistryMode(); got != RegistryEnforce {
		t.Fatalf("reloaded registry mode = %q, want enforce", got)
	}
	flags.OnNotify(unknownKey, true)
	if got, source := flags.Resolve(unknownKey); got || source != SourceDefault {
		t.Fatalf("enforce unknown notification = (%v,%s), want (false,default)", got, source)
	}
	flags.OnNotify(FeatureImap, true)
	if got, source := flags.Resolve(FeatureImap); got || source != SourceEnvironment {
		t.Fatalf("environment override after known notification = (%v,%s), want (false,environment)", got, source)
	}
}

func assertStillBlocked(t *testing.T, result <-chan error, message string) {
	t.Helper()
	select {
	case err := <-result:
		t.Fatalf("%s: completed early with %v", message, err)
	case <-time.After(100 * time.Millisecond):
	}
}

func assertRegistryInvariant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var mode string
	var unknown int
	if err := pool.QueryRow(ctx, `SELECT s.mode, count(ft.key) FILTER (WHERE feature_registry_classify(ft.key)='unknown')::int FROM feature_toggle_registry_state s LEFT JOIN feature_toggles ft ON true WHERE s.singleton GROUP BY s.mode`).Scan(&mode, &unknown); err != nil {
		t.Fatal(err)
	}
	if mode == "enforce" && unknown != 0 {
		t.Fatalf("invalid registry state: mode=enforce unknown=%d", unknown)
	}
}

func cleanupRegistryProbe(t *testing.T, ctx context.Context, pool *pgxpool.Pool, key string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `SELECT feature_toggle_registry_mode_set('observe','rollback-compatible',1,'127.0.0.1','test cleanup')`); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("restore observe: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT feature_toggle_delete_unknown($1,1,'127.0.0.1','test cleanup')`, key); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup unknown: %v", err)
	}
}

func hasSQLState(err error, state string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == state
}
