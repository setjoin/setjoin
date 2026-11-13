package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/sql/dbschema"
)

// schemaCmd manages the DATABASE SCHEMA VERSION — the forward migrations
// (V<NNN>__*.sql) the gateway expects the database to be at. It is the operator-
// facing complement to the gateway's refuse-to-start guard: where the gateway
// only REFUSES to run on a stale schema, `mailctl schema check|apply` lets the
// operator see and close the gap during an upgrade.
//
// This is the schema-version concept, NOT the unrelated mailbox/data import
// "migration" (`mailctl migration`). It connects DIRECTLY to the database via
// DB_DSN (like `mailctl scim`), not through the gateway HTTP API — applying DDL
// is an out-of-band, privileged operation.
// runSchema is the modeDB entrypoint. It validates the action FIRST (so
// `schema bogus` returns its "unknown action" error without demanding a DSN —
// byte-identical with the pre-table dispatch), then the sub-handlers open the
// pool via c.openDB(), which applies schema's DB_DIRECT_DSN-preferred policy
// (resolveSchemaDSN).
func runSchema(c *cmdCtx, action string, args []string) error {
	switch action {
	case "check":
		return schemaCheck(c, args)
	case "apply":
		return schemaApply(c, args)
	default:
		return fmt.Errorf("unknown schema action: %s. Try: check, apply", action)
	}
}

// openSchemaDB connects to DB_DSN and reads the current schema version
// (MAX(schema_migrations.version)). A missing schema_migrations table means the
// baseline was never loaded — surfaced as a clear error, not a stack trace.
// resolveSchemaDSN picks the DSN for schema operations. DDL must run as the
// schema OWNER: under the constrained native-RLS shape install.sh writes
// (DB_DSN = setjoin_app), applying migrations over DB_DSN would create
// app-owned tables — NATIVE_RLS_FLIP_RUNBOOK.md footgun #1. So prefer the
// owner DSNs (direct first — DDL should bypass the PgBouncer transaction
// pool), then the legacy fallbacks, which ARE the owner on permissive/
// pre-flip installs. Same precedence as deploy/scripts/upgrade.sh.
// Pure + env-only so it is unit-testable without a database.
func resolveSchemaDSN() (string, error) {
	if dsn := resolveOperatorDSN(""); dsn != "" {
		return dsn, nil
	}
	return "", fmt.Errorf("DB_DIRECT_OWNER_DSN, DB_OWNER_DSN, DB_DIRECT_DSN or DB_DSN environment variable is required")
}

// openSchemaDB opens the schema pool via the dispatch-supplied lazy opener
// (which applies the DB_DIRECT_DSN-preferred policy) and reads the current schema
// version. The pool is pinned to c.db and closed by dispatch's deferred cleanup;
// callers must not close it themselves.
func openSchemaDB(c *cmdCtx, ctx context.Context) (*pgxpool.Pool, int, error) {
	pool, err := c.openDB()
	if err != nil {
		return nil, 0, err
	}
	// Shared read with the gateway + admin endpoint: 0 for an unbaselined DB
	// (handled by the current==0 refusal in apply), a distinct error otherwise.
	current, err := dbschema.ReadCurrentVersion(ctx, pool)
	if err != nil {
		return nil, 0, fmt.Errorf("reading schema version: %w", err)
	}
	return pool, current, nil
}

// schemaCheck reports current vs expected schema version and EXITS NON-ZERO when
// the database is behind — so an upgrade script / CI gate can detect drift
// programmatically (and `--json` makes it machine-readable).
func schemaCheck(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("schema check", flag.ExitOnError)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "JSON output")
	fs.Parse(args)

	ctx := context.Background()
	_, current, err := openSchemaDB(c, ctx)
	if err != nil {
		return err
	}
	// The pool is closed by dispatch's deferred cleanup (it owns c.db).

	expected := dbschema.ExpectedVersion()
	pending := dbschema.Pending(current)
	names := make([]string, 0, len(pending))
	for _, m := range pending {
		names = append(names, m.Name)
	}
	upToDate := current >= expected

	if asJSON {
		out, _ := json.Marshal(map[string]any{
			"current": current, "expected": expected, "up_to_date": upToDate, "pending": names,
		})
		fmt.Println(string(out))
	} else {
		fmt.Printf("database schema version: current=%d expected=%d\n", current, expected)
		if upToDate {
			fmt.Println("up to date")
		} else {
			fmt.Printf("BEHIND by %d migration(s): %s\n", len(pending), strings.Join(names, ", "))
			fmt.Println("apply with: mailctl schema apply")
		}
	}
	if !upToDate {
		os.Exit(1) // drift is a non-zero exit for upgrade/CI gating
	}
	return nil
}

// schemaApply applies every pending FORWARD migration (each in its own
// transaction, in version order) to bring the database up to ExpectedVersion().
// It refuses to run on a database with no baseline (load that out of band first),
// and confirms before changing schema unless --yes is given.
func schemaApply(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("schema apply", flag.ExitOnError)
	var yLong, yShort bool
	fs.BoolVar(&yLong, "yes", false, "skip confirmation")
	fs.BoolVar(&yShort, "y", false, "skip confirmation (short)")
	fs.Parse(args)
	// Merge the locally-parsed --yes/-y into the ctx flag that confirm() reads
	// (modeDB does not pre-parse global flags, so c.yes starts false here).
	if yLong || yShort {
		c.yes = true
	}

	ctx := context.Background()
	pool, current, err := openSchemaDB(c, ctx)
	if err != nil {
		return err
	}
	// The pool is closed by dispatch's deferred cleanup (it owns c.db).

	expected := dbschema.ExpectedVersion()
	if current == 0 {
		return fmt.Errorf("database has no baseline (schema version 0) — load it first:\n" +
			"  prod: deploy/scripts/install.sh\n" +
			"  dev:  bash scripts/load-test-schema.sh\n" +
			"then re-run 'mailctl schema apply' for the forward migrations")
	}

	pending := dbschema.Pending(current) // version > current; baseline (V001) excluded for current>=1
	if len(pending) == 0 {
		fmt.Printf("database schema is up to date (version %d)\n", current)
		return nil
	}

	names := make([]string, len(pending))
	for i, m := range pending {
		names[i] = m.Name
	}
	fmt.Printf("pending (current=%d → target=%d): %s\n", current, expected, strings.Join(names, ", "))
	if !confirm(c, "apply "+strconv.Itoa(len(pending))+" database schema migration(s)") {
		return fmt.Errorf("aborted")
	}

	for _, m := range pending {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("%s failed (rolled back, schema unchanged): %w", m.Name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", m.Name, err)
		}
		fmt.Printf("  applied %s\n", m.Name)
	}
	fmt.Printf("database schema is now at version %d\n", expected)
	return nil
}
