// Package dbschema embeds the database schema-migration SQL files (V<NNN>__*.sql)
// and derives the schema version this binary EXPECTS the database to be at.
//
// Named dbschema (not "migrations") on purpose: this is the DATABASE SCHEMA
// version, distinct from the unrelated mailbox/data import "migration"
// (internal/migration, `mailctl migration`). The directory was renamed
// sql/migrations/ → sql/dbschema/ to match the package; the V<NNN>__*.sql
// filenames are unchanged (a stable, flyway-style contract).
//
// Why this exists: "what version should the DB be at" is a property of the
// migration files themselves, not a number to hand-maintain. Before this package
// there were two independent `expectedVersion = 1` constants (in the gateway's
// startup check and in the admin SchemaVersionStatus endpoint) that BOTH had to be
// bumped per migration — and both had already drifted stale (the files were at
// V004 while the constants said 1). Deriving the expected version from the
// embedded filenames makes adding a migration automatically bump it, with no
// constant to forget. The gateway (refuse-to-start guard), the admin API, and
// `mailctl schema check|apply` all read from this one source.
//
// The embed/version surface (this file) is pure-stdlib; the embedded SQL travels
// inside every binary, so `mailctl schema apply` can apply pending migrations on a
// server that has only the binary — no repo checkout. The one DB-touching helper,
// ReadCurrentVersion (read.go), uses pgx — but both importers (the gateway and
// mailctl) already depend on pgx, so it adds no transitive cost.
package dbschema

import (
	"embed"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

// All embedded V<NNN>__*.sql files. The glob deliberately includes V001 (the
// ~400KB collapsed baseline) so Pending(0) can describe a fresh database too.
// The .go files in this directory are not matched by *.sql.
//
//go:embed *.sql
var migrationFS embed.FS

// V<NNN>__<name>.sql — NNN is the integer version, the rest is a human label.
var filenameRe = regexp.MustCompile(`^V(\d+)__.+\.sql$`)

// Migration is one forward-migration file: its version, its filename, and the
// SQL to apply (which is expected to INSERT its own schema_migrations row, so
// applying it advances MAX(version) — guarded by the test).
type Migration struct {
	Version int
	Name    string // filename, e.g. "V004__rls_enable.sql"
	SQL     string
}

var (
	loadOnce sync.Once
	loaded   []Migration
)

// load parses every embedded migration once, ascending by version. A filename
// that does not match the V<NNN>__*.sql shape is a build-time mistake (the test
// asserts the set is well-formed), so it panics rather than silently skipping —
// a skipped migration is exactly the failure mode this package exists to prevent.
func load() []Migration {
	loadOnce.Do(func() {
		entries, err := migrationFS.ReadDir(".")
		if err != nil {
			panic("migrations: cannot read embedded FS: " + err.Error())
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			m := filenameRe.FindStringSubmatch(e.Name())
			if m == nil {
				panic("migrations: embedded SQL filename is not V<NNN>__*.sql: " + e.Name())
			}
			v, _ := strconv.Atoi(m[1])
			b, err := migrationFS.ReadFile(e.Name())
			if err != nil {
				panic("migrations: cannot read embedded " + e.Name() + ": " + err.Error())
			}
			loaded = append(loaded, Migration{Version: v, Name: e.Name(), SQL: string(b)})
		}
		sort.Slice(loaded, func(i, j int) bool { return loaded[i].Version < loaded[j].Version })
	})
	return loaded
}

// All returns every embedded migration, ascending by version (a fresh copy).
func All() []Migration {
	src := load()
	out := make([]Migration, len(src))
	copy(out, src)
	return out
}

// ExpectedVersion is the highest migration version compiled into this binary —
// the version the database must be at (or ahead of) for this binary to run.
// Returns 0 when no migrations are embedded.
func ExpectedVersion() int {
	all := load()
	if len(all) == 0 {
		return 0
	}
	return all[len(all)-1].Version
}

// Pending returns the migrations whose version is greater than applied,
// ascending — what must run to bring a database at `applied` up to
// ExpectedVersion(). Pending(0) on a fresh database includes the V001 baseline.
func Pending(applied int) []Migration {
	var out []Migration
	for _, m := range load() {
		if m.Version > applied {
			out = append(out, m)
		}
	}
	return out
}
