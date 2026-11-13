package dbschema

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestExpectedVersionMatchesDisk is the anti-drift guard: the version this
// binary expects must equal the highest V<NNN>__*.sql actually on disk. If
// someone adds V005 the expected version moves automatically; if the embed glob
// ever stops matching a file, this fails instead of the gateway silently
// accepting a stale database.
func TestExpectedVersionMatchesDisk(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	re := regexp.MustCompile(`^V(\d+)__.+\.sql$`)
	maxOnDisk := 0
	count := 0
	for _, e := range entries {
		m := re.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		count++
		v, _ := strconv.Atoi(m[1])
		if v > maxOnDisk {
			maxOnDisk = v
		}
	}
	if count == 0 {
		t.Fatal("no V<NNN>__*.sql migration files found on disk")
	}
	if got := ExpectedVersion(); got != maxOnDisk {
		t.Fatalf("ExpectedVersion()=%d but highest file on disk is V%03d — embed glob drifted from disk", got, maxOnDisk)
	}
	if got := len(All()); got != count {
		t.Fatalf("All() has %d migrations but %d V-files are on disk — embed glob missed a file", got, count)
	}
}

// TestMigrationsSortedAndUnique: All() must be ascending with no duplicate
// version numbers — Pending() and apply ordering depend on it.
func TestMigrationsSortedAndUnique(t *testing.T) {
	seen := map[int]string{}
	prev := -1
	for _, m := range All() {
		if m.Version <= prev {
			t.Fatalf("migrations not strictly ascending: %s (v%d) followed v%d", m.Name, m.Version, prev)
		}
		if other, dup := seen[m.Version]; dup {
			t.Fatalf("duplicate migration version %d: %s and %s", m.Version, other, m.Name)
		}
		seen[m.Version] = m.Name
		prev = m.Version
	}
}

// TestEveryMigrationAdvancesVersion is the load-bearing invariant for
// `mailctl schema apply`: each migration must INSERT its own schema_migrations
// row, so applying it advances MAX(version). A migration that forgot this would
// re-run forever (Pending never shrinks) — catch it here, not in production.
func TestEveryMigrationAdvancesVersion(t *testing.T) {
	ledgerInsert := regexp.MustCompile(
		`(?is)INSERT\s+INTO\s+(?:public\.)?schema_migrations\s*\(([^)]*)\)`,
	)
	for _, m := range All() {
		// e.g. INSERT INTO public.schema_migrations (version, applied_at) VALUES (4, now())
		needle := "schema_migrations"
		if !strings.Contains(m.SQL, needle) {
			t.Errorf("%s does not touch schema_migrations — applying it would not advance MAX(version)", m.Name)
			continue
		}
		// The inserted version must be this migration's own version, i.e. the SQL
		// contains "VALUES (N," or "VALUES (N " (the schema_migrations INSERT).
		vN := strconv.Itoa(m.Version)
		if !strings.Contains(m.SQL, "VALUES ("+vN+",") && !strings.Contains(m.SQL, "VALUES ("+vN+" ") {
			t.Errorf("%s inserts into schema_migrations but not version %d — apply would loop", m.Name, m.Version)
		}
		match := ledgerInsert.FindStringSubmatch(m.SQL)
		if len(match) != 2 {
			t.Errorf("%s does not use an explicit schema_migrations column list", m.Name)
			continue
		}
		columns := strings.Join(strings.Fields(strings.ReplaceAll(match[1], ",", " ")), ",")
		if columns != "version,applied_at" {
			t.Errorf(
				"%s writes schema_migrations columns %q, want version,applied_at (the unified ledger has no name column)",
				m.Name,
				columns,
			)
		}
	}
}

// TestPending covers the slice arithmetic the gateway guard and the CLI rely on.
func TestPending(t *testing.T) {
	expected := ExpectedVersion()
	if got := Pending(expected); len(got) != 0 {
		t.Fatalf("Pending(expected=%d) should be empty, got %d", expected, len(got))
	}
	if got := Pending(expected - 1); len(got) != 1 || got[0].Version != expected {
		t.Fatalf("Pending(expected-1) should be just the top migration, got %#v", got)
	}
	// A fresh DB (0) must include the baseline (V001) and reach the top.
	all := Pending(0)
	if len(all) != len(All()) {
		t.Fatalf("Pending(0) should include every migration incl. the baseline, got %d of %d", len(all), len(All()))
	}
}
