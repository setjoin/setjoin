// sod_perm_map_guard_test.go — static (no-DB) drift guard for the SoD perm→class
// map that is hand-copied from Go into SQL.
//
// The authoritative perm→class map lives in Go (shared/permissions.PermClasses).
// Two SQL sites re-copy it inline: the enablement pre-flight scan
// (reducers/admin_sod_precheck.sql) and the request-path assignment trigger
// (dbschema/V219__exchange_assessment_sod_perm_map.sql — the current definition of
// sod_exclusion_guard()). A perm added to PermClasses but not to those copies is
// a silent SoD false-negative (a role spanning two classes slips past the span
// check because a perm is absent from the map). This test fails — naming the
// specific drifting perm — the instant either copy diverges from PermClasses.
//
// Mirrors admin_ca_guard_test.go arm 1 (static file scan, no DB).
//
// Run: go test ./internal/admin/ -run TestSoDPermMap
package admin

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"setjoin.com/shared/permissions"
)

const (
	sodReducerDir = "../../sql/reducers"
	sodSchemaDir  = "../../sql/dbschema"
)

// sodSupersededMaps are immutable already-applied migrations whose inline
// perm→class map is a historical snapshot and MUST NOT be kept in sync with
// the current PermClasses. Skipped by the drift sweep.
var sodSupersededMaps = map[string]struct{}{
	"V019__dengbao_sod.sql":             {},
	"V024__sod_exclusion_perm_span.sql": {},
	"V100__sod_guard_perm_map_sync.sql": {},
}

// map-row line regexes. Map entries live one-per-line as SQL VALUES rows, e.g.
//
//	('users.read',          'system'),
//	('mail.pipeline'),
//
// Anchoring to line start (after leading whitespace) isolates real map rows
// from string literals inside format()/RAISE, which begin with a quote, not '('.
var (
	sodPairLineRe   = regexp.MustCompile(`(?m)^\s*\('([^']+)'\s*,\s*'([^']+)'\)`)
	sodSingleLineRe = regexp.MustCompile(`(?m)^\s*\('([^']+)'\)\s*,?\s*$`)
	// A file carries the perm→class map if it declares the VALUES block under
	// either the CTE name (admin_sod_precheck) or the pcm alias (the guard fn).
	sodMapMarkerRe = regexp.MustCompile(`perm_class_map\(perm|pcm\(perm, sod_class\)`)
)

// expectedPairs flattens PermClasses into a set of "perm\x00class" keys.
func expectedPairs() map[string]struct{} {
	m := make(map[string]struct{})
	for perm, classes := range permissions.PermClasses {
		for _, c := range classes {
			m[perm+"\x00"+c] = struct{}{}
		}
	}
	return m
}

// expectedKeys is the set of classed perms (keys of PermClasses).
func expectedKeys() map[string]struct{} {
	m := make(map[string]struct{})
	for perm := range permissions.PermClasses {
		m[perm] = struct{}{}
	}
	return m
}

// pairsInFile returns the deduped set of (perm,class) pairs found as VALUES rows
// in src, keyed "perm\x00class". A file may repeat the block (the guard fn has
// two identical copies); the set collapses them.
func pairsInFile(src string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, g := range sodPairLineRe.FindAllStringSubmatch(src, -1) {
		m[g[1]+"\x00"+g[2]] = struct{}{}
	}
	return m
}

// sortedDiff returns keys present in got but not want, formatted for a message.
func sortedDiff(got, want map[string]struct{}) []string {
	var d []string
	for k := range got {
		if _, ok := want[k]; !ok {
			d = append(d, strings.ReplaceAll(k, "\x00", "→"))
		}
	}
	sort.Strings(d)
	return d
}

// assertPairs compares a file's pair set against expected, naming both drift
// directions so a future perm-add points at the exact SQL line to fix.
func assertPairs(t *testing.T, label string, got, want map[string]struct{}) {
	t.Helper()
	if missing := sortedDiff(want, got); len(missing) > 0 {
		t.Errorf("%s: perm→class pairs in PermClasses but MISSING from the SQL map — add them: %s",
			label, strings.Join(missing, ", "))
	}
	if extra := sortedDiff(got, want); len(extra) > 0 {
		t.Errorf("%s: perm→class pairs in the SQL map but NOT in PermClasses — remove them (or add to Go): %s",
			label, strings.Join(extra, ", "))
	}
}

// TestSoDPermMapPairsMatchPermClasses scans every live SQL copy of the perm→class
// map (auto-discovered across reducers/ + dbschema/, minus superseded migrations)
// and asserts each equals the flattened PermClasses. Goes red — naming the perm —
// if either the Go map or an SQL copy is edited without the other.
func TestSoDPermMapPairsMatchPermClasses(t *testing.T) {
	want := expectedPairs()
	checked := 0

	for _, dir := range []string{sodReducerDir, sodSchemaDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("cannot read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
				continue
			}
			if _, skip := sodSupersededMaps[e.Name()]; skip {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("%s: cannot read: %v", e.Name(), err)
				continue
			}
			body := string(src)
			if !sodMapMarkerRe.MatchString(body) {
				continue // not a perm→class map file
			}
			assertPairs(t, e.Name(), pairsInFile(body), want)
			checked++
		}
	}

	if checked == 0 {
		t.Fatal("no live perm→class map SQL files discovered — check the marker regex / paths")
	}
	t.Logf("checked %d live perm→class map file(s) against PermClasses", checked)
}

// TestSoDPrecheckClassedPermsMatchKeys asserts the classed_perms 1-tuple VALUES
// block in admin_sod_precheck.sql equals the key set of PermClasses. That block
// is the "which perms are classed at all" list; a classed perm absent from it
// would be mis-flagged as a no-class (unclassifiable) perm.
func TestSoDPrecheckClassedPermsMatchKeys(t *testing.T) {
	path := filepath.Join(sodReducerDir, "admin_sod_precheck.sql")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	body := string(src)

	// Scope to the classed_perms(perm) AS ( ... ) block so unrelated 1-tuples
	// (none today, but be robust) cannot leak in.
	start := strings.Index(body, "classed_perms(perm) AS (")
	if start < 0 {
		t.Fatal("classed_perms(perm) AS ( block not found in admin_sod_precheck.sql")
	}
	end := strings.Index(body[start:], "\n  ),")
	if end < 0 {
		t.Fatal("could not find end of classed_perms VALUES block")
	}
	block := body[start : start+end]

	got := make(map[string]struct{})
	for _, g := range sodSingleLineRe.FindAllStringSubmatch(block, -1) {
		got[g[1]] = struct{}{}
	}
	if len(got) == 0 {
		t.Fatal("no classed_perms 1-tuples parsed — check the block regex")
	}

	want := expectedKeys()
	if missing := sortedDiff(want, got); len(missing) > 0 {
		t.Errorf("admin_sod_precheck.sql classed_perms: perms in PermClasses but MISSING — add them: %s",
			strings.Join(missing, ", "))
	}
	if extra := sortedDiff(got, want); len(extra) > 0 {
		t.Errorf("admin_sod_precheck.sql classed_perms: perms listed but NOT in PermClasses — remove them: %s",
			strings.Join(extra, ", "))
	}
}
