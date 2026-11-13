package jmap

import "setjoin.com/mailserver/internal/reducercall"

// buildReducerSQL is a test-only thin alias of reducercall.BuildReducerSQL,
// kept in-package so the existing caller_test.go / caller_scoped_test.go cases
// (which assert on the renderer and the SELECT fn($1) shape) continue to compile
// and run unchanged after the reducer-call seam was lifted into
// internal/reducercall. Production jmap code constructs reducercall.PoolCaller
// directly, so this is referenced only by tests.
func buildReducerSQL(fn string, n int) string {
	return reducercall.BuildReducerSQL(fn, n)
}
