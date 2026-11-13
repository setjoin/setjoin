package testutil

import "testing"

func TestSkipIfNoEnv(t *testing.T) {
	// With no env vars set, should not skip (vacuously true — all vars set)
	// We can't test the skip behaviour because it calls t.Skip which stops
	// the test.  Just verify the function exists and doesn't panic.
	SkipIfNoEnv(t) // trivially passes (no required vars)
}
