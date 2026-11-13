// Package testutil provides shared helpers for E2E integration tests
// that connect to Docker-based test services.
package testutil

import (
	"os"
	"testing"
)

// SkipIfNoEnv skips the test unless ALL named environment variables are
// set (to any non-empty value).  Call this at the top of E2E tests so
// they are silently skipped when the Docker services aren't running.
func SkipIfNoEnv(t *testing.T, vars ...string) {
	t.Helper()
	for _, v := range vars {
		if os.Getenv(v) == "" {
			t.Skipf("skipping E2E test: %s not set", v)
		}
	}
}
