package main

import "os"

// operatorDSNEnvKeys is the shared privileged-connection precedence for
// schema, pg_dump, and pg_restore. Native-RLS installs deliberately put the
// constrained setjoin_app credential in DB_DSN, so owner-capable connections
// must win. The direct legacy fallbacks keep pre-flip/permissive installs
// working, where those credentials are still the owner.
var operatorDSNEnvKeys = []string{
	"DB_DIRECT_OWNER_DSN",
	"DB_OWNER_DSN",
	"DB_DIRECT_DSN",
	"DB_DSN",
}

// resolveOperatorDSN returns an explicit flag value first, then the common
// owner-first environment precedence. An empty return means no source is set.
func resolveOperatorDSN(flagDSN string) string {
	if flagDSN != "" {
		return flagDSN
	}
	for _, key := range operatorDSNEnvKeys {
		if dsn := os.Getenv(key); dsn != "" {
			return dsn
		}
	}
	return ""
}
