// Package envutil provides shared environment variable and config helpers.
package envutil

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// Getenv reads an environment variable with a default fallback.
func Getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ParseBool parses common boolean string representations. An unset (empty)
// variable substitutes false silently — OFF is the project's safe default —
// but a set-yet-unparseable value is operator error and is now named loudly
// instead of silently becoming false (silent-substitution hardening: the
// substituted outcome is unchanged, only the diagnostics gain a signal).
func ParseBool(s string) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		if s != "" {
			slog.Warn("envutil: invalid boolean value; substituting false",
				"raw", s)
		}
		return false
	}
	return b
}

// ParseInt wraps strconv.Atoi with a default value on parse failure. Like
// ParseBool, an empty value substitutes the default silently; a non-empty
// unparseable value is logged loudly before the default is substituted.
func ParseInt(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		if s != "" {
			slog.Warn("envutil: invalid integer value; substituting default",
				"raw", s, "default", def)
		}
		return def
	}
	return n
}

// ParseDuration wraps time.ParseDuration with a default value on parse
// failure. Like ParseBool, an empty value substitutes the default silently;
// a non-empty unparseable value is logged loudly before the default is
// substituted.
func ParseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		if s != "" {
			slog.Warn("envutil: invalid duration value; substituting default",
				"raw", s, "default", def.String())
		}
		return def
	}
	return d
}

// RandomID returns a hex-encoded random string for unique identifiers.
func RandomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
