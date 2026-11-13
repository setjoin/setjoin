//go:build linux

package config

// defaultConfigDir is the on-disk config directory on Linux (standard + the
// xinchuang targets Kylin V10 / UOS V20 — all share /etc/mail). Replaces the
// former 15-method pal.Platform abstraction, of which only ConfigDir was ever
// consumed (geoip db, kerberos keytab, config.env).
func defaultConfigDir() string { return "/etc/mail" }
