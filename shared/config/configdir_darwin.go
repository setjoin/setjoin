//go:build darwin

package config

// defaultConfigDir on macOS (dev). Preserves the former pal darwin path.
func defaultConfigDir() string { return "/usr/local/etc/mail" }
