//go:build !linux && !darwin

package config

// defaultConfigDir fallback for any other GOOS (build safety). setjoin ships on
// Linux (prod) + macOS (dev); this keeps cross-builds honest.
func defaultConfigDir() string { return "/etc/mail" }
