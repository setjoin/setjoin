// Package config provides a layered configuration loader using koanf.
// It merges three layers: defaults → YAML file → environment variables,
// with env vars having the highest priority.
//
// Exception: identity-critical keys (IdentityCriticalKeys) can be given file
// authority over the environment layer by the explicit opt-in
// Options.IdentityFileAuthority. The opt-in is DEFAULT OFF, so the documented
// env-highest precedence stays the shipped behavior until an operator (and
// the governing sign-off) explicitly enables it; when enabled, a conflicting
// environment value for those keys is not applied and is logged loudly
// instead of silently overriding the operator's YAML.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	fileprovider "github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// IdentityCriticalKeys lists the config keys whose merged value pins service
// identity: the hostname alone feeds the WebSocket origin pin, the OIDC
// issuer, the SMTP Received identity, and the outbound approval/booking/push
// URLs. Runtime environments frequently populate HOSTNAME themselves (Docker
// sets it to the container ID), so under the default env-highest precedence
// an ambient value silently replaces the operator's YAML pin.
//
// This list is the explicit compatibility boundary: every key NOT listed here
// keeps the documented env-highest precedence under every option setting.
// Extending it changes a documented behavior contract and requires its own
// explicit sign-off.
var IdentityCriticalKeys = []string{"hostname"}

// Options controls how koanf loads configuration.
type Options struct {
	// FilePath is an optional path to a YAML config file. Empty = no file.
	FilePath string

	// EnvPrefix filters env vars by prefix (e.g. "SETJOIN_" reads only
	// SETJOIN_DB_DSN, SETJOIN_LISTEN, etc.). Empty = read all env vars
	// and match against existing config keys.
	EnvPrefix string

	// Delimiter for nested keys. Default ".".
	Delimiter string

	// IdentityFileAuthority restores file (YAML) authority over the
	// environment layer for the keys in IdentityCriticalKeys. It is DEFAULT
	// OFF: the documented env-highest precedence applies to every key until
	// this is explicitly enabled, and enabling it changes that documented
	// contract, so it requires explicit operator sign-off.
	//
	// When enabled, an environment value that CONFLICTS with a value the
	// file explicitly pinned for an identity-critical key is NOT applied;
	// the conflict is surfaced as a loud warning naming the key and the
	// ignored environment variable. A key the file did not pin keeps the
	// existing ambient fallback behavior (for example a deploy that relies
	// on the machine HOSTNAME boots unchanged).
	IdentityFileAuthority bool
}

// Load builds a koanf instance with three merged layers:
//  1. Defaults map (lowest priority)
//  2. YAML file (optional, overrides defaults)
//  3. Environment variables (highest priority, overrides everything —
//     except identity-critical keys explicitly pinned by the file when
//     Options.IdentityFileAuthority is enabled)
//
// The defaults map uses dotted keys like "db.dsn", "smtp.inbound_addr".
// Returns the configured *koanf.Koanf ready for k.String(), k.Int(), etc.
func Load(defaults map[string]interface{}, opts Options) (*koanf.Koanf, error) {
	delim := opts.Delimiter
	if delim == "" {
		delim = "."
	}
	k := koanf.New(delim)

	// Layer 1: Defaults map. Set each key individually to avoid
	// the maps.Unflatten cross-key collision bug.
	for key, value := range defaults {
		k.Set(key, value)
	}

	// Layer 2: YAML file (optional). The file is loaded into its own layer
	// instance and then merged, so the file-authority gate below can inspect
	// the YAML layer itself instead of inferring pins from the merged
	// projection.
	var fileLayer *koanf.Koanf
	if opts.FilePath != "" {
		warnConfigFilePermissions(opts.FilePath)
		fileLayer = koanf.New(delim)
		if err := fileLayer.Load(fileprovider.Provider(opts.FilePath), yaml.Parser()); err != nil {
			return nil, err
		}
		if err := k.Merge(fileLayer); err != nil {
			return nil, err
		}
	}

	// File-authority capture (opt-in): with IdentityFileAuthority enabled,
	// record which identity-critical keys the YAML layer itself contains,
	// BEFORE the environment layer can mask them. Presence is detected in
	// the file layer, so an explicitly supplied value that happens to equal
	// the default still counts as a pin — comparing the merged value with
	// the defaults projection cannot make that distinction. A key the file
	// did not mention keeps the existing ambient fallback behavior.
	filePinned := map[string]bool{}
	if opts.IdentityFileAuthority && fileLayer != nil {
		for _, key := range IdentityCriticalKeys {
			if fileLayer.Exists(key) {
				filePinned[key] = true
			}
		}
	}

	// Layer 3: Environment variables (highest priority).
	applyEnvOverrides(k, opts.EnvPrefix, filePinned)

	return k, nil
}

// warnConfigFilePermissions surfaces a permissive or symlinked config file at
// the one central chokepoint every service loads through. The YAML config is
// the most secret-dense file in a deployment (JWT_SECRET, DB_ENCRYPTION_KEY,
// AUDIT_HMAC_KEY all live here), so the required posture is the same one
// mailctl enforces for backups: a regular, non-symlink, owner-only (0600)
// file. Enforcement is deliberately NOT applied here (deployment tooling may
// legitimately create the file before tightening it), but an operator leaving
// it group/world-readable or pointing it at a symlink is warned loudly at
// every boot instead of silently accepted.
func warnConfigFilePermissions(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		// Let the provider's own load error surface the missing file verbatim.
		return
	}
	if !info.Mode().IsRegular() {
		slog.Warn("config: config file is not a regular file (symlink or device?); "+
			"expected a regular 0600 file",
			"path", path, "mode", info.Mode().String())
		return
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		slog.Warn("config: config file is group/world readable; secrets in YAML "+
			"should be owner-only (0600)",
			"path", path, "mode", info.Mode().String())
	}
}

// applyEnvOverrides reads environment variables, transforms their names
// to koanf key paths, and sets keys that already exist in the config
// (set by defaults or YAML). This avoids loading hundreds of unrelated
// system env vars that can trigger maps.Unflatten merge bugs.
//
// filePinned holds the identity-critical keys (see IdentityCriticalKeys)
// that the file layer explicitly pinned under Options.IdentityFileAuthority.
// For those keys a conflicting environment value is not applied and is
// logged loudly; an empty map preserves the plain env-highest behavior.
func applyEnvOverrides(k *koanf.Koanf, prefix string, filePinned map[string]bool) {
	transform := makeEnvTransform(prefix)
	for _, envLine := range os.Environ() {
		parts := strings.SplitN(envLine, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := transform(parts[0], parts[1])
		if key == "" {
			continue
		}
		// Prefer the historical transform when it names a real key. If a
		// section itself contains an underscore (for example
		// oidc_provider.enabled or ad_sync.enabled), the first-underscore rule
		// cannot represent it. Fall back to the unique existing key whose
		// conventional ENV spelling (dots -> underscores) matches exactly.
		if !k.Exists(key) {
			key = existingKeyForEnv(k, prefix, parts[0])
		}
		// Only override keys that already exist in the config.
		if k.Exists(key) {
			if filePinned[key] {
				// File authority: the file explicitly pinned this
				// identity-critical key, so the ambient environment must
				// not silently replace it. Surface the conflict loudly and
				// keep the file value. Identical values are not a conflict.
				if envStr, ok := value.(string); ok && fmt.Sprint(k.Get(key)) != envStr {
					slog.Warn("config: file-pinned identity key conflicts with environment; keeping file value",
						"config_key", key,
						"env_var", parts[0])
				}
				continue
			}
			k.Set(key, value)
		}
	}
}

func existingKeyForEnv(k *koanf.Koanf, prefix, envKey string) string {
	if prefix != "" {
		if !strings.HasPrefix(envKey, prefix) {
			return ""
		}
		envKey = strings.TrimPrefix(envKey, prefix)
	}
	envKey = strings.ToUpper(envKey)
	var match string
	for _, candidate := range k.Keys() {
		if strings.ToUpper(strings.ReplaceAll(candidate, ".", "_")) != envKey {
			continue
		}
		if match != "" {
			// Ambiguous spellings must not silently select one config key.
			return ""
		}
		match = candidate
	}
	return match
}

// makeEnvTransform returns a function that transforms env var names
// to koanf key paths: FILTER by prefix, strip prefix, lowercase,
// convert __ → ., convert first _ → . for one-level nesting.
//
// Example: prefix "SETJOIN_" + key "SETJOIN_DB_MAX_CONNS" → "db.max_conns"
//
// For deeper nesting, use double underscore: TLS__AUTOCERT__DOMAINS.
//
// The prefix is a filter, not just a strip (Options.EnvPrefix contract): an
// env var WITHOUT the prefix is rejected so a prefix-isolated caller can
// never have an ambient variable (HOSTNAME, PATH, ...) override its config
// keys. Empty prefix = read all env vars.
func makeEnvTransform(prefix string) func(string, string) (string, interface{}) {
	return func(key string, value string) (string, interface{}) {
		if prefix != "" {
			if !strings.HasPrefix(key, prefix) {
				return "", value
			}
			key = strings.TrimPrefix(key, prefix)
		}
		key = strings.ToLower(key)
		key = strings.ReplaceAll(key, "__", ".")
		if idx := strings.Index(key, "_"); idx >= 0 {
			key = key[:idx] + "." + key[idx+1:]
		}
		// Filter out keys that would produce empty path segments.
		if key == "" {
			return "", value
		}
		for _, part := range strings.Split(key, ".") {
			if part == "" {
				return "", value
			}
		}
		return key, value
	}
}
