package notify

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WelcomeLocale is one language's editable content.
type WelcomeLocale struct {
	Subject  string `json:"subject"`
	BodyText string `json:"body_text"`
	BodyHTML string `json:"body_html"`
}

// WelcomeEmailConfig is the org-wide welcome-email configuration stored in
// system_config under the key "welcome_email" (seeded by V018).
type WelcomeEmailConfig struct {
	Enabled       bool                     `json:"enabled"`
	DefaultLocale string                   `json:"default_locale"`
	Locales       map[string]WelcomeLocale `json:"locales"`
}

// parseWelcomeConfig unmarshals the system_config JSONB value.
func parseWelcomeConfig(raw []byte) (WelcomeEmailConfig, error) {
	var cfg WelcomeEmailConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return WelcomeEmailConfig{}, fmt.Errorf("parse welcome_email config: %w", err)
	}
	return cfg, nil
}

// LoadWelcomeConfig reads the welcome_email config via get_system_config.
// found=false means the key is absent (SQL NULL) — which should not happen on a
// post-V018 database (the startup schema guard refuses to boot below V018), so
// callers log and no-op rather than synthesizing content.
func LoadWelcomeConfig(ctx context.Context, pool *pgxpool.Pool) (WelcomeEmailConfig, bool, error) {
	var raw []byte
	err := pool.QueryRow(ctx, `SELECT get_system_config('welcome_email')`).Scan(&raw)
	if err != nil {
		return WelcomeEmailConfig{}, false, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return WelcomeEmailConfig{}, false, nil
	}
	cfg, err := parseWelcomeConfig(raw)
	if err != nil {
		return WelcomeEmailConfig{}, false, err
	}
	return cfg, true, nil
}

// resolveWelcomeTemplate picks the template for locale, falling back to
// DefaultLocale then "en". ok=false when disabled or no usable locale exists.
func resolveWelcomeTemplate(cfg WelcomeEmailConfig, locale string) (WelcomeLocale, bool) {
	if !cfg.Enabled {
		return WelcomeLocale{}, false
	}
	for _, loc := range []string{locale, cfg.DefaultLocale, "en"} {
		if loc == "" {
			continue
		}
		if tmpl, ok := cfg.Locales[loc]; ok && tmpl.Subject != "" {
			return tmpl, true
		}
	}
	return WelcomeLocale{}, false
}
