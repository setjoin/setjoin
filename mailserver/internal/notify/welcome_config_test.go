package notify

import "testing"

const sampleWelcomeJSON = `{
  "enabled": true,
  "default_locale": "zh",
  "locales": {
    "en": {"subject": "Hi", "body_text": "en body", "body_html": ""},
    "zh": {"subject": "你好", "body_text": "zh body", "body_html": "<p>zh</p>"}
  }
}`

func TestParseWelcomeConfig(t *testing.T) {
	cfg, err := parseWelcomeConfig([]byte(sampleWelcomeJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
	if cfg.DefaultLocale != "zh" {
		t.Errorf("default_locale = %q, want zh", cfg.DefaultLocale)
	}
	if cfg.Locales["zh"].Subject != "你好" || cfg.Locales["zh"].BodyHTML != "<p>zh</p>" {
		t.Errorf("zh locale parsed wrong: %+v", cfg.Locales["zh"])
	}
}

func TestResolveWelcomeTemplate(t *testing.T) {
	cfg, _ := parseWelcomeConfig([]byte(sampleWelcomeJSON))

	// Exact locale.
	if tmpl, ok := resolveWelcomeTemplate(cfg, "en"); !ok || tmpl.BodyText != "en body" {
		t.Errorf("en resolve: ok=%v tmpl=%+v", ok, tmpl)
	}
	// Unknown locale -> default_locale (zh).
	if tmpl, ok := resolveWelcomeTemplate(cfg, "fr"); !ok || tmpl.BodyText != "zh body" {
		t.Errorf("fr should fall back to default zh: ok=%v tmpl=%+v", ok, tmpl)
	}
	// Empty locale -> default_locale (zh).
	if tmpl, ok := resolveWelcomeTemplate(cfg, ""); !ok || tmpl.Subject != "你好" {
		t.Errorf("empty should use default zh: ok=%v tmpl=%+v", ok, tmpl)
	}
}

func TestResolveWelcomeTemplate_DisabledOrEmpty(t *testing.T) {
	disabled, _ := parseWelcomeConfig([]byte(`{"enabled": false, "default_locale":"en","locales":{"en":{"subject":"x","body_text":"y","body_html":""}}}`))
	if _, ok := resolveWelcomeTemplate(disabled, "en"); ok {
		t.Error("disabled config must not resolve a template")
	}
	empty, _ := parseWelcomeConfig([]byte(`{"enabled": true, "default_locale":"en","locales":{}}`))
	if _, ok := resolveWelcomeTemplate(empty, "en"); ok {
		t.Error("no locales must not resolve a template")
	}
}
