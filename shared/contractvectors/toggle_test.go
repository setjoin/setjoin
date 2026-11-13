package contractvectors

import (
	"testing"

	"setjoin.com/shared/toggle"
)

func TestRecordToggle(t *testing.T) {
	type vector struct {
		Name   string `json:"name"`
		Input  any    `json:"input"`
		Output any    `json:"output"`
	}
	cases := []vector{}
	for _, c := range []struct {
		name, key string
		rows      map[string]bool
	}{
		{"registered_default_on", "feature.imap", nil},
		{"registered_default_off", "feature.drive", nil},
		{"database_row_overrides_default", "feature.drive", map[string]bool{"feature.drive": true}},
		{"unknown_observe_fallback", "feature.not_registered", nil},
		{"empty_key_observe_fallback", "", nil},
		{"unknown_row_observe", "future.toggle", map[string]bool{"future.toggle": false}},
	} {
		flags := toggle.NewStatic(c.rows)
		enabled, source := flags.Resolve(c.key)
		definition, found := toggle.Lookup(c.key)
		cases = append(cases, vector{c.name, map[string]any{"operation": "resolve", "key": c.key, "rows": c.rows, "mode": "observe"}, map[string]any{"enabled": enabled, "source": source, "registered": found, "definition": definition}})
	}
	notified := toggle.NewStatic(map[string]bool{"feature.drive": false})
	notified.OnNotify("feature.drive", true)
	enabled, source := notified.Resolve("feature.drive")
	cases = append(cases, vector{"notification_updates_row", map[string]any{"operation": "notify", "key": "feature.drive", "rows": map[string]bool{"feature.drive": false}, "enabled": true, "mode": "observe"}, map[string]any{"enabled": enabled, "source": source}})
	cases = append(cases, vector{"registry_digest", map[string]any{"operation": "registry"}, map[string]any{"definitions": toggle.Definitions(), "sha256": toggle.RegistryDigest()}})
	writeVectors(t, "toggle", cases)
}
