package main

import "fmt"

type featureToggle struct {
	Key                  string   `json:"key"`
	Enabled              bool     `json:"enabled"`
	Description          string   `json:"description"`
	ChangeMode           string   `json:"changeMode"`
	DisableBehavior      string   `json:"disableBehavior"`
	Dependencies         []string `json:"dependencies"`
	ConfirmationRequired bool     `json:"confirmationRequired"`
}

func runFeature(c *cmdCtx, action string, args []string) error {
	switch action {
	case "list":
		return featureListCmd(c)
	case "get":
		return featureGetCmd(c, args)
	case "set":
		return featureSetCmd(c, args)
	default:
		return fmt.Errorf("unknown feature action: %s (try: list, get, set)", action)
	}
}

func featureListCmd(c *cmdCtx) error {
	toggles, err := loadFeatureToggles(c)
	if err != nil {
		return err
	}

	if c.json {
		return printOut(c, toggles)
	}

	if len(toggles) == 0 {
		fmt.Println("No feature toggles defined.")
		return nil
	}

	fmt.Printf("%-45s %-7s %s\n", "Key", "Enabled", "Description")
	for _, t := range toggles {
		fmt.Printf("%-45s %-7s %s\n", t.Key, enabledStr(t.Enabled), t.Description)
	}
	return nil
}

// featureGetCmd looks up a single toggle. There is no single-key GET route
// (only GET /admin/features list + PUT /admin/features/{key}), so it lists
// and matches locally — same pattern as resolveUserID.
func featureGetCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl feature get <key>")
	}
	key := args[0]

	toggles, err := loadFeatureToggles(c)
	if err != nil {
		return err
	}
	for _, t := range toggles {
		if t.Key == key {
			if c.json {
				return printOut(c, t)
			}
			if t.Description != "" {
				fmt.Printf("%s: %s — %s\n", t.Key, enabledStr(t.Enabled), t.Description)
			} else {
				fmt.Printf("%s: %s\n", t.Key, enabledStr(t.Enabled))
			}
			return nil
		}
	}
	return fmt.Errorf("no feature toggle found with key %q", key)
}

func featureSetCmd(c *cmdCtx, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: mailctl feature set <key> <on|off>")
	}
	key, val := args[0], args[1]

	var enabled bool
	switch val {
	case "on":
		enabled = true
	case "off":
		enabled = false
	default:
		return fmt.Errorf("value must be 'on' or 'off', got %q", val)
	}

	// Fetch the server-owned exact-key metadata before any mutation. Failure is
	// fail-closed: proceeding would silently bypass a newly added confirmation.
	toggles, err := loadFeatureToggles(c)
	if err != nil {
		return err
	}
	confirmationRequired := false
	found := false
	for _, feature := range toggles {
		if feature.Key == key {
			found = true
			confirmationRequired = feature.ConfirmationRequired
			break
		}
	}
	if !found {
		return fmt.Errorf("no feature toggle found with key %q", key)
	}
	if confirmationRequired {
		if !confirm(c, fmt.Sprintf("Set security feature %s to %s", key, val)) {
			return fmt.Errorf("cancelled")
		}
	}

	body := map[string]interface{}{"enabled": enabled}
	if err := c.client.Do("PUT", "/admin/features/"+key, body, nil); err != nil {
		return err
	}
	fmt.Printf("Feature %s set to %s.\n", key, val)
	return nil
}

func loadFeatureToggles(c *cmdCtx) ([]featureToggle, error) {
	var toggles []featureToggle
	if err := c.client.Do("GET", "/admin/features", nil, &toggles); err != nil {
		return nil, err
	}
	return toggles, nil
}
