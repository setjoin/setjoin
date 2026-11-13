package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ── Device ────────────────────────────────────────────────────────────

func runDevice(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/mam/devices", nil, &result); err != nil {
			return err
		}
		return printOut(c, result["devices"])

	case "show":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl device show <device_id>")
		}
		deviceID := args[0]
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/mdm/devices/"+deviceID, nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "events":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl device events <device_id>")
		}
		deviceID := args[0]
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/mam/devices/"+deviceID+"/events", nil, &result); err != nil {
			return err
		}
		return printOut(c, result["events"])

	case "policy":
		if len(args) < 2 {
			return fmt.Errorf("usage: mailctl device policy <set|unset> <device_id> [key] [value]")
		}
		subAction := args[0]
		deviceID := args[1]
		switch subAction {
		case "set":
			if len(args) < 4 {
				return fmt.Errorf("usage: mailctl device policy set <device_id> <key> <value>")
			}
			key := args[2]
			value := args[3]
			var result map[string]interface{}
			return cl.Do("PUT", "/admin/mam/devices/"+deviceID+"/policy",
				map[string]map[string]string{"policies": {key: value}}, &result)
		case "unset":
			if len(args) < 3 {
				return fmt.Errorf("usage: mailctl device policy unset <device_id> <key>")
			}
			key := args[2]
			var result map[string]interface{}
			return cl.Do("DELETE", "/admin/mam/devices/"+deviceID+"/policy/"+key, nil, &result)
		default:
			return fmt.Errorf("unknown device policy action: %s. Try: set, unset", subAction)
		}

	case "lock":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl device lock <device_id>")
		}
		deviceID := args[0]
		if !confirm(c, "Lock device "+deviceID) {
			return fmt.Errorf("cancelled")
		}
		var result map[string]interface{}
		return cl.Do("POST", "/admin/mam/devices/"+deviceID+"/lock", nil, &result)

	case "unlock":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl device unlock <device_id>")
		}
		deviceID := args[0]
		var result map[string]interface{}
		return cl.Do("POST", "/admin/mam/devices/"+deviceID+"/unlock", nil, &result)

	case "wipe":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl device wipe <device_id> [--level account|device]")
		}
		deviceID := args[0]
		fs := flag.NewFlagSet("device wipe", flag.ExitOnError)
		level := fs.String("level", "account", "Wipe level: account or device")
		if len(args) > 1 {
			fs.Parse(args[1:])
		}
		if *level != "account" && *level != "device" {
			return fmt.Errorf("level must be 'account' or 'device'")
		}
		if !confirm(c, fmt.Sprintf("Wipe device %s (level: %s)", deviceID, *level)) {
			return fmt.Errorf("cancelled")
		}
		var result map[string]interface{}
		return cl.Do("POST", "/admin/mdm/devices/"+deviceID+"/wipe",
			map[string]string{"level": *level}, &result)

	default:
		return fmt.Errorf("unknown device action: %s. Try: list, show, events, policy, lock, unlock, wipe", action)
	}
}

// ── Policy ────────────────────────────────────────────────────────────

func runPolicy(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/mam/policies", nil, &result); err != nil {
			return err
		}
		if !c.quiet {
			fmt.Println("Global policies:")
		}
		if err := printOut(c, result["global"]); err != nil {
			return err
		}
		if !c.quiet {
			fmt.Println("\nGroup policies:")
		}
		return printOut(c, result["groups"])

	case "set":
		if len(args) < 2 {
			return fmt.Errorf("usage: mailctl policy set <key> <value>")
		}
		key := args[0]
		value := args[1]
		var result map[string]interface{}
		return cl.Do("PUT", "/admin/mam/policies",
			map[string]map[string]string{"policies": {key: value}}, &result)

	case "group":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl policy group <list|set|unset> [args...]")
		}
		subAction := args[0]
		switch subAction {
		case "list":
			var result map[string]interface{}
			if err := cl.Do("GET", "/admin/mam/policies", nil, &result); err != nil {
				return err
			}
			return printOut(c, result["groups"])

		case "set":
			if len(args) < 5 {
				return fmt.Errorf("usage: mailctl policy group set <group_type> <group_id> <key> <value>")
			}
			groupType := args[1]
			groupID := args[2]
			key := args[3]
			value := args[4]
			var result map[string]interface{}
			return cl.Do("PUT", "/admin/mam/policies/group", map[string]interface{}{
				"group_type": groupType,
				"group_id":   parseInt64(groupID),
				"policies":   map[string]string{key: value},
			}, &result)

		case "unset":
			if len(args) < 4 {
				return fmt.Errorf("usage: mailctl policy group unset <group_type> <group_id> <key>")
			}
			groupType := args[1]
			groupID := args[2]
			key := args[3]
			var result map[string]interface{}
			return cl.Do("DELETE",
				"/admin/mam/policies/group/"+groupType+"/"+groupID+"/"+key,
				nil, &result)

		default:
			return fmt.Errorf("unknown policy group action: %s. Try: list, set, unset", subAction)
		}

	case "template":
		return policyTemplateCmd(c, args)

	default:
		return fmt.Errorf("unknown policy action: %s. Try: list, set, group, template", action)
	}
}

// ── Policy Templates ──────────────────────────────────────────────────

func policyTemplateCmd(c *cmdCtx, args []string) error {
	cl := c.client
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl policy template <save|load|list> [name]")
	}

	templatesDir, err := templateDir()
	if err != nil {
		return err
	}

	switch args[0] {
	case "save":
		if len(args) < 2 {
			return fmt.Errorf("usage: mailctl policy template save <name>")
		}
		name := args[1]

		// Fetch current policies from server
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/mam/policies", nil, &result); err != nil {
			return fmt.Errorf("failed to fetch policies: %w", err)
		}

		if err := os.MkdirAll(templatesDir, 0700); err != nil {
			return fmt.Errorf("create templates dir: %w", err)
		}

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal template: %w", err)
		}

		path := filepath.Join(templatesDir, name+".json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write template: %w", err)
		}
		if !c.quiet {
			fmt.Printf("Template saved: %s\n", path)
		}
		return nil

	case "load":
		if len(args) < 2 {
			return fmt.Errorf("usage: mailctl policy template load <name>")
		}
		name := args[1]
		path := filepath.Join(templatesDir, name+".json")

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read template %s: %w", name, err)
		}

		var tmpl map[string]interface{}
		if err := json.Unmarshal(data, &tmpl); err != nil {
			return fmt.Errorf("parse template: %w", err)
		}

		// Apply global policies
		if globalPolicies, ok := tmpl["global"].([]interface{}); ok {
			policies := make(map[string]string)
			for _, p := range globalPolicies {
				if pm, ok := p.(map[string]interface{}); ok {
					key, _ := pm["policy_key"].(string)
					val, _ := pm["policy_value"].(string)
					if key != "" {
						policies[key] = val
					}
				}
			}
			if len(policies) > 0 {
				var result map[string]interface{}
				if err := cl.Do("PUT", "/admin/mam/policies",
					map[string]map[string]string{"policies": policies}, &result); err != nil {
					return fmt.Errorf("apply global policies: %w", err)
				}
				if !c.quiet {
					fmt.Printf("Applied %d global policies from template %q\n", len(policies), name)
				}
			}
		}

		// Apply group policies
		if groupPolicies, ok := tmpl["groups"].([]interface{}); ok {
			for _, gp := range groupPolicies {
				if gpm, ok := gp.(map[string]interface{}); ok {
					groupType, _ := gpm["group_type"].(string)
					groupID := fmt.Sprintf("%v", gpm["group_id"])
					key, _ := gpm["policy_key"].(string)
					val, _ := gpm["policy_value"].(string)
					if groupType != "" && key != "" {
						var result map[string]interface{}
						cl.Do("PUT", "/admin/mam/policies/group", map[string]interface{}{
							"group_type": groupType,
							"group_id":   parseInt64(groupID),
							"policies":   map[string]string{key: val},
						}, &result)
					}
				}
			}
		}

		if !c.quiet {
			fmt.Printf("Template %q loaded.\n", name)
		}
		return nil

	case "list":
		entries, err := os.ReadDir(templatesDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("(no templates)")
				return nil
			}
			return err
		}
		if len(entries) == 0 {
			fmt.Println("(no templates)")
			return nil
		}
		for _, e := range entries {
			if !e.IsDir() && len(e.Name()) > 5 {
				if name, ok := strings.CutSuffix(e.Name(), ".json"); ok {
					fmt.Println(name)
				}
			}
		}
		return nil

	default:
		return fmt.Errorf("unknown template action: %s. Try: save, load, list", args[0])
	}
}

func templateDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot find config dir: %w", err)
	}
	return filepath.Join(configDir, "mailctl", "templates"), nil
}

func parseInt64(s string) int64 {
	// ponytail: silent-zero on parse error preserved intentionally (see AGENTS.md #45)
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
