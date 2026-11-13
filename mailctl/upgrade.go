package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"time"
)

func runUpgrade(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "status":
		var result map[string]any
		if err := cl.DoBounded("GET", "/admin/system/upgrades", nil, &result, 2<<20); err != nil {
			return err
		}
		return printOut(c, result)

	case "history":
		var result struct {
			History []map[string]any `json:"history"`
		}
		if err := cl.DoBounded("GET", "/admin/system/upgrades", nil, &result, 2<<20); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result.History)
		}
		for _, intent := range result.History {
			fmt.Printf("%v  %v  %v  %v\n", intent["createdAt"], intent["intentId"], intent["releaseId"], intent["state"])
		}
		return nil

	case "watch":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl upgrade watch <intent-id> [--interval 2s] [--timeout 10m]")
		}
		id, err := canonicalIntentID(args[0])
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("upgrade watch", flag.ContinueOnError)
		interval := fs.Duration("interval", 2*time.Second, "poll interval")
		timeout := fs.Duration("timeout", 10*time.Minute, "maximum watch duration")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *interval < 250*time.Millisecond || *interval > time.Minute || *timeout <= 0 || *timeout > 24*time.Hour {
			return fmt.Errorf("invalid watch interval or timeout")
		}
		deadline := time.Now().Add(*timeout)
		var priorState string
		for {
			var intent map[string]any
			if err := cl.DoBounded("GET", "/admin/system/upgrades/intents/"+id, nil, &intent, 1<<20); err != nil {
				return err
			}
			state, _ := intent["state"].(string)
			if state != priorState {
				if c.json {
					if err := printOut(c, intent); err != nil {
						return err
					}
				} else {
					fmt.Printf("%v  %s\n", intent["updatedAt"], state)
				}
				priorState = state
			}
			if terminalUpgradeState(state) {
				if state == "verified" || state == "rolled_back" || state == "cancelled" {
					return nil
				}
				return fmt.Errorf("upgrade reached terminal state %s", state)
			}
			if time.Now().Add(*interval).After(deadline) {
				return fmt.Errorf("upgrade watch timed out after %s", *timeout)
			}
			time.Sleep(*interval)
		}

	case "cancel":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl upgrade cancel <intent-id> --generation <n> --reason <text>")
		}
		id, err := canonicalIntentID(args[0])
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("upgrade cancel", flag.ContinueOnError)
		generation := fs.String("generation", "", "expected decimal state generation")
		reason := fs.String("reason", "", "audited cancellation reason")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return fmt.Errorf("invalid cancel arguments")
		}
		if _, err := canonicalIntentID(*generation); err != nil {
			return fmt.Errorf("invalid --generation")
		}
		if len(*reason) < 8 || len(*reason) > 1024 {
			return fmt.Errorf("--reason must contain 8-1024 characters")
		}
		var result map[string]any
		if err := cl.DoWithReason("POST", "/admin/system/upgrades/intents/"+id+"/cancel", *reason,
			map[string]string{"expectedGeneration": *generation, "reason": *reason}, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "diagnostics":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl upgrade diagnostics <intent-id> --output <file>")
		}
		id, err := canonicalIntentID(args[0])
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("upgrade diagnostics", flag.ContinueOnError)
		output := fs.String("output", "", "new local JSON evidence file")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *output == "" {
			return fmt.Errorf("--output is required")
		}
		var result map[string]any
		if err := cl.DoBounded("GET", "/admin/system/upgrades/intents/"+id+"/diagnostics", nil, &result, 1<<20); err != nil {
			return err
		}
		raw, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		if _, err := publishPrivateNew(*output, append(raw, '\n')); err != nil {
			return fmt.Errorf("write diagnostics output: %w", err)
		}
		fmt.Printf("Sanitized diagnostics written to %s\n", *output)
		return nil

	default:
		return fmt.Errorf("unknown upgrade action: %s (try: status, watch, cancel, history, diagnostics)", action)
	}
}

func canonicalIntentID(raw string) (string, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != raw {
		return "", fmt.Errorf("invalid decimal identifier %q", raw)
	}
	return raw, nil
}

func terminalUpgradeState(state string) bool {
	switch state {
	case "verified", "rolled_back", "failed", "recovery_required", "cancelled", "expired":
		return true
	default:
		return false
	}
}

func runAutoUpdate(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "status":
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/system/auto-update", nil, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("Enabled:       %v\n", result["enabled"])
		fmt.Printf("Channel:       %v\n", result["channel"])
		fmt.Printf("Interval:      %v\n", result["check_interval"])
		fmt.Printf("Auto-apply:    %v\n", result["auto_apply_safe"])
		return nil

	case "enable":
		cfg := map[string]interface{}{
			"enabled":                  true,
			"channel":                  "stable",
			"check_interval":           "daily",
			"auto_apply_safe":          false,
			"notify_admin":             true,
			"require_confirm_breaking": true,
		}
		if err := cl.Do("PUT", "/admin/system/auto-update", cfg, nil); err != nil {
			return err
		}
		if c.json {
			return printOut(c, map[string]bool{"enabled": true})
		}
		fmt.Println("Auto-update enabled")
		return nil

	case "disable":
		if err := cl.Do("PUT", "/admin/system/auto-update", map[string]interface{}{"enabled": false}, nil); err != nil {
			return err
		}
		if c.json {
			return printOut(c, map[string]bool{"enabled": false})
		}
		fmt.Println("Auto-update disabled")
		return nil

	default:
		return fmt.Errorf("unknown auto-update action: %s (try: status, enable, disable)", action)
	}
}
