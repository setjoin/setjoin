package main

import "fmt"

func runSystem(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "status":
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/system/status", nil, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("Status:       %v\n", result["status"])
		fmt.Printf("PID:          %v\n", result["pid"])
		fmt.Printf("Uptime:       %v seconds\n", result["uptime_sec"])
		fmt.Printf("Version:      %v\n", result["version"])
		fmt.Printf("Goroutines:   %v\n", result["goroutines"])
		fmt.Printf("Memory:       %v MB\n", result["memory_mb"])
		fmt.Printf("Started:      %v\n", result["started_at"])
		return nil

	case "restart":
		mode := "hot_reload"
		if len(args) > 0 && args[0] == "--full" {
			mode = "full_restart"
		}
		if !confirm(c, "Restart system (mode: "+mode+")") {
			return fmt.Errorf("cancelled")
		}
		var result map[string]interface{}
		body := map[string]string{"mode": mode}
		if err := cl.Do("POST", "/admin/system/restart", body, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("Restarting: %v (mode: %v)\n", result["status"], result["mode"])
		return nil

	case "stop":
		if !confirm(c, "Stop system") {
			return fmt.Errorf("cancelled")
		}
		var result map[string]interface{}
		body := map[string]int{"drain_timeout_sec": 30}
		if err := cl.Do("POST", "/admin/system/stop", body, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("Stopping: %v\n", result["status"])
		return nil

	default:
		return fmt.Errorf("unknown system action: %s (try: status, restart, stop)", action)
	}
}
