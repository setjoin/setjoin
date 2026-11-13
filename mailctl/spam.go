package main

import (
	"fmt"
)

// runSpam handles the "spam" subcommand group.
func runSpam(c *cmdCtx, action string, args []string) error {
	switch action {
	case "status":
		return spamStatusCmd(c)
	case "reset":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl spam reset <userId>")
		}
		return spamResetCmd(c, args[0])
	case "":
		return fmt.Errorf("spam subcommand required: status, reset")
	default:
		return fmt.Errorf("unknown spam action: %s (try: status, reset)", action)
	}
}

// spamStatusCmd fetches and displays the ML spam classifier health dashboard.
func spamStatusCmd(c *cmdCtx) error {
	cl := c.client
	var d struct {
		Enabled         bool    `json:"enabled"`
		TotalModels     int     `json:"total_models"`
		TotalSamples    int64   `json:"total_samples"`
		AvgSamples      float64 `json:"avg_samples"`
		ActiveWeek      int     `json:"active_week"`
		DisabledUsers   int     `json:"disabled_users"`
		TotalFP         int64   `json:"total_fp"`
		TotalClassified int64   `json:"total_classified"`
		FPRate          float64 `json:"fp_rate"`
	}
	if err := cl.Do("GET", "/admin/spam", nil, &d); err != nil {
		return err
	}

	if c.json {
		return printOut(c, d)
	}

	fmt.Printf("Status:     %s\n", enabledStr(d.Enabled))
	fmt.Printf("Models:     %d users trained (%d opted out)\n", d.TotalModels, d.DisabledUsers)
	fmt.Printf("Samples:    %d total (%.0f avg/user)\n", d.TotalSamples, d.AvgSamples)
	fmt.Printf("Active:     %d users this week\n", d.ActiveWeek)
	if d.TotalClassified > 0 {
		fmt.Printf("Accuracy:   %.2f%% FP rate (%d rescues / %d classified)\n", d.FPRate*100, d.TotalFP, d.TotalClassified)
	}
	return nil
}

// spamResetCmd resets the spam model for a given user ID.
func spamResetCmd(c *cmdCtx, userID string) error {
	cl := c.client
	if !confirm(c, "Reset spam model for user "+userID) {
		return fmt.Errorf("cancelled")
	}
	if err := cl.Do("DELETE", "/admin/spam/models/"+userID, nil, nil); err != nil {
		return err
	}
	if c.json {
		return printOut(c, map[string]string{"status": "reset", "user": userID})
	}
	fmt.Printf("Spam model reset for user %s\n", userID)
	return nil
}
