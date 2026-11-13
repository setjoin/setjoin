package main

import "fmt"

// runAD handles `mailctl ad <action>` — Active Directory sync.
func runAD(c *cmdCtx, action string, args []string) error {
	switch action {
	case "sync":
		return directorySyncCmd(c, "/admin/ad/sync")
	case "sync-log":
		return directorySyncLogCmd(c, "/admin/ad/sync-log")
	case "health":
		return directoryHealthCmd(c, "/admin/ad/health")
	default:
		return fmt.Errorf("unknown ad action: %s (try: sync, sync-log, health)", action)
	}
}

// runLDAP handles `mailctl ldap <action>` — generic LDAP directory sync.
func runLDAP(c *cmdCtx, action string, args []string) error {
	switch action {
	case "sync":
		return directorySyncCmd(c, "/admin/ldap/sync")
	case "sync-log":
		return directorySyncLogCmd(c, "/admin/ldap/sync-log")
	case "health":
		return directoryHealthCmd(c, "/admin/ldap/health")
	default:
		return fmt.Errorf("unknown ldap action: %s (try: sync, sync-log, health)", action)
	}
}

// directorySyncResult mirrors ad.SyncResult / ldapsync.SyncResult (identical shape).
type directorySyncResult struct {
	Checked  int    `json:"checked"`
	Created  int    `json:"created"`
	Updated  int    `json:"updated"`
	Disabled int    `json:"disabled"`
	Skipped  int    `json:"skipped"`
	Errors   int    `json:"errors"`
	Duration string `json:"duration"`
}

// directorySyncCmd triggers an immediate sync. Cron material: a non-zero
// Errors count in the result fails the command (non-zero exit) so monitoring
// on the cron job alerts, after the result is still printed for visibility.
func directorySyncCmd(c *cmdCtx, path string) error {
	var result directorySyncResult
	if err := c.client.Do("POST", path, nil, &result); err != nil {
		return err
	}
	if c.json {
		if err := printOut(c, result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Sync complete: checked=%d created=%d updated=%d disabled=%d skipped=%d errors=%d duration=%s\n",
			result.Checked, result.Created, result.Updated, result.Disabled, result.Skipped, result.Errors, result.Duration)
	}
	if result.Errors > 0 {
		return fmt.Errorf("sync completed with %d error(s)", result.Errors)
	}
	return nil
}

// directorySyncLogEntry mirrors the GetSyncLog handler's per-row shape.
type directorySyncLogEntry struct {
	Source          string `json:"source"`
	Checked         int    `json:"checked"`
	Created         int    `json:"created"`
	Updated         int    `json:"updated"`
	Disabled        int    `json:"disabled"`
	Skipped         int    `json:"skipped"`
	Errors          int    `json:"errors"`
	DurationSeconds int    `json:"durationSeconds"`
	SyncedAt        string `json:"syncedAt"`
}

func directorySyncLogCmd(c *cmdCtx, path string) error {
	var entries []directorySyncLogEntry
	if err := c.client.Do("GET", path, nil, &entries); err != nil {
		return err
	}
	if c.json {
		return printOut(c, entries)
	}
	if len(entries) == 0 {
		fmt.Println("No sync log entries.")
		return nil
	}
	fmt.Printf("%-20s %-7s %-7s %-7s %-8s %-7s %-6s %s\n",
		"SyncedAt", "Checked", "Created", "Updated", "Disabled", "Skipped", "Errors", "Duration(s)")
	for _, e := range entries {
		fmt.Printf("%-20s %-7d %-7d %-7d %-8d %-7d %-6d %d\n",
			e.SyncedAt, e.Checked, e.Created, e.Updated, e.Disabled, e.Skipped, e.Errors, e.DurationSeconds)
	}
	return nil
}

// directoryHealthResp mirrors the AD/LDAP Health handler's response shape.
type directoryHealthResp struct {
	LastSync         *string `json:"lastSync"`
	Status           string  `json:"status"` // healthy, error, unknown
	Checked          int     `json:"checked"`
	Created          int     `json:"created"`
	Updated          int     `json:"updated"`
	Disabled         int     `json:"disabled"`
	Skipped          int     `json:"skipped"`
	Errors           int     `json:"errors"`
	PendingConflicts int     `json:"pendingConflicts"`
}

// directoryHealthCmd is cron material: any status other than "healthy"
// (i.e. "error" or "unknown" — not configured / never synced / stale) fails
// the command after printing, so a monitoring cron job alerts on it.
func directoryHealthCmd(c *cmdCtx, path string) error {
	var resp directoryHealthResp
	if err := c.client.Do("GET", path, nil, &resp); err != nil {
		return err
	}
	if c.json {
		if err := printOut(c, resp); err != nil {
			return err
		}
	} else {
		lastSync := "never"
		if resp.LastSync != nil {
			lastSync = *resp.LastSync
		}
		fmt.Printf("Status: %s\nLast sync: %s\nChecked: %d  Created: %d  Updated: %d  Disabled: %d  Skipped: %d  Errors: %d\nPending conflicts: %d\n",
			resp.Status, lastSync, resp.Checked, resp.Created, resp.Updated, resp.Disabled, resp.Skipped, resp.Errors, resp.PendingConflicts)
	}
	if resp.Status != "healthy" {
		return fmt.Errorf("directory sync status: %s", resp.Status)
	}
	return nil
}
