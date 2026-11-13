package main

import (
	"fmt"
	"os"
)

// runStorage handles the "storage" subcommand group (modeREST — uses the
// dispatch-supplied c.client; the old code built its own Client internally,
// which was a wasted double config-load). It returns errors for operational
// failures (dispatch prints "Error: %v" + exits 1, byte-identical with the old
// internal handling). Unknown actions return the uniform error too, so dispatch
// renders "Error: ..." + exit 1 rather than a bespoke os.Exit.
func runStorage(c *cmdCtx, action string, args []string) error {
	switch action {
	case "status":
		return storageStatus(c)
	case "migrate":
		return storageMigrate(c, args)
	case "verify":
		return storageVerify(c)
	default:
		return fmt.Errorf("unknown storage action: %s (try: status, migrate, verify)", action)
	}
}

func storageStatus(c *cmdCtx) error {
	var result any
	if err := c.client.Do("GET", "/admin/storage/status", nil, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

func storageMigrate(c *cmdCtx, args []string) error {
	target := os.Getenv("STORAGE_PROVIDER")
	if target == "" {
		return fmt.Errorf("--target is required or set STORAGE_PROVIDER")
	}

	var result any
	path := "/admin/storage/migrate?target=" + target
	if err := c.client.Do("POST", path, nil, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

func storageVerify(c *cmdCtx) error {
	var result any
	if err := c.client.Do("POST", "/admin/storage/dr-scan", nil, &result); err != nil {
		return err
	}
	return printOut(c, result)
}
