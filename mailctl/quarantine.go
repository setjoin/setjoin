package main

import (
	"flag"
	"fmt"
	"net/url"
)

func runQuarantine(c *cmdCtx, action string, args []string) error {
	switch action {
	case "list":
		return quarantineListCmd(c, args)
	case "stats":
		return quarantineStatsCmd(c)
	case "preview":
		return quarantinePreviewCmd(c, args)
	case "release":
		return quarantineReleaseCmd(c, args)
	case "reject":
		return quarantineRejectCmd(c, args)
	default:
		return fmt.Errorf("unknown quarantine action: %s (try: list, stats, preview, release, reject)", action)
	}
}

// quarantineItem mirrors admin.quarantineItem's JSON shape
// (mailserver/internal/admin/admin_quarantine.go).
type quarantineItem struct {
	ID            int64   `json:"id"`
	MessageID     int64   `json:"messageId"`
	MailboxID     int64   `json:"mailboxId"`
	Subject       string  `json:"subject"`
	FromAddr      string  `json:"fromAddr"`
	OriginalTag   string  `json:"originalTag"`
	Reason        string  `json:"reason"`
	ReasonType    string  `json:"reasonType"`
	VirusName     *string `json:"virusName,omitempty"`
	PreviewToken  string  `json:"previewToken"`
	QuarantinedAt string  `json:"quarantinedAt"`
	ReleasedAt    *string `json:"releasedAt,omitempty"`
	ReleasedBy    *int64  `json:"releasedBy,omitempty"`
	RejectedAt    *string `json:"rejectedAt,omitempty"`
	RejectedBy    *int64  `json:"rejectedBy,omitempty"`
	SizeBytes     int64   `json:"sizeBytes"`
	Recipient     string  `json:"recipient"`
}

func quarantineListCmd(c *cmdCtx, args []string) error {
	cl := c.client
	fs := flag.NewFlagSet("quarantine list", flag.ExitOnError)
	status := fs.String("status", "", "Filter: active, released, rejected, all")
	q := fs.String("q", "", "Search subject/from")
	limit := fs.Int("limit", 0, "Page size (default 50, max 100)")
	offset := fs.Int("offset", 0, "Page offset")
	if err := fs.Parse(args); err != nil {
		return err
	}

	qs := url.Values{}
	if *status != "" {
		qs.Set("status", *status)
	}
	if *q != "" {
		qs.Set("q", *q)
	}
	if *limit != 0 {
		qs.Set("limit", fmt.Sprintf("%d", *limit))
	}
	if *offset != 0 {
		qs.Set("offset", fmt.Sprintf("%d", *offset))
	}
	path := "/admin/quarantine"
	if enc := qs.Encode(); enc != "" {
		path += "?" + enc
	}

	var result struct {
		Items []quarantineItem `json:"items"`
	}
	if err := cl.Do("GET", path, nil, &result); err != nil {
		return err
	}

	if c.json {
		return printOut(c, result.Items)
	}

	if len(result.Items) == 0 {
		fmt.Println("No quarantined messages.")
		return nil
	}

	fmt.Printf("%-6s %-30s %-30s %-15s %s\n", "ID", "Subject", "From", "Reason", "Quarantined")
	for _, it := range result.Items {
		state := "active"
		if it.ReleasedAt != nil {
			state = "released"
		} else if it.RejectedAt != nil {
			state = "rejected"
		}
		fmt.Printf("%-6d %-30s %-30s %-15s %s (%s)\n", it.ID, truncate(it.Subject, 30), truncate(it.FromAddr, 30), it.ReasonType, it.QuarantinedAt, state)
	}
	return nil
}

func quarantineStatsCmd(c *cmdCtx) error {
	cl := c.client
	var stats map[string]int
	if err := cl.Do("GET", "/admin/quarantine/stats", nil, &stats); err != nil {
		return err
	}
	if c.json {
		return printOut(c, stats)
	}
	fmt.Printf("Active:   %d\n", stats["active"])
	fmt.Printf("Released: %d\n", stats["released"])
	fmt.Printf("Rejected: %d\n", stats["rejected"])
	return nil
}

func quarantinePreviewCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl quarantine preview <id>")
	}
	id := args[0]
	cl := c.client
	var result struct {
		HTML          string `json:"html"`
		Subject       string `json:"subject"`
		FromAddr      string `json:"fromAddr"`
		QuarantinedAt string `json:"quarantinedAt"`
	}
	if err := cl.Do("GET", "/admin/quarantine/"+id+"/preview", nil, &result); err != nil {
		return err
	}
	if c.json {
		return printOut(c, result)
	}
	fmt.Printf("Subject:       %s\n", result.Subject)
	fmt.Printf("From:          %s\n", result.FromAddr)
	fmt.Printf("Quarantined:   %s\n", result.QuarantinedAt)
	fmt.Println("---")
	fmt.Println(result.HTML)
	return nil
}

func quarantineReleaseCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl quarantine release <id>")
	}
	id := args[0]
	if !confirm(c, "Release quarantined message "+id+" to the recipient's inbox") {
		return fmt.Errorf("cancelled")
	}
	if err := c.client.Do("POST", "/admin/quarantine/"+id+"/release", nil, nil); err != nil {
		return err
	}
	fmt.Printf("Quarantined message %s released.\n", id)
	return nil
}

func quarantineRejectCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl quarantine reject <id>")
	}
	id := args[0]
	if !confirm(c, "Reject (permanently delete) quarantined message "+id) {
		return fmt.Errorf("cancelled")
	}
	if err := c.client.Do("POST", "/admin/quarantine/"+id+"/reject", nil, nil); err != nil {
		return err
	}
	fmt.Printf("Quarantined message %s rejected.\n", id)
	return nil
}
