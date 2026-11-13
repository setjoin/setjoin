package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
)

func runEAP(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		return eapListCmd(c)
	case "create":
		return eapCreateCmd(cl, args)
	case "update":
		return eapUpdateCmd(cl, args)
	case "delete":
		return eapDeleteCmd(c, args)
	case "apply":
		return eapApplyCmd(cl, args)
	case "reorder":
		return eapReorderCmd(cl, args)
	default:
		return fmt.Errorf("unknown eap action: %s (try: list, create, update, delete, apply, reorder)", action)
	}
}

func eapListCmd(c *cmdCtx) error {
	cl := c.client
	var policies []struct {
		ID                        int64  `json:"id"`
		Priority                  int    `json:"priority"`
		Name                      string `json:"name"`
		Enabled                   bool   `json:"enabled"`
		OverwriteDirectoryAddress bool   `json:"overwriteDirectoryAddress"`
		PrimaryTemplate           string `json:"primaryTemplate"`
		DuplicateResolution       string `json:"duplicateResolution"`
		UpdatedAt                 string `json:"updatedAt"`
	}
	if err := cl.Do("GET", "/admin/email-address-policies", nil, &policies); err != nil {
		return err
	}

	if c.json {
		return printOut(c, policies)
	}

	if len(policies) == 0 {
		fmt.Println("No email address policies defined.")
		return nil
	}

	fmt.Printf("%-4s %-25s %-7s %-8s %-40s %s\n", "#", "Name", "Enabled", "Overwrite", "PrimaryTemplate", "Updated")
	for _, p := range policies {
		overwrite := "no"
		if p.OverwriteDirectoryAddress {
			overwrite = "yes"
		}
		fmt.Printf("%-4d %-25s %-7s %-8s %-40s %s\n",
			p.Priority, p.Name, enabledStr(p.Enabled), overwrite, p.PrimaryTemplate, p.UpdatedAt)
	}
	return nil
}

func eapCreateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("eap create", flag.ExitOnError)
	name := fs.String("name", "", "Policy name (required)")
	primary := fs.String("primary", "", "Primary address template, e.g. {given_name}.{surname}@{domain} (required)")
	additional := fs.String("additional", "", "Additional templates JSON array, e.g. '[\"a@{domain}\"]'")
	enabled := fs.Bool("enabled", true, "Enable policy")
	overwrite := fs.Bool("overwrite", false, "Overwrite existing directory address")
	condDepartment := fs.String("cond-department", "", "Department condition JSON array, e.g. '[\"Sales\"]'")
	condDomainIds := fs.String("cond-domain-ids", "", "Domain IDs condition JSON array, e.g. '[5,6]'")
	condMailboxType := fs.String("cond-mailbox-type", "", "Mailbox type condition JSON array, e.g. '[\"personal\"]'")
	condAdOu := fs.String("cond-ad-ou", "", "AD OU condition JSON array, e.g. '[\"OU=Sales\"]'")
	dupResolution := fs.String("duplicate-resolution", "", "Duplicate resolution strategy (numeric_suffix, …)")
	fs.Parse(args)

	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *primary == "" {
		return fmt.Errorf("--primary is required")
	}

	body := map[string]interface{}{
		"name":                      *name,
		"primaryTemplate":           *primary,
		"enabled":                   *enabled,
		"overwriteDirectoryAddress": *overwrite,
	}
	if *additional != "" {
		body["additionalTemplates"] = json.RawMessage(*additional)
	}
	if *condDepartment != "" {
		body["condDepartment"] = json.RawMessage(*condDepartment)
	}
	if *condDomainIds != "" {
		body["condDomainIds"] = json.RawMessage(*condDomainIds)
	}
	if *condMailboxType != "" {
		body["condMailboxType"] = json.RawMessage(*condMailboxType)
	}
	if *condAdOu != "" {
		body["condAdOu"] = json.RawMessage(*condAdOu)
	}
	if *dupResolution != "" {
		body["duplicateResolution"] = *dupResolution
	}

	if err := cl.Do("POST", "/admin/email-address-policies", body, nil); err != nil {
		return err
	}
	fmt.Println("Email address policy created.")
	return nil
}

func eapUpdateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("eap update", flag.ExitOnError)
	id := fs.Int64("id", 0, "Policy ID (required)")
	name := fs.String("name", "", "Policy name")
	primary := fs.String("primary", "", "Primary address template")
	additional := fs.String("additional", "", "Additional templates JSON array")
	// --enabled is a bool, matching eap create. On a partial update it is only sent
	// when explicitly passed (detected via fs.Visit), so it isn't forced to its
	// default on every update.
	enabled := fs.Bool("enabled", false, "Enable/disable policy")
	overwrite := fs.String("overwrite", "", "Overwrite directory address (true/false)")
	condDepartment := fs.String("cond-department", "", "Department condition JSON array")
	condDomainIds := fs.String("cond-domain-ids", "", "Domain IDs condition JSON array")
	condMailboxType := fs.String("cond-mailbox-type", "", "Mailbox type condition JSON array")
	condAdOu := fs.String("cond-ad-ou", "", "AD OU condition JSON array")
	dupResolution := fs.String("duplicate-resolution", "", "Duplicate resolution strategy")
	fs.Parse(args)

	if *id == 0 {
		return fmt.Errorf("--id is required")
	}

	body := map[string]interface{}{}
	setIfNotEmpty(body, "name", *name)
	setIfNotEmpty(body, "primaryTemplate", *primary)
	if *additional != "" {
		body["additionalTemplates"] = json.RawMessage(*additional)
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "enabled" {
			body["enabled"] = *enabled
		}
	})
	if *overwrite != "" {
		body["overwriteDirectoryAddress"] = *overwrite == "true"
	}
	if *condDepartment != "" {
		body["condDepartment"] = json.RawMessage(*condDepartment)
	}
	if *condDomainIds != "" {
		body["condDomainIds"] = json.RawMessage(*condDomainIds)
	}
	if *condMailboxType != "" {
		body["condMailboxType"] = json.RawMessage(*condMailboxType)
	}
	if *condAdOu != "" {
		body["condAdOu"] = json.RawMessage(*condAdOu)
	}
	setIfNotEmpty(body, "duplicateResolution", *dupResolution)

	url := fmt.Sprintf("/admin/email-address-policies/%d", *id)
	if err := cl.Do("PUT", url, body, nil); err != nil {
		return err
	}
	fmt.Printf("Email address policy %d updated.\n", *id)
	return nil
}

func eapDeleteCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl eap delete <id>")
	}
	id := args[0]
	if !confirm(c, "Delete email address policy "+id) {
		return fmt.Errorf("cancelled")
	}
	url := fmt.Sprintf("/admin/email-address-policies/%s", id)
	if err := c.client.Do("DELETE", url, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Email address policy %s deleted.\n", id)
	return nil
}

func eapApplyCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("eap apply", flag.ExitOnError)
	id := fs.Int64("id", 0, "Policy ID to apply (omit to apply all enabled policies)")
	fs.Parse(args)

	// Handler expects {"policyId": N}; omitting the ID (zero) applies all enabled policies.
	var policyID *int64
	if *id != 0 {
		policyID = id
	}
	body := map[string]interface{}{"policyId": policyID}

	var result struct {
		JobID int64 `json:"jobId"`
	}
	if err := cl.Do("POST", "/admin/email-address-policies/apply", body, &result); err != nil {
		return err
	}
	fmt.Printf("Apply job enqueued: jobId=%d\n", result.JobID)
	return nil
}

func eapReorderCmd(cl *Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl eap reorder <id1> <id2> ...")
	}

	// Handler expects {"order":[ids int64]}.
	ids := make([]int64, 0, len(args))
	for _, a := range args {
		n, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ID %q: %w", a, err)
		}
		ids = append(ids, n)
	}

	body := map[string]interface{}{"order": ids}
	if err := cl.Do("POST", "/admin/email-address-policies/reorder", body, nil); err != nil {
		return err
	}
	fmt.Println("Email address policy order updated.")
	return nil
}
