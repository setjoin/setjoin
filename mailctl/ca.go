package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runCA(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	// ── existing CRUD ────────────────────────────────────────────────────
	case "list":
		return caListCmd(c)
	case "create":
		return caCreateCmd(cl, args)
	case "update":
		return caUpdateCmd(cl, args)
	case "delete":
		return caDeleteCmd(c, args)
	case "reorder":
		return caReorderCmd(cl, args)

	// ── offline verbs (no server) ─────────────────────────────────────────
	case "validate":
		return caValidateCmd(args)
	case "fmt":
		return caFmtCmd(args)
	case "explain":
		return caExplainCmd(args)

	// ── server verbs (D-handler endpoints) ──────────────────────────────
	case "export":
		return caExportCmd(cl, args)
	case "import":
		return caImportCmd(cl, args)
	case "apply":
		return caApplyCmd(cl, args)
	case "diff":
		return caDiffCmd(cl, args)
	case "plan":
		return caPlanCmd(cl, args)
	case "migrate":
		return caMigrateCmd(cl, args)
	case "promote":
		return caPromoteCmd(cl, args)
	case "init":
		return caInitCmd(cl, args)
	case "why":
		return caWhyCmd(cl, args)
	case "simulate":
		return caSimulateCmd(cl, args)
	case "coverage":
		return caCoverageCmd(cl, args)
	case "doctor":
		return caDoctorCmd(cl, args)
	case "install-pack":
		return caInstallPackCmd(cl, args)
	case "pack":
		return caPackCmd(cl, args)
	case "signin-log":
		return caSigninLogCmd(cl, args)

	default:
		return fmt.Errorf("unknown ca action: %s (try: list, create, update, delete, reorder, export, import, validate, apply, diff, plan, fmt, migrate, promote, init, why, simulate, coverage, doctor, explain, install-pack, pack, signin-log)", action)
	}
}

func caListCmd(c *cmdCtx) error {
	cl := c.client
	var policies []struct {
		ID          int    `json:"id"`
		Priority    int    `json:"priority"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
		ScopeType   string `json:"scope_type"`
		ScopeTarget string `json:"scope_target"`
		UpdatedAt   string `json:"updated_at"`
	}
	if err := cl.Do("GET", "/admin/conditional-access/policies", nil, &policies); err != nil {
		return err
	}

	if c.json {
		return printOut(c, policies)
	}

	if len(policies) == 0 {
		fmt.Println("No conditional access policies defined.")
		return nil
	}

	fmt.Printf("%-4s %-25s %-15s %-7s %s\n", "#", "Name", "Scope", "Enabled", "Updated")
	for _, p := range policies {
		scope := p.ScopeType
		if p.ScopeTarget != "" {
			scope += ":" + p.ScopeTarget
		}
		fmt.Printf("%-4d %-25s %-15s %-7s %s\n", p.Priority, p.Name, scope, enabledStr(p.Enabled), p.UpdatedAt)
	}
	return nil
}

// resolveCAState resolves the --enabled deprecated alias against --state.
// --state (default: report_only) is the canonical field.
// --enabled is a deprecated alias: true→"on", false→"off". When both are
// supplied, --enabled wins (last-write-wins flag semantics). A deprecation
// warning is printed to stderr when --enabled is set (non-empty).
func resolveCAState(state, enabled string) string {
	if enabled == "" {
		return state
	}
	fmt.Fprintln(os.Stderr, "warning: --enabled is deprecated; use --state (report_only|on|off)")
	if enabled == "true" {
		return "on"
	}
	return "off"
}

// buildCACreateBody parses ca-create flags from args and returns the request
// body. Extracted so unit tests can validate flag semantics without a live server.
func buildCACreateBody(args []string) (map[string]interface{}, error) {
	fs := flag.NewFlagSet("ca create", flag.ContinueOnError)
	name := fs.String("name", "", "Policy name (required)")
	desc := fs.String("desc", "", "Description")
	state := fs.String("state", "report_only", "Policy state: report_only, on, off")
	// ponytail: --enabled kept as a deprecated alias; removed when callers have migrated.
	enabled := fs.String("enabled", "", "DEPRECATED: use --state. true→on, false→off")
	scopeType := fs.String("scope", "user", "Scope type: user, group, domain, global")
	scopeTarget := fs.String("target", "", "Scope target")
	conditions := fs.String("conditions", "{}", "Conditions JSON")
	actions := fs.String("actions", "{}", "Actions JSON")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if *name == "" {
		return nil, fmt.Errorf("--name is required")
	}

	resolvedState := resolveCAState(*state, *enabled)

	body := map[string]interface{}{
		"name":         *name,
		"description":  *desc,
		"state":        resolvedState,
		"scope_type":   *scopeType,
		"scope_target": *scopeTarget,
		"conditions":   json.RawMessage(*conditions),
		"actions":      json.RawMessage(*actions),
	}
	return body, nil
}

func caCreateCmd(cl *Client, args []string) error {
	body, err := buildCACreateBody(args)
	if err != nil {
		return err
	}
	if err := cl.Do("POST", "/admin/conditional-access/policies", body, nil); err != nil {
		return err
	}
	fmt.Println("Policy created.")
	return nil
}

func caUpdateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca update", flag.ExitOnError)
	id := fs.Int("id", 0, "Policy ID (required)")
	name := fs.String("name", "", "Policy name")
	desc := fs.String("desc", "", "Description")
	state := fs.String("state", "", "Policy state: report_only, on, off")
	// ponytail: --enabled kept as a deprecated alias (mirrors ca create); drop when callers migrate.
	enabled := fs.String("enabled", "", "DEPRECATED: use --state. true→on, false→off")
	scopeType := fs.String("scope", "", "Scope type")
	scopeTarget := fs.String("target", "", "Scope target")
	conditions := fs.String("conditions", "", "Conditions JSON")
	actions := fs.String("actions", "", "Actions JSON")
	fs.Parse(args)

	if *id == 0 {
		return fmt.Errorf("--id is required")
	}

	body := map[string]interface{}{}
	setIfNotEmpty(body, "name", *name)
	setIfNotEmpty(body, "description", *desc)
	setIfNotEmpty(body, "state", resolveCAState(*state, *enabled))
	setIfNotEmpty(body, "scope_type", *scopeType)
	setIfNotEmpty(body, "scope_target", *scopeTarget)
	if *conditions != "" {
		body["conditions"] = json.RawMessage(*conditions)
	}
	if *actions != "" {
		body["actions"] = json.RawMessage(*actions)
	}

	url := fmt.Sprintf("/admin/conditional-access/policies/%d", *id)
	if err := cl.Do("PUT", url, body, nil); err != nil {
		return err
	}
	fmt.Printf("Policy %d updated.\n", *id)
	return nil
}

func caDeleteCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca delete <id>")
	}
	id := args[0]
	if !confirm(c, "Delete conditional-access policy "+id) {
		return fmt.Errorf("cancelled")
	}
	url := fmt.Sprintf("/admin/conditional-access/policies/%s", id)
	if err := c.client.Do("DELETE", url, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Policy %s deleted.\n", id)
	return nil
}

// setIfNotEmpty sets m[k] = v when v is non-empty; keeps update-command maps concise.
func setIfNotEmpty(m map[string]interface{}, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func caReorderCmd(cl *Client, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mailctl ca reorder <id1> <id2> ...")
	}

	body := map[string][]string{"order": args}
	if err := cl.Do("POST", "/admin/conditional-access/policies/reorder", body, nil); err != nil {
		return err
	}
	fmt.Println("Policy order updated.")
	return nil
}
