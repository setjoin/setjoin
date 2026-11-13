package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
)

// approval.go — mailctl "approval" command family: imperative CRUD over
// approval_policies (GET/POST/PUT/DELETE/reorder /admin/approval-policies)
// plus declarative export/apply/diff (mirrors ca.go's shape) and an audit
// read of approval_requests. See internal/admin/admin_approvals.go for the
// server-side handler this talks to.
//
// ponytail: there is no dedicated server-side export/import/diff route for
// approval policies (unlike CA), so apply/diff are synthesized client-side
// from list+create+update. Identity for matching desired-vs-live is
// (consumerType, name) — the numeric id is server-assigned and not portable
// across environments, so it's ignored for matching (mirrors how `ca apply`
// treats the document as the source of truth, not raw ids).

func runApproval(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		return approvalListCmd(c, args)
	case "create":
		return approvalCreateCmd(cl, args)
	case "update":
		return approvalUpdateCmd(cl, args)
	case "delete":
		return approvalDeleteCmd(c, args)
	case "reorder":
		return approvalReorderCmd(cl, args)
	case "export":
		return approvalExportCmd(cl, args)
	case "apply":
		return approvalApplyCmd(cl, args)
	case "diff":
		return approvalDiffCmd(cl, args)
	case "audit":
		return approvalAuditCmd(c, args)
	default:
		return fmt.Errorf("unknown approval action: %s (try: list, create, update, delete, reorder, export, apply, diff, audit)", action)
	}
}

// approvalPolicy mirrors admin_approvals.go's approvalPolicyResponse /
// createPolicyRequest shapes closely enough to serve both as decode target
// (list/export) and encode source (create/apply) — id/priority/timestamps
// are omitted on encode when zero/empty.
type approvalPolicy struct {
	ID               int64           `json:"id,omitempty"`
	ConsumerType     string          `json:"consumerType"`
	Name             string          `json:"name"`
	Enabled          bool            `json:"enabled"`
	Priority         int             `json:"priority,omitempty"`
	Conditions       json.RawMessage `json:"conditions,omitempty"`
	RequiresApproval bool            `json:"requiresApproval"`
	ApproverSpec     json.RawMessage `json:"approverSpec,omitempty"`
	CreatedAt        string          `json:"createdAt,omitempty"`
	UpdatedAt        string          `json:"updatedAt,omitempty"`
}

func approvalListPath(consumerType string) string {
	path := "/admin/approval-policies"
	if consumerType != "" {
		path += "?consumer_type=" + url.QueryEscape(consumerType)
	}
	return path
}

func approvalListCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("approval list", flag.ContinueOnError)
	consumerType := fs.String("consumer-type", "", "Filter by consumer type: rbac.jit_activation, mail.external_send, mail.group_moderation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var policies []approvalPolicy
	if err := c.client.Do("GET", approvalListPath(*consumerType), nil, &policies); err != nil {
		return err
	}

	if c.json {
		return printOut(c, policies)
	}

	if len(policies) == 0 {
		fmt.Println("No approval policies defined.")
		return nil
	}

	fmt.Printf("%-4s %-24s %-28s %-8s %-8s %-3s %s\n", "ID", "ConsumerType", "Name", "Enabled", "Requires", "Pri", "Updated")
	for _, p := range policies {
		fmt.Printf("%-4d %-24s %-28s %-8s %-8s %-3d %s\n",
			p.ID, p.ConsumerType, p.Name, enabledStr(p.Enabled), enabledStr(p.RequiresApproval), p.Priority, p.UpdatedAt)
	}
	return nil
}

func approvalCreateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("approval create", flag.ExitOnError)
	consumerType := fs.String("consumer-type", "", "Consumer type: rbac.jit_activation, mail.external_send, mail.group_moderation (required)")
	name := fs.String("name", "", "Policy name (required)")
	enabled := fs.Bool("enabled", true, "Enable policy")
	conditions := fs.String("conditions", "{}", "Conditions JSON object")
	requiresApproval := fs.Bool("requires-approval", true, "Require approval (false = auto-allow on match)")
	approverSpec := fs.String("approver-spec", "{}", "Approver spec JSON object")
	fs.Parse(args)

	if *consumerType == "" {
		return fmt.Errorf("--consumer-type is required")
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}

	body := map[string]interface{}{
		"consumerType":     *consumerType,
		"name":             *name,
		"enabled":          *enabled,
		"conditions":       json.RawMessage(*conditions),
		"requiresApproval": *requiresApproval,
		"approverSpec":     json.RawMessage(*approverSpec),
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := cl.Do("POST", "/admin/approval-policies", body, &result); err != nil {
		return err
	}
	fmt.Printf("Approval policy created: id=%d\n", result.ID)
	return nil
}

func approvalUpdateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("approval update", flag.ExitOnError)
	id := fs.Int64("id", 0, "Policy ID (required)")
	name := fs.String("name", "", "Policy name")
	// --enabled/--requires-approval are bools; on a partial update they're only
	// sent when explicitly passed (via fs.Visit), matching eap update's
	// pattern — otherwise a bare `approval update --id 5 --name x` would force
	// enabled=false on every call.
	enabled := fs.Bool("enabled", false, "Enable/disable policy")
	conditions := fs.String("conditions", "", "Conditions JSON object")
	requiresApproval := fs.Bool("requires-approval", false, "Require approval")
	approverSpec := fs.String("approver-spec", "", "Approver spec JSON object")
	fs.Parse(args)

	if *id == 0 {
		return fmt.Errorf("--id is required")
	}

	body := map[string]interface{}{}
	setIfNotEmpty(body, "name", *name)
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "enabled":
			body["enabled"] = *enabled
		case "requires-approval":
			body["requiresApproval"] = *requiresApproval
		}
	})
	if *conditions != "" {
		body["conditions"] = json.RawMessage(*conditions)
	}
	if *approverSpec != "" {
		body["approverSpec"] = json.RawMessage(*approverSpec)
	}

	path := fmt.Sprintf("/admin/approval-policies/%d", *id)
	if err := cl.Do("PUT", path, body, nil); err != nil {
		return err
	}
	fmt.Printf("Approval policy %d updated.\n", *id)
	return nil
}

func approvalDeleteCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl approval delete <id>")
	}
	id := args[0]
	if !confirm(c, "Delete approval policy "+id) {
		return fmt.Errorf("cancelled")
	}
	path := fmt.Sprintf("/admin/approval-policies/%s", id)
	if err := c.client.Do("DELETE", path, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Approval policy %s deleted.\n", id)
	return nil
}

// approvalReorderCmd renumbers policies within one consumer_type — the server
// requires consumerType alongside orderedIds (priority is scoped per type).
// Usage: approval reorder --consumer-type <ct> <id1> <id2> ...
func approvalReorderCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("approval reorder", flag.ExitOnError)
	consumerType := fs.String("consumer-type", "", "Consumer type (required)")
	fs.Parse(args)

	if *consumerType == "" {
		return fmt.Errorf("--consumer-type is required")
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: mailctl approval reorder --consumer-type <ct> <id1> <id2> ...")
	}

	orderedIDs := make([]int64, 0, len(rest))
	for _, a := range rest {
		n, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ID %q: %w", a, err)
		}
		orderedIDs = append(orderedIDs, n)
	}

	body := map[string]interface{}{"consumerType": *consumerType, "orderedIds": orderedIDs}
	if err := cl.Do("POST", "/admin/approval-policies/reorder", body, nil); err != nil {
		return err
	}
	fmt.Println("Approval policy order updated.")
	return nil
}

// approvalExportCmd exports the live policy set (optionally filtered by
// --consumer-type) as a JSON array suitable for `approval apply`/`approval diff`.
func approvalExportCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("approval export", flag.ContinueOnError)
	consumerType := fs.String("consumer-type", "", "Filter by consumer type")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var policies []approvalPolicy
	return doJSON(cl, "GET", approvalListPath(*consumerType), nil, &policies)
}

// approvalPolicyChanged reports whether want's mutable fields differ from
// have's. Conditions/approverSpec are compared by JSON value, not raw bytes,
// so re-formatted-but-equivalent JSON doesn't register as drift.
func approvalPolicyChanged(have, want approvalPolicy) bool {
	if have.Enabled != want.Enabled || have.RequiresApproval != want.RequiresApproval {
		return true
	}
	return !jsonValueEqual(have.Conditions, want.Conditions) || !jsonValueEqual(have.ApproverSpec, want.ApproverSpec)
}

func jsonValueEqual(a, b json.RawMessage) bool {
	if len(a) == 0 {
		a = json.RawMessage("{}")
	}
	if len(b) == 0 {
		b = json.RawMessage("{}")
	}
	var av, bv interface{}
	if err := json.Unmarshal(a, &av); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

// approvalKey is the identity used to match desired-vs-live policies for
// apply/diff: (consumerType, name). Ids are server-assigned per environment
// and not a stable join key across export→apply round trips.
func approvalKey(consumerType, name string) string {
	return consumerType + "\x00" + name
}

// approvalApplyCmd idempotently applies a JSON document (array of
// approvalPolicy): creates missing policies, updates changed ones, leaves
// matching ones alone, and reports counts. Usage: approval apply -f <file.json>
func approvalApplyCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("approval apply", flag.ContinueOnError)
	f := fs.String("f", "", "Policy document file (JSON array; - for stdin)")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return err
	}
	raw, err := readFileOrStdin(path)
	if err != nil {
		return err
	}
	var desired []approvalPolicy
	if err := json.Unmarshal(raw, &desired); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	var live []approvalPolicy
	if err := cl.Do("GET", "/admin/approval-policies", nil, &live); err != nil {
		return exitFor(err)
	}
	liveByKey := make(map[string]approvalPolicy, len(live))
	for _, p := range live {
		liveByKey[approvalKey(p.ConsumerType, p.Name)] = p
	}

	var created, updated, unchanged int
	for _, want := range desired {
		key := approvalKey(want.ConsumerType, want.Name)
		if have, ok := liveByKey[key]; ok {
			if !approvalPolicyChanged(have, want) {
				unchanged++
				continue
			}
			body := map[string]interface{}{
				"name":             want.Name,
				"enabled":          want.Enabled,
				"conditions":       want.Conditions,
				"requiresApproval": want.RequiresApproval,
				"approverSpec":     want.ApproverSpec,
			}
			if err := cl.Do("PUT", fmt.Sprintf("/admin/approval-policies/%d", have.ID), body, nil); err != nil {
				return exitFor(fmt.Errorf("update %q: %w", want.Name, err))
			}
			updated++
			continue
		}
		body := map[string]interface{}{
			"consumerType":     want.ConsumerType,
			"name":             want.Name,
			"enabled":          want.Enabled,
			"conditions":       want.Conditions,
			"requiresApproval": want.RequiresApproval,
			"approverSpec":     want.ApproverSpec,
		}
		if err := cl.Do("POST", "/admin/approval-policies", body, nil); err != nil {
			return exitFor(fmt.Errorf("create %q: %w", want.Name, err))
		}
		created++
	}

	fmt.Printf("Apply complete: %d created, %d updated, %d unchanged.\n", created, updated, unchanged)
	return nil
}

// approvalDiffCmd shows drift between a document and live server state
// without applying it. Exit 0 = no drift; exit 2 = drift present (Terraform
// plan parity, mirrors ca diff); exit 1 = error. Usage: approval diff -f <file.json>
func approvalDiffCmd(cl *Client, args []string) error {
	raw, err := readDoc(args)
	if err != nil {
		return err
	}
	var desired []approvalPolicy
	if err := json.Unmarshal(raw, &desired); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	var live []approvalPolicy
	if err := cl.Do("GET", "/admin/approval-policies", nil, &live); err != nil {
		return exitFor(err)
	}

	liveByKey := make(map[string]approvalPolicy, len(live))
	for _, p := range live {
		liveByKey[approvalKey(p.ConsumerType, p.Name)] = p
	}
	wantKeys := make(map[string]bool, len(desired))

	added := []string{}
	changed := []string{}
	for _, want := range desired {
		key := approvalKey(want.ConsumerType, want.Name)
		wantKeys[key] = true
		if have, ok := liveByKey[key]; ok {
			if approvalPolicyChanged(have, want) {
				changed = append(changed, want.Name)
			}
		} else {
			added = append(added, want.Name)
		}
	}
	removed := []string{}
	for _, have := range live {
		if !wantKeys[approvalKey(have.ConsumerType, have.Name)] {
			removed = append(removed, have.Name)
		}
	}

	result := struct {
		Drift   bool     `json:"drift"`
		Added   []string `json:"added"`
		Changed []string `json:"changed"`
		Removed []string `json:"removed"`
	}{
		Drift:   len(added) > 0 || len(changed) > 0 || len(removed) > 0,
		Added:   added,
		Changed: changed,
		Removed: removed,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if result.Drift {
		// ponytail: exitCodeErr(2) = changes present, mirrors `ca diff`/terraform plan.
		return exitCodeErr{code: 2, msg: "changes present"}
	}
	return nil
}

// approvalAuditCmd reads the approval_requests audit trail.
// Usage: approval audit [--limit N] [--offset N]
func approvalAuditCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("approval audit", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "Max rows to return")
	offset := fs.Int("offset", 0, "Row offset")
	if err := fs.Parse(args); err != nil {
		return err
	}

	path := fmt.Sprintf("/admin/approval-requests/audit?limit=%d&offset=%d", *limit, *offset)
	var rows []map[string]interface{}
	if err := c.client.Do("GET", path, nil, &rows); err != nil {
		return err
	}

	if c.json {
		return printOut(c, rows)
	}
	if len(rows) == 0 {
		fmt.Println("No approval requests.")
		return nil
	}
	return printMapSlice(rows)
}
