package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// role.go — the RBAC role command family. Imperative CRUD + membership
// (list/create/update/delete/grant/revoke) plus a declarative
// export/apply/diff triad (mirrors ca.go's declarative verbs).
//
// Authorization is fully server-side (grant-only-what-you-hold, mutation-scope
// confinement, SoD) — this CLI only carries the JWT and the audit reason. Every
// mutating verb (create/update/delete/grant/revoke and apply) REQUIRES --reason:
// the gateway rejects role mutations without X-Audit-Reason in audit-hardened
// deployments (main.go wires requireReason on every POST/PUT/DELETE role route).

// roleRow mirrors the server's roleResponse (admin/admin_roles.go).
type roleRow struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	DomainScope *int64   `json:"domainScope,omitempty"`
	IsBuiltin   bool     `json:"isBuiltin"`
	MemberCount int      `json:"memberCount"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

type roleMemberRow struct {
	UserID    int64  `json:"userId"`
	UserEmail string `json:"userEmail"`
}

// roleExport is the declarative document shape for export/apply/diff.
type roleExport struct {
	Roles []roleExportEntry `json:"roles"`
}

type roleExportEntry struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	DomainScope *int64   `json:"domainScope,omitempty"`
	IsBuiltin   bool     `json:"isBuiltin,omitempty"`
	Members     []string `json:"members"` // member emails
}

func runRole(c *cmdCtx, action string, args []string) error {
	switch action {
	// ── imperative CRUD + membership ──────────────────────────────────────
	case "list":
		return roleListCmd(c)
	case "create":
		return roleCreateCmd(c, args)
	case "update":
		return roleUpdateCmd(c, args)
	case "delete":
		return roleDeleteCmd(c, args)
	case "grant":
		return roleGrantCmd(c, args)
	case "revoke":
		return roleRevokeCmd(c, args)

	// ── declarative (mirror ca export/apply/diff) ─────────────────────────
	case "export":
		return roleExportCmd(c)
	case "apply":
		return roleApplyCmd(c, args)
	case "diff":
		return roleDiffCmd(c, args)

	default:
		return fmt.Errorf("unknown role action: %s (try: list, create, update, delete, grant, revoke, export, apply, diff)", action)
	}
}

// requireReason enforces the mandatory --reason on mutating verbs. The gateway
// 400s a role mutation without X-Audit-Reason, so we fail fast client-side with
// a clear message rather than surfacing an opaque HTTP 400.
func requireReason(reason, action string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("--reason is required for role %s (audit-hardened deployments reject role mutations without an audit reason)", action)
	}
	return nil
}

// splitCSV splits a comma-separated flag value, trimming spaces and dropping
// empties (the bare strings.Split used elsewhere keeps blanks).
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fetchRoles(c *cmdCtx) ([]roleRow, error) {
	var roles []roleRow
	if err := c.client.Do("GET", "/admin/roles", nil, &roles); err != nil {
		return nil, err
	}
	return roles, nil
}

// resolveRole looks up a role by name (there is no by-name GET; list + match
// locally, same shape as resolveUserID). Returns the full row so callers can
// read IsBuiltin for the privileged-confirm gate.
func resolveRole(c *cmdCtx, name string) (roleRow, error) {
	if name == "" {
		return roleRow{}, fmt.Errorf("role name is required")
	}
	roles, err := fetchRoles(c)
	if err != nil {
		return roleRow{}, err
	}
	for _, r := range roles {
		if r.Name == name {
			return r, nil
		}
	}
	return roleRow{}, fmt.Errorf("no role found with name %q", name)
}

func fetchRoleMembers(c *cmdCtx, id int64) ([]roleMemberRow, error) {
	var detail struct {
		Members []roleMemberRow `json:"members"`
	}
	if err := c.client.Do("GET", fmt.Sprintf("/admin/roles/%d", id), nil, &detail); err != nil {
		return nil, err
	}
	return detail.Members, nil
}

// buildUserIndex lists users once and maps email->id, for bulk grant/revoke
// during apply (single-verb grant/revoke uses the foundation's resolveUserID).
func buildUserIndex(c *cmdCtx) (map[string]int64, error) {
	var users []struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	}
	if err := c.client.Do("GET", "/admin/users", nil, &users); err != nil {
		return nil, err
	}
	idx := make(map[string]int64, len(users))
	for _, u := range users {
		idx[u.Email] = u.ID
	}
	return idx, nil
}

func roleListCmd(c *cmdCtx) error {
	roles, err := fetchRoles(c)
	if err != nil {
		return err
	}
	if c.json {
		return printOut(c, roles)
	}
	if len(roles) == 0 {
		fmt.Println("No roles defined.")
		return nil
	}
	fmt.Printf("%-5s %-25s %-8s %-8s %s\n", "ID", "Name", "Builtin", "Members", "Permissions")
	for _, r := range roles {
		builtin := "no"
		if r.IsBuiltin {
			builtin = "yes"
		}
		fmt.Printf("%-5d %-25s %-8s %-8d %s\n", r.ID, r.Name, builtin, r.MemberCount, strings.Join(r.Permissions, ","))
	}
	return nil
}

func roleCreateCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("role create", flag.ContinueOnError)
	name := fs.String("name", "", "Role name (required)")
	desc := fs.String("desc", "", "Description")
	perms := fs.String("permissions", "", "Comma-separated permission keys (required)")
	domainScope := fs.Int64("domain-scope", 0, "Domain scope ID (0 = global)")
	reason := fs.String("reason", "", "Audit reason (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *perms == "" {
		return fmt.Errorf("--permissions is required")
	}
	if err := requireReason(*reason, "create"); err != nil {
		return err
	}

	body := map[string]interface{}{
		"name":        *name,
		"description": *desc,
		"permissions": splitCSV(*perms),
	}
	if *domainScope > 0 {
		body["domainScope"] = *domainScope
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := c.client.DoWithReason("POST", "/admin/roles", *reason, body, &result); err != nil {
		return err
	}
	if c.json {
		return printOut(c, result)
	}
	fmt.Printf("Role created: id=%d\n", result.ID)
	return nil
}

func roleUpdateCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("role update", flag.ContinueOnError)
	id := fs.Int64("id", 0, "Role ID (required)")
	name := fs.String("name", "", "Role name")
	desc := fs.String("desc", "", "Description")
	perms := fs.String("permissions", "", "Comma-separated permission keys")
	// Server maps domain-scope <=0 to NULL (clear to global) and sod-class "" to NULL.
	domainScope := fs.Int64("domain-scope", 0, "Domain scope ID (<=0 clears to global)")
	sodClass := fs.String("sod-class", "", "SoD class (empty clears)")
	reason := fs.String("reason", "", "Audit reason (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("--id is required")
	}
	if err := requireReason(*reason, "update"); err != nil {
		return err
	}

	// Only send fields the caller explicitly set (partial update).
	body := map[string]interface{}{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			body["name"] = *name
		case "desc":
			body["description"] = *desc
		case "permissions":
			body["permissions"] = splitCSV(*perms)
		case "domain-scope":
			body["domainScope"] = *domainScope
		case "sod-class":
			body["sodClass"] = *sodClass
		}
	})
	if len(body) == 0 {
		return fmt.Errorf("no fields to update (set --name, --desc, --permissions, --domain-scope, or --sod-class)")
	}

	if err := c.client.DoWithReason("PUT", fmt.Sprintf("/admin/roles/%d", *id), *reason, body, nil); err != nil {
		return err
	}
	fmt.Printf("Role %d updated.\n", *id)
	return nil
}

func roleDeleteCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: mailctl role delete <id> --reason <r>")
	}
	id := args[0]
	fs := flag.NewFlagSet("role delete", flag.ContinueOnError)
	reason := fs.String("reason", "", "Audit reason (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if err := requireReason(*reason, "delete"); err != nil {
		return err
	}
	if !confirm(c, "Delete role "+id) {
		return fmt.Errorf("cancelled")
	}
	if err := c.client.DoWithReason("DELETE", "/admin/roles/"+id, *reason, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Role %s deleted.\n", id)
	return nil
}

func roleGrantCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: mailctl role grant <email> --role <name> --reason <r> [--expires <RFC3339>]")
	}
	email := args[0]
	fs := flag.NewFlagSet("role grant", flag.ContinueOnError)
	roleName := fs.String("role", "", "Role name (required)")
	expires := fs.String("expires", "", "Expiry (RFC3339) for a time-boxed grant")
	reason := fs.String("reason", "", "Audit reason (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *roleName == "" {
		return fmt.Errorf("--role is required")
	}
	if err := requireReason(*reason, "grant"); err != nil {
		return err
	}

	role, err := resolveRole(c, *roleName)
	if err != nil {
		return err
	}
	userID, err := resolveUserID(c, email)
	if err != nil {
		return err
	}
	if role.IsBuiltin && !confirm(c, fmt.Sprintf("Grant privileged (built-in) role %q to %s", role.Name, email)) {
		return fmt.Errorf("cancelled")
	}

	body := map[string]interface{}{"userId": userID}
	if *expires != "" {
		body["expiresAt"] = *expires
	}
	if err := c.client.DoWithReason("POST", fmt.Sprintf("/admin/roles/%d/members", role.ID), *reason, body, nil); err != nil {
		return err
	}
	fmt.Printf("Granted role %q to %s.\n", role.Name, email)
	return nil
}

func roleRevokeCmd(c *cmdCtx, args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: mailctl role revoke <email> --role <name> --reason <r>")
	}
	email := args[0]
	fs := flag.NewFlagSet("role revoke", flag.ContinueOnError)
	roleName := fs.String("role", "", "Role name (required)")
	reason := fs.String("reason", "", "Audit reason (required)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *roleName == "" {
		return fmt.Errorf("--role is required")
	}
	if err := requireReason(*reason, "revoke"); err != nil {
		return err
	}

	role, err := resolveRole(c, *roleName)
	if err != nil {
		return err
	}
	userID, err := resolveUserID(c, email)
	if err != nil {
		return err
	}
	if role.IsBuiltin && !confirm(c, fmt.Sprintf("Revoke privileged (built-in) role %q from %s", role.Name, email)) {
		return fmt.Errorf("cancelled")
	}

	if err := c.client.DoWithReason("DELETE", fmt.Sprintf("/admin/roles/%d/members/%d", role.ID, userID), *reason, nil, nil); err != nil {
		return err
	}
	fmt.Printf("Revoked role %q from %s.\n", role.Name, email)
	return nil
}

// ── declarative export / apply / diff ────────────────────────────────────────

func roleExportCmd(c *cmdCtx) error {
	roles, err := fetchRoles(c)
	if err != nil {
		return err
	}
	doc := roleExport{Roles: make([]roleExportEntry, 0, len(roles))}
	for _, r := range roles {
		members, err := fetchRoleMembers(c, r.ID)
		if err != nil {
			return err
		}
		emails := make([]string, 0, len(members))
		for _, m := range members {
			emails = append(emails, m.UserEmail)
		}
		sort.Strings(emails)
		doc.Roles = append(doc.Roles, roleExportEntry{
			Name:        r.Name,
			Description: r.Description,
			Permissions: r.Permissions,
			DomainScope: r.DomainScope,
			IsBuiltin:   r.IsBuiltin,
			Members:     emails,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func roleApplyCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("role apply", flag.ContinueOnError)
	f := fs.String("f", "", "Roles document (JSON); '-' for stdin")
	prune := fs.Bool("prune", false, "Delete live roles/members absent from the document")
	reason := fs.String("reason", "", "Audit reason (required)")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return err
	}
	if err := requireReason(*reason, "apply"); err != nil {
		return err
	}
	doc, err := parseRoleDoc(path)
	if err != nil {
		return err
	}

	// Persistent reason: every mutation reconcile performs carries X-Audit-Reason.
	c.client.Reason = *reason
	changed, err := reconcileRoles(c, doc, true, *prune)
	if err != nil {
		return err
	}
	if changed {
		fmt.Println("Apply complete.")
	} else {
		fmt.Println("No changes; roles already match the document.")
	}
	return nil
}

func roleDiffCmd(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("role diff", flag.ContinueOnError)
	f := fs.String("f", "", "Roles document (JSON); '-' for stdin")
	prune := fs.Bool("prune", false, "Include deletions (roles/members absent from the document)")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return err
	}
	doc, err := parseRoleDoc(path)
	if err != nil {
		return err
	}

	changed, err := reconcileRoles(c, doc, false, *prune)
	if err != nil {
		return err
	}
	if !changed {
		fmt.Println("No drift.")
		return nil
	}
	// ponytail: exit 2 = changes present, mirrors ca diff / terraform plan.
	return exitCodeErr{code: 2, msg: "changes present"}
}

// parseRoleDoc reads + unmarshals a roles document (file path, or "-" for stdin).
func parseRoleDoc(path string) (roleExport, error) {
	raw, err := readFileOrStdin(path)
	if err != nil {
		return roleExport{}, err
	}
	var doc roleExport
	if err := json.Unmarshal(raw, &doc); err != nil {
		return roleExport{}, fmt.Errorf("invalid JSON: %w", err)
	}
	return doc, nil
}

// reconcileRoles compares the desired document against live server state. With
// apply=false it prints the plan and returns whether drift exists; with
// apply=true it performs the create/update/grant (and, with prune, revoke/delete)
// mutations. Built-in roles are never created/updated/deleted (the server
// rejects it) but their memberships still reconcile. Mutations rely on the
// caller having set c.client.Reason so X-Audit-Reason rides every request.
func reconcileRoles(c *cmdCtx, doc roleExport, apply, prune bool) (bool, error) {
	liveRoles, err := fetchRoles(c)
	if err != nil {
		return false, err
	}
	liveByName := make(map[string]roleRow, len(liveRoles))
	for _, r := range liveRoles {
		liveByName[r.Name] = r
	}
	userIdx, err := buildUserIndex(c)
	if err != nil {
		return false, err
	}

	changed := false
	desiredNames := make(map[string]bool, len(doc.Roles))

	for _, want := range doc.Roles {
		desiredNames[want.Name] = true
		live, exists := liveByName[want.Name]

		var roleID int64
		if !exists {
			changed = true
			if want.IsBuiltin {
				fmt.Printf("~ skip built-in role %q (absent; built-ins are server-seeded)\n", want.Name)
				continue
			}
			if apply {
				body := map[string]interface{}{
					"name":        want.Name,
					"description": want.Description,
					"permissions": want.Permissions,
				}
				if want.DomainScope != nil && *want.DomainScope > 0 {
					body["domainScope"] = *want.DomainScope
				}
				var res struct {
					ID int64 `json:"id"`
				}
				if err := c.client.Do("POST", "/admin/roles", body, &res); err != nil {
					return changed, err
				}
				roleID = res.ID
				fmt.Printf("+ created role %q (id=%d)\n", want.Name, roleID)
			} else {
				fmt.Printf("+ create role %q\n", want.Name)
			}
		} else {
			roleID = live.ID
			if !live.IsBuiltin && roleFieldsDiffer(want, live) {
				changed = true
				if apply {
					body := map[string]interface{}{
						"name":        want.Name,
						"description": want.Description,
						"permissions": want.Permissions,
					}
					if err := c.client.Do("PUT", fmt.Sprintf("/admin/roles/%d", roleID), body, nil); err != nil {
						return changed, err
					}
					fmt.Printf("~ updated role %q\n", want.Name)
				} else {
					fmt.Printf("~ update role %q\n", want.Name)
				}
			}
		}

		if err := reconcileMembers(c, want, live, exists, roleID, userIdx, apply, prune, &changed); err != nil {
			return changed, err
		}
	}

	if prune {
		for _, live := range liveRoles {
			if desiredNames[live.Name] || live.IsBuiltin {
				continue
			}
			changed = true
			if apply {
				if err := c.client.Do("DELETE", fmt.Sprintf("/admin/roles/%d", live.ID), nil, nil); err != nil {
					return changed, err
				}
				fmt.Printf("- deleted role %q\n", live.Name)
			} else {
				fmt.Printf("- delete role %q\n", live.Name)
			}
		}
	}

	return changed, nil
}

// reconcileMembers grants desired-but-absent members and (when prune) revokes
// live-but-undesired ones, for a single role. Updates *changed in place.
func reconcileMembers(c *cmdCtx, want roleExportEntry, live roleRow, exists bool, roleID int64, userIdx map[string]int64, apply, prune bool, changed *bool) error {
	liveEmails := map[string]int64{}
	if exists {
		members, err := fetchRoleMembers(c, live.ID)
		if err != nil {
			return err
		}
		for _, m := range members {
			liveEmails[m.UserEmail] = m.UserID
		}
	}

	wantEmails := map[string]bool{}
	for _, e := range want.Members {
		wantEmails[e] = true
		if _, ok := liveEmails[e]; ok {
			continue
		}
		*changed = true
		uid, ok := userIdx[e]
		if !ok {
			return fmt.Errorf("role %q: no user with email %q", want.Name, e)
		}
		if apply {
			if roleID == 0 {
				return fmt.Errorf("role %q: cannot grant members to a role that failed to create", want.Name)
			}
			if err := c.client.Do("POST", fmt.Sprintf("/admin/roles/%d/members", roleID), map[string]interface{}{"userId": uid}, nil); err != nil {
				return err
			}
			fmt.Printf("+ granted %s -> %q\n", e, want.Name)
		} else {
			fmt.Printf("+ grant %s -> %q\n", e, want.Name)
		}
	}

	if prune {
		for e, uid := range liveEmails {
			if wantEmails[e] {
				continue
			}
			*changed = true
			if apply {
				if err := c.client.Do("DELETE", fmt.Sprintf("/admin/roles/%d/members/%d", live.ID, uid), nil, nil); err != nil {
					return err
				}
				fmt.Printf("- revoked %s from %q\n", e, want.Name)
			} else {
				fmt.Printf("- revoke %s from %q\n", e, want.Name)
			}
		}
	}
	return nil
}

// roleFieldsDiffer reports whether the desired entry's description, permission
// set, or domain scope differs from the live role.
func roleFieldsDiffer(want roleExportEntry, live roleRow) bool {
	if want.Description != live.Description {
		return true
	}
	if !sameStringSet(want.Permissions, live.Permissions) {
		return true
	}
	return !sameInt64Ptr(want.DomainScope, live.DomainScope)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func sameInt64Ptr(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
