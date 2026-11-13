package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ca_verbs.go — offline and server verb implementations for CA-1 E2/E3.
// E2: validate, fmt, explain — no server required.
// E3: export, import, apply, diff, migrate, promote, init, why, simulate,
//     coverage, doctor, install-pack, pack, signin-log — server verbs.
// ponytail: shared exitFor + doJSON helpers; one file.

// ── exit-code plumbing ────────────────────────────────────────────────────────

// exitCodeErr wraps an error with a specific process exit code.
// Dispatch inspects this type; the caller of dispatch calls os.Exit(ec.code).
// ponytail: a concrete type, not an interface — simpler type assertion.
type exitCodeErr struct {
	code int
	msg  string
}

func (e exitCodeErr) Error() string { return e.msg }

// exitFor maps a server error (from Client.Do) to the right exitCodeErr.
// HTTP 403 → 3 (auth); BZ087/409 → 4 (conflict); everything else → 1 (generic).
// If err is already an exitCodeErr it passes through unchanged.
func exitFor(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := err.(exitCodeErr); ok {
		return err
	}
	s := err.Error()
	if strings.Contains(s, "HTTP 403") || strings.Contains(s, "HTTP 401") {
		return exitCodeErr{code: 3, msg: s}
	}
	if strings.Contains(s, "HTTP 409") || strings.Contains(s, "BZ087") {
		return exitCodeErr{code: 4, msg: s}
	}
	return err
}

// ── offline verbs ─────────────────────────────────────────────────────────────

// caValidateCmd validates a policy document file against the F6 schema offline.
// Usage: ca validate [--strict] <file.json>
// Exit 0 = valid; exit 2 = schema error (--strict also makes warnings non-zero).
func caValidateCmd(args []string) error {
	fs := flag.NewFlagSet("ca validate", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "treat warnings as errors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: mailctl ca validate [--strict] <file.json>")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("read %s: %w", fs.Arg(0), err)
	}
	warns, err := validateDoc(raw)
	if err != nil {
		// ponytail: exit 2 = validation error per brief §Produces contract.
		return exitCodeErr{code: 2, msg: err.Error()}
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if *strict && len(warns) > 0 {
		return fmt.Errorf("validation failed: %d warning(s) (--strict)", len(warns))
	}
	fmt.Printf("%s: OK (schemaVersion %d)\n", fs.Arg(0), caSchemaVersion)
	return nil
}

// caFmtCmd formats a policy document with canonical stable key order.
// Usage: ca fmt <file.json>  (writes to stdout; pipe to file to update in-place)
func caFmtCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca fmt <file.json>")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	out, err := fmtDoc(raw)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

// caExplainCmd prints the offline plain-English explanation for a BZ error code.
// Usage: ca explain <BZnnn>
func caExplainCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca explain <BZnnn>")
	}
	fmt.Println(explainCode(args[0]))
	return nil
}

// ── server verbs ──────────────────────────────────────────────────────────────
// ponytail: doJSON(cl, method, path, body, &out) is the shared request/print
// helper for the read-only endpoints; write-only endpoints call cl.Do directly.

// doJSON issues method+path, decodes the response into out (any), prints it to
// stdout as indented JSON. out must be a pointer. Returns exitFor(err) so all
// HTTP errors get the right exit code automatically.
func doJSON(cl *Client, method, path string, body interface{}, out interface{}) error {
	if err := cl.Do(method, path, body, out); err != nil {
		return exitFor(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// docPathFlag parses fs (which must already have -f registered as f) against
// args and resolves the document path: the -f value if set, else the first
// remaining positional arg, else "". Shared by every verb that accepts a
// document either via -f or a positional path.
func docPathFlag(fs *flag.FlagSet, f *string, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	path := *f
	if path == "" && fs.NArg() > 0 {
		path = fs.Arg(0)
	}
	return path, nil
}

// readDoc reads a file path from args (flag -f or first positional).
func readDoc(args []string) ([]byte, error) {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	f := fs.String("f", "", "Policy document file (- for stdin)")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("usage: -f <file.json> (or pass file as positional arg)")
	}
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// caExportCmd exports the server's current CA policy set as a JSON document.
// Calls GET /admin/conditional-access/export; writes to stdout.
func caExportCmd(cl *Client, _ []string) error {
	// exitFor is idempotent on a plain error (no HTTP 403/409 substring), so
	// wrapping every stage here (not just request/http/status, as before) is
	// behaviorally identical to the prior selective wrapping.
	return exitFor(cl.rawStream("/admin/conditional-access/export",
		func() (io.Writer, error) { return os.Stdout, nil }, nil))
}

// caImportCmd imports a policy document to the server.
// Usage: ca import -f <file.json> [--mode merge|replace|prune]
func caImportCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca import", flag.ContinueOnError)
	f := fs.String("f", "", "Policy document file")
	mode := fs.String("mode", "merge", "Import mode: merge, replace, prune")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return err
	}
	raw, err := readFileOrStdin(path)
	if err != nil {
		return err
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	url := fmt.Sprintf("/admin/conditional-access/import?mode=%s", *mode)
	if err := cl.Do(http.MethodPost, url, doc, nil); err != nil {
		return exitFor(err)
	}
	fmt.Println("Import complete.")
	return nil
}

// caApplyCmd idempotently applies a document (default mode=replace).
// Usage: ca apply -f <file.json> [--prune]
func caApplyCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca apply", flag.ContinueOnError)
	f := fs.String("f", "", "Policy document file")
	prune := fs.Bool("prune", false, "Use prune mode (removes policies not in doc)")
	path, err := docPathFlag(fs, f, args)
	if err != nil {
		return err
	}
	raw, err := readFileOrStdin(path)
	if err != nil {
		return err
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	mode := "replace"
	if *prune {
		mode = "prune"
	}
	url := fmt.Sprintf("/admin/conditional-access/import?mode=%s", mode)
	if err := cl.Do(http.MethodPost, url, doc, nil); err != nil {
		return exitFor(err)
	}
	fmt.Println("Apply complete.")
	return nil
}

// caDiffCmd shows the diff between a document and the live server state.
// Exit 0 = no change; exit 2 = changes present (Terraform parity); exit 1 = error.
// Usage: ca diff -f <file.json>
func caDiffCmd(cl *Client, args []string) error {
	raw, err := readDoc(args)
	if err != nil {
		return err
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var result struct {
		Drift   bool        `json:"drift"`
		Changes interface{} `json:"changes"`
	}
	if err := cl.Do(http.MethodPost, "/admin/conditional-access/diff", doc, &result); err != nil {
		return exitFor(err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if result.Drift {
		// ponytail: exitCodeErr(2) = changes present, mirrors terraform plan exit code.
		return exitCodeErr{code: 2, msg: "changes present"}
	}
	return nil
}

// caPlanCmd is an alias for diff (reads proposed state, prints what would change).
func caPlanCmd(cl *Client, args []string) error {
	return caDiffCmd(cl, args)
}

// caMigrateCmd migrates legacy policy format to the current schema.
// Calls POST /admin/conditional-access/migrate.
func caMigrateCmd(cl *Client, _ []string) error {
	var result map[string]interface{}
	return doJSON(cl, http.MethodPost, "/admin/conditional-access/migrate", nil, &result)
}

// caPromoteCmd promotes a policy from report_only → on (enforce).
// Fetches impact first; refuses without --yes when would_block > 0.
// Usage: ca promote --id <id> [--yes]
func caPromoteCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca promote", flag.ContinueOnError)
	id := fs.Int("id", 0, "Policy ID (required)")
	yes := fs.Bool("yes", false, "Skip would-block confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == 0 {
		return fmt.Errorf("--id is required")
	}

	// Fetch impact before promoting — guard against accidental lockout.
	var impact struct {
		WouldBlock int `json:"would_block"`
		Matched    int `json:"matched"`
	}
	if err := cl.Do(http.MethodGet,
		fmt.Sprintf("/admin/conditional-access/policies/%d/impact", *id),
		nil, &impact); err != nil {
		return exitFor(err)
	}
	if impact.WouldBlock > 0 && !*yes {
		return fmt.Errorf("promote would block %d user(s) — add --yes to confirm", impact.WouldBlock)
	}

	var result map[string]interface{}
	// The server promote handler requires a JSON body {"confirm": bool}; a nil body
	// is rejected with 400 "invalid JSON". We've already cleared the would-block
	// guard above, so confirm the promotion.
	if err := doJSON(cl, http.MethodPost,
		fmt.Sprintf("/admin/conditional-access/policies/%d/promote", *id),
		map[string]bool{"confirm": true}, &result); err != nil {
		return err
	}
	fmt.Printf("Policy %d promoted to enforced.\n", *id)
	return nil
}

// caInitCmd instantiates a named policy template on the server.
// Usage: ca init <slug>
func caInitCmd(cl *Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca init <template-slug>")
	}
	slug := args[0]
	var result map[string]interface{}
	url := fmt.Sprintf("/admin/conditional-access/templates/%s/instantiate", slug)
	if err := doJSON(cl, http.MethodPost, url, nil, &result); err != nil {
		return err
	}
	fmt.Printf("Policy instantiated from template %q.\n", slug)
	return nil
}

// caWhyCmd shows why a user was allowed/blocked on their last sign-in.
// Usage: ca why <email-or-id> [--correlation <id>]
func caWhyCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca why", flag.ContinueOnError)
	correlation := fs.String("correlation", "", "Correlation ID of a specific sign-in event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	user := fs.Arg(0)
	if user == "" {
		return fmt.Errorf("usage: mailctl ca why <email-or-user-id>")
	}
	qurl := fmt.Sprintf("/admin/conditional-access/why-lookup?user=%s", url.QueryEscape(user))
	if *correlation != "" {
		qurl += "&correlation=" + url.QueryEscape(*correlation)
	}
	var result map[string]interface{}
	return doJSON(cl, http.MethodGet, qurl, nil, &result)
}

// caSimulateCmd simulates policy evaluation for a hypothetical sign-in.
// --expect <decision> exits non-zero when the server's decision doesn't match.
// Usage: ca simulate --user <email> [--ip <ip>] [--device-trust <tier>] [--expect <decision>]
func caSimulateCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca simulate", flag.ContinueOnError)
	user := fs.String("user", "", "User email or ID (required)")
	ip := fs.String("ip", "", "Source IP address")
	deviceTrust := fs.String("device-trust", "", "Device trust tier")
	expect := fs.String("expect", "", "Expected decision (fails if mismatch)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	body := map[string]interface{}{"user": *user}
	if *ip != "" {
		body["ip"] = *ip
	}
	if *deviceTrust != "" {
		body["device_trust"] = *deviceTrust
	}
	var result struct {
		Decision  string      `json:"decision"`
		MatchedBy interface{} `json:"matched_by"`
	}
	if err := cl.Do(http.MethodPost, "/admin/conditional-access/simulate", body, &result); err != nil {
		return exitFor(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if *expect != "" && result.Decision != *expect {
		return fmt.Errorf("simulate: expected %q, got %q", *expect, result.Decision)
	}
	return nil
}

// caCoverageCmd shows coverage gaps in the current policy set.
// --fail-on-gap exits non-zero when any gaps are found.
// Usage: ca coverage [--fail-on-gap]
func caCoverageCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca coverage", flag.ContinueOnError)
	failOnGap := fs.Bool("fail-on-gap", false, "Exit non-zero if any gaps found")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var result struct {
		Gaps     int `json:"gaps"`
		Shadowed int `json:"shadowed"`
	}
	if err := cl.Do(http.MethodGet, "/admin/conditional-access/coverage", nil, &result); err != nil {
		return exitFor(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}

	if *failOnGap && result.Gaps > 0 {
		return fmt.Errorf("coverage: %d gap(s) found", result.Gaps)
	}
	return nil
}

// caDoctorCmd aggregates CA health checks into a score + next-actions.
// Usage: ca doctor [--json]
// --json: emit machine-readable JSON; default: human-readable summary.
func caDoctorCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Output raw JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var result struct {
		Score  int `json:"score"`
		Total  int `json:"total"`
		Checks []struct {
			Name       string `json:"name"`
			Passed     bool   `json:"passed"`
			NextAction string `json:"next_action,omitempty"`
		} `json:"checks"`
		Hygiene struct {
			StaleReportOnly []struct {
				ID        int64  `json:"id"`
				Name      string `json:"name"`
				State     string `json:"state"`
				DaysSince int64  `json:"days_since_created"`
			} `json:"stale_report_only"`
		} `json:"hygiene"`
		TimeToFirstPolicySec *int64 `json:"time_to_first_policy_sec"`
	}
	if err := cl.Do(http.MethodGet, "/admin/conditional-access/doctor", nil, &result); err != nil {
		return exitFor(err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// ponytail: human-readable summary; no tabwriter needed — compact bullet list.
	icon := func(passed bool) string {
		if passed {
			return "[PASS]"
		}
		return "[FAIL]"
	}
	fmt.Printf("CA health: %d/%d checks passed\n\n", result.Score, result.Total)
	for _, c := range result.Checks {
		fmt.Printf("  %s %s\n", icon(c.Passed), c.Name)
		if c.NextAction != "" {
			fmt.Printf("       → %s\n", c.NextAction)
		}
	}

	if len(result.Hygiene.StaleReportOnly) > 0 {
		fmt.Printf("\nHygiene: %d stale report_only policy/policies (>30d):\n", len(result.Hygiene.StaleReportOnly))
		for _, p := range result.Hygiene.StaleReportOnly {
			fmt.Printf("  [id=%d] %s — %dd in report_only\n", p.ID, p.Name, p.DaysSince)
		}
		fmt.Println("  → Promote or disable to keep policies actionable.")
	}

	if result.TimeToFirstPolicySec != nil {
		fmt.Printf("\nTime to first enforcing policy: %ds\n", *result.TimeToFirstPolicySec)
	}

	if result.Score < result.Total {
		// ponytail: exitCodeErr(1) so CI pipelines can gate on doctor passing.
		return exitCodeErr{code: 1, msg: "ca doctor: not all checks passed"}
	}
	return nil
}

// caSigninLogCmd shows recent CA-evaluated sign-ins.
// Usage: ca signin-log [--limit N] [--user <user-id>] [--correlation <id>]
func caSigninLogCmd(cl *Client, args []string) error {
	fs := flag.NewFlagSet("ca signin-log", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "Max rows to return")
	// The server filters by numeric user_id or correlation_id (it does not resolve
	// emails); send user_id so the request isn't rejected with
	// "user_id or correlation_id required".
	user := fs.String("user", "", "Filter by numeric user id")
	correlation := fs.String("correlation", "", "Filter by correlation id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	qurl := fmt.Sprintf("/admin/conditional-access/signin-log?limit=%d", *limit)
	if *user != "" {
		qurl += "&user_id=" + url.QueryEscape(*user)
	}
	if *correlation != "" {
		qurl += "&correlation_id=" + url.QueryEscape(*correlation)
	}
	// The server wraps the rows in {"rows": [...]}. Unwrap and emit the bare array
	// so callers (and `| jq`) get a list, not an envelope.
	var resp struct {
		Rows []map[string]interface{} `json:"rows"`
	}
	if err := cl.Do(http.MethodGet, qurl, nil, &resp); err != nil {
		return exitFor(err)
	}
	if resp.Rows == nil {
		resp.Rows = []map[string]interface{}{}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp.Rows)
}

// caInstallPackCmd installs a policy pack file to the server (idempotent import).
// Usage: ca install-pack <pack-file.json>
func caInstallPackCmd(cl *Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca install-pack <pack-file.json>")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %s: %w", args[0], err)
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := cl.Do(http.MethodPost, "/admin/conditional-access/import?mode=merge", doc, nil); err != nil {
		return exitFor(err)
	}
	fmt.Printf("Pack installed from %s.\n", args[0])
	return nil
}

// caPackCmd runs pack sub-commands: diff.
// Usage: ca pack diff <pack-file.json>
func caPackCmd(cl *Client, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mailctl ca pack diff <pack-file.json>")
	}
	switch args[0] {
	case "diff":
		if len(args) < 2 {
			return fmt.Errorf("usage: mailctl ca pack diff <pack-file.json>")
		}
		return caDiffCmd(cl, []string{"-f", args[1]})
	default:
		return fmt.Errorf("ca pack: unknown sub-command %q (use: diff)", args[0])
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// readFileOrStdin reads from path; if path is empty or "-", reads stdin.
func readFileOrStdin(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("usage: -f <file.json> (or pass file as first positional arg)")
	}
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return data, nil
}
