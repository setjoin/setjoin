package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// cliSecretMaxBytes bounds a stdin-delivered secret, matching the 4096-byte
// ceiling readPrivateCredentialFile enforces for file-delivered secrets.
const cliSecretMaxBytes = 4096

// nonArgvSecret describes the legal sources for a CLI secret. The legacy argv
// flag stays registered so a misuse gets targeted guidance rather than an
// "unknown flag" error, but its value is never used.
type nonArgvSecret struct {
	label    string // human-readable secret name, e.g. "initial password"
	flagName string // legacy argv flag name, e.g. "password"
	value    string // value of the legacy argv flag; only inspected for refusal
	argvSet  bool   // the legacy argv flag was explicitly set on the command line
	file     string // 0600 regular file holding the secret
	stdin    bool   // read one stdin line
}

// flagWasSet reports whether name was explicitly provided on the command line.
// Defaults — including environment-seeded defaults — do not count, which is
// what lets env-sourced credentials keep working while argv values are refused.
func flagWasSet(fs *flag.FlagSet, name string) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			seen = true
		}
	})
	return seen
}

// splitFlagArgs separates positional arguments from flag tokens so commands
// with a positional before their flags (the documented `user password <email>
// --new-password-file <path>` order) still parse every flag: flag.Parse stops
// at the first non-flag token, which would otherwise hide the later flags.
// Everything after a bare "--" is positional, per flag semantics.
func splitFlagArgs(fs *flag.FlagSet, args []string) (flagArgs, positionals []string) {
	takesValue := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if _, isBool := f.Value.(interface{ IsBoolFlag() bool }); !isBool {
			takesValue[f.Name] = true
		}
	})
	consumeNext := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case consumeNext:
			flagArgs = append(flagArgs, arg)
			consumeNext = false
		case arg == "--":
			positionals = append(positionals, args[i+1:]...)
			return flagArgs, positionals
		case len(arg) > 1 && arg[0] == '-':
			flagArgs = append(flagArgs, arg)
			name := strings.TrimLeft(arg, "-")
			if strings.IndexByte(name, '=') >= 0 {
				continue // --name=value form carries its own value
			}
			if takesValue[name] {
				consumeNext = true
			}
		default:
			positionals = append(positionals, arg)
		}
	}
	return flagArgs, positionals
}

// resolveNonArgvSecret implements the module's no-secrets-in-argv control (the
// bootstrap_admin.go / backup_recovery.go / identity.go shape): a regular 0600
// file or one bounded stdin line. An argv-supplied value is refused with
// guidance and never used. An absent source yields "" so callers decide whether
// the secret is required.
func resolveNonArgvSecret(src nonArgvSecret, in io.Reader) (string, error) {
	if src.argvSet {
		return "", fmt.Errorf("--%s must not be passed on the command line (process listings and shell history expose it); pass --%s-file (0600) or --%s-stdin instead",
			src.flagName, src.flagName, src.flagName)
	}
	if src.file != "" && src.stdin {
		return "", fmt.Errorf("choose only one of --%s-file or --%s-stdin", src.flagName, src.flagName)
	}
	switch {
	case src.file != "":
		return readPrivateCredentialFile(src.file, src.label)
	case src.stdin:
		line, err := bufio.NewReader(io.LimitReader(in, cliSecretMaxBytes+1)).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", fmt.Errorf("read %s from stdin: %w", src.label, err)
		}
		secret := strings.TrimRight(line, "\r\n")
		if secret == "" {
			return "", fmt.Errorf("%s from stdin is empty", src.label)
		}
		if len(secret) > cliSecretMaxBytes {
			return "", fmt.Errorf("%s from stdin exceeds %d bytes", src.label, cliSecretMaxBytes)
		}
		return secret, nil
	default:
		return "", nil
	}
}

// ── Output ────────────────────────────────────────────────────────────

// printOut formats output as JSON or human-readable, respecting c.json and
// c.quiet (the per-command flags, formerly the jsonOut/quiet package globals).
func printOut(c *cmdCtx, v interface{}) error {
	if c.quiet {
		return nil
	}
	if c.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	// For slices of maps, print as a table.
	switch src := v.(type) {
	case []map[string]interface{}:
		return printMapSlice(src)
	case string:
		fmt.Println(src)
		return nil
	default:
		fmt.Printf("%v\n", v)
		return nil
	}
}

// printTable writes aligned columnar output using tabwriter.
// headers and rows are provided; column widths are auto-calculated.
func printTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	// Header row
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	// Rows
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

// printMapSlice prints a []map[string]interface{} as a table.
// Columns are derived from the keys present in the first element.
func printMapSlice(items []map[string]interface{}) error {
	if len(items) == 0 {
		fmt.Println("(empty)")
		return nil
	}
	// Determine headers from first element's keys.
	var headers []string
	for k := range items[0] {
		headers = append(headers, k)
	}
	// Build rows.
	rows := make([][]string, len(items))
	for i, item := range items {
		row := make([]string, len(headers))
		for j, h := range headers {
			row[j] = fmt.Sprintf("%v", item[h])
		}
		rows[i] = row
	}
	printTable(headers, rows)
	return nil
}

// ── Confirmation ──────────────────────────────────────────────────────

// confirm asks the user for confirmation before a destructive action.
// Returns true if the user confirms by typing "yes". Skipped if c.yes is set
// (the per-command flag, formerly the yesFlag package global).
func confirm(c *cmdCtx, action string) bool {
	if c.yes {
		return true
	}
	fmt.Fprintf(os.Stderr, "%s — are you sure? (type 'yes' to confirm): ", action)
	var response string
	fmt.Scanln(&response)
	return strings.ToLower(strings.TrimSpace(response)) == "yes"
}

// ── User ──────────────────────────────────────────────────────────────

func runUser(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/users", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "create":
		fs := flag.NewFlagSet("user create", flag.ExitOnError)
		email := fs.String("email", "", "Email address")
		display := fs.String("display", "", "Display name")
		password := fs.String("password", "", "initial password; refused on the command line (process listings expose it) — use --password-file or --password-stdin")
		passwordFile := fs.String("password-file", "", "0600 regular file containing the initial password")
		passwordStdin := fs.Bool("password-stdin", false, "read the initial password from one stdin line")
		fs.Parse(args)
		if *email == "" {
			return fmt.Errorf("--email is required")
		}
		secret, err := resolveNonArgvSecret(nonArgvSecret{
			label: "initial password", flagName: "password",
			value: *password, argvSet: flagWasSet(fs, "password"),
			file: *passwordFile, stdin: *passwordStdin,
		}, os.Stdin)
		if err != nil {
			return err
		}
		var result map[string]interface{}
		if err := cl.Do("POST", "/admin/users", map[string]string{
			"email": *email, "display_name": *display, "password": secret,
		}, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("User %s created (id %v).\n", *email, result["id"])
		return nil

	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("email required")
		}
		if !confirm(c, "Delete user "+args[0]) {
			return fmt.Errorf("cancelled")
		}
		return cl.Do("DELETE", "/admin/users?email="+args[0], nil, nil)

	case "password":
		fs := flag.NewFlagSet("user password", flag.ExitOnError)
		newpw := fs.String("new-password", "", "new password; refused on the command line (process listings expose it) — use --new-password-file or --new-password-stdin")
		newpwFile := fs.String("new-password-file", "", "0600 regular file containing the new password")
		newpwStdin := fs.Bool("new-password-stdin", false, "read the new password from one stdin line")
		flagArgs, positionals := splitFlagArgs(fs, args)
		fs.Parse(flagArgs)
		if len(positionals) < 1 {
			return fmt.Errorf("usage: mailctl user password <email> (--new-password-file <path> | --new-password-stdin)")
		}
		secret, err := resolveNonArgvSecret(nonArgvSecret{
			label: "new password", flagName: "new-password",
			value: *newpw, argvSet: flagWasSet(fs, "new-password"),
			file: *newpwFile, stdin: *newpwStdin,
		}, os.Stdin)
		if err != nil {
			return err
		}
		if secret == "" {
			return fmt.Errorf("a new password is required: pass --new-password-file (0600) or --new-password-stdin")
		}
		email := positionals[0]
		if err := cl.Do("PUT", "/admin/users/"+email+"/password", map[string]string{"new_password": secret}, nil); err != nil {
			return err
		}
		if c.json {
			return printOut(c, map[string]string{"status": "ok", "email": email})
		}
		fmt.Printf("Password updated for %s.\n", email)
		return nil

	case "quota":
		return userQuota(c, args)

	case "bulk-create":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl user bulk-create <file.csv>")
		}
		return bulkCreateUsers(c, args[0])

	default:
		return fmt.Errorf("unknown user action: %s (try: list, create, delete, password, quota, bulk-create)", action)
	}
}

// userQuota implements `user quota get <email>` and `user quota set <email> <bytes>`.
// It resolves the email to a numeric id (no by-email quota route) then hits
// GET/PUT /admin/users/{id}/quota.
func userQuota(c *cmdCtx, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: mailctl user quota get <email> | set <email> <bytes>")
	}
	sub, email := args[0], args[1]
	id, err := resolveUserID(c, email)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/admin/users/%d/quota", id)

	switch sub {
	case "get":
		var result map[string]interface{}
		if err := c.client.Do("GET", path, nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "set":
		if len(args) < 3 {
			return fmt.Errorf("usage: mailctl user quota set <email> <bytes>")
		}
		nbytes, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid bytes %q: %w", args[2], err)
		}
		// The server's SetQuota silently ignores non-positive quotaBytes (a quota
		// cannot be zeroed via this route), so reject it here instead of no-op'ing.
		if nbytes <= 0 {
			return fmt.Errorf("quota bytes must be positive; the server ignores non-positive values (a quota cannot be zeroed this way)")
		}
		if err := c.client.Do("PUT", path, map[string]int64{"quotaBytes": nbytes}, nil); err != nil {
			return err
		}
		if c.json {
			return printOut(c, map[string]interface{}{"email": email, "quotaBytes": nbytes})
		}
		fmt.Printf("Quota set for %s: %d bytes.\n", email, nbytes)
		return nil

	default:
		return fmt.Errorf("unknown quota action: %s (try: get, set)", sub)
	}
}

// parseCSV parses a bulk user CSV with columns: email, display_name, password.
func parseCSV(data []byte) ([]map[string]string, error) {
	r := csv.NewReader(bytes.NewReader(data))
	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if headers[0] != "email" {
		return nil, fmt.Errorf("first column must be 'email', got %q", headers[0])
	}

	var users []map[string]string
	for {
		row, err := r.Read()
		if err != nil {
			break
		}
		u := make(map[string]string)
		for i, h := range headers {
			if i < len(row) {
				u[h] = row[i]
			}
		}
		users = append(users, u)
	}
	return users, nil
}

// bulkCreateUsers reads a CSV file and creates users via the API.
func bulkCreateUsers(c *cmdCtx, filePath string) error {
	cl := c.client
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read %s: %w", filePath, err)
	}
	users, err := parseCSV(data)
	if err != nil {
		return fmt.Errorf("parse CSV: %w", err)
	}

	var created, failed int
	for _, u := range users {
		var result map[string]interface{}
		err := cl.Do("POST", "/admin/users", u, &result)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL %s: %v\n", u["email"], err)
			failed++
			continue
		}
		if !c.quiet {
			fmt.Printf("  CREATED %s\n", u["email"])
		}
		created++
	}
	if !c.quiet {
		fmt.Printf("Done: %d created, %d failed\n", created, failed)
	}
	if failed > 0 {
		return fmt.Errorf("bulk-create: %d/%d failed", failed, len(users))
	}
	return nil
}

// ── Domain ────────────────────────────────────────────────────────────

func runDomain(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "add":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl domain add <name>")
		}
		var result map[string]interface{}
		if err := cl.Do("POST", "/admin/domains", map[string]string{"name": args[0]}, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		fmt.Printf("Domain %s added (id %v).\n", args[0], result["id"])
		return nil
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/domains", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("usage: mailctl domain delete <name>")
		}
		if !confirm(c, "Delete domain "+args[0]) {
			return fmt.Errorf("cancelled")
		}
		return cl.Do("DELETE", "/admin/domains?name="+args[0], nil, nil)
	default:
		return fmt.Errorf("unknown domain action: %s (try: add, list, delete)", action)
	}
}

// ── Health ────────────────────────────────────────────────────────────

func runHealth(c *cmdCtx, action string, args []string) error {
	var result map[string]interface{}
	if err := c.client.Do("GET", "/admin/health", nil, &result); err != nil {
		return err
	}
	return printOut(c, result)
}

// ── Webhook ───────────────────────────────────────────────────────────

func runWebhook(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/webhooks", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "create":
		fs := flag.NewFlagSet("webhook create", flag.ExitOnError)
		url := fs.String("url", "", "Destination URL")
		events := fs.String("events", "", "Comma-separated event types")
		fs.Parse(args)
		if *url == "" || *events == "" {
			return fmt.Errorf("--url and --events are required")
		}
		var result map[string]interface{}
		if err := cl.Do("POST", "/admin/webhooks", map[string]interface{}{
			"url": *url, "eventTypes": strings.Split(*events, ","),
		}, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		// The signing secret is returned exactly once; discarding it (the old bug)
		// left the operator unable to verify HMAC on deliveries.
		secret, _ := result["secret"].(string)
		fmt.Printf("Webhook created (id %v).\n\n", result["id"])
		fmt.Printf("  Signing secret (save now — cannot be recovered):\n  %s\n", secret)
		return nil

	case "delete":
		if len(args) < 1 {
			return fmt.Errorf("webhook ID required")
		}
		if !confirm(c, "Delete webhook "+args[0]) {
			return fmt.Errorf("cancelled")
		}
		return cl.Do("DELETE", "/admin/webhooks/"+args[0], nil, nil)

	case "rotate-secret":
		if len(args) < 1 {
			return fmt.Errorf("webhook ID required")
		}
		var result map[string]interface{}
		if err := cl.Do("POST", "/admin/webhooks/"+args[0]+"/rotate-secret", nil, &result); err != nil {
			return err
		}
		if c.json {
			return printOut(c, result)
		}
		// The new signing secret is returned exactly once — the server keeps only its
		// hash-equivalent (secret + prev_secret). Discarding it here (the old bug) left
		// the operator with a rotated-but-unknown secret and a broken integration.
		secret, _ := result["secret"].(string)
		fmt.Printf("Webhook %s secret rotated.\n\n", args[0])
		fmt.Printf("  New signing secret (save now — cannot be recovered):\n")
		fmt.Printf("  %s\n\n", secret)
		fmt.Printf("Update your receiver's HMAC verification with this secret. The previous\n")
		fmt.Printf("secret stays valid briefly (prev_secret) so in-flight deliveries don't break.\n")
		return nil

	case "deliveries":
		if len(args) < 1 {
			return fmt.Errorf("webhook ID required")
		}
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/webhooks/"+args[0]+"/deliveries", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	case "events":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/webhooks/events", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)

	default:
		return fmt.Errorf("unknown webhook action: %s (try: list, create, delete, rotate-secret, deliveries, events)", action)
	}
}

// ── Config ────────────────────────────────────────────────────────────

func runConfig(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/system/config", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	case "get":
		if len(args) < 1 {
			return fmt.Errorf("config key required")
		}
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/system/config/"+args[0], nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	default:
		return fmt.Errorf("unknown config action: %s (try: get, list)", action)
	}
}

// ── Migration ─────────────────────────────────────────────────────────

func runMigration(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/migration/jobs", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	case "status":
		if len(args) < 1 {
			return fmt.Errorf("job ID required")
		}
		var result map[string]interface{}
		if err := cl.Do("GET", "/admin/migration/jobs/"+args[0], nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	case "cancel":
		if len(args) < 1 {
			return fmt.Errorf("job ID required")
		}
		return cl.Do("POST", "/admin/migration/jobs/"+args[0]+"/cancel", nil, nil)
	default:
		return fmt.Errorf("unknown migration action: %s (try: list, status, cancel)", action)
	}
}

// ── Backup ────────────────────────────────────────────────────────────

func runBackup(c *cmdCtx, action string, args []string) error {
	cl := c.client
	switch action {
	case "create", "verify":
		return runPreUpgradeBackup(c, action, args)
	case "list":
		var result []map[string]interface{}
		if err := cl.Do("GET", "/admin/system/backup/list", nil, &result); err != nil {
			return err
		}
		return printOut(c, result)
	case "run":
		var result map[string]interface{}
		return cl.Do("POST", "/admin/system/backup", nil, &result)
	default:
		return fmt.Errorf("unknown backup action: %s (try: run, list, create, verify)", action)
	}
}
