package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// mode classifies a command by how its backend is wired before run() executes.
// The dispatch switch (dispatch below) reads the mode to decide what to build
// into the cmdCtx: a REST Client, a DB pool, or nothing.
type mode int

const (
	// modeLocal: fully local, no server and no database (dane). The run gets an
	// empty ctx and parses its own flags from the raw args.
	modeLocal mode = iota
	// modeConfig: the run manages the config file itself (login builds its own
	// Client from the server arg and POSTs /auth/login; logout rewrites config).
	// No Client/DB is populated.
	modeConfig
	// modeREST: needs LoadConfig() -> NewClient(); ctx.client is populated and the
	// global --json/--quiet/--yes flags are parsed into the ctx before run.
	modeREST
	// modeDB: connects directly to PostgreSQL (scim + schema ONLY); ctx.db is
	// populated. scim uses the pooled DB_DSN; schema prefers DB_DIRECT_DSN (DDL
	// bypasses PgBouncer) via resolveSchemaDSN — declared per-row by preferDirect.
	modeDB
	// modePure: prints a literal, touches nothing (version).
	modePure
)

// cmdCtx is the single uniform context handed to every command's run. The active
// field is populated per mode: client for modeREST (and the run builds its own
// for modeConfig), db for modeDB; modeLocal/modePure see neither. A REST run
// observing a nil db (or a DB run a nil client) is a mode-mismatch that the table
// prevents — the doc-comment is the contract, not a runtime guard.
type cmdCtx struct {
	client *Client
	db     *pgxpool.Pool

	// openDB lazily opens the modeDB pool with this command's DSN policy and
	// caches it on db. It is nil for non-modeDB commands. modeDB runs call it
	// AFTER validating the action, so an unknown action (`schema bogus`) still
	// returns its "unknown action" error without first demanding a DSN —
	// byte-identical with the pre-table behavior where each command opened its
	// own pool only on a known action.
	openDB func() (*pgxpool.Pool, error)

	// Global flags, formerly package globals. Parsed from the command line for
	// modeREST commands (the only ones that went through the old default arm);
	// modeDB/modeLocal commands parse their own flags from the raw args, exactly
	// as before.
	json  bool
	quiet bool
	yes   bool
}

// command is one row of the dispatch table. Adding a command is one row here
// (plus its run func); help, backend-wiring, and DB routing all derive from it.
type command struct {
	name string
	mode mode
	// usage is the per-subcommand action/argument line printed by `mailctl <cmd>
	// -h` (printSubHelp) — the single source the help derives from, so it cannot
	// drift from the dispatch.
	usage string
	// preferDirect only matters for modeDB: true => schema's DB_DIRECT_DSN-preferred
	// policy (resolveSchemaDSN); false => scim's pooled DB_DSN. Ignored otherwise.
	preferDirect bool
	run          func(c *cmdCtx, action string, args []string) error
}

// commands is the dispatch table: one row per top-level command. The order here
// is the order printHelp would iterate, but printHelp prints its own curated
// layout (grouped, with descriptions) — the table guarantees coverage, not the
// exact rendering. usage strings feed printSubHelp.
var commands = []command{
	{name: "login", mode: modeConfig, usage: "login <server-url>", run: runLogin},
	{name: "logout", mode: modeConfig, usage: "logout", run: runLogout},

	{name: "user", mode: modeREST, usage: "user create|list|delete|password|quota|bulk-create\n  user create --email <e> [--display <d>] [--password-file <f> | --password-stdin]\n  user list\n  user delete <email>\n  user password <email> (--new-password-file <f> | --new-password-stdin)\n  user quota get <email>\n  user quota set <email> <bytes>\n  user bulk-create <file.csv>", run: runUser},
	{name: "domain", mode: modeREST, usage: "domain add <name> | list | delete <name>", run: runDomain},
	{name: "health", mode: modeREST, usage: "health check", run: runHealth},
	{name: "version", mode: modePure, usage: "version", run: runVersion},
	{name: "webhook", mode: modeREST, usage: "webhook create --url <u> --events <e1,e2> | list | delete <id> | rotate-secret <id> | deliveries <id> | events", run: runWebhook},
	{name: "config", mode: modeREST, usage: "config get <key> | list", run: runConfig},
	{name: "migration", mode: modeREST, usage: "migration list | status <id> | cancel <id>", run: runMigration},
	{name: "mailbox", mode: modeREST, usage: "mailbox retained | parity | preview <mailbox-id> | suspend|resume|detach-retain <mailbox-id> --generation N --reason TEXT | reconnect <mailbox-id> --generation N --target-user ID --evidence-kind local_user|identity_link --reason TEXT | purge-schedule <mailbox-id> --generation N --preview-digest HEX --approver-user ID --reason TEXT | purge-approve|purge-deny <approval-id> [--comment TEXT] | purge-cancel|purge-execute <purge-id> --reason TEXT", run: runMailboxLifecycle},
	{name: "schema", mode: modeDB, preferDirect: true, usage: "schema check [--json] | apply [--yes]\n  (database schema version — forward migrations; requires DB_DSN env var)", run: runSchema},
	{name: "bootstrap-admin", mode: modeDB, preferDirect: true, usage: "bootstrap-admin --email <address> [--password-stdin | --password-file <0600-file>]\n  (local first-boot authority; requires an owner/direct DB DSN and refuses after any user exists)", run: runBootstrapAdmin},
	{name: "backup", mode: modeREST, usage: "backup run | list | create --pre-upgrade [options] | verify --pre-upgrade <recovery-set-id> [options]", run: runBackup},
	{name: "backup-db", mode: modeLocal, usage: "backup-db --bucket <b> --access-key-file <0600-file> --secret-key-file <0600-file> [--dsn <dsn>] [--provider <p>] [--endpoint <e>] [--region <r>]\n  (operator pg_dump -> backup bucket; DSN defaults to owner-first DB_*_DSN precedence; secrets also via BACKUP_ACCESS_KEY/BACKUP_SECRET_KEY env; argv secret flags refused)", run: runBackupDB},
	{name: "restore", mode: modeLocal, usage: "restore --bucket <b> --access-key-file <0600-file> --secret-key-file <0600-file> [--control-socket <absolute-path>] [--type full|config|blobs] [--hashes csv] [--dsn <dsn>] [--dry-run] [--yes]\n  (uses the local Unix control socket; type=full pg_restores the DB dump locally; secrets also via BACKUP_ACCESS_KEY/BACKUP_SECRET_KEY env; argv secret flags refused)", run: runRestore},
	{name: "entitlement", mode: modeLocal, usage: "entitlement import <file> [--json] | show [--json]", run: runEntitlement},
	{name: "exchange-a0", mode: modeLocal, usage: "exchange-a0 registry --output <file> | validate --input <collector.json> | report --input <collector.json> --output <new-dir> [--locale zh-CN|en-US] [--pdf] | attest --kind handling|decision-use ... | verify-receipt --receipt <file> --report <file>\n  (internal, customer-local A0/v0 discovery evidence; read-only and not importable as a product assessment)", run: runExchangeA0},
	{name: "exchange", mode: modeLocal, usage: "exchange assess preflight --offline [--json] | sample --output DIR [--json] | collect --input FILE --output DIR [--non-interactive] | inspect BUNDLE [--json] | report BUNDLE --output DIR [--format html,json] | import BUNDLE --project-id ID [--server URL] | diagnose BUNDLE --output FILE\n  (V1A assessment only; replacement readiness is never implied)", run: runExchange},
	{name: "upgrade", mode: modeREST, usage: "upgrade status | watch <intent-id> [--interval 2s] [--timeout 10m] | cancel <intent-id> --generation <n> --reason <text> | history | diagnostics <intent-id> --output <file>", run: runUpgrade},
	{name: "auto-update", mode: modeREST, usage: "auto-update status | enable | disable", run: runAutoUpdate},
	{name: "system", mode: modeREST, usage: "system status | restart [--full] | stop", run: runSystem},
	{name: "dane", mode: modeLocal, usage: "dane generate --cert <pem> --hostname <fqdn> [--usage N] [--selector N] [--matching N]", run: runDane},
	{name: "tls", mode: modeREST, usage: "tls status | set --challenge <c> --domains <d> --email <e> --dns-provider <p>", run: runTLS},
	{name: "ca", mode: modeREST, usage: "ca list | create --name <n> [--state report_only|on|off] ... | update --id <id> ... | delete <id> | reorder <id1> <id2> ...\n  ca export|import|apply|diff|plan|migrate|promote|init|why|simulate|coverage|doctor|install-pack|pack|signin-log\n  ca validate|fmt|explain (offline, no server)", run: runCA},
	{name: "eap", mode: modeREST, usage: "eap list | create --name <n> --primary <tpl> ... | update --id <id> ... | delete <id> | apply [--id <id>] | reorder <id1> <id2> ...", run: runEAP},
	{name: "spam", mode: modeREST, usage: "spam status | reset <userId>", run: runSpam},
	{name: "scim", mode: modeDB, preferDirect: false, usage: "scim create-token --name <n> --source <scim-source-key> [--expiry <dur>] [--deletion-policy soft|hard] | list-tokens\n  (requires DB_DSN env var; source must be an active SCIM identity source)", run: runScim},
	{name: "smime", mode: modeDB, preferDirect: false, usage: "smime import <manifest.csv> [--dry-run] [--default]\n  (bulk-import users' own S/MIME certs at cutover; CSV cols: email,cert_path,key_path[,label]; requires DB_DSN + DB_ENCRYPTION_KEY)", run: runSmime},
	{name: "storage", mode: modeREST, usage: "storage status | migrate | verify\n  (migrate target from STORAGE_PROVIDER env var)", run: runStorage},
	{name: "device", mode: modeREST, usage: "device list | show <id> | events <id> | policy set|unset <id> <key> [value] | lock <id> | unlock <id> | wipe <id> [--level account|device]", run: runDevice},
	{name: "policy", mode: modeREST, usage: "policy list | set <key> <value> | group list|set|unset <type> <id> <key> [value] | template save|load|list [name]", run: runPolicy},

	{name: "push", mode: modeDB, preferDirect: false, usage: "push doctor | test --user <email>\n  push doctor              validate each configured provider (VAPID/APNs cert/FCM SA/HMS); local, no server\n  push test --user <email> send one test push to the user's devices (requires DB_DSN + DB_ENCRYPTION_KEY)", run: runPush},

	{name: "quarantine", mode: modeREST, usage: "quarantine list|stats|preview|release|reject", run: runQuarantine},
	{name: "ad", mode: modeREST, usage: "ad sync|sync-log|health\n  ad sync                 trigger an immediate AD sync (POST /admin/ad/sync)\n  ad sync-log             show recent sync log entries (GET /admin/ad/sync-log)\n  ad health               show connectivity + last-sync status (GET /admin/ad/health)", run: runAD},
	{name: "ldap", mode: modeREST, usage: "ldap sync|sync-log|health\n  ldap sync                trigger an immediate LDAP sync (POST /admin/ldap/sync)\n  ldap sync-log            show recent sync log entries (GET /admin/ldap/sync-log)\n  ldap health              show connectivity + last-sync status (GET /admin/ldap/health)", run: runLDAP},
	{name: "identity", mode: modeREST, usage: "identity inventory|source|people|conflict|transition|events|job|upgrade ... | doctor|diagnostics\n  identity doctor [--source KEY]\n  identity inventory export --output FILE\n  identity source list\n  identity people list\n  identity conflict list\n  identity transition list\n  identity transition preview --person ID --reason TEXT [--idempotency-key UUID]\n  identity transition start DRAFT --preview-digest HEX --reason TEXT [--approval-request ID]\n  identity transition show ID\n  identity transition export ID --output FILE\n  identity events list\n  identity job show|watch|cancel|results UUID\n  identity diagnostics (--source KEY|--transition UUID) --since DURATION --reason TEXT --output FILE\n  identity upgrade status|preflight|backfill|shadow|retirement-check\n  identity upgrade canary plan|enable|disable --source KEY ...\n  identity upgrade rollback --reason TEXT [--yes]", run: runIdentity},
	{name: "feature", mode: modeREST, usage: "feature list|get|set\n  feature list\n  feature get <key>\n  feature set <key> <on|off>", run: runFeature},
	{name: "office", mode: modeREST, usage: "office doctor|diagnostics|status | configure ... | qualify ... | activate ... | install ...\n  (provider configuration and managed CODE installation remain separate from explicit routing activation)", run: runOffice},
	{name: "sources", mode: modeDB, preferDirect: false, usage: "sources status|doctor [--json] [--profile global|china|isolated|custom] [--collabora-registry HOST/REPO]\n  (read-only Collabora/provider/Ubuntu source posture; never changes host files)", run: runSources},
	{name: "audit", mode: modeREST, usage: "audit export [--out <file>] | verify-chain [--from <id>] [--to <id>]", run: runAudit},
	{name: "approval", mode: modeREST, usage: "approval list [--consumer-type <ct>] | create --consumer-type <ct> --name <n> [--enabled] [--conditions <json>] [--requires-approval] [--approver-spec <json>] | update --id <id> [fields...] | delete <id> | reorder --consumer-type <ct> <id1> <id2> ...\n  approval export [--consumer-type <ct>] | apply -f <file.json> | diff -f <file.json> | audit [--limit N] [--offset N]", run: runApproval},
	{name: "role", mode: modeREST, usage: "role list | create --name <n> --permissions <p1,p2> --reason <r> [--desc <d>] [--domain-scope <id>] | update --id <id> --reason <r> [fields...] | delete <id> --reason <r>\n  role grant <email> --role <name> --reason <r> [--expires <RFC3339>] | revoke <email> --role <name> --reason <r>\n  role export | apply -f <file.json> --reason <r> [--prune] | diff -f <file.json> [--prune]", run: runRole},
}

// lookup returns the command row for name, or nil if unknown.
func lookup(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// dispatch is the entrypoint body shared by main(): it resolves the command,
// handles help / unknown exactly as before, builds the cmdCtx per the command's
// mode, parses the global flags for REST commands, and runs the command. It
// exits the process (os.Exit) on the same paths main() did, so behavior is
// byte-identical with the old two-level switch.
func dispatch(cmd string, cmdArgs []string) {
	// `mailctl help` / `-h` / `--help` at the top level.
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		printHelp()
		return
	}

	c := lookup(cmd)
	if c == nil {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'mailctl help' for available commands.\n", cmd)
		os.Exit(1)
	}

	// modeConfig (login/logout) bypasses the generic help/bare-action routing:
	// these were top-level switch cases in the old main and manage their own
	// arg handling (login validates its own arg count; logout ignores extra
	// args). Routing them through printSubHelp would change `mailctl login`
	// (no arg) and `mailctl login -h` behavior. They receive the raw args.
	if c.mode == modeConfig {
		ctx := &cmdCtx{}
		if err := c.run(ctx, "", cmdArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Per-subcommand help and bare-command usage. `version` takes no action, so a
	// bare `mailctl version` falls through to its handler (modePure) rather than
	// printing usage; a `mailctl version -h` still prints usage.
	action := ""
	if len(cmdArgs) > 0 {
		action = cmdArgs[0]
	}
	if isHelpArg(action) {
		printSubHelp(cmd)
		return
	}
	if action == "" && cmd != "version" {
		printSubHelp(cmd)
		return
	}

	ctx := &cmdCtx{}
	var runArgs []string // args passed to run after the action

	switch c.mode {
	case modeLocal, modePure:
		// No backend; run gets the raw args after the action and parses its own
		// flags (dane) or ignores them (version).
		runArgs = argsAfter(cmdArgs, 1)

	case modeConfig:
		// Unreachable: modeConfig is handled by the early return above. Listed so
		// the switch stays exhaustive over mode.

	case modeREST:
		cfg, err := LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Config error: %v\nRun 'mailctl login <server>' first.\n", err)
			os.Exit(1)
		}
		ctx.client = NewClient(cfg)

		// Global flags (--json/--quiet/--yes) may LEAD the post-action args; what
		// remains is forwarded to the subcommand. A subcommand flag (e.g. promote
		// --id, signin-log --limit) is NOT a global flag — ExitOnError used to abort
		// the whole program on it, making every flag-taking subcommand unusable. Use
		// ContinueOnError and, on the first unrecognized flag, forward ALL post-action
		// args to the subcommand (which owns its own flagset).
		postAction := argsAfter(cmdArgs, 1)
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.BoolVar(&ctx.json, "json", false, "JSON output")
		fs.BoolVar(&ctx.quiet, "quiet", false, "Suppress output")
		var yesShort bool
		fs.BoolVar(&ctx.yes, "yes", false, "Skip confirmation prompts")
		fs.BoolVar(&yesShort, "y", false, "Skip confirmation prompts (short)")
		if err := fs.Parse(postAction); err != nil {
			// Hit a subcommand flag — hand the subcommand its raw args untouched.
			runArgs = postAction
		} else {
			runArgs = fs.Args()
		}
		if yesShort {
			ctx.yes = true
		}

	case modeDB:
		// Direct-DB commands declare their DSN intent (preferDirect):
		// schema prefers DB_DIRECT_DSN (DDL over a real connection), scim uses the
		// pooled DB_DSN. A small local opener honours that — NOT a shared seam
		// (the two policies differ; see plan B, DROPPED). It is wired as a lazy
		// opener so the run validates the action BEFORE any DSN is demanded; on
		// success the run pins it to ctx.db (closed below). The run gets the raw
		// args after the action and parses its own flags.
		preferDirect := c.preferDirect
		ctx.openDB = func() (*pgxpool.Pool, error) {
			pool, err := openModeDB(preferDirect)
			if err != nil {
				return nil, err
			}
			ctx.db = pool
			return pool, nil
		}
		defer func() {
			if ctx.db != nil {
				ctx.db.Close()
			}
		}()
		runArgs = argsAfter(cmdArgs, 1)
	}

	if err := c.run(ctx, action, runArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		// ponytail: exitCodeErr carries a specific exit code (0 ok/1 generic/2 drift/3 auth/4 conflict).
		if ec, ok := err.(exitCodeErr); ok {
			os.Exit(ec.code)
		}
		os.Exit(1)
	}
}

// openModeDB opens the pgx pool for a modeDB command. preferDirect selects the
// DSN policy: schema (true) prefers DB_DIRECT_DSN via resolveSchemaDSN; scim
// (false) uses the pooled DB_DSN. This is a tiny dispatch-local helper, not an
// elevated reusable seam (plan B was dropped because the two policies differ).
func openModeDB(preferDirect bool) (*pgxpool.Pool, error) {
	var dsn string
	if preferDirect {
		d, err := resolveSchemaDSN()
		if err != nil {
			return nil, err
		}
		dsn = d
	} else {
		dsn = os.Getenv("DB_DSN")
		if dsn == "" {
			return nil, fmt.Errorf("DB_DSN environment variable is required")
		}
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	return pool, nil
}

// runVersion is the modePure entrypoint: prints the literal version, touches
// nothing. Matches the old `case "version": fmt.Println("mailctl v1.0.0")`.
func runVersion(c *cmdCtx, action string, args []string) error {
	fmt.Println("mailctl v1.0.0")
	return nil
}

// argsAfter returns s[i:] when long enough, else nil — the slice-bounds guard
// (cf. argsAt, which indexes os.Args) applied to an already-sliced arg list.
func argsAfter(s []string, i int) []string {
	if len(s) > i {
		return s[i:]
	}
	return nil
}
