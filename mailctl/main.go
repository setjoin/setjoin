package main

import (
	"fmt"
	"os"
)

// argsAt returns os.Args[i:] when the slice is long enough, otherwise an empty
// slice. The argv shim forwards os.Args[2:] to dispatch; indexing os.Args
// directly panics with "slice bounds out of range" on an incomplete command
// line (e.g. `mailctl user`). Callers must use this guard.
func argsAt(i int) []string {
	if len(os.Args) > i {
		return os.Args[i:]
	}
	return nil
}

// isHelpArg reports whether the per-subcommand argument is a help request.
// Without this, `mailctl user -h` treats "-h" as the action and prints
// "unknown user action: -h" instead of usage.
func isHelpArg(s string) bool {
	return s == "-h" || s == "--help" || s == "help"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: mailctl <command> [args...]\nRun 'mailctl help' for available commands.\n")
		os.Exit(1)
	}

	// Thin argv shim: the slice-bounds guards (argsAt) and the help-arg guard
	// stay visible at the entrypoint; everything else (lookup, mode-routing,
	// flag parsing, run) lives in dispatch.go, derived from the commands table.
	dispatch(os.Args[1], argsAt(2))
}

// printHelp prints the full command list. The layout is curated (grouped, with
// per-command descriptions that don't all live in the table's usage strings),
// but every command in the `commands` table is listed here — the
// dispatch_test asserts that coverage so the help cannot silently drift.
func printHelp() {
	fmt.Print(`mailctl — Mailserver CLI

Commands:
  login <server>     Log in interactively (JWT)
  logout             Clear stored credentials

  user create|list|delete|password|quota|bulk-create
    user create --email <e> [--display <d>] [--password <p>]
    user list
    user delete <email>
    user password <email> --new-password <pw>
    user quota get <email>
    user quota set <email> <bytes>
    user bulk-create <file.csv>
  domain add|list|delete
  health check
  version
  webhook create|list|delete|rotate-secret|deliveries|events
  config get|list
  migration list|status|cancel
  mailbox retained|preview|suspend|resume|detach-retain|reconnect
          purge-schedule|purge-approve|purge-deny|purge-cancel|purge-execute
  schema check|apply
  bootstrap-admin    Create the first administrator through the local database authority
  backup run|list|create --pre-upgrade|verify --pre-upgrade <id>
  backup-db          Operator pg_dump -> backup bucket (no gateway)
  restore            Restore through the local filesystem-permissioned control socket
  entitlement import|show  Verify and atomically install an offline Enterprise entitlement
  exchange-a0        Internal read-only A0/v0 Exchange discovery reports and attestations
  exchange assess    V1A Exchange replacement assessment (preflight/sample/collect/inspect/report/import/diagnose)
  upgrade status|watch|cancel|history|diagnostics
  auto-update status|enable|disable
  system status|restart|stop
  dane generate      Generate TLSA DNS record from server certificate
  tls status         Show TLS certificate status and expiry
  tls set            Configure TLS certificate settings
  ca list            List conditional access policies
  ca create          Create a conditional access policy
  ca update          Update a conditional access policy
  ca delete          Delete a conditional access policy
  ca reorder         Reorder conditional access policies
  eap list           List email address policies
  eap create         Create an email address policy
  eap update         Update an email address policy
  eap delete         Delete an email address policy
  eap apply          Enqueue bulk-apply job (async, returns jobId)
  eap reorder        Reorder email address policies
  spam status        Show ML spam classifier health dashboard
  spam reset <id>    Reset spam model for a user
  scim create-token  Create a SCIM provisioning token
  scim list-tokens   List SCIM provisioning tokens
  smime import       Bulk-import users' S/MIME certs at cutover (CSV manifest)
  push doctor        Validate configured push providers (VAPID/APNs/FCM/HMS)
  push test          Send a test push to a user's devices (--user <email>)
  device list        List all MAM devices
  device show <id>   Show device detail
  device events <id> Device detection timeline
  device policy set|unset <id> <key> [value]
                     Set or remove per-device policy override
  device lock <id>   Force-lock a device
  device unlock <id> Clear device lock
  device wipe <id>   Queue remote wipe
  policy list        Show all MAM policies (global + groups)
  policy set <k> <v> Set a global MAM policy
  policy group list|set|unset <type> <id> <key> [value]
                     Manage group-scoped policies
  policy template save|load|list [name]
                     Manage policy templates locally
  quarantine list|stats|preview|release|reject
    quarantine list [--status active|released|rejected|all] [--q <search>] [--limit <n>] [--offset <n>]
    quarantine stats
    quarantine preview <id>
    quarantine release <id>
    quarantine reject <id>
  ad sync|sync-log|health          Active Directory sync (cron-friendly: non-zero exit on sync errors or non-healthy status)
    ad sync                        Trigger an immediate AD sync
    ad sync-log                    Show recent AD sync log entries
    ad health                      Show AD connectivity + last-sync status
  ldap sync|sync-log|health        Generic LDAP directory sync (cron-friendly: non-zero exit on sync errors or non-healthy status)
    ldap sync                      Trigger an immediate LDAP sync
    ldap sync-log                  Show recent LDAP sync log entries
    ldap health                    Show LDAP connectivity + last-sync status
  identity doctor                 Read-only readiness checks with stable exits
  identity inventory              Aggregate or export redacted identity inventory
  identity source|people|conflict Normalized source/person/conflict views
  identity transition             Preview, start, show, export, and list transitions
  identity job                    Show, watch, cancel, and page durable job results
  identity diagnostics            Create, verify, and save a sanitized support bundle
  identity events                 Read normalized identity audit events
  identity upgrade               Preflight, backfill, shadow, canary, rollback, retirement
                                   Mutations require reason; transition start requires fresh AAL2
  feature list|get|set
  feature list       List all feature toggles
  feature get <key>  Show a single feature toggle
  feature set <key> <on|off>
                     Set a feature toggle (confirms for security-family flags)
  office doctor|diagnostics|status|configure|qualify|activate|install
                     Check Office/Drive History feature readiness without reading provider secrets
  sources status|doctor
                     Inspect Collabora, external-provider, and Ubuntu source posture without host writes
  audit export|verify-chain     compliance audit log export + tamper-evidence check
    audit export [--out <file>]           stream the CSV export (GET /admin/audit/csv) to stdout or a file
    audit verify-chain [--from <id>] [--to <id>]
                                           verify the SHA-256 checksum chain (GET /admin/audit/verify); exits
                                           non-zero if any row in range fails verification
  approval list      List approval policies
  approval create    Create an approval policy
  approval update    Update an approval policy
  approval delete    Delete an approval policy
  approval reorder   Reorder approval policies within a consumer type
  approval export    Export approval policies to a JSON document
  approval apply     Idempotently apply a JSON document (create-missing + update-changed)
  approval diff      Show drift between a JSON document and live policies
  approval audit     Show approval-request audit trail
  role list          List RBAC roles (id, builtin, member count, perms)
  role create        Create a role (--name --permissions --reason required)
  role update        Patch a role by --id (only supplied fields; --reason required)
  role delete <id>   Delete a role (--reason required, confirms)
  role grant <email> --role <n>   Grant a role to a user (--reason required)
  role revoke <email> --role <n>  Revoke a role from a user (--reason required)
  role export        Export roles + members to a JSON document (stdout)
  role apply -f <f>  Reconcile roles from a JSON document (--reason required)
  role diff -f <f>   Show drift vs a JSON document (exit 2 = changes present)

Flags (for all subcommands):
  --json             Machine-readable JSON output
  --quiet            Suppress output, exit 0 on success
  --yes, -y          Skip confirmation prompts

All commands support --json, --quiet, and --yes flags.
`)
}

// printSubHelp prints usage for a single subcommand, derived from the command's
// `usage` field in the dispatch table. Printed by `mailctl <cmd> -h` (and a bare
// `mailctl <cmd>` with no action), so an integrator gets usage instead of a
// panic or a misleading "unknown action" error. An unknown command falls back
// to the full help.
func printSubHelp(cmd string) {
	if c := lookup(cmd); c != nil {
		fmt.Printf("Usage: mailctl %s\n\nFlags (all subcommands): --json, --quiet, --yes/-y\n", c.usage)
		return
	}
	printHelp()
}
