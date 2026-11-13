package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"setjoin.com/mailserver/internal/updater"
)

var (
	installRoot  = "/opt/setjoin"
	journalDir   = "/var/lib/setjoin-updater/journal"
	evidenceDir  = "/var/lib/setjoin-updater/recovery-evidence"
	dsnFile      = "/etc/setjoin-updater/updater-dsn"
	effectiveUID = os.Geteuid
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	journal, err := updater.OpenJournal(journalDir)
	if err != nil {
		return fail(err)
	}
	options := updater.RecoveryOptions{InstallRoot: installRoot, EvidenceDir: evidenceDir,
		Journal: journal, Host: updater.SystemdHost{}}
	ctx := context.Background()
	switch args[0] {
	case "status":
		flags := flag.NewFlagSet("status", flag.ContinueOnError)
		asJSON := flags.Bool("json", false, "JSON output")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		status, err := options.Status()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			raw, _ := json.Marshal(status)
			fmt.Println(string(raw))
		} else {
			fmt.Printf("current=%s previous=%s intent=%s state=%s recovery_required=%t database_reconciliation_required=%t\n",
				status.Current, status.Previous, status.IntentID, status.IntentState,
				status.RecoveryRequired, status.DatabaseReconciliationRequired)
		}
		return 0
	case "evidence":
		flags := flag.NewFlagSet("evidence", flag.ContinueOnError)
		reason := flags.String("reason", "operator evidence snapshot", "audited snapshot reason")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
			return 2
		}
		path, err := options.Snapshot(ctx, *reason)
		if err != nil {
			return fail(err)
		}
		fmt.Println(path)
		return 0
	case "activate-previous":
		flags := flag.NewFlagSet("activate-previous", flag.ContinueOnError)
		reason := flags.String("reason", "", "required audited recovery reason")
		force := flags.Bool("force", false, "allow explicit local TTY break-glass entry")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || strings.TrimSpace(*reason) == "" {
			usage()
			return 2
		}
		if effectiveUID() != 0 {
			return fail(fmt.Errorf("activate-previous must run as root"))
		}
		status, err := options.Status()
		if err != nil {
			return fail(err)
		}
		var control *updater.PGControlPlane
		if status.RecoveryRequired || status.DatabaseReconciliationRequired {
			dsn, err := updater.ReadCredentialFile(dsnFile)
			if err != nil {
				return fail(err)
			}
			control, err = updater.OpenPGControlPlane(ctx, dsn)
			if err != nil {
				return fail(err)
			}
			defer func() { _ = control.Close(context.Background()) }()
			options.Control = control
		}
		tty := false
		if info, err := os.Stdin.Stat(); err == nil {
			tty = info.Mode()&os.ModeCharDevice != 0
		}
		path, err := options.Recover(ctx, *reason, *force, tty)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("previous release verified; evidence=%s\n", path)
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: setjoin-recovery status [--json] | evidence [--reason TEXT] | activate-previous --reason TEXT [--force]")
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "setjoin-recovery:", err)
	return 1
}
