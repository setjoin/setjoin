package main

import (
	"strings"
	"testing"
)

// TestCommandsTableWellFormed asserts every row in the dispatch table has a
// non-empty name and usage, and a non-nil run — so a future row added without a
// usage line (which would break printSubHelp) or without a run (a nil-call
// panic) fails here at origin, not downstream.
func TestCommandsTableWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range commands {
		if c.name == "" {
			t.Errorf("commands[%d] has an empty name", i)
		}
		if seen[c.name] {
			t.Errorf("commands[%d]: duplicate command name %q", i, c.name)
		}
		seen[c.name] = true
		if c.usage == "" {
			t.Errorf("command %q has an empty usage", c.name)
		}
		if c.run == nil {
			t.Errorf("command %q has a nil run", c.name)
		}
		// The usage line is rendered as "Usage: mailctl <usage>"; it should start
		// with the command name so `mailctl <cmd> -h` reads correctly.
		if !strings.HasPrefix(c.usage, c.name) {
			t.Errorf("command %q usage %q should start with the command name", c.name, c.usage)
		}
	}
}

// TestCommandModesSane locks the per-command mode classification so a future
// edit that, say, sends scim back through the REST path (the original
// inconsistency this refactor removed) trips the test. modeDB is scim + schema
// ONLY; login/logout are modeConfig; dane is modeLocal; version is modePure;
// everything else is modeREST.
func TestCommandModesSane(t *testing.T) {
	wantMode := map[string]mode{
		"login":           modeConfig,
		"logout":          modeConfig,
		"version":         modePure,
		"dane":            modeLocal,
		"backup-db":       modeLocal,
		"restore":         modeLocal,
		"entitlement":     modeLocal,
		"exchange-a0":     modeLocal,
		"exchange":        modeLocal,
		"scim":            modeDB,
		"schema":          modeDB,
		"bootstrap-admin": modeDB,
		"smime":           modeDB,
		"push":            modeDB,
		"user":            modeREST,
		"domain":          modeREST,
		"health":          modeREST,
		"webhook":         modeREST,
		"config":          modeREST,
		"migration":       modeREST,
		"mailbox":         modeREST,
		"backup":          modeREST,
		"upgrade":         modeREST,
		"auto-update":     modeREST,
		"system":          modeREST,
		"tls":             modeREST,
		"ca":              modeREST,
		"eap":             modeREST,
		"spam":            modeREST,
		"storage":         modeREST,
		"device":          modeREST,
		"policy":          modeREST,
		"quarantine":      modeREST,
		"ad":              modeREST,
		"ldap":            modeREST,
		"identity":        modeREST,
		"feature":         modeREST,
		"office":          modeREST,
		"sources":         modeDB,
		"audit":           modeREST,
		"approval":        modeREST,
		"role":            modeREST,
	}

	if len(wantMode) != len(commands) {
		t.Fatalf("table has %d commands, expectation covers %d — keep them in sync", len(commands), len(wantMode))
	}

	var dbCmds []string
	for _, c := range commands {
		want, ok := wantMode[c.name]
		if !ok {
			t.Errorf("command %q not covered by the mode expectation", c.name)
			continue
		}
		if c.mode != want {
			t.Errorf("command %q mode = %d, want %d", c.name, c.mode, want)
		}
		if c.mode == modeDB {
			dbCmds = append(dbCmds, c.name)
		}
	}

	// Exactly the six explicitly local database commands are modeDB.
	if len(dbCmds) != 6 {
		t.Errorf("modeDB commands = %v, want bootstrap-admin/scim/schema/smime/push/sources", dbCmds)
	}

	// preferDirect must be declared correctly: schema prefers DB_DIRECT_DSN,
	// scim uses the pooled DB_DSN; non-modeDB rows leave it false.
	for _, c := range commands {
		switch c.name {
		case "schema", "bootstrap-admin":
			if !c.preferDirect {
				t.Errorf("%s must declare preferDirect=true (DB_DIRECT_DSN policy)", c.name)
			}
		case "scim", "sources":
			if c.preferDirect {
				t.Errorf("%s must declare preferDirect=false (pooled DB_DSN policy)", c.name)
			}
		case "smime":
			if c.preferDirect {
				t.Errorf("smime must declare preferDirect=false (pooled DB_DSN policy)")
			}
		default:
			if c.preferDirect {
				t.Errorf("command %q sets preferDirect but is not modeDB", c.name)
			}
		}
	}
}

// TestLookup confirms lookup resolves known names and rejects unknown ones.
func TestLookup(t *testing.T) {
	if c := lookup("scim"); c == nil || c.name != "scim" {
		t.Errorf("lookup(scim) = %v, want the scim row", c)
	}
	if c := lookup("does-not-exist"); c != nil {
		t.Errorf("lookup(unknown) = %v, want nil", c)
	}
}

// TestHelpListsEveryCommand asserts the full help (printHelp) names every
// command in the table, so the curated help layout can't silently drop a command
// as the table grows. `storage` is a known historical omission from printHelp
// (it predates this refactor; the help content is frozen byte-identical, so it
// is not added here) — but it IS reachable via `mailctl storage -h`
// (printSubHelp, asserted in TestPrintSubHelpDerivesFromTable).
func TestHelpListsEveryCommand(t *testing.T) {
	knownOmitted := map[string]bool{"storage": true}
	help := captureStdout(t, printHelp)
	for _, c := range commands {
		if knownOmitted[c.name] {
			continue
		}
		if !strings.Contains(help, c.name) {
			t.Errorf("printHelp output does not mention command %q", c.name)
		}
	}
}

// TestPrintSubHelpDerivesFromTable confirms every command's per-subcommand help
// is the table's usage line — the single source so help can't drift from
// dispatch.
func TestPrintSubHelpDerivesFromTable(t *testing.T) {
	for _, c := range commands {
		out := captureStdout(t, func() { printSubHelp(c.name) })
		if !strings.Contains(out, "Usage: mailctl "+c.usage) {
			t.Errorf("printSubHelp(%q) = %q, want it to contain the table usage %q", c.name, out, c.usage)
		}
		if !strings.Contains(out, "Flags (all subcommands): --json, --quiet, --yes/-y") {
			t.Errorf("printSubHelp(%q) missing the flags footer: %q", c.name, out)
		}
	}
	// An unknown command falls back to the full help.
	out := captureStdout(t, func() { printSubHelp("nope") })
	if !strings.Contains(out, "mailctl — Mailserver CLI") {
		t.Errorf("printSubHelp(unknown) should fall back to full help, got %q", out)
	}
}

// TestArgsAfter covers the slice-bounds guard the dispatch uses on the already-
// sliced arg list (the analogue of argsAt for os.Args).
func TestArgsAfter(t *testing.T) {
	cases := []struct {
		in   []string
		i    int
		want []string
	}{
		{nil, 1, nil},
		{[]string{"a"}, 1, nil},
		{[]string{"a", "b"}, 1, []string{"b"}},
		{[]string{"a", "b", "c"}, 1, []string{"b", "c"}},
	}
	for _, tc := range cases {
		got := argsAfter(tc.in, tc.i)
		if len(got) != len(tc.want) {
			t.Fatalf("argsAfter(%v, %d) = %v, want %v", tc.in, tc.i, got, tc.want)
		}
		for j := range got {
			if got[j] != tc.want[j] {
				t.Fatalf("argsAfter(%v, %d)[%d] = %q, want %q", tc.in, tc.i, j, got[j], tc.want[j])
			}
		}
	}
}
