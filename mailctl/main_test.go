package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestArgsAt covers the slice guard that replaced the raw os.Args[3:] /
// os.Args[2:] indexing. The old code panicked with "slice bounds out of range
// [3:2]" when an integrator typed an incomplete command like `mailctl user`.
func TestArgsAt(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()

	cases := []struct {
		name string
		argv []string
		idx  int
		want []string
	}{
		{"incomplete user (argv len 2), slice at 3", []string{"mailctl", "user"}, 3, nil},
		{"incomplete user (argv len 2), slice at 2", []string{"mailctl", "user"}, 2, nil},
		{"action present, slice at 3 empty", []string{"mailctl", "user", "list"}, 3, nil},
		{"action + flags, slice at 3", []string{"mailctl", "user", "create", "--email", "a@b.c"}, 3, []string{"--email", "a@b.c"}},
		{"slice at 2 returns action+rest", []string{"mailctl", "storage", "migrate"}, 2, []string{"migrate"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.argv
			got := argsAt(tc.idx)
			if len(got) != len(tc.want) {
				t.Fatalf("argsAt(%d) on %v = %v, want %v", tc.idx, tc.argv, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("argsAt(%d)[%d] = %q, want %q", tc.idx, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestIsHelpArg(t *testing.T) {
	for _, s := range []string{"-h", "--help", "help"} {
		if !isHelpArg(s) {
			t.Errorf("isHelpArg(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "list", "create", "-help", "h"} {
		if isHelpArg(s) {
			t.Errorf("isHelpArg(%q) = true, want false", s)
		}
	}
}

// TestPrintSubHelp confirms each known command emits a usage line (and never
// the panic/"unknown action" path) for `mailctl <cmd> -h`.
func TestPrintSubHelp(t *testing.T) {
	for _, cmd := range []string{"user", "domain", "dane", "scim", "storage", "webhook", "device", "policy"} {
		out := captureStdout(t, func() { printSubHelp(cmd) })
		if !strings.Contains(out, "Usage: mailctl "+cmd) {
			t.Errorf("printSubHelp(%q) output missing usage line: %q", cmd, out)
		}
	}
	// Unknown command falls back to the full help.
	out := captureStdout(t, func() { printSubHelp("nope") })
	if !strings.Contains(out, "mailctl — Mailserver CLI") {
		t.Errorf("printSubHelp(unknown) should fall back to full help, got %q", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

// TestIncompleteCommandNoPanic builds the binary and runs the incomplete
// commands + per-subcommand help as a subprocess. This is the regression test
// for the panic: before the fix, `mailctl user` exited with a Go stack trace
// ("slice bounds out of range [3:2]") on stderr. It must now exit cleanly with
// a usage message and no "panic:" in the output.
func TestIncompleteCommandNoPanic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess build in -short mode")
	}
	bin := filepath.Join(t.TempDir(), "mailctl")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build mailctl: %v\n%s", err, out)
	}

	cases := []struct {
		name      string
		args      []string
		wantInOut string // substring expected somewhere in stdout+stderr
	}{
		{"incomplete user", []string{"user"}, "Usage: mailctl user"},
		{"user help short", []string{"user", "-h"}, "Usage: mailctl user"},
		{"user help long", []string{"user", "--help"}, "Usage: mailctl user"},
		{"dane no action", []string{"dane"}, "Usage: mailctl dane"},
		{"dane help", []string{"dane", "-h"}, "Usage: mailctl dane"},
		{"storage no action", []string{"storage"}, "Usage: mailctl storage"},
		{"scim no action", []string{"scim"}, "Usage: mailctl scim"},
		{"domain help", []string{"domain", "-h"}, "Usage: mailctl domain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, tc.args...)
			out, _ := cmd.CombinedOutput()
			s := string(out)
			if strings.Contains(s, "panic:") || strings.Contains(s, "slice bounds out of range") {
				t.Fatalf("`mailctl %s` panicked:\n%s", strings.Join(tc.args, " "), s)
			}
			if !strings.Contains(s, tc.wantInOut) {
				t.Fatalf("`mailctl %s` output missing %q:\n%s", strings.Join(tc.args, " "), tc.wantInOut, s)
			}
		})
	}
}
