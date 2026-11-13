package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCSV(t *testing.T) {
	csv := []byte("email,display_name,password\nalice@local.com,Alice,temp123\nbob@local.com,Bob,temp456\n")
	users, err := parseCSV(csv)
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0]["email"] != "alice@local.com" {
		t.Errorf("user 0 email = %q, want alice@local.com", users[0]["email"])
	}
	if users[0]["display_name"] != "Alice" {
		t.Errorf("user 0 display_name = %q, want Alice", users[0]["display_name"])
	}
	if users[0]["password"] != "temp123" {
		t.Errorf("user 0 password = %q, want temp123", users[0]["password"])
	}
}

func TestParseCSVEmptyFile(t *testing.T) {
	csv := []byte("email,display_name,password\n")
	users, err := parseCSV(csv)
	if err != nil {
		t.Fatalf("parseCSV: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

func TestParseCSVBadHeader(t *testing.T) {
	csv := []byte("wrong,columns\n")
	_, err := parseCSV(csv)
	if err == nil {
		t.Error("expected error for bad header")
	}
}

func TestPrintMapSlice(t *testing.T) {
	items := []map[string]interface{}{
		{"email": "alice@local.com", "display_name": "Alice", "enabled": true},
		{"email": "bob@local.com", "display_name": "Bob", "enabled": false},
	}
	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printMapSlice(items)

	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("printMapSlice: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	// Verify headers and values appear.
	for _, want := range []string{"email", "display_name", "enabled", "alice@local.com", "Alice"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("expected output to contain %q, got %q", want, out)
		}
	}
}

func TestPrintMapSliceEmpty(t *testing.T) {
	err := printMapSlice([]map[string]interface{}{})
	if err != nil {
		t.Fatalf("printMapSlice empty: %v", err)
	}
}

func TestPrintOutJSON(t *testing.T) {
	// Flags now live on cmdCtx — no process-global save/restore needed.
	c := &cmdCtx{json: true, quiet: false}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printOut(c, map[string]string{"status": "ok"})

	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("printOut JSON: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.Bytes()

	var parsed map[string]string
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("printOut produced invalid JSON: %s", out)
	}
	if parsed["status"] != "ok" {
		t.Errorf("status = %q, want ok", parsed["status"])
	}
}

func TestPrintOutQuiet(t *testing.T) {
	c := &cmdCtx{json: false, quiet: true}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printOut(c, "should not appear")

	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("printOut quiet: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() > 0 {
		t.Errorf("quiet mode should produce no output, got %q", buf.String())
	}
}

func TestConfirmYesFlag(t *testing.T) {
	// confirm should return true without reading stdin when c.yes is set.
	c := &cmdCtx{yes: true}
	if !confirm(c, "Delete test") {
		t.Error("confirm with c.yes=true should return true")
	}
}

func TestPrintTable(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	printTable([]string{"Name", "Status"}, [][]string{
		{"alice", "active"},
		{"bob", "disabled"},
	})

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	out := buf.String()

	for _, want := range []string{"Name", "Status", "alice", "active", "bob", "disabled"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("expected table output to contain %q, got %q", want, out)
		}
	}
}

// ── No-secrets-in-argv control (Invariant 5) ─────────────────────────────

// TestResolveNonArgvSecretRefusesArgvValue asserts the core refusal: a value
// passed via the legacy argv flag errors with guidance and is never used.
func TestResolveNonArgvSecretRefusesArgvValue(t *testing.T) {
	_, err := resolveNonArgvSecret(nonArgvSecret{
		label: "initial password", flagName: "password",
		value: "sekret", argvSet: true,
	}, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected refusal of argv-supplied secret")
	}
	if !strings.Contains(err.Error(), "must not be passed on the command line") {
		t.Errorf("error should carry guidance: %v", err)
	}
	if strings.Contains(err.Error(), "sekret") {
		t.Errorf("refusal must not echo the secret: %v", err)
	}
}

// TestResolveNonArgvSecretMutualExclusion asserts file and stdin are exclusive.
func TestResolveNonArgvSecretMutualExclusion(t *testing.T) {
	_, err := resolveNonArgvSecret(nonArgvSecret{
		label: "new password", flagName: "new-password",
		file: "/tmp/whatever", stdin: true,
	}, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

// TestResolveNonArgvSecretFromFile asserts the 0600-file source, including the
// single trailing-newline trim readPrivateCredentialFile performs.
func TestResolveNonArgvSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveNonArgvSecret(nonArgvSecret{label: "initial password", flagName: "password", file: path}, strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("secret = %q, want file-secret", got)
	}
}

// TestResolveNonArgvSecretRejectsLooseFilePerms asserts the 0600 requirement.
func TestResolveNonArgvSecretRejectsLooseFilePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pw")
	if err := os.WriteFile(path, []byte("file-secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveNonArgvSecret(nonArgvSecret{label: "initial password", flagName: "password", file: path}, strings.NewReader("")); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected 0600 refusal, got %v", err)
	}
}

// TestResolveNonArgvSecretFromStdin asserts the one-line stdin source.
func TestResolveNonArgvSecretFromStdin(t *testing.T) {
	got, err := resolveNonArgvSecret(nonArgvSecret{label: "new password", flagName: "new-password", stdin: true}, strings.NewReader("stdin-secret\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "stdin-secret" {
		t.Errorf("secret = %q, want stdin-secret", got)
	}
	if _, err := resolveNonArgvSecret(nonArgvSecret{label: "new password", flagName: "new-password", stdin: true}, strings.NewReader("\n")); err == nil {
		t.Error("expected error for empty stdin secret")
	}
}

// TestResolveNonArgvSecretAbsentIsOptional asserts an absent source yields ""
// so the caller decides whether the secret is required.
func TestResolveNonArgvSecretAbsentIsOptional(t *testing.T) {
	got, err := resolveNonArgvSecret(nonArgvSecret{label: "initial password", flagName: "password"}, strings.NewReader(""))
	if err != nil || got != "" {
		t.Fatalf("absent source: got (%q, %v), want (\"\", nil)", got, err)
	}
}

// newRecordingUserServer returns an admin API stub capturing method, path, and
// request body for the user surfaces.
func newRecordingUserServer(t *testing.T) (*httptest.Server, *struct {
	method, path, body string
	calls              int
}) {
	t.Helper()
	captured := &struct {
		method, path, body string
		calls              int
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		captured.method, captured.path, captured.body = r.Method, r.URL.Path, string(raw)
		captured.calls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 7}`))
	}))
	t.Cleanup(srv.Close)
	return srv, captured
}

// TestUserCreatePasswordFileSourcedAndArgvRefused asserts user create delivers a
// file-sourced password in the request body and refuses the argv flag outright.
func TestUserCreatePasswordFileSourcedAndArgvRefused(t *testing.T) {
	srv, captured := newRecordingUserServer(t)
	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	c := &cmdCtx{client: cl}

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runUser(c, "create", []string{"--email", "alice@local.test", "--password-file", pwPath}); err != nil {
		t.Fatalf("runUser create: %v", err)
	}
	if captured.method != http.MethodPost || captured.path != "/api/admin/users" {
		t.Fatalf("request = %s %s", captured.method, captured.path)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(captured.body), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["password"] != "file-secret" {
		t.Errorf("body password = %q, want file-secret", body["password"])
	}

	captured.calls = 0
	err := runUser(c, "create", []string{"--email", "alice@local.test", "--password", "sekret"})
	if err == nil || !strings.Contains(err.Error(), "must not be passed on the command line") {
		t.Fatalf("expected argv refusal, got %v", err)
	}
	if captured.calls != 0 {
		t.Errorf("refused create must not reach the API (%d calls)", captured.calls)
	}
}

// TestUserPasswordSourcesAndRefusal mirrors the control on `user password`:
// file/stdin sources deliver the body; the argv flag refuses before any request.
func TestUserPasswordSourcesAndRefusal(t *testing.T) {
	srv, captured := newRecordingUserServer(t)
	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	c := &cmdCtx{client: cl}

	dir := t.TempDir()
	pwPath := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwPath, []byte("rotated-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runUser(c, "password", []string{"alice@local.test", "--new-password-file", pwPath}); err != nil {
		t.Fatalf("runUser password: %v", err)
	}
	if captured.method != http.MethodPut || captured.path != "/api/admin/users/alice@local.test/password" {
		t.Fatalf("request = %s %s", captured.method, captured.path)
	}
	if !strings.Contains(captured.body, "rotated-secret") {
		t.Errorf("body missing file-sourced password: %s", captured.body)
	}

	// No source at all is a required-secret error, not a silent empty password.
	captured.calls = 0
	if err := runUser(c, "password", []string{"alice@local.test"}); err == nil || !strings.Contains(err.Error(), "new password is required") {
		t.Fatalf("expected required-secret error, got %v", err)
	}
	// The argv flag refuses before any API call and never echoes the value.
	err := runUser(c, "password", []string{"alice@local.test", "--new-password", "sekret"})
	if err == nil || !strings.Contains(err.Error(), "must not be passed on the command line") {
		t.Fatalf("expected argv refusal, got %v", err)
	}
	if captured.calls != 0 {
		t.Errorf("refused password change must not reach the API (%d calls)", captured.calls)
	}
}

// TestSplitFlagArgs asserts positional arguments are separated from flag tokens
// in both documented orders, including "--flag value" consumption and "--".
func TestSplitFlagArgs(t *testing.T) {
	fs := flag.NewFlagSet("user password", flag.ContinueOnError)
	fs.String("new-password-file", "", "")
	fs.Bool("new-password-stdin", false, "")

	flagArgs, positionals := splitFlagArgs(fs, []string{"alice@local.test", "--new-password-file", "/tmp/pw"})
	if len(positionals) != 1 || positionals[0] != "alice@local.test" {
		t.Errorf("positionals = %v", positionals)
	}
	if len(flagArgs) != 2 || flagArgs[0] != "--new-password-file" || flagArgs[1] != "/tmp/pw" {
		t.Errorf("flagArgs = %v", flagArgs)
	}

	flagArgs, positionals = splitFlagArgs(fs, []string{"--new-password-stdin", "alice@local.test"})
	if len(positionals) != 1 || positionals[0] != "alice@local.test" {
		t.Errorf("flags-first positionals = %v", positionals)
	}
	if len(flagArgs) != 1 || flagArgs[0] != "--new-password-stdin" {
		t.Errorf("flags-first flagArgs = %v", flagArgs)
	}

	// "--name=value" form must not consume the next token.
	flagArgs, positionals = splitFlagArgs(fs, []string{"--new-password-file=/tmp/pw", "bob@local.test"})
	if len(flagArgs) != 1 || len(positionals) != 1 || positionals[0] != "bob@local.test" {
		t.Errorf("equals-form split: flagArgs=%v positionals=%v", flagArgs, positionals)
	}

	// A bare "--" sends everything after it to positionals.
	flagArgs, positionals = splitFlagArgs(fs, []string{"--new-password-stdin", "--", "carol@local.test"})
	if len(flagArgs) != 1 || len(positionals) != 1 || positionals[0] != "carol@local.test" {
		t.Errorf("dash-dash split: flagArgs=%v positionals=%v", flagArgs, positionals)
	}
}
