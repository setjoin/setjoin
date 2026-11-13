package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validExchangeA0Input(t *testing.T) exchangeA0Input {
	t.Helper()
	registry, _, digest, err := loadExchangeA0Registry()
	if err != nil {
		t.Fatal(err)
	}
	probes := make([]exchangeA0Probe, 0, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		probes = append(probes, exchangeA0Probe{
			CapabilityID: capability.ID,
			Status:       "observed",
			Facts:        json.RawMessage(`{"count":1}`),
		})
	}
	return exchangeA0Input{
		SchemaVersion:    exchangeA0InputSchema,
		ArtifactKind:     "assessment-input",
		CollectorVersion: "a0-v0",
		RegistryDigest:   digest,
		CollectedAt:      "2026-08-23T12:00:00Z",
		Source:           exchangeA0Source{Organization: "设计伙伴 A", Topology: "hybrid", Builds: []string{"Version 15.2"}},
		Probes:           probes,
	}
}

func writeExchangeA0InputFixture(t *testing.T, input exchangeA0Input) string {
	t.Helper()
	raw, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "collector.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExchangeA0RegistryIsReadOnlyAndStable(t *testing.T) {
	registry, raw, digest, err := loadExchangeA0Registry()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(raw)
	if digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("digest = %s, want %x", digest, wantDigest)
	}
	seenCommands := map[string]bool{}
	for _, capability := range registry.Capabilities {
		for _, command := range capability.Commands {
			if !strings.HasPrefix(command, "Get-") {
				t.Errorf("non-read-only command in registry: %s", command)
			}
			seenCommands[command] = true
		}
	}
	if len(seenCommands) != 10 {
		t.Fatalf("registry command count = %d, want 10", len(seenCommands))
	}
}

func TestExchangeA0InputValidationFailsClosed(t *testing.T) {
	registry, _, digest, err := loadExchangeA0Registry()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*exchangeA0Input)
		want string
	}{
		{name: "wrong digest", edit: func(in *exchangeA0Input) { in.RegistryDigest = strings.Repeat("0", 64) }, want: "registry digest mismatch"},
		{name: "unknown capability", edit: func(in *exchangeA0Input) { in.Probes[0].CapabilityID = "UNKNOWN" }, want: "unknown or duplicate"},
		{name: "duplicate capability", edit: func(in *exchangeA0Input) { in.Probes[1].CapabilityID = in.Probes[0].CapabilityID }, want: "unknown or duplicate"},
		{name: "optimistic blocked", edit: func(in *exchangeA0Input) { in.Probes[0].Status = "blocked" }, want: "requires diagnosticId and detail"},
		{name: "observed diagnostic", edit: func(in *exchangeA0Input) { in.Probes[0].DiagnosticID = "SHOULD-NOT" }, want: "must not carry"},
		{name: "unknown status", edit: func(in *exchangeA0Input) { in.Probes[0].Status = "supported" }, want: "invalid status"},
		{name: "noncanonical time", edit: func(in *exchangeA0Input) { in.CollectedAt = "2026-08-23T20:00:00+08:00" }, want: "canonical UTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validExchangeA0Input(t)
			tt.edit(&input)
			if err := validateExchangeA0Input(input, registry, digest); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestExchangeA0InputRejectsUnknownFieldsAndSymlinks(t *testing.T) {
	input := validExchangeA0Input(t)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"futureOptimism":true}`)...)
	path := filepath.Join(t.TempDir(), "unknown.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAndValidateExchangeA0Input(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
	validPath := writeExchangeA0InputFixture(t, input)
	link := filepath.Join(t.TempDir(), "input-link.json")
	if err := os.Symlink(validPath, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := loadAndValidateExchangeA0Input(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestExchangeA0ReportIsDeterministicIncompleteAndEscaped(t *testing.T) {
	input := validExchangeA0Input(t)
	input.Probes = input.Probes[:len(input.Probes)-1]
	input.Probes[0].Facts = json.RawMessage(`{"hostile":"</pre><script>alert(1)</script>","中文":"会议室"}`)
	when := time.Date(2026, 8, 23, 12, 30, 0, 0, time.UTC)
	first, err := buildExchangeA0Report(input, strings.Repeat("a", 64), when)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildExchangeA0Report(input, strings.Repeat("a", 64), when)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same input and timestamp produced different reports")
	}
	if first.Importable || first.Complete != first.Expected-1 {
		t.Fatalf("report importable=%v complete=%d expected=%d", first.Importable, first.Complete, first.Expected)
	}
	last := first.Rows[len(first.Rows)-1]
	if last.Status != "unassessed" || last.DiagnosticID != "A0-MISSING" {
		t.Fatalf("missing probe row = %+v", last)
	}
	html, err := renderExchangeA0HTML(first, "zh-CN")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>alert(1)</script>") || !strings.Contains(string(html), "&lt;script&gt;") {
		t.Fatalf("hostile fact was not HTML-escaped: %s", html)
	}
	if !strings.Contains(string(html), "会议室") {
		t.Fatal("CJK content was lost")
	}
}

func TestExchangeA0ReportArtifactsArePrivateAndBound(t *testing.T) {
	input := validExchangeA0Input(t)
	inputPath := writeExchangeA0InputFixture(t, input)
	loaded, inputDigest, err := loadAndValidateExchangeA0Input(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := buildExchangeA0Report(loaded, inputDigest, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "report")
	if err := writeExchangeA0Report(t.Context(), output, "en-US", report, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.html", "manifest.json"} {
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, info.Mode().Perm())
		}
	}
	if err := writeExchangeA0Report(t.Context(), output, "en-US", report, false); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("second report error = %v", err)
	}
	var manifest exchangeA0Manifest
	raw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.InputDigest != inputDigest || manifest.RowSetDigest != report.RowSetDigest || len(manifest.Artifacts) != 2 {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestExchangeA0OptionalPDFUsesLocalEdgeAndJoinsManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture is POSIX-only; Windows behavior is covered by the real-host lane")
	}
	input := validExchangeA0Input(t)
	inputPath := writeExchangeA0InputFixture(t, input)
	loaded, inputDigest, err := loadAndValidateExchangeA0Input(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := buildExchangeA0Report(loaded, inputDigest, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	fakeEdge := filepath.Join(t.TempDir(), "edge")
	script := "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in --print-to-pdf=*) out=${arg#*=};; esac; done\nprintf '%%PDF-1.4\\n' > \"$out\"\n"
	if err := os.WriteFile(fakeEdge, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SETJOIN_A0_EDGE", fakeEdge)
	output := filepath.Join(t.TempDir(), "report")
	if err := writeExchangeA0Report(t.Context(), output, "zh-CN", report, true); err != nil {
		t.Fatal(err)
	}
	var manifest exchangeA0Manifest
	raw, err := os.ReadFile(filepath.Join(output, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if !validExchangeA0Digest(manifest.Artifacts["report.pdf"]) {
		t.Fatalf("PDF digest missing from manifest: %+v", manifest.Artifacts)
	}
}

func TestExchangeA0FileURLEscapesPortablePaths(t *testing.T) {
	value := exchangeA0FileURL(filepath.Join(string(filepath.Separator), "tmp", "报告 #1.html"))
	if !strings.HasPrefix(value, "file:") || strings.Contains(value, " ") || strings.Contains(value, "#1") || !strings.Contains(value, "%23") {
		t.Fatalf("file URL is not safely escaped: %s", value)
	}
}

func TestExchangeA0AttestationReceiptIsExplicitlyUnsignedAndNonImportable(t *testing.T) {
	input := validExchangeA0Input(t)
	inputPath := writeExchangeA0InputFixture(t, input)
	loaded, inputDigest, err := loadAndValidateExchangeA0Input(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := buildExchangeA0Report(loaded, inputDigest, time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	reportRaw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, append(reportRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	err = runExchangeA0Attest([]string{"--kind", "decision-use", "--report", reportPath, "--organization", "Partner A", "--actor", "Named owner", "--decision", "defer", "--purpose", "Migration go/no-go meeting", "--retention-days", "30", "--issued-at", "2026-08-23T13:00:00Z", "--output", receiptPath})
	if err != nil {
		t.Fatal(err)
	}
	var receipt exchangeA0Receipt
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Importable || receipt.SignatureStatus != "unsigned_customer_attestation" || len(receipt.ReceiptID) != 64 {
		t.Fatalf("receipt = %+v", receipt)
	}
	if err := runExchangeA0VerifyReceipt([]string{"--receipt", receiptPath, "--report", reportPath}); err != nil {
		t.Fatalf("verify generated receipt: %v", err)
	}
	receipt.Purpose = "tampered purpose"
	tampered, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receiptPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runExchangeA0VerifyReceipt([]string{"--receipt", receiptPath, "--report", reportPath}); err == nil || !strings.Contains(err.Error(), "receipt ID mismatch") {
		t.Fatalf("tampered receipt error = %v", err)
	}
}

func TestExchangeA0PowerShellCollectorHasNoDynamicOrMutatingExchangeExecution(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "scripts", "exchange-a0", "Collect-SetjoinExchangeA0.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	var executableLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			executableLines = append(executableLines, line)
		}
	}
	script := strings.Join(executableLines, "\n")
	for _, forbidden := range []string{
		"Invoke-Expression", "[ScriptBlock]::Create", "Invoke-Command", "& $",
		"Invoke-WebRequest", "Invoke-RestMethod", "System.Net.Http", "WebClient", "Start-Process",
		"Set-Mailbox", "Set-CalendarProcessing", "Set-MailboxFolderPermission",
		"Add-MailboxPermission", "Remove-MailboxPermission", "Add-RecipientPermission", "Remove-RecipientPermission",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("collector contains forbidden execution token %q", forbidden)
		}
	}
	if strings.Contains(script, "PrimarySmtpAddress =") || strings.Contains(script, "DisplayName =") {
		t.Fatal("collector appears to serialize raw mailbox identity fields")
	}
}
