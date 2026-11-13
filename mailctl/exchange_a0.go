package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	exchangeA0InputSchema    = "setjoin.exchange.a0.input/v0"
	exchangeA0ReportSchema   = "setjoin.exchange.a0.report/v0"
	exchangeA0ManifestSchema = "setjoin.exchange.a0.manifest/v0"
	exchangeA0ReceiptSchema  = "setjoin.exchange.a0.receipt/v0"
	maxExchangeA0InputBytes  = 16 << 20
)

//go:embed exchange_a0_registry_v0.json
var exchangeA0Files embed.FS

type exchangeA0Registry struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Capabilities  []exchangeA0Capability `json:"capabilities"`
}

type exchangeA0Capability struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Outcome  string   `json:"outcome"`
	Commands []string `json:"commands"`
}

type exchangeA0Input struct {
	SchemaVersion    string            `json:"schemaVersion"`
	ArtifactKind     string            `json:"artifactKind"`
	CollectorVersion string            `json:"collectorVersion"`
	RegistryDigest   string            `json:"registryDigest"`
	CollectedAt      string            `json:"collectedAt"`
	Source           exchangeA0Source  `json:"source"`
	Probes           []exchangeA0Probe `json:"probes"`
}

type exchangeA0Source struct {
	Organization string   `json:"organization"`
	Topology     string   `json:"topology"`
	Builds       []string `json:"builds"`
}

type exchangeA0Probe struct {
	CapabilityID string          `json:"capabilityId"`
	Status       string          `json:"status"`
	DiagnosticID string          `json:"diagnosticId,omitempty"`
	Detail       string          `json:"detail,omitempty"`
	Facts        json.RawMessage `json:"facts"`
}

type exchangeA0Report struct {
	SchemaVersion  string                `json:"schemaVersion"`
	Phase          string                `json:"phase"`
	Importable     bool                  `json:"importable"`
	RegistryDigest string                `json:"registryDigest"`
	InputDigest    string                `json:"inputDigest"`
	RowSetDigest   string                `json:"rowSetDigest"`
	GeneratedAt    string                `json:"generatedAt"`
	Source         exchangeA0Source      `json:"source"`
	Complete       int                   `json:"complete"`
	Expected       int                   `json:"expected"`
	Rows           []exchangeA0ReportRow `json:"rows"`
}

type exchangeA0ReportRow struct {
	CapabilityID string          `json:"capabilityId"`
	Title        string          `json:"title"`
	Outcome      string          `json:"outcome"`
	Status       string          `json:"status"`
	DiagnosticID string          `json:"diagnosticId,omitempty"`
	Detail       string          `json:"detail,omitempty"`
	Facts        json.RawMessage `json:"facts"`
}

type exchangeA0Manifest struct {
	SchemaVersion  string            `json:"schemaVersion"`
	RegistryDigest string            `json:"registryDigest"`
	InputDigest    string            `json:"inputDigest"`
	RowSetDigest   string            `json:"rowSetDigest"`
	Artifacts      map[string]string `json:"artifacts"`
}

type exchangeA0Receipt struct {
	SchemaVersion   string `json:"schemaVersion"`
	ReceiptKind     string `json:"receiptKind"`
	ReceiptID       string `json:"receiptId"`
	ReportDigest    string `json:"reportDigest"`
	Organization    string `json:"organization"`
	Actor           string `json:"actor"`
	Decision        string `json:"decision"`
	Purpose         string `json:"purpose"`
	RetentionDays   int    `json:"retentionDays"`
	IssuedAt        string `json:"issuedAt"`
	SignatureStatus string `json:"signatureStatus"`
	Importable      bool   `json:"importable"`
}

func runExchangeA0(_ *cmdCtx, action string, args []string) error {
	switch action {
	case "registry":
		return runExchangeA0Registry(args)
	case "validate":
		return runExchangeA0Validate(args)
	case "report":
		return runExchangeA0Report(args)
	case "attest":
		return runExchangeA0Attest(args)
	case "verify-receipt":
		return runExchangeA0VerifyReceipt(args)
	default:
		return fmt.Errorf("unknown exchange-a0 action %q (expected registry, validate, report, attest, or verify-receipt)", action)
	}
}

func loadExchangeA0Registry() (exchangeA0Registry, []byte, string, error) {
	raw, err := exchangeA0Files.ReadFile("exchange_a0_registry_v0.json")
	if err != nil {
		return exchangeA0Registry{}, nil, "", err
	}
	var registry exchangeA0Registry
	if err := decodeStrictJSON(raw, &registry); err != nil {
		return exchangeA0Registry{}, nil, "", fmt.Errorf("decode embedded A0 registry: %w", err)
	}
	if registry.SchemaVersion != "setjoin.exchange.a0.registry/v0" || len(registry.Capabilities) == 0 {
		return exchangeA0Registry{}, nil, "", errors.New("invalid embedded A0 registry")
	}
	seen := make(map[string]bool, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		if capability.ID == "" || capability.Title == "" || capability.Outcome == "" || len(capability.Commands) == 0 || seen[capability.ID] {
			return exchangeA0Registry{}, nil, "", fmt.Errorf("invalid or duplicate A0 capability %q", capability.ID)
		}
		seen[capability.ID] = true
	}
	digest := sha256.Sum256(raw)
	return registry, raw, hex.EncodeToString(digest[:]), nil
}

func runExchangeA0Registry(args []string) error {
	fs := flag.NewFlagSet("exchange-a0 registry", flag.ContinueOnError)
	output := fs.String("output", "", "write the embedded v0 registry to a new file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("usage: exchange-a0 registry --output <new-file>")
	}
	_, raw, digest, err := loadExchangeA0Registry()
	if err != nil {
		return err
	}
	if err := writeNewPrivateFile(*output, raw); err != nil {
		return err
	}
	fmt.Printf("A0/v0 registry written to %s\nSHA-256: %s\n", *output, digest)
	return nil
}

func runExchangeA0Validate(args []string) error {
	fs := flag.NewFlagSet("exchange-a0 validate", flag.ContinueOnError)
	inputPath := fs.String("input", "", "A0/v0 collector JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inputPath == "" {
		return errors.New("usage: exchange-a0 validate --input <collector.json>")
	}
	_, digest, err := loadAndValidateExchangeA0Input(*inputPath)
	if err != nil {
		return err
	}
	fmt.Printf("Valid non-importable A0/v0 input. SHA-256: %s\n", digest)
	return nil
}

func loadAndValidateExchangeA0Input(path string) (exchangeA0Input, string, error) {
	raw, err := readBoundedRegularFile(path, maxExchangeA0InputBytes)
	if err != nil {
		return exchangeA0Input{}, "", err
	}
	var input exchangeA0Input
	if err := decodeStrictJSON(raw, &input); err != nil {
		return exchangeA0Input{}, "", fmt.Errorf("decode A0 input: %w", err)
	}
	registry, _, registryDigest, err := loadExchangeA0Registry()
	if err != nil {
		return exchangeA0Input{}, "", err
	}
	if err := validateExchangeA0Input(input, registry, registryDigest); err != nil {
		return exchangeA0Input{}, "", err
	}
	digest := sha256.Sum256(raw)
	return input, hex.EncodeToString(digest[:]), nil
}

func validateExchangeA0Input(input exchangeA0Input, registry exchangeA0Registry, registryDigest string) error {
	if input.SchemaVersion != exchangeA0InputSchema || input.ArtifactKind != "assessment-input" || input.CollectorVersion != "a0-v0" {
		return errors.New("unsupported A0 input schema, kind, or collector version")
	}
	if input.RegistryDigest != registryDigest {
		return fmt.Errorf("registry digest mismatch: input uses %s; embedded registry is %s", input.RegistryDigest, registryDigest)
	}
	if input.Source.Organization == "" || input.Source.Topology == "" || len(input.Source.Builds) == 0 {
		return errors.New("source organization, topology, and at least one build are required")
	}
	if !validExchangeA0Text(input.Source.Organization, 256) || !validExchangeA0Text(input.Source.Topology, 64) || len(input.Source.Builds) > 64 || len(input.Probes) > len(registry.Capabilities) {
		return errors.New("source or probe collection exceeds A0 bounds")
	}
	for _, build := range input.Source.Builds {
		if !validExchangeA0Text(build, 256) {
			return errors.New("source build contains invalid text")
		}
	}
	collectedAt, err := time.Parse(time.RFC3339, input.CollectedAt)
	if err != nil || collectedAt.UTC().Format(time.RFC3339) != input.CollectedAt {
		return errors.New("collectedAt must be canonical UTC RFC3339")
	}
	allowed := make(map[string]bool, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		allowed[capability.ID] = true
	}
	seen := make(map[string]bool, len(input.Probes))
	for _, probe := range input.Probes {
		if !allowed[probe.CapabilityID] || seen[probe.CapabilityID] {
			return fmt.Errorf("unknown or duplicate capabilityId %q", probe.CapabilityID)
		}
		seen[probe.CapabilityID] = true
		if (probe.DiagnosticID != "" && !validExchangeA0Text(probe.DiagnosticID, 128)) || (probe.Detail != "" && !validExchangeA0Text(probe.Detail, 1024)) || len(probe.Facts) > 1<<20 {
			return fmt.Errorf("probe %s exceeds text or fact bounds", probe.CapabilityID)
		}
		switch probe.Status {
		case "observed":
			if probe.DiagnosticID != "" {
				return fmt.Errorf("observed probe %s must not carry a diagnosticId", probe.CapabilityID)
			}
		case "unassessed", "blocked", "unsupported":
			if probe.DiagnosticID == "" || probe.Detail == "" {
				return fmt.Errorf("incomplete probe %s requires diagnosticId and detail", probe.CapabilityID)
			}
		default:
			return fmt.Errorf("invalid status %q for %s", probe.Status, probe.CapabilityID)
		}
		if len(probe.Facts) == 0 || !json.Valid(probe.Facts) {
			return fmt.Errorf("probe %s facts must be valid JSON", probe.CapabilityID)
		}
	}
	return nil
}

func runExchangeA0Report(args []string) error {
	fs := flag.NewFlagSet("exchange-a0 report", flag.ContinueOnError)
	inputPath := fs.String("input", "", "A0/v0 collector JSON")
	outputDir := fs.String("output", "", "new output directory")
	locale := fs.String("locale", "zh-CN", "zh-CN or en-US")
	withPDF := fs.Bool("pdf", false, "also render report.pdf with locally installed Microsoft Edge")
	generatedAt := fs.String("generated-at", "", "canonical UTC RFC3339 time (test/reproduction override)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *inputPath == "" || *outputDir == "" {
		return errors.New("usage: exchange-a0 report --input <collector.json> --output <new-dir> [--locale zh-CN|en-US] [--pdf]")
	}
	if *locale != "zh-CN" && *locale != "en-US" {
		return fmt.Errorf("unsupported locale %q", *locale)
	}
	when := time.Now().UTC().Truncate(time.Second)
	if *generatedAt != "" {
		var err error
		when, err = time.Parse(time.RFC3339, *generatedAt)
		if err != nil || when.UTC().Format(time.RFC3339) != *generatedAt {
			return errors.New("generated-at must be canonical UTC RFC3339")
		}
	}
	input, inputDigest, err := loadAndValidateExchangeA0Input(*inputPath)
	if err != nil {
		return err
	}
	report, err := buildExchangeA0Report(input, inputDigest, when)
	if err != nil {
		return err
	}
	return writeExchangeA0Report(context.Background(), *outputDir, *locale, report, *withPDF)
}

func buildExchangeA0Report(input exchangeA0Input, inputDigest string, generatedAt time.Time) (exchangeA0Report, error) {
	registry, _, registryDigest, err := loadExchangeA0Registry()
	if err != nil {
		return exchangeA0Report{}, err
	}
	probes := make(map[string]exchangeA0Probe, len(input.Probes))
	for _, probe := range input.Probes {
		probes[probe.CapabilityID] = probe
	}
	rows := make([]exchangeA0ReportRow, 0, len(registry.Capabilities))
	complete := 0
	for _, capability := range registry.Capabilities {
		probe, ok := probes[capability.ID]
		if !ok {
			probe = exchangeA0Probe{CapabilityID: capability.ID, Status: "unassessed", DiagnosticID: "A0-MISSING", Detail: "Collector emitted no result for this capability.", Facts: json.RawMessage(`{}`)}
		}
		if probe.Status == "observed" {
			complete++
		}
		rows = append(rows, exchangeA0ReportRow{CapabilityID: capability.ID, Title: capability.Title, Outcome: capability.Outcome, Status: probe.Status, DiagnosticID: probe.DiagnosticID, Detail: probe.Detail, Facts: probe.Facts})
	}
	rowBytes, err := json.Marshal(rows)
	if err != nil {
		return exchangeA0Report{}, err
	}
	rowDigest := sha256.Sum256(rowBytes)
	return exchangeA0Report{SchemaVersion: exchangeA0ReportSchema, Phase: "A0 concierge discovery only — replacement readiness not established", Importable: false, RegistryDigest: registryDigest, InputDigest: inputDigest, RowSetDigest: hex.EncodeToString(rowDigest[:]), GeneratedAt: generatedAt.UTC().Format(time.RFC3339), Source: input.Source, Complete: complete, Expected: len(rows), Rows: rows}, nil
}

func writeExchangeA0Report(ctx context.Context, outputDir, locale string, report exchangeA0Report, withPDF bool) error {
	parent := filepath.Dir(outputDir)
	if _, err := os.Stat(outputDir); err == nil {
		return fmt.Errorf("refusing to replace existing output directory %s", outputDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tempDir, err := os.MkdirTemp(parent, ".exchange-a0-report-*")
	if err != nil {
		return fmt.Errorf("create report staging directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := os.Chmod(tempDir, 0o700); err != nil {
		return err
	}
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	reportJSON = append(reportJSON, '\n')
	htmlBytes, err := renderExchangeA0HTML(report, locale)
	if err != nil {
		return err
	}
	artifacts := map[string][]byte{"report.json": reportJSON, "report.html": htmlBytes}
	for name, data := range artifacts {
		if err := os.WriteFile(filepath.Join(tempDir, name), data, 0o600); err != nil {
			return err
		}
	}
	if withPDF {
		if err := renderExchangeA0PDF(ctx, filepath.Join(tempDir, "report.html"), filepath.Join(tempDir, "report.pdf")); err != nil {
			return err
		}
	}
	manifest := exchangeA0Manifest{SchemaVersion: exchangeA0ManifestSchema, RegistryDigest: report.RegistryDigest, InputDigest: report.InputDigest, RowSetDigest: report.RowSetDigest, Artifacts: map[string]string{}}
	for _, name := range []string{"report.html", "report.json", "report.pdf"} {
		data, err := os.ReadFile(filepath.Join(tempDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		manifest.Artifacts[name] = hex.EncodeToString(digest[:])
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tempDir, "manifest.json"), append(manifestJSON, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempDir, outputDir); err != nil {
		return fmt.Errorf("install report directory: %w", err)
	}
	fmt.Printf("Non-importable A0/v0 report written to %s (%d/%d observed).\n", outputDir, report.Complete, report.Expected)
	return nil
}

func renderExchangeA0HTML(report exchangeA0Report, locale string) ([]byte, error) {
	const page = `<!doctype html><html lang="{{.Locale}}"><head><meta charset="utf-8"><title>Setjoin Exchange A0</title><style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;margin:36px;color:#172033}h1{margin-bottom:4px}.warning{padding:12px;background:#fff4d6;border-left:4px solid #cc8400}.meta{color:#536079}table{border-collapse:collapse;width:100%;margin-top:24px}th,td{border:1px solid #ccd3df;padding:8px;text-align:left;vertical-align:top}th{background:#eef2f8}.observed{color:#176b3a}.blocked,.unsupported,.unassessed{color:#9b2c2c}pre{white-space:pre-wrap;word-break:break-word}@media print{body{margin:12mm}.no-print{display:none}tr{break-inside:avoid}}</style></head><body>
<h1>Setjoin Exchange A0</h1><p class="warning">{{.Report.Phase}} / {{if eq .Locale "zh-CN"}}不可作为产品评估导入或替代承诺。{{else}}Not importable as a product assessment or replacement commitment.{{end}}</p>
<p class="meta">{{.Report.Source.Organization}} · {{.Report.Source.Topology}} · {{.Report.Complete}}/{{.Report.Expected}} observed<br>Registry {{.Report.RegistryDigest}}<br>Rows {{.Report.RowSetDigest}}</p>
<table><thead><tr><th>ID</th><th>Outcome</th><th>Status</th><th>Evidence / blocker</th></tr></thead><tbody>{{range .Report.Rows}}<tr><td>{{.CapabilityID}}<br>{{.Title}}</td><td>{{.Outcome}}</td><td class="{{.Status}}">{{.Status}}{{if .DiagnosticID}}<br>{{.DiagnosticID}}{{end}}</td><td>{{.Detail}}<pre>{{json .Facts}}</pre></td></tr>{{end}}</tbody></table>
<p class="meta">Generated {{.Report.GeneratedAt}} · Input {{.Report.InputDigest}}</p></body></html>`
	tmpl, err := template.New("report").Funcs(template.FuncMap{"json": func(raw json.RawMessage) string {
		var out bytes.Buffer
		if json.Indent(&out, raw, "", "  ") != nil {
			return "{}"
		}
		return out.String()
	}}).Parse(page)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = tmpl.Execute(&out, struct {
		Locale string
		Report exchangeA0Report
	}{Locale: locale, Report: report})
	return out.Bytes(), err
}

func renderExchangeA0PDF(ctx context.Context, htmlPath, pdfPath string) error {
	edge, err := findMicrosoftEdge()
	if err != nil {
		return err
	}
	absHTML, err := filepath.Abs(htmlPath)
	if err != nil {
		return err
	}
	absPDF, err := filepath.Abs(pdfPath)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, edge, "--headless", "--disable-gpu", "--no-pdf-header-footer", "--print-to-pdf="+absPDF, exchangeA0FileURL(absHTML))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("render PDF with Microsoft Edge: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if info, err := os.Stat(absPDF); err != nil || info.Size() == 0 {
		return errors.New("Microsoft Edge did not produce report.pdf")
	}
	return os.Chmod(absPDF, 0o600)
}

func exchangeA0FileURL(path string) string {
	slashed := filepath.ToSlash(path)
	if runtime.GOOS == "windows" && !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

func findMicrosoftEdge() (string, error) {
	if configured := os.Getenv("SETJOIN_A0_EDGE"); configured != "" {
		return configured, nil
	}
	for _, name := range []string{"msedge", "microsoft-edge", "Microsoft Edge"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	if runtime.GOOS == "windows" {
		for _, path := range []string{filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "msedge.exe"), filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "msedge.exe")} {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				return path, nil
			}
		}
	}
	return "", errors.New("Microsoft Edge not found; omit --pdf or set SETJOIN_A0_EDGE")
}

func runExchangeA0Attest(args []string) error {
	fs := flag.NewFlagSet("exchange-a0 attest", flag.ContinueOnError)
	kind := fs.String("kind", "", "handling or decision-use")
	reportPath := fs.String("report", "", "report.json path")
	organization := fs.String("organization", "", "attesting organization")
	actor := fs.String("actor", "", "named attesting actor")
	decision := fs.String("decision", "", "accepted|rejected for handling; go|no-go|defer for decision-use")
	purpose := fs.String("purpose", "", "real handling or decision purpose")
	retentionDays := fs.Int("retention-days", 0, "accepted local retention in days")
	issuedAt := fs.String("issued-at", "", "canonical UTC RFC3339 time")
	output := fs.String("output", "", "new receipt JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *reportPath == "" || *organization == "" || *actor == "" || *purpose == "" || *output == "" || *issuedAt == "" {
		return errors.New("usage: exchange-a0 attest --kind handling|decision-use --report report.json --organization TEXT --actor TEXT --decision VALUE --purpose TEXT --retention-days N --issued-at UTC --output <new-file>")
	}
	if (*kind == "handling" && *decision != "accepted" && *decision != "rejected") || (*kind == "decision-use" && *decision != "go" && *decision != "no-go" && *decision != "defer") {
		return errors.New("invalid receipt kind or decision")
	}
	if !validExchangeA0Text(*organization, 256) || !validExchangeA0Text(*actor, 256) || !validExchangeA0Text(*purpose, 1024) {
		return errors.New("organization, actor, or purpose contains invalid or excessive text")
	}
	when, err := time.Parse(time.RFC3339, *issuedAt)
	if err != nil || when.UTC().Format(time.RFC3339) != *issuedAt || *retentionDays < 0 || *retentionDays > 3650 {
		return errors.New("issued-at must be canonical UTC RFC3339 and retention-days must be 0..3650")
	}
	reportRaw, err := readBoundedRegularFile(*reportPath, maxExchangeA0InputBytes)
	if err != nil {
		return err
	}
	var report exchangeA0Report
	if err := decodeStrictJSON(reportRaw, &report); err != nil {
		return fmt.Errorf("decode A0 report: %w", err)
	}
	if err := validateExchangeA0Report(report); err != nil {
		return errors.New("receipt requires a valid non-importable A0/v0 report")
	}
	reportDigest := sha256.Sum256(reportRaw)
	receipt := exchangeA0Receipt{SchemaVersion: exchangeA0ReceiptSchema, ReceiptKind: *kind, ReportDigest: hex.EncodeToString(reportDigest[:]), Organization: *organization, Actor: *actor, Decision: *decision, Purpose: *purpose, RetentionDays: *retentionDays, IssuedAt: *issuedAt, SignatureStatus: "unsigned_customer_attestation", Importable: false}
	canonical, err := canonicalExchangeA0Receipt(receipt)
	if err != nil {
		return err
	}
	id := sha256.Sum256(canonical)
	receipt.ReceiptID = hex.EncodeToString(id[:])
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNewPrivateFile(*output, append(encoded, '\n')); err != nil {
		return err
	}
	fmt.Printf("Unsigned, non-importable A0/v0 %s receipt written to %s\n", *kind, *output)
	return nil
}

func validateExchangeA0Report(report exchangeA0Report) error {
	registry, _, digest, err := loadExchangeA0Registry()
	if err != nil {
		return err
	}
	if report.SchemaVersion != exchangeA0ReportSchema || report.Importable || report.RegistryDigest != digest || report.Phase != "A0 concierge discovery only — replacement readiness not established" {
		return errors.New("invalid report identity or registry binding")
	}
	if report.Expected != len(registry.Capabilities) || len(report.Rows) != report.Expected || report.Complete < 0 || report.Complete > report.Expected {
		return errors.New("invalid report completeness")
	}
	if !validExchangeA0Text(report.Source.Organization, 256) || !validExchangeA0Text(report.Source.Topology, 64) || len(report.Source.Builds) == 0 || len(report.Source.Builds) > 64 {
		return errors.New("invalid report source")
	}
	for _, build := range report.Source.Builds {
		if !validExchangeA0Text(build, 256) {
			return errors.New("invalid report source build")
		}
	}
	complete := 0
	for i, capability := range registry.Capabilities {
		row := report.Rows[i]
		if row.CapabilityID != capability.ID || row.Title != capability.Title || row.Outcome != capability.Outcome {
			return fmt.Errorf("report row %d does not match registry", i)
		}
		if row.Status == "observed" {
			if row.DiagnosticID != "" {
				return fmt.Errorf("observed report row %s carries a diagnostic", row.CapabilityID)
			}
			complete++
		} else if row.Status != "unassessed" && row.Status != "blocked" && row.Status != "unsupported" {
			return fmt.Errorf("invalid report row status %q", row.Status)
		} else if !validExchangeA0Text(row.DiagnosticID, 128) || !validExchangeA0Text(row.Detail, 1024) {
			return fmt.Errorf("incomplete report row %s lacks a bounded diagnostic", row.CapabilityID)
		}
		if len(row.Facts) == 0 || !json.Valid(row.Facts) {
			return fmt.Errorf("invalid report row facts for %s", row.CapabilityID)
		}
	}
	if complete != report.Complete {
		return errors.New("report complete count does not match rows")
	}
	rows, err := json.Marshal(report.Rows)
	if err != nil {
		return err
	}
	rowDigest := sha256.Sum256(rows)
	if report.RowSetDigest != hex.EncodeToString(rowDigest[:]) {
		return errors.New("report row-set digest mismatch")
	}
	if !validExchangeA0Digest(report.InputDigest) {
		return errors.New("invalid report input digest")
	}
	when, err := time.Parse(time.RFC3339, report.GeneratedAt)
	if err != nil || when.UTC().Format(time.RFC3339) != report.GeneratedAt {
		return errors.New("invalid report generation time")
	}
	return nil
}

func canonicalExchangeA0Receipt(receipt exchangeA0Receipt) ([]byte, error) {
	receipt.ReceiptID = ""
	return json.Marshal(receipt)
}

func validateExchangeA0ReceiptFields(receipt exchangeA0Receipt) error {
	validDecision := (receipt.ReceiptKind == "handling" && (receipt.Decision == "accepted" || receipt.Decision == "rejected")) ||
		(receipt.ReceiptKind == "decision-use" && (receipt.Decision == "go" || receipt.Decision == "no-go" || receipt.Decision == "defer"))
	when, err := time.Parse(time.RFC3339, receipt.IssuedAt)
	if receipt.SchemaVersion != exchangeA0ReceiptSchema || receipt.Importable || receipt.SignatureStatus != "unsigned_customer_attestation" ||
		!validDecision || !validExchangeA0Digest(receipt.ReceiptID) || !validExchangeA0Digest(receipt.ReportDigest) ||
		!validExchangeA0Text(receipt.Organization, 256) || !validExchangeA0Text(receipt.Actor, 256) || !validExchangeA0Text(receipt.Purpose, 1024) ||
		receipt.RetentionDays < 0 || receipt.RetentionDays > 3650 || err != nil || when.UTC().Format(time.RFC3339) != receipt.IssuedAt {
		return errors.New("invalid A0/v0 receipt fields")
	}
	return nil
}

func validExchangeA0Text(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func runExchangeA0VerifyReceipt(args []string) error {
	fs := flag.NewFlagSet("exchange-a0 verify-receipt", flag.ContinueOnError)
	receiptPath := fs.String("receipt", "", "A0/v0 receipt JSON")
	reportPath := fs.String("report", "", "bound report.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *receiptPath == "" || *reportPath == "" {
		return errors.New("usage: exchange-a0 verify-receipt --receipt <receipt.json> --report <report.json>")
	}
	receiptRaw, err := readBoundedRegularFile(*receiptPath, maxExchangeA0InputBytes)
	if err != nil {
		return err
	}
	var receipt exchangeA0Receipt
	if err := decodeStrictJSON(receiptRaw, &receipt); err != nil {
		return fmt.Errorf("decode A0 receipt: %w", err)
	}
	if err := validateExchangeA0ReceiptFields(receipt); err != nil {
		return err
	}
	canonical, err := canonicalExchangeA0Receipt(receipt)
	if err != nil {
		return err
	}
	receiptID := sha256.Sum256(canonical)
	if receipt.ReceiptID != hex.EncodeToString(receiptID[:]) {
		return errors.New("A0 receipt ID mismatch")
	}
	reportRaw, err := readBoundedRegularFile(*reportPath, maxExchangeA0InputBytes)
	if err != nil {
		return err
	}
	var report exchangeA0Report
	if err := decodeStrictJSON(reportRaw, &report); err != nil {
		return fmt.Errorf("decode bound A0 report: %w", err)
	}
	if err := validateExchangeA0Report(report); err != nil {
		return fmt.Errorf("validate bound A0 report: %w", err)
	}
	reportDigest := sha256.Sum256(reportRaw)
	if receipt.ReportDigest != hex.EncodeToString(reportDigest[:]) {
		return errors.New("A0 receipt report digest mismatch")
	}
	fmt.Printf("Valid unsigned, non-importable A0/v0 %s receipt %s\n", receipt.ReceiptKind, receipt.ReceiptID)
	return nil
}

func validExchangeA0Digest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("multiple JSON values are not allowed")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func readBoundedRegularFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("input must be a regular file no larger than %d bytes", max)
	}
	return os.ReadFile(path)
}

func writeNewPrivateFile(path string, data []byte) error {
	_, err := publishPrivateNew(path, data)
	if err != nil {
		return fmt.Errorf("create new output %s: %w", path, err)
	}
	return nil
}
