package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	exchangeExitUsage       = 2
	exchangeExitPreflight   = 3
	exchangeExitPartial     = 4
	exchangeExitIntegrity   = 5
	exchangeExitRetryable   = 6
	exchangeExitUnsupported = 7
	exchangeExitInternal    = 10
	exchangeBundleSchema    = "setjoin.exchange.bundle/v1"
	exchangeReportSchema    = "setjoin.exchange.report/v1"
)

var exchangeDiagnosticPattern = regexp.MustCompile(`^[A-Z][A-Z0-9-]{1,63}$`)

//go:embed exchange_registry_v1.json
var exchangeV1Files embed.FS

type exchangeV1Registry struct {
	SchemaVersion     string          `json:"schemaVersion"`
	RegistryVersion   int             `json:"registryVersion"`
	CatalogVersion    int             `json:"catalogVersion"`
	SourceDigest      string          `json:"sourceDigest"`
	GeneratedFrom     []string        `json:"generatedFrom"`
	Roots             json.RawMessage `json:"roots"`
	Probes            json.RawMessage `json:"probes"`
	RedactionProfiles json.RawMessage `json:"redactionProfiles"`
	Compatibility     json.RawMessage `json:"compatibility"`
	Capabilities      []struct {
		ID                  string            `json:"id"`
		Category            string            `json:"category"`
		Outcome             map[string]string `json:"outcome"`
		MappingMaximum      string            `json:"mappingMaximum"`
		ClaimMaximum        string            `json:"claimMaximum"`
		Documentation       string            `json:"documentation"`
		ImplementationUnits []string          `json:"implementationUnits"`
		SourceProperties    []string          `json:"sourceProperties"`
		PhaseImpacts        json.RawMessage   `json:"phaseImpacts"`
	} `json:"capabilities"`
	SupportCells []struct {
		ID                  string   `json:"id"`
		ProductFamily       string   `json:"productFamily"`
		Topology            string   `json:"topology"`
		Admission           string   `json:"admission"`
		Digest              string   `json:"digest"`
		NamedCU             string   `json:"namedCU"`
		BuildAllowlist      []string `json:"buildAllowlist"`
		DirectoryAuthority  string   `json:"directoryAuthority"`
		PowerShellRuntime   string   `json:"powerShellRuntime"`
		CloudAdapterVersion string   `json:"cloudAdapterVersion"`
		CollectorVersion    string   `json:"collectorVersion"`
		CatalogVersion      int      `json:"catalogVersion"`
		RegistryVersion     int      `json:"registryVersion"`
		SetjoinRelease      string   `json:"setjoinRelease"`
	} `json:"supportCells"`
}

type exchangeV1Probe struct {
	CapabilityID string         `json:"capabilityId"`
	State        string         `json:"state"`
	DiagnosticID string         `json:"diagnosticId,omitempty"`
	SafeFacts    map[string]any `json:"safeFacts,omitempty"`
}
type exchangeV1Bundle struct {
	SchemaVersion     string            `json:"schemaVersion"`
	Phase             string            `json:"phase"`
	Importable        bool              `json:"importable"`
	RegistryVersion   int               `json:"registryVersion"`
	RegistryDigest    string            `json:"registryDigest"`
	CatalogVersion    int               `json:"catalogVersion"`
	SupportCellID     string            `json:"supportCellId"`
	SupportCellDigest string            `json:"supportCellDigest"`
	CollectorVersion  string            `json:"collectorVersion"`
	CollectedAt       string            `json:"collectedAt"`
	OriginDigest      string            `json:"originDigest"`
	Probes            []exchangeV1Probe `json:"probes"`
}

type exchangeCollectorOutput struct {
	SchemaVersion string            `json:"schemaVersion"`
	SupportCellID string            `json:"supportCellId"`
	CollectedAt   string            `json:"collectedAt"`
	Probes        []exchangeV1Probe `json:"probes"`
}

func runExchange(c *cmdCtx, action string, args []string) error {
	if action != "assess" || len(args) == 0 {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess preflight|sample|collect|inspect|report|import|diagnose"}
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "preflight":
		return exchangePreflight(rest)
	case "sample":
		return exchangeSample(rest)
	case "collect":
		return exchangeCollect(rest)
	case "inspect":
		return exchangeInspect(rest)
	case "report":
		return exchangeReport(rest)
	case "import":
		return exchangeImport(rest)
	case "diagnose":
		return exchangeDiagnose(rest)
	default:
		return exitCodeErr{exchangeExitUsage, fmt.Sprintf("unknown exchange assess action %q", verb)}
	}
}

func loadExchangeV1Registry() (exchangeV1Registry, []byte, error) {
	raw, err := exchangeV1Files.ReadFile("exchange_registry_v1.json")
	if err != nil {
		return exchangeV1Registry{}, nil, err
	}
	var registry exchangeV1Registry
	if err := decodeExchangeV1JSON(raw, &registry); err != nil {
		return registry, nil, err
	}
	if registry.SchemaVersion != "setjoin.exchange.projection/v1" || registry.RegistryVersion < 1 || len(registry.Capabilities) == 0 {
		return registry, nil, errors.New("embedded Exchange registry is invalid")
	}
	return registry, raw, nil
}

func exchangePreflight(args []string) error {
	fs := flag.NewFlagSet("exchange assess preflight", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	offline := fs.Bool("offline", false, "perform no network calls")
	doctor := fs.Bool("doctor", false, "emit developer verification details")
	jsonOut := fs.Bool("json", false, "JSON output")
	configOut := fs.String("write-config", "", "write starter config")
	if err := fs.Parse(args); err != nil {
		return exitCodeErr{exchangeExitUsage, err.Error()}
	}
	registry, raw, err := loadExchangeV1Registry()
	if err != nil {
		return exitCodeErr{exchangeExitIntegrity, err.Error()}
	}
	digest := sha256.Sum256(raw)
	networkDetail := "connected checks not requested"
	if *offline {
		networkDetail = "offline: no network attempted"
	}
	checks := []map[string]any{
		{"id": "PKG-REGISTRY", "status": "pass", "detail": fmt.Sprintf("registry v%d source %s", registry.RegistryVersion, registry.SourceDigest)},
		{"id": "RUNTIME", "status": "pass", "detail": runtime.GOOS + "/" + runtime.GOARCH},
		{"id": "NETWORK", "status": "pass", "detail": networkDetail},
	}
	if *doctor {
		checks = append(checks, map[string]any{"id": "FIXTURE", "status": "pass", "detail": fmt.Sprintf("%d capabilities; embedded sha256 %x", len(registry.Capabilities), digest)})
	}
	if *configOut != "" {
		if err := writeExclusive(*configOut, []byte("schema_version: 1\nexchange:\n  servers: []\ncollection:\n  modules: [topology, identities, delegates, calendars, resources]\n  max_parallel: 4\nredaction:\n  profile: standard\noutput:\n  locale: zh-CN\n  retention_days: 30\n")); err != nil {
			return exitCodeErr{exchangeExitUsage, err.Error()}
		}
	}
	out := map[string]any{"schemaVersion": "setjoin.exchange.preflight/v1", "phase": "V1A assessment only — replacement readiness not established", "offline": *offline, "complete": true, "checks": checks}
	if *jsonOut {
		return printExchangeJSON(out)
	}
	fmt.Println(out["phase"])
	for _, check := range checks {
		fmt.Printf("[PASS] %s: %s\n", check["id"], check["detail"])
	}
	return nil
}

func exchangeSample(args []string) error {
	fs := flag.NewFlagSet("exchange assess sample", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "new output directory")
	jsonOut := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil || *output == "" {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess sample --output <new-dir> [--json]"}
	}
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		return exitCodeErr{exchangeExitIntegrity, err.Error()}
	}
	cell := registry.SupportCells[0]
	probes := make([]exchangeV1Probe, 0, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		probes = append(probes, exchangeV1Probe{CapabilityID: capability.ID, State: "unassessed", DiagnosticID: "SAMPLE-001", SafeFacts: map[string]any{"fixture": true}})
	}
	bundle := exchangeV1Bundle{SchemaVersion: exchangeBundleSchema, Phase: "V1A assessment only — replacement readiness not established", Importable: false, RegistryVersion: registry.RegistryVersion, RegistryDigest: registry.SourceDigest, CatalogVersion: registry.CatalogVersion, SupportCellID: cell.ID, SupportCellDigest: cell.Digest, CollectorVersion: cell.CollectorVersion, CollectedAt: "2026-08-23T00:00:00Z", Probes: probes}
	bundle.OriginDigest = exchangeBundleDigest(bundle)
	raw, _ := json.MarshalIndent(bundle, "", "  ")
	raw = append(raw, '\n')
	if err := os.Mkdir(*output, 0o700); err != nil {
		return exitCodeErr{exchangeExitUsage, fmt.Sprintf("create output: %v", err)}
	}
	if err := writeExclusive(filepath.Join(*output, "bundle.sja"), raw); err != nil {
		return err
	}
	if err := writeExchangeV1Reports(*output, bundle, registry); err != nil {
		return exitCodeErr{exchangeExitInternal, err.Error()}
	}
	if *jsonOut {
		return printExchangeJSON(map[string]any{"output": *output, "originDigest": bundle.OriginDigest, "complete": true})
	}
	fmt.Printf("Sample written to %s\n%s\n", *output, bundle.Phase)
	return nil
}

func exchangeCollect(args []string) error {
	fs := flag.NewFlagSet("exchange assess collect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "output directory")
	input := fs.String("input", "", "strict collector output JSON")
	resume := fs.String("resume", "", "checkpoint file")
	_ = fs.Bool("non-interactive", false, "forbid prompts")
	if err := fs.Parse(args); err != nil || *output == "" || *input == "" {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess collect --input collector.json --output DIR [--resume checkpoint.json]"}
	}
	if *resume != "" {
		return exitCodeErr{exchangeExitUsage, "COLLECT-005: resumable collection is not available in the bounded V1A file-conversion lane; rerun the fixed source collector and collect into a new output directory"}
	}
	raw, err := readBoundedRegularFile(*input, maxExchangeA0InputBytes)
	if err != nil {
		return exitCodeErr{exchangeExitIntegrity, "COLLECT-001: " + err.Error()}
	}
	var collected exchangeCollectorOutput
	if err := decodeExchangeV1JSON(raw, &collected); err != nil {
		return exitCodeErr{exchangeExitIntegrity, "COLLECT-001: " + err.Error()}
	}
	if collected.SchemaVersion != "setjoin.exchange.collector-output/v1" {
		return exitCodeErr{exchangeExitUnsupported, "COLLECT-001: unsupported collector output schema"}
	}
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		return exitCodeErr{exchangeExitIntegrity, err.Error()}
	}
	var cell *struct {
		ID                  string   `json:"id"`
		ProductFamily       string   `json:"productFamily"`
		Topology            string   `json:"topology"`
		Admission           string   `json:"admission"`
		Digest              string   `json:"digest"`
		NamedCU             string   `json:"namedCU"`
		BuildAllowlist      []string `json:"buildAllowlist"`
		DirectoryAuthority  string   `json:"directoryAuthority"`
		PowerShellRuntime   string   `json:"powerShellRuntime"`
		CloudAdapterVersion string   `json:"cloudAdapterVersion"`
		CollectorVersion    string   `json:"collectorVersion"`
		CatalogVersion      int      `json:"catalogVersion"`
		RegistryVersion     int      `json:"registryVersion"`
		SetjoinRelease      string   `json:"setjoinRelease"`
	}
	for i := range registry.SupportCells {
		if registry.SupportCells[i].ID == collected.SupportCellID {
			cell = &registry.SupportCells[i]
			break
		}
	}
	if cell == nil {
		return exitCodeErr{exchangeExitUnsupported, "COLLECT-002: unknown support cell"}
	}
	bundle := exchangeV1Bundle{SchemaVersion: exchangeBundleSchema, Phase: "V1A assessment only — replacement readiness not established", Importable: true, RegistryVersion: registry.RegistryVersion, RegistryDigest: registry.SourceDigest, CatalogVersion: registry.CatalogVersion, SupportCellID: cell.ID, SupportCellDigest: cell.Digest, CollectorVersion: cell.CollectorVersion, CollectedAt: collected.CollectedAt, Probes: collected.Probes}
	bundle.OriginDigest = exchangeBundleDigest(bundle)
	encoded, _ := json.MarshalIndent(bundle, "", "  ")
	encoded = append(encoded, '\n')
	if err := os.Mkdir(*output, 0o700); err != nil {
		return exitCodeErr{exchangeExitUsage, err.Error()}
	}
	bundlePath := filepath.Join(*output, "bundle.sja")
	if err := writeExclusive(bundlePath, encoded); err != nil {
		return exitCodeErr{exchangeExitInternal, err.Error()}
	}
	if _, _, err := readExchangeBundle(bundlePath); err != nil {
		_ = os.Remove(bundlePath)
		_ = os.Remove(*output)
		return err
	}
	if err := writeExchangeV1Reports(*output, bundle, registry); err != nil {
		return exitCodeErr{exchangeExitInternal, err.Error()}
	}
	fmt.Printf("Importable V1A bundle written to %s on %s/%s; live Exchange evidence remains unassessed until the collector output is captured in an approved support cell.\n", *output, runtime.GOOS, runtime.GOARCH)
	return nil
}

func exchangeInspect(args []string) error {
	fs := flag.NewFlagSet("exchange assess inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "JSON output")
	path, flagArgs := exchangeLeadingPath(args)
	if err := fs.Parse(flagArgs); err != nil || (path == "" && fs.NArg() != 1) {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess inspect <bundle.sja> [--json]"}
	}
	if path == "" {
		path = fs.Arg(0)
	}
	bundle, _, err := readExchangeBundle(path)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, p := range bundle.Probes {
		counts[p.State]++
	}
	out := map[string]any{"phase": bundle.Phase, "importable": bundle.Importable, "originDigest": bundle.OriginDigest, "supportCellId": bundle.SupportCellID, "collectorVersion": bundle.CollectorVersion, "counts": counts, "excludedByDefault": []string{"credentials", "tokens", "message content", "raw identities", "customer documents"}}
	if *jsonOut {
		return printExchangeJSON(out)
	}
	fmt.Println(bundle.Phase)
	fmt.Printf("Digest: %s\nSupport cell: %s\n", bundle.OriginDigest, bundle.SupportCellID)
	for state, count := range counts {
		fmt.Printf("%s: %d\n", state, count)
	}
	return nil
}

func exchangeReport(args []string) error {
	fs := flag.NewFlagSet("exchange assess report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "new output directory")
	_ = fs.String("format", "html,json", "formats")
	path, flagArgs := exchangeLeadingPath(args)
	if err := fs.Parse(flagArgs); err != nil || (path == "" && fs.NArg() != 1) || *output == "" {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess report <bundle.sja> --output <new-dir> [--format html,json]"}
	}
	if path == "" {
		path = fs.Arg(0)
	}
	bundle, _, err := readExchangeBundle(path)
	if err != nil {
		return err
	}
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		return err
	}
	if err := os.Mkdir(*output, 0o700); err != nil {
		return exitCodeErr{exchangeExitUsage, err.Error()}
	}
	if err := writeExchangeV1Reports(*output, bundle, registry); err != nil {
		return exitCodeErr{exchangeExitInternal, err.Error()}
	}
	fmt.Printf("Reports written to %s\n", *output)
	return nil
}

func exchangeImport(args []string) error {
	fs := flag.NewFlagSet("exchange assess import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.Int64("project-id", 0, "existing assessment project")
	server := fs.String("server", "", "server URL override")
	jsonOut := fs.Bool("json", false, "JSON output")
	path, flagArgs := exchangeLeadingPath(args)
	if err := fs.Parse(flagArgs); err != nil || (path == "" && fs.NArg() != 1) || *projectID <= 0 {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess import <bundle.sja> --project-id ID [--server URL] [--json]"}
	}
	if path == "" {
		path = fs.Arg(0)
	}
	bundle, raw, err := readExchangeBundle(path)
	if err != nil {
		return err
	}
	if !bundle.Importable {
		return exitCodeErr{exchangeExitIntegrity, "IMPORT-001: this sample/A0 bundle is explicitly non-importable"}
	}
	cfg, err := LoadConfig()
	if err != nil {
		return exitCodeErr{exchangeExitPreflight, err.Error()}
	}
	if *server != "" {
		cfg.Server = *server
	}
	client := NewClient(cfg)
	var run struct {
		ID         int64 `json:"id"`
		Generation int64 `json:"generation"`
	}
	apiRoute := fmt.Sprintf("/admin/exchange-replacement/projects/%d/runs", *projectID)
	body := map[string]any{"supportCellId": bundle.SupportCellID, "supportCellDigest": bundle.SupportCellDigest, "registryVersion": bundle.RegistryVersion, "registryDigest": bundle.RegistryDigest, "catalogVersion": bundle.CatalogVersion, "collectorVersion": bundle.CollectorVersion}
	createRaw, _ := json.Marshal(body)
	createHeaders := make(http.Header)
	createHeaders.Set("X-Audit-Reason", "Import verified Exchange assessment bundle")
	createHeaders.Set("Idempotency-Key", uuid.NewString())
	if err := client.DoRawWithHeadersBounded(http.MethodPost, apiRoute, "application/json", createHeaders, bytes.NewReader(createRaw), &run, 1<<20); err != nil {
		return exchangeExitForAPI(err)
	}
	if run.ID < 1 || run.Generation < 1 {
		return exitCodeErr{exchangeExitInternal, "IMPORT-004: server returned an invalid run receipt"}
	}
	rawDigest := sha256.Sum256(raw)
	headers := make(http.Header)
	headers.Set("X-Audit-Reason", "Upload verified Exchange assessment bundle")
	headers.Set("X-Run-Generation", strconv.FormatInt(run.Generation, 10))
	headers.Set("X-Content-SHA256", hex.EncodeToString(rawDigest[:]))
	var artifact map[string]any
	if err := client.DoRawWithHeadersBounded(http.MethodPut, fmt.Sprintf("/admin/exchange-replacement/runs/%d/bundle", run.ID), "application/vnd.setjoin.exchange-bundle+json", headers, bytes.NewReader(raw), &artifact, 1<<20); err != nil {
		return exchangeExitForAPI(err)
	}
	result := map[string]any{"id": run.ID, "generation": run.Generation, "artifact": artifact, "originDigest": bundle.OriginDigest, "importDigestMatch": true}
	if *jsonOut {
		return printExchangeJSON(result)
	}
	fmt.Printf("Imported assessment run %d; encrypted artifact committed; origin digest %s verified\n", run.ID, bundle.OriginDigest)
	return nil
}

func exchangeDiagnose(args []string) error {
	fs := flag.NewFlagSet("exchange assess diagnose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	output := fs.String("output", "", "new support JSON file")
	path, flagArgs := exchangeLeadingPath(args)
	if err := fs.Parse(flagArgs); err != nil || (path == "" && fs.NArg() != 1) || *output == "" {
		return exitCodeErr{exchangeExitUsage, "usage: mailctl exchange assess diagnose <bundle.sja> --output <new-file>"}
	}
	if path == "" {
		path = fs.Arg(0)
	}
	bundle, _, err := readExchangeBundle(path)
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, p := range bundle.Probes {
		counts[p.DiagnosticID]++
	}
	support := map[string]any{"schemaVersion": "setjoin.exchange.support/v1", "originDigest": bundle.OriginDigest, "versions": map[string]any{"registry": bundle.RegistryVersion, "catalog": bundle.CatalogVersion, "collector": bundle.CollectorVersion}, "diagnosticCounts": counts, "redaction": "raw facts, identities, credentials and documents excluded"}
	raw, _ := json.MarshalIndent(support, "", "  ")
	return writeExclusive(*output, append(raw, '\n'))
}

func readExchangeBundle(path string) (exchangeV1Bundle, []byte, error) {
	raw, err := readBoundedRegularFile(path, 64<<20)
	if err != nil {
		return exchangeV1Bundle{}, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: " + err.Error()}
	}
	var bundle exchangeV1Bundle
	if err := decodeExchangeV1JSON(raw, &bundle); err != nil {
		return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: " + err.Error()}
	}
	if bundle.SchemaVersion != exchangeBundleSchema {
		return bundle, nil, exitCodeErr{exchangeExitUnsupported, "IMPORT-001: unsupported bundle schema"}
	}
	if bundle.OriginDigest != exchangeBundleDigest(bundle) {
		return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-002: bundle digest mismatch"}
	}
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		return bundle, nil, err
	}
	if bundle.RegistryVersion != registry.RegistryVersion || bundle.RegistryDigest != registry.SourceDigest {
		return bundle, nil, exitCodeErr{exchangeExitUnsupported, "IMPORT-001: registry version/digest mismatch"}
	}
	if bundle.CatalogVersion != registry.CatalogVersion || bundle.Phase != "V1A assessment only — replacement readiness not established" {
		return bundle, nil, exitCodeErr{exchangeExitUnsupported, "IMPORT-001: catalog/phase mismatch"}
	}
	var cell *struct {
		ID                  string   `json:"id"`
		ProductFamily       string   `json:"productFamily"`
		Topology            string   `json:"topology"`
		Admission           string   `json:"admission"`
		Digest              string   `json:"digest"`
		NamedCU             string   `json:"namedCU"`
		BuildAllowlist      []string `json:"buildAllowlist"`
		DirectoryAuthority  string   `json:"directoryAuthority"`
		PowerShellRuntime   string   `json:"powerShellRuntime"`
		CloudAdapterVersion string   `json:"cloudAdapterVersion"`
		CollectorVersion    string   `json:"collectorVersion"`
		CatalogVersion      int      `json:"catalogVersion"`
		RegistryVersion     int      `json:"registryVersion"`
		SetjoinRelease      string   `json:"setjoinRelease"`
	}
	for i := range registry.SupportCells {
		if registry.SupportCells[i].ID == bundle.SupportCellID {
			cell = &registry.SupportCells[i]
			break
		}
	}
	if cell == nil || cell.Digest != bundle.SupportCellDigest || cell.CollectorVersion != bundle.CollectorVersion || cell.CatalogVersion != bundle.CatalogVersion || cell.RegistryVersion != bundle.RegistryVersion {
		return bundle, nil, exitCodeErr{exchangeExitUnsupported, "IMPORT-001: support-cell/collector tuple mismatch"}
	}
	if when, err := time.Parse(time.RFC3339, bundle.CollectedAt); err != nil || when.UTC().Format(time.RFC3339) != bundle.CollectedAt {
		return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: collectedAt must be canonical UTC RFC3339"}
	}
	known := make(map[string]struct{}, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		known[capability.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(bundle.Probes))
	if len(bundle.Probes) > len(known) {
		return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: probe count exceeds registry denominator"}
	}
	for _, probe := range bundle.Probes {
		if _, ok := known[probe.CapabilityID]; !ok {
			return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: unknown capability probe"}
		}
		if _, ok := seen[probe.CapabilityID]; ok {
			return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: duplicate capability probe"}
		}
		seen[probe.CapabilityID] = struct{}{}
		if probe.State != "complete" && probe.State != "complete_zero" && probe.State != "partial" && probe.State != "failed" && probe.State != "unassessed" {
			return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: invalid terminal probe state"}
		}
		if probe.DiagnosticID != "" && !exchangeDiagnosticPattern.MatchString(probe.DiagnosticID) {
			return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: invalid diagnostic ID"}
		}
		facts, _ := json.Marshal(probe.SafeFacts)
		if len(facts) > 64<<10 || containsSensitiveExchangeKey(probe.SafeFacts) {
			return bundle, nil, exitCodeErr{exchangeExitIntegrity, "IMPORT-003: unsafe or oversized safeFacts"}
		}
	}
	if bundle.Importable && len(seen) != len(known) {
		return bundle, nil, exitCodeErr{exchangeExitPartial, "COLLECT-003: importable bundle has an incomplete probe denominator"}
	}
	return bundle, raw, nil
}
func exchangeBundleDigest(bundle exchangeV1Bundle) string {
	bundle.OriginDigest = ""
	raw, _ := json.Marshal(bundle)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func exchangeLeadingPath(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}
func decodeExchangeV1JSON(raw []byte, target any) error {
	if err := rejectDuplicateExchangeJSONKeys(raw); err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func rejectDuplicateExchangeJSONKeys(raw []byte) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds 64 levels")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

func containsSensitiveExchangeKey(value any) bool {
	sensitive := map[string]struct{}{"credential": {}, "password": {}, "accesstoken": {}, "refreshtoken": {}, "privatekey": {}, "messagebody": {}, "rawidentity": {}}
	var visit func(any) bool
	visit = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for key, child := range x {
				normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
				if _, bad := sensitive[normalized]; bad {
					return true
				}
				if visit(child) {
					return true
				}
			}
		case []any:
			for _, child := range x {
				if visit(child) {
					return true
				}
			}
		}
		return false
	}
	return visit(value)
}
func writeExclusive(path string, raw []byte) error {
	_, err := publishPrivateNew(path, raw)
	return err
}
func printExchangeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
func exchangeExitForAPI(err error) error {
	if api, ok := asAPIError(err); ok {
		switch {
		case api.Status == 401 || api.Status == 403:
			return exitCodeErr{exchangeExitPreflight, api.Error()}
		case api.Status == 409:
			return exitCodeErr{exchangeExitPartial, api.Error()}
		case api.Status == 429 || api.Status >= 500:
			return exitCodeErr{exchangeExitRetryable, api.Error()}
		default:
			return exitCodeErr{exchangeExitInternal, api.Error()}
		}
	}
	return exitCodeErr{exchangeExitRetryable, err.Error()}
}

func writeExchangeV1Reports(dir string, bundle exchangeV1Bundle, registry exchangeV1Registry) error {
	rows := make([]map[string]any, 0, len(registry.Capabilities))
	states := map[string]exchangeV1Probe{}
	for _, p := range bundle.Probes {
		states[p.CapabilityID] = p
	}
	for _, c := range registry.Capabilities {
		p, ok := states[c.ID]
		if !ok {
			p = exchangeV1Probe{CapabilityID: c.ID, State: "unassessed", DiagnosticID: "COLLECT-003"}
		}
		rows = append(rows, map[string]any{"capabilityId": c.ID, "outcome": c.Outcome, "category": c.Category, "mappingMaximum": c.MappingMaximum, "claimMaximum": c.ClaimMaximum, "state": p.State, "diagnosticId": p.DiagnosticID})
	}
	complete := len(bundle.Probes) == len(registry.Capabilities)
	for _, probe := range bundle.Probes {
		if probe.State != "complete" && probe.State != "complete_zero" {
			complete = false
			break
		}
	}
	report := map[string]any{"schemaVersion": exchangeReportSchema, "phase": bundle.Phase, "replacementReady": false, "originDigest": bundle.OriginDigest, "registryDigest": bundle.RegistryDigest, "complete": complete, "rows": rows}
	raw, _ := json.MarshalIndent(report, "", "  ")
	if err := writeExclusive(filepath.Join(dir, "report.json"), append(raw, '\n')); err != nil {
		return err
	}
	manifest := map[string]any{"schemaVersion": "setjoin.exchange.manifest/v1", "originDigest": bundle.OriginDigest, "registryDigest": bundle.RegistryDigest, "included": []string{"report.json", "report.html", "receipt.json"}, "omitted": []string{"raw facts", "identities", "credentials", "customer documents"}}
	mraw, _ := json.MarshalIndent(manifest, "", "  ")
	if err := writeExclusive(filepath.Join(dir, "manifest.json"), append(mraw, '\n')); err != nil {
		return err
	}
	signatureStatus := "unsigned_fixture"
	if bundle.Importable {
		signatureStatus = "integrity_only_sha256"
	}
	receipt := map[string]any{"schemaVersion": "setjoin.exchange.receipt/v1", "kind": "local-report", "originDigest": bundle.OriginDigest, "signatureStatus": signatureStatus, "importable": bundle.Importable}
	rraw, _ := json.MarshalIndent(receipt, "", "  ")
	if err := writeExclusive(filepath.Join(dir, "receipt.json"), append(rraw, '\n')); err != nil {
		return err
	}
	var b strings.Builder
	t := template.Must(template.New("report").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Exchange replacement assessment</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;color:#172033}table{width:100%;border-collapse:collapse}th,td{padding:10px;border-bottom:1px solid #ccd3dd;text-align:left}.warning{padding:16px;background:#fff4d6;border-left:4px solid #ad6b00}</style><h1>Exchange 替代评估 / Exchange replacement assessment</h1><p class="warning">{{.Phase}}。未知不是零；本报告不构成替代就绪声明。</p><p>Origin digest: <code>{{.Digest}}</code></p><table><thead><tr><th>ID</th><th>Outcome</th><th>State</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{index . "capabilityId"}}</td><td>{{index (index . "outcome") "zh"}}</td><td>{{index . "state"}}</td></tr>{{end}}</tbody></table></html>`))
	if err := t.Execute(&b, map[string]any{"Phase": bundle.Phase, "Digest": bundle.OriginDigest, "Rows": rows}); err != nil {
		return err
	}
	return writeExclusive(filepath.Join(dir, "report.html"), []byte(b.String()))
}
