package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExchangeV1RegistryAndSampleRoundTrip(t *testing.T) {
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		t.Fatal(err)
	}
	if registry.SourceDigest != "cf6f4a008b80a10314b120fb058802bae42386c92af7fa187d18745cf7f50f09" {
		t.Fatalf("source digest = %s", registry.SourceDigest)
	}
	var compatibility struct {
		AcceptedBundleSchemas []string `json:"acceptedBundleSchemas"`
		UnknownFieldPolicy    string   `json:"unknownFieldPolicy"`
		FeatureDefault        string   `json:"featureDefault"`
	}
	if err := json.Unmarshal(registry.Compatibility, &compatibility); err != nil || len(compatibility.AcceptedBundleSchemas) != 1 || compatibility.AcceptedBundleSchemas[0] != exchangeBundleSchema || compatibility.UnknownFieldPolicy != "reject_before_import" || compatibility.FeatureDefault != "off" {
		t.Fatalf("compatibility=%+v err=%v", compatibility, err)
	}
	out := filepath.Join(t.TempDir(), "样例 with spaces")
	if err := exchangeSample([]string{"--output", out, "--json"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bundle.sja", "report.html", "report.json", "manifest.json", "receipt.json"} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is not private: %o", name, info.Mode().Perm())
		}
	}
	bundle, _, err := readExchangeBundle(filepath.Join(out, "bundle.sja"))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Importable || len(bundle.Probes) != len(registry.Capabilities) {
		t.Fatalf("unexpected sample: %+v", bundle)
	}
}

func TestExchangeBundleTamperFailsClosed(t *testing.T) {
	registry, _, _ := loadExchangeV1Registry()
	b := exchangeV1Bundle{SchemaVersion: exchangeBundleSchema, Phase: "V1A assessment only — replacement readiness not established", RegistryVersion: registry.RegistryVersion, RegistryDigest: registry.SourceDigest, CatalogVersion: registry.CatalogVersion, SupportCellID: "x", SupportCellDigest: strings.Repeat("a", 64), CollectorVersion: "test", CollectedAt: "2026-08-23T00:00:00Z"}
	b.OriginDigest = exchangeBundleDigest(b)
	b.SupportCellID = "tampered"
	raw, _ := json.Marshal(b)
	path := filepath.Join(t.TempDir(), "bundle.sja")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := readExchangeBundle(path)
	var exit exitCodeErr
	if !errors.As(err, &exit) || exit.code != exchangeExitIntegrity || !strings.Contains(err.Error(), "IMPORT-002") {
		t.Fatalf("err=%v", err)
	}
}

func TestExchangePreflightAndNonImportableRefusal(t *testing.T) {
	config := filepath.Join(t.TempDir(), "assessment.yaml")
	if err := exchangePreflight([]string{"--offline", "--doctor", "--json", "--write-config", config}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "schema_version: 1") {
		t.Fatal("starter config missing schema")
	}
	out := filepath.Join(t.TempDir(), "sample")
	if err := exchangeSample([]string{"--output", out}); err != nil {
		t.Fatal(err)
	}
	err = exchangeImport([]string{filepath.Join(out, "bundle.sja"), "--project-id", "1"})
	var exit exitCodeErr
	if !errors.As(err, &exit) || exit.code != exchangeExitIntegrity {
		t.Fatalf("err=%v", err)
	}
}

func TestExchangeStableExitConstants(t *testing.T) {
	want := []int{0, 2, 3, 4, 5, 6, 7, 10, 130}
	got := []int{0, exchangeExitUsage, exchangeExitPreflight, exchangeExitPartial, exchangeExitIntegrity, exchangeExitRetryable, exchangeExitUnsupported, exchangeExitInternal, 130}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("exit[%d]=%d want %d", i, got[i], want[i])
		}
	}
}

func TestExchangeBundleRejectsDuplicateJSONKeys(t *testing.T) {
	var target exchangeV1Bundle
	err := decodeExchangeV1JSON([]byte(`{"schemaVersion":"setjoin.exchange.bundle/v1","schemaVersion":"setjoin.exchange.bundle/v1"}`), &target)
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate key error = %v", err)
	}
}

func TestExchangeBundleRejectsExcessiveJSONNesting(t *testing.T) {
	var target exchangeV1Bundle
	raw := strings.Repeat(`{"x":`, 65) + `0` + strings.Repeat(`}`, 65)
	if err := decodeExchangeV1JSON([]byte(raw), &target); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("nesting error = %v", err)
	}
}

func TestExchangeBundleRejectsUnsafeFactsAndIncompleteImport(t *testing.T) {
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		t.Fatal(err)
	}
	cell := registry.SupportCells[0]
	bundle := exchangeV1Bundle{SchemaVersion: exchangeBundleSchema, Phase: "V1A assessment only — replacement readiness not established", Importable: true, RegistryVersion: registry.RegistryVersion, RegistryDigest: registry.SourceDigest, CatalogVersion: registry.CatalogVersion, SupportCellID: cell.ID, SupportCellDigest: cell.Digest, CollectorVersion: cell.CollectorVersion, CollectedAt: "2026-08-23T00:00:00Z", Probes: []exchangeV1Probe{{CapabilityID: registry.Capabilities[0].ID, State: "complete", DiagnosticID: "COLLECT-OK", SafeFacts: map[string]any{"accessToken": "secret"}}}}
	bundle.OriginDigest = exchangeBundleDigest(bundle)
	raw, _ := json.Marshal(bundle)
	path := filepath.Join(t.TempDir(), "unsafe.sja")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readExchangeBundle(path); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("unsafe facts error = %v", err)
	}
	bundle.Probes[0].SafeFacts = map[string]any{"count": 1}
	bundle.OriginDigest = exchangeBundleDigest(bundle)
	raw, _ = json.Marshal(bundle)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readExchangeBundle(path); err == nil || !strings.Contains(err.Error(), "denominator") {
		t.Fatalf("denominator error = %v", err)
	}
}

func TestExchangeCollectPromotesOnlyCompleteStrictCollectorOutput(t *testing.T) {
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		t.Fatal(err)
	}
	probes := make([]exchangeV1Probe, 0, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		probes = append(probes, exchangeV1Probe{CapabilityID: capability.ID, State: "complete", DiagnosticID: "COLLECT-OK", SafeFacts: map[string]any{"count": 1}})
	}
	input := exchangeCollectorOutput{SchemaVersion: "setjoin.exchange.collector-output/v1", SupportCellID: registry.SupportCells[0].ID, CollectedAt: "2026-08-23T00:00:00Z", Probes: probes}
	raw, _ := json.Marshal(input)
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "collector.json")
	if err := os.WriteFile(inputPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "assessment")
	if err := exchangeCollect([]string{"--input", inputPath, "--output", output, "--non-interactive"}); err != nil {
		t.Fatal(err)
	}
	bundle, _, err := readExchangeBundle(filepath.Join(output, "bundle.sja"))
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.Importable || len(bundle.Probes) != len(registry.Capabilities) {
		t.Fatalf("bundle=%+v", bundle)
	}
	var report map[string]any
	reportRaw, err := os.ReadFile(filepath.Join(output, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatal(err)
	}
	if report["replacementReady"] != false || report["complete"] != true {
		t.Fatalf("report=%v", report)
	}
}

func TestExchangeCollectRejectsReservedResumeInsteadOfIgnoringIt(t *testing.T) {
	err := exchangeCollect([]string{"--input", "collector.json", "--output", "assessment", "--resume", "checkpoint.json"})
	if err == nil || !strings.Contains(err.Error(), "COLLECT-005") {
		t.Fatalf("resume error = %v", err)
	}
}

func FuzzDecodeExchangeBundleHostileJSON(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"setjoin.exchange.bundle/v1"}`))
	f.Add([]byte(`{"x":{"x":{"x":[]}}}`))
	f.Add([]byte(`{"schemaVersion":"x","schemaVersion":"y"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		var bundle exchangeV1Bundle
		_ = decodeExchangeV1JSON(raw, &bundle)
	})
}

func BenchmarkExchangeBundleValidation(b *testing.B) {
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		b.Fatal(err)
	}
	cell := registry.SupportCells[0]
	probes := make([]exchangeV1Probe, 0, len(registry.Capabilities))
	for _, capability := range registry.Capabilities {
		probes = append(probes, exchangeV1Probe{CapabilityID: capability.ID, State: "complete", SafeFacts: map[string]any{"count": 1}})
	}
	bundle := exchangeV1Bundle{SchemaVersion: exchangeBundleSchema, Phase: "V1A assessment only — replacement readiness not established", Importable: true, RegistryVersion: registry.RegistryVersion, RegistryDigest: registry.SourceDigest, CatalogVersion: registry.CatalogVersion, SupportCellID: cell.ID, SupportCellDigest: cell.Digest, CollectorVersion: cell.CollectorVersion, CollectedAt: "2026-08-23T00:00:00Z", Probes: probes}
	bundle.OriginDigest = exchangeBundleDigest(bundle)
	raw, _ := json.Marshal(bundle)
	path := filepath.Join(b.TempDir(), "bundle.sja")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := readExchangeBundle(path); err != nil {
			b.Fatal(err)
		}
	}
}
