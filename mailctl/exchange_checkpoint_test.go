package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Oracle: EX plan's same-generation resume and immutable prior-bundle contract
// (docs/designs/exchange-replacement-contract.md).
//
// Gap recorded for the owning unit: collector checkpoint/resume remains
// unfinished by plan (retired-docs:superpowers/plans/2026-08-23-exchange-replacement-
// contract.md, 2026-09-06 execution guidance) — there is no checkpoint writer
// or same-support-cell/catalog resume validation, and --resume refuses with
// COLLECT-005 until the authorized V1B wave lands it. Landing the full oracle
// (successful same-generation resume) requires that wave, not a local fix.
//
// Until then this pins the honestly-available half: a resume attempt against a
// completed output is refused at the gate and never damages the prior bundle.
func TestExchangeCollectResumeRefusedPreservesCompletedBundle(t *testing.T) {
	input := exchangeCheckpointFixture(t)
	output := filepath.Join(t.TempDir(), "恢复 with spaces")
	args := []string{"--input", input, "--output", output, "--non-interactive"}
	if err := exchangeCollect(args); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(filepath.Join(output, "bundle.sja"))
	if err != nil {
		t.Fatal(err)
	}
	err = exchangeCollect(append(args, "--resume", filepath.Join(output, "checkpoint.json")))
	var exit exitCodeErr
	if !errors.As(err, &exit) || exit.code != exchangeExitUsage || !strings.Contains(err.Error(), "COLLECT-005") {
		t.Fatalf("resume must refuse with COLLECT-005 while the V1B resume wave is unauthorized: err=%v", err)
	}
	after, err := os.Stat(filepath.Join(output, "bundle.sja"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("resume refusal replaced completed bundle")
	}
}

func exchangeCheckpointFixture(t *testing.T) string {
	t.Helper()
	registry, _, err := loadExchangeV1Registry()
	if err != nil {
		t.Fatal(err)
	}
	probes := make([]exchangeV1Probe, 0, len(registry.Capabilities))
	for _, c := range registry.Capabilities {
		probes = append(probes, exchangeV1Probe{CapabilityID: c.ID, State: "complete", SafeFacts: map[string]any{"count": 1}})
	}
	raw, err := json.Marshal(exchangeCollectorOutput{SchemaVersion: "setjoin.exchange.collector-output/v1", SupportCellID: registry.SupportCells[0].ID, CollectedAt: "2026-08-23T00:00:00Z", Probes: probes})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "collector.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
