// Package contractvectors records frozen Go contracts for the Rust parity oracle.
package contractvectors

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type vectorCase struct {
	Name   string `json:"name"`
	Input  any    `json:"input"`
	Output any    `json:"output"`
}

func writeVectors(t *testing.T, contract string, cases any) {
	t.Helper()
	dir := os.Getenv("GOFREE_VECTOR_DIR")
	if dir == "" {
		return
	}
	data, err := json.MarshalIndent(struct {
		Contract string `json:"contract"`
		Cases    any    `json:"cases"`
	}{contract, cases}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(filepath.Join(dir, contract+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

// The recorder is an executable seam: an existing recording must never change.
func TestRecorderDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	run := func() error {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRecordClientip$")
		cmd.Env = append(os.Environ(), "GOFREE_VECTOR_DIR="+dir)
		return cmd.Run()
	}
	if err := run(); err != nil {
		t.Fatalf("first recording: %v", err)
	}
	path := filepath.Join(dir, "clientip.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil {
		t.Fatal("recording overwrote an existing fixture")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("existing fixture changed")
	}
}
