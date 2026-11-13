// main_test.go — the gencontract CLI's underlying run function: the success
// path writes the frozen grammar bytes verbatim to stdout (byte-identical to
// ContractJSON — the same bytes the ER1 checker pins), and a failing stdout
// reports the write fault on stderr with exit code 1.
package main

import (
	"bytes"
	"errors"
	"testing"

	securityprogram "setjoin.com/shared/securityprogram"
)

type failingWriter struct{ err error }

func (w failingWriter) Write(p []byte) (int, error) { return 0, w.err }

func TestRunWritesGrammarToStdout(t *testing.T) {
	want, err := securityprogram.ContractJSON()
	if err != nil {
		t.Fatalf("ContractJSON: %v", err)
	}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	if code := run(stdout, stderr); code != 0 {
		t.Fatalf("run = %d with stderr %q", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatalf("stdout drifted from the frozen grammar bytes")
	}
	if stderr.Len() != 0 {
		t.Fatalf("success must leave stderr empty, got %q", stderr.String())
	}
}

func TestRunReportsStdoutWriteFault(t *testing.T) {
	writeErr := errors.New("stdout closed")
	stderr := &bytes.Buffer{}
	code := run(failingWriter{err: writeErr}, stderr)
	if code != 1 {
		t.Fatalf("run = %d, want 1 on a stdout write fault", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("gencontract: "+writeErr.Error())) {
		t.Fatalf("stderr = %q, want the namespaced write fault", stderr.String())
	}
}
