package securityprogram

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The freeze test: the committed grammar artifact must match the package
// grammar byte-for-byte. Any grammar change must regenerate the artifact and
// re-pin the checker's hash in the same reviewable change — never silently.
func TestFrozenGrammarArtifactMatchesPackage(t *testing.T) {
	committed, err := os.ReadFile(filepath.Join("..", "..", TransitionsArtifactPath))
	if err != nil {
		t.Fatalf("frozen grammar artifact missing (%s): %v", TransitionsArtifactPath, err)
	}
	generated, err := ContractJSON()
	if err != nil {
		t.Fatalf("ContractJSON failed: %v", err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatalf("frozen grammar artifact drifted from the package grammar; regenerate via `go run ./securityprogram/cmd/gencontract` and re-pin the checker hash (got sha256 %s)", SHA256Hex(generated))
	}
}

func TestCatalogCoversEmittedCodesExactly(t *testing.T) {
	emitted := EmittedCodes()
	if len(emitted) == 0 {
		t.Fatal("namespace emits no codes")
	}
	for _, code := range emitted {
		triple, ok := catalog[code]
		if !ok {
			t.Fatalf("emitted code %s missing from the shared catalog table", code)
		}
		for i, part := range triple {
			if strings.TrimSpace(part) == "" {
				t.Fatalf("catalog[%s][%d] is empty", code, i)
			}
		}
		if !strings.HasPrefix(code, "E_SECURITY_PROGRAM_") {
			t.Fatalf("code %s is outside the shared E_SECURITY_PROGRAM_* authority", code)
		}
	}
	if len(catalog) != len(emitted) {
		t.Fatalf("catalog holds %d codes but the namespace emits %d — the tables must match exactly", len(catalog), len(emitted))
	}
}

func TestErrorContract(t *testing.T) {
	err := newErr(CodeAttemptUnknown, OpComplete, "occ_x", "no active attempt")
	if !IsCode(err, CodeAttemptUnknown) || IsCode(err, CodeUsage) {
		t.Fatalf("IsCode misclassified: %v", err)
	}
	if got := CodeOf(err); got != CodeAttemptUnknown {
		t.Fatalf("CodeOf = %s, want %s", got, CodeAttemptUnknown)
	}
	wrapped := fmtWrap(err)
	if got := CodeOf(wrapped); got != CodeAttemptUnknown {
		t.Fatalf("CodeOf through wrap = %s, want %s", got, CodeAttemptUnknown)
	}
	// Unknown errors fail closed as internal, never as caller problems.
	if got := CodeOf(os.ErrNotExist); got != CodeInternal {
		t.Fatalf("CodeOf(unknown) = %s, want %s", got, CodeInternal)
	}
	if !strings.HasPrefix(err.Error(), CodeAttemptUnknown+":") {
		t.Fatalf("error text must lead with the stable code: %q", err.Error())
	}
}

func TestLedgerSchemaFailsClosed(t *testing.T) {
	_, err := LoadLedger([]byte(`{"schema":"setjoin.sec.deep-security-remediation-ledger/v999","rows":[]}`))
	if !IsCode(err, CodeSchemaUnsupported) {
		t.Fatalf("unknown schema must refuse with %s, got %v", CodeSchemaUnsupported, err)
	}
	_, err = LoadLedger([]byte(`{not json`))
	if !IsCode(err, CodeEvidenceInvalid) {
		t.Fatalf("invalid envelope must refuse with %s, got %v", CodeEvidenceInvalid, err)
	}
	_, err = LoadLedger([]byte(`{"schema":"` + LedgerSchemaV1 + `","rows":[{"occurrenceId":"occ_a"},{"occurrenceId":"occ_a"}]}`))
	if !IsCode(err, CodeEvidenceInvalid) {
		t.Fatalf("duplicate occurrence ids must refuse, got %v", err)
	}
}

func fmtWrap(err error) error {
	return &wrapped{err}
}

type wrapped struct{ error }

func (w *wrapped) Unwrap() error { return w.error }
func (w *wrapped) Error() string { return "wrapped: " + w.error.Error() }
