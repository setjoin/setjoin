// ledger_test.go — the sealed-ledger document layer's fail-closed edges the
// service happy paths never reach: LoadLedger's structural refusals
// (missing schema/rows, non-object rows), ViewRow's closed-enum and
// closed-shape refusals, bumpCounts's broken-tally refusals surfaced through
// Service.Start/Complete (a parseable ledger with a corrupt counts object
// must refuse its first mutating commit, never silently reconcile), and
// refreshVerificationStatement's guards (no verification block, non-object
// verification, or a statement without the zero-receipt phrase leaves the
// ledger's own words untouched). Also pins the typed error's three text
// projections (contract.go's Error arms).
package securityprogram

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// topFixture round-trips the standard fixture ledger through a generic map
// so tests can delete or corrupt top-level fields without rebuilding the
// whole document. extraLocal is the second row's localStatus ("" for none).
func topFixture(t *testing.T, extraLocal string, mutate func(top map[string]any)) []byte {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(testLedgerBytes(t, extraLocal), &top); err != nil {
		t.Fatalf("fixture reparse: %v", err)
	}
	mutate(top)
	out, err := json.Marshal(top)
	if err != nil {
		t.Fatalf("fixture remarshal: %v", err)
	}
	return out
}

func loadBytes(t *testing.T, data []byte) *Service {
	t.Helper()
	doc, err := LoadLedger(data)
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	return NewService(doc)
}

func rawRow(t *testing.T, s string) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("row fixture unmarshal: %v", err)
	}
	return m
}

func TestLoadLedgerStructuralRefusals(t *testing.T) {
	schema := `"schema":"` + LedgerSchemaV1 + `"`

	// A document without the schema field cannot even be identified.
	_, err := LoadLedger([]byte(`{"rows":[]}`))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "missing schema") {
		t.Fatalf("missing schema = %v", err)
	}
	// The identified schema is required before any rows are read.
	_, err = LoadLedger([]byte(`{` + schema + `}`))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "missing rows") {
		t.Fatalf("missing rows = %v", err)
	}
	// A row that is not a JSON object is structural corruption.
	_, err = LoadLedger([]byte(`{` + schema + `,"rows":[7]}`))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "not a JSON object") {
		t.Fatalf("non-object row = %v", err)
	}
	// A row without its occurrence identity is unusable — never guessed.
	_, err = LoadLedger([]byte(`{` + schema + `,"rows":[{}]}`))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "occurrenceId") {
		t.Fatalf("row without occurrenceId = %v", err)
	}

	// Rows reports the sealed occurrence count.
	doc, err := LoadLedger(testLedgerBytes(t, "no_change_candidate"))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	if doc.Rows() != 2 {
		t.Fatalf("Rows = %d, want 2", doc.Rows())
	}
}

func TestViewRowClosedEnumAndShapeRefusals(t *testing.T) {
	for _, c := range []struct{ name, row string }{
		{"disposition", `{"occurrenceId":"occ_x","disposition":"banana","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"not_ready"}`},
		{"localStatus", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"banana","verificationStatus":"none","releaseStatus":"not_ready"}`},
		{"verificationStatus", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"banana","releaseStatus":"not_ready"}`},
		{"releaseStatus", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"banana"}`},
		{"closurePatch not an object", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"not_ready","closurePatch":7}`},
		{"evidence not an object", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"not_ready","evidence":7}`},
		{"remediation not an object", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"not_ready","remediation":7}`},
		{"remediationTransitions not an array", `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped","verificationStatus":"none","releaseStatus":"not_ready","remediationTransitions":7}`},
	} {
		_, err := ViewRow(rawRow(t, c.row))
		if !IsCode(err, CodeEvidenceInvalid) {
			t.Fatalf("%s = %v, want %s", c.name, err, CodeEvidenceInvalid)
		}
	}

	// A non-array tests field is tolerated as absent (the projection never
	// invents occurrence-specific tests from a corrupt value) — every closed
	// enum stays valid so the tolerance, not an enum refusal, is what runs.
	v, err := ViewRow(rawRow(t, `{"occurrenceId":"occ_x","disposition":"blocked","localStatus":"unmapped",`+
		`"verificationStatus":"none","releaseStatus":"not_ready","tests":7}`))
	if err != nil {
		t.Fatalf("corrupt tests must not fail the projection: %v", err)
	}
	if len(v.Tests) != 0 {
		t.Fatalf("corrupt tests projected as %+v", v.Tests)
	}
}

func TestCommitFailsClosedOnBrokenCounts(t *testing.T) {
	ctx := context.Background()

	// No counts object at all: the staged start transition refuses at commit
	// (the namespace cannot maintain a tally the document does not carry).
	svc := loadBytes(t, topFixture(t, "", func(top map[string]any) { delete(top, "counts") }))
	_, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if !IsCode(err, CodeInternal) || !strings.Contains(err.Error(), "no counts object") {
		t.Fatalf("start without counts = %v", err)
	}

	// A counts object of the wrong JSON type is evidence corruption.
	svc = loadBytes(t, topFixture(t, "", func(top map[string]any) { top["counts"] = 5 }))
	_, err = svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "counts") {
		t.Fatalf("start with non-object counts = %v", err)
	}

	// A completion bumps fixed, then blocked, then locallyRemediated — each
	// non-integer tally refuses the commit in turn.
	for _, tally := range []string{"fixed", "blocked", "locallyRemediated"} {
		svc := loadBytes(t, topFixture(t, "", func(top map[string]any) {
			top["counts"].(map[string]any)[tally] = "not-a-number"
		}))
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("counts.%s: start: %v", tally, err)
		}
		_, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json"))
		if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), tally) {
			t.Fatalf("complete with non-integer counts.%s = %v", tally, err)
		}
	}

	// The no_change bump arm: the same refusal from the candidate state.
	svc = loadBytes(t, topFixture(t, "no_change_candidate", func(top map[string]any) {
		top["counts"].(map[string]any)["no_change"] = "not-a-number"
	}))
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOccB)}); err != nil {
		t.Fatalf("no_change: start: %v", err)
	}
	_, err = svc.Complete(ctx, completeReq(testOccB, "no_change", "test-results/x/manifest.json"))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "no_change") {
		t.Fatalf("complete with non-integer counts.no_change = %v", err)
	}
}

func TestRefreshVerificationStatementGuards(t *testing.T) {
	ctx := context.Background()
	complete := func(t *testing.T, data []byte) []byte {
		t.Helper()
		svc := loadBytes(t, data)
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		if _, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json")); err != nil {
			t.Fatalf("complete: %v", err)
		}
		out, err := svc.doc.Bytes()
		if err != nil {
			t.Fatalf("bytes: %v", err)
		}
		return out
	}

	// No verification block: the completion commits without statement
	// handling (the guard reads only what the document carries).
	noVerif := complete(t, topFixture(t, "", func(top map[string]any) { delete(top, "verification") }))
	if !strings.Contains(string(noVerif), `"disposition": "fixed"`) {
		t.Fatalf("completion without verification block did not commit")
	}

	// A non-object verification block is left exactly as found.
	kept := complete(t, topFixture(t, "", func(top map[string]any) { top["verification"] = 5 }))
	if !strings.Contains(string(kept), `"verification": 5`) {
		t.Fatalf("non-object verification was rewritten")
	}

	// A statement that does not carry the zero-receipt phrase is colleague
	// wording — never rewritten by the receipt refresh.
	untouched := complete(t, topFixture(t, "", func(top map[string]any) {
		top["verification"].(map[string]any)["statement"] = "custom statement stays"
	}))
	if !strings.Contains(string(untouched), "custom statement stays") {
		t.Fatalf("foreign verification statement was rewritten")
	}
}

// TestBytesRenderRowMutations pins the load-time rows re-encode: the
// namespace owns the rows array's CONTENT, so Bytes() — the LedgerAfter a
// publisher writes — must render the row mutations a transition commits. A
// republication that only moved the top-level tallies would contradict its
// own counts and silently drop every receipt binding from the durable
// artifact.
func TestBytesRenderRowMutations(t *testing.T) {
	ctx := context.Background()
	svc, doc := loadTestService(t, "")
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json")); err != nil {
		t.Fatalf("complete: %v", err)
	}
	out, err := doc.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	for _, want := range []string{
		`"receipt_bound"`,                  // the row's verification axis moved
		`"proof_patched"`,                  // the row's localStatus moved
		`"remediationTransitions"`,         // the recorded transition chain
		`"verdict": "pass"`,                // the receipt-bound evidence rewrite
		`"attemptId": "` + testAttID + `"`, // the closed attempt record
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("published ledger bytes lost the committed row mutation %s:\n%s", want, out)
		}
	}
}

func TestErrorTextProjections(t *testing.T) {
	// Op + occurrence: the operation-scoped form.
	both := newErr(CodeAttemptUnknown, OpComplete, "occ_x", "no active attempt")
	if !strings.Contains(both.Error(), OpComplete) || !strings.Contains(both.Error(), "occ_x") {
		t.Fatalf("op+occurrence error text = %q", both.Error())
	}
	// Op only: the usage form.
	opOnly := usageErr(OpStart, "attemptId is required")
	if !strings.HasPrefix(opOnly.Error(), CodeUsage+":") || !strings.Contains(opOnly.Error(), OpStart) {
		t.Fatalf("op-only error text = %q", opOnly.Error())
	}
	// Occurrence only: no empty op segment between the code and the id.
	occOnly := newErr(CodeEvidenceInvalid, "", "occ_y", "corrupt")
	if occOnly.Error() != CodeEvidenceInvalid+": occ_y: corrupt" {
		t.Fatalf("occurrence-only error text = %q", occOnly.Error())
	}
	// Neither: the bare code form.
	plain := newErr(CodeInternal, "", "", "boom")
	if plain.Error() != CodeInternal+": boom" {
		t.Fatalf("bare error text = %q", plain.Error())
	}
}
