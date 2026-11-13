package securityprogram

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testOcc   = "occ_d1f5f94c5e8134c091061ca2"
	testOccB  = "occ_250316670c6ed7b069a8d45b"
	testRunID = "run-20260918-er3-test"
	testAttID = "att-0001"
)

// testLedgerBytes builds a minimal sealed-ledger-shaped document with the
// same schema and owned fields as the real artifact (never the real file).
func testLedgerBytes(t *testing.T, extraRowLocal string) []byte {
	t.Helper()
	rows := []map[string]any{sealedRow(testOcc, "unmapped")}
	if extraRowLocal != "" {
		rows = append(rows, sealedRow(testOccB, extraRowLocal))
	}
	doc := map[string]any{
		"schema":            LedgerSchemaV1,
		"preparedOn":        "2026-09-18",
		"colleagueTopLevel": "preserve me",
		"counts": map[string]any{
			"sealedOccurrences": len(rows), "dispositioned": len(rows),
			"fixed": 0, "no_change": 0, "blocked": len(rows), "accountedFor": len(rows),
			"locallyRemediated": 0, "releaseReady": 0, "nightlyJoinedOccurrences": 0,
		},
		"verification": map[string]any{
			"statement": "No sealed occurrence carries closure verification. Zero receipts exist proving sealed-occurrence closure.",
		},
		"rows": rows,
	}
	out, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatalf("fixture marshal: %v", err)
	}
	return append(out, '\n')
}

func sealedRow(occ, local string) map[string]any {
	return map[string]any{
		"occurrenceId":   occ,
		"findingId":      "csf_" + occ[4:12],
		"identityAnchor": "anchor-" + occ[4:8],
		"ruleId":         "rule.test",
		"title":          "sealed " + occ,
		"scanLocations":  []string{"mailserver/cmd/mailserverd/main.go"},
		"resumeBatch":    "B01",
		"closurePatch":   nil,
		"tests":          []any{},
		"evidence": map[string]any{
			"sealedIndex":       "retired-docs:zcode-security-deep/handoff/sj-glm-sec-20260909-003-triage/sec-ledger-index.json",
			"plan":              "retired-docs:superpowers/plans/2026-08-28-deep-security-scan-remediation.md",
			"planBatch":         "B01",
			"verification":      "none",
			"manifest":          nil,
			"sourceFingerprint": nil,
			"verdict":           "none",
		},
		"disposition":        "blocked",
		"dispositionBasis":   "program_gate_not_admitted",
		"localStatus":        local,
		"releaseStatus":      "not_ready",
		"verificationStatus": "none",
		"blockedReason":      "Sealed-baseline remediation not admitted or started (program gate).",
		"releaseGates":       []any{},
		"colleagueOwned":     map[string]any{"note": "preserve me"},
	}
}

func loadTestService(t *testing.T, local string) (*Service, *LedgerDoc) {
	t.Helper()
	doc, err := LoadLedger(testLedgerBytes(t, local))
	if err != nil {
		t.Fatalf("LoadLedger: %v", err)
	}
	return NewService(doc), doc
}

func authedReq(occ string) Request {
	return Request{
		Contract:     ContractVersion,
		Authority:    AuthorityServiceRole,
		OccurrenceID: occ,
		AttemptID:    testAttID,
		RunID:        testRunID,
	}
}

func completeReq(occ, outcome, evidencePath string) CompleteRequest {
	return CompleteRequest{
		Request: authedReq(occ),
		Outcome: outcome,
		ClosurePatch: &ClosurePatch{
			Trigger:    "send unauthenticated telemetry to /ingest",
			Legitimate: "authenticated ingestion path with bounded inserts",
			Bypass:     "curl -X POST /ingest without auth is refused 401",
		},
		Tests:            []string{"TestTelemetryIngestRequiresAuth"},
		EvidenceManifest: evidencePath,
	}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if !IsCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestStartStatusCompleteRejectHappyPath(t *testing.T) {
	ctx := context.Background()
	svc, doc := loadTestService(t, "")

	// status before any work: start is allowed, attempt absent.
	st, err := svc.Status(ctx, StatusRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.State.Disposition != DispositionBlocked || st.State.LocalStatus != LocalUnmapped {
		t.Fatalf("unexpected initial state: %s", st.State)
	}
	if !containsString(st.Allowed, OpStart) || containsString(st.Allowed, OpComplete) {
		t.Fatalf("pre-start allowed set wrong: %v", st.Allowed)
	}

	// start: opens the attempt, unmapped traces to traced.
	start, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if start.Transition.Op != OpStart || start.Transition.From.LocalStatus != LocalUnmapped ||
		start.Transition.To.LocalStatus != LocalTraced {
		t.Fatalf("start transition wrong: %+v", start.Transition)
	}
	if start.Transition.Authority != AuthorityServiceRole || start.Transition.Contract != ContractVersion {
		t.Fatalf("start transition contract fields wrong: %+v", start.Transition)
	}
	if start.Evidence != nil {
		t.Fatalf("start must not carry an evidence artifact")
	}

	// status mid-attempt: complete/reject now allowed.
	st, err = svc.Status(ctx, StatusRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("status mid-attempt: %v", err)
	}
	if st.Attempt == nil || st.Attempt.State != AttemptActive || st.Attempt.AttemptID != testAttID {
		t.Fatalf("active attempt not projected: %+v", st.Attempt)
	}
	if !containsString(st.Allowed, OpComplete) || !containsString(st.Allowed, OpReject) {
		t.Fatalf("mid-attempt allowed set wrong: %v", st.Allowed)
	}

	// complete: receipt-bound closure with atomic evidence artifact.
	complete, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/deep-security-remediation/"+testRunID+"/manifest.json"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if complete.Transition.To.Disposition != DispositionFixed ||
		complete.Transition.To.LocalStatus != LocalProofPatched ||
		complete.Transition.To.VerificationStatus != VerificationReceiptBound {
		t.Fatalf("complete terminal state wrong: %s", complete.Transition.To)
	}
	if complete.Evidence == nil || len(complete.Evidence.Body) == 0 {
		t.Fatalf("complete must carry the evidence artifact")
	}
	if complete.Transition.EvidenceSHA256 != SHA256Hex(complete.Evidence.Body) {
		t.Fatalf("evidence sha256 binding missing from the transition record")
	}

	// the in-memory document must be checker-consistent: fixed rows carry the
	// patch, tests and receipt-bound verification; counts reconcile; the
	// zero-receipt statement was refreshed.
	view, err := ViewRow(mustFind(t, doc, testOcc))
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.ClosurePatch == nil || len(view.Tests) == 0 {
		t.Fatalf("completed row lost its closure claim bindings")
	}
	if view.Evidence.Manifest != complete.Evidence.Path || view.Evidence.Verdict != "pass" {
		t.Fatalf("evidence pointer not written: %+v", view.Evidence)
	}
	if view.Attempt.State != AttemptCompleted || view.Attempt.ClosedAt == "" {
		t.Fatalf("attempt not closed as completed: %+v", view.Attempt)
	}
	if len(view.Transitions) != 2 || view.Transitions[0].Op != OpStart || view.Transitions[1].Op != OpComplete {
		t.Fatalf("transition chain wrong: %+v", view.Transitions)
	}
	if view.Transitions[1].To.Equal(view.Transitions[1].From) || view.Transitions[1].From.Equal(RowState{}) {
		t.Fatalf("complete transition must record distinct from/to states")
	}
	assertCounts(t, doc, 1, 0, 0, 1)
	assertStatementRefreshed(t, doc)

	// post-completion status: terminal — no further mutation offered.
	st, err = svc.Status(ctx, StatusRequest{Request: authedReq(testOcc)})
	if err != nil {
		t.Fatalf("post status: %v", err)
	}
	if len(st.Allowed) != 1 || st.Allowed[0] != OpStatus {
		t.Fatalf("terminal occurrence must allow only status, got %v", st.Allowed)
	}

	// start after completion is a state refusal.
	_, err = svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
	requireCode(t, err, CodeEvidenceInvalid)
}

func TestRejectHappyPathReturnsToBlocked(t *testing.T) {
	ctx := context.Background()
	svc, doc := loadTestService(t, "")
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
		t.Fatalf("start: %v", err)
	}
	rej, err := svc.Reject(ctx, RejectRequest{Request: authedReq(testOcc), Reason: "gate still HOLD: Astra integration verdict (astra-plan-sec.md)"})
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rej.Transition.To.Disposition != DispositionBlocked || rej.Transition.To.LocalStatus != LocalBlocked ||
		rej.Transition.To.VerificationStatus != VerificationNone || rej.Transition.Reason == "" {
		t.Fatalf("reject terminal state wrong: %+v", rej.Transition)
	}
	view, err := ViewRow(mustFind(t, doc, testOcc))
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if view.BlockedReason == "" || view.Attempt.State != AttemptRejected {
		t.Fatalf("reject must keep a cited blocked reason and close the attempt: %+v", view)
	}
	assertCounts(t, doc, 0, 0, 1, 0)
}

func TestValidationRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("authority is service-role only on every operation", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		req := authedReq(testOcc)
		req.Authority = "admin"
		_, err := svc.Status(ctx, StatusRequest{Request: req})
		requireCode(t, err, CodeApprovalRequired)
		_, err = svc.Start(ctx, StartRequest{Request: req})
		requireCode(t, err, CodeApprovalRequired)
		demotedComplete := completeReq(testOcc, "fixed", "test-results/x/manifest.json")
		demotedComplete.Authority = "admin"
		_, err = svc.Complete(ctx, demotedComplete)
		requireCode(t, err, CodeApprovalRequired)
		_, err = svc.Reject(ctx, RejectRequest{Request: req, Reason: "r"})
		requireCode(t, err, CodeApprovalRequired)
	})

	t.Run("contract version fails closed", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		missing := authedReq(testOcc)
		missing.Contract = ""
		_, err := svc.Start(ctx, StartRequest{Request: missing})
		requireCode(t, err, CodeUsage)
		stale := authedReq(testOcc)
		stale.Contract = "setjoin.sec.security-program-remediation/v0"
		_, err = svc.Start(ctx, StartRequest{Request: stale})
		requireCode(t, err, CodeSchemaUnsupported)
	})

	t.Run("unknown or partial occurrence ids are never guessed", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		_, err := svc.Status(ctx, StatusRequest{Request: authedReq("occ_ffffffffffffffffffffffff")})
		requireCode(t, err, CodeAttemptUnknown)
		empty := authedReq(testOcc)
		empty.OccurrenceID = ""
		_, err = svc.Start(ctx, StartRequest{Request: empty})
		requireCode(t, err, CodeUsage)
	})

	t.Run("complete requires an active matching attempt", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		_, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json"))
		requireCode(t, err, CodeAttemptUnknown)
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		wrong := completeReq(testOcc, "fixed", "test-results/x/manifest.json")
		wrong.AttemptID = "att-other"
		_, err = svc.Complete(ctx, wrong)
		requireCode(t, err, CodeAttemptUnknown)
	})

	t.Run("complete requires closure patch and occurrence-specific tests", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		noPatch := completeReq(testOcc, "fixed", "test-results/x/manifest.json")
		noPatch.ClosurePatch = nil
		_, err := svc.Complete(ctx, noPatch)
		requireCode(t, err, CodePrerequisiteBlocked)
		partial := completeReq(testOcc, "fixed", "test-results/x/manifest.json")
		partial.ClosurePatch = &ClosurePatch{Trigger: "t"}
		_, err = svc.Complete(ctx, partial)
		requireCode(t, err, CodePrerequisiteBlocked)
		noTests := completeReq(testOcc, "fixed", "test-results/x/manifest.json")
		noTests.Tests = nil
		_, err = svc.Complete(ctx, noTests)
		requireCode(t, err, CodePrerequisiteBlocked)
	})

	t.Run("no_change requires the no-change-candidate state", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		_, err := svc.Complete(ctx, completeReq(testOcc, "no_change", "test-results/x/manifest.json"))
		requireCode(t, err, CodeEvidenceInvalid)
	})

	t.Run("no_change from the candidate state succeeds", func(t *testing.T) {
		svc, doc := loadTestService(t, "no_change_candidate")
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOccB)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		cs, err := svc.Complete(ctx, completeReq(testOccB, "no_change", "test-results/x/manifest.json"))
		if err != nil {
			t.Fatalf("no_change complete: %v", err)
		}
		assertCounts(t, doc, 0, 1, 1, 1)
		if cs.Transition.To.Disposition != DispositionNoChange {
			t.Fatalf("outcome not applied: %s", cs.Transition.To)
		}
	})

	t.Run("reject requires a cited reason and an active attempt", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		_, err := svc.Reject(ctx, RejectRequest{Request: authedReq(testOcc), Reason: "unused"})
		requireCode(t, err, CodeAttemptUnknown)
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		_, err = svc.Reject(ctx, RejectRequest{Request: authedReq(testOcc), Reason: "   "})
		requireCode(t, err, CodeUsage)
	})

	t.Run("unsafe evidence paths are usage errors", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		for _, p := range []string{"/etc/passwd", "../outside.json", ""} {
			_, err := svc.Complete(ctx, completeReq(testOcc, "fixed", p))
			requireCode(t, err, CodeUsage)
		}
	})

	t.Run("double start is refused while an attempt is active", func(t *testing.T) {
		svc, _ := loadTestService(t, "")
		if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
			t.Fatalf("start: %v", err)
		}
		_, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)})
		requireCode(t, err, CodeAttemptUnknown)
	})
}

// Unknown fields owned by colleagues must survive a namespace commit verbatim.
func TestCommitPreservesUnknownFields(t *testing.T) {
	ctx := context.Background()
	svc, doc := loadTestService(t, "")
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
		t.Fatalf("start: %v", err)
	}
	if _, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json")); err != nil {
		t.Fatalf("complete: %v", err)
	}
	after, err := doc.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if !bytes.Contains(after, []byte(`"preserve me"`)) || !bytes.Contains(after, []byte(`"colleagueTopLevel"`)) {
		t.Fatalf("colleague-owned content was dropped by republication:\n%s", after)
	}
	// Deterministic rendering: identical bytes on re-marshal.
	again, err := doc.Bytes()
	if err != nil || !bytes.Equal(after, again) {
		t.Fatalf("ledger rendering must be deterministic")
	}
}

func mustFind(t *testing.T, doc *LedgerDoc, occ string) map[string]json.RawMessage {
	t.Helper()
	row, ok := doc.Find(occ)
	if !ok {
		t.Fatalf("row %s missing", occ)
	}
	return row
}

func assertCounts(t *testing.T, doc *LedgerDoc, fixed, noChange, blocked, locallyRemediated int) {
	t.Helper()
	after, err := doc.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	var parsed struct {
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(after, &parsed); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if parsed.Counts["fixed"] != fixed || parsed.Counts["no_change"] != noChange ||
		parsed.Counts["blocked"] != blocked || parsed.Counts["locallyRemediated"] != locallyRemediated {
		t.Fatalf("counts reconcile wrong: %+v (want fixed=%d no_change=%d blocked=%d locallyRemediated=%d)",
			parsed.Counts, fixed, noChange, blocked, locallyRemediated)
	}
}

func assertStatementRefreshed(t *testing.T, doc *LedgerDoc) {
	t.Helper()
	after, err := doc.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	var parsed struct {
		Verification struct {
			Statement string `json:"statement"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(after, &parsed); err != nil {
		t.Fatalf("reparse: %v", err)
	}
	if strings.Contains(parsed.Verification.Statement, StatementNoReceipts) {
		t.Fatalf("zero-receipt statement survived a receipt-bound completion: %q", parsed.Verification.Statement)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
