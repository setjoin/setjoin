// operations_edge_test.go — the transition grammar's refusal arms the
// happy-path suites never reach: start's required attempt/run identity,
// complete's outcome vocabulary, the not-open-sealed-state fence shared by
// complete and reject (an active attempt on a row the seal has already
// dispositioned is corruption the namespace refuses rather than advances),
// and reject's attempt-identity fence.
package securityprogram

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// nonOpenAttemptedLedger builds a fixture whose single row is already
// dispositioned (fixed/none) yet carries an ACTIVE attempt record — a state
// the namespace's own transitions can never produce, so the only way to
// exercise the not-open-sealed fence is to stage it directly in the fixture.
func nonOpenAttemptedLedger(t *testing.T) []byte {
	t.Helper()
	doc := map[string]any{}
	if err := json.Unmarshal(testLedgerBytes(t, ""), &doc); err != nil {
		t.Fatalf("fixture reparse: %v", err)
	}
	rows := doc["rows"].([]any)
	row := rows[0].(map[string]any)
	row["disposition"] = "fixed"
	row["localStatus"] = "patched"
	row["remediation"] = map[string]any{
		"attemptId": testAttID, "runId": "run-past", "state": AttemptActive,
		"openedAt": "2026-09-17T00:00:00Z",
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("fixture remarshal: %v", err)
	}
	return out
}

func TestStartRequiresAttemptAndRunIdentity(t *testing.T) {
	ctx := context.Background()
	svc, _ := loadTestService(t, "")

	noAttempt := authedReq(testOcc)
	noAttempt.AttemptID = ""
	_, err := svc.Start(ctx, StartRequest{Request: noAttempt})
	requireCode(t, err, CodeUsage)

	noRun := authedReq(testOcc)
	noRun.RunID = ""
	_, err = svc.Start(ctx, StartRequest{Request: noRun})
	requireCode(t, err, CodeUsage)
}

func TestCompleteOutcomeVocabularyIsClosed(t *testing.T) {
	ctx := context.Background()
	svc, _ := loadTestService(t, "")
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
		t.Fatalf("start: %v", err)
	}
	_, err := svc.Complete(ctx, completeReq(testOcc, "worse", "test-results/x/manifest.json"))
	requireCode(t, err, CodeUsage)
}

// TestCompleteAndRejectRefuseNonOpenSealedState pins the shared
// concrete open-state axis constraints: an active attempt on a row the seal
// has already dispositioned is corruption — complete and reject both refuse
// the transition instead of advancing the row again.
func TestCompleteAndRejectRefuseNonOpenSealedState(t *testing.T) {
	ctx := context.Background()
	svc := loadBytes(t, nonOpenAttemptedLedger(t))

	_, err := svc.Complete(ctx, completeReq(testOcc, "fixed", "test-results/x/manifest.json"))
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "not an open sealed state") {
		t.Fatalf("complete over dispositioned row = %v", err)
	}

	rej := RejectRequest{Request: authedReq(testOcc), Reason: "gate still HOLD"}
	_, err = svc.Reject(ctx, rej)
	if !IsCode(err, CodeEvidenceInvalid) || !strings.Contains(err.Error(), "not an open sealed state") {
		t.Fatalf("reject over dispositioned row = %v", err)
	}
}

func TestRejectAttemptIdentityFence(t *testing.T) {
	ctx := context.Background()
	svc, _ := loadTestService(t, "")
	if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
		t.Fatalf("start: %v", err)
	}
	wrong := RejectRequest{Request: authedReq(testOcc), Reason: "not the active attempt"}
	wrong.AttemptID = "att-other"
	_, err := svc.Reject(ctx, wrong)
	requireCode(t, err, CodeAttemptUnknown)
}
