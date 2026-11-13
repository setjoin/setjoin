package securityprogram

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Authority: accepted SEC-DP1 A–E and remediation-quickstart.md §5. Expected
// axes, attempt outcomes and counts below are explicit oracles, not obtained
// from operationRules or ContractJSON. The Node checker consumes actual
// serialized writer output, including the hash-bound evidence body.
func TestSerializedTransitionProof(t *testing.T) {
	for _, outcome := range []string{"active", "fixed", "no_change", "rejected", "reject-restart-fixed"} {
		t.Run(outcome, func(t *testing.T) {
			row := sealedRow(testOcc, "unmapped")
			if outcome == "no_change" {
				row["localStatus"] = "no_change_candidate"
			}
			var input map[string]any
			if err := json.Unmarshal(testLedgerBytes(t, ""), &input); err != nil {
				t.Fatal(err)
			}
			input["rows"] = []any{row}
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := LoadLedger(raw)
			if err != nil {
				t.Fatal(err)
			}
			svc := NewService(doc)
			ctx := context.Background()
			before, err := doc.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.Status(ctx, StatusRequest{Request: authedReq(testOcc)}); err != nil {
				t.Fatal(err)
			}
			afterStatus, err := doc.Bytes()
			if err != nil || !bytes.Equal(before, afterStatus) {
				t.Fatal("status must not serialize a transition or mutate the ledger")
			}
			request := authedReq(testOcc)
			change, err := svc.Start(ctx, StartRequest{Request: request})
			if err != nil {
				t.Fatal(err)
			}
			wantState := RowState{"blocked", "traced", "none", "not_ready"}
			wantAttempt, wantHistory := "active", 1
			fixed, noChange, blocked, remediated := 0, 0, 1, 0
			if outcome == "rejected" || outcome == "reject-restart-fixed" {
				change, err = svc.Reject(ctx, RejectRequest{Request: request, Reason: "independent regression still fails"})
				if err != nil {
					t.Fatal(err)
				}
				wantState, wantAttempt, wantHistory = RowState{"blocked", "blocked", "none", "not_ready"}, "rejected", 2
			}
			if outcome == "reject-restart-fixed" {
				request.AttemptID = "att-0002"
				if _, err = svc.Start(ctx, StartRequest{Request: request}); err != nil {
					t.Fatal(err)
				}
				wantHistory = 3
			}
			if outcome == "fixed" || outcome == "no_change" || outcome == "reject-restart-fixed" {
				finish := "fixed"
				if outcome == "no_change" {
					finish = "no_change"
				}
				req := completeReq(testOcc, finish, "test-results/er3/manifest.json")
				req.Request = request
				change, err = svc.Complete(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				wantState, wantAttempt = RowState{Disposition(finish), "proof_patched", "receipt_bound", "not_ready"}, "completed"
				wantHistory++
				blocked, remediated = 0, 1
				if finish == "fixed" {
					fixed = 1
				} else {
					noChange = 1
				}
			}
			// Reload the wire bytes. An in-memory view would have missed the
			// prior LedgerDoc.Bytes serialization regression.
			reloaded, err := LoadLedger(change.LedgerAfter)
			if err != nil {
				t.Fatal(err)
			}
			view, err := ViewRow(mustFind(t, reloaded, testOcc))
			if err != nil {
				t.Fatal(err)
			}
			if view.State != wantState || view.Attempt.State != wantAttempt || len(view.Transitions) != wantHistory {
				t.Fatalf("serialized outcome differs from independent expectation: %+v", view)
			}
			assertCounts(t, reloaded, fixed, noChange, blocked, remediated)
			if remediated != 0 {
				assertStatementRefreshed(t, reloaded)
			} else if !bytes.Contains(change.LedgerAfter, []byte(StatementNoReceipts)) {
				t.Fatal("non-completion removed the honest zero-receipt statement")
			}
			proof, err := json.Marshal(struct {
				Ledger   json.RawMessage `json:"ledger"`
				Evidence *EvidenceFile   `json:"evidence"`
			}{change.LedgerAfter, change.Evidence})
			if err != nil {
				t.Fatal(err)
			}
			root, err := filepath.Abs(filepath.Join("..", ".."))
			if err != nil {
				t.Fatal(err)
			}
			deadline, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(deadline, "node", "--input-type=module", "-e", `
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const root = process.argv[1];
const {readEr3Contract, validateEr3Row} = await import(pathToFileURL(path.join(root, 'scripts/check-deep-security-remediation.mjs')));
const proof = JSON.parse(fs.readFileSync(0, 'utf8'));
const errors = [];
const grammar = readEr3Contract(errors, JSON.parse(fs.readFileSync(path.join(root, 'docs/verification/deep-security-remediation-transitions.json'))));
for (const row of proof.ledger.rows) validateEr3Row(errors, row, grammar);
if (proof.evidence) {
  const row = proof.ledger.rows[0];
  const body = Buffer.from(proof.evidence.Body, 'base64');
  if (crypto.createHash('sha256').update(body).digest('hex') !== row.remediationTransitions.at(-1).evidenceSha256) errors.push('evidence hash mismatch');
  const evidence = JSON.parse(body);
  if (evidence.occurrenceId !== row.occurrenceId || evidence.outcome !== row.disposition || evidence.attemptId !== row.remediation.attemptId) errors.push('evidence identity mismatch');
}
if (errors.length) { console.error(JSON.stringify(errors)); process.exitCode = 1; }
`, root)
			cmd.Stdin = bytes.NewReader(proof)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("offline checker rejected real serialized %s history: %v\n%s", outcome, err, output)
			}
		})
	}
}

func TestPreservedV1GrammarArtifact(t *testing.T) {
	raw, err := os.ReadFile("testdata/transitions-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if SHA256Hex(raw) != "ddadb2ad45372d5da0669d22d938c3b325ddf32e50db92c4ea040acfc87d1add" {
		t.Fatal("historical v1 grammar must remain byte-identical")
	}
	if ContractVersion != "setjoin.sec.security-program-remediation/v1" {
		t.Fatal("grammar v2 must not rewrite the request/history contract")
	}
}

func TestRequiredRunIdentityOnClosure(t *testing.T) {
	for _, op := range []string{"complete", "reject"} {
		t.Run(op, func(t *testing.T) {
			svc, _ := loadTestService(t, "")
			ctx := context.Background()
			if _, err := svc.Start(ctx, StartRequest{Request: authedReq(testOcc)}); err != nil {
				t.Fatal(err)
			}
			req := authedReq(testOcc)
			req.RunID = ""
			var err error
			if op == "complete" {
				complete := completeReq(testOcc, "fixed", "test-results/er3/manifest.json")
				complete.Request = req
				_, err = svc.Complete(ctx, complete)
			} else {
				_, err = svc.Reject(ctx, RejectRequest{Request: req, Reason: "proof missing"})
			}
			if !IsCode(err, CodeUsage) || !strings.Contains(err.Error(), "runId") {
				t.Fatalf("missing run identity must be a usage refusal before publication: %v", err)
			}
		})
	}
}
