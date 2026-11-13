package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"setjoin.com/mailserver/internal/smime"
)

// --- pure helper: stripSignSMIME ---

func TestStripSignSMIME(t *testing.T) {
	in := json.RawMessage(`{"emailId":"42","signSMIME":true,"onSendUndoWindowSeconds":30}`)
	out := stripSignSMIME(in)
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := obj["signSMIME"]; ok {
		t.Error("signSMIME must be removed")
	}
	if _, ok := obj["emailId"]; !ok {
		t.Error("emailId must be preserved")
	}
	if _, ok := obj["onSendUndoWindowSeconds"]; !ok {
		t.Error("other fields must be preserved")
	}
}

func TestStripSignSMIME_AbsentIsNoop(t *testing.T) {
	in := json.RawMessage(`{"emailId":"42"}`)
	out := stripSignSMIME(in)
	if string(out) != string(in) {
		t.Errorf("absent signSMIME should return input unchanged, got %s", out)
	}
}

func TestStripSignSMIME_MalformedReturnsInput(t *testing.T) {
	in := json.RawMessage(`not json`)
	out := stripSignSMIME(in)
	if string(out) != string(in) {
		t.Errorf("malformed input should pass through unchanged, got %s", out)
	}
}

// --- pure helper: classifyDraftLoadErr (fail-closed on transient load error) ---

func TestClassifyDraftLoadErr_NoRowsIsNothingToSign(t *testing.T) {
	// A genuine not-found/not-owned draft is NOT a sign failure: return ("","")
	// so the reducer can emit its own notFound and the message passes through.
	ref, reason := classifyDraftLoadErr(pgx.ErrNoRows)
	if ref != "" || reason != "" {
		t.Errorf("pgx.ErrNoRows → (%q,%q), want (\"\",\"\")", ref, reason)
	}
}

func TestClassifyDraftLoadErr_TransientFailsClosed(t *testing.T) {
	// A transient/connection error MUST fail closed: the user asked to sign, so
	// returning ("","") (= pass through unsigned) would be a fail-open trust bug.
	ref, reason := classifyDraftLoadErr(errors.New("boom"))
	if ref != "" {
		t.Errorf("transient error → signedRef %q, want \"\"", ref)
	}
	if reason != smime.ReasonSignFailed {
		t.Errorf("transient error → reason %q, want %q (must fail closed)", reason, smime.ReasonSignFailed)
	}
}

func TestClassifyDraftLoadErr_WrappedNoRowsIsNothingToSign(t *testing.T) {
	// errors.Is must see through a wrapped pgx.ErrNoRows.
	ref, reason := classifyDraftLoadErr(fmt.Errorf("scan: %w", pgx.ErrNoRows))
	if ref != "" || reason != "" {
		t.Errorf("wrapped pgx.ErrNoRows → (%q,%q), want (\"\",\"\")", ref, reason)
	}
}

// --- pure helper: mergeNotCreated ---

func TestMergeNotCreated_Empty(t *testing.T) {
	result := json.RawMessage(`{"created":{"k1":{"id":"1"}},"notCreated":{}}`)
	out := mergeNotCreated(result, nil)
	if string(out) != string(result) {
		t.Errorf("empty goNotCreated should return result unchanged, got %s", out)
	}
}

func TestMergeNotCreated_MergesIntoExisting(t *testing.T) {
	result := json.RawMessage(`{"created":{},"notCreated":{"r1":{"type":"notFound","description":"x"}}}`)
	go1, _ := json.Marshal(map[string]string{"type": "smime_no_cert", "description": "no cert"})
	out := mergeNotCreated(result, map[string]json.RawMessage{"k2": go1})

	var resp struct {
		NotCreated map[string]struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"notCreated"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.NotCreated["r1"].Type != "notFound" {
		t.Error("existing reducer notCreated entry must be preserved")
	}
	if resp.NotCreated["k2"].Type != "smime_no_cert" {
		t.Errorf("go-side notCreated entry must be merged, got %+v", resp.NotCreated)
	}
}

func TestMergeNotCreated_NoExistingKey(t *testing.T) {
	result := json.RawMessage(`{"created":{}}`)
	go1, _ := json.Marshal(map[string]string{"type": "smime_sign_failed", "description": "boom"})
	out := mergeNotCreated(result, map[string]json.RawMessage{"k1": go1})
	var resp struct {
		NotCreated map[string]struct {
			Type string `json:"type"`
		} `json:"notCreated"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.NotCreated["k1"].Type != "smime_sign_failed" {
		t.Errorf("notCreated key must be created when absent, got %s", out)
	}
}

func TestMergeNotCreated_MalformedResultUnchanged(t *testing.T) {
	result := json.RawMessage(`not json`)
	go1, _ := json.Marshal(map[string]string{"type": "smime_no_cert"})
	out := mergeNotCreated(result, map[string]json.RawMessage{"k1": go1})
	if string(out) != string(result) {
		t.Errorf("malformed result should pass through unchanged, got %s", out)
	}
}

// --- no-infra signSubmissions: strips signSMIME, no signing performed ---

func TestSignSubmissions_NoInfraStripsFlag(t *testing.T) {
	// nil pool / nil minio handler — the no-infra shape. signSMIME must be
	// stripped (so the dormant worker path never fires) and no signedRefs/
	// notCreated produced.
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	create := map[string]json.RawMessage{
		"k1": json.RawMessage(`{"emailId":"42","signSMIME":true}`),
		"k2": json.RawMessage(`{"emailId":"43"}`),
	}
	modified, signedRefs, notCreated := h.signSubmissions(context.Background(), 7, 7, create)

	if len(signedRefs) != 0 {
		t.Errorf("no signing without infra: signedRefs=%v", signedRefs)
	}
	if len(notCreated) != 0 {
		t.Errorf("no-infra is not a sign failure: notCreated=%v", notCreated)
	}
	// k1 had signSMIME → must be stripped.
	var k1 map[string]json.RawMessage
	if err := json.Unmarshal(modified["k1"], &k1); err != nil {
		t.Fatal(err)
	}
	if _, ok := k1["signSMIME"]; ok {
		t.Error("k1 signSMIME must be stripped even without infra")
	}
	// k2 had no signSMIME → passed through verbatim.
	if string(modified["k2"]) != `{"emailId":"43"}` {
		t.Errorf("k2 should pass through unchanged, got %s", modified["k2"])
	}
}

// --- end-to-end: the reducer never sees signSMIME, and the 4th arg is wired ---

func TestEmailSubmissionSet_StripsSignSMIMEBeforeReducer(t *testing.T) {
	// No infra (nil pool/minio via newFakeHandler) so signing is skipped, but the
	// stripping + arg-count plumbing still runs. Assert the worker reducer receives
	// a create map with signSMIME removed and a 4th (p_signed_raw_ref) arg present.
	fake := &fakeCaller{returnRaw: json.RawMessage(`{"created":{},"notCreated":{}}`)}
	h := newFakeHandler(fake)
	user := testClaims(7)
	args, _ := json.Marshal(map[string]any{
		"accountId": "7",
		"create": map[string]any{
			"k1": map[string]any{"emailId": "42", "signSMIME": true},
		},
	})
	name, _ := h.emailSubmissionSet(context.Background(), user, args)
	if name != "EmailSubmission/set" {
		t.Fatalf("got %q, want EmailSubmission/set", name)
	}
	if fake.gotFn != "jmap_email_submission_set" {
		t.Fatalf("reducer fn = %q", fake.gotFn)
	}
	// 5 positional args: accountID, userID, create, processedRefs, isEncrypted.
	if len(fake.gotArgs) != 5 {
		t.Fatalf("reducer arg count = %d, want 5 (incl. p_processed_raw_ref + p_is_encrypted)", len(fake.gotArgs))
	}
	createArg, ok := fake.gotArgs[2].(json.RawMessage)
	if !ok {
		t.Fatalf("arg[2] type = %T, want json.RawMessage", fake.gotArgs[2])
	}
	var createMap map[string]json.RawMessage
	if err := json.Unmarshal(createArg, &createMap); err != nil {
		t.Fatalf("create arg unmarshal: %v", err)
	}
	var k1 map[string]json.RawMessage
	if err := json.Unmarshal(createMap["k1"], &k1); err != nil {
		t.Fatal(err)
	}
	if _, present := k1["signSMIME"]; present {
		t.Error("signSMIME must be stripped from the create map reaching the reducer")
	}
	if _, present := k1["emailId"]; !present {
		t.Error("emailId must survive into the reducer create map")
	}
}
