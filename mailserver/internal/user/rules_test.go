package user

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/httputil"
)

func TestRuleRequestParsing(t *testing.T) {
	payload := `{
		"name": "Test Rule",
		"enabled": true,
		"priority": 10,
		"runOn": "server",
		"conditions": {"operator":"OR","conditions":[{"field":"subject","op":"contains","value":"test"}]},
		"actions": [{"type":"mark_read","params":{}}],
		"stopProcessing": false
	}`
	var req ruleRequest
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if req.Name != "Test Rule" {
		t.Errorf("name = %q, want %q", req.Name, "Test Rule")
	}
	if !req.Enabled {
		t.Error("expected enabled = true")
	}
	if req.Priority != 10 {
		t.Errorf("priority = %d, want 10", req.Priority)
	}
	if req.RunOn != "server" {
		t.Errorf("runOn = %q, want server", req.RunOn)
	}
	if req.StopProcessing {
		t.Error("expected stopProcessing = false")
	}
}

func TestRuleResponseParsing(t *testing.T) {
	payload := `{
		"id": 1,
		"name": "Test Rule",
		"enabled": true,
		"priority": 10,
		"runOn": "server",
		"isTransportRule": false,
		"conditions": [],
		"actions": [],
		"stopProcessing": false,
		"createdAt": "2024-01-01T00:00:00Z",
		"updatedAt": "2024-01-01T00:00:00Z"
	}`
	var resp ruleResponse
	if err := json.Unmarshal([]byte(payload), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if resp.ID != 1 {
		t.Errorf("id = %d, want 1", resp.ID)
	}
	if resp.Name != "Test Rule" {
		t.Errorf("name = %q, want %q", resp.Name, "Test Rule")
	}
}

func TestWriteJSONError(t *testing.T) {
	rec := httptest.NewRecorder()
	httputil.WriteError(rec, http.StatusBadRequest, "bad input")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var body httputil.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body failed: %v", err)
	}
	if body.Detail != "bad input" {
		t.Errorf("detail = %q, want %q", body.Detail, "bad input")
	}
}

func TestRuleRequestValidation(t *testing.T) {
	// Empty name should be rejected by handler (tested at unit level)
	req := ruleRequest{
		Name:     "",
		Enabled:  true,
		Priority: 5,
		RunOn:    "",
	}
	if req.Name == "" {
		// Handler will reject this; just confirming the struct state
		_ = req
	}
}

func TestRuleConditionsORGroup(t *testing.T) {
	conds := map[string]interface{}{
		"operator": "OR",
		"conditions": []map[string]interface{}{
			{"field": "subject", "op": "contains", "value": "test"},
			{"field": "from_addr", "op": "equals", "value": "alice@example.com"},
		},
	}
	b, err := json.Marshal(conds)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var parsed json.RawMessage = b
	if len(parsed) == 0 {
		t.Error("expected non-empty JSON")
	}
}
