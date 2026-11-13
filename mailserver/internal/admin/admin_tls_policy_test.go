package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTLSPolicyGet_Empty(t *testing.T) {
	t.Skip("requires database")

	h := NewTLSPolicyHandler(nil, nil)
	req := httptest.NewRequest("GET", "/admin/outbound-tls-policy", nil)
	rec := httptest.NewRecorder()
	h.GetTLSPolicy(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp tlsPolicyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.GlobalMode != "opportunistic" {
		t.Errorf("expected global_mode=opportunistic, got %q", resp.GlobalMode)
	}
	if len(resp.EnforceDomains) != 0 {
		t.Errorf("expected empty enforce_domains, got %v", resp.EnforceDomains)
	}
	if len(resp.SkipDomains) != 0 {
		t.Errorf("expected empty skip_domains, got %v", resp.SkipDomains)
	}
}

func TestTLSPolicyPut_EnforceOnly(t *testing.T) {
	t.Skip("requires database")

	h := NewTLSPolicyHandler(nil, nil)

	// PUT enforce domains
	putBody := `{"enforce_domains":["example.com","example.org"],"skip_domains":[],"global_mode":"enforce"}`
	putReq := httptest.NewRequest("PUT", "/admin/outbound-tls-policy", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.PutTLSPolicy(putRec, putReq)

	if putRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", putRec.Code, putRec.Body.String())
	}

	// GET and verify
	getReq := httptest.NewRequest("GET", "/admin/outbound-tls-policy", nil)
	getRec := httptest.NewRecorder()
	h.GetTLSPolicy(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRec.Code, getRec.Body.String())
	}

	var resp tlsPolicyResponse
	if err := json.NewDecoder(getRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.GlobalMode != "enforce" {
		t.Errorf("expected global_mode=enforce, got %q", resp.GlobalMode)
	}
	if len(resp.EnforceDomains) != 2 {
		t.Errorf("expected 2 enforce_domains, got %v", resp.EnforceDomains)
	}
	if resp.EnforceDomains[0] != "example.com" {
		t.Errorf("expected enforce_domains[0]=example.com, got %q", resp.EnforceDomains[0])
	}
	if resp.EnforceDomains[1] != "example.org" {
		t.Errorf("expected enforce_domains[1]=example.org, got %q", resp.EnforceDomains[1])
	}
	if len(resp.SkipDomains) != 0 {
		t.Errorf("expected empty skip_domains, got %v", resp.SkipDomains)
	}
}

func TestTLSPolicyPut_InvalidJSON(t *testing.T) {
	h := NewTLSPolicyHandler(nil, nil)

	putBody := `not json`
	putReq := httptest.NewRequest("PUT", "/admin/outbound-tls-policy", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.PutTLSPolicy(putRec, putReq)

	if putRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d: %s", putRec.Code, putRec.Body.String())
	}
}

func TestTLSPolicyPut_InvalidMode(t *testing.T) {
	h := NewTLSPolicyHandler(nil, nil)

	putBody := `{"enforce_domains":["example.com"],"skip_domains":[],"global_mode":"invalid"}`
	putReq := httptest.NewRequest("PUT", "/admin/outbound-tls-policy", strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	h.PutTLSPolicy(putRec, putReq)

	if putRec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid mode, got %d: %s", putRec.Code, putRec.Body.String())
	}
}

func TestTLSPolicyNewHandler(t *testing.T) {
	h := NewTLSPolicyHandler(nil, nil)
	if h == nil {
		t.Fatal("NewTLSPolicyHandler returned nil")
	}
}

func TestTLSPolicyResponse_RoundTrip(t *testing.T) {
	resp := tlsPolicyResponse{
		EnforceDomains: []string{"example.com", "example.org"},
		SkipDomains:    []string{"skip.example.com"},
		GlobalMode:     "enforce",
	}
	data, _ := json.Marshal(resp)
	var r2 tlsPolicyResponse
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r2.GlobalMode != "enforce" {
		t.Errorf("global_mode = %q, want enforce", r2.GlobalMode)
	}
	if len(r2.EnforceDomains) != 2 || r2.EnforceDomains[0] != "example.com" {
		t.Errorf("enforce_domains mismatch: %v", r2.EnforceDomains)
	}
	if len(r2.SkipDomains) != 1 || r2.SkipDomains[0] != "skip.example.com" {
		t.Errorf("skip_domains mismatch: %v", r2.SkipDomains)
	}
}

func TestTLSPolicyValidation(t *testing.T) {
	h := NewTLSPolicyHandler(nil, nil)

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"valid enforce", `{"enforce_domains":["a.com"],"skip_domains":[],"global_mode":"enforce"}`, ""},
		{"valid opportunistic", `{"enforce_domains":[],"skip_domains":["b.com"],"global_mode":"opportunistic"}`, ""},
		{"valid empty both", `{"enforce_domains":[],"skip_domains":[],"global_mode":"enforce"}`, ""},
		{"invalid mode", `{"enforce_domains":[],"skip_domains":[],"global_mode":"bad"}`, "global_mode"},
		{"missing mode", `{"enforce_domains":[],"skip_domains":[]}`, "global_mode"},
		{"enforce not array", `{"enforce_domains":"not-array","skip_domains":[],"global_mode":"enforce"}`, "enforce_domains"},
		{"skip not array", `{"enforce_domains":[],"skip_domains":"not-array","global_mode":"enforce"}`, "skip_domains"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			putReq := httptest.NewRequest("PUT", "/admin/outbound-tls-policy", strings.NewReader(tt.body))
			putReq.Header.Set("Content-Type", "application/json")
			putRec := httptest.NewRecorder()

			// Call validate directly to test validation logic
			var req tlsPolicyRequest
			if err := json.NewDecoder(strings.NewReader(tt.body)).Decode(&req); err != nil {
				if tt.wantErr == "" {
					t.Errorf("unexpected decode error: %v", err)
				}
				return
			}
			err := h.validateTLSPolicyRequest(req)
			if tt.wantErr == "" && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got %v", tt.wantErr, err)
				}
			}
			_ = putRec
		})
	}
}
