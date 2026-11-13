package jmap

import (
	"encoding/json"
	"testing"
)

func TestErrorMarshalJSON_RFC8620(t *testing.T) {
	// Verify that marshaling an Error produces RFC 8620 §7.1 Problem Details JSON.
	err := Error{Type: "invalidArguments", Description: "bad thing happened"}
	data, merr := json.Marshal(err)
	if merr != nil {
		t.Fatalf("Marshal failed: %v", merr)
	}

	// Unmarshal into a generic map to check all fields.
	var out map[string]any
	if uerr := json.Unmarshal(data, &out); uerr != nil {
		t.Fatalf("Unmarshal failed: %v", uerr)
	}

	// Type must be a full URN.
	if out["type"] != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("type: got %q, want urn:ietf:params:jmap:error:invalidArguments", out["type"])
	}

	// Status must be an HTTP status code (400 for invalidArguments).
	if out["status"] != float64(400) {
		t.Errorf("status: got %v, want 400", out["status"])
	}

	// Detail must carry the human description.
	if out["detail"] != "bad thing happened" {
		t.Errorf("detail: got %q, want 'bad thing happened'", out["detail"])
	}
}

func TestErrorMarshalJSON_ServerFail(t *testing.T) {
	err := Error{Type: "serverFail", Description: "database error"}
	data, merr := json.Marshal(err)
	if merr != nil {
		t.Fatalf("Marshal failed: %v", merr)
	}

	var out map[string]any
	json.Unmarshal(data, &out)

	if out["type"] != "urn:ietf:params:jmap:error:serverFail" {
		t.Errorf("type: got %q", out["type"])
	}
	if out["status"] != float64(500) {
		t.Errorf("status: got %v, want 500", out["status"])
	}
}

func TestErrorMarshalJSON_EmptyDescription(t *testing.T) {
	// Description can be omitted when there is nothing to say.
	err := Error{Type: "unknownMethod"}
	data, _ := json.Marshal(err)
	var out map[string]any
	json.Unmarshal(data, &out)

	if _, hasDetail := out["detail"]; hasDetail {
		t.Errorf("detail should be omitted when empty, got %v", out["detail"])
	}
}

func TestErrorUnmarshalJSON_RoundTrip(t *testing.T) {
	// An Error that's marshaled should unmarshal back to the same logical Error.
	orig := Error{Type: "accountNotFound", Description: "no such account"}
	data, _ := json.Marshal(orig)

	var back Error
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if back.Type != "accountNotFound" {
		t.Errorf("round-trip Type: got %q, want 'accountNotFound'", back.Type)
	}
	if back.Description != "no such account" {
		t.Errorf("round-trip Description: got %q, want 'no such account'", back.Description)
	}
}

func TestErrorStatusMapping(t *testing.T) {
	tests := []struct {
		typ    string
		status int
	}{
		{"invalidArguments", 400},
		{"invalidPatch", 400},
		{"notJSON", 400},
		{"notRequest", 400},
		{"unknownMethod", 400},
		{"unknownCapability", 400},
		{"accountNotFound", 400},
		{"blobNotFound", 400},
		{"emailNotFound", 400},
		{"stateMismatch", 400},
		{"requestTooLarge", 400},
		{"accountReadOnly", 403},
		{"tooLarge", 413},
		{"rateLimit", 429},
		{"serverFail", 500},
		{"serverUnavailable", 500},
		{"overQuota", 500},
		{"forbidden", 500},
		{"someUnknownType", 500},
	}

	for _, tc := range tests {
		s := errorStatus(tc.typ)
		if s != tc.status {
			t.Errorf("errorStatus(%q) = %d, want %d", tc.typ, s, tc.status)
		}
	}
}
