package jmap

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictJSONAcceptsOneObjectAndRejectsExtraInput(t *testing.T) {
	t.Parallel()
	type input struct {
		Value string `json:"value"`
	}

	var valid input
	if err := decodeStrictJSON(json.RawMessage(`{"value":"ok"}`), &valid); err != nil {
		t.Fatalf("valid object: %v", err)
	}
	if valid.Value != "ok" {
		t.Fatalf("value = %q, want ok", valid.Value)
	}

	for name, raw := range map[string]json.RawMessage{
		"malformed":      json.RawMessage(`{"value":`),
		"unknown field":  json.RawMessage(`{"value":"ok","extra":true}`),
		"trailing value": json.RawMessage(`{"value":"ok"} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			var got input
			if err := decodeStrictJSON(raw, &got); err == nil {
				t.Fatal("expected strict decode failure")
			} else if name == "trailing value" && !strings.Contains(err.Error(), "trailing JSON") {
				t.Fatalf("error = %q, want trailing JSON", err)
			}
		})
	}
}
