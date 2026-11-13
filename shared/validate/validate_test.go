package validate

import (
	"encoding/json"
	"testing"

	"setjoin.com/shared/httputil"
)

func TestValidationError_ToFieldError(t *testing.T) {
	e := NewValidationError("email", "must contain @", "INVALID_EMAIL")
	got := e.ToFieldError()
	want := httputil.FieldError{Field: "email", Message: "must contain @"}
	if got != want {
		t.Errorf("ToFieldError() = %+v, want %+v", got, want)
	}
	// Message must equal Reason so the existing `Detail: ve.Reason` call sites
	// stay byte-identical when switched to `ve.ToFieldError().Message`.
	if got.Message != e.Reason {
		t.Errorf("ToFieldError().Message = %q, want Reason %q", got.Message, e.Reason)
	}
	if got.Field != e.Field {
		t.Errorf("ToFieldError().Field = %q, want Field %q", got.Field, e.Field)
	}
}

func TestValidationError_Error(t *testing.T) {
	e := NewValidationError("email", "must contain @", "INVALID_EMAIL")
	got := e.Error()
	want := `validation failed for email: must contain @`
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestValidationError_JSON(t *testing.T) {
	e := NewValidationError("email", "must contain @", "INVALID_EMAIL")
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var out struct {
		Field  string `json:"field"`
		Reason string `json:"reason"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if out.Field != "email" {
		t.Errorf("Field = %q, want %q", out.Field, "email")
	}
	if out.Reason != "must contain @" {
		t.Errorf("Reason = %q, want %q", out.Reason, "must contain @")
	}
	if out.Code != "INVALID_EMAIL" {
		t.Errorf("Code = %q, want %q", out.Code, "INVALID_EMAIL")
	}
}
