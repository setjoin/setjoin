package httputil

import (
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogAttrsIncludesRequestIDAndUserID(t *testing.T) {
	attrs := LogAttrs(context.Background(), "42")
	if len(attrs) < 4 {
		t.Fatalf("LogAttrs returned %d attrs, want at least 4", len(attrs))
	}
	found := map[string]bool{}
	for i := 0; i < len(attrs); i += 2 {
		if key, ok := attrs[i].(string); ok {
			found[key] = true
		}
	}
	if !found["request_id"] {
		t.Error("LogAttrs missing 'request_id' key")
	}
	if !found["user_id"] {
		t.Error("LogAttrs missing 'user_id' key")
	}
}

func TestLogAttrsSetsUserIDToAnonWhenEmpty(t *testing.T) {
	attrs := LogAttrs(context.Background(), "")
	var userID string
	for i := 0; i < len(attrs); i += 2 {
		if key, ok := attrs[i].(string); ok && key == "user_id" {
			if val, ok := attrs[i+1].(string); ok {
				userID = val
			}
		}
	}
	if userID != "anon" {
		t.Errorf("user_id = %q, want 'anon'", userID)
	}
}

func TestLogAttrsPreservesUserID(t *testing.T) {
	attrs := LogAttrs(context.Background(), "12345")
	var userID string
	for i := 0; i < len(attrs); i += 2 {
		if key, ok := attrs[i].(string); ok && key == "user_id" {
			if val, ok := attrs[i+1].(string); ok {
				userID = val
			}
		}
	}
	if userID != "12345" {
		t.Errorf("user_id = %q, want '12345'", userID)
	}
}

func TestLogAttrsOutputLength(t *testing.T) {
	// LogAttrs always produces request_id + user_id (4 items), plus extras.
	baseLen := len(LogAttrs(context.Background(), "42"))
	if baseLen != 4 {
		t.Errorf("base LogAttrs length = %d, want 4", baseLen)
	}
	extraLen := len(LogAttrs(context.Background(), "42", "key1", "val1", "key2", "val2"))
	if extraLen != 8 {
		t.Errorf("LogAttrs with 2 extra pairs length = %d, want 8", extraLen)
	}
}

func TestLogAttrsRequestIDEmptyFromBareContext(t *testing.T) {
	attrs := LogAttrs(context.Background(), "42")
	var reqID string
	for i := 0; i < len(attrs); i += 2 {
		if key, ok := attrs[i].(string); ok && key == "request_id" {
			if val, ok := attrs[i+1].(string); ok {
				reqID = val
			}
		}
	}
	if reqID != "" {
		t.Errorf("request_id from bare context = %q, want empty string", reqID)
	}
}

func TestRedactEmailNormal(t *testing.T) {
	result := RedactEmail("user@example.com")
	if result != "u***@example.com" {
		t.Errorf("RedactEmail('user@example.com') = %q, want 'u***@example.com'", result)
	}
}

func TestRedactEmailSingleCharLocal(t *testing.T) {
	result := RedactEmail("a@b.com")
	if result != "a***@b.com" {
		t.Errorf("RedactEmail('a@b.com') = %q, want 'a***@b.com'", result)
	}
}

func TestRedactEmailEmpty(t *testing.T) {
	result := RedactEmail("")
	if result != "" {
		t.Errorf("RedactEmail('') = %q, want ''", result)
	}
}

func TestRedactEmailNoAtSign(t *testing.T) {
	result := RedactEmail("no-at-sign")
	if result != "***" {
		t.Errorf("RedactEmail('no-at-sign') = %q, want '***'", result)
	}
}

func TestRedactEmailAtStart(t *testing.T) {
	// at <= 0 (IndexByte returns -1 when not found, 0 when at start)
	result := RedactEmail("@domain.com")
	if result != "***" {
		t.Errorf("RedactEmail('@domain.com') = %q, want '***'", result)
	}
}

func TestRedactedStringLogValue(t *testing.T) {
	rs := RedactedString("supersecret")
	val := rs.LogValue()
	if val.Kind() != slog.KindString {
		t.Errorf("LogValue kind = %v, want String", val.Kind())
	}
	if !strings.Contains(val.String(), "REDACTED") {
		t.Errorf("LogValue = %q, want redacted", val.String())
	}
	// Verify the original value is NOT in the output.
	if strings.Contains(val.String(), "supersecret") {
		t.Error("LogValue leaks the original secret value")
	}
}

func TestRedactedStringZeroValue(t *testing.T) {
	var rs RedactedString // zero value
	val := rs.LogValue()
	if !strings.Contains(val.String(), "REDACTED") {
		t.Errorf("zero RedactedString LogValue = %q, want redacted", val.String())
	}
}

func TestLogErrorDoesNotPanic(t *testing.T) {
	// Just verify the function runs without panicking.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("LogError panicked: %v", r)
		}
	}()
	LogError(context.Background(), "test message", "42", "error", "something went wrong")
}

func TestLogWarnDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("LogWarn panicked: %v", r)
		}
	}()
	LogWarn(context.Background(), "test warning", "", "count", 5)
}

func TestLogInfoDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("LogInfo panicked: %v", r)
		}
	}()
	LogInfo(context.Background(), "test info", "anon")
}
