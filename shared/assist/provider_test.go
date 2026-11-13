package assist_test

import (
	"context"
	"strings"
	"testing"

	"setjoin.com/shared/assist"
)

// TestProviderTypes asserts the envelope types and Provider interface shape.
func TestProviderTypes(t *testing.T) {
	// Message{Role, Content string}
	msg := assist.Message{Role: "user", Content: "hello"}
	if msg.Role != "user" || msg.Content != "hello" {
		t.Errorf("Message fields: got Role=%q Content=%q", msg.Role, msg.Content)
	}

	// Request{Messages []Message, Context string, Locale string}
	req := assist.Request{
		Messages: []assist.Message{msg},
		Context:  "ctx",
		Locale:   "en",
	}
	if len(req.Messages) != 1 || req.Context != "ctx" || req.Locale != "en" {
		t.Errorf("Request fields: got %+v", req)
	}

	// Response{Content string}
	resp := assist.Response{Content: "hi"}
	if resp.Content != "hi" {
		t.Errorf("Response.Content: got %q", resp.Content)
	}
}

// TestProviderInterface asserts that Provider is an interface with Complete.
// We compile a nil assignment to verify the interface is satisfied.
func TestProviderInterface(t *testing.T) {
	// This verifies that the interface exists; a real implementation is tested separately.
	var _ assist.Provider = (*mockProvider)(nil)
}

// mockProvider satisfies the Provider interface for compile-time checking.
type mockProvider struct{}

func (m *mockProvider) Complete(_ context.Context, _ assist.Request) (assist.Response, error) {
	return assist.Response{}, nil
}

// TestValidate tests the Validate helper.
func TestValidate(t *testing.T) {
	t.Run("empty_messages", func(t *testing.T) {
		err := assist.Validate(assist.Request{})
		if err == nil {
			t.Fatal("expected error for empty Messages, got nil")
		}
		if err != assist.ErrEmptyMessages {
			t.Errorf("expected ErrEmptyMessages, got %v", err)
		}
	})

	t.Run("empty_content", func(t *testing.T) {
		err := assist.Validate(assist.Request{
			Messages: []assist.Message{{Role: "user", Content: ""}},
		})
		if err == nil {
			t.Fatal("expected error for empty Content, got nil")
		}
	})

	t.Run("too_large", func(t *testing.T) {
		// Default byte cap is 512 KiB (512*1024).
		// Build a request with content exceeding that.
		big := strings.Repeat("x", 512*1024+1)
		err := assist.Validate(assist.Request{
			Messages: []assist.Message{{Role: "user", Content: big}},
		})
		if err == nil {
			t.Fatal("expected error for oversized content, got nil")
		}
		if err != assist.ErrRequestTooLarge {
			t.Errorf("expected ErrRequestTooLarge, got %v", err)
		}
	})

	t.Run("invalid_role", func(t *testing.T) {
		err := assist.Validate(assist.Request{
			Messages: []assist.Message{{Role: "admin", Content: "hello"}},
		})
		if err == nil {
			t.Fatal("expected error for invalid role, got nil")
		}
		if err != assist.ErrInvalidRole {
			t.Errorf("expected ErrInvalidRole, got %v", err)
		}
	})

	t.Run("valid_roles", func(t *testing.T) {
		for _, role := range []string{"system", "user", "assistant"} {
			err := assist.Validate(assist.Request{
				Messages: []assist.Message{{Role: role, Content: "hello"}},
			})
			if err != nil {
				t.Errorf("role %q: expected nil, got %v", role, err)
			}
		}
	})

	t.Run("valid_request", func(t *testing.T) {
		err := assist.Validate(assist.Request{
			Messages: []assist.Message{{Role: "user", Content: "Tell me a joke"}},
			Context:  "compose",
			Locale:   "en",
		})
		if err != nil {
			t.Errorf("expected nil for valid request, got %v", err)
		}
	})
}
