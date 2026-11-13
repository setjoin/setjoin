// Package assist provides a shared AI assist provider abstraction consumed by
// the mailserver gateway. The Provider interface targets OpenAI-compatible
// chat-completions APIs (Ollama, vLLM, LM Studio, hosted endpoints).
//
// No business logic or SQL lives here — only contracts, envelope types, and the
// OpenAI-compatible HTTP adapter. (shared/AGENTS.md: "No business logic here.")
package assist

import (
	"context"
	"errors"
)

// Sentinel errors returned by Validate and providers.
var (
	// ErrEmptyMessages is returned when Request.Messages is empty.
	ErrEmptyMessages = errors.New("assist: messages must not be empty")

	// ErrRequestTooLarge is returned when total content exceeds MaxRequestBytes.
	ErrRequestTooLarge = errors.New("assist: request content exceeds size limit")

	// ErrInvalidRole is returned when a message has an unrecognised role.
	// Allowed roles: "system", "user", "assistant".
	ErrInvalidRole = errors.New("assist: message role must be system, user, or assistant")

	// ErrUpstreamFailed is returned when the upstream provider returns a non-200 status.
	ErrUpstreamFailed = errors.New("assist: upstream provider returned an error")
)

// MaxRequestBytes is the default total content byte cap enforced by Validate.
// 512 KiB is generous for compose-assist but prevents abuse.
const MaxRequestBytes = 512 * 1024

// Message is one turn in the conversation.
type Message struct {
	Role    string `json:"role"`    // system | user | assistant
	Content string `json:"content"` // non-empty text
}

// Request is the inbound envelope from the client.
type Request struct {
	Messages []Message `json:"messages"`
	// Context is an optional short string describing the compose context
	// (e.g. "compose", "reply"). Folded into a leading system message.
	Context string `json:"context,omitempty"`
	// Locale is the user's preferred locale (BCP-47). Passed to the model
	// as part of a system message when set.
	Locale string `json:"locale,omitempty"`
}

// Response is the outbound envelope to the client.
type Response struct {
	Content string `json:"content"`
}

// Provider is the shared AI assist abstraction. Each server that wants AI
// capabilities instantiates one; the interface keeps handler code DB-free.
type Provider interface {
	// Complete sends Request to the model and returns the full response.
	Complete(ctx context.Context, req Request) (Response, error)
}

// validRoles is the set of allowed message roles.
var validRoles = map[string]bool{
	"system":    true,
	"user":      true,
	"assistant": true,
}

// Validate checks the request envelope for correctness before forwarding to a
// provider. It is intentionally stateless and allocation-light.
//
// Rules:
//   - Messages must not be empty (ErrEmptyMessages).
//   - Each message Content must be non-empty (ErrEmptyMessages reused for simplicity;
//     callers see "assist: messages must not be empty" — adequate for clients).
//   - Total content bytes must not exceed MaxRequestBytes (ErrRequestTooLarge).
//   - Each message Role must be one of system | user | assistant (ErrInvalidRole).
func Validate(req Request) error {
	if len(req.Messages) == 0 {
		return ErrEmptyMessages
	}

	var total int
	for _, m := range req.Messages {
		if m.Content == "" {
			return ErrEmptyMessages
		}
		if !validRoles[m.Role] {
			return ErrInvalidRole
		}
		total += len(m.Content)
	}
	// Include Context in the byte budget (it becomes a system message).
	total += len(req.Context)

	if total > MaxRequestBytes {
		return ErrRequestTooLarge
	}

	return nil
}
