package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// Config holds the configuration for an OpenAI-compatible provider.
// It is intentionally simple — no secrets are logged or embedded in error messages.
type Config struct {
	// BaseURL is the provider endpoint root, e.g. "https://api.openai.com/v1"
	// or "http://localhost:11434/v1" (Ollama).
	BaseURL string

	// Model is the model name to send in the request body.
	Model string

	// APIKey is sent as "Bearer <APIKey>" in the Authorization header.
	// May be empty for local deployments that do not require auth.
	APIKey string

	// HTTPClient is used for all outbound requests. When nil, a client with a
	// 30s timeout is used. Tests inject a *httptest.Server client here.
	HTTPClient *http.Client
}

// OpenAICompatible is an implementation of Provider that talks to any
// OpenAI-compatible chat/completions endpoint (OpenAI, Ollama, vLLM, LM Studio,
// Azure OpenAI in OpenAI-compat mode, etc.).
type OpenAICompatible struct {
	cfg    Config
	client *http.Client
}

// NewOpenAICompatible constructs an OpenAICompatible provider.
func NewOpenAICompatible(cfg Config) *OpenAICompatible {
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &OpenAICompatible{cfg: cfg, client: c}
}

// MaxResponseBytes bounds how many bytes of an AI-assist provider response this
// package will buffer before JSON decoding (resource-exhaustion closure,
// occ_7bfd6e7db92c85e0c8eb9111). The provider endpoint is admin-configured but
// its responses are untrusted input to this process: an unbounded decode lets a
// hostile or misconfigured upstream (or a hijacked DNS answer for its host)
// exhaust gateway memory with an endless body. The 1 MiB cap mirrors the
// repo's admin-config request precedent (mailserver/internal/admin/
// admin_config.go:225); a legitimate chat/completions reply for this product's
// bounded prompts sits far below it, and a reply past the cap is refused
// without surfacing the upstream body to callers.
const MaxResponseBytes = 1 << 20

// chatRequest is the JSON body sent to the /chat/completions endpoint.
type chatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// chatResponse is the JSON body returned by the /chat/completions endpoint.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// Complete posts Request to {BaseURL}/chat/completions and returns the
// assistant's reply. Context cancellation is respected. Non-200 responses
// surface as ErrUpstreamFailed without leaking the upstream body to callers.
func (p *OpenAICompatible) Complete(ctx context.Context, req Request) (Response, error) {
	msgs := buildMessages(req)

	body := chatRequest{
		Model:    p.cfg.Model,
		Messages: msgs,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return Response{}, fmt.Errorf("assist: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.cfg.BaseURL+"/chat/completions",
		bytes.NewReader(payload),
	)
	if err != nil {
		return Response{}, fmt.Errorf("assist: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.cfg.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}

	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("assist: upstream request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		// Drain and discard — never surface upstream body to callers.
		_, _ = io.Copy(io.Discard, httpResp.Body)
		return Response{}, fmt.Errorf("%w: status %d", ErrUpstreamFailed, httpResp.StatusCode)
	}

	// Read the response under a hard byte bound BEFORE decoding: the decoder
	// alone would happily buffer an arbitrarily large provider body. Reading
	// MaxResponseBytes+1 bytes distinguishes an over-cap body (refuse) from an
	// at-cap body (decode).
	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, MaxResponseBytes+1))
	if err != nil {
		return Response{}, fmt.Errorf("assist: read response: %w", err)
	}
	if len(raw) > MaxResponseBytes {
		return Response{}, fmt.Errorf("assist: upstream response exceeds %d byte bound", MaxResponseBytes)
	}

	var cr chatResponse
	if err := json.Unmarshal(raw, &cr); err != nil {
		return Response{}, fmt.Errorf("assist: decode response: %w", err)
	}

	if len(cr.Choices) == 0 {
		return Response{}, fmt.Errorf("assist: upstream returned no choices")
	}

	return Response{Content: cr.Choices[0].Message.Content}, nil
}

// buildMessages constructs the messages slice to send to the API.
// If req.Context is set, it is prepended as the only system message; likewise
// req.Locale is appended to that system message when present.
//
// Prompt-privilege hardening (GO-ASSIST-PROMPT-PRIVILEGE-CONFUSION): the
// caller never speaks at system tier. A client-declared "system" message is
// downgraded to "user", reserving the highest prompt tier for the
// server-constructed preamble; Context/Locale are control-character-stripped
// so client text cannot forge additional lines inside that preamble.
func buildMessages(req Request) []Message {
	var msgs []Message

	if req.Context != "" {
		system := "Context: " + sanitizePreamble(req.Context)
		if req.Locale != "" {
			system += ". Respond in locale: " + sanitizePreamble(req.Locale)
		}
		msgs = append(msgs, Message{Role: "system", Content: system})
	}

	for _, m := range req.Messages {
		if m.Role == "system" {
			m.Role = "user"
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// sanitizePreamble replaces control characters (including CR/LF) with spaces
// so caller-controlled Context/Locale text cannot introduce additional lines
// — or message-boundary structure — inside the synthesized system preamble.
func sanitizePreamble(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
