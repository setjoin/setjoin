package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const maxAPIErrorBody = 1 << 20

// APIError is the typed RFC 7807 error returned by the Setjoin HTTP APIs.
// Status is always the actual HTTP response status; a mismatched or omitted
// status in the response body cannot change client control flow.
type APIError struct {
	Status      int    `json:"status"`
	Type        string `json:"type,omitempty"`
	Code        string `json:"code,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Instance    string `json:"instance,omitempty"`
	Retryable   *bool  `json:"retryable,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	RetryAfter  string `json:"retryAfter,omitempty"`
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d", e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " %s", e.Code)
	}
	if e.Detail != "" {
		fmt.Fprintf(&b, ": %s", oneLine(e.Detail))
	} else if e.Type != "" {
		fmt.Fprintf(&b, ": %s", oneLine(e.Type))
	}
	if e.Remediation != "" {
		fmt.Fprintf(&b, " (remediation: %s)", oneLine(e.Remediation))
	}
	if e.RetryAfter != "" {
		fmt.Fprintf(&b, " (retry after: %s)", oneLine(e.RetryAfter))
	}
	return b.String()
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func decodeAPIError(resp *http.Response) error {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxAPIErrorBody+1))
	if readErr != nil {
		return fmt.Errorf("HTTP %d: read problem response: %w", resp.StatusCode, readErr)
	}
	if len(body) > maxAPIErrorBody {
		return &APIError{
			Status: resp.StatusCode,
			Detail: "problem response exceeded the 1 MiB client limit",
		}
	}

	apiErr := &APIError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
	var wire struct {
		Type        string `json:"type"`
		Code        string `json:"code"`
		Detail      string `json:"detail"`
		Instance    string `json:"instance"`
		Retryable   *bool  `json:"retryable"`
		Remediation string `json:"remediation"`
		RetryAfter  string `json:"retryAfter"`
	}
	if len(bytes.TrimSpace(body)) != 0 {
		if err := json.Unmarshal(body, &wire); err != nil {
			apiErr.Detail = oneLine(string(body))
			if apiErr.Detail == "" {
				apiErr.Detail = http.StatusText(resp.StatusCode)
			}
			return apiErr
		}
		apiErr.Type = wire.Type
		apiErr.Code = wire.Code
		apiErr.Detail = wire.Detail
		apiErr.Instance = wire.Instance
		apiErr.Retryable = wire.Retryable
		apiErr.Remediation = wire.Remediation
		if apiErr.RetryAfter == "" {
			apiErr.RetryAfter = wire.RetryAfter
		}
	}
	if apiErr.Detail == "" {
		apiErr.Detail = http.StatusText(resp.StatusCode)
	}
	return apiErr
}

func asAPIError(err error) (*APIError, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return nil, false
	}
	return apiErr, true
}

// Client wraps the mailserver REST API.
type Client struct {
	Server    string
	AuthToken string
	HTTP      *http.Client

	// Reason, when non-empty, is sent as the X-Audit-Reason header on every
	// request Do makes. Role mutations require it (they 400 in audit-hardened
	// deployments). Set it directly for the lifetime of the client, or use
	// DoWithReason for a one-shot that restores the previous value.
	Reason string
}

// DoWithReason performs a request with a one-shot X-Audit-Reason header,
// restoring the client's prior Reason afterward. Role grant/revoke require an
// audit reason; other callers may keep using Do.
func (c *Client) DoWithReason(method, path, reason string, body, result interface{}) error {
	return c.withReason(reason, func() error {
		return c.Do(method, path, body, result)
	})
}

// DoWithReasonBounded is DoBounded with a one-shot audit reason.
func (c *Client) DoWithReasonBounded(method, path, reason string, body, result interface{}, maxBytes int64) error {
	return c.withReason(reason, func() error {
		return c.DoBounded(method, path, body, result, maxBytes)
	})
}

func (c *Client) withReason(reason string, request func() error) error {
	prev := c.Reason
	c.Reason = reason
	defer func() { c.Reason = prev }()
	return request()
}

// NewClient creates a client from config or env vars.
func NewClient(cfg *Config) *Client {
	token := cfg.Auth.Token
	if token == "" {
		token = cfg.Auth.APIKey
	}
	server := cfg.Server
	if s := os.Getenv("MAILCTL_SERVER"); s != "" {
		server = s
	}
	if t := os.Getenv("MAILCTL_API_KEY"); t != "" {
		token = t
	}
	if t := os.Getenv("MAILCTL_TOKEN"); t != "" {
		token = t
	}
	return &Client{
		Server:    server,
		AuthToken: token,
		HTTP:      &http.Client{},
	}
}

// apiPinnedPrefixes mirrors the gateway's pinned root surfaces
// (scripts/api-pinned-prefixes.txt): every other path is JSON API served
// canonically under /api, so Do injects the prefix at this single seam
// instead of editing ~90 call sites.
var apiPinnedPrefixes = []string{
	"/auth", "/jmap", "/.well-known", "/caldav", "/carddav", "/scim", "/rtc",
	"/setup", "/approvals/email", "/link-protect", "/admin/migration/m365",
	"/updates", "/downloads", "/health", "/ready", "/metrics", "/api", "/terms", "/favicon.ico",
}

func apiPath(path string) string {
	pathOnly := path
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	for _, p := range apiPinnedPrefixes {
		if pathOnly == p || strings.HasPrefix(pathOnly, p+"/") {
			return path
		}
	}
	return "/api" + path
}

// rawStream issues a GET to path and streams the raw response body through to
// a writer — no decode/re-encode, so the server's on-wire formatting round-trips
// byte for byte (used by `ca export` and `audit export`). newWriter is called
// to obtain the destination ONLY after the response status is confirmed OK, so
// a failed request never creates/truncates an output file. wrapWriteErr, if
// non-nil, wraps a failure from the final copy (e.g. disk-full) into a
// caller-specific message; every other error is returned as built here
// (request/http/status), matching each caller's prior wrapping exactly.
func (cl *Client) rawStream(path string, newWriter func() (io.Writer, error), wrapWriteErr func(error) error) error {
	path = apiPath(path)
	req, err := http.NewRequest(http.MethodGet, cl.Server+path, nil)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if cl.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+cl.AuthToken)
	}
	if cl.Reason != "" {
		req.Header.Set("X-Audit-Reason", cl.Reason)
	}
	resp, err := cl.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}
	w, err := newWriter()
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		if wrapWriteErr != nil {
			return wrapWriteErr(err)
		}
		return err
	}
	return nil
}

// Do performs an authenticated request and unmarshals the JSON response.
// Non-pinned paths are rewritten to their canonical /api form (see apiPath).
func (c *Client) Do(method, path string, body interface{}, result interface{}) error {
	return c.do(method, path, body, result, 0)
}

// DoBounded performs Do but rejects a successful JSON response larger than
// maxBytes before unmarshalling it. Streaming endpoints must continue to use
// rawStream instead.
func (c *Client) DoBounded(method, path string, body interface{}, result interface{}, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("response limit must be positive")
	}
	return c.do(method, path, body, result, maxBytes)
}

// DoRawWithHeadersBounded sends caller-owned bytes with an explicit content
// type and headers, then decodes one bounded JSON response. It is used by
// identity source secret commands so credential bytes never enter a JSON
// value, argv, environment, or formatted diagnostic.
func (c *Client) DoRawWithHeadersBounded(
	method, path, contentType string,
	headers http.Header,
	body io.Reader,
	result interface{},
	maxBytes int64,
) error {
	if maxBytes <= 0 {
		return fmt.Errorf("response limit must be positive")
	}
	path = apiPath(path)
	req, err := http.NewRequest(method, c.Server+path, body)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}
	if result == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("response exceeded the %d-byte client limit", maxBytes)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return err
	}
	return nil
}

func (c *Client) do(method, path string, body interface{}, result interface{}, maxBytes int64) error {
	path = apiPath(path)
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, c.Server+path, bodyReader)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}
	if c.Reason != "" {
		req.Header.Set("X-Audit-Reason", c.Reason)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}

	if result != nil {
		if maxBytes > 0 {
			raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
			if err != nil {
				return fmt.Errorf("read response: %w", err)
			}
			if int64(len(raw)) > maxBytes {
				return fmt.Errorf("response exceeded the %d-byte client limit", maxBytes)
			}
			if err := json.Unmarshal(raw, result); err != nil {
				return err
			}
			return nil
		}
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}
