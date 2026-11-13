package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestAPIPathCanonicalizesUnpinnedRoutesAndPreservesQuery(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"/admin/users":             "/api/admin/users",
		"/admin/audit/csv?from=10": "/api/admin/audit/csv?from=10",
		"/api/admin/users":         "/api/admin/users",
		"/health?verbose=true":     "/health?verbose=true",
		"/rtc/token?room=test":     "/rtc/token?room=test",
		"/favicon.ico?v=1":         "/favicon.ico?v=1",
	}
	for input, want := range cases {
		if got := apiPath(input); got != want {
			t.Errorf("apiPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRawStreamUsesCanonicalAPIPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RequestURI() != "/api/admin/audit/csv?from=10" {
			t.Errorf("raw stream URI = %q, want canonical API URI", r.URL.RequestURI())
		}
		_, _ = io.WriteString(w, "id,action\n10,export\n")
	}))
	defer srv.Close()

	var out bytes.Buffer
	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	err := cl.rawStream("/admin/audit/csv?from=10", func() (io.Writer, error) {
		return &out, nil
	}, nil)
	if err != nil {
		t.Fatalf("rawStream: %v", err)
	}
	if got, want := out.String(), "id,action\n10,export\n"; got != want {
		t.Fatalf("rawStream body = %q, want %q", got, want)
	}
}

func TestDoDecodesRFC7807APIError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.Header().Set("Retry-After", "17")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{
			"type":"https://setjoin.com/problems/identity/preview-stale",
			"title":"Conflict",
			"status":400,
			"detail":"Preview changed",
			"instance":"/api/admin/identity/v2/transitions/execute",
			"code":"BZ234",
			"retryable":false,
			"remediation":"Generate a new preview."
		}`)
	}))
	defer srv.Close()

	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	err := cl.Do(http.MethodPost, "/admin/identity/v2/transitions/execute", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("Do error = %T(%v), want *APIError", err, err)
	}
	if apiErr.Status != http.StatusConflict {
		t.Fatalf("Status = %d, want actual HTTP status %d", apiErr.Status, http.StatusConflict)
	}
	if apiErr.Type != "https://setjoin.com/problems/identity/preview-stale" ||
		apiErr.Code != "BZ234" || apiErr.Detail != "Preview changed" ||
		apiErr.Instance != "/api/admin/identity/v2/transitions/execute" ||
		apiErr.Retryable == nil || *apiErr.Retryable ||
		apiErr.Remediation != "Generate a new preview." || apiErr.RetryAfter != "17" {
		t.Fatalf("decoded APIError = %#v", apiErr)
	}
}

func TestRawStreamDecodesAPIErrorWithoutCreatingOutput(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"status":403,"detail":"permission denied"}`)
	}))
	defer srv.Close()

	called := false
	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	err := cl.rawStream("/admin/audit/csv", func() (io.Writer, error) {
		called = true
		return io.Discard, nil
	}, nil)
	if called {
		t.Fatal("rawStream created output before confirming success")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden ||
		apiErr.Detail != "permission denied" {
		t.Fatalf("rawStream error = %T(%v), want typed 403 APIError", err, err)
	}
}

func TestDoBoundsMalformedProblemBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxAPIErrorBody+1))
	}))
	defer srv.Close()

	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	err := cl.Do(http.MethodGet, "/admin/users", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadGateway ||
		apiErr.Detail != "problem response exceeded the 1 MiB client limit" {
		t.Fatalf("bounded error = %T(%v), want typed oversize APIError", err, err)
	}
}

func TestDoBoundedRejectsOversizedSuccessBeforeDecode(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"items":[1,2,3]}`)
	}))
	defer srv.Close()

	cl := &Client{Server: srv.URL, HTTP: srv.Client()}
	var result map[string]any
	err := cl.DoBounded(http.MethodGet, "/admin/identity/v2/sources", nil, &result, 8)
	if err == nil || err.Error() != "response exceeded the 8-byte client limit" {
		t.Fatalf("DoBounded error = %v, want exact limit failure", err)
	}
	if result != nil {
		t.Fatalf("oversized response partially decoded: %#v", result)
	}
}

func TestDoWithReasonRestoresPriorReason(t *testing.T) {
	t.Parallel()

	var reasons []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reasons = append(reasons, r.Header.Get("X-Audit-Reason"))
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	cl := &Client{Server: srv.URL, HTTP: srv.Client(), Reason: "session reason"}
	if err := cl.DoWithReason(http.MethodGet, "/admin/users", "one-shot reason", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := cl.Do(http.MethodGet, "/admin/users", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reasons, ","); got != "one-shot reason,session reason" {
		t.Fatalf("audit reasons = %q", got)
	}
}

func TestDoRawWithHeadersBoundedPreservesOpaqueBodyAndMutationHeaders(t *testing.T) {
	t.Parallel()

	secret := []byte{0x00, 's', 'e', 'c', 'r', 'e', 't', 0xff}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/admin/identity/v2/sources/corp/secrets/clientSecret" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := r.Header.Get("If-Match"); got != `"7"` {
			t.Fatalf("If-Match = %q", got)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("opaque body changed: %x", got)
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	var result struct {
		OK bool `json:"ok"`
	}
	headers := make(http.Header)
	headers.Set("If-Match", `"7"`)
	err := (&Client{Server: srv.URL, HTTP: srv.Client()}).DoRawWithHeadersBounded(
		http.MethodPut,
		"/admin/identity/v2/sources/corp/secrets/clientSecret",
		"application/octet-stream",
		headers,
		bytes.NewReader(secret),
		&result,
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK {
		t.Fatal("bounded raw response was not decoded")
	}
}

func TestAPIErrorFormattingAndFallbacks(t *testing.T) {
	var nilError *APIError
	if nilError.Error() != "" {
		t.Fatalf("nil APIError string=%q, want empty", nilError.Error())
	}
	err := (&APIError{
		Status:      http.StatusTooManyRequests,
		Type:        "urn:setjoin:rate\nlimit",
		Remediation: "wait\nand retry",
		RetryAfter:  "17\nseconds",
	}).Error()
	for _, want := range []string{
		"HTTP 429", "urn:setjoin:rate limit",
		"remediation: wait and retry", "retry after: 17 seconds",
	} {
		if !strings.Contains(err, want) {
			t.Fatalf("formatted API error %q missing %q", err, want)
		}
	}

	readFailure := errors.New("read failed")
	got := decodeAPIError(&http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(failingReader{err: readFailure}),
		Header:     make(http.Header),
	})
	if !errors.Is(got, readFailure) {
		t.Fatalf("problem-body read error=%v, want wrapped read failure", got)
	}
	got = decodeAPIError(&http.Response{
		StatusCode: http.StatusTeapot,
		Body:       io.NopCloser(strings.NewReader(" \n\t")),
		Header:     make(http.Header),
	})
	apiErr, ok := asAPIError(got)
	if !ok || apiErr.Detail != http.StatusText(http.StatusTeapot) {
		t.Fatalf("empty problem fallback=%#v, %v", apiErr, got)
	}
	if _, ok := asAPIError(errors.New("plain")); ok {
		t.Fatal("plain error unexpectedly classified as APIError")
	}
}

func TestBoundedClientFailureMatrix(t *testing.T) {
	readFailure := errors.New("read failed")
	base := &Client{Server: "http://example.test"}
	if err := base.DoBounded(http.MethodGet, "/x", nil, nil, 0); err == nil {
		t.Fatal("DoBounded accepted a non-positive limit")
	}
	if err := base.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, nil, 0,
	); err == nil {
		t.Fatal("DoRawWithHeadersBounded accepted a non-positive limit")
	}

	badURL := &Client{Server: "://bad", HTTP: http.DefaultClient}
	if err := badURL.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, nil, 8,
	); err == nil || !strings.Contains(err.Error(), "request:") {
		t.Fatalf("raw invalid URL error=%v", err)
	}

	transportFailure := errors.New("transport failed")
	failedHTTP := &http.Client{Transport: roundTripFunc(
		func(*http.Request) (*http.Response, error) {
			return nil, transportFailure
		},
	)}
	cl := &Client{
		Server: "http://example.test", AuthToken: "token", HTTP: failedHTTP,
	}
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, nil, 8,
	); !errors.Is(err, transportFailure) {
		t.Fatalf("raw transport error=%v", err)
	}

	response := func(status int, body io.Reader) *http.Client {
		return &http.Client{Transport: roundTripFunc(
			func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Authorization") != "Bearer token" {
					return nil, fmt.Errorf("missing bearer token")
				}
				return &http.Response{
					StatusCode: status,
					Header:     make(http.Header),
					Body:       io.NopCloser(body),
					Request:    req,
				}, nil
			},
		)}
	}

	cl.HTTP = response(http.StatusBadRequest, strings.NewReader(`{"detail":"bad"}`))
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, nil, 8,
	); err == nil {
		t.Fatal("raw HTTP error unexpectedly succeeded")
	}
	cl.HTTP = response(http.StatusNoContent, strings.NewReader(""))
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, nil, 8,
	); err != nil {
		t.Fatalf("nil-result raw request: %v", err)
	}
	cl.HTTP = response(http.StatusOK, failingReader{err: readFailure})
	var result map[string]any
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, &result, 8,
	); !errors.Is(err, readFailure) {
		t.Fatalf("raw response read error=%v", err)
	}
	cl.HTTP = response(http.StatusOK, strings.NewReader(`{"too":"large"}`))
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, &result, 4,
	); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("raw oversize error=%v", err)
	}
	cl.HTTP = response(http.StatusOK, strings.NewReader(`{`))
	if err := cl.DoRawWithHeadersBounded(
		http.MethodPost, "/x", "application/octet-stream", nil,
		http.NoBody, &result, 8,
	); err == nil {
		t.Fatal("raw malformed JSON unexpectedly decoded")
	}

	cl.HTTP = response(http.StatusOK, failingReader{err: readFailure})
	if err := cl.DoBounded(
		http.MethodGet, "/x", nil, &result, 8,
	); !errors.Is(err, readFailure) {
		t.Fatalf("bounded response read error=%v", err)
	}
	cl.HTTP = response(http.StatusOK, strings.NewReader(`{`))
	if err := cl.DoBounded(
		http.MethodGet, "/x", nil, &result, 8,
	); err == nil {
		t.Fatal("bounded malformed JSON unexpectedly decoded")
	}
}
