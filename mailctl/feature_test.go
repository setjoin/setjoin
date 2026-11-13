package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func featureTestContext(server *httptest.Server) *cmdCtx {
	return &cmdCtx{client: &Client{Server: server.URL, HTTP: server.Client()}}
}

func TestFeatureSetConfirmationComesFromExactAPIMetadata(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/admin/features":
			_, _ = io.WriteString(w, `[{"key":"feature.user_risk","confirmationRequired":true}]`)
		case r.Method == http.MethodPut:
			puts++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	oldStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = oldStdin })
	_, _ = io.WriteString(writer, "no\n")
	_ = writer.Close()

	err = featureSetCmd(featureTestContext(server), []string{"feature.user_risk", "on"})
	if err == nil || !strings.Contains(err.Error(), "cancelled") || puts != 0 {
		t.Fatalf("err=%v puts=%d, want metadata-driven cancellation before PUT", err, puts)
	}
}

func TestFeatureSetUnknownExactKeyDoesNotMutate(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `[{"key":"feature.user_risk","confirmationRequired":true}]`)
			return
		}
		puts++
	}))
	defer server.Close()

	err := featureSetCmd(featureTestContext(server), []string{"feature.future_security_gate", "on"})
	if err == nil || !strings.Contains(err.Error(), `no feature toggle found with key "feature.future_security_gate"`) || puts != 0 {
		t.Fatalf("err=%v puts=%d, want exact-key fail-closed refusal", err, puts)
	}
}

func TestFeatureSetDoesNotSubstringGuessOrWarnWithoutMetadata(t *testing.T) {
	var gets, puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			gets++
			_, _ = io.WriteString(w, `[{"key":"feature.not_conditional_access_clone"}]`)
		case http.MethodPut:
			puts++
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	if err := featureSetCmd(featureTestContext(server), []string{"feature.not_conditional_access_clone", "off"}); err != nil {
		t.Fatal(err)
	}
	if gets != 1 || puts != 1 {
		t.Fatalf("GET metadata=%d PUT=%d, want one each", gets, puts)
	}
}

func TestFeatureSetFailsBeforeMutationWhenMetadataCannotBeRead(t *testing.T) {
	var puts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		puts++
	}))
	defer server.Close()

	err := featureSetCmd(featureTestContext(server), []string{"feature.imap", "off"})
	if err == nil || puts != 0 {
		t.Fatalf("err=%v puts=%d, want fail-closed metadata read", err, puts)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusServiceUnavailable {
		t.Fatalf("err=%T(%v), want typed 503", err, err)
	}
}
