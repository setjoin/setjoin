package smtp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func skipWithoutIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("skipping integration test; set INTEGRATION=1 to run")
	}
}

// TestSandboxPipelineIntegration tests a full pipeline with stubbed CAPE returning
// a malicious score for a PDF-carrying MIME message.
func TestSandboxPipelineIntegration(t *testing.T) {
	skipWithoutIntegration(t)

	// Stub CAPE returns score 9.5 (malicious) for any submission
	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task_id":1}`))
	})
	mux.HandleFunc("/apiv2/tasks/view/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task":{"status":"reported","id":1},"info":{"score":9.5,"signatures":["Trojan.Generic"]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	pipeline := NewAttachmentAnalysisPipeline(
		[]SandboxAnalyzer{cape}, 30*time.Second, FailOpen, slog.Default(),
	)

	// PDF-carrying MIME message
	msg := []byte(
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"Body text\r\n" +
			"--b\r\n" +
			"Content-Type: application/pdf\r\n" +
			"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n" +
			"\r\n" +
			"%PDF-1.4 fake content\r\n" +
			"--b--",
	)

	verdict := pipeline.Analyze(context.Background(), msg)
	if verdict.Severity != SandboxMalicious {
		t.Errorf("severity = %d, want SandboxMalicious", verdict.Severity)
	}
}

// TestSandboxPipelineCleanAttachment tests that a clean file returns clean verdict.
func TestSandboxPipelineCleanAttachment(t *testing.T) {
	skipWithoutIntegration(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task_id":2}`))
	})
	mux.HandleFunc("/apiv2/tasks/view/2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task":{"status":"reported","id":2},"info":{"score":0.0}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	pipeline := NewAttachmentAnalysisPipeline(
		[]SandboxAnalyzer{cape}, 30*time.Second, FailOpen, slog.Default(),
	)

	msg := []byte(
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: application/pdf\r\n" +
			"\r\n" +
			"%PDF-1.4 clean pdf\r\n" +
			"--b--",
	)

	verdict := pipeline.Analyze(context.Background(), msg)
	if verdict.Severity != SandboxClean {
		t.Errorf("severity = %d, want SandboxClean", verdict.Severity)
	}
}

// TestSandboxFailClosedBlocksDelivery tests that fail-closed returns malicious
// when the analyzer errors.
func TestSandboxFailClosedBlocksDelivery(t *testing.T) {
	skipWithoutIntegration(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal server error"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	pipeline := NewAttachmentAnalysisPipeline(
		[]SandboxAnalyzer{cape}, 30*time.Second, FailClosed, slog.Default(),
	)

	msg := []byte(
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: application/pdf\r\n" +
			"\r\n" +
			"%PDF-1.4 content\r\n" +
			"--b--",
	)

	verdict := pipeline.Analyze(context.Background(), msg)
	if verdict.Severity != SandboxMalicious {
		t.Errorf("severity = %d, want SandboxMalicious (fail-closed)", verdict.Severity)
	}
}

// TestPipelineWithMultipleAnalyzers tests aggregating suspicious results.
func TestPipelineWithMultipleAnalyzers(t *testing.T) {
	skipWithoutIntegration(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task_id":3}`))
	})
	mux.HandleFunc("/apiv2/tasks/view/3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task":{"status":"reported","id":3},"info":{"score":4.5,"signatures":["SuspiciousBehavior"]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	pipeline := NewAttachmentAnalysisPipeline(
		[]SandboxAnalyzer{cape}, 30*time.Second, FailOpen, slog.Default(),
	)

	msg := []byte(
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: application/x-msdownload\r\n" +
			"\r\n" +
			"binary content\r\n" +
			"--b--",
	)

	verdict := pipeline.Analyze(context.Background(), msg)
	if verdict.Severity != SandboxSuspicious {
		t.Errorf("severity = %d, want SandboxSuspicious", verdict.Severity)
	}
	if verdict.Score != 4.5 {
		t.Errorf("score = %f, want 4.5", verdict.Score)
	}
}
