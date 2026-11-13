package smtp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// stubSandboxAnalyzer implements SandboxAnalyzer for testing.
type stubSandboxAnalyzer struct {
	name      string
	verdict   *SandboxVerdict
	err       error
	onAnalyze func(ctx context.Context, data []byte)
}

func (s *stubSandboxAnalyzer) Name() string { return s.name }
func (s *stubSandboxAnalyzer) Analyze(ctx context.Context, data []byte) (*SandboxVerdict, error) {
	if s.onAnalyze != nil {
		s.onAnalyze(ctx, data)
	}
	return s.verdict, s.err
}
func (s *stubSandboxAnalyzer) HealthCheck(ctx context.Context) error { return nil }

func TestSandboxVerdictConstants(t *testing.T) {
	if SandboxClean != 0 {
		t.Errorf("SandboxClean = %d, want 0", SandboxClean)
	}
	if SandboxMalicious != 2 {
		t.Errorf("SandboxMalicious = %d, want 2", SandboxMalicious)
	}
}

func TestFailModeConstants(t *testing.T) {
	if FailOpen != "open" {
		t.Errorf("FailOpen = %q, want %q", FailOpen, "open")
	}
	if FailClosed != "closed" {
		t.Errorf("FailClosed = %q, want %q", FailClosed, "closed")
	}
}

func TestPipelineAggregateFirstMalicious(t *testing.T) {
	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "a", verdict: &SandboxVerdict{Severity: SandboxSuspicious, Score: 5.0}},
		&stubSandboxAnalyzer{name: "b", verdict: &SandboxVerdict{Severity: SandboxMalicious, Score: 9.0, VirusName: "Trojan.X"}},
		&stubSandboxAnalyzer{name: "c", verdict: &SandboxVerdict{Severity: SandboxClean, Score: 0}},
	}, 10*time.Second, FailOpen, slog.Default())

	verdict := p.Analyze(context.Background(), []byte("test"))
	if verdict.Severity != SandboxMalicious {
		t.Errorf("severity = %d, want SandboxMalicious (%d)", verdict.Severity, SandboxMalicious)
	}
	if verdict.VirusName != "Trojan.X" {
		t.Errorf("virusName = %q, want %q", verdict.VirusName, "Trojan.X")
	}
}

func TestPipelineShortCircuitsAfterMalicious(t *testing.T) {
	called := false
	tracker := &stubSandboxAnalyzer{
		name:    "tracker",
		verdict: &SandboxVerdict{Severity: SandboxClean},
		onAnalyze: func(ctx context.Context, data []byte) {
			called = true
		},
	}

	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "mal", verdict: &SandboxVerdict{Severity: SandboxMalicious, Score: 9.0}},
		tracker,
	}, 10*time.Second, FailOpen, slog.Default())

	p.Analyze(context.Background(), []byte("test"))
	if called {
		t.Error("short-circuit failed: analyzer after malicious was still called")
	}
}

func TestPipelineAllSuspiciousAggregates(t *testing.T) {
	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "a", verdict: &SandboxVerdict{Severity: SandboxSuspicious, Score: 5.0, Behaviors: []string{"macro"}}},
		&stubSandboxAnalyzer{name: "b", verdict: &SandboxVerdict{Severity: SandboxSuspicious, Score: 6.0, Behaviors: []string{"network"}}},
	}, 10*time.Second, FailOpen, slog.Default())

	verdict := p.Analyze(context.Background(), []byte("test"))
	if verdict.Severity != SandboxSuspicious {
		t.Errorf("severity = %d, want SandboxSuspicious (%d)", verdict.Severity, SandboxSuspicious)
	}
	if verdict.Score != 6.0 {
		t.Errorf("score = %f, want 6.0", verdict.Score)
	}
	if len(verdict.Behaviors) != 2 {
		t.Errorf("behaviors count = %d, want 2", len(verdict.Behaviors))
	}
}

func TestPipelineAnalyzerErrorFailOpen(t *testing.T) {
	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "err-analyzer", err: errors.New("down")},
		&stubSandboxAnalyzer{name: "clean", verdict: &SandboxVerdict{Severity: SandboxClean}},
	}, 10*time.Second, FailOpen, slog.Default())

	verdict := p.Analyze(context.Background(), []byte("test"))
	if verdict.Severity != SandboxClean {
		t.Errorf("severity = %d, want SandboxClean (%d)", verdict.Severity, SandboxClean)
	}
}

func TestPipelineAnalyzerErrorFailClosed(t *testing.T) {
	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "err-analyzer", err: errors.New("down")},
	}, 10*time.Second, FailClosed, slog.Default())

	verdict := p.Analyze(context.Background(), []byte("test"))
	if verdict.Severity != SandboxMalicious {
		t.Errorf("severity = %d, want SandboxMalicious (%d)", verdict.Severity, SandboxMalicious)
	}
}

func TestPipelineNoAnalyzers(t *testing.T) {
	p := NewAttachmentAnalysisPipeline(nil, 10*time.Second, FailOpen, slog.Default())
	verdict := p.Analyze(context.Background(), []byte("test"))
	if verdict.Severity != SandboxClean {
		t.Errorf("severity = %d, want SandboxClean (%d)", verdict.Severity, SandboxClean)
	}
}

func TestPipelineLen(t *testing.T) {
	p := NewAttachmentAnalysisPipeline([]SandboxAnalyzer{
		&stubSandboxAnalyzer{name: "a"},
		&stubSandboxAnalyzer{name: "b"},
	}, 10*time.Second, FailOpen, slog.Default())
	if p.Len() != 2 {
		t.Errorf("Len() = %d, want 2", p.Len())
	}
}

// ── CAPE Analyzer Tests ──────────────────────────────────────────────────────

func TestCAPEAnalyzerName(t *testing.T) {
	cape := NewCAPEAnalyzer("http://localhost:8090", "test-key", 30*time.Second)
	if cape.Name() != "cape" {
		t.Errorf("Name() = %q, want %q", cape.Name(), "cape")
	}
}

func TestCAPEAnalyzerHealthCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/status/health/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	if err := cape.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck() error = %v, want nil", err)
	}
}

func TestCAPEAnalyzerSubmitAndPollClean(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Token test-key" {
			t.Errorf("Authorization = %q, want %q", got, "Token test-key")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task_id":42}`))
	})
	mux.HandleFunc("/apiv2/tasks/view/42", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"task":{"status":"reported","id":42},"info":{"score":0.0}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	verdict, err := cape.Analyze(context.Background(), []byte("test file content"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if verdict.Severity != SandboxClean {
		t.Errorf("severity = %d, want SandboxClean", verdict.Severity)
	}
}

func TestCAPEAnalyzerSubmitAndPollMalicious(t *testing.T) {
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
	verdict, err := cape.Analyze(context.Background(), []byte("malicious file"))
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if verdict.Severity != SandboxMalicious {
		t.Errorf("severity = %d, want SandboxMalicious", verdict.Severity)
	}
	if verdict.Score != 9.5 {
		t.Errorf("score = %f, want 9.5", verdict.Score)
	}
}

func TestCAPEAnalyzerSubmitError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/apiv2/tasks/create/file/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"error":"internal server error"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cape := NewCAPEAnalyzer(srv.URL, "test-key", 30*time.Second)
	_, err := cape.Analyze(context.Background(), []byte("test"))
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestCAPEScoreInterpretation(t *testing.T) {
	tests := []struct {
		score    float64
		expected SandboxSeverity
	}{
		{0.0, SandboxClean},
		{3.0, SandboxClean},
		{3.1, SandboxSuspicious},
		{6.9, SandboxSuspicious},
		{7.0, SandboxMalicious},
		{10.0, SandboxMalicious},
	}
	for _, tc := range tests {
		got := capeScoreToSeverity(tc.score)
		if got != tc.expected {
			t.Errorf("capeScoreToSeverity(%f) = %d, want %d", tc.score, got, tc.expected)
		}
	}
}

func TestSandboxVerdictString(t *testing.T) {
	tests := []struct {
		verdict *SandboxVerdict
		want    string
	}{
		{&SandboxVerdict{Severity: SandboxClean}, "clean"},
		{&SandboxVerdict{Severity: SandboxSuspicious, VirusName: "Heuristic.X"}, "suspicious:Heuristic.X"},
		{&SandboxVerdict{Severity: SandboxMalicious, VirusName: "Trojan.X"}, "malicious:Trojan.X"},
		{&SandboxVerdict{Severity: SandboxError, Detail: "connection refused"}, "error:connection refused"},
	}
	for _, tc := range tests {
		got := tc.verdict.String()
		if got != tc.want {
			t.Errorf("Verdict.String() = %q, want %q", got, tc.want)
		}
	}
}
