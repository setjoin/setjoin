package smtp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// SandboxSeverity classifies the severity of an attachment analysis result.
type SandboxSeverity int

const (
	SandboxClean      SandboxSeverity = 0
	SandboxSuspicious SandboxSeverity = 1
	SandboxMalicious  SandboxSeverity = 2
	SandboxError      SandboxSeverity = 3
	SandboxUnknown    SandboxSeverity = 4
)

// FailMode controls how the pipeline behaves when an analyzer errors.
type FailMode string

const (
	FailOpen   FailMode = "open"
	FailClosed FailMode = "closed"
)

// SandboxVerdict is the result of an attachment analysis.
type SandboxVerdict struct {
	Severity  SandboxSeverity
	Analyzer  string
	Score     float64 // 0.0-10.0
	Detail    string
	VirusName string
	Behaviors []string
}

// String returns a human-readable summary of the verdict.
func (v *SandboxVerdict) String() string {
	switch v.Severity {
	case SandboxClean:
		return "clean"
	case SandboxSuspicious:
		if v.VirusName != "" {
			return "suspicious:" + v.VirusName
		}
		return "suspicious"
	case SandboxMalicious:
		if v.VirusName != "" {
			return "malicious:" + v.VirusName
		}
		return "malicious"
	case SandboxError:
		return "error:" + v.Detail
	default:
		return "unknown"
	}
}

// SandboxAnalyzer is the interface for a single attachment analysis check.
// Each implementation performs one check and returns a verdict.
type SandboxAnalyzer interface {
	Name() string
	Analyze(ctx context.Context, data []byte) (*SandboxVerdict, error)
	HealthCheck(ctx context.Context) error
}

// AttachmentAnalysisPipeline holds an ordered list of analyzers and runs them
// in priority sequence against the raw MIME message, short-circuiting on
// first malicious verdict and aggregating suspicious scores.
type AttachmentAnalysisPipeline struct {
	analyzers []SandboxAnalyzer
	timeout   time.Duration
	failMode  FailMode
	logger    *slog.Logger
}

// NewAttachmentAnalysisPipeline creates a new analysis pipeline.
func NewAttachmentAnalysisPipeline(analyzers []SandboxAnalyzer, timeout time.Duration, failMode FailMode, logger *slog.Logger) *AttachmentAnalysisPipeline {
	return &AttachmentAnalysisPipeline{
		analyzers: analyzers,
		timeout:   timeout,
		failMode:  failMode,
		logger:    logger,
	}
}

// Analyze runs all analyzers in order against the data and returns the
// aggregate verdict. Rules:
//  1. Empty pipeline → SandboxClean
//  2. Wrap context with pipeline timeout
//  3. Iterate analyzers in order
//  4. On first SandboxMalicious → short-circuit
//  5. On error → failClosed returns SandboxMalicious; failOpen records error and continues
//  6. Track worst verdict by Severity (higher = worse), tiebreak by Score
//  7. Accumulate all Behaviors across analyzers
//  8. If none ran (all errored with fail-open), return SandboxClean
func (p *AttachmentAnalysisPipeline) Analyze(ctx context.Context, data []byte) *SandboxVerdict {
	if len(p.analyzers) == 0 {
		return &SandboxVerdict{Severity: SandboxClean}
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	var worstSeen SandboxSeverity
	bestVerdict := &SandboxVerdict{Severity: SandboxClean}
	anyRan := false

	for _, a := range p.analyzers {
		select {
		case <-ctx.Done():
			// Timeout — treat as error
			if p.failMode == FailClosed {
				return &SandboxVerdict{Severity: SandboxMalicious, Analyzer: a.Name(), Detail: "pipeline timeout (fail-closed)"}
			}
			// Fail-open: worst we've seen so far
			if !anyRan {
				return &SandboxVerdict{Severity: SandboxClean}
			}
			return bestVerdict
		default:
		}

		verdict, err := a.Analyze(ctx, data)
		if err != nil {
			p.logger.Warn("sandbox analyzer error", "analyzer", a.Name(), "error", err)
			if p.failMode == FailClosed {
				return &SandboxVerdict{Severity: SandboxMalicious, Analyzer: a.Name(), Detail: err.Error()}
			}
			// fail-open: log and skip this analyzer — do not let errors
			// pollute the verdict aggregation when healthy analyzers are present.
			continue
		}

		if verdict == nil {
			continue
		}

		anyRan = true

		// Aggregate behaviors
		if len(verdict.Behaviors) > 0 {
			bestVerdict.Behaviors = append(bestVerdict.Behaviors, verdict.Behaviors...)
		}

		// Short-circuit on malicious
		if verdict.Severity == SandboxMalicious {
			bestVerdict.Severity = SandboxMalicious
			bestVerdict.Analyzer = verdict.Analyzer
			bestVerdict.Score = verdict.Score
			bestVerdict.Detail = verdict.Detail
			bestVerdict.VirusName = verdict.VirusName
			return bestVerdict
		}

		// Track worst severity (Error/Unknown are non-results and don't outrank Clean)
		if verdict.Severity == SandboxSuspicious || verdict.Severity == SandboxClean {
			if verdict.Severity > worstSeen {
				worstSeen = verdict.Severity
				bestVerdict.Severity = verdict.Severity
				bestVerdict.Analyzer = verdict.Analyzer
				bestVerdict.Score = verdict.Score
				bestVerdict.Detail = verdict.Detail
				bestVerdict.VirusName = verdict.VirusName
			} else if verdict.Severity == worstSeen && verdict.Score > bestVerdict.Score {
				// Tiebreak by score
				bestVerdict.Score = verdict.Score
				bestVerdict.Analyzer = verdict.Analyzer
				bestVerdict.Detail = verdict.Detail
				bestVerdict.VirusName = verdict.VirusName
			}
		}
	}

	if !anyRan {
		return &SandboxVerdict{Severity: SandboxClean}
	}
	return bestVerdict
}

// HealthCheck runs health checks on all analyzers.
func (p *AttachmentAnalysisPipeline) HealthCheck(ctx context.Context) error {
	for _, a := range p.analyzers {
		if err := a.HealthCheck(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Len returns the number of analyzers in the pipeline.
func (p *AttachmentAnalysisPipeline) Len() int {
	return len(p.analyzers)
}

// ── CAPE Sandbox Analyzer ────────────────────────────────────────────────────

// CAPEAnalyzer submits files to a CAPE sandbox for behavioral analysis.
// It implements the SandboxAnalyzer interface.
type CAPEAnalyzer struct {
	baseURL string
	apiKey  string
	timeout time.Duration
	client  *http.Client
}

// NewCAPEAnalyzer creates a new CAPE sandbox analyzer.
func NewCAPEAnalyzer(baseURL, apiKey string, timeout time.Duration) *CAPEAnalyzer {
	return &CAPEAnalyzer{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns "cape".
func (c *CAPEAnalyzer) Name() string { return "cape" }

// HealthCheck verifies the CAPE sandbox is reachable.
func (c *CAPEAnalyzer) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/apiv2/tasks/status/health/", nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cape health check returned %d", resp.StatusCode)
	}
	return nil
}

// Analyze submits the file to CAPE, polls for results, and maps the score to a verdict.
func (c *CAPEAnalyzer) Analyze(ctx context.Context, data []byte) (*SandboxVerdict, error) {
	taskID, err := c.submitFile(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("cape submit: %w", err)
	}

	score, signatures, err := c.pollTask(ctx, taskID)
	if err != nil {
		return nil, fmt.Errorf("cape poll: %w", err)
	}

	severity := capeScoreToSeverity(score)
	virusName := extractCapeMalwareFamily(signatures)

	return &SandboxVerdict{
		Severity:  severity,
		Analyzer:  "cape",
		Score:     score,
		VirusName: virusName,
	}, nil
}

// submitFile uploads a file to CAPE for analysis and returns the task ID.
func (c *CAPEAnalyzer) submitFile(ctx context.Context, data []byte) (int64, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "attachment.bin")
	if err != nil {
		return 0, err
	}
	if _, err := part.Write(data); err != nil {
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/apiv2/tasks/create/file/", &buf)
	if err != nil {
		return 0, err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("cape submit returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		TaskID int64 `json:"task_id"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("cape submit parse: %w", err)
	}
	if result.TaskID == 0 {
		return 0, fmt.Errorf("cape submit returned zero task_id")
	}
	return result.TaskID, nil
}

// pollTask waits for a CAPE task to complete, polling every 3 seconds.
func (c *CAPEAnalyzer) pollTask(ctx context.Context, taskID int64) (score float64, signatures []string, err error) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-ticker.C:
		}

		s, sigs, done, viewErr := c.viewTask(ctx, taskID)
		if viewErr != nil {
			return 0, nil, viewErr
		}
		if done {
			return s, sigs, nil
		}
	}
}

// viewTask fetches a CAPE task status and returns the score if complete.
func (c *CAPEAnalyzer) viewTask(ctx context.Context, taskID int64) (score float64, signatures []string, done bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/apiv2/tasks/view/%d", c.baseURL, taskID), nil)
	if err != nil {
		return 0, nil, false, err
	}
	c.setAuth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, false, err
	}

	var result struct {
		Task struct {
			Status string `json:"status"`
			ID     int64  `json:"id"`
		} `json:"task"`
		Info struct {
			Score      float64  `json:"score"`
			Signatures []string `json:"signatures"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, nil, false, fmt.Errorf("cape view parse: %w", err)
	}

	switch result.Task.Status {
	case "reported", "completed":
		return result.Info.Score, result.Info.Signatures, true, nil
	case "failed_analysis", "failed_processing", "failed_reporting":
		return 0, nil, true, fmt.Errorf("cape task %d failed with status %q", taskID, result.Task.Status)
	default:
		// Still running: pending, running, processing, etc.
		return 0, nil, false, nil
	}
}

// setAuth sets the CAPE API authorization header.
func (c *CAPEAnalyzer) setAuth(req *http.Request) {
	req.Header.Set("Authorization", "Token "+c.apiKey)
}

// capeScoreToSeverity maps a CAPE 0-10 score to a SandboxSeverity.
// ≤3 → Clean, 3.0 < score < 7.0 → Suspicious, ≥7 → Malicious.
func capeScoreToSeverity(score float64) SandboxSeverity {
	switch {
	case score <= 3.0:
		return SandboxClean
	case score < 7.0:
		return SandboxSuspicious
	default:
		return SandboxMalicious
	}
}

// extractCapeMalwareFamily extracts the malware family name from the last signature.
func extractCapeMalwareFamily(signatures []string) string {
	if len(signatures) == 0 {
		return ""
	}
	return signatures[len(signatures)-1]
}
