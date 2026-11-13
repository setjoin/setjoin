package smtp

import (
	"context"
	"errors"
	"testing"

	"setjoin.com/shared/toggle"
)

// mockPhishDetector implements PhishDetector for pipeline testing.
type mockPhishDetector struct {
	name    string
	verdict PhishVerdict
	ev      []string
	err     error
}

func (m *mockPhishDetector) Name() string { return m.name }

func (m *mockPhishDetector) Check(ctx context.Context, msg *PhishInput) (*PhishResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.verdict == PhishNone {
		return nil, nil
	}
	return &PhishResult{
		Verdict:  m.verdict,
		Detector: m.name,
		Evidence: m.ev,
	}, nil
}

// mockToggles implements ToggleChecker for testing.
type mockToggles struct {
	flags map[string]bool
}

func (m *mockToggles) IsEnabled(key string) bool {
	if v, ok := m.flags[key]; ok {
		return v
	}
	// Return false for unknown keys (safe default — production toggle.New would
	// load from DB; our mock is explicit only).
	return false
}

func newMockToggles(enabled map[string]bool) *mockToggles {
	return &mockToggles{flags: enabled}
}

func TestPhishPipelineRejectShortCircuits(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishReject, ev: []string{"ev1"}},
		&mockPhishDetector{name: "lookalike", verdict: PhishWarn, ev: []string{"ev2"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishLookalike:   true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishReject {
		t.Errorf("expected PhishReject, got %v", verdict)
	}
	if len(evidence) != 1 {
		t.Errorf("expected 1 evidence (short-circuit), got %d: %v", len(evidence), evidence)
	}
}

func TestPhishPipelineWarnAggregates(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishWarn, ev: []string{"dn-ev"}},
		&mockPhishDetector{name: "lookalike", verdict: PhishWarn, ev: []string{"ll-ev"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishLookalike:   true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishWarn {
		t.Errorf("expected PhishWarn, got %v", verdict)
	}
	if len(evidence) != 2 {
		t.Errorf("expected 2 evidence items, got %d: %v", len(evidence), evidence)
	}
}

func TestPhishPipelineRejectOverridesWarn(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishWarn, ev: []string{"dn-ev"}},
		&mockPhishDetector{name: "lookalike", verdict: PhishReject, ev: []string{"ll-ev"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishLookalike:   true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishReject {
		t.Errorf("expected PhishReject, got %v", verdict)
	}
	if len(evidence) != 2 {
		t.Errorf("expected 2 evidence (dn-ev + ll-ev accumulated before short-circuit), got %d: %v", len(evidence), evidence)
	}
}

func TestPhishPipelineAllNone(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishNone},
		&mockPhishDetector{name: "lookalike", verdict: PhishNone},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishLookalike:   true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishNone {
		t.Errorf("expected PhishNone, got %v", verdict)
	}
	if len(evidence) != 0 {
		t.Errorf("expected 0 evidence, got %d", len(evidence))
	}
}

func TestPhishPipelineErrorSkipsDetector(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", err: errors.New("db down")},
		&mockPhishDetector{name: "lookalike", verdict: PhishWarn, ev: []string{"ll-ev"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishLookalike:   true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishWarn {
		t.Errorf("expected PhishWarn from non-errored detector, got %v", verdict)
	}
	if len(evidence) != 1 {
		t.Errorf("expected 1 evidence from non-errored detector, got %d", len(evidence))
	}
}

func TestPhishPipelineDisabledToggleSkips(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishReject, ev: []string{"dn-ev"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: false,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishNone {
		t.Errorf("expected PhishNone when detector is disabled, got %v", verdict)
	}
	if len(evidence) != 0 {
		t.Errorf("expected 0 evidence when disabled, got %d", len(evidence))
	}
}

func TestPhishPipelineStrictMode(t *testing.T) {
	detectors := []PhishDetector{
		&mockPhishDetector{name: "display_name", verdict: PhishWarn, ev: []string{"dn-ev"}},
	}
	toggles := newMockToggles(map[string]bool{
		toggle.FeatureAntiphishDisplayName: true,
		toggle.FeatureAntiphishStrictMode:  true,
	})

	verdict, evidence := RunPhishPipeline(context.Background(), detectors, toggles, &PhishInput{})
	if verdict != PhishReject {
		t.Errorf("expected PhishReject in strict mode, got %v", verdict)
	}
	if len(evidence) == 0 {
		t.Error("expected evidence in strict mode")
	}
}

func TestInjectAntiPhishHeaders_Warn(t *testing.T) {
	data := []byte("From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello World")
	result := InjectAntiPhishHeaders(data, PhishWarn, []string{"display_name_fuzzy_match:jane:0.92"})
	resultStr := string(result)
	if !containsStr(resultStr, "X-AntiPhish: warn") {
		t.Errorf("expected X-AntiPhish header, got:\n%s", resultStr)
	}
	if !containsStr(resultStr, "[WARNING]") {
		t.Errorf("expected safety banner, got:\n%s", resultStr)
	}
}

func TestInjectAntiPhishHeaders_None(t *testing.T) {
	data := []byte("From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello World")
	result := InjectAntiPhishHeaders(data, PhishNone, nil)
	resultStr := string(result)
	expectedStr := string(data)
	if resultStr != expectedStr {
		t.Errorf("expected unchanged data for PhishNone, got:\n%s\nvs\n%s", resultStr, expectedStr)
	}
}

func TestInjectAntiPhishHeaders_RejectNoBanner(t *testing.T) {
	data := []byte("From: sender@example.com\r\nTo: rcpt@example.com\r\n\r\nHello World")
	result := InjectAntiPhishHeaders(data, PhishReject, []string{"homoglyph_domain:google.com:goоgle.com"})
	resultStr := string(result)
	if !containsStr(resultStr, "X-AntiPhish: reject") {
		t.Errorf("expected X-AntiPhish: reject header, got:\n%s", resultStr)
	}
	if containsStr(resultStr, "[WARNING]") {
		t.Errorf("expected NO safety banner for Reject, but found one:\n%s", resultStr)
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
