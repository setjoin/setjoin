package authn

import (
	"context"
	"testing"
)

// mockChallengeProvider implements ChallengeProvider for interface-contract testing.
type mockChallengeProvider struct {
	name string
}

func (m *mockChallengeProvider) Name() string                                     { return m.name }
func (m *mockChallengeProvider) Available(ctx context.Context, userID int64) bool { return true }
func (m *mockChallengeProvider) GenerateChallenge(ctx context.Context, userID int64, sessionID string) (*ChallengeResponse, error) {
	return &ChallengeResponse{Method: m.name, TTLSeconds: 120}, nil
}
func (m *mockChallengeProvider) VerifyChallenge(ctx context.Context, userID int64, nonce, answer string) error {
	return nil
}

func TestChallengeProviderInterface(t *testing.T) {
	var p ChallengeProvider = &mockChallengeProvider{name: "mock"}

	if p.Name() != "mock" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mock")
	}
	if !p.Available(context.Background(), 1) {
		t.Error("Available() = false, want true")
	}
	resp, err := p.GenerateChallenge(context.Background(), 1, "session-1")
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}
	if resp.Method != "mock" {
		t.Errorf("resp.Method = %q, want %q", resp.Method, "mock")
	}
	if resp.TTLSeconds != 120 {
		t.Errorf("resp.TTLSeconds = %d, want 120", resp.TTLSeconds)
	}
	if err := p.VerifyChallenge(context.Background(), 1, "n", "a"); err != nil {
		t.Errorf("VerifyChallenge() error = %v", err)
	}
}
