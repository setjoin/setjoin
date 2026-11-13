package spam

import (
	"testing"
)

func TestModel_TrainAndScore(t *testing.T) {
	m := NewModel(DefaultFeatureSize)
	if m == nil {
		t.Fatal("NewModel returned nil")
	}

	// Train on a known spam message and a known ham message.
	spamRaw := []byte("From: spammer@evil.com\r\nSubject: WINNER Click here\r\n\r\nhttp://evil.com/prize You won a million dollars!")
	hamRaw := []byte("From: alice@setjoin.com\r\nSubject: Q3 Budget Review\r\nMessage-Id: abc123\r\nDate: Mon, 1 Jun 2026\r\nContent-Type: text/plain\r\n\r\nHere is the budget for Q3. Please review.")

	for i := 0; i < 10; i++ {
		m.Train(spamRaw, true)
		m.Train(hamRaw, false)
	}

	spamScore := m.Score(spamRaw)
	hamScore := m.Score(hamRaw)

	if spamScore <= hamScore {
		t.Errorf("spamScore=%.4f should be > hamScore=%.4f", spamScore, hamScore)
	}

	// After 10 iterations, the model should clearly separate these two examples.
	if spamScore < 0.7 {
		t.Errorf("spamScore=%.4f, expected > 0.7", spamScore)
	}
}

func TestModel_PersistRestore(t *testing.T) {
	m1 := NewModel(DefaultFeatureSize)
	raw := []byte("From: spam@evil.com\r\nSubject: Test\r\n\r\nTest body")
	for i := 0; i < 5; i++ {
		m1.Train(raw, true)
	}

	data, err := m1.Save()
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	m2 := NewModel(DefaultFeatureSize)
	if err := m2.Load(data); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Scores should be identical after round-trip.
	if m1.Score(raw) != m2.Score(raw) {
		t.Errorf("scores diverge after persist: %.6f vs %.6f", m1.Score(raw), m2.Score(raw))
	}
}
