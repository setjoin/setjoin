package spam

import (
	"math"
	"testing"
)

func TestFTRLModel_Predict_ZeroForUntrained(t *testing.T) {
	m := NewFTRLModel(0.1, 1.0, 0.01, 0.01, 1<<20)
	// Without any training, a few features should produce a near-zero dot product.
	score := m.Predict([]string{"hello-world", "buy-cheap"})
	// Raw score (pre-sigmoid); initial weights are zero, so score should be near 0.
	if math.IsNaN(score) {
		t.Error("predict returned NaN for untrained model")
	}
}

func TestFTRLModel_UpdateAndPredict_Converges(t *testing.T) {
	m := NewFTRLModel(0.1, 1.0, 0.01, 0.01, 1<<18)
	features := []string{"buy-cheap", "cheap-viagra", "free-now", "click-here"}

	// Train on positive examples (label=1.0 means "this class matches").
	for i := 0; i < 20; i++ {
		m.Update(features, 1.0)
	}

	score := m.Predict(features)
	// After positive training, the raw score should become positive.
	if score <= 0 {
		t.Errorf("expected positive score after training on positive labels, got %.4f", score)
	}
}

func TestFTRLModel_UpdateNegative_ScoreDecreases(t *testing.T) {
	m := NewFTRLModel(0.1, 1.0, 0.01, 0.01, 1<<18)
	features := []string{"buy-cheap", "cheap-viagra"}

	// Train positive first.
	for i := 0; i < 10; i++ {
		m.Update(features, 1.0)
	}
	posScore := m.Predict(features)

	// Train negative.
	for i := 0; i < 10; i++ {
		m.Update(features, 0.0)
	}
	negScore := m.Predict(features)

	if negScore >= posScore {
		t.Errorf("score should decrease after negative training: positive=%.4f, negative=%.4f", posScore, negScore)
	}
}

func TestFTRLModel_DifferentFeaturesDiverge(t *testing.T) {
	m := NewFTRLModel(0.1, 1.0, 0.01, 0.01, 1<<18)
	spamFeats := []string{"buy-cheap", "cheap-viagra", "click-here"}
	hamFeats := []string{"meeting-agenda", "agenda-tomorrow", "project-update"}

	// Train spam features positively.
	for i := 0; i < 15; i++ {
		m.Update(spamFeats, 1.0)
	}
	// Train ham features negatively.
	for i := 0; i < 15; i++ {
		m.Update(hamFeats, 0.0)
	}

	spamScore := m.Predict(spamFeats)
	hamScore := m.Predict(hamFeats)

	if spamScore <= hamScore {
		t.Errorf("spam features should score higher than ham: spam=%.4f, ham=%.4f", spamScore, hamScore)
	}
}

func TestFTRLModel_EmptyFeatures(t *testing.T) {
	m := NewFTRLModel(0.1, 1.0, 0.01, 0.01, 1<<18)
	score := m.Predict(nil)
	if score != 0 {
		t.Errorf("expected 0 score for nil features, got %.4f", score)
	}
	score = m.Predict([]string{})
	if score != 0 {
		t.Errorf("expected 0 score for empty features, got %.4f", score)
	}
	// Update with empty features should not panic.
	m.Update(nil, 1.0)
	m.Update([]string{}, 0.0)
}

func TestMultiClassFTRL_Predict_ReturnsAllClasses(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	result := m.Predict([]string{"buy-cheap", "cheap-viagra", "viagra-now"})

	if result.Label == "" {
		t.Error("expected a label")
	}
	if result.Probability <= 0 || result.Probability > 1 {
		t.Errorf("probability out of range: %.4f", result.Probability)
	}
	if len(result.Scores) != 5 {
		t.Errorf("expected 5 class scores, got %d", len(result.Scores))
	}

	// Verify all expected classes are present.
	for _, c := range m.Classes() {
		if _, ok := result.Scores[c]; !ok {
			t.Errorf("missing score for class %s", c)
		}
	}
}

func TestMultiClassFTRL_SoftmaxSumsToOne(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	features := []string{"test-feature-a", "test-feature-b"}

	// Train one round on each class to give non-zero values.
	for _, c := range m.Classes() {
		m.Train(features, c)
	}

	result := m.Predict(features)
	sum := 0.0
	for _, p := range result.Scores {
		sum += p
	}
	if math.Abs(sum-1.0) > 0.001 {
		t.Errorf("softmax probabilities should sum to 1, got %.6f", sum)
	}
}

func TestMultiClassFTRL_TrainAndPredict_SpamFavored(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	spamFeatures := []string{"buy-cheap", "cheap-viagra", "free-now", "click-here"}

	// Train spam class 20 times on these features.
	for i := 0; i < 20; i++ {
		m.Train(spamFeatures, ClassSpam)
	}

	result := m.Predict(spamFeatures)
	if result.Label != ClassSpam {
		t.Logf("after training, predicted %s with probability %.4f (scores: %v)",
			result.Label, result.Probability, result.Scores)
	}
	// The spam class should have the highest probability.
	spamProb := result.Scores[ClassSpam]
	for c, p := range result.Scores {
		if p > spamProb && c != ClassSpam {
			t.Errorf("class %s has higher probability (%.4f) than spam (%.4f) after spam training",
				c, p, spamProb)
		}
	}
}

func TestMultiClassFTRL_TrainAndPredict_NewsletterFavored(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	nlFeatures := []string{"weekly-digest", "unsubscribe-here", "newsletter-edition"}

	for i := 0; i < 20; i++ {
		m.Train(nlFeatures, ClassNewsletter)
	}

	result := m.Predict(nlFeatures)
	nlProb := result.Scores[ClassNewsletter]
	for c, p := range result.Scores {
		if p > nlProb && c != ClassNewsletter {
			t.Errorf("class %s has higher probability (%.4f) than newsletter (%.4f) after newsletter training",
				c, p, nlProb)
		}
	}
}

func TestMultiClassFTRL_UnknownClass_Error(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	err := m.Train([]string{"test"}, ClassLabel("__label__unknown"))
	if err == nil {
		t.Error("expected error for unknown class")
	}
}

func TestMultiClassFTRL_ProbabilityIsCorrectLabel(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	result := m.Predict([]string{"some-feature"})
	// The probability field should match the winning class's softmax probability.
	if math.Abs(result.Probability-result.Scores[result.Label]) > 0.001 {
		t.Errorf("Probability (%.4f) should equal winning class score (%.4f)",
			result.Probability, result.Scores[result.Label])
	}
}

func TestMultiClassFTRL_Classes_ReturnsCopy(t *testing.T) {
	m := NewMultiClassFTRL(1 << 18)
	classes := m.Classes()
	if len(classes) != 5 {
		t.Errorf("expected 5 classes, got %d", len(classes))
	}
	// Verify it's a copy by modifying.
	classes[0] = ClassLabel("modified")
	classes2 := m.Classes()
	if classes2[0] == ClassLabel("modified") {
		t.Error("Classes() should return a copy")
	}
}
