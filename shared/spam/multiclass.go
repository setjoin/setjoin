package spam

import (
	"fmt"
	"hash/fnv"
	"math"
)

// ClassLabel identifies a spam classification category.
type ClassLabel string

const (
	// ClassHam is legitimate non-bulk personal or business email.
	ClassHam ClassLabel = "__label__ham"
	// ClassSpam is unsolicited bulk/commercial email.
	ClassSpam ClassLabel = "__label__spam"
	// ClassNewsletter is opted-in bulk mail with List-Unsubscribe header.
	ClassNewsletter ClassLabel = "__label__newsletter"
	// ClassPromotional is marketing email from known commercial senders.
	ClassPromotional ClassLabel = "__label__promotional"
	// ClassPhishing is credential-harvesting or fraud email.
	ClassPhishing ClassLabel = "__label__phishing"
)

// ClassResult holds the prediction result from a multi-class classifier.
type ClassResult struct {
	// Label is the predicted class (the one with highest softmax probability).
	Label ClassLabel
	// Probability is the softmax probability of the predicted class (0-1).
	Probability float64
	// Scores holds the softmax probability for every class.
	Scores map[ClassLabel]float64
}

// ftrlModel is a single-class FTRL-Proximal online learner that works with string
// features. Each feature string is hashed to a weight index via FNV-1a.
// The Predict method returns the raw dot product (pre-sigmoid) so that
// MultiClassFTRL can apply softmax across all classes.
type ftrlModel struct {
	size uint32
	w    []float64 // per-feature weights
	g    []float64 // sum of gradients
	z    []float64 // proximal accumulator
	n    []float64 // sum of squared gradients
	p    ftrlParams
}

// ftrlParams holds hyperparameters for FTRL-Proximal.
type ftrlParams struct {
	alpha float64 // learning rate
	beta  float64 // smoothing
	l1    float64 // L1 regularization
	l2    float64 // L2 regularization
}

// NewFTRLModel creates a single-class FTRL model that works with string features.
// size is the hash space dimensionality (number of weight buckets).
func NewFTRLModel(alpha, beta, l1, l2 float64, size uint32) *ftrlModel {
	return &ftrlModel{
		size: size,
		w:    make([]float64, size),
		g:    make([]float64, size),
		z:    make([]float64, size),
		n:    make([]float64, size),
		p:    ftrlParams{alpha: alpha, beta: beta, l1: l1, l2: l2},
	}
}

// hashFeature maps a string feature to a weight index using FNV-1a 64-bit hash.
func (m *ftrlModel) hashFeature(feature string) uint32 {
	h := fnv.New64a()
	h.Write([]byte(feature))
	return uint32(h.Sum64() % uint64(m.size))
}

// Predict returns the raw dot product (pre-sigmoid) for the given string features.
// For multi-class use, this raw score is fed into softmax across classes.
func (m *ftrlModel) Predict(features []string) float64 {
	var dot float64
	for _, f := range features {
		idx := m.hashFeature(f)
		dot += m.w[idx]
	}
	return dot
}

// Update trains the model on a single labeled example.
// label=1.0 means this class is the correct one; label=0.0 means it is not.
func (m *ftrlModel) Update(features []string, label float64) {
	if len(features) == 0 {
		return
	}

	p := sigmoid(m.Predict(features))
	g := p - label // gradient of logistic loss

	for _, f := range features {
		idx := m.hashFeature(f)

		sigma := (math.Sqrt(m.n[idx]+g*g) - math.Sqrt(m.n[idx])) / m.p.alpha
		m.z[idx] += g - sigma*m.w[idx]
		m.n[idx] += g * g

		if math.Abs(m.z[idx]) <= m.p.l1 {
			m.w[idx] = 0
		} else {
			sign := 1.0
			if m.z[idx] < 0 {
				sign = -1.0
			}
			m.w[idx] = (sign*m.p.l1 - m.z[idx]) /
				((m.p.beta+math.Sqrt(m.n[idx]))/m.p.alpha + m.p.l2)
		}
	}
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// MultiClassFTRL is a multi-class FTRL-Proximal classifier.
// It maintains one ftrlModel per class and uses softmax for prediction.
// Classes: ham, spam, newsletter, promotional, phishing.
type MultiClassFTRL struct {
	classes []ClassLabel
	models  map[ClassLabel]*ftrlModel
	size    uint32
}

// NewMultiClassFTRL creates a new multi-class classifier with the given hash space size.
// Uses sensible FTRL hyperparameters: alpha=0.1, beta=1.0, l1=0.01, l2=0.01.
func NewMultiClassFTRL(size uint32) *MultiClassFTRL {
	if size == 0 {
		size = 1 << 20 // 1M buckets default
	}
	classes := []ClassLabel{ClassHam, ClassSpam, ClassNewsletter, ClassPromotional, ClassPhishing}
	models := make(map[ClassLabel]*ftrlModel, len(classes))
	for _, c := range classes {
		models[c] = NewFTRLModel(0.1, 1.0, 0.01, 0.01, size)
	}
	return &MultiClassFTRL{
		classes: classes,
		models:  models,
		size:    size,
	}
}

// Classes returns a copy of the class label list.
func (m *MultiClassFTRL) Classes() []ClassLabel {
	out := make([]ClassLabel, len(m.classes))
	copy(out, m.classes)
	return out
}

// Predict classifies features and returns the predicted class with softmax probabilities.
func (m *MultiClassFTRL) Predict(features []string) ClassResult {
	scores := make(map[ClassLabel]float64, len(m.classes))
	var maxScore float64
	var maxClass ClassLabel

	for _, c := range m.classes {
		scores[c] = m.models[c].Predict(features)
		if c == m.classes[0] || scores[c] > maxScore {
			maxScore = scores[c]
			maxClass = c
		}
	}

	// Softmax: exp(x_i - max) / sum(exp(x_j - max)) for numerical stability.
	var sumExp float64
	softmax := make(map[ClassLabel]float64, len(m.classes))
	for _, c := range m.classes {
		softmax[c] = math.Exp(scores[c] - maxScore)
		sumExp += softmax[c]
	}
	for _, c := range m.classes {
		softmax[c] /= sumExp
	}

	return ClassResult{
		Label:       maxClass,
		Probability: softmax[maxClass],
		Scores:      softmax,
	}
}

// Train updates the classifier on a single labeled example.
// feature-label → positive for the correct class (1.0), negative for all others (0.0).
func (m *MultiClassFTRL) Train(features []string, label ClassLabel) error {
	model, ok := m.models[label]
	if !ok {
		return fmt.Errorf("multi-class FTRL: unknown class %q", label)
	}
	// Positive update for the correct class.
	model.Update(features, 1.0)

	// Negative update for all other classes.
	for _, c := range m.classes {
		if c != label {
			m.models[c].Update(features, 0.0)
		}
	}
	return nil
}
