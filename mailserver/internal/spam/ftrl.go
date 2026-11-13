package spam

import (
	"encoding/binary"
	"fmt"
	"math"
)

// FTRLParams holds the hyperparameters for FTRL-Proximal.
// Defaults are from Stalwart's production config.
type FTRLParams struct {
	Alpha float64 // learning rate (default 0.1)
	Beta  float64 // smoothing (default 1.0)
	L1    float64 // L1 regularization (default 0.01)
	L2    float64 // L2 regularization (default 0.01)
}

// DefaultFTRLParams returns Stalwart's recommended defaults.
func DefaultFTRLParams() FTRLParams {
	return FTRLParams{Alpha: 0.1, Beta: 1.0, L1: 0.01, L2: 0.01}
}

// FTRL holds the weight tables for FTRL-Proximal online learning.
// Size is the feature space dimensionality (number of hash buckets).
type FTRL struct {
	Size uint32
	W    []float64 // per-feature weights
	Z    []float64 // proximal accumulator
	N    []float64 // sum of squared gradients
	P    FTRLParams
}

// NewFTRL creates a new FTRL model with the given feature space size.
func NewFTRL(size uint32, params FTRLParams) *FTRL {
	return &FTRL{
		Size: size,
		W:    make([]float64, size),
		Z:    make([]float64, size),
		N:    make([]float64, size),
		P:    params,
	}
}

// Predict returns the probability (0-1) that the given features indicate spam.
func (m *FTRL) Predict(features []uint32) float64 {
	var dot float64
	for _, idx := range features {
		if idx < m.Size {
			dot += m.W[idx]
		}
	}
	return sigmoid(dot)
}

// Update trains the model on a single labeled example.
// label=1.0 means spam, label=0.0 means ham.
func (m *FTRL) Update(features []uint32, label float64) {
	p := m.Predict(features)
	g := p - label // gradient of logistic loss

	for _, idx := range features {
		if idx >= m.Size {
			continue
		}
		sigma := (math.Sqrt(m.N[idx]+g*g) - math.Sqrt(m.N[idx])) / m.P.Alpha
		m.Z[idx] += g - sigma*m.W[idx]
		m.N[idx] += g * g

		if math.Abs(m.Z[idx]) <= m.P.L1 {
			m.W[idx] = 0
		} else {
			sign := 1.0
			if m.Z[idx] < 0 {
				sign = -1.0
			}
			m.W[idx] = (sign*m.P.L1 - m.Z[idx]) /
				((m.P.Beta+math.Sqrt(m.N[idx]))/m.P.Alpha + m.P.L2)
		}
	}
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

// Binary format for serialization: 4-byte magic prefix, 4-byte size, then [W][Z][N] as float64 arrays.
// Magic "FTR2" (bumped from "FTRL") marks the 3-array layout after the dead G
// (sum-of-gradients) array was dropped; an old 4-array "FTRL" blob is rejected
// rather than misparsed with shifted offsets — the caller (store.go) falls
// back to a fresh model on any UnmarshalBinary error, so old persisted models
// just retrain from scratch on first load post-deploy.
const ftrlMagic = "FTR2"

// MarshalBinary serializes the FTRL model to a binary format.
func (m *FTRL) MarshalBinary() ([]byte, error) {
	headerLen := 4 + 4             // magic + size uint32
	dataLen := int(m.Size) * 3 * 8 // 3 arrays of float64
	buf := make([]byte, headerLen+dataLen)

	copy(buf[0:], ftrlMagic)
	binary.LittleEndian.PutUint32(buf[4:], m.Size)

	offset := 8
	for _, arr := range [][]float64{m.W, m.Z, m.N} {
		for _, v := range arr {
			binary.LittleEndian.PutUint64(buf[offset:], math.Float64bits(v))
			offset += 8
		}
	}
	return buf, nil
}

// UnmarshalBinary deserializes the FTRL model from a binary format.
//
// Structural checks alone are not enough at this trust boundary: a corrupt
// but well-formed blob (bit rot, torn write, buggy writer) must be rejected
// rather than loaded, because a NaN weight makes Predict return NaN and the
// spam verdict silently fails open (NaN > threshold is always false). The
// decoded state is validated before any of it is committed, so a rejected
// blob leaves the model untouched and the caller falls back to a fresh model.
func (m *FTRL) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("ftrl data too short")
	}
	if string(data[:4]) != ftrlMagic {
		return fmt.Errorf("invalid ftrl magic")
	}
	size := binary.LittleEndian.Uint32(data[4:8])
	if size != m.Size {
		return fmt.Errorf("ftrl size mismatch: stored %d, model %d", size, m.Size)
	}
	wantLen := 8 + int(size)*3*8
	if len(data) != wantLen {
		return fmt.Errorf("ftrl data length mismatch: got %d, want %d", len(data), wantLen)
	}

	w := make([]float64, size)
	z := make([]float64, size)
	n := make([]float64, size)
	offset := 8
	for _, table := range []struct {
		name string
		vals []float64
	}{{"W", w}, {"Z", z}, {"N", n}} {
		for i := range table.vals {
			v := math.Float64frombits(binary.LittleEndian.Uint64(data[offset:]))
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return fmt.Errorf("ftrl blob contains non-finite value %s[%d]", table.name, i)
			}
			table.vals[i] = v
			offset += 8
		}
	}
	// N accumulates squared gradients, so a healthy writer can never persist
	// a negative element; one would corrupt the Update arithmetic.
	for i, v := range n {
		if v < 0 {
			return fmt.Errorf("ftrl blob contains negative value N[%d]=%v", i, v)
		}
	}
	m.W, m.Z, m.N = w, z, n
	return nil
}
