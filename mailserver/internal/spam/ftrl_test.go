package spam

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestFTRL_UpdateAndPredict(t *testing.T) {
	m := NewFTRL(100, FTRLParams{
		Alpha: 0.1,
		Beta:  1.0,
		L1:    0.01,
		L2:    0.01,
	})

	// Train: feature 5 → spam (label=1.0), feature 7 → ham (label=0.0)
	// Repeat a few times so weights diverge.
	for i := 0; i < 10; i++ {
		m.Update([]uint32{5}, 1.0)
		m.Update([]uint32{7}, 0.0)
	}

	// After training: feature 5 should predict >0.5 (spam), feature 7 <0.5 (ham).
	spamScore := m.Predict([]uint32{5})
	hamScore := m.Predict([]uint32{7})
	if spamScore <= hamScore {
		t.Errorf("spamScore=%.4f should be > hamScore=%.4f", spamScore, hamScore)
	}
	if spamScore <= 0.5 {
		t.Errorf("spamScore=%.4f should be > 0.5", spamScore)
	}
}

func TestFTRL_SerializeRoundtrip(t *testing.T) {
	m := NewFTRL(50, DefaultFTRLParams())
	m.Update([]uint32{1, 2, 3}, 1.0)
	m.Update([]uint32{4, 5}, 0.0)

	data, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	wantLen := 8 + 3*8*50 // header + 3 arrays of float64 (W, Z, N — G dropped)
	if len(data) != wantLen {
		t.Errorf("MarshalBinary length = %d, want %d", len(data), wantLen)
	}

	m2 := NewFTRL(50, DefaultFTRLParams())
	if err := m2.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	// Predictions should be identical after round-trip.
	for _, feats := range [][]uint32{{1, 2, 3}, {4, 5}, {1, 5}} {
		if math.Abs(m.Predict(feats)-m2.Predict(feats)) > 1e-6 {
			t.Errorf("predictions diverge after round-trip for features %v", feats)
		}
	}
}

func TestFTRL_UnmarshalBinary_RejectsOldFourArrayFormat(t *testing.T) {
	const size = 50
	// Synthesize an old-format blob: magic "FTRL", size, then 4 arrays of
	// float64 zeros (the pre-cleanup layout including the dead G array).
	old := make([]byte, 8+size*4*8)
	copy(old[0:], "FTRL")
	binary.LittleEndian.PutUint32(old[4:], size)

	m := NewFTRL(size, DefaultFTRLParams())
	if err := m.UnmarshalBinary(old); err == nil {
		t.Fatal("UnmarshalBinary should reject old 4-array \"FTRL\" blob, got nil error")
	}

	// Also reject a blob with the current magic but the old (longer) length.
	wrongLen := make([]byte, 8+size*4*8)
	copy(wrongLen[0:], ftrlMagic)
	binary.LittleEndian.PutUint32(wrongLen[4:], size)
	if err := m.UnmarshalBinary(wrongLen); err == nil {
		t.Fatal("UnmarshalBinary should reject current-magic blob with old 4-array length, got nil error")
	}
}

func TestFTRL_UnmarshalBinary_RejectsNonFiniteAndNegativeValues(t *testing.T) {
	const size = 8
	trained := NewFTRL(size, DefaultFTRLParams())
	trained.Update([]uint32{1}, 1.0)

	blob, err := trained.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// A corrupt-but-well-formed blob with a NaN weight must be rejected:
	// a NaN score would silently fail open (NaN > threshold is false).
	mut := func(t *testing.T, mutate func(vals []byte)) []byte {
		t.Helper()
		out := make([]byte, len(blob))
		copy(out, blob)
		mutate(out[8:])
		return out
	}
	patchFirst := func(bitPattern uint64) func([]byte) {
		return func(vals []byte) {
			binary.LittleEndian.PutUint64(vals, bitPattern)
		}
	}
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"NaN weight in W", patchFirst(math.Float64bits(math.NaN()))},
		{"+Inf weight in W", patchFirst(math.Float64bits(math.Inf(1)))},
		{"-Inf weight in Z", func(vals []byte) {
			binary.LittleEndian.PutUint64(vals[8*size:], math.Float64bits(math.Inf(-1)))
		}},
		{"negative N", func(vals []byte) {
			binary.LittleEndian.PutUint64(vals[16*size:], math.Float64bits(-1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewFTRL(size, DefaultFTRLParams())
			m.W[0] = 0.25 // sentinel to prove rejected blobs leave state untouched
			if err := m.UnmarshalBinary(mut(t, tc.mutate)); err == nil {
				t.Fatal("UnmarshalBinary should reject corrupt value, got nil error")
			}
			if m.W[0] != 0.25 {
				t.Fatalf("rejected blob mutated model state: W[0]=%v, want 0.25", m.W[0])
			}
		})
	}

	// The unmutated control still loads cleanly.
	if err := NewFTRL(size, DefaultFTRLParams()).UnmarshalBinary(blob); err != nil {
		t.Fatalf("UnmarshalBinary on healthy blob: %v", err)
	}
}

func TestFTRL_Convergence(t *testing.T) {
	m := NewFTRL(500, FTRLParams{
		Alpha: 0.1,
		Beta:  1.0,
		L1:    0.1,
		L2:    1.0,
	})

	// Generate two clusters of features that should linearly separate.
	spamFeats := []uint32{10, 11, 12, 13, 14}
	hamFeats := []uint32{20, 21, 22, 23, 24}

	for epoch := 0; epoch < 50; epoch++ {
		m.Update(spamFeats, 1.0)
		m.Update(hamFeats, 0.0)
	}

	if m.Predict(spamFeats) < 0.6 {
		t.Errorf("spam cluster didn't converge: %.4f", m.Predict(spamFeats))
	}
	if m.Predict(hamFeats) > 0.4 {
		t.Errorf("ham cluster didn't converge: %.4f", m.Predict(hamFeats))
	}
}
