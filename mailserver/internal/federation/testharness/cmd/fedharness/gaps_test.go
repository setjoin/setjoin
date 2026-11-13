package main

import (
	"encoding/json"
	"testing"
)

func TestDialsFirst(t *testing.T) {
	cases := []struct {
		local, peer string
		want        bool
	}{
		{"alpha.test", "bravo.test", true},   // alpha < bravo -> alpha dials
		{"bravo.test", "alpha.test", false},  // bravo > alpha -> bravo accepts
		{"alpha.test", "charlie.test", true}, // alpha < charlie -> alpha dials
		{"charlie.test", "bravo.test", false},
	}
	for _, c := range cases {
		if got := dialsFirst(c.local, c.peer); got != c.want {
			t.Errorf("dialsFirst(%q,%q) = %v, want %v", c.local, c.peer, got, c.want)
		}
	}
	// Exactly one side of every ordered pair dials — the other accepts.
	for _, c := range cases {
		if dialsFirst(c.local, c.peer) == dialsFirst(c.peer, c.local) {
			t.Errorf("dialsFirst(%q,%q) and its reverse must disagree (no double-dial, no double-skip)", c.local, c.peer)
		}
	}
}

func TestComputeInboxGapsEmpty(t *testing.T) {
	count, minSeq, maxSeq, gaps := computeInboxGaps(nil)
	if count != 0 || minSeq != 0 || maxSeq != 0 || gaps != nil {
		t.Fatalf("empty input: got (%d,%d,%d,%v), want (0,0,0,nil)", count, minSeq, maxSeq, gaps)
	}
}

func TestComputeInboxGapsNoGaps(t *testing.T) {
	seqs := []int64{3, 1, 2, 5, 4}
	count, minSeq, maxSeq, gaps := computeInboxGaps(seqs)
	if count != 5 || minSeq != 1 || maxSeq != 5 || len(gaps) != 0 {
		t.Fatalf("got (%d,%d,%d,%v), want (5,1,5,[])", count, minSeq, maxSeq, gaps)
	}
}

func TestComputeInboxGapsWithGaps(t *testing.T) {
	seqs := []int64{1, 2, 5, 7}
	count, minSeq, maxSeq, gaps := computeInboxGaps(seqs)
	if count != 4 || minSeq != 1 || maxSeq != 7 {
		t.Fatalf("got count=%d min=%d max=%d, want 4,1,7", count, minSeq, maxSeq)
	}
	want := []int64{3, 4, 6}
	if len(gaps) != len(want) {
		t.Fatalf("gaps=%v, want %v", gaps, want)
	}
	for i, g := range want {
		if gaps[i] != g {
			t.Fatalf("gaps=%v, want %v", gaps, want)
		}
	}
}

func TestComputeInboxGapsDuplicatesDoNotDoubleCount(t *testing.T) {
	seqs := []int64{1, 1, 2, 2, 3}
	count, _, maxSeq, gaps := computeInboxGaps(seqs)
	if count != 3 || maxSeq != 3 || len(gaps) != 0 {
		t.Fatalf("got count=%d max=%d gaps=%v, want 3,3,[]", count, maxSeq, gaps)
	}
}

func TestPercentile(t *testing.T) {
	sorted := []float64{10, 20, 30, 40, 50}
	if got := percentile(sorted, 0); got != 10 {
		t.Errorf("p0 = %v, want 10", got)
	}
	if got := percentile(sorted, 1); got != 50 {
		t.Errorf("p100 = %v, want 50", got)
	}
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("percentile(nil) = %v, want 0", got)
	}
}

func TestBuildPayloadValidJSONAndSize(t *testing.T) {
	body, err := buildPayload(7, 500)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	if len(body) < 500 {
		t.Errorf("body len %d < requested size 500", len(body))
	}
	var p enqueuePayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.N != 7 {
		t.Errorf("N = %d, want 7", p.N)
	}
	if p.EnqueuedAt == "" {
		t.Error("EnqueuedAt is empty")
	}
}

func TestBuildPayloadNoPadWhenSizeZero(t *testing.T) {
	body, err := buildPayload(1, 0)
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var p enqueuePayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Pad != "" {
		t.Errorf("Pad = %q, want empty when size=0", p.Pad)
	}
}
