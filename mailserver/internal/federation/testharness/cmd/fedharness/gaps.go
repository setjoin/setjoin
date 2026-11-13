package main

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// dialsFirst implements the wiring rule that keeps exactly ONE duplex stream
// per ordered pair: the lexicographically-smaller domain dials, the larger
// one accepts. Both sides evaluate this same pure function independently
// (no coordination), so it must be total and symmetric — local == peer never
// happens in practice (a domain does not federate with itself) but returns
// false (accept) rather than panicking, since "don't dial yourself" is the
// safe default either way.
func dialsFirst(local, peer string) bool {
	return local < peer
}

// computeInboxGaps summarizes a peer's applied federation_inbox peer_seq
// values: count, the observed min/max, and every seq missing from 1..max —
// this is E2's exactly-once + gap-free assertion made mechanical. seqs need
// not be sorted or de-duplicated (federation_inbox's PK already guarantees
// no duplicates, but the function tolerates them defensively — a dup would
// otherwise silently double-count).
func computeInboxGaps(seqs []int64) (count int, minSeq, maxSeq int64, gaps []int64) {
	if len(seqs) == 0 {
		return 0, 0, 0, nil
	}
	have := make(map[int64]bool, len(seqs))
	for _, s := range seqs {
		have[s] = true
	}
	sorted := make([]int64, 0, len(have))
	for s := range have {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	minSeq, maxSeq = sorted[0], sorted[len(sorted)-1]
	for s := int64(1); s <= maxSeq; s++ {
		if !have[s] {
			gaps = append(gaps, s)
		}
	}
	return len(sorted), minSeq, maxSeq, gaps
}

// percentile returns the p-th percentile (0..1) of an already-sorted
// ascending slice via nearest-rank — good enough for a spike's p50/p95
// latency read, not a statistics library.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// enqueuePayload is the ~size-byte JSON body /enqueue and /room/fanout write
// into federation_outbox.payload. EnqueuedAt is the wall-clock read GET
// /latency subtracts federation_inbox.applied_at from to compute p50/p95
// enqueue-commit -> apply latency (the task's "make it measurable" ask —
// simplest form: stash the timestamp in the payload itself rather than a
// second tracking table).
type enqueuePayload struct {
	N          int    `json:"n"`
	EnqueuedAt string `json:"enqueuedAt"`
	Pad        string `json:"pad,omitempty"`
}

// buildPayload marshals an enqueuePayload padded to approximately size bytes
// (0/absent = no padding, just the envelope). Padding is approximate by
// design — the caller asked for "~size bytes", not an exact byte count.
func buildPayload(n, size int) (json.RawMessage, error) {
	p := enqueuePayload{N: n, EnqueuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	base, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if pad := size - len(base); pad > 0 {
		p.Pad = strings.Repeat("x", pad)
		base, err = json.Marshal(p)
		if err != nil {
			return nil, err
		}
	}
	return base, nil
}
