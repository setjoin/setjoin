package drive

import "testing"

// TestChunkRange pins the O(1) offset->ordinal math (spec §3.1): fixed 4 MiB
// chunks, so ordinal = floor(offset/chunkSize), no scan required.
func TestChunkRange(t *testing.T) {
	for _, tc := range []struct {
		offset      int64
		wantOrdinal int64
		wantSkip    int64
	}{
		{0, 0, 0},
		{4194303, 0, 4194303},          // last byte of chunk 0
		{4194304, 1, 0},                // first byte of chunk 1
		{10 * 1024 * 1024, 2, 2097152}, // 10 MiB into a 3rd (index 2) chunk
	} {
		gotOrdinal, gotSkip := chunkRange(tc.offset, driveChunkSize)
		if gotOrdinal != tc.wantOrdinal || gotSkip != tc.wantSkip {
			t.Errorf("chunkRange(%d) = (%d,%d), want (%d,%d)", tc.offset, gotOrdinal, gotSkip, tc.wantOrdinal, tc.wantSkip)
		}
	}
}

func TestParseSingleRange(t *testing.T) {
	const size = 10_000_000
	for _, tc := range []struct {
		name      string
		header    string
		wantStart int64
		wantEnd   int64
		wantOK    bool
	}{
		{"start-end", "bytes=4194300-4194310", 4194300, 4194310, true},
		{"open-ended", "bytes=100-", 100, size - 1, true},
		{"end clamped to size", "bytes=0-999999999", 0, size - 1, true},
		{"multipart rejected", "bytes=0-10,20-30", 0, 0, false},
		{"suffix form rejected", "bytes=-500", 0, 0, false},
		{"no bytes= prefix", "0-10", 0, 0, false},
		{"start beyond size", "bytes=99999999-", 0, 0, false},
		{"end before start", "bytes=100-50", 0, 0, false},
		{"garbage", "bytes=abc-def", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd, ok := parseSingleRange(tc.header, size)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if gotStart != tc.wantStart || gotEnd != tc.wantEnd {
				t.Errorf("= (%d,%d), want (%d,%d)", gotStart, gotEnd, tc.wantStart, tc.wantEnd)
			}
		})
	}
}
