package jmap

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBlobPureHelpersBoundInputsAndFallbacks(t *testing.T) {
	random := genRandomHex(24)
	if len(random) != 24 {
		t.Fatalf("random hex length = %d, want 24", len(random))
	}
	for _, char := range random {
		if !strings.ContainsRune("0123456789abcdef", char) {
			t.Fatalf("random output contains non-hex character %q", char)
		}
	}

	payload := mustMarshal(map[string]string{"status": "ok"})
	if !json.Valid(payload) || !strings.Contains(string(payload), `"status":"ok"`) {
		t.Fatalf("mustMarshal valid payload = %s", payload)
	}
	if fallback := mustMarshal(make(chan int)); string(fallback) != `{}` {
		t.Fatalf("mustMarshal fallback = %s, want {}", fallback)
	}

	unsafe := "quo\"te\\slash\x00\x1f\x7f.txt"
	if got := sanitizeFilename(unsafe); got != "quoteslash.txt" {
		t.Fatalf("sanitizeFilename(%q) = %q", unsafe, got)
	}
	long := strings.Repeat("a", 300)
	if got := sanitizeFilename(long); len(got) != 255 || got != long[:255] {
		t.Fatalf("long filename length = %d, want a 255-byte prefix", len(got))
	}
}
