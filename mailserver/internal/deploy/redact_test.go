package deploy

// Shifted-overlap regressions for the exact-secret redaction pass (r2 review
// HOLD, redact.go): regex alternation + ReplaceAllLiteralString consumes only
// NONOVERLAPPING leftmost matches, so secrets "ABCDEF"+"DEFSECRET" against
// output "ABCDEFSECRET" matched [0,6) alone and yielded "[REDACTED]SECRET" —
// the shifted tail of DEFSECRET survived. replaceExactSecrets must redact the
// UNION of overlapping (and adjacent) match intervals from the ORIGINAL text.

import (
	"strings"
	"testing"
)

// TestRedactOutput_ShiftedOverlapLeavesNoTail is the pinned review shape: the
// whole overlapped region must collapse into the sentinel, in either secret
// argument order.
func TestRedactOutput_ShiftedOverlapLeavesNoTail(t *testing.T) {
	for _, secrets := range [][]string{
		{"ABCDEF", "DEFSECRET"},
		{"DEFSECRET", "ABCDEF"},
	} {
		out := RedactOutput("ABCDEFSECRET", secrets...)
		if out != redactionSentinel {
			t.Fatalf("shifted overlap secrets %v: got %q, want exactly %q", secrets, out, redactionSentinel)
		}
		if strings.Contains(out, "SECRET") || strings.Contains(out, "ABCDEF") || strings.Contains(out, "DEF") {
			t.Errorf("shifted overlap secrets %v: leaked fragment in %q", secrets, out)
		}
	}
}

// TestRedactOutput_ShiftedOverlapEmbeddedInOutput: the shifted-overlap region
// embedded in surrounding output is redacted in place — surrounding structure
// survives, exactly one sentinel covers the union, and no fragment of either
// secret (including the leaked "SECRET"/"DEF" tails of the pre-fix behavior)
// remains.
func TestRedactOutput_ShiftedOverlapEmbeddedInOutput(t *testing.T) {
	out := RedactOutput("token=ABCDEFSECRET;tail", "ABCDEF", "DEFSECRET")
	if !strings.HasPrefix(out, "token=") || !strings.HasSuffix(out, ";tail") {
		t.Fatalf("surrounding output not preserved: %q", out)
	}
	if n := strings.Count(out, redactionSentinel); n != 1 {
		t.Fatalf("want exactly one sentinel for one merged region, got %d in %q", n, out)
	}
	for _, frag := range []string{"SECRET", "ABCDEF", "DEFSECRET", "EFSEC"} {
		if strings.Contains(out, frag) {
			t.Errorf("shifted-overlap fragment %q survived: %q", frag, out)
		}
	}
}

// TestRedactOutput_AdjacentSecretsCoalesce: touching (non-overlapping) match
// intervals are one union region — a single sentinel, no boundary fragment.
func TestRedactOutput_AdjacentSecretsCoalesce(t *testing.T) {
	out := RedactOutput("prefixABCDEFsuffix", "ABC", "DEF")
	if out != "prefix"+redactionSentinel+"suffix" {
		t.Fatalf("adjacent secrets = %q, want %q", out, "prefix"+redactionSentinel+"suffix")
	}
}

// TestRedactOutput_ShiftedOverlapMultipleOccurrences: the union applies to
// every occurrence of the overlapping secrets, not just the first.
func TestRedactOutput_ShiftedOverlapMultipleOccurrences(t *testing.T) {
	out := RedactOutput("x ABCDEFSECRET y ABCDEFSECRET z", "ABCDEF", "DEFSECRET")
	if n := strings.Count(out, redactionSentinel); n != 2 {
		t.Fatalf("want 2 sentinels for 2 merged regions, got %d in %q", n, out)
	}
	for _, frag := range []string{"SECRET", "ABCDEF"} {
		if strings.Contains(out, frag) {
			t.Errorf("shifted-overlap fragment %q survived: %q", frag, out)
		}
	}
}

// TestRedactOutput_ShiftedOverlapRealisticSecret pins the regression against
// the package's realistic secret fixtures: two overlapping slices of one
// generated password must redact the whole password everywhere it occurs.
func TestRedactOutput_ShiftedOverlapRealisticSecret(t *testing.T) {
	whole := testPgpPass
	head := testPgpPass[:16]
	tail := testPgpPass[12:]
	out := RedactOutput("err: got password "+whole+" back", head, tail)
	assertNoSecretFragments(t, "shifted real-secret overlap", out, whole)
	if !strings.Contains(out, redactionSentinel) {
		t.Errorf("expected sentinel in %q", out)
	}
}
