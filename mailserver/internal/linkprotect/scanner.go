package linkprotect

import (
	"context"
)

// Verdict is the threat assessment for a URL.
type Verdict int

const (
	VerdictSafe      Verdict = iota // URL is known-safe
	VerdictMalicious                // URL is known-malicious (block)
	VerdictUnknown                  // URL could not be classified (warn or block in strict mode)
)

// String returns a human-readable verdict name.
func (v Verdict) String() string {
	switch v {
	case VerdictSafe:
		return "safe"
	case VerdictMalicious:
		return "malicious"
	case VerdictUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Scanner checks a URL for threats. Registered in priority order.
type Scanner interface {
	Name() string
	Check(ctx context.Context, url string) (Verdict, error)
}

// ScanPipeline runs scanners in order against a URL.
// - First malicious verdict short-circuits (remaining scanners skipped).
// - All safe → safe.
// - Any unknown (and no malicious) → unknown.
// - All errors → unknown + allErrors=true (passthrough — never block on third-party outage).
// Returns the final verdict, per-scanner results, and whether all results were due to errors.
func ScanPipeline(ctx context.Context, scanners []Scanner, url string) (Verdict, map[string]Verdict, bool) {
	results := make(map[string]Verdict, len(scanners))
	hasUnknown := false
	allErrors := true

	for _, s := range scanners {
		v, err := s.Check(ctx, url)
		if err != nil {
			results[s.Name()] = VerdictUnknown
			hasUnknown = true
			continue
		}
		allErrors = false
		results[s.Name()] = v

		if v == VerdictMalicious {
			return VerdictMalicious, results, false
		}
		if v == VerdictUnknown {
			hasUnknown = true
		}
	}

	if len(scanners) == 0 {
		return VerdictSafe, results, false
	}

	if allErrors {
		return VerdictUnknown, results, true
	}
	if hasUnknown {
		return VerdictUnknown, results, false
	}
	return VerdictSafe, results, false
}
