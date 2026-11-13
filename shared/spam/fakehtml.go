package spam

import (
	"regexp"
	"strings"
)

// fakeHTMLPatterns matches CSS patterns commonly used in phishing and spam
// to hide text from human readers while keeping it visible to spam classifiers.
// Each pattern maps to a human-readable label describing the technique.
var fakeHTMLPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`(?i)font-size\s*:\s*0\s*(?:px|pt|em|rem)?`), "hidden:text:font-size-zero"},
	{regexp.MustCompile(`(?i)font-size\s*:\s*[12]px`), "hidden:text:tiny-font"},
	{regexp.MustCompile(`(?i)display\s*:\s*none`), "hidden:text:display-none"},
	{regexp.MustCompile(`(?i)color\s*:\s*white`), "hidden:text:white-on-white"},
	{regexp.MustCompile(`(?i)color\s*:\s*#fff(?:fff)?\b`), "hidden:text:white-hex"},
	{regexp.MustCompile(`(?i)opacity\s*:\s*0\b`), "hidden:text:opacity-zero"},
	{regexp.MustCompile(`(?i)visibility\s*:\s*hidden`), "hidden:text:visibility-hidden"},
	{regexp.MustCompile(`(?i)position\s*:\s*absolute\s*;\s*left\s*:\s*-9999px`), "hidden:text:offscreen-left"},
	{regexp.MustCompile(`(?i)position\s*:\s*absolute\s*;\s*left\s*:\s*-10000px`), "hidden:text:offscreen-left"},
	{regexp.MustCompile(`(?i)text-indent\s*:\s*-9999px`), "hidden:text:neg-indent"},
	{regexp.MustCompile(`(?i)width\s*:\s*0\b.*height\s*:\s*0\b`), "hidden:text:zero-size"},
	{regexp.MustCompile(`(?i)height\s*:\s*0\b.*width\s*:\s*0\b`), "hidden:text:zero-size"},
}

// DetectFakeHTML scans an HTML body for common phishing and spam concealment
// techniques. It detects hidden text patterns such as:
//   - font-size:0 (text rendered at zero height)
//   - display:none (text hidden from rendering)
//   - color:white on white backgrounds
//   - opacity:0 (fully transparent)
//   - visibility:hidden
//   - offscreen positioning (left:-9999px)
//
// Returns (detected, patterns) where patterns is a list of technique labels
// found in the HTML. Each distinct technique is reported only once.
func DetectFakeHTML(htmlBody string) (bool, []string) {
	if htmlBody == "" {
		return false, nil
	}

	seen := make(map[string]bool)
	var patterns []string

	for _, p := range fakeHTMLPatterns {
		if p.re.MatchString(htmlBody) && !seen[p.label] {
			seen[p.label] = true
			patterns = append(patterns, p.label)
		}
	}

	return len(patterns) > 0, patterns
}

// DetectFakeHTMLScore is a convenience wrapper that returns a numerical score
// (0-10) instead of pattern labels. Each detected technique adds 2.5 points.
func DetectFakeHTMLScore(htmlBody string) float64 {
	fake, patterns := DetectFakeHTML(htmlBody)
	if !fake {
		return 0
	}
	score := float64(len(patterns)) * 2.5
	if score > 10.0 {
		score = 10.0
	}
	return score
}

// suppress unused import warning
var _ = strings.TrimSpace
