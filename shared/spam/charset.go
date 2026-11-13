package spam

import "unicode"

// script ranges for Unicode character classification.
type script int

const (
	scriptLatin    script = iota // Basic Latin, Latin-1 Supplement, Latin Extended
	scriptCJK                    // CJK Unified Ideographs, Hiragana, Katakana, Hangul
	scriptCyrillic               // Cyrillic
	scriptArabic                 // Arabic
	scriptOther                  // Everything else (digits, punctuation, symbols)
)

// DetectMixedCharset checks whether text contains characters from multiple
// writing systems in a way that suggests spam. Legitimate multilingual email
// is typically structured (entire paragraphs in one language). Spam frequently
// mixes scripts within short spans to evade single-script classifiers.
//
// The score is based on:
//   - Number of distinct scripts detected (2 scripts = moderate, 3+ = high)
//   - How imbalanced the script distribution is (small minority = suspicious)
//
// Returns (detected, score). Score range: 0-10.
func DetectMixedCharset(text string) (bool, float64) {
	if len(text) == 0 {
		return false, 0
	}

	// Count meaningful characters per script (skip spaces and punctuation).
	var counts [5]int // indices match script consts above
	total := 0
	for _, r := range text {
		s := classifyRune(r)
		if s == scriptOther {
			continue
		}
		counts[s]++
		total++
	}

	if total < 5 {
		// Too few meaningful characters for reliable detection.
		return false, 0
	}

	// Count how many scripts have meaningful representation.
	scriptCount := 0
	for _, c := range counts {
		if c > 0 {
			scriptCount++
		}
	}

	if scriptCount < 2 {
		return false, 0
	}

	// Base score: 4 per detected script, capped at 8 for 3+ scripts.
	score := float64(scriptCount-1) * 4.0
	if score > 8.0 {
		score = 8.0
	}

	// Imbalance penalty: if one script dominates (>90%), the minority script
	// is likely intentional evasion, not legitimate bilingual text.
	for i := 0; i < len(counts); i++ {
		if counts[i] > 0 {
			ratio := float64(counts[i]) / float64(total)
			if ratio < 0.1 && ratio > 0 {
				score += 2.0
				break // only apply once
			}
		}
	}

	if score > 10.0 {
		score = 10.0
	}

	return true, score
}

// classifyRune maps a rune to a broad script category.
func classifyRune(r rune) script {
	switch {
	// Cyrillic
	case (r >= 0x0400 && r <= 0x04FF) || // Cyrillic
		(r >= 0x0500 && r <= 0x052F): // Cyrillic Supplement
		return scriptCyrillic

	// CJK
	case (r >= 0x4E00 && r <= 0x9FFF) || // CJK Unified Ideographs
		(r >= 0x3400 && r <= 0x4DBF) || // CJK Extension A
		(r >= 0x20000 && r <= 0x2A6DF) || // CJK Extension B
		(r >= 0x3040 && r <= 0x309F) || // Hiragana
		(r >= 0x30A0 && r <= 0x30FF) || // Katakana
		(r >= 0xAC00 && r <= 0xD7AF): // Hangul Syllables
		return scriptCJK

	// Arabic
	case (r >= 0x0600 && r <= 0x06FF) || // Arabic
		(r >= 0x0750 && r <= 0x077F) || // Arabic Supplement
		(r >= 0xFB50 && r <= 0xFDFF) || // Arabic Presentation Forms
		(r >= 0xFE70 && r <= 0xFEFF): // Arabic Presentation Forms B
		return scriptArabic

	// Latin (including Latin-1 Supplement A, Latin Extended A/B, IPA)
	case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
		(r >= 0x00C0 && r <= 0x024F) || // Latin-1 Supplement + Latin Extended A/B
		(r >= 0x1E00 && r <= 0x1EFF): // Latin Extended Additional
		return scriptLatin

	default:
		if unicode.IsLetter(r) {
			return scriptOther
		}
		return scriptOther // digits, punctuation, symbols, whitespace
	}
}
