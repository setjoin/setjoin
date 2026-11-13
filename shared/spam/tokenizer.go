package spam

import "unicode"

// OSBTokenize implements Orthogonal Sparse Bigrams (OSB) — rspamd's language-agnostic
// tokenizer. It works identically on English, Chinese, Japanese, Korean, and mixed text.
//
// Algorithm:
//  1. Split text into tokens: each CJK character is its own token; Latin words are
//     split on whitespace/punctuation boundaries.
//  2. Generate sparse bigrams within a sliding window: for each token at position i,
//     pair it with tokens at positions i+1 through i+window-1.
//  3. Deduplicate bigrams (each appears at most once in the result).
//
// The result is a set of "token1-token2" strings suitable for hashing into FTRL
// feature indices or direct use as feature names.
func OSBTokenize(text string) []string {
	tokens := extractTokens(text)
	if len(tokens) < 2 {
		return tokens
	}
	return slidingBigrams(tokens, 5)
}

// extractTokens splits text into tokens. Each CJK character (including Hiragana,
// Katakana, Hangul) is its own token. Latin words are split on whitespace and
// punctuation boundaries.
func extractTokens(text string) []string {
	var tokens []string
	var current []rune

	for _, r := range text {
		if unicode.IsSpace(r) || isPunct(r) {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = nil
			}
			continue
		}
		if isCJK(r) {
			if len(current) > 0 {
				tokens = append(tokens, string(current))
				current = nil
			}
			tokens = append(tokens, string(r))
			continue
		}
		current = append(current, r)
	}
	if len(current) > 0 {
		tokens = append(tokens, string(current))
	}
	return tokens
}

// slidingBigrams generates sparse bigrams within a sliding window.
// For each token at position i, pairs it with every token at position j
// where i < j < i+window. Results are deduplicated.
func slidingBigrams(tokens []string, window int) []string {
	seen := make(map[string]bool)
	var result []string
	for i := 0; i < len(tokens); i++ {
		end := i + window
		if end > len(tokens) {
			end = len(tokens)
		}
		for j := i + 1; j < end; j++ {
			bigram := tokens[i] + "-" + tokens[j]
			if !seen[bigram] {
				seen[bigram] = true
				result = append(result, bigram)
			}
		}
	}
	return result
}

// isCJK returns true for CJK Unified Ideographs, Hiragana, Katakana, and Hangul.
func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || // CJK Unified Ideographs
		(r >= 0x3400 && r <= 0x4DBF) || // CJK Unified Extension A
		(r >= 0x20000 && r <= 0x2A6DF) || // CJK Unified Extension B
		(r >= 0x3040 && r <= 0x309F) || // Hiragana
		(r >= 0x30A0 && r <= 0x30FF) || // Katakana
		(r >= 0xAC00 && r <= 0xD7AF) // Hangul Syllables
}

// isPunct returns true for punctuation and symbol characters.
func isPunct(r rune) bool {
	return unicode.IsPunct(r) || unicode.IsSymbol(r)
}
