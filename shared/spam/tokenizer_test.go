package spam

import (
	"strings"
	"testing"
)

func TestOSBTokenize_English(t *testing.T) {
	tokens := OSBTokenize("buy cheap viagra now free")
	if len(tokens) == 0 {
		t.Error("expected tokens for English text")
	}
	for _, tok := range tokens {
		if !strings.Contains(tok, "-") {
			t.Errorf("expected bigram containing '-', got %q", tok)
		}
	}
	// Verify specific expected bigrams exist
	seen := make(map[string]bool)
	for _, tok := range tokens {
		seen[tok] = true
	}
	expected := []string{"buy-cheap", "buy-viagra", "cheap-viagra"}
	for _, e := range expected {
		if !seen[e] {
			t.Errorf("expected bigram %q not found in tokens: %v", e, tokens)
		}
	}
}

func TestOSBTokenize_Chinese(t *testing.T) {
	tokens := OSBTokenize("购买伟哥现在便宜")
	if len(tokens) == 0 {
		t.Error("expected tokens for Chinese text")
	}
	// Each CJK character becomes its own token, then bigrams are formed
	seen := make(map[string]bool)
	for _, tok := range tokens {
		seen[tok] = true
		if !strings.Contains(tok, "-") {
			t.Errorf("expected bigram containing '-', got %q", tok)
		}
	}
	// Should contain character-pair bigrams
	if len(tokens) < 4 {
		t.Errorf("expected at least 4 bigrams for 5-char Chinese text, got %d: %v", len(tokens), tokens)
	}
}

func TestOSBTokenize_MixedCJKAndLatin(t *testing.T) {
	tokens := OSBTokenize("hello 世界 welcome")
	if len(tokens) == 0 {
		t.Error("expected tokens for mixed CJK+Latin text")
	}
	seen := make(map[string]bool)
	for _, tok := range tokens {
		seen[tok] = true
	}
	// Should have tokens for both "hello", "世界" (as two chars), "welcome"
	// Bigrams should bridge Latin and CJK tokens
	if !seen["hello-世"] && !seen["hello-界"] {
		t.Errorf("expected cross-script bigram for 'hello' and CJK chars: %v", tokens)
	}
}

func TestOSBTokenize_Empty(t *testing.T) {
	tokens := OSBTokenize("")
	if len(tokens) != 0 {
		t.Errorf("expected no tokens for empty string, got %d: %v", len(tokens), tokens)
	}
}

func TestOSBTokenize_SingleWord(t *testing.T) {
	tokens := OSBTokenize("hello")
	// Single word: no bigrams possible since we need at least 2 tokens.
	// The tokenizer may return the single token with no bigram partner.
	if len(tokens) > 0 {
		// If tokens are returned, they should be the word itself (no dash)
		for _, tok := range tokens {
			if strings.Contains(tok, "-") {
				t.Errorf("single word should not produce bigrams, got %q", tok)
			}
		}
	}
}

func TestOSBTokenize_SingleCJKChar(t *testing.T) {
	tokens := OSBTokenize("中")
	if len(tokens) == 0 {
		t.Error("expected at least the single CJK char token")
	}
}

func TestOSBTokenize_Japanese(t *testing.T) {
	tokens := OSBTokenize("これはテストです")
	if len(tokens) == 0 {
		t.Error("expected tokens for Japanese text")
	}
	// Hiragana characters should each be individual tokens
	if len(tokens) < 3 {
		t.Errorf("expected at least 3 bigrams for 7-char Japanese text, got %d: %v", len(tokens), tokens)
	}
}

func TestOSBTokenize_Korean(t *testing.T) {
	tokens := OSBTokenize("안녕하세요 감사합니다")
	if len(tokens) == 0 {
		t.Error("expected tokens for Korean text")
	}
	// Hangul syllables should each be individual tokens
	for _, tok := range tokens {
		if !strings.Contains(tok, "-") {
			t.Errorf("expected bigram containing '-', got %q", tok)
		}
	}
}

func TestOSBTokenize_PunctuationSkipped(t *testing.T) {
	tokens := OSBTokenize("hello, world! how are you?")
	// Punctuation should be stripped, leaving only word tokens
	for _, tok := range tokens {
		// Bigrams should not contain punctuation
		if strings.ContainsAny(tok, ",!?") {
			t.Errorf("bigram should not contain punctuation: %q", tok)
		}
	}
}

func TestOSBTokenize_DuplicateBigrams(t *testing.T) {
	tokens := OSBTokenize("spam spam spam spam spam")
	// Duplicate bigrams should be deduplicated
	seen := make(map[string]int)
	for _, tok := range tokens {
		seen[tok]++
	}
	for tok, count := range seen {
		if count > 1 {
			t.Errorf("duplicate bigram %q appears %d times", tok, count)
		}
	}
}

func TestOSBTokenize_WindowSize(t *testing.T) {
	// With a window of 5, tokens beyond position+5 should NOT form bigrams.
	// 10 tokens = "a b c d e f g h i j"
	text := "one two three four five six seven eight nine ten"
	tokens := OSBTokenize(text)
	// "one" and "ten" are 9 positions apart → should NOT form a bigram
	// because window=5 means only tokens within 5 positions pair up
	farBigram := "one-ten"
	for _, tok := range tokens {
		if tok == farBigram {
			t.Errorf("tokens 9 positions apart should not form bigram with window=5: %q", tok)
		}
	}
	// "one" and "five" are 4 positions apart → should form a bigram
	nearBigram := "one-five"
	found := false
	for _, tok := range tokens {
		if tok == nearBigram {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected bigram %q for tokens 4 apart (within window=5)", nearBigram)
	}
}
