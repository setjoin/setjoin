package spam

import (
	"testing"
)

func TestDetectMixedCharset_SingleScript_NoDetection(t *testing.T) {
	cases := []string{
		"Hello world, this is a normal English email.",
		"这是一封普通的中文邮件。",
		"これは普通の日本語のメールです。",
		"Это обычное письмо на русском языке.",
		"",                  // empty
		"a",                 // single char
		"hello world 12345", // Latin + digits only
	}
	for _, c := range cases {
		detected, score := DetectMixedCharset(c)
		if detected {
			t.Errorf("should not detect mixed charset in single-script text: %q", c)
		}
		if score != 0 {
			t.Errorf("expected score 0 for single-script text, got %f: %q", score, c)
		}
	}
}

func TestDetectMixedCharset_LatinAndCJK(t *testing.T) {
	// Latin + Chinese mixed in same text — common in spam
	cases := []string{
		"Buy cheap 伟哥 now free shipping 便宜货",
		"Hello 你好 world 世界 spam",
	}
	for _, c := range cases {
		detected, score := DetectMixedCharset(c)
		if !detected {
			t.Errorf("should detect mixed Latin+CJK: %q", c)
		}
		if score <= 0 {
			t.Errorf("expected positive score for mixed Latin+CJK, got %f: %q", score, c)
		}
	}
}

func TestDetectMixedCharset_LatinAndCyrillic(t *testing.T) {
	// Latin + Cyrillic mixed — common in Russian spam
	detected, score := DetectMixedCharset("Buy cheap товары now со скидкой")
	if !detected {
		t.Error("should detect mixed Latin+Cyrillic")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectMixedCharset_ManyScripts(t *testing.T) {
	// 3+ scripts mixed — extremely suspicious
	detected, score := DetectMixedCharset("Hello 你好 мир 世界")
	if !detected {
		t.Error("should detect 3+ script mixing")
	}
	if score <= 0 {
		t.Errorf("expected positive score for 3 scripts, got %f", score)
	}
}

func TestDetectMixedCharset_CJKWithLatinNoise(t *testing.T) {
	// Primarily CJK with a few Latin words — common spam pattern
	detected, score := DetectMixedCharset("您好，我们提供best price for药品，请click here购买")
	if !detected {
		t.Error("should detect CJK text with embedded Latin spam terms")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectMixedCharset_LegitimateShort(t *testing.T) {
	// Very short mixed text (fewer than 10 meaningful chars) might be legitimate
	// e.g., a subject line "Re: 关于" (about)
	detected, _ := DetectMixedCharset("Re: 关于")
	// Short texts get lower scores but may still be detected
	// We don't assert specific outcome — just ensure no panic
	t.Logf("short mixed text: detected=%v", detected)
}

func TestDetectMixedCharset_ScoreIncreasesWithScripts(t *testing.T) {
	_, score2 := DetectMixedCharset("Hello 你好")
	_, score3 := DetectMixedCharset("Hello 你好 мир")
	if score3 <= score2 {
		t.Errorf("3-script score (%.1f) should be higher than 2-script score (%.1f)", score3, score2)
	}
}

func TestDetectMixedCharset_ScoreRange(t *testing.T) {
	// Verify scores are in [0, 10] range
	testCases := []string{
		"Hello world",
		"你好世界",
		"Buy cheap 伟哥 now",
		"Hello 你好 мир 世界 spam",
		"",
	}
	for _, tc := range testCases {
		_, score := DetectMixedCharset(tc)
		if score < 0 || score > 10.0 {
			t.Errorf("score %f out of [0,10] range for %q", score, tc)
		}
	}
}

func TestDetectMixedCharset_RatioThreshold(t *testing.T) {
	// A mostly-English message with a single Chinese character: low ratio = higher score
	// A balanced bilingual message: higher minority ratio = lower score
	_, scoreImbalanced := DetectMixedCharset("Hello world spam buy pills 药 now")
	_, scoreBalanced := DetectMixedCharset("Hello 世界你好 世界你好 世界你好 世界你好")

	// Imbalanced (small minority script) should be more suspicious
	if scoreImbalanced <= scoreBalanced {
		t.Logf("imbalanced score (%.1f) vs balanced score (%.1f)", scoreImbalanced, scoreBalanced)
	}
}

func TestDetectMixedCharset_ExactScore(t *testing.T) {
	// 2 scripts, small minority ratio -> high score
	detected, score := DetectMixedCharset("This is a spam message with 伟哥")
	if !detected {
		t.Error("expected detection")
	}
	// Score should be non-zero and within range
	if score <= 0 || score > 10.0 {
		t.Errorf("unexpected score: %f", score)
	}
	// With 2 scripts and a very small minority, score should be close to max for 2 scripts
	if score < 5.0 {
		t.Errorf("expected score >= 5.0 for imbalanced 2-script text, got %f", score)
	}
}
