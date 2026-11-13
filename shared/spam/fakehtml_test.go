package spam

import (
	"strings"
	"testing"
)

func TestDetectFakeHTML_NoIssues(t *testing.T) {
	html := "<html><body><p>Hello world</p></body></html>"
	fake, patterns := DetectFakeHTML(html)
	if fake {
		t.Errorf("clean HTML should not be detected as fake: patterns=%v", patterns)
	}
}

func TestDetectFakeHTML_FontSizeZero(t *testing.T) {
	cases := []string{
		`<span style="font-size:0">hidden text</span>`,
		`<span style="font-size: 0px">hidden</span>`,
		`<div style="font-size:0pt">invisible</div>`,
	}
	for _, c := range cases {
		fake, patterns := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect font-size:0 as fake HTML: %q", c)
		}
		found := false
		for _, p := range patterns {
			if strings.Contains(p, "font-size") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("patterns should mention font-size: %v", patterns)
		}
	}
}

func TestDetectFakeHTML_DisplayNone(t *testing.T) {
	cases := []string{
		`<div style="display:none">hidden</div>`,
		`<div style="display: none">hidden</div>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect display:none as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_ColorWhite(t *testing.T) {
	cases := []string{
		`<span style="color:white">hidden text</span>`,
		`<span style="color: white">hidden</span>`,
		`<span style="color:#ffffff">hidden</span>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect color:white as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_OpacityZero(t *testing.T) {
	cases := []string{
		`<div style="opacity:0">invisible</div>`,
		`<div style="opacity: 0">invisible</div>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect opacity:0 as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_VisibilityHidden(t *testing.T) {
	cases := []string{
		`<div style="visibility:hidden">hidden</div>`,
		`<div style="visibility: hidden">hidden</div>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect visibility:hidden as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_PositionOffscreen(t *testing.T) {
	cases := []string{
		`<div style="position:absolute;left:-9999px">offscreen</div>`,
		`<span style="position: absolute; left: -9999px">hidden</span>`,
		`<div style="position:absolute;left:-10000px">hidden</div>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect offscreen positioning as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_TinyText(t *testing.T) {
	cases := []string{
		`<span style="font-size:1px">tiny</span>`,
		`<span style="font-size: 2px">tiny</span>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect tiny font-size as fake HTML: %q", c)
		}
	}
}

func TestDetectFakeHTML_MultiplePatterns(t *testing.T) {
	html := `<html><body>
		<span style="font-size:0;color:white">hidden text</span>
		<div style="display:none">more hidden</div>
	</body></html>`
	fake, patterns := DetectFakeHTML(html)
	if !fake {
		t.Error("should detect multiple fake HTML patterns")
	}
	if len(patterns) < 2 {
		t.Errorf("expected at least 2 patterns, got %d: %v", len(patterns), patterns)
	}
}

func TestDetectFakeHTML_CaseInsensitive(t *testing.T) {
	cases := []string{
		`<span style="FONT-SIZE:0">hidden</span>`,
		`<div style="DISPLAY:NONE">hidden</div>`,
		`<span style="COLOR:WHITE">hidden</span>`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		if !fake {
			t.Errorf("should detect fake HTML regardless of case: %q", c)
		}
	}
}

func TestDetectFakeHTML_EmptyText(t *testing.T) {
	fake, patterns := DetectFakeHTML("")
	if fake {
		t.Errorf("empty HTML should not be detected: patterns=%v", patterns)
	}
}

func TestDetectFakeHTML_NoRepeatedPatterns(t *testing.T) {
	// Same pattern appearing multiple times should only be reported once
	html := `<div style="display:none">a</div><div style="display:none">b</div>`
	fake, patterns := DetectFakeHTML(html)
	if !fake {
		t.Error("should detect display:none")
	}
	count := 0
	for _, p := range patterns {
		if strings.Contains(p, "display") {
			count++
		}
	}
	if count > 1 {
		t.Errorf("display:none should only be reported once, got %d occurrences in %v", count, patterns)
	}
}

func TestDetectFakeHTML_PhishingCRLFInjection(t *testing.T) {
	// CRLF injection in headers is a phishing technique
	cases := []string{
		`<div style="text-align:center;font-family:Arial">`,
	}
	for _, c := range cases {
		fake, _ := DetectFakeHTML(c)
		// Normal styles should not trigger detection
		if fake {
			t.Errorf("normal CSS should not be detected as fake: %q", c)
		}
	}
}
