package spam

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

func TestStructureHash_IdenticalHTML(t *testing.T) {
	html1 := `<html><head><title>Login</title></head><body><div class="container"><h1>Welcome</h1><p>Please login</p></div></body></html>`
	html2 := `<html><head><title>Login</title></head><body><div class="container"><h1>Welcome</h1><p>Please login</p></div></body></html>`

	h1 := StructureHash(html1)
	h2 := StructureHash(html2)

	if h1 == "" {
		t.Error("hash should not be empty")
	}
	if h1 != h2 {
		t.Errorf("identical HTML should produce identical structure hash: %s vs %s", h1, h2)
	}
}

func TestStructureHash_SameStructure_DifferentContent(t *testing.T) {
	// Same DOM structure, different text content → same hash.
	html1 := `<html><body><div><h1>Welcome to Bank of America</h1><p>Enter your password</p></div></body></html>`
	html2 := `<html><body><div><h1>Hello John Smith</h1><p>Your order is confirmed</p></div></body></html>`

	h1 := StructureHash(html1)
	h2 := StructureHash(html2)

	if h1 != h2 {
		t.Errorf("identical structure with different text should produce same hash: %s vs %s", h1, h2)
	}
}

func TestStructureHash_DifferentStructure(t *testing.T) {
	html1 := `<html><body><div><h1>Title</h1><p>Text</p></div></body></html>`
	html2 := `<html><body><table><tr><td>Cell</td></tr></table></body></html>`

	h1 := StructureHash(html1)
	h2 := StructureHash(html2)

	if h1 == h2 {
		t.Errorf("different HTML structures should produce different hashes: %s", h1)
	}
}

func TestStructureHash_AttributeValuesIgnored(t *testing.T) {
	// Same structure, different attribute values → same hash.
	html1 := `<html><body><div class="login-box" id="box1"><a href="/login">Login</a></div></body></html>`
	html2 := `<html><body><div class="login-box" id="box2"><a href="/phishing">Login</a></div></body></html>`

	h1 := StructureHash(html1)
	h2 := StructureHash(html2)

	if h1 != h2 {
		t.Errorf("same structure with different attr values should match: %s vs %s", h1, h2)
	}
}

func TestStructureHash_AttributeNamesMatter(t *testing.T) {
	// Elements with class attributes vs without → different structure.
	html1 := `<html><body><div class="container"><p>Text</p></div></body></html>`
	html2 := `<html><body><div><p>Text</p></div></body></html>`

	h1 := StructureHash(html1)
	h2 := StructureHash(html2)

	if h1 == h2 {
		t.Errorf("div with class vs without should produce different hashes: %s", h1)
	}
}

func TestStructureHash_Empty(t *testing.T) {
	h := StructureHash("")
	if h != "" {
		t.Errorf("empty HTML should produce empty hash, got %s", h)
	}
}

func TestStructureHash_MalformedHTML(t *testing.T) {
	// Malformed HTML should still produce a hash (the parser recovers).
	h := StructureHash("<html><body><p>unclosed paragraph</body></html>")
	if h == "" {
		t.Error("malformed HTML should still produce a structure hash")
	}
}

func TestStructureHash_MinimalHTML(t *testing.T) {
	h := StructureHash("<p>Hello</p>")
	if h == "" {
		t.Error("minimal HTML should produce a hash")
	}
}

func TestStructureHash_PhishingVsLegitimate(t *testing.T) {
	// Phishing template that copies a legitimate login page structure.
	legit := `
<html>
<head><title>Sign In</title></head>
<body>
  <div class="login-container" id="login">
    <form class="login-form">
      <input class="email-input" type="email">
      <input class="password-input" type="password">
      <button class="submit-btn" type="submit">Sign In</button>
    </form>
    <div class="footer-links">
      <a class="forgot-link">Forgot password?</a>
    </div>
  </div>
</body>
</html>`

	phish := `
<html>
<head><title>Sign In - Microsoft</title></head>
<body>
  <div class="login-container" id="login">
    <form class="login-form">
      <input class="email-input" type="email" placeholder="you@company.com">
      <input class="password-input" type="password">
      <button class="submit-btn" type="submit">Sign In</button>
    </form>
    <div class="footer-links">
      <a class="forgot-link">Can't access your account?</a>
    </div>
  </div>
</body>
</html>`

	h1 := StructureHash(legit)
	h2 := StructureHash(phish)

	if h1 != h2 {
		t.Errorf("phishing copy of legitimate template should have same structure hash: %s vs %s", h1, h2)
	}
}

func TestStructureHash_Deterministic(t *testing.T) {
	html := `<html><body><div class="a"><span>hello</span></div></body></html>`

	h1 := StructureHash(html)
	h2 := StructureHash(html)
	h3 := StructureHash(html)

	if h1 != h2 || h2 != h3 {
		t.Error("StructureHash should be deterministic")
	}
}

func TestIsKnownPhishing_Match(t *testing.T) {
	templates := map[string]string{
		"abc123def456789001234567890abcd": "Microsoft 365 Login Phishing",
		"def7890123456abc01234567890abcd": "DocuSign Envelope Phishing",
	}

	found, name := IsKnownPhishing("abc123def456789001234567890abcd", templates)
	if !found {
		t.Error("expected match for known phishing template")
	}
	if name != "Microsoft 365 Login Phishing" {
		t.Errorf("expected 'Microsoft 365 Login Phishing', got %q", name)
	}
}

func TestIsKnownPhishing_NoMatch(t *testing.T) {
	templates := map[string]string{
		"abc123": "Known Phish",
	}

	found, name := IsKnownPhishing("unknown_hash", templates)
	if found {
		t.Error("expected no match for unknown hash")
	}
	if name != "" {
		t.Errorf("expected empty name, got %q", name)
	}
}

func TestIsKnownPhishing_EmptyTemplates(t *testing.T) {
	found, name := IsKnownPhishing("somehash", nil)
	if found {
		t.Error("expected no match with nil templates")
	}
	if name != "" {
		t.Errorf("expected empty name, got %q", name)
	}
}

func TestStructureHash_ScriptTags(t *testing.T) {
	html := `<html><body><script>alert('hello')</script><p>text</p></body></html>`
	h := StructureHash(html)
	if h == "" {
		t.Error("HTML with script tags should produce a hash")
	}
}

func TestStructureHash_StyleTags(t *testing.T) {
	html := `<html><head><style>.red { color: red; }</style></head><body><p class="red">text</p></body></html>`
	h := StructureHash(html)
	if h == "" {
		t.Error("HTML with style tags should produce a hash")
	}
}

// --- Golden hash continuity ---
//
// These literals were captured from the original recursive extractor at
// HEAD (git 98bdb647 lineage) immediately before the iterative rewrite.
// The iterative walk must serialize byte-identically, so every fixture
// below must keep hashing to exactly these values. Any change here means
// the serialization changed — golden continuity broken.

func TestStructureHash_GoldenContinuity(t *testing.T) {
	goldens := []struct {
		name string
		html string
		want string
	}{
		{"identical", `<html><head><title>Login</title></head><body><div class="container"><h1>Welcome</h1><p>Please login</p></div></body></html>`, "e276b1f810ec1976ad20ba7aae1afe78"},
		{"diffstruct1", `<html><body><div><h1>Title</h1><p>Text</p></div></body></html>`, "afc3a82bc59be8f1242a92875e00acd0"},
		{"diffstruct2", `<html><body><table><tr><td>Cell</td></tr></table></body></html>`, "0986f690e49a865eb497e92aa3a984e7"},
		{"attrs", `<html><body><div class="login-box" id="box1"><a href="/login">Login</a></div></body></html>`, "4c55034e95364506684493f433ccc8b7"},
		{"minimal", `<p>Hello</p>`, "36c7d9ad601eb4278ce4a42a1b5bf8c7"},
		// Astra L2-C7: doctype-bearing input must hash identically to its
		// doctype-free form. The original recursive serializer omitted empty
		// child serializations (`if s != ""`), so a doctype contributed no
		// bytes. The iterative walker folded the empty doctype serialization
		// into the document frame, and strings.Join emitted a leading
		// separator — adding <!doctype html> shifted this established hash
		// from 36c7… to 14f6….
		{"doctype", `<!doctype html><p>Hello</p>`, "36c7d9ad601eb4278ce4a42a1b5bf8c7"},
		{"malformed", `<html><body><p>unclosed paragraph</body></html>`, "36c7d9ad601eb4278ce4a42a1b5bf8c7"},
		{"script", `<html><body><script>alert('hello')</script><p>text</p></body></html>`, "6629dece6b048a4f02f64d5c5b549505"},
		{"style", `<html><head><style>.red { color: red; }</style></head><body><p class="red">text</p></body></html>`, "a88e68474a6137df63ef9079683886a3"},
		{"det", `<html><body><div class="a"><span>hello</span></div></body></html>`, "57a9313c1b6273ba4991731766bfba1f"},
		{"phishlegit", "<html>\n<head><title>Sign In</title></head>\n<body>\n  <div class=\"login-container\" id=\"login\">\n    <form class=\"login-form\">\n      <input class=\"email-input\" type=\"email\">\n      <input class=\"password-input\" type=\"password\">\n      <button class=\"submit-btn\" type=\"submit\">Sign In</button>\n    </form>\n    <div class=\"footer-links\">\n      <a class=\"forgot-link\">Forgot password?</a>\n    </div>\n  </div>\n</body>\n</html>", "1fb9cfdc0539306f29fd7a0d6f50cc1d"},
		{"plain_text", "just some text, no tags", "394bdf4ea35fbd1da49ec9bcf177ed48"},
		// Comment-only / whitespace input still hashes: the parser
		// synthesizes html/body, so the structure is "(html (body))".
		{"comment_only", "<!-- hello world -->", "dcb489c51b1c02ba9f363891de1cddeb"},
		{"ws_only", "   ", "dcb489c51b1c02ba9f363891de1cddeb"},
		{"deep505", nestDivs(505), "22e57c49c30a9c4ee8325f69a2c461c7"},
		{"deep50", nestDivs(50), "7e3c611dc22f65042abd1a6b4aa027f8"},
	}
	for _, g := range goldens {
		if got := StructureHash(g.html); got != g.want {
			t.Errorf("%s: golden hash drifted: got %s, want %s", g.name, got, g.want)
		}
	}
}

// nestDivs builds nested-div HTML: <html><body><div>×n ... </div>×n</body></html>.
func nestDivs(n int) string {
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < n; i++ {
		sb.WriteString("<div>")
	}
	sb.WriteString("x")
	for i := 0; i < n; i++ {
		sb.WriteString("</div>")
	}
	sb.WriteString("</body></html>")
	return sb.String()
}

// --- Walker-direct tests (r2-C7-1) ---
//
// These build deep trees programmatically (linked html.Node chains — no
// parser involved) and drive the budgeted walk directly. This is the test
// that fails if the walk is reverted to recursion: the original recursive
// extractor fatal-stack-overflows on the 100k-node tree, crashing the test
// binary instead of returning StructBudgetExceeded.

// divChainDoc builds a DocumentNode wrapping a chain of n nested <div>
// element nodes (div 1's FirstChild is div 2, and so on).
func divChainDoc(n int) *html.Node {
	doc := &html.Node{Type: html.DocumentNode}
	cur := doc
	for i := 0; i < n; i++ {
		d := &html.Node{Type: html.ElementNode, Data: "div"}
		cur.AppendChild(d)
		cur = d
	}
	return doc
}

func TestExtractStructureBounded_Programmatic10kChain_BudgetExceeded(t *testing.T) {
	doc := divChainDoc(10_000)

	start := time.Now()
	structure, status := extractStructureBounded(doc, DefaultStructBudget())
	elapsed := time.Since(start)

	if status != StructBudgetExceeded {
		t.Fatalf("10k-deep programmatic tree: want StructBudgetExceeded, got %v", status)
	}
	if structure != "" {
		t.Errorf("budget-exceeded walk must not synthesize a partial structure, got %d bytes", len(structure))
	}
	if elapsed > 5*time.Second {
		t.Errorf("budgeted walk must be bounded in time, took %v", elapsed)
	}
}

func TestExtractStructureBounded_Programmatic100kChain_BudgetExceeded(t *testing.T) {
	// Mutation killer: reverting to the unbudgeted tree-recursive extractor
	// makes this test fatal (stack overflow), not merely red.
	doc := divChainDoc(100_000)

	start := time.Now()
	structure, status := extractStructureBounded(doc, DefaultStructBudget())
	elapsed := time.Since(start)

	if status != StructBudgetExceeded {
		t.Fatalf("100k-deep programmatic tree: want StructBudgetExceeded, got %v", status)
	}
	if structure != "" {
		t.Errorf("budget-exceeded walk must not synthesize a partial structure, got %d bytes", len(structure))
	}
	if elapsed > 5*time.Second {
		t.Errorf("budgeted walk must be bounded in time, took %v", elapsed)
	}
}

func TestExtractStructureBounded_ProgrammaticChain_InBudgetSerialization(t *testing.T) {
	// In-budget programmatic trees must serialize identically to the
	// original recursive serializer (golden continuity beyond the shallow
	// parser fixtures).
	for n := 1; n <= 6; n++ {
		doc := divChainDoc(n)
		structure, status := extractStructureBounded(doc, DefaultStructBudget())
		if status != StructOK {
			t.Fatalf("chain of %d (depth %d <= 512): want StructOK, got %v", n, n, status)
		}
		want := "(div)"
		for i := 1; i < n; i++ {
			want = "(div " + want + ")"
		}
		if structure != want {
			t.Errorf("chain of %d: serialization drifted:\n got %s\nwant %s", n, structure, want)
		}
	}

	// Deep-but-in-budget chain (300 < 512): OK with no partial-synthesis.
	doc := divChainDoc(300)
	structure, status := extractStructureBounded(doc, DefaultStructBudget())
	if status != StructOK || structure == "" {
		t.Errorf("300-deep chain within default budget: want StructOK, got %v (len %d)", status, len(structure))
	}
}

// parseCapBoundary locates the parser's open-element ceiling empirically
// (r2-C7-1: do not hard-code an unverified ceiling). At the pinned
// x/net v0.58.0 it is html/body + 510 divs = 512 open elements.
func parseCapBoundary(t *testing.T) int {
	t.Helper()
	parses := func(divs int) bool {
		_, err := html.Parse(strings.NewReader(nestDivs(divs)))
		return err == nil
	}
	if !parses(505) || parses(10_000) {
		t.Fatalf("parser cap window moved: parse(505) must succeed and parse(10000) must fail at the pinned x/net version")
	}
	lo, hi := 505, 10_000 // parses(lo), !parses(hi)
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if parses(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

func TestParseCapExhaustion_ParseableDeepFixture_BudgetExceeded(t *testing.T) {
	// Parse-cap end-to-end: a fixture that parses successfully just under
	// the parser cap, with a walker budget BELOW the resulting DOM depth,
	// must come back BudgetExceeded — proving walker depth accounting is
	// driven by a parseable input's STRUCTURE, not by parse failure.
	boundary := parseCapBoundary(t)
	deep := nestDivs(boundary - 5) // safely parseable by construction

	if _, err := html.Parse(strings.NewReader(deep)); err != nil {
		t.Fatalf("fixture must parse at the pin: %v", err)
	}

	budget := StructBudget{MaxDepth: 64, MaxInputBytes: 1 << 30, MaxStructureBytes: 1 << 30}
	hash, status := ExtractStructureHash(deep, budget)
	if status != StructBudgetExceeded {
		t.Fatalf("parseable deep fixture with sub-depth budget: want StructBudgetExceeded, got %v", status)
	}
	if hash != "" {
		t.Errorf("non-OK status must carry empty hash, got %q", hash)
	}

	known, template, status := ClassifyStructure(deep, map[string]string{"*": "any"}, budget)
	if known || template != "" || status != StructBudgetExceeded {
		t.Errorf("ClassifyStructure deep-parseable: want (false, \"\", StructBudgetExceeded), got (%v, %q, %v)", known, template, status)
	}
}

func TestParseCapExhaustion_OverCapFixture_Unparseable(t *testing.T) {
	// Over the parser cap end-to-end through the public API: StructUnparseable —
	// NOT BudgetExceeded, NOT a silent ""-with-OK status.
	overCap := nestDivs(parseCapBoundary(t) + 5)

	hash, status := ExtractStructureHash(overCap, DefaultStructBudget())
	if status != StructUnparseable {
		t.Fatalf("over-parser-cap fixture: want StructUnparseable, got %v", status)
	}
	if hash != "" {
		t.Errorf("unparseable outcome must carry empty hash, got %q", hash)
	}

	templates := map[string]string{hash: "never-matches"}
	known, template, status := ClassifyStructure(overCap, templates, DefaultStructBudget())
	if known || template != "" || status != StructUnparseable {
		t.Errorf("ClassifyStructure over-cap: want (false, \"\", StructUnparseable), got (%v, %q, %v)", known, template, status)
	}
}

func TestWalkerDepthCountsStructureNotInputSize(t *testing.T) {
	// Two parseable inputs of similar byte length but different nesting:
	// only the deep one trips a sub-depth budget — the counter tracks tree
	// depth, not input size.
	deep := nestDivs(400)                                                                           // walker depth 402 (html, body, 400 divs); ~4.4 KiB
	shallow := "<html><body><div>" + strings.Repeat("<span>x</span>", 314) + "</div></body></html>" // depth 3; ~4.4 KiB

	if len(deep) > len(shallow)*110/100 || len(shallow) > len(deep)*110/100 {
		t.Fatalf("fixtures must be similar byte length: deep=%d shallow=%d", len(deep), len(shallow))
	}

	budget := StructBudget{MaxDepth: 64, MaxInputBytes: 1 << 30, MaxStructureBytes: 1 << 30}

	if _, status := ExtractStructureHash(shallow, budget); status != StructOK {
		t.Errorf("shallow-wide input within depth budget: want StructOK, got %v", status)
	}
	if _, status := ExtractStructureHash(deep, budget); status != StructBudgetExceeded {
		t.Errorf("deep input past depth budget: want StructBudgetExceeded, got %v", status)
	}
}

func TestDeepButLegitimateTableHTML_OK(t *testing.T) {
	// Realistic nested newsletter/table HTML (~30 levels) stays OK under
	// the default budget.
	var sb strings.Builder
	sb.WriteString("<html><body>")
	for i := 0; i < 10; i++ {
		sb.WriteString("<table><tr><td><div>")
	}
	sb.WriteString(`<p class="body">Hello</p>`)
	for i := 0; i < 10; i++ {
		sb.WriteString("</div></td></tr></table>")
	}
	sb.WriteString("</body></html>")
	doc := sb.String()

	hash, status := ExtractStructureHash(doc, DefaultStructBudget())
	if status != StructOK {
		t.Fatalf("deep-but-legitimate table HTML: want StructOK, got %v", status)
	}
	if hash == "" {
		t.Error("OK status must carry a non-empty hash")
	}
}

// --- ClassifyStructure boundary table (r2-C7-2) ---
//
// Mutation contract: any change collapsing a non-OK status into
// (false, "", StructOK) must fail this table.

func TestClassifyStructure_BoundaryTable(t *testing.T) {
	templates := map[string]string{
		"36c7d9ad601eb4278ce4a42a1b5bf8c7": "Known Phishing Template",
	}

	bigBudget := StructBudget{MaxDepth: 512, MaxInputBytes: 1 << 30, MaxStructureBytes: 1 << 30}
	tinyInputCap := StructBudget{MaxDepth: 512, MaxInputBytes: 1024, MaxStructureBytes: 1 << 30}
	subDepth := StructBudget{MaxDepth: 64, MaxInputBytes: 1 << 30, MaxStructureBytes: 1 << 30}
	benign := `<html><body><div class="newsletter"><h1>Weekly Digest</h1><p>News</p></div></body></html>`
	match := `<html><body><p>hello</p></body></html>` // golden 36c7... above

	cases := []struct {
		name       string
		html       string
		budget     StructBudget
		wantKnown  bool
		wantTmpl   string
		wantStatus StructStatus
	}{
		{"empty input", "", DefaultStructBudget(), false, "", StructEmpty},
		{"over parse cap", nestDivs(10_000), DefaultStructBudget(), false, "", StructUnparseable},
		{"over input cap", strings.Repeat("<p>x</p>", 400), tinyInputCap, false, "", StructBudgetExceeded},
		{"over depth budget", nestDivs(400), subDepth, false, "", StructBudgetExceeded},
		{"benign in budget", benign, bigBudget, false, "", StructOK},
		{"template match", match, bigBudget, true, "Known Phishing Template", StructOK},
	}

	for _, tc := range cases {
		known, tmpl, status := ClassifyStructure(tc.html, templates, tc.budget)
		if known != tc.wantKnown || tmpl != tc.wantTmpl || status != tc.wantStatus {
			t.Errorf("%s: ClassifyStructure = (%v, %q, %v), want (%v, %q, %v)",
				tc.name, known, tmpl, status, tc.wantKnown, tc.wantTmpl, tc.wantStatus)
		}
		if status != StructOK && (known || tmpl != "") {
			t.Errorf("%s: non-OK status must never classify: (%v, %q, %v)", tc.name, known, tmpl, status)
		}
	}

	// Empty-status contract through ExtractStructureHash as well.
	if _, status := ExtractStructureHash("", DefaultStructBudget()); status != StructEmpty {
		t.Errorf("empty input: want StructEmpty, got %v", status)
	}

	// Non-OK statuses always carry an empty hash.
	for name, tc := range map[string]struct {
		html   string
		budget StructBudget
	}{
		"unparseable":   {nestDivs(10_000), DefaultStructBudget()},
		"input-overcap": {strings.Repeat("<p>x</p>", 400), tinyInputCap},
		"depth-overcap": {nestDivs(400), subDepth},
	} {
		if hash, status := ExtractStructureHash(tc.html, tc.budget); status != StructOK && hash != "" {
			t.Errorf("%s: non-OK status must carry empty hash, got %q (%v)", name, hash, status)
		}
	}
}

func TestExtractStructureHash_NilRootProgrammatic(t *testing.T) {
	if _, status := extractStructureBounded(nil, DefaultStructBudget()); status != StructEmpty {
		t.Errorf("nil root: want StructEmpty, got %v", status)
	}
}

// --- Budget edge semantics ---

func TestExtractStructureHash_NonPositiveBudgetFailsClosed(t *testing.T) {
	// A non-positive limit means everything exceeds it: fail closed.
	for _, budget := range []StructBudget{
		{},
		{MaxDepth: 0, MaxInputBytes: 1 << 20, MaxStructureBytes: 1 << 20},
		{MaxDepth: 512, MaxInputBytes: 0, MaxStructureBytes: 1 << 20},
		{MaxDepth: 512, MaxInputBytes: 1 << 20, MaxStructureBytes: 0},
	} {
		_, status := ExtractStructureHash("<p>Hello</p>", budget)
		if status != StructBudgetExceeded {
			t.Errorf("budget %+v: want StructBudgetExceeded (fail closed), got %v", budget, status)
		}
	}
}

func TestDefaultStructBudget_Sane(t *testing.T) {
	b := DefaultStructBudget()
	if b.MaxDepth != 512 {
		t.Errorf("DefaultStructBudget MaxDepth = %d, want 512", b.MaxDepth)
	}
	if b.MaxInputBytes != 2<<20 {
		t.Errorf("DefaultStructBudget MaxInputBytes = %d, want 2 MiB", b.MaxInputBytes)
	}
	if b.MaxStructureBytes != 2<<20 {
		t.Errorf("DefaultStructBudget MaxStructureBytes = %d, want 2 MiB", b.MaxStructureBytes)
	}
	if !strings.Contains(fmt.Sprintf("%v", StructEmpty), "empty") {
		t.Errorf("StructStatus.String should render status names")
	}
}

// --- Straggler-wave gap tests: status naming and budget-arm boundaries ---

func TestStructStatus_String_AllStatuses(t *testing.T) {
	cases := []struct {
		status StructStatus
		want   string
	}{
		{StructOK, "ok"},
		{StructEmpty, "empty"},
		{StructBudgetExceeded, "budget_exceeded"},
		{StructUnparseable, "unparseable"},
		{StructStatus(42), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("StructStatus(%d).String() = %q, want %q", int(tc.status), got, tc.want)
		}
	}
}

func TestExtractStructureHash_NonPositiveStructureBudget_FailsClosed(t *testing.T) {
	// A non-positive serialized-size budget fails closed before any walk.
	hash, status := ExtractStructureHash("<p>hi</p>", StructBudget{
		MaxDepth:          8,
		MaxInputBytes:     1 << 20,
		MaxStructureBytes: -1,
	})
	if status != StructBudgetExceeded || hash != "" {
		t.Errorf("want (\"\", budget_exceeded), got (%q, %v)", hash, status)
	}
}

func TestExtractStructureHash_FoldSeparatorCrossesBudget(t *testing.T) {
	// The fold-time join separator is the increment that crosses the
	// budget: (html(head)(body(b)( p))) accumulates 24 framing bytes, and
	// folding "(p)" next to "(b)" adds the separator that tips to 25.
	_, status := ExtractStructureHash("<b></b><p></p>", StructBudget{
		MaxDepth:          8,
		MaxInputBytes:     1 << 20,
		MaxStructureBytes: 24,
	})
	if status != StructBudgetExceeded {
		t.Errorf("want budget_exceeded at fold separator, got %v", status)
	}
}

func TestExtractStructureHash_TextJoinSeparator_Counted(t *testing.T) {
	// Two text nodes inside one element (split by a child element) add a
	// join separator between their TEXT tokens — and still hash cleanly.
	hash, status := ExtractStructureHash("<p>hello <b>x</b> world</p>", DefaultStructBudget())
	if status != StructOK || hash == "" {
		t.Errorf("want ok hash, got (%q, %v)", hash, status)
	}
	plain, statusPlain := ExtractStructureHash("<p>hello world</p>", DefaultStructBudget())
	if statusPlain != StructOK || plain == "" {
		t.Fatalf("want ok hash for plain paragraph, got (%q, %v)", plain, statusPlain)
	}
	if hash == plain {
		t.Error("element-split text must not hash identically to a single text node")
	}
}
