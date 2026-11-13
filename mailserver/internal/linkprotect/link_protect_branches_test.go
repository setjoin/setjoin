package linkprotect

// Branch-completion tests for the rewrite/unwrap pipeline: every decode,
// re-encode, splice, skip, and unwrap branch the delivery and egress paths
// take. Complements link_protect_test.go / link_protect_e2e_test.go /
// link_protect_corpus_test.go, which own the end-to-end and adversarial
// cases; this file pins the individual branch behaviors so a regression in
// any single arm cannot hide behind a passing aggregate count.

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

var w5Keys = NewTokenKeys([]byte("w5-link-protect-branch-secret"), nil, 1)
var w5Internal = []string{"corp.example"}

// w5Sign is a convenience signer with a near-expiry-free claims set.
func w5Sign(t *testing.T, url string) string {
	t.Helper()
	tok, err := SignTokenN(TokenClaims{
		URL:       url,
		MessageID: "<branch@test>",
		MailboxID: 7,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}, w5Keys)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func w5Protected(t *testing.T, url string) string {
	return "https://guard.example" + protectedPath + "?token=" + w5Sign(t, url)
}

// TestNewTokenKeysNormalizesVersion: a zero-valued set clamps to version 1
// (pre-rotation byte-identical behavior) and an explicit version survives.
func TestNewTokenKeysNormalizesVersion(t *testing.T) {
	if got := NewTokenKeys(nil, nil, 0); got.Version != 1 {
		t.Errorf("zero version = %d, want 1", got.Version)
	}
	if got := NewTokenKeys([]byte("s"), []byte("p"), 4); got.Version != 4 || string(got.PreviousSecret) != "p" {
		t.Errorf("explicit set = %+v", got)
	}
	if got := (TokenKeys{Secret: []byte("s")}).normalized(); got.Version != 1 {
		t.Errorf("normalized zero set = %+v, want version 1", got)
	}
	// previousTokenKey: drained window (version 1) and empty previous secret
	// yield nil; a rotated set derives the version-1 key of the old secret.
	if (TokenKeys{Secret: []byte("s")}).previousTokenKey() != nil {
		t.Error("no previous secret must yield nil")
	}
	if (TokenKeys{Secret: []byte("s"), PreviousSecret: []byte("p"), Version: 1}).previousTokenKey() != nil {
		t.Error("version 1 must never carry a previous key")
	}
	rotated := TokenKeys{Secret: []byte("s"), PreviousSecret: []byte("p"), Version: 2}
	if !bytes.Equal(rotated.previousTokenKey(), tokenKeyN([]byte("p"), 1)) {
		t.Error("previous key must be the retiring secret's version-1 derivation")
	}
}

// TestRewriteMessageBodyN_ShapeBranches: header-less bodies rewrite as plain
// text; an unparseable Content-Type fails closed; multipart with html, plain,
// calendar, and untouched leaves rewrites exactly the target leaves.
func TestRewriteMessageBodyN_ShapeBranches(t *testing.T) {
	t.Run("headerless plain body", func(t *testing.T) {
		in := []byte("Subject: probe\r\n\r\nlook at https://evil.test/x now")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if !bytes.Contains(out, []byte(protectedMarker)) || bytes.Contains(out, []byte("https://evil.test/x now")) {
			t.Errorf("external URL must be rewritten:\n%s", out)
		}
	})

	t.Run("unparseable content type fails closed", func(t *testing.T) {
		in := []byte("Content-Type: multipart/mixed\r\n\r\nbody")
		if _, _, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7); err == nil {
			t.Fatal("multipart Content-Type without a boundary must error")
		}
	})

	t.Run("multipart mixed leaves", func(t *testing.T) {
		plain := "see https://ext1.test/a and stay on https://corp.example/ok"
		html := `<p><a href="https://ext2.test/b">x</a><img src="https://ext3.test/c.png"></p>`
		cal := "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"
		in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
			"--B\r\nContent-Type: text/plain\r\n\r\n" + plain + "\r\n" +
			"--B\r\nContent-Type: text/html\r\n\r\n" + html + "\r\n" +
			"--B\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\n" + cal + "\r\n" +
			"--B\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n" +
			"--B--\r\n")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n < 3 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		s := string(out)
		if strings.Contains(s, "https://ext1.test/a") || strings.Contains(s, "https://ext2.test/b") || strings.Contains(s, "https://ext3.test/c.png") {
			t.Errorf("external URLs must be rewritten:\n%s", s)
		}
		if !strings.Contains(s, "https://corp.example/ok") {
			t.Errorf("internal URL must stay direct:\n%s", s)
		}
		if !strings.Contains(s, "BEGIN:VCALENDAR") || !strings.Contains(s, "aGVsbG8=") {
			t.Errorf("calendar and binary leaves must stay byte-exact:\n%s", s)
		}
	})

	t.Run("base64 single part re-encoded", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte("visit https://ext4.test/d today")) + "\r\n")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		decoded, _, derr := decodeCTE("base64", bytes.SplitN(out, []byte("\r\n\r\n"), 2)[1])
		if derr != nil {
			t.Fatalf("re-encoded body must decode: %v\n%s", derr, out)
		}
		if !bytes.Contains(decoded, []byte(protectedMarker)) {
			t.Errorf("base64 body must be decoded, rewritten, and re-encoded:\n%s", out)
		}
	})

	t.Run("quoted-printable single part", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nvisit https://ext5.test/e=20 today\r\n")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if !bytes.Contains(out, []byte(protectedMarker)) {
			t.Errorf("quoted-printable body must be rewritten:\n%s", out)
		}
	})

	t.Run("calendar single part untouched", func(t *testing.T) {
		in := []byte("Content-Type: text/calendar\r\n\r\nhttps://ext6.test/f")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n != 0 || !bytes.Equal(out, in) {
			t.Fatalf("calendar part must be untouched: n=%d equal=%v err=%v", n, bytes.Equal(out, in), err)
		}
	})

	t.Run("plain part with no URLs is byte-exact", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\n\r\nnothing to rewrite here")
		out, n, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7)
		if err != nil || n != 0 || !bytes.Equal(out, in) {
			t.Fatalf("no-URL body must stay byte-exact: n=%d equal=%v err=%v", n, bytes.Equal(out, in), err)
		}
	})
}

// TestRebuildMessage_SeparatorShapes: the header splice keeps LF-only and
// header-less bodies intact.
func TestRebuildMessage_SeparatorShapes(t *testing.T) {
	body := []byte("BODY")
	if got := rebuildMessage([]byte("Subject: lf\n\nold"), body); !bytes.Equal(got, []byte("Subject: lf\n\nBODY")) {
		t.Errorf("LF-only splice = %q", got)
	}
	if got := rebuildMessage([]byte("no header block at all"), body); !bytes.Equal(got, body) {
		t.Errorf("header-less splice = %q, want the body alone", got)
	}
	if got := rebuildMessage([]byte("Subject: crlf\r\n\r\nold"), body); !bytes.Equal(got, []byte("Subject: crlf\r\n\r\nBODY")) {
		t.Errorf("CRLF splice = %q", got)
	}
}

// TestRewriteCSS_Branches: url() and @import targets are rewritten, non-matches
// kept, and a stylesheet with no external fetches returns count 0.
func TestRewriteCSS_Branches(t *testing.T) {
	css := `body { background: url("https://ext7.test/bg.png") } @import "https://ext8.test/x.css"; a { color: red }`
	out, n := rewriteCSS(css, w5Keys, w5Internal, "<m>", 7)
	if n != 2 {
		t.Fatalf("n=%d", n)
	}
	if strings.Contains(out, "https://ext7.test") || strings.Contains(out, "https://ext8.test") {
		t.Errorf("CSS fetches must be rewritten:\n%s", out)
	}
	if !strings.Contains(out, "color: red") {
		t.Errorf("non-URL CSS must survive:\n%s", out)
	}
	if out2, n2 := rewriteCSS("a { color: blue }", w5Keys, w5Internal, "<m>", 7); n2 != 0 || out2 != "a { color: blue }" {
		t.Errorf("no-fetch CSS must be untouched: n=%d out=%q", n2, out2)
	}
}

// TestRewriteSrcset_Branches: every external candidate is rewritten with its
// descriptors preserved; a srcset with no external candidates returns 0.
func TestRewriteSrcset_Branches(t *testing.T) {
	val := `https://ext9.test/a.png 1x, https://corp.example/local.png 2x`
	out, n := rewriteSrcset(val, w5Keys, w5Internal, "<m>", 7)
	if n != 1 {
		t.Fatalf("n=%d out=%q", n, out)
	}
	if strings.Contains(out, "https://ext9.test") || !strings.Contains(out, "https://corp.example/local.png 2x") {
		t.Errorf("srcset rewrite lost descriptors:\n%s", out)
	}
	if out2, n2 := rewriteSrcset("https://corp.example/only.png 1x", w5Keys, w5Internal, "<m>", 7); n2 != 0 || out2 != "https://corp.example/only.png 1x" {
		t.Errorf("internal-only srcset must be untouched: n=%d out=%q", n2, out2)
	}
}

// TestUnwrapMessageBodyN_ShapeBranches: the egress unwrap mirrors the rewrite
// shapes — header-less, multipart, calendar skip, encoded parts, unknown
// contexts, and empty bodies.
func TestUnwrapMessageBodyN_ShapeBranches(t *testing.T) {
	t.Run("headerless plain body", func(t *testing.T) {
		in := []byte("go to " + w5Protected(t, "https://dest1.test/a") + " now")
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
		if !bytes.Contains(out, []byte("https://dest1.test/a")) {
			t.Errorf("destination must be restored:\n%s", out)
		}
	})

	t.Run("empty headerless body falls to unknown context", func(t *testing.T) {
		out, n, err := UnwrapMessageBodyN([]byte("\r\n"), w5Keys)
		if err != nil || n != 0 || !bytes.Equal(out, []byte("\r\n")) {
			t.Fatalf("empty body: n=%d equal=%v err=%v", n, bytes.Equal(out, []byte("\r\n")), err)
		}
	})

	t.Run("multipart html and plain unwrap", func(t *testing.T) {
		dest := "https://dest2.test/b"
		tok := w5Protected(t, dest)
		in := []byte("Content-Type: multipart/alternative; boundary=B\r\n\r\n" +
			"--B\r\nContent-Type: text/plain\r\n\r\nsee " + tok + "\r\n" +
			"--B\r\nContent-Type: text/html\r\n\r\n<a href=\"" + tok + "\">x</a>\r\n" +
			"--B--\r\n")
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 2 {
			t.Fatalf("n=%d err=%v\n%s", n, err, out)
		}
		if strings.Count(string(out), dest) != 2 {
			t.Errorf("both leaves must unwrap to the destination:\n%s", out)
		}
	})

	t.Run("calendar part untouched", func(t *testing.T) {
		tok := w5Protected(t, "https://dest3.test/c")
		in := []byte("Content-Type: text/calendar\r\n\r\n" + tok)
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 0 || !bytes.Contains(out, []byte("token=")) {
			t.Fatalf("calendar unwrap must be a no-op: n=%d out=%s err=%v", n, out, err)
		}
	})

	t.Run("base64 part unwrapped", func(t *testing.T) {
		plain := "wrapped " + w5Protected(t, "https://dest4.test/d")
		in := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte(plain)) + "\r\n")
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 1 {
			t.Fatalf("n=%d err=%v\n%s", n, err, out)
		}
		decoded, _, derr := decodeCTE("base64", bytes.SplitN(out, []byte("\r\n\r\n"), 2)[1])
		if derr != nil {
			t.Fatalf("re-encoded body must decode: %v\n%s", derr, out)
		}
		if !bytes.Contains(decoded, []byte("https://dest4.test/d")) {
			t.Errorf("base64 part must unwrap:\n%s", out)
		}
	})

	t.Run("plain part without marker untouched", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\n\r\nno redirects here")
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 0 || !bytes.Equal(out, in) {
			t.Fatalf("marker-free part untouched: n=%d equal=%v err=%v", n, bytes.Equal(out, in), err)
		}
	})
}

// TestUnwrapHTMLBody_Branches: attributes, srcset, style attributes, <style>
// text, and text nodes unwrap; a part with none of ours is byte-exact; a raw-
// text literal context retains its redirect.
func TestUnwrapHTMLBody_Branches(t *testing.T) {
	dest := "https://dest5.test/e"
	tok := w5Protected(t, dest)

	html := `<div><a href="` + tok + `">x</a>` +
		`<img srcset="` + tok + ` 2x" style="background:url('` + tok + `')">` +
		`<style>@import "` + tok + `";</style>` +
		`<p>text with ` + tok + ` inline</p></div>`
	out, n, err := unwrapHTMLBody([]byte(html), w5Keys)
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v\n%s", n, err, out)
	}
	if strings.Contains(string(out), "token=") {
		t.Errorf("every protected URL must unwrap:\n%s", out)
	}
	if strings.Count(string(out), dest) != 5 {
		t.Errorf("all five positions must carry the destination:\n%s", out)
	}

	if out2, n2, err := unwrapHTMLBody([]byte("<p>nothing of ours</p>"), w5Keys); err != nil || n2 != 0 || string(out2) != "<p>nothing of ours</p>" {
		t.Errorf("marker-free html must stay byte-exact: n=%d out=%q err=%v", n2, out2, err)
	}

	scriptHTML := `<script>var u = "` + tok + `";</script>`
	out3, n3, err := unwrapHTMLBody([]byte(scriptHTML), w5Keys)
	if err != nil || n3 != 0 {
		t.Fatalf("raw-text literal context must retain the redirect: n=%d err=%v", n3, err)
	}
	if !bytes.Contains(out3, []byte(protectedMarker)) {
		t.Errorf("script redirect must be retained verbatim:\n%s", out3)
	}
}

// TestUnwrapCSS_Branches: url() and @import splices restore destinations that
// are CSS-string-safe and keep unsafe ones inert.
func TestUnwrapCSS_Branches(t *testing.T) {
	dest := "https://dest6.test/f"
	tok := w5Protected(t, dest)
	css := `x { background: url("` + tok + `") } y { z }`
	out, n := unwrapCSS(css, w5Keys)
	if n != 1 || !strings.Contains(out, "url(\""+dest+"\")") {
		t.Fatalf("n=%d out=%q", n, out)
	}
	if out2, n2 := unwrapCSS("a { color: red }", w5Keys); n2 != 0 || out2 != "a { color: red }" {
		t.Errorf("marker-free css untouched: n=%d out=%q", n2, out2)
	}
}

// TestUnwrapSrcset_Branches: full-value candidates unwrap; unsafe
// destinations (whitespace-bearing) stay protected.
func TestUnwrapSrcset_Branches(t *testing.T) {
	tok := w5Protected(t, "https://dest7.test/g 1x")
	// A destination carrying whitespace is rejected (would forge the grammar).
	val := tok + " 2x"
	if out, n := unwrapSrcset(val, w5Keys); n != 0 || out != val {
		t.Fatalf("whitespace destination must stay protected: n=%d out=%q", n, out)
	}
	clean := w5Protected(t, "https://dest8.test/h")
	out, n := unwrapSrcset(clean+" 1x", w5Keys)
	if n != 1 || !strings.HasPrefix(out, "https://dest8.test/h 1x") {
		t.Fatalf("n=%d out=%q", n, out)
	}
	if out2, n2 := unwrapSrcset("https://corp.example/a.png 1x", w5Keys); n2 != 0 || out2 != "https://corp.example/a.png 1x" {
		t.Errorf("non-token srcset untouched: n=%d out=%q", n2, out2)
	}
}

// TestUnwrapUnknownContext_Inertness: the raw-byte fallback substitutes only
// inert destinations and keeps control-character-bearing ones protected.
func TestUnwrapUnknownContext_Inertness(t *testing.T) {
	good := w5Protected(t, "https://dest9.test/i")
	out, n, err := unwrapUnknownContext([]byte("see "+good+" ok"), w5Keys)
	if err != nil || n != 1 || !bytes.Contains(out, []byte("https://dest9.test/i")) {
		t.Fatalf("inert destination must substitute: n=%d out=%s err=%v", n, out, err)
	}

	evil := w5Protected(t, "https://evil.test/\r\nX")
	out2, n2, err2 := unwrapUnknownContext([]byte("see "+evil+" ok"), w5Keys)
	if err2 != nil || n2 != 0 || !bytes.Contains(out2, []byte("token=")) {
		t.Fatalf("control-bearing destination must stay protected: n=%d out=%s err=%v", n2, out2, err2)
	}

	if out3, n3, err3 := unwrapUnknownContext([]byte("no tokens"), w5Keys); err3 != nil || n3 != 0 || string(out3) != "no tokens" {
		t.Errorf("token-free context untouched: n=%d out=%q err=%v", n3, out3, err3)
	}
}

// TestVerifyTokenN_RotationArms: current-key verification wins; a previous-key
// token verifies only while the overlap is configured; junk signatures fail.
func TestVerifyTokenN_RotationArms(t *testing.T) {
	oldKeys := NewTokenKeys([]byte("rot-old"), nil, 1)
	newKeys := NewTokenKeys([]byte("rot-new"), []byte("rot-old"), 2)
	claims := TokenClaims{URL: "https://dest.test/r", ExpiresAt: time.Now().Add(time.Hour).Unix()}

	oldTok, err := SignTokenN(claims, oldKeys)
	if err != nil {
		t.Fatalf("sign old: %v", err)
	}
	if got, err := VerifyTokenN(oldTok, newKeys); err != nil || got.URL != claims.URL {
		t.Errorf("old token must verify under the overlap key: %v %v", got, err)
	}
	drained := NewTokenKeys([]byte("rot-new"), nil, 2)
	if _, err := VerifyTokenN(oldTok, drained); err == nil {
		t.Error("old token must fail once the previous key is drained")
	}
	newTok, err := SignTokenN(claims, newKeys)
	if err != nil {
		t.Fatalf("sign new: %v", err)
	}
	if got, err := VerifyTokenN(newTok, newKeys); err != nil || got.URL != claims.URL {
		t.Errorf("new token must verify under the current key: %v %v", got, err)
	}
	if _, err := VerifyTokenN(newTok, oldKeys); err == nil {
		t.Error("new-version token must fail under the retired key set")
	}
}

// TestRewriteURL_GuardArms: mailto, fragment, own-redirect, and internal URLs
// skip rewriting; external http(s) rewrites; empty fails.
func TestRewriteURL_GuardArms(t *testing.T) {
	skip := []string{
		"",
		"mailto:user@corp.example",
		"#section",
		"/link-protect?token=abc.def",
		"https://corp.example/ok",
		"HTTP://CORP.EXAMPLE/UPPER",
	}
	for _, u := range skip {
		if _, ok := rewriteURL(u, w5Keys, w5Internal, "<m>", 7); ok {
			t.Errorf("rewriteURL(%q) must skip", u)
		}
	}
	out, ok := rewriteURL("https://ext.test/a", w5Keys, w5Internal, "<m>", 7)
	if !ok || !strings.Contains(out, protectedMarker) {
		t.Errorf("external URL must rewrite, got %q ok=%v", out, ok)
	}
}

// TestRewriteMessageBodyN_FailClosedBranches: malformed MIME framing and
// undecodable transfer encodings must ERROR (the delivery caller quarantines)
// — never deliver a body that was not fully scanner-visible.
func TestRewriteMessageBodyN_FailClosedBranches(t *testing.T) {
	t.Run("malformed header block", func(t *testing.T) {
		if _, _, err := RewriteMessageBodyN([]byte("bad-header-line\r\n\r\nbody"), w5Keys, w5Internal, "<m>", 7); err == nil {
			t.Error("malformed header line must fail closed")
		}
	})
	t.Run("undecodable base64 part", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n")
		if _, _, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7); err == nil {
			t.Error("invalid base64 must fail closed")
		}
	})
	// NOTE: no quoted-printable decode-error case — mime/quotedprintable is
	// deliberately lenient (invalid =XX sequences pass through as literals),
	// so decodeCTE's qp error branch is unreachable with the stdlib reader.
	t.Run("ambiguous multipart framing", func(t *testing.T) {
		in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nno close boundary")
		if _, _, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7); err == nil {
			t.Error("missing close boundary must fail closed")
		}
	})
}

// TestUnwrapMessageBodyN_ErrorAndSkipBranches: the unwrap path fails closed on
// the same framing/encoding defects and skips non-text leaves.
func TestUnwrapMessageBodyN_ErrorAndSkipBranches(t *testing.T) {
	// NOTE: no malformed-header case — UnwrapMessageBodyN degrades a
	// header-parse failure to unwrapUnknownContext (raw-byte fallback), which
	// succeeds by design.
	t.Run("undecodable base64 part", func(t *testing.T) {
		in := []byte("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n")
		if _, _, err := UnwrapMessageBodyN(in, w5Keys); err == nil {
			t.Error("invalid base64 must fail closed")
		}
	})
	t.Run("ambiguous multipart framing", func(t *testing.T) {
		in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nno close boundary")
		if _, _, err := UnwrapMessageBodyN(in, w5Keys); err == nil {
			t.Error("missing close boundary must fail closed")
		}
	})
	t.Run("binary leaf skipped", func(t *testing.T) {
		tok := w5Protected(t, "https://destA.test/j")
		in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
			"--B\r\nContent-Type: application/octet-stream\r\n\r\n" + tok + "\r\n" +
			"--B--\r\n")
		out, n, err := UnwrapMessageBodyN(in, w5Keys)
		if err != nil || n != 0 {
			t.Fatalf("binary leaf must be skipped: n=%d err=%v", n, err)
		}
		if !bytes.Contains(out, []byte("token=")) {
			t.Errorf("binary leaf token must stay protected:\n%s", out)
		}
	})
	t.Run("second bad part short-circuits", func(t *testing.T) {
		in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
			"--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n" +
			"--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n" +
			"--B--\r\n")
		if _, _, err := UnwrapMessageBodyN(in, w5Keys); err == nil {
			t.Error("a bad leaf must fail the whole multipart unwrap")
		}
	})
}

// TestRewriteURL_AdditionalGuards: control-character URLs are never signed and
// the exported shorthand delegates to the canonical rewriter.
func TestRewriteURL_AdditionalGuards(t *testing.T) {
	if out, ok := rewriteURL("https://evil.test/\r\nset-cookie", w5Keys, w5Internal, "<m>", 7); ok || out != "https://evil.test/\r\nset-cookie" {
		t.Errorf("CRLF-bearing URL must stay unrewritten, got %q ok=%v", out, ok)
	}
	out, ok := RewriteURL("https://ext.test/entry", []byte("w5-shorthand-secret"), w5Internal, "<m>", 7)
	if !ok || !strings.Contains(out, protectedMarker) {
		t.Errorf("RewriteURL shorthand must rewrite, got %q ok=%v", out, ok)
	}
}

// TestParseURLHost_Rejections: empty URLs, hostless URLs, and empty hostnames
// are rejected — callers fail closed to NOT-internal.
func TestParseURLHost_Rejections(t *testing.T) {
	for _, u := range []string{"", "/relative/path", "mailto:a@b.c"} {
		if _, err := parseURLHost(u); err == nil {
			t.Errorf("parseURLHost(%q) must reject", u)
		}
	}
	if host, err := parseURLHost("http://:80/"); err == nil || host != "" {
		t.Errorf("empty hostname must reject, got %q err=%v", host, err)
	}
	if host, err := parseURLHost("http://User@Internal.Example:8080/x"); err != nil || host != "internal.example" {
		t.Errorf("userinfo must be excluded, got %q err=%v", host, err)
	}
}

// TestRewriteMultipart_BadLeafShortCircuits: once one leaf fails (bad base64),
// later leaves short-circuit without decoding, and the whole body errors.
func TestRewriteMultipart_BadLeafShortCircuits(t *testing.T) {
	in := []byte("Content-Type: multipart/mixed; boundary=B\r\n\r\n" +
		"--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n" +
		"--B\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!!\r\n" +
		"--B--\r\n")
	if _, _, err := RewriteMessageBodyN(in, w5Keys, w5Internal, "<m>", 7); err == nil {
		t.Error("a bad leaf must fail the whole multipart rewrite")
	}
}

// TestRewriteCSS_InternalTargetsSkipped: internal url()/@import targets are
// left direct (count reflects only the rewritten ones).
func TestRewriteCSS_InternalTargetsSkipped(t *testing.T) {
	css := `x { background: url("https://corp.example/bg") } y { z }`
	if out, n := rewriteCSS(css, w5Keys, w5Internal, "<m>", 7); n != 0 || out != css {
		t.Errorf("internal url() must stay direct: n=%d out=%q", n, out)
	}
	css2 := `@import "https://corp.example/s.css";`
	if out, n := rewriteCSS(css2, w5Keys, w5Internal, "<m>", 7); n != 0 || out != css2 {
		t.Errorf("internal @import must stay direct: n=%d out=%q", n, out)
	}
}
