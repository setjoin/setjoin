//go:build gofree_record

package smtp

// Test stimulus authoring uses frozen Go token minting and MIME encoders. The
// recorded outputs still come from the complete outbound worker and TCP peer.
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/quotedprintable"
	"setjoin.com/mailserver/internal/linkprotect"
	"strings"
	"testing"
)

func outboundPreparationCases(t *testing.T, baseline outboundCase) []outboundCase {
	t.Helper()
	current := "smtp3-link-current"
	previous := "smtp3-link-previous"
	sign := func(url, secret string, version int, expires int64) string {
		token, e := linkprotect.SignTokenN(linkprotect.TokenClaims{URL: url, MessageID: "<protected@smtp3.test>", MailboxID: 9348021, ExpiresAt: expires}, linkprotect.NewTokenKeys([]byte(secret), nil, version))
		if e != nil {
			t.Fatal(e)
		}
		return "https://mail.smtp3.test/link-protect?token=" + token
	}
	valid := sign("https://origin.test/a?x=1&y=2", current, 2, 4102444800)
	markup := sign(`https://origin.test/?q="><script>alert(1)</script>`, current, 2, 4102444800)
	css := sign("https://origin.test/image.png", current, 2, 4102444800)
	comma := sign("https://origin.test/a,b.png", current, 2, 4102444800)
	old := sign("https://origin.test/old", previous, 1, 4102444800)
	expired := sign("https://origin.test/expired", current, 2, 1)
	foreign := sign("https://origin.test/foreign", "foreign", 2, 4102444800)
	control := sign("https://origin.test/\r\nInjected: x", current, 2, 4102444800)
	quoted := func(s string) string {
		var out bytes.Buffer
		w := quotedprintable.NewWriter(&out)
		if _, e := w.Write([]byte(s)); e != nil {
			t.Fatal(e)
		}
		if e := w.Close(); e != nil {
			t.Fatal(e)
		}
		return out.String()
	}
	raw := func(ct, cte, body string) string {
		return "From: sender@smtp3.test\r\nSubject: forwarded\r\nContent-Type: " + ct + "\r\n" + func() string {
			if cte == "" {
				return ""
			}
			return "Content-Transfer-Encoding: " + cte + "\r\n"
		}() + "\r\n" + body
	}
	fixtures := []struct {
		name, raw string
		enabled   bool
	}{
		{"unwrap-plain", raw("text/plain", "", valid+"\r\n"), true},
		{"unwrap-html-quoted", raw("text/html", "", `<a class="x" href="`+markup+`">`+valid+`</a><br>`), true},
		{"unwrap-html-css-srcset", raw("text/html", "", `<style>body{background:url('`+css+`')} @import "`+css+`";</style><img src="`+css+`" srcset="`+comma+` 1x, `+css+` 2x" style="background:url(`+css+`)">`), true},
		{"unwrap-html-literal-contexts", raw("text/html", "", `<script>"`+markup+`"</script><iframe>`+valid+`</iframe><p>`+valid+`</p>`), true},
		{"unwrap-base64", raw("text/plain", "base64", base64.StdEncoding.EncodeToString([]byte(valid+" no newline"))), true},
		{"unwrap-quoted-printable", raw("text/plain", "quoted-printable", quoted(valid+" no newline")), true},
		{"unwrap-multipart", raw("multipart/mixed; boundary=outer", "", "preamble\r\n--outer\r\nContent-Type: text/plain\r\n\r\n"+valid+"\r\n--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\n--inner\r\nContent-Type: text/html\r\n\r\n<a href=\""+valid+"\">link</a>\r\n--inner--\r\n--outer\r\nContent-Type: application/octet-stream\r\n\r\n"+valid+"\r\n--outer\r\nContent-Type: text/calendar\r\n\r\n"+valid+"\r\n--outer--\r\nepilogue"), true},
		{"unwrap-broken-multipart", raw("multipart/mixed; boundary=outer", "", "--outer\r\nContent-Type: text/plain\r\n\r\n"+valid), true},
		{"unwrap-invalid-base64", raw("text/plain", "base64", valid), true},
		{"unwrap-unknown-inert", valid, true},
		{"unwrap-unknown-markup", markup, true},
		{"unwrap-calendar-unchanged", raw("text/calendar", "", valid), true},
		{"unwrap-token-refusals", raw("text/plain", "", expired+" "+foreign+" "+control), true},
		{"unwrap-retiring-key", raw("text/plain", "", old), true},
		{"unwrap-not-forward", raw("text/plain", "", valid), false},
		{"unwrap-edge-unknown-inert", sign("https://origin.test/plain", current, 2, 4102444800) + "\n", true},
		{"unwrap-edge-unknown-markup", markup + "\n", true},
		{"unwrap-edge-binary-plain", raw("text/plain", "", string([]byte{0xff})+" "+valid+"\r\n"), true},
		{"unwrap-edge-binary-unknown", string([]byte{0xff}) + foreign + "\n", true},
		{"unwrap-edge-qp-malformed", raw("text/plain", "quoted-printable", "literal=ZZ "+valid), true},
		{"unwrap-edge-css-refused", raw("text/html", "", `<style>body{background:url('`+markup+`')}</style><p>`+valid+`</p>`), true},
	}
	var out []outboundCase
	for _, fixture := range fixtures {
		c := baseline
		c.Name = fixture.name
		c.Ticks = 1
		rawRef := fixture.raw
		if strings.ContainsRune(rawRef, '\ufffd') || strings.IndexByte(rawRef, 0xff) >= 0 {
			rawRef = "blobs/forward-raw"
			c.Blobs = map[string]string{rawRef: base64.StdEncoding.EncodeToString([]byte(fixture.raw))}
			c.BlobHeaders = map[string]string{"Last-Modified": "Thu, 10 Sep 2026 10:00:00 GMT"}
		}
		c.SQL = strings.Split(baseline.SQL, "INSERT INTO outbound_queue")[0] + fmt.Sprintf("INSERT INTO outbound_queue(id,message_id,from_addr,rcpt_addrs,raw_ref,attempt_count,mailbox_id,message_pk,forward_unwrap_links) VALUES (9350011,'<outbound@smtp3.test>','sender@smtp3.test',ARRAY['one@dest.test'],%s,0,9348021,9350001,%t);", "'"+strings.ReplaceAll(rawRef, "'", "''")+"'", fixture.enabled)
		c.LinkSecret = current
		c.LinkPrevious = previous
		c.LinkVersion = 2
		out = append(out, c)
	}
	// Round-trip through JSON ensures stimuli are exactly what the Rust replay sees.
	b, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
