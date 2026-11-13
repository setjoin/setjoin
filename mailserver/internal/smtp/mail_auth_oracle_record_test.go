//go:build gofree_record

package smtp

// Test-only DNS fixture. Every authentication decision still runs frozen Go.
import (
	"bufio"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
	"strings"
	"testing"
	"time"
)

func smtpOracleDNS(records map[string]json.RawMessage) func() {
	oldTXT, oldIP, oldMX, oldPTR := LookupTXT, LookupIP, LookupMX, LookupAddr
	if records == nil {
		return func() {}
	}
	lookup := func(kind, name string) ([]string, error) {
		raw, ok := records[kind+":"+name]
		if !ok {
			return nil, &net.DNSError{IsNotFound: true}
		}
		var values []string
		if json.Unmarshal(raw, &values) == nil {
			return values, nil
		}
		return nil, &net.DNSError{IsNotFound: string(raw) == `"nxdomain"`, IsTemporary: true}
	}
	LookupTXT = func(name string) ([]string, error) { return lookup("txt", name) }
	LookupIP = func(name string) ([]net.IP, error) {
		values, e := lookup("ip", name)
		var out []net.IP
		for _, v := range values {
			out = append(out, net.ParseIP(v))
		}
		return out, e
	}
	LookupMX = func(name string) ([]*net.MX, error) {
		values, e := lookup("mx", name)
		var out []*net.MX
		for _, v := range values {
			out = append(out, &net.MX{Host: v})
		}
		return out, e
	}
	LookupAddr = func(name string) ([]string, error) { return lookup("ptr", name) }
	return func() { LookupTXT, LookupIP, LookupMX, LookupAddr = oldTXT, oldIP, oldMX, oldPTR }
}

// The verifier's public inputs and projected authenticated identity metadata.
// Signing stimuli use frozen Go + fixed, test-only keys, then go through the
// production TCP recorder separately. Existing corpora are never overwritten.
func TestRecordSMTPDKIM(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "dkim-vectors-go.json")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("golden exists or inaccessible")
	}
	keyBytes, err := os.ReadFile(filepath.Join(root, "auth-fixture/rsa.pem"))
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := ParseRSAPrivateKey(string(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	edBytes, err := os.ReadFile(filepath.Join(root, "auth-fixture/ed25519.pem"))
	if err != nil {
		t.Fatal(err)
	}
	edBlock, _ := pem.Decode(edBytes)
	edAny, err := x509.ParsePKCS8PrivateKey(edBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	edKey := edAny.(ed25519.PrivateKey)
	rsaPub, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	edPub, _ := x509.MarshalPKIXPublicKey(edKey.Public())
	rsaRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(rsaPub)
	edRecord := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edPub)
	const domain = "dkim.smtp2.test"
	unsigned := "From: Alice <sender@" + domain + ">\r\nTo: alice@smtp1.test\r\nSubject: DKIM fixture\r\nDate: Thu, 10 Sep 2026 10:00:00 +0000\r\nMessage-Id: <dkim@smtp2.test>\r\n\r\nbody line\r\nsecond line\r\n"
	header, err := SignDKIM([]byte(unsigned), "sel", domain, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	good := "DKIM-Signature: " + header + "\r\n" + unsigned
	sign := func(algorithm, canonical string, length int64, body, extra string) string {
		sig := &DKIMSig{Domain: domain, Selector: "sel", Algorithm: algorithm, Canonical: canonical, Headers: []string{"from", "to", "subject", "date"}, Created: 1, Expires: 2, Length: length}
		_, b := splitHeadersBody([]byte(body))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(b, canonical, length))
		data := []byte(dkimSignedData(body, sig))
		var signature []byte
		if algorithm == "ed25519-sha256" {
			signature = ed25519.Sign(edKey, data)
		} else {
			h := sha256.Sum256(data)
			signature, err = rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, h[:])
			if err != nil {
				t.Fatal(err)
			}
		}
		return "DKIM-Signature: " + dkimSigBody(sig) + base64.StdEncoding.EncodeToString(signature) + extra + "\r\n" + body
	}
	type vector struct {
		Name      string                     `json:"name"`
		Raw       string                     `json:"raw_base64"`
		DNS       map[string]json.RawMessage `json:"dns"`
		Result    DKIMResult                 `json:"result"`
		Domain    string                     `json:"domain"`
		Length    int64                      `json:"signed_len"`
		Canonical string                     `json:"canonical"`
	}
	var vectors []vector
	var sessions []smtpOracleSession
	add := func(name, raw, record string, dnsErr bool) {
		records := map[string]json.RawMessage{}
		if dnsErr {
			records["txt:sel._domainkey."+domain] = json.RawMessage(`"temporary"`)
		} else if record != "" {
			v, _ := json.Marshal([]string{record})
			records["txt:sel._domainkey."+domain] = v
		}
		restore := smtpOracleDNS(records)
		result, d, l, c := (&inConnState{data: []byte(raw)}).verifyDKIM()
		restore()
		vectors = append(vectors, vector{Name: name, Raw: base64.StdEncoding.EncodeToString([]byte(raw)), DNS: records, Result: result, Domain: d, Length: l, Canonical: c})
		// SMTP dot-stuffing is part of the recorded listener seam.
		wire := strings.ReplaceAll(raw, "\r\n.", "\r\n..")
		if !strings.HasSuffix(wire, "\r\n") {
			wire += "\r\n"
		}
		sessions = append(sessions, smtpOracleSession{Name: name, MailAuth: map[string]bool{toggle.FeatureDKIM: true}, DNS: records, ObserveEffects: true, Steps: []smtpOracleStep{
			{Send: "", Lines: 1}, {Send: "EHLO peer.test\r\n", Lines: 5}, {Send: "MAIL FROM:<sender@dkim.smtp2.test>\r\n", Lines: 1}, {Send: "RCPT TO:<alice@smtp1.test>\r\n", Lines: 1}, {Send: "DATA\r\n", Lines: 1}, {Send: wire + ".\r\n", Lines: 1}, {Send: "QUIT\r\n", Lines: 1},
		}})
	}
	add("unsigned", unsigned, rsaRecord, false)
	add("missing-selector", "DKIM-Signature: d="+domain+"; a=rsa-sha256\r\n"+unsigned, rsaRecord, false)
	add("rsa-pass", good, rsaRecord, false)
	add("expired-signature-still-passes", sign("rsa-sha256", "relaxed/relaxed", 0, unsigned, ""), rsaRecord, false)
	add("simple-signature", sign("rsa-sha256", "simple/simple", 0, unsigned, ""), rsaRecord, false)
	add("header-whitespace", sign("rsa-sha256", "relaxed/relaxed", 0, strings.Replace(unsigned, "Subject: DKIM fixture", "Subject: DKIM  fixture", 1), ""), rsaRecord, false)
	add("body-relaxation", sign("rsa-sha256", "relaxed/relaxed", 0, strings.Replace(unsigned, "body line", "body \t line  \t", 1), ""), rsaRecord, false)
	add("signed-prefix-with-untrusted-tail", sign("rsa-sha256", "relaxed/relaxed", 4, unsigned, ""), rsaRecord, false)
	add("zero-length-empty-body", "DKIM-Signature: "+func() string {
		h, e := SignDKIM([]byte(strings.Split(unsigned, "\r\n\r\n")[0]+"\r\n\r\n"), "sel", domain, rsaKey)
		if e != nil {
			t.Fatal(e)
		}
		return h
	}()+"\r\n"+strings.Split(unsigned, "\r\n\r\n")[0]+"\r\n\r\n", rsaRecord, false)
	add("tampered-body", strings.Replace(good, "body line", "evil line", 1), rsaRecord, false)
	add("tampered-header", strings.Replace(good, "Subject: DKIM fixture", "Subject: evil", 1), rsaRecord, false)
	add("dns-nxdomain", good, "", false)
	add("dns-temporary", good, "", true)
	add("no-key-record", good, "some unrelated record", false)
	add("revoked-key", good, "v=DKIM1; k=rsa; p=", false)
	add("bad-base64-key", good, "v=DKIM1; p=oops!", false)
	add("not-spki", good, "v=DKIM1; p="+base64.StdEncoding.EncodeToString([]byte("garbage")), false)
	add("rsa-sha1-forbidden", strings.Replace(good, "a=rsa-sha256", "a=rsa-sha1", 1), rsaRecord, false)
	add("unsupported-algorithm", strings.Replace(good, "a=rsa-sha256", "a=unknown", 1), rsaRecord, false)
	add("rsa-algorithm-ed-key", good, edRecord, false)
	edGood := sign("ed25519-sha256", "relaxed/relaxed", 0, unsigned, "")
	add("ed25519-go-direct-data", edGood, edRecord, false)
	add("ed-algorithm-rsa-key", edGood, rsaRecord, false)
	add("bad-signature", strings.Replace(good, "; b=", "; b=AAAA", 1), rsaRecord, false)
	add("duplicate-domain-last-wins", strings.Replace(good, "d="+domain, "d=victim.test; d="+domain, 1), rsaRecord, false)
	add("unsigned-query-identity-tags", strings.Replace(good, "; b=", "; q=invalid; i=forged@victim.test; z=whatever; b=", 1), rsaRecord, false)
	add("first-signature-only", "DKIM-Signature: d=other.test; s=bad; a=rsa-sha1\r\n"+good, rsaRecord, false)
	add("unknown-canonicalization", sign("rsa-sha256", "unknown/unknown", 0, unsigned, ""), rsaRecord, false)
	add("duplicate-from", sign("rsa-sha256", "relaxed/relaxed", 0, strings.Replace(unsigned, "To:", "From: second@dkim.smtp2.test\r\nTo:", 1), ""), rsaRecord, false)
	for name, value := range map[string]any{"dkim-vectors-go.json": vectors, "dkim-requests.json": sessions} {
		data, e := json.MarshalIndent(value, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, name)
		if _, e = os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("exists", path)
		}
		if e = os.WriteFile(path, append(data, '\n'), 0644); e != nil {
			t.Fatal(e)
		}
	}
}

// Record the signing stage AND frozen outbound DATA bytes received by a fake
// remote MTA. Queue claiming/MX/TLS policy belong to #350/#351, not this seam.
func TestRecordSMTPSigning(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	path := filepath.Join(root, "signing-go.json")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("golden exists")
	}
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	keyBytes, e := os.ReadFile(filepath.Join(root, "auth-fixture/rsa.pem"))
	if e != nil {
		t.Fatal(e)
	}
	key, e := ParseRSAPrivateKey(string(keyBytes))
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte("From: sender@dmarc.smtp2.test\r\nTo: alice@smtp1.test\r\nSubject: outbound signed fixture\r\nDate: Thu, 10 Sep 2026 10:00:00 +0000\r\nMessage-Id: <sign@smtp2.test>\r\n\r\nfirst line\r\n.dot line\r\n")
	rows := []map[string]any{}
	for _, body := range []struct{ name, raw string }{{"dkim-standard", string(raw)}, {"dkim-empty", strings.Split(string(raw), "\r\n\r\n")[0] + "\r\n\r\n"}, {"dkim-whitespace", strings.Replace(string(raw), "first line", "first \t line  \t", 1)}} {
		value, e := SignDKIM([]byte(body.raw), "default", "dmarc.smtp2.test", key)
		if e != nil {
			t.Fatal(e)
		}
		sig := parseDKIMSignature("DKIM-Signature: " + value + "\r\n" + body.raw)
		rows = append(rows, map[string]any{"name": body.name, "operation": "helper", "raw_base64": base64.StdEncoding.EncodeToString([]byte(body.raw)), "time": sig.Created, "header": value})
	}
	fixtureBytes, e := os.ReadFile(filepath.Join(root, "arc-requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var plans []smtpOracleSession
	if e = json.Unmarshal(fixtureBytes, &plans); e != nil {
		t.Fatal(e)
	}
	for _, index := range []int{0, 1, 2, 3, 4} {
		plan := plans[index]
		for _, file := range []string{"cleanup.sql", "seed.sql"} {
			data, e := os.ReadFile(filepath.Join(root, file))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Exec(ctx, string(data)); e != nil {
				t.Fatal(e)
			}
		}
		if plan.SetupSQL != "" {
			if _, e = pool.Exec(ctx, plan.SetupSQL); e != nil {
				t.Fatal(e)
			}
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		w := &OutboundWorker{pool: pool, logger: logger}
		signed := w.signDKIM(ctx, queueItem{fromAddr: "sender@dmarc.smtp2.test"}, string(raw))
		var timestamp int64
		if signed != string(raw) {
			sig := parseDKIMSignature("DKIM-Signature: " + signed)
			if sig == nil {
				t.Fatal("missing generated signature")
			}
			timestamp = sig.Created
		}
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		receipt := make(chan string, 1)
		errC := make(chan error, 1)
		go func() {
			conn, e := listener.Accept()
			if e != nil {
				errC <- e
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			var wire strings.Builder
			line, e := reader.ReadString('\n')
			wire.WriteString(line)
			if e != nil {
				errC <- e
				return
			}
			if line != "DATA\r\n" {
				errC <- fmt.Errorf("unexpected %q", line)
				return
			}
			fmt.Fprint(conn, "354 continue\r\n")
			for {
				line, e = reader.ReadString('\n')
				wire.WriteString(line)
				if e != nil {
					errC <- e
					return
				}
				if line == ".\r\n" {
					break
				}
			}
			fmt.Fprint(conn, "250 accepted\r\n")
			receipt <- wire.String()
		}()
		conn, e := net.Dial("tcp", listener.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		tp := textproto.NewConn(conn)
		code, reply, e := w.sendData(tp, signed)
		if e != nil {
			t.Fatal(e)
		}
		tp.Close()
		listener.Close()
		var wire string
		select {
		case wire = <-receipt:
		case e = <-errC:
			t.Fatal(e)
		}
		rows = append(rows, map[string]any{"name": "outbound-" + plan.Name, "operation": "outbound", "raw_base64": base64.StdEncoding.EncodeToString(raw), "time": timestamp, "signed_base64": base64.StdEncoding.EncodeToString([]byte(signed)), "wire_base64": base64.StdEncoding.EncodeToString([]byte(wire)), "code": code, "reply": reply, "setup_sql": plan.SetupSQL, "teardown_sql": plan.TeardownSQL})
		if plan.TeardownSQL != "" {
			if _, e = pool.Exec(ctx, plan.TeardownSQL); e != nil {
				t.Fatal(e)
			}
		}
	}
	cleanup, e := os.ReadFile(filepath.Join(root, "cleanup.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, string(cleanup)); e != nil {
		t.Fatal(e)
	}
	data, e := json.MarshalIndent(rows, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(data, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
