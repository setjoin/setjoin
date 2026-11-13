//go:build gofree_record

package smtp

// Fixtures only. Every SMTP reply, calendar effect and notification is recorded
// by TestRecordSMTPListener through production Go, not predicted here.
import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateSMTP6IMIPRequests(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	path := filepath.Join(root, "security-imip-smime-requests.json")
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("refusing existing stimuli")
	}
	raw, e := os.ReadFile(filepath.Join(root, "security-imip-roles-requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var templates []smtpOracleSession
	if e = json.Unmarshal(raw, &templates); e != nil {
		t.Fatal(e)
	}
	base := templates[0]
	signer := smtp6NewSigner(t, []string{"organizer@external.test", "second@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2020, 2099)
	attendee := smtp6NewSigner(t, []string{"alice@smtp1.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2020, 2099)
	cleanup := "DELETE FROM smime_trust_anchors WHERE label='smtp6-fixture'; DELETE FROM smime_revocation_blocklist WHERE reason='smtp6-fixture'; DELETE FROM recipient_smime_certs WHERE owner_user_id BETWEEN 9348011 AND 9348013;"
	var cases []smtpOracleSession
	for _, tc := range []struct{ name, domain, kind string }{
		{"smime-cancel-global", "NULL", ""}, {"smime-cancel-recipient-domain", "9348001", ""}, {"smime-cancel-foreign-domain", "9348002", ""}, {"smime-cancel-unknown-anchor", "none", ""},
		{"smime-cancel-revoked-badge", "NULL", "revoked"}, {"smime-cancel-wrong-from", "NULL", "from"}, {"smime-cancel-second-san", "NULL", "second"}, {"smime-cancel-tampered", "NULL", "tamper"},
		{"smime-cancel-occurrence-domain", "9348001", "occurrence"}, {"smime-request-untrusted-no-fallback", "none", "request"}, {"smime-request-valid", "NULL", "request"},
		{"smime-reply-domain", "9348001", "reply"}, {"smime-reply-global", "NULL", "reply"}, {"smime-cancel-trailing-unsigned-request", "NULL", "tail"},
	} {
		s := base
		s.Name = tc.name
		s.MailAuth = map[string]bool{}
		s.DNS = nil
		s.SetupSQL = cleanup + base.SetupSQL
		s.TeardownSQL = cleanup + base.TeardownSQL
		method := "CANCEL"
		from := "organizer@external.test"
		sig := signer
		if tc.kind == "reply" {
			method = "REPLY"
			from = "alice@smtp1.test"
			sig = attendee
		}
		if tc.kind == "request" {
			method = "REQUEST"
		}
		if tc.domain != "none" {
			s.SetupSQL += smtp6Anchor(sig, tc.domain)
		}
		if tc.kind == "revoked" {
			s.MailAuth["feature.smime_verify"] = true
			s.SetupSQL += fmt.Sprintf("INSERT INTO smime_revocation_blocklist(fingerprint,reason) VALUES('%x','smtp6-fixture');", sha256.Sum256(sig.leaf.Raw))
		}
		content := "Content-Type: text/calendar; method=" + method + "\r\n\r\nBEGIN:VCALENDAR\r\nMETHOD:" + method + "\r\nBEGIN:VEVENT\r\nUID:smtp6-meeting\r\nSUMMARY:Signed meeting\r\nDTSTART:20300103T100000Z\r\nDTEND:20300103T110000Z\r\nORGANIZER:mailto:organizer@external.test\r\nATTENDEE;CN=Alice;PARTSTAT=ACCEPTED:mailto:alice@smtp1.test\r\n"
		if tc.kind == "occurrence" {
			content += "RECURRENCE-ID:20300103T100000Z\r\n"
		}
		content += "END:VEVENT\r\nEND:VCALENDAR\r\n"
		if tc.kind == "second" {
			from = "second@external.test"
			s.SetupSQL += "UPDATE calendar_events SET organizer_email='second@external.test' WHERE id IN (9348061,9348062);"
			content = strings.ReplaceAll(content, "organizer@external.test", from)
		}
		body := smtp6Detached(t, sig, content)
		if tc.kind == "tamper" {
			body = strings.Replace(body, "Signed meeting", "Tampered meeting", 1)
		}
		if tc.kind == "from" {
			from = "different@external.test"
		}
		if tc.kind == "tail" {
			body += "Content-Type: text/calendar; method=REQUEST\r\n\r\nMETHOD:REQUEST\r\n"
		}
		s.Steps = smtp6Session(tc.name, "relay@external.test", "alias@smtp1.test", "Relay", body, "", "", nil, nil).Steps
		s.Steps[3].Send = strings.Replace(s.Steps[3].Send, "From: Relay <relay@external.test>", "From: <"+from+">", 1)
		cases = append(cases, s)
	}
	bytes, e := json.MarshalIndent(cases, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(bytes, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}

func TestGenerateSMTP6IMIPDKIMRequests(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	path := filepath.Join(root, "security-imip-dkim-requests.json")
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("refusing existing stimuli")
	}
	keyBytes, e := os.ReadFile(filepath.Join(root, "auth-fixture/rsa.pem"))
	if e != nil {
		t.Fatal(e)
	}
	key, e := ParseRSAPrivateKey(string(keyBytes))
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(root, "security-imip-roles-requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var templates []smtpOracleSession
	if e = json.Unmarshal(raw, &templates); e != nil {
		t.Fatal(e)
	}
	var cases []smtpOracleSession
	for _, tc := range []struct{ name, domain, from, kind string }{
		{"dkim-cancel-full", "external.test", "organizer@external.test", ""},
		{"dkim-cancel-misaligned", "attacker.test", "organizer@external.test", ""},
		{"dkim-cancel-full-address-mismatch", "external.test", "attacker@external.test", ""},
		{"dkim-reply-full", "smtp1.test", "alice@smtp1.test", "reply"},
		{"dkim-cancel-occurrence-full", "external.test", "organizer@external.test", "occurrence"},
	} {
		s := templates[0]
		if tc.kind == "reply" {
			s = templates[9]
		}
		if tc.kind == "occurrence" {
			s = templates[5]
		}
		s.Name = tc.name
		s.MailAuth = map[string]bool{"feature.dkim": true}
		s.Steps = append([]smtpOracleStep(nil), s.Steps...)
		wire := s.Steps[3].Send
		wire = strings.TrimSuffix(wire, ".\r\n")
		wire = strings.Replace(wire, "From: organizer@external.test", "From: "+tc.from, 1)
		wire = strings.Replace(wire, "From: alice@smtp1.test", "From: "+tc.from, 1)
		// No l= signature: production Go hashing/canonicalization and standard RSA.
		sig := &DKIMSig{Domain: tc.domain, Selector: "smtp6", Algorithm: "rsa-sha256", Canonical: "relaxed/relaxed", Headers: []string{"from", "to", "subject"}, Created: time.Now().Unix(), Expires: time.Now().Add(24 * time.Hour).Unix()}
		_, body := splitHeadersBody([]byte(wire))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, 0))
		digest := sha256.Sum256([]byte(dkimSignedData(wire, sig)))
		signature, e := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
		if e != nil {
			t.Fatal(e)
		}
		s.Steps[3].Send = "DKIM-Signature: " + dkimSigBody(sig) + base64.StdEncoding.EncodeToString(signature) + "\r\n" + wire + ".\r\n"
		records, _ := json.Marshal([]string{"v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)})
		s.DNS = map[string]json.RawMessage{"txt:smtp6._domainkey." + tc.domain: records}
		cases = append(cases, s)
	}
	bytes, e := json.MarshalIndent(cases, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(bytes, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}

func TestGenerateSMTP6IMIPBytesRequests(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	path := filepath.Join(root, "security-imip-bytes-requests.json")
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("refusing existing stimuli")
	}
	raw, e := os.ReadFile(filepath.Join(root, "security-imip-requests-requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var templates []smtpOracleSession
	if e = json.Unmarshal(raw, &templates); e != nil {
		t.Fatal(e)
	}
	signer := smtp6NewSigner(t, []string{"organizer@external.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, 2020, 2099)
	cleanup := "DELETE FROM smime_trust_anchors WHERE label='smtp6-fixture'; DELETE FROM recipient_smime_certs WHERE owner_user_id BETWEEN 9348011 AND 9348013;"
	content := "Content-Type: text/calendar; method=REQUEST; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nBEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:smtp6-calendar-bytes\r\nSUMMARY:Caf\xe9\r\nDTSTART:20300102T100000Z\r\nDTEND:20300102T110000Z\r\nORGANIZER:mailto:organizer@external.test\r\nATTENDEE:mailto:alice@smtp1.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	s := smtp6Session("imip-signed-8bit-pristine", "organizer@external.test", "alias@smtp1.test", "Organizer", smtp6Detached(t, signer, content), cleanup+templates[0].SetupSQL+smtp6Anchor(signer, "NULL"), cleanup+templates[0].TeardownSQL, map[string]bool{"feature.smime_verify": true}, nil)
	s.Steps[3].SendBase64 = base64.StdEncoding.EncodeToString([]byte(s.Steps[3].Send))
	s.Steps[3].Send = ""
	bytes, e := json.MarshalIndent([]smtpOracleSession{s}, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(bytes, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
