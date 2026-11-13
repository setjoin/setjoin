package jmap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/smime"
)

// --- description map for the encrypt reasons (Step 1) ---

func TestSmimeNotCreatedDescription_EncryptReasons(t *testing.T) {
	cases := []struct{ reason string }{
		{smime.ReasonEncryptNoCert},
		{smime.ReasonEncryptNoSenderCert},
		{smime.ReasonEncryptNoJournalCert},
	}
	for _, c := range cases {
		got := smimeNotCreatedDescription(c.reason)
		if got == "" || got == "S/MIME signing failed." {
			t.Errorf("reason %q: want a specific encrypt description, got %q", c.reason, got)
		}
	}
}

func TestExtractEmailsRejectsMalformedAndOmitsEmptyAddresses(t *testing.T) {
	t.Parallel()
	if got := extractEmails(nil); got != nil {
		t.Fatalf("nil input = %v, want nil", got)
	}
	if got := extractEmails([]byte(`{"email":`)); got != nil {
		t.Fatalf("malformed input = %v, want nil", got)
	}
	want := []string{"a@example.test", "b@example.test"}
	got := extractEmails([]byte(`[{"email":"a@example.test"},{"email":""},{"email":"b@example.test"}]`))
	if !slices.Equal(got, want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
}

// genEncryptCert builds a self-signed RSA cert binding email (encryption-capable).
func genEncryptCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// genSigningOnlyCert mints an RSA cert whose keyUsage is DigitalSignature ONLY
// (no keyEncipherment). IsEncryptionCapable rejects it (present keyUsage lacking
// keyEncipherment = sign-only), so it models an admin who configured a
// signing-only journal cert — which must surface ReasonEncryptNoJournalCert, not
// the user-facing no-cert marker.
func genSigningOnlyCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// --- buildEncryptCertSet (Step 2) ---

func TestBuildEncryptCertSet_Union(t *testing.T) {
	r1 := genEncryptCert(t, "r1")
	r2 := genEncryptCert(t, "r2")
	sender := genEncryptCert(t, "sender")
	journal := genEncryptCert(t, "journal")

	set := buildEncryptCertSet([]*x509.Certificate{r1, r2}, sender, journal)
	if len(set) != 4 {
		t.Fatalf("want 4 (r1,r2,sender,journal), got %d", len(set))
	}
}

func TestBuildEncryptCertSet_NilSenderAndJournalOmitted(t *testing.T) {
	r1 := genEncryptCert(t, "r1")
	set := buildEncryptCertSet([]*x509.Certificate{r1}, nil, nil)
	if len(set) != 1 {
		t.Fatalf("nil sender/journal must be omitted: want 1, got %d", len(set))
	}
}

func TestBuildEncryptCertSet_DedupByFingerprint(t *testing.T) {
	r1 := genEncryptCert(t, "r1")
	// sender == one of the recipients (encrypt-to-self of an internal recipient).
	set := buildEncryptCertSet([]*x509.Certificate{r1}, r1, nil)
	if len(set) != 1 {
		t.Fatalf("dedup by fingerprint: want 1, got %d", len(set))
	}
}

// --- fail-closed per-creation outcomes (Step 3) ---
// A stub of the smimeEncryptOps seam lets us drive every branch with no DB / no S3.

type stubEncryptResolver struct {
	// certByEmail returns (cert, ok) for ResolveEncryptCert; missing key → not ok.
	certByEmail map[string]*x509.Certificate
	// the draft envelope SenderInfo returns.
	fromAddr   string
	domainID   int64
	recipients []string
	// journalingRequired + journalCert (configured) for the journal branch.
	journalingRequired bool
	journalCert        *x509.Certificate
	journalConfigured  bool
	// captured cert set handed to SignAndEncrypt (for assertions).
	gotCerts []*x509.Certificate
}

func (s *stubEncryptResolver) ResolveEncryptCert(_ context.Context, _ int64, email string) (*x509.Certificate, bool) {
	c, ok := s.certByEmail[email]
	return c, ok
}
func (s *stubEncryptResolver) SenderInfo(_ context.Context, _ int64, _ string) (string, int64, []string, bool) {
	return s.fromAddr, s.domainID, s.recipients, true
}
func (s *stubEncryptResolver) JournalingRequired(_ context.Context, _ int64) (bool, error) {
	return s.journalingRequired, nil
}
func (s *stubEncryptResolver) JournalCert(_ context.Context, _ int64) (*x509.Certificate, bool, error) {
	return s.journalCert, s.journalConfigured, nil
}
func (s *stubEncryptResolver) SignAndEncrypt(_ context.Context, _ int64, emailID string, certs []*x509.Certificate, _ bool) (string, error) {
	s.gotCerts = certs
	return "enc-blob-" + emailID, nil
}

func TestProcessSubmissions_EncryptFailClosed(t *testing.T) {
	recip := genEncryptCert(t, "to@x.test")
	sender := genEncryptCert(t, "u@x.test")

	base := func() *stubEncryptResolver {
		return &stubEncryptResolver{
			certByEmail: map[string]*x509.Certificate{
				"to@x.test": recip,
				"u@x.test":  sender,
			},
			fromAddr:   "u@x.test",
			domainID:   1,
			recipients: []string{"to@x.test"},
		}
	}

	cases := []struct {
		name        string
		resolver    *stubEncryptResolver
		wantReason  string // "" = success (no notCreated)
		wantDropped bool
		wantEncrypt bool
	}{
		{
			name:        "all_resolve",
			resolver:    base(),
			wantReason:  "",
			wantDropped: false,
			wantEncrypt: true,
		},
		{
			name: "recipient_unresolved",
			resolver: func() *stubEncryptResolver {
				r := base()
				delete(r.certByEmail, "to@x.test")
				return r
			}(),
			wantReason:  smime.ReasonEncryptNoCert,
			wantDropped: true,
		},
		{
			name: "sender_unresolved",
			resolver: func() *stubEncryptResolver {
				r := base()
				delete(r.certByEmail, "u@x.test")
				return r
			}(),
			wantReason:  smime.ReasonEncryptNoSenderCert,
			wantDropped: true,
		},
		{
			name: "journal_required_no_cert",
			resolver: func() *stubEncryptResolver {
				r := base()
				r.journalingRequired = true
				r.journalConfigured = false
				return r
			}(),
			wantReason:  smime.ReasonEncryptNoJournalCert,
			wantDropped: true,
		},
		{
			name: "journal_required_with_cert",
			resolver: func() *stubEncryptResolver {
				r := base()
				r.journalingRequired = true
				r.journalConfigured = true
				r.journalCert = genEncryptCert(t, "journal@x.test")
				return r
			}(),
			wantReason:  "",
			wantDropped: false,
			wantEncrypt: true,
		},
		{
			// REGRESSION: a CONFIGURED but signing-only journal cert must fail
			// closed under the ADMIN marker (ReasonEncryptNoJournalCert), not the
			// user-facing ReasonEncryptNoCert. Without the IsEncryptionCapable gate
			// on the journal cert, smime.Encrypt would fail later and surface the
			// wrong (no-cert, empty-address) marker that blames the sender.
			name: "journal_required_signing_only_cert",
			resolver: func() *stubEncryptResolver {
				r := base()
				r.journalingRequired = true
				r.journalConfigured = true
				r.journalCert = genSigningOnlyCert(t, "journal@x.test")
				return r
			}(),
			wantReason:  smime.ReasonEncryptNoJournalCert,
			wantDropped: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEncryptTestHandler(tc.resolver)
			create := map[string]json.RawMessage{
				"c1": json.RawMessage(`{"emailId":"42","encryptSMIME":true}`),
			}
			modified, processedRefs, isEncrypted, notCreated := h.processSubmissions(
				context.Background(), 7, 7, create)

			if tc.wantReason == "" {
				if _, dropped := modified["c1"]; !dropped {
					t.Errorf("success: c1 must survive in modified")
				}
				if len(notCreated) != 0 {
					t.Errorf("success: want no notCreated, got %v", notCreated)
				}
				if tc.wantEncrypt {
					if processedRefs["c1"] == "" {
						t.Errorf("success: want processedRefs[c1] set")
					}
					if !isEncrypted["c1"] {
						t.Errorf("success: want isEncrypted[c1]=true")
					}
				}
				return
			}
			// Failure: dropped + the right reason.
			if _, present := modified["c1"]; present {
				t.Errorf("%s: creation must be DROPPED from modified", tc.name)
			}
			entry, ok := notCreated["c1"]
			if !ok {
				t.Fatalf("%s: want notCreated[c1]", tc.name)
			}
			var obj struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(entry, &obj); err != nil {
				t.Fatal(err)
			}
			if obj.Type != tc.wantReason {
				t.Errorf("%s: notCreated type = %q, want %q", tc.name, obj.Type, tc.wantReason)
			}
		})
	}
}

// P4: the no-cert notCreated entry must NAME the offending recipients (D-F2:
// "names ALL recipients") so the compose UX can list every gap up front, not just
// say "some recipients". ALL unresolved recipients must appear in addresses, and
// the markers that have no per-recipient meaning (sender/journal) carry no list.
func TestProcessSubmissions_NoCertEntryNamesAllMissingRecipients(t *testing.T) {
	sender := genEncryptCert(t, "u@x.test")
	good := genEncryptCert(t, "ok@x.test")
	// Two recipients with no cert + one with a cert; the entry must list BOTH gaps.
	resolver := &stubEncryptResolver{
		certByEmail: map[string]*x509.Certificate{
			"u@x.test":  sender,
			"ok@x.test": good,
		},
		fromAddr:   "u@x.test",
		domainID:   1,
		recipients: []string{"alice@ext.test", "ok@x.test", "bob@ext.test"},
	}
	h := newEncryptTestHandler(resolver)
	create := map[string]json.RawMessage{
		"c1": json.RawMessage(`{"emailId":"42","encryptSMIME":true}`),
	}
	_, _, _, notCreated := h.processSubmissions(context.Background(), 7, 7, create)

	entry, ok := notCreated["c1"]
	if !ok {
		t.Fatal("want notCreated[c1]")
	}
	var obj struct {
		Type      string   `json:"type"`
		Addresses []string `json:"addresses"`
	}
	if err := json.Unmarshal(entry, &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Type != smime.ReasonEncryptNoCert {
		t.Fatalf("type = %q, want %q", obj.Type, smime.ReasonEncryptNoCert)
	}
	got := map[string]bool{}
	for _, a := range obj.Addresses {
		got[a] = true
	}
	if !got["alice@ext.test"] || !got["bob@ext.test"] {
		t.Errorf("addresses must list ALL missing recipients, got %v", obj.Addresses)
	}
	if got["ok@x.test"] {
		t.Errorf("a recipient WITH a cert must NOT appear in addresses, got %v", obj.Addresses)
	}
}

// The sender/journal markers carry no per-recipient address list (the compose copy
// for those is about the user's own cert / the admin, not a recipient roster).
func TestProcessSubmissions_SenderAndJournalMarkersHaveNoAddresses(t *testing.T) {
	cases := []struct {
		name     string
		resolver *stubEncryptResolver
		want     string
	}{
		{
			name: "sender",
			resolver: &stubEncryptResolver{
				certByEmail: map[string]*x509.Certificate{"to@x.test": genEncryptCert(t, "to@x.test")},
				fromAddr:    "u@x.test", domainID: 1, recipients: []string{"to@x.test"},
			},
			want: smime.ReasonEncryptNoSenderCert,
		},
		{
			name: "journal",
			resolver: &stubEncryptResolver{
				certByEmail: map[string]*x509.Certificate{
					"to@x.test": genEncryptCert(t, "to@x.test"),
					"u@x.test":  genEncryptCert(t, "u@x.test"),
				},
				fromAddr: "u@x.test", domainID: 1, recipients: []string{"to@x.test"},
				journalingRequired: true, journalConfigured: false,
			},
			want: smime.ReasonEncryptNoJournalCert,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEncryptTestHandler(tc.resolver)
			create := map[string]json.RawMessage{"c1": json.RawMessage(`{"emailId":"42","encryptSMIME":true}`)}
			_, _, _, notCreated := h.processSubmissions(context.Background(), 7, 7, create)
			var obj struct {
				Type      string   `json:"type"`
				Addresses []string `json:"addresses"`
			}
			if err := json.Unmarshal(notCreated["c1"], &obj); err != nil {
				t.Fatal(err)
			}
			if obj.Type != tc.want {
				t.Fatalf("type = %q, want %q", obj.Type, tc.want)
			}
			if len(obj.Addresses) != 0 {
				t.Errorf("%s marker must carry no addresses, got %v", tc.name, obj.Addresses)
			}
		})
	}
}

// encrypt NOT requested → unchanged passthrough (no encryption).
func TestProcessSubmissions_NoEncryptPassthrough(t *testing.T) {
	h := newEncryptTestHandler(&stubEncryptResolver{})
	create := map[string]json.RawMessage{
		"c1": json.RawMessage(`{"emailId":"42"}`),
	}
	modified, processedRefs, isEncrypted, notCreated := h.processSubmissions(
		context.Background(), 7, 7, create)
	if len(notCreated) != 0 {
		t.Errorf("no-encrypt: want no notCreated, got %v", notCreated)
	}
	if len(processedRefs) != 0 {
		t.Errorf("no-encrypt: want no processedRefs, got %v", processedRefs)
	}
	if isEncrypted["c1"] {
		t.Errorf("no-encrypt: isEncrypted[c1] must be false")
	}
	if string(modified["c1"]) != `{"emailId":"42"}` {
		t.Errorf("no-encrypt: c1 must pass through unchanged, got %s", modified["c1"])
	}
}

// TestProcessSubmissions_EncryptUsesEnvelopeRecipients proves encrypt cert
// resolution targets the SMTP envelope recipients (the delivery set) — not the
// draft to/cc/bcc headers — when the submission carries an explicit envelope.
// SenderInfo (the draft headers) lists ONLY a no-cert address; the envelope lists
// a recipient WITH a cert. Honoring the envelope makes the send succeed; falling
// back to the draft headers would fail closed (no cert) — so this is non-vacuous.
func TestProcessSubmissions_EncryptUsesEnvelopeRecipients(t *testing.T) {
	sender := genEncryptCert(t, "u@x.test")
	envRcpt := genEncryptCert(t, "env@x.test")
	resolver := &stubEncryptResolver{
		certByEmail: map[string]*x509.Certificate{
			"u@x.test":   sender,
			"env@x.test": envRcpt,
			// "draft@x.test" (the draft header) intentionally has NO cert.
		},
		fromAddr:   "u@x.test",
		domainID:   1,
		recipients: []string{"draft@x.test"}, // SenderInfo = draft headers (no cert)
	}
	h := newEncryptTestHandler(resolver)
	create := map[string]json.RawMessage{
		"c1": json.RawMessage(`{"emailId":"42","encryptSMIME":true,"envelope":{"rcptTo":[{"email":"env@x.test"}]}}`),
	}
	modified, processedRefs, isEncrypted, notCreated := h.processSubmissions(
		context.Background(), 7, 7, create)

	if len(notCreated) != 0 {
		t.Fatalf("envelope recipient HAS a cert → must NOT fail closed; got notCreated=%v", notCreated)
	}
	if !isEncrypted["c1"] || processedRefs["c1"] == "" {
		t.Errorf("want encrypted success using the envelope recipient (isEncrypted+processedRef)")
	}
	if _, ok := modified["c1"]; !ok {
		t.Errorf("c1 must survive in modified")
	}
	// The cert set handed to SignAndEncrypt must include the ENVELOPE recipient's cert.
	gotEnv := false
	for _, c := range resolver.gotCerts {
		if c.Equal(envRcpt) {
			gotEnv = true
		}
	}
	if !gotEnv {
		t.Errorf("SignAndEncrypt cert set must include the envelope recipient's cert")
	}
}

// newEncryptTestHandler builds a no-DB handler whose smimeEncryptOps seam is the
// stub, so processSubmissions' decision tree runs with no Postgres / no S3.
func newEncryptTestHandler(ops smimeEncryptOps) *JMAPHandler {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	h.encryptOps = ops
	return h
}
