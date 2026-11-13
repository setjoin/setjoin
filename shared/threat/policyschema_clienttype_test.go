package threat

import "testing"

// med-shard3-022 / D-SHARED-THREAT-001 (CA-SCHEMA-ENUM-DRIFT-CONDITION-NO-OP).
// The F6 validator's stated purpose is converting "a typo'd condition silently
// fails to enforce" into an authoring-time rejection — and for client_type it
// failed exactly that: the accepted vocabulary (browser/native/pop/activesync)
// is never emitted by clientTypeFromProtocol (web/mobile/imap/smtp/caldav/
// legacy), so a validator-accepted 'browser' block policy evaluated 'skipped'
// with default-allow. The domain is now derived from the emitter constants;
// these tests pin the alignment in both directions.

// Authoring-time rejection: condition values that can never be emitted must be
// REJECTED, not accepted into a dead (default-allow) block policy.
func TestValidatePolicyDocumentRejectsNeverEmittedClientTypes(t *testing.T) {
	for _, v := range []string{"browser", "native", "pop", "activesync"} {
		conds := map[string]interface{}{"client_type": v}
		err := ValidatePolicyDocument(conds, map[string]interface{}{"action": "block"})
		if err == nil {
			t.Errorf("client_type %q is never emitted at runtime; a block policy carrying it must be rejected at authoring time, got nil error", v)
			continue
		}
		if !containsSubstr(err.Error(), v) {
			t.Errorf("rejection must name the offending value %q, got: %v", v, err)
		}
	}
}

// Every value the runtime emitters can produce must remain authorable.
func TestValidatePolicyDocumentAcceptsAllEmittedClientTypes(t *testing.T) {
	for _, v := range AllowedClientTypeValues() {
		conds := map[string]interface{}{"client_type": v}
		if err := ValidatePolicyDocument(conds, map[string]interface{}{"action": "block"}); err != nil {
			t.Errorf("runtime-emitted client_type %q must validate, got: %v", v, err)
		}
	}
}

// TestClientTypeDomainMatchesRuntimeEmission is the mechanical anti-drift check:
// drive clientTypeFromProtocol / clientTypeFromProtocolUmbrella over the whole
// protocol/UA surface and require every emitted value to be inside the validator
// domain — and the domain to contain exactly the emittable vocabulary. A new
// emitter value without a validator update fails here instead of producing
// unauthorable policies; a hand-added non-emittable domain value fails too.
func TestClientTypeDomainMatchesRuntimeEmission(t *testing.T) {
	emitted := map[string]bool{}
	cases := []struct {
		protocol, ua string
		umbrella     bool
	}{
		{ProtocolHTTP, "Mozilla/5.0 (Macintosh; Intel Mac OS X) Safari/605", false},
		{ProtocolHTTP, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile", false},
		{ProtocolHTTP, "", false},
		{ProtocolIMAP, "", false},
		{ProtocolSMTP, "", false},
		{ProtocolCalDAV, "", false},
		{ProtocolCardDAV, "", false},
		{"some-future-protocol", "", false}, // default arm → web
		{ProtocolIMAP, "", true},            // umbrella → legacy
		{ProtocolSMTP, "", true},            // umbrella → legacy
		{ProtocolHTTP, "Mozilla/5.0 (Linux; Android 14; Mobile)", true},
	}
	for _, tc := range cases {
		ct := clientTypeFromProtocolUmbrella(tc.protocol, tc.ua, tc.umbrella)
		if ct == "" {
			t.Fatalf("emitter returned empty client_type for protocol=%q umbrella=%v", tc.protocol, tc.umbrella)
		}
		emitted[ct] = true
		if err := ValidatePolicyDocument(map[string]interface{}{"client_type": ct}, nil); err != nil {
			t.Errorf("runtime-emitted client_type %q must be authorable (in the validator domain), got: %v", ct, err)
		}
	}

	want := map[string]bool{
		ClientTypeWeb:    true,
		ClientTypeMobile: true,
		ProtocolIMAP:     true,
		ProtocolSMTP:     true,
		ProtocolCalDAV:   true,
		ClientTypeLegacy: true,
	}
	got := map[string]bool{}
	for _, v := range AllowedClientTypeValues() {
		got[v] = true
	}
	if len(got) != len(want) {
		t.Fatalf("client_type domain %v drifted from the emittable set %v", got, want)
	}
	for v := range want {
		if !got[v] {
			t.Errorf("emittable client_type %q missing from the validator domain", v)
		}
		if !emitted[v] {
			t.Errorf("domain value %q was not produced by any emitter case — extend the emitter table if a new runtime value is real", v)
		}
	}
}
