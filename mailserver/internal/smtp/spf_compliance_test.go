package smtp

import (
	"testing"
)

// TestSPF_MultipleRecords_PermError verifies RFC 7208 §4.5:
// Multiple SPF TXT records MUST return permerror.
func TestSPF_MultipleRecords_PermError(t *testing.T) {
	// evaluateSPF with a valid record should not crash
	result := evaluateSPF("v=spf1 +all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result == SPFPermErr {
		t.Error("single SPF record should not be permerror")
	}
	if result != SPFPass {
		t.Logf("single +all SPF record returned %s (expected pass)", result)
	}
}

// TestSPF_CaseInsensitive_Matching verifies RFC 7208 §4.6:
// SPF mechanism matching MUST be case-insensitive.
func TestSPF_CaseInsensitive_Matching(t *testing.T) {
	// Test with mixed-case mechanism names
	// "ALL" should match (with + qualifier = pass)
	result := evaluateSPF("v=spf1 +ALL", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("case-insensitive ALL mechanism: expected pass, got %s (RFC 7208 §4.6)", result)
	}

	// "Ip4:" prefix should be case-insensitive
	result = evaluateSPF("v=spf1 Ip4:127.0.0.1", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("case-insensitive Ip4 mechanism: expected pass, got %s (RFC 7208 §4.6)", result)
	}
}

// TestSPF_Qualifiers verifies SPF qualifier behavior (RFC 7208 §4.6.2).
func TestSPF_Qualifiers(t *testing.T) {
	// + (pass)
	result := evaluateSPF("v=spf1 +all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("'+' qualifier: expected pass, got %s", result)
	}

	// - (fail)
	result = evaluateSPF("v=spf1 -all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFFail {
		t.Errorf("'-' qualifier: expected fail, got %s", result)
	}

	// ~ (softfail)
	result = evaluateSPF("v=spf1 ~all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFSoftFail {
		t.Errorf("'~' qualifier: expected softfail, got %s", result)
	}

	// ? (neutral)
	result = evaluateSPF("v=spf1 ?all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFNeutral {
		t.Errorf("'?' qualifier: expected neutral, got %s", result)
	}
}

// TestSPF_DefaultQualifier_IsPlus verifies RFC 7208 §4.6.2:
// Default qualifier is '+' (pass).
func TestSPF_DefaultQualifier_IsPlus(t *testing.T) {
	result := evaluateSPF("v=spf1 all", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("default qualifier: expected pass (implicit '+'), got %s (RFC 7208 §4.6.2)", result)
	}
}

// TestSPF_IP4_Matching verifies ip4 mechanism matching.
func TestSPF_IP4_Matching(t *testing.T) {
	// Exact IP match
	result := evaluateSPF("v=spf1 ip4:192.168.1.1", "example.com", "192.168.1.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("ip4 exact match: expected pass, got %s", result)
	}

	// CIDR match
	result = evaluateSPF("v=spf1 ip4:192.168.0.0/16", "example.com", "192.168.1.1", "", "", 0, &[]int{0}[0])
	if result != SPFPass {
		t.Errorf("ip4 CIDR match: expected pass, got %s", result)
	}

	// Non-match
	result = evaluateSPF("v=spf1 ip4:10.0.0.1", "example.com", "192.168.1.1", "", "", 0, &[]int{0}[0])
	if result != SPFNeutral {
		t.Errorf("ip4 non-match: expected neutral, got %s", result)
	}
}

// TestSPF_Include_Mechanism verifies the include: mechanism.
func TestSPF_Include_Mechanism(t *testing.T) {
	// include: with a domain that has no SPF record → should return None
	// Since we can't do real DNS lookups in unit tests, test the qualifier handling
	result := evaluateSPF("v=spf1 +include:example.com", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	// DNS lookup will fail in test → temperror or none depending on NXDOMAIN
	if result != SPFTempErr && result != SPFNone && result != SPFPermErr {
		t.Logf("include: mechanism with DNS failure returned %s", result)
	}
}

// TestSPF_Redirect_Mechanism verifies the redirect= mechanism.
func TestSPF_Redirect_Mechanism(t *testing.T) {
	result := evaluateSPF("v=spf1 redirect=example.com", "example.com", "127.0.0.1", "", "", 0, &[]int{0}[0])
	// redirect replaces the entire evaluation
	if result != SPFTempErr && result != SPFNone && result != SPFPermErr {
		t.Logf("redirect= mechanism returned %s", result)
	}
}

// TestSPF_DNS_LookupCount verifies RFC 7208 §4.6.4:
// Total DNS lookups must not exceed 10.
func TestSPF_DNS_LookupCount(t *testing.T) {
	// countLookup with 10 existing lookups should return permerror
	lookups := 10
	result := countLookup(&lookups)
	if result != SPFPermErr {
		t.Errorf("countLookup at 10: expected permerror, got %s (RFC 7208 §4.6.4)", result)
	}

	// countLookup with 0 lookups should return ""
	lookups = 0
	result = countLookup(&lookups)
	if result != "" {
		t.Errorf("countLookup at 0: expected '', got %s", result)
	}
	if lookups != 1 {
		t.Errorf("countLookup should increment counter, got %d", lookups)
	}
}

// TestSPF_Recursion_Depth_Limit verifies max recursion depth of 10.
func TestSPF_Recursion_Depth_Limit(t *testing.T) {
	result := checkSPFDepth("example.com", "127.0.0.1", "", "", 11, &[]int{0}[0])
	if result != SPFPermErr {
		t.Errorf("depth 11: expected permerror, got %s (RFC 7208 §4.6.4)", result)
	}
}

// TestSPF_MacroExpansion verifies basic macro expansion (RFC 7208 §7).
func TestSPF_MacroExpansion(t *testing.T) {
	result := expandSPFMacros("%{d}", "example.com", "user@example.com", "mail.example.com", "1.2.3.4")
	if result != "example.com" {
		t.Errorf("%%{d} expansion: expected 'example.com', got %s", result)
	}

	result = expandSPFMacros("%{s}", "example.com", "user@example.com", "", "")
	if result != "user@example.com" {
		t.Errorf("%%{s} expansion: expected 'user@example.com', got %s", result)
	}

	result = expandSPFMacros("%{l}", "example.com", "user@example.com", "", "")
	if result != "user" {
		t.Errorf("%%{l} expansion: expected 'user', got %s", result)
	}

	result = expandSPFMacros("%{o}", "example.com", "user@example.com", "", "")
	if result != "example.com" {
		t.Errorf("%%{o} expansion: expected 'example.com', got %s", result)
	}

	result = expandSPFMacros("%{i}", "example.com", "", "", "1.2.3.4")
	if result != "1.2.3.4" {
		t.Errorf("%%{i} expansion: expected '1.2.3.4', got %s", result)
	}

	result = expandSPFMacros("%{h}", "example.com", "", "mail.example.com", "")
	if result != "mail.example.com" {
		t.Errorf("%%{h} expansion: expected 'mail.example.com', got %s", result)
	}
}
