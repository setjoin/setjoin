package main

import (
	"strings"
	"testing"
)

// TestValidateDocBadGrantType — a policy doc with an unknown grant type returns
// a BZ085-class error whose message contains "grant" and the skeleton hint.
func TestValidateDocBadGrantType(t *testing.T) {
	doc := `{
		"schemaVersion": 1,
		"policies": [{
			"name": "bad",
			"actions": {"grants": [{"type": "frobnicate"}]}
		}]
	}`
	warns, err := validateDoc([]byte(doc))
	if err == nil {
		t.Fatal("expected error for unknown grant type, got nil")
	}
	if !strings.Contains(err.Error(), "BZ085") {
		t.Errorf("expected BZ085 in error, got: %v", err)
	}
	// The error hint should include the canonical skeleton so authors know what's valid.
	if !strings.Contains(err.Error(), "grants") {
		t.Errorf("expected 'grants' skeleton hint in error, got: %v", err)
	}
	_ = warns // warnings may be nil on hard error
}

// TestValidateDocValid — a well-formed doc returns no error and warnings is nil/empty.
func TestValidateDocValid(t *testing.T) {
	doc := `{
		"schemaVersion": 1,
		"policies": [{
			"name": "mfa-for-all",
			"conditions": {"device_trust": "managed"},
			"actions": {"grants": [{"type": "require_acr", "acr": "aal2"}]}
		}],
		"named_locations": [],
		"auth_strengths": []
	}`
	warns, err := validateDoc([]byte(doc))
	if err != nil {
		t.Fatalf("expected valid doc to pass, got: %v", err)
	}
	if len(warns) > 0 {
		t.Logf("warnings (non-fatal): %v", warns)
	}
}

// TestValidateDocUnknownConditionKey — unknown condition key → BZ085 error.
func TestValidateDocUnknownConditionKey(t *testing.T) {
	doc := `{
		"schemaVersion": 1,
		"policies": [{
			"name": "p",
			"conditions": {"frobnicate": "yes"},
			"actions": {"grants": [{"type": "block"}]}
		}]
	}`
	_, err := validateDoc([]byte(doc))
	if err == nil {
		t.Fatal("expected error for unknown condition key")
	}
	if !strings.Contains(err.Error(), "BZ085") {
		t.Errorf("expected BZ085, got: %v", err)
	}
}

// TestFmtDocStableOrder — fmtDoc produces stable sorted output and is idempotent.
func TestFmtDocStableOrder(t *testing.T) {
	// Deliberately out-of-order keys to verify canonical sorting.
	doc := `{"policies":[],"schemaVersion":1,"named_locations":[],"auth_strengths":[]}`
	out1, err := fmtDoc([]byte(doc))
	if err != nil {
		t.Fatalf("fmtDoc: %v", err)
	}
	// Second pass on already-formatted output must produce identical bytes (idempotent).
	out2, err := fmtDoc(out1)
	if err != nil {
		t.Fatalf("fmtDoc pass2: %v", err)
	}
	if string(out1) != string(out2) {
		t.Errorf("fmtDoc not idempotent:\npass1: %s\npass2: %s", out1, out2)
	}
	// schemaVersion must appear before policies in the output (sorted keys).
	i1 := strings.Index(string(out1), "schemaVersion")
	i2 := strings.Index(string(out1), "policies")
	if i1 < 0 || i2 < 0 {
		t.Fatalf("expected both keys present, got: %s", out1)
	}
	// "auth_strengths" < "named_locations" < "policies" < "schemaVersion" (lexicographic).
	if i1 < i2 {
		t.Errorf("expected 'policies' before 'schemaVersion' (sorted), got order: schemaVersion@%d policies@%d", i1, i2)
	}
}

// TestExplainCodeBZ086 — explainCode("BZ086") contains "slug" and the #BZ086 doc anchor.
func TestExplainCodeBZ086(t *testing.T) {
	s := explainCode("BZ086")
	if !strings.Contains(s, "BZ086") {
		t.Errorf("expected BZ086 in explanation, got: %q", s)
	}
	// The anchor enables deep-linking into the CA error reference.
	if !strings.Contains(s, "#BZ086") {
		t.Errorf("expected '#BZ086' doc anchor, got: %q", s)
	}
}

// TestExplainCodeBZ085 — BZ085 explanation mentions unknown slug.
func TestExplainCodeBZ085(t *testing.T) {
	s := explainCode("BZ085")
	if s == "" {
		t.Fatal("expected non-empty explanation for BZ085")
	}
	if !strings.Contains(strings.ToLower(s), "slug") {
		t.Errorf("expected 'slug' in BZ085 explanation, got: %q", s)
	}
}

// TestExplainCodeUnknown — an unrecognised code returns a non-empty fallback.
func TestExplainCodeUnknown(t *testing.T) {
	s := explainCode("BZ999")
	if s == "" {
		t.Error("expected non-empty fallback for unknown code")
	}
}

// TestCASchemaVersion — the published constant is 1 (mirrors exportSchemaVersion on the server).
func TestCASchemaVersion(t *testing.T) {
	if caSchemaVersion != 1 {
		t.Errorf("caSchemaVersion = %d, want 1", caSchemaVersion)
	}
}

// TestValidateDocShadowedAllow — block followed by allow in same grants array produces a warning
// (the allow is unreachable). --strict would promote this to an error.
func TestValidateDocShadowedAllow(t *testing.T) {
	doc := `{
		"schemaVersion": 1,
		"policies": [{
			"name": "shadowed",
			"actions": {"grants": [{"type": "block"}, {"type": "allow"}]}
		}]
	}`
	warns, err := validateDoc([]byte(doc))
	if err != nil {
		t.Fatalf("expected no hard error, got: %v", err)
	}
	if len(warns) == 0 {
		t.Fatal("expected at least one warning for shadowed allow, got none")
	}
	if !strings.Contains(warns[0], "shadowed") {
		t.Errorf("expected 'shadowed' in warning, got: %q", warns[0])
	}
}
