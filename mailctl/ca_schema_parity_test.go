package main

import (
	"strings"
	"testing"
)

// c10-bug regression: the hand-copied allow-lists drifted from
// shared/threat/policyschema.go three schema changes in a row. Validation now
// delegates to that seam; these cases pin the exact drift that was live.
func TestValidateDoc_SeamParity(t *testing.T) {
	doc := func(policy string) []byte {
		return []byte(`{"schemaVersion":1,"policies":[` + policy + `]}`)
	}

	t.Run("CA-3 grants the hand copy false-rejected now validate", func(t *testing.T) {
		// limited_web is a grant-array type; require_terms / require_risk_remediation
		// are TOP-LEVEL action verbs (the seam even rejects them inside a grants
		// array with an actionable message — precision the hand copy never had).
		if _, err := validateDoc(doc(`{"actions":{"grants":[{"type":"limited_web"}]}}`)); err != nil {
			t.Errorf("grant limited_web must validate (server accepts it): %v", err)
		}
		for _, verb := range []string{"require_terms", "require_risk_remediation"} {
			if _, err := validateDoc(doc(`{"actions":{"action":"` + verb + `"}}`)); err != nil {
				t.Errorf("top-level action %q must validate (server accepts it): %v", verb, err)
			}
		}
		if _, err := validateDoc(doc(`{"actions":{"grants":[{"type":"require_terms"}]}}`)); err == nil {
			t.Error("require_terms inside a grants array must be rejected (top-level verb only)")
		}
	})

	t.Run("removed auth_strength condition the hand copy false-accepted now rejects", func(t *testing.T) {
		_, err := validateDoc(doc(`{"conditions":{"auth_strength":"mfa"}}`))
		if err == nil {
			t.Fatal("auth_strength was removed server-side (latent fail-open); mailctl must reject it")
		}
		if !strings.Contains(err.Error(), "policy[0]") {
			t.Errorf("error must keep the operator-facing policy index, got: %v", err)
		}
	})

	t.Run("CA-2 conditions the hand copy false-rejected now validate", func(t *testing.T) {
		if _, err := validateDoc(doc(`{"conditions":{"device_bound":true}}`)); err != nil {
			t.Errorf("device_bound must validate (server accepts it): %v", err)
		}
	})

	t.Run("wrong-typed value now rejected offline (hand copy checked key names only)", func(t *testing.T) {
		if _, err := validateDoc(doc(`{"conditions":{"device_bound":"yes"}}`)); err == nil {
			t.Fatal("wrong-typed condition value must fail offline like it fails at the server")
		}
	})

	t.Run("shadowed-allow warning survives the repoint", func(t *testing.T) {
		warns, err := validateDoc(doc(`{"actions":{"grants":[{"type":"block"},{"type":"allow"}]}}`))
		if err != nil {
			t.Fatalf("valid doc: %v", err)
		}
		if len(warns) != 1 || !strings.Contains(warns[0], "shadowed") {
			t.Errorf("expected the shadowed-allow warning, got %v", warns)
		}
	})
}
