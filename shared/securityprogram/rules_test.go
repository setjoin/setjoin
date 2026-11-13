package securityprogram

import "testing"

// Authority: the v2 grammar semantics documented in remediation-quickstart §5.
// Literal expectations exercise omitted-axis preservation and exact constraints,
// independently of the operation declarations and their generated artifact.
func TestStateConstraintSemantics(t *testing.T) {
	input := RowState{"blocked", "traced", "none", "external_evidence_open"}
	for _, tt := range []struct {
		name        string
		constraints stateConstraints
		want        bool
	}{
		{"omitted axes", stateConstraints{}, true},
		{"exact four axes", stateConstraints{"blocked", "traced", "none", "external_evidence_open"}, true},
		{"disposition mismatch", stateConstraints{Disposition: "fixed"}, false},
		{"local mismatch", stateConstraints{LocalStatus: "proof_patched"}, false},
		{"verification mismatch", stateConstraints{VerificationStatus: "receipt_bound"}, false},
		{"release mismatch", stateConstraints{ReleaseStatus: "not_ready"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.constraints.matches(input); got != tt.want {
				t.Fatalf("constraint result %t, want %t", got, tt.want)
			}
		})
	}
	if got := (stateConstraints{LocalStatus: "patched"}).apply(input); got != (RowState{"blocked", "patched", "none", "external_evidence_open"}) {
		t.Fatalf("overlay changed an unmentioned axis: %v", got)
	}
}

func TestUnknownRequiredFieldFailsClosed(t *testing.T) {
	// A rule descriptor unsupported by the writer must refuse, never ignore a
	// newly added prerequisite until its field semantics are implemented.
	err := validateRequired(opSpec{Op: "start", Requires: []string{"futureField"}}, Request{}, nil, "")
	if !IsCode(err, CodeInternal) {
		t.Fatalf("unsupported required field was not refused: %v", err)
	}
	err = validateRequired(opSpec{Op: "complete", Requires: []string{"evidenceManifest"}}, Request{}, nil, "")
	if !IsCode(err, CodeInternal) {
		t.Fatalf("missing completion request was not refused: %v", err)
	}
}
