package spam

import (
	"math"
	"testing"
)

func TestEvalComposites_AllConditionsMatch(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "SPOOFED_UNAUTH",
			Conditions: []CompositeCondition{
				{Check: "spf", Result: []string{"fail", "softfail", "neutral"}},
				{Check: "dkim", Result: []string{"fail", "none"}},
				{Check: "dmarc", Result: []string{"fail", "none"}},
			},
			Action:      "score +25.0",
			Description: "All auth methods failed for claimed sender domain",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"spf":   "fail",
			"dkim":  "none",
			"dmarc": "fail",
		},
		Scores: map[string]float64{},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != ActionScore {
		t.Errorf("expected ActionScore, got %s", actions[0].Type)
	}
	if math.Abs(actions[0].Score-25.0) > 0.001 {
		t.Errorf("expected score 25.0, got %.2f", actions[0].Score)
	}
	if actions[0].RuleName != "SPOOFED_UNAUTH" {
		t.Errorf("expected rule name SPOOFED_UNAUTH, got %s", actions[0].RuleName)
	}
}

func TestEvalComposites_NoMatch(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "SPOOFED_UNAUTH",
			Conditions: []CompositeCondition{
				{Check: "spf", Result: []string{"fail"}},
			},
			Action: "score +25.0",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"spf": "pass",
		},
		Scores: map[string]float64{},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 0 {
		t.Errorf("expected no actions, got %d", len(actions))
	}
}

func TestEvalComposites_ScoreGT(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "HIGH_SCORE_ACTION",
			Conditions: []CompositeCondition{
				{Check: "spam_score_total", Gt: ptr(5.0)},
			},
			Action: "classify spam",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{},
		Scores: map[string]float64{
			"spam_score_total": 7.5,
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != ActionClassify {
		t.Errorf("expected ActionClassify, got %s", actions[0].Type)
	}
	if actions[0].ClassifyAs != ClassSpam {
		t.Errorf("expected classify as spam, got %s", actions[0].ClassifyAs)
	}
}

func TestEvalComposites_ScoreLT(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "LOW_SCORE_NEWSLETTER",
			Conditions: []CompositeCondition{
				{Check: "list_unsubscribe", Result: []string{"present"}},
				{Check: "spam_score_total", Lt: ptr(3.0)},
			},
			Action: "classify newsletter",
		},
	}

	// Condition met: List-Unsubscribe present AND score < 3.0
	ctx := &EvalContext{
		Checks: map[string]string{
			"list_unsubscribe": "present",
		},
		Scores: map[string]float64{
			"spam_score_total": 1.5,
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != ActionClassify {
		t.Errorf("expected ActionClassify, got %s", actions[0].Type)
	}
	if actions[0].ClassifyAs != ClassNewsletter {
		t.Errorf("expected classify as newsletter, got %s", actions[0].ClassifyAs)
	}
}

func TestEvalComposites_ScoreLT_NotMet(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "LOW_SCORE_NEWSLETTER",
			Conditions: []CompositeCondition{
				{Check: "spam_score_total", Lt: ptr(3.0)},
			},
			Action: "classify newsletter",
		},
	}

	// Score exceeds threshold, rule should not fire.
	ctx := &EvalContext{
		Scores: map[string]float64{
			"spam_score_total": 5.0,
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions when score exceeds LT threshold, got %d", len(actions))
	}
}

func TestEvalComposites_Quarantine(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "ENCRYPTED_ARCHIVE_EXTERNAL",
			Conditions: []CompositeCondition{
				{Check: "has_encrypted_attachment", Result: []string{"true"}},
				{Check: "sender_authenticated", Result: []string{"false"}},
			},
			Action: "quarantine",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"has_encrypted_attachment": "true",
			"sender_authenticated":     "false",
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != ActionQuarantine {
		t.Errorf("expected ActionQuarantine, got %s", actions[0].Type)
	}
}

func TestEvalComposites_MultipleRules(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "RULE_A",
			Conditions: []CompositeCondition{
				{Check: "spf", Result: []string{"fail"}},
			},
			Action: "score +5.0",
		},
		{
			Name: "RULE_B",
			Conditions: []CompositeCondition{
				{Check: "dkim", Result: []string{"none"}},
			},
			Action: "score +3.0",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"spf":  "fail",
			"dkim": "none",
		},
		Scores: map[string]float64{},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}
}

func TestEvalComposites_ClassifyQuarantineActions(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "SPAM_RULE",
			Conditions: []CompositeCondition{
				{Check: "spam_score_total", Gt: ptr(5.0)},
			},
			Action: "classify spam",
		},
		{
			Name: "PHISH_RULE",
			Conditions: []CompositeCondition{
				{Check: "spam_score_total", Gt: ptr(10.0)},
			},
			Action: "classify phishing",
		},
	}

	ctx := &EvalContext{
		Scores: map[string]float64{
			"spam_score_total": 12.0,
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}

	// Check both classify actions are correct.
	classLabels := map[ClassLabel]bool{}
	for _, a := range actions {
		if a.Type == ActionClassify {
			classLabels[a.ClassifyAs] = true
		}
	}
	if !classLabels[ClassSpam] {
		t.Error("missing 'classify spam' action")
	}
	if !classLabels[ClassPhishing] {
		t.Error("missing 'classify phishing' action")
	}
}

func TestEvalComposites_AttachmentInfo(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "IMAGE_ONLY_SPAM",
			Conditions: []CompositeCondition{
				{Check: "mime_type", Result: []string{"image/*"}},
				{Check: "body_text_length", Lt: ptr(50.0)},
			},
			Action: "classify spam",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"mime_type": "image/png",
		},
		Scores: map[string]float64{
			"body_text_length": 10,
		},
		BodyTextLength: 10,
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action for image-only spam, got %d", len(actions))
	}
	if actions[0].ClassifyAs != ClassSpam {
		t.Errorf("expected classify as spam, got %s", actions[0].ClassifyAs)
	}
}

func TestEvalComposites_StripAttachment(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "DANGEROUS_EXT",
			Conditions: []CompositeCondition{
				{Check: "has_dangerous_extension", Result: []string{"true"}},
			},
			Action: "strip_attachment",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{
			"has_dangerous_extension": "true",
		},
	}

	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != ActionStripAttachment {
		t.Errorf("expected ActionStripAttachment, got %s", actions[0].Type)
	}
}

func TestEvalComposites_EmptyRules(t *testing.T) {
	ctx := &EvalContext{
		Checks: map[string]string{"spf": "fail"},
	}
	actions := EvalComposites(nil, ctx)
	if len(actions) != 0 {
		t.Errorf("expected no actions for nil rules, got %d", len(actions))
	}
	actions = EvalComposites([]CompositeRule{}, ctx)
	if len(actions) != 0 {
		t.Errorf("expected no actions for empty rules, got %d", len(actions))
	}
}

func TestEvalComposites_UnknownCheck(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "UNKNOWN_CHECK_RULE",
			Conditions: []CompositeCondition{
				{Check: "nonexistent_check", Result: []string{"anything"}},
			},
			Action: "score +5.0",
		},
	}

	ctx := &EvalContext{
		Checks: map[string]string{"spf": "fail"},
	}

	// Unknown check means the condition fails — the check value is empty.
	actions := EvalComposites(rules, ctx)
	if len(actions) != 0 {
		t.Errorf("expected no actions for unknown check, got %d", len(actions))
	}
}

func TestEvalComposites_GtAndLtBothSet(t *testing.T) {
	// When both Gt and Lt are set, both must be satisfied (AND logic).
	rules := []CompositeRule{
		{
			Name: "MID_RANGE",
			Conditions: []CompositeCondition{
				{Check: "spam_score_total", Gt: ptr(2.0), Lt: ptr(8.0)},
			},
			Action: "score +3.0",
		},
	}

	// Score 5.0 is between 2.0 and 8.0 → rule fires.
	ctx := &EvalContext{
		Scores: map[string]float64{"spam_score_total": 5.0},
	}
	actions := EvalComposites(rules, ctx)
	if len(actions) != 1 {
		t.Errorf("expected 1 action when score is in range, got %d", len(actions))
	}

	// Score 1.0 is below Gt → rule should not fire.
	ctx.Scores["spam_score_total"] = 1.0
	actions = EvalComposites(rules, ctx)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions when score is below Gt, got %d", len(actions))
	}

	// Score 9.0 is above Lt → rule should not fire.
	ctx.Scores["spam_score_total"] = 9.0
	actions = EvalComposites(rules, ctx)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions when score is above Lt, got %d", len(actions))
	}
}

func TestParseAction_UnknownAction(t *testing.T) {
	a := parseAction("unknown_action arg", "TEST_RULE")
	if a.Type != ActionScore {
		t.Errorf("expected fallback to ActionScore for unknown action, got %s", a.Type)
	}
}

func TestParseAction_ScoreNegative(t *testing.T) {
	a := parseAction("score -10.5", "TEST_RULE")
	if a.Type != ActionScore {
		t.Errorf("expected ActionScore, got %s", a.Type)
	}
	if math.Abs(a.Score-(-10.5)) > 0.001 {
		t.Errorf("expected score -10.5, got %.2f", a.Score)
	}
}

func ptr(v float64) *float64 { return &v }

// TestEvalComposites_TypedEncryptedAttachmentVisibleToResult pins defect A of
// D-SHARED-SPAM-005: a {check: has_encrypted_attachment, result: ["true"]}
// condition must consult the typed EvalContext.HasEncryptedAttachment field
// when the string Checks map does not carry the key.
func TestEvalComposites_TypedEncryptedAttachmentVisibleToResult(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "ENCRYPTED_ARCHIVE_EXTERNAL",
			Conditions: []CompositeCondition{
				{Check: "has_encrypted_attachment", Result: []string{"true"}},
			},
			Action: "quarantine",
		},
	}

	// Typed flag set, NO string Checks entry: previously invisible to the
	// Result branch, so the rule never fired.
	actions := EvalComposites(rules, &EvalContext{HasEncryptedAttachment: true})
	if len(actions) != 1 {
		t.Fatalf("expected 1 action from typed flag, got %d", len(actions))
	}
	if actions[0].Type != ActionQuarantine {
		t.Errorf("expected ActionQuarantine, got %s", actions[0].Type)
	}

	// Typed flag false must not match a ["true"] Result.
	actions = EvalComposites(rules, &EvalContext{})
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions when the typed flag is false, got %d", len(actions))
	}

	// The string Checks map remains the first lookup (pipeline override intact).
	actions = EvalComposites(rules, &EvalContext{
		Checks:                 map[string]string{"has_encrypted_attachment": "true"},
		HasEncryptedAttachment: false,
	})
	if len(actions) != 1 {
		t.Fatalf("expected 1 action from Checks-map value, got %d", len(actions))
	}
}

// TestEvalComposites_ThresholdAbsentScoreDoesNotFire pins defect B of
// D-SHARED-SPAM-005: when a Gt/Lt threshold's score is absent from Scores, the
// condition must not match even though its Result leg matched — a threshold
// that cannot be evaluated never fires the rule.
func TestEvalComposites_ThresholdAbsentScoreDoesNotFire(t *testing.T) {
	rules := []CompositeRule{
		{
			Name: "HIGH_SCORE_ENCRYPTED",
			Conditions: []CompositeCondition{
				{Check: "has_encrypted_attachment", Result: []string{"true"}},
				{Check: "spam_score_total", Gt: ptr(5.0)},
			},
			Action: "quarantine",
		},
	}

	// Result leg matches, but the Gt score is ABSENT: previously the rule
	// fired on the Result match with the threshold silently bypassed.
	actions := EvalComposites(rules, &EvalContext{
		Checks: map[string]string{"has_encrypted_attachment": "true"},
	})
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions when the Gt score is absent, got %d", len(actions))
	}

	// With the score present and above the threshold, the rule fires.
	actions = EvalComposites(rules, &EvalContext{
		Checks: map[string]string{"has_encrypted_attachment": "true"},
		Scores: map[string]float64{"spam_score_total": 7.5},
	})
	if len(actions) != 1 {
		t.Fatalf("expected 1 action when Gt verifies, got %d", len(actions))
	}
}
