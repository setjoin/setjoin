package spam

import (
	"strconv"
	"strings"
)

// ActionType classifies the type of action a composite rule triggers.
type ActionType string

const (
	// ActionScore adds or subtracts from the spam score.
	ActionScore ActionType = "score"
	// ActionClassify sets a classification label on the message.
	ActionClassify ActionType = "classify"
	// ActionQuarantine sends the message to quarantine.
	ActionQuarantine ActionType = "quarantine"
	// ActionQuarantineHigh quarantines the message and alerts admin.
	ActionQuarantineHigh ActionType = "quarantine_high"
	// ActionQuarantineLow quarantines the message and notifies user via digest.
	ActionQuarantineLow ActionType = "quarantine_low"
	// ActionStripAttachment removes dangerous attachments from the message.
	ActionStripAttachment ActionType = "strip_attachment"
)

// CompositeRule is a named rule with conditions and an action string.
// Rules are evaluated by EvalComposites against a runtime EvalContext.
// Designed to be loaded from YAML (mailserver/internal/smtp/spam_rules.yaml).
type CompositeRule struct {
	Name        string               `yaml:"name"`
	Conditions  []CompositeCondition `yaml:"conditions"`
	Action      string               `yaml:"action"`      // e.g. "score +25.0", "classify spam", "quarantine"
	Description string               `yaml:"description"` // human-readable explanation
}

// CompositeCondition defines a single check within a composite rule.
// All conditions within a rule must match (AND logic) for the rule to fire.
//
// A condition matches when:
//   - If Result is set: the check's value in EvalContext.Checks is in the Result list.
//   - If Gt is set: the check's value in EvalContext.Scores is > Gt.
//   - If Lt is set: the check's value in EvalContext.Scores is < Lt.
//   - If both Gt and Lt are set: both must be satisfied.
//
// A Gt/Lt threshold requires the score to be present: when the value is absent
// from EvalContext.Scores the condition does not match, even if a Result leg
// matched (a threshold that cannot be evaluated never fires the rule).
//
// When neither Result, Gt, nor Lt is set, the condition passes
// (useful for boolean flag checks where mere presence of the key suffices).
type CompositeCondition struct {
	Check  string   `yaml:"check"`  // check name: "spf", "dkim", "dmarc", "mime_type", etc.
	Result []string `yaml:"result"` // allowed values for the check result (string match)
	Gt     *float64 `yaml:"gt"`     // numeric score > threshold
	Lt     *float64 `yaml:"lt"`     // numeric score < threshold
}

// EvalContext holds the runtime state available to composite rule evaluation.
// Populated by the SMTP pipeline before calling EvalComposites.
type EvalContext struct {
	// Checks holds string-valued check results (e.g. "spf" → "fail", "mime_type" → "image/png").
	Checks map[string]string
	// Scores holds numeric check scores (e.g. "spam_score_total" → 7.5, "body_text_length" → 10).
	Scores map[string]float64
	// Attachments is a list of attachment metadata.
	Attachments []AttachmentInfo
	// HasEncryptedAttachment is true if any attachment is an encrypted archive.
	HasEncryptedAttachment bool
	// BodyTextLength is the length of the plain text body in characters.
	BodyTextLength int
}

// AttachmentInfo holds metadata about a MIME attachment for rule evaluation.
type AttachmentInfo struct {
	MimeType string
	FileName string
	Size     int64
}

// CompositeAction is the parsed result of a composite rule's action string.
type CompositeAction struct {
	// Type is the action category.
	Type ActionType
	// Score is the score delta for ActionScore actions (may be negative).
	Score float64
	// ClassifyAs is the target class for ActionClassify actions.
	ClassifyAs ClassLabel
	// RuleName is the name of the rule that produced this action.
	RuleName string
}

// EvalComposites evaluates all composite rules against the given context and
// returns the actions for every matching rule. Rules are evaluated independently;
// the caller is responsible for resolving conflicting actions.
func EvalComposites(rules []CompositeRule, ctx *EvalContext) []CompositeAction {
	var actions []CompositeAction
	for _, rule := range rules {
		if evalConditions(rule.Conditions, ctx) {
			actions = append(actions, parseAction(rule.Action, rule.Name))
		}
	}
	return actions
}

// evalConditions returns true if all conditions in the rule match the context.
func evalConditions(conds []CompositeCondition, ctx *EvalContext) bool {
	for _, cond := range conds {
		if !evalCondition(cond, ctx) {
			return false
		}
	}
	// Per rspamd convention: if no conditions exist, the rule does not fire.
	return len(conds) > 0
}

// evalCondition checks a single condition against the context.
func evalCondition(cond CompositeCondition, ctx *EvalContext) bool {
	matched := false

	// 1. Check string result matching.
	if len(cond.Result) > 0 {
		val, ok := ctx.Checks[cond.Check]
		if !ok {
			// Fall back to Scores map: if the check is stored as a numeric
			// score but the condition expects a string, try converting.
			if scoreVal, scoreOk := ctx.Scores[cond.Check]; scoreOk {
				val = strconv.FormatFloat(scoreVal, 'f', -1, 64)
			}
		}
		if val == "" {
			// Check also falls back to bool-like scores: body_text_length is stored
			// in Scores, not Checks. For conditions checking Result, if we can't find
			// the value in Checks, check if Scores has a matching interpretation.
			if cond.Check == "body_text_length" {
				bodyLen := ctx.BodyTextLength
				if bodyLen == 0 {
					if scoreVal, scoreOk := ctx.Scores[cond.Check]; scoreOk {
						bodyLen = int(scoreVal)
					}
				}
				val = strconv.Itoa(bodyLen)
			}
			// The typed attachment flag must be visible to the Result branch too:
			// a condition {check: "has_encrypted_attachment", result: ["true"]}
			// would otherwise never match unless the SMTP pipeline ALSO populated
			// the string Checks map (the typed field was invisible here
			// — D-SHARED-SPAM-005 defect A).
			if cond.Check == "has_encrypted_attachment" {
				val = strconv.FormatBool(ctx.HasEncryptedAttachment)
			}
		}
		matched = containsString(cond.Result, val)
		if !matched {
			return false
		}
		// Continue checking Gt/Lt below even if Result matched.
	}

	// 2. Check numeric thresholds.
	if cond.Gt != nil || cond.Lt != nil {
		scoreVal, ok := ctx.Scores[cond.Check]
		if !ok {
			// For Checks like body_text_length, look up via BodyTextLength.
			if cond.Check == "body_text_length" {
				scoreVal = float64(ctx.BodyTextLength)
			} else {
				// A threshold that cannot be evaluated must not fire the rule.
				// The previous behavior returned the Result match here, so a
				// rule with {result: [...], gt: N} fired on the Result leg even
				// when the score was absent — Gt/Lt silently bypassed
				// (D-SHARED-SPAM-005 defect B). Fail the condition instead:
				// the rule fires only when its threshold genuinely verifies.
				return false
			}
		}

		if cond.Gt != nil && scoreVal <= *cond.Gt {
			return false
		}
		if cond.Lt != nil && scoreVal >= *cond.Lt {
			return false
		}
		return true
	}

	// 3. If only Result was specified (and matched above), return true.
	// 4. If neither Result, Gt, nor Lt was specified, check passes (flag existence).
	if len(cond.Result) == 0 && cond.Gt == nil && cond.Lt == nil {
		// Check that the check key exists in either Checks or Scores.
		_, inChecks := ctx.Checks[cond.Check]
		_, inScores := ctx.Scores[cond.Check]
		if !inChecks && !inScores {
			// For special fields, check struct values.
			switch cond.Check {
			case "has_encrypted_attachment":
				return ctx.HasEncryptedAttachment
			case "body_text_length":
				return true // BodyTextLength always exists (may be 0)
			default:
				return false
			}
		}
		return true
	}

	return matched
}

// containsString returns true if the slice contains the given string.
// Supports wildcard patterns: "image/*" matches "image/png", "image/jpeg", etc.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if matchPattern(item, s) {
			return true
		}
	}
	return false
}

// matchPattern returns true if s matches the pattern.
// If pattern contains '*', it does prefix/suffix matching:
//
//	"image/*"  matches "image/png", "image/jpeg"
//	"*.exe"    matches "foo.exe", "bar.exe"
//	"*"        matches anything
//
// Otherwise it does exact string comparison.
func matchPattern(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	// Prefix match: "image/*"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(s, prefix)
	}
	// Suffix match: "*.exe"
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(s, suffix)
	}
	// Contains match: "image/*/data"
	parts := strings.SplitN(pattern, "*", 2)
	return strings.HasPrefix(s, parts[0]) && strings.HasSuffix(s, parts[1])
}

// parseAction parses an action string into a CompositeAction.
//
// Supported formats:
//   - "score +25.0" or "score -5.0" → ActionScore
//   - "classify spam" → ActionClassify with ClassSpam
//   - "classify phishing" → ActionClassify with ClassPhishing
//   - "classify newsletter" → ActionClassify with ClassNewsletter
//   - "classify promotional" → ActionClassify with ClassPromotional
//   - "classify ham" → ActionClassify with ClassHam
//   - "quarantine" → ActionQuarantine
//   - "quarantine_high" → ActionQuarantineHigh
//   - "quarantine_low" → ActionQuarantineLow
//   - "strip_attachment" → ActionStripAttachment
func parseAction(actionStr string, ruleName string) CompositeAction {
	a := CompositeAction{RuleName: ruleName}
	parts := strings.Fields(actionStr)
	if len(parts) == 0 {
		return a
	}

	switch parts[0] {
	case "score":
		a.Type = ActionScore
		if len(parts) >= 2 {
			a.Score, _ = strconv.ParseFloat(parts[1], 64)
		}

	case "classify":
		a.Type = ActionClassify
		if len(parts) >= 2 {
			a.ClassifyAs = parseClassLabel(parts[1])
		}

	case "quarantine":
		a.Type = ActionQuarantine

	case "quarantine_high":
		a.Type = ActionQuarantineHigh

	case "quarantine_low":
		a.Type = ActionQuarantineLow

	case "strip_attachment":
		a.Type = ActionStripAttachment

	default:
		// Unknown action type — fall back to score (no-op).
		a.Type = ActionScore
	}

	return a
}

// parseClassLabel converts a string to a ClassLabel.
func parseClassLabel(s string) ClassLabel {
	// Support both "spam" and "__label__spam" forms.
	switch strings.ToLower(strings.TrimPrefix(s, "__label__")) {
	case "ham":
		return ClassHam
	case "spam":
		return ClassSpam
	case "newsletter":
		return ClassNewsletter
	case "promotional":
		return ClassPromotional
	case "phishing":
		return ClassPhishing
	default:
		return ClassSpam // default to spam for safety
	}
}
