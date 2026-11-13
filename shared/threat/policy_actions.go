// Conditional access grant / action dispatch — split out of policy.go
// (pure file reorganization; same package, no behavior change).
package threat

import (
	"fmt"
	"strings"

	"setjoin.com/shared/jwtutil"
)

// ── Action dispatch ──

// Grant is one unit of access control within a policy action block. The legacy
// single-action form {"action":"block"} is read-back as a Grant with Type=action;
// the canonical multi-control form uses {"operator":"all","grants":[{type:...}]}.
// Deprecated bare form is tolerated for existing data; the write path rejects it
// (BZ085) so no new policies are created in that shape.
type Grant struct {
	Type       string `json:"type"`
	ACR        string `json:"acr,omitempty"`
	StrengthID int64  `json:"strength_id,omitempty"`
}

// grantDiscriminator resolves the canonical `type` and schema-v1 `action`
// spellings. Any present discriminator must be a non-empty string, and a dual
// pair must match exactly; malformed or divergent input must fail closed.
func grantDiscriminator(grant map[string]interface{}) (value string, invalid bool) {
	typeRaw, typePresent := grant["type"]
	typeValue, typeString := typeRaw.(string)
	if typePresent && (!typeString || typeValue == "") {
		return "", true
	}
	actionRaw, actionPresent := grant["action"]
	actionValue, actionString := actionRaw.(string)
	if actionPresent && (!actionString || actionValue == "") {
		return "", true
	}
	if typeValue != "" && actionValue != "" && typeValue != actionValue {
		return "", true
	}
	if typeValue != "" {
		return typeValue, false
	}
	return actionValue, false
}

// parseGrants reads the canonical grant-array shape, falling back to the
// read-only single-action legacy form {"action":"X"} → one grant. (Deprecated:
// removed in setjoin v-next; writes/import reject the bare form via BZ085.)
func parseGrants(actions map[string]interface{}) (op string, grants []Grant) {
	op, _ = actions["operator"].(string)
	if op == "" {
		op = "all"
	}
	if raw, ok := actions["grants"].([]interface{}); ok {
		for _, g := range raw {
			gm, ok := g.(map[string]interface{})
			if !ok {
				continue
			}
			gr := Grant{}
			var invalid bool
			gr.Type, invalid = grantDiscriminator(gm)
			// ponytail: tolerate the SQL-side grant-array key "action" — the V050
			// demo seed, ca_validate_policy_document, and the template catalog all
			// emit grants:[{"action":X}], but the engine's canonical key is "type",
			// so without this they parse to Type:"" and silently fail to enforce.
			// Canonicalize everything on "type" in a follow-up (see TODOS).
			if invalid {
				// Empty is the unknown-grant sentinel; evalGrant maps it to block.
				gr.Type = ""
			}
			gr.ACR, _ = gm["acr"].(string)
			if id, err := toInt64(gm["strength_id"]); err == nil {
				gr.StrengthID = id
			}
			grants = append(grants, gr)
		}
		return op, grants
	}
	// Legacy single-action tolerance.
	if a, ok := actions["action"].(string); ok && a != "" {
		return "all", []Grant{{Type: a, ACR: actionStr(actions, "acr")}}
	}
	return op, grants
}

// actionStr is a one-liner to safely read a string field from a map.
func actionStr(m map[string]interface{}, k string) string {
	s, _ := m[k].(string)
	return s
}

// evalGrant resolves a single Grant to (decision, stepUpMethods, notifyChannels).
// require_strength: HTTP path (CurrentACR non-empty OR CompletedFactors non-nil)
// → step_up with cheapest missing combination; legacy path (both empty) → block (T3).
// A nil/empty strengths map on require_strength is treated as block (fail-closed).
func evalGrant(g Grant, pectx PolicyEvalContext, strengths map[int64]AuthStrength) (PolicyDecision, []string, []string) {
	switch g.Type {
	case "block":
		return DecisionBlock, nil, nil
	case "allow":
		return DecisionAllow, nil, nil
	case "step_up":
		return DecisionStepUp, []string{"totp", "webauthn"}, nil
	case "notify":
		return DecisionNotify, nil, nil
	case "require_acr":
		required := g.ACR
		if required == "" {
			required = jwtutil.ACRAAL2
		}
		if jwtutil.ACRSatisfies(pectx.CurrentACR, required) {
			return DecisionAllow, nil, nil
		}
		return DecisionStepUp, []string{"totp", "webauthn"}, nil
	case "limited_web":
		// ponytail: allow + flag set in dispatchAction; capability cut applied by gateway.
		return DecisionAllow, nil, nil
	case "require_strength":
		// ponytail: fail-closed when strength missing from cache — deny/step-up never silently allow.
		s, ok := strengths[g.StrengthID]
		if !ok {
			return DecisionBlock, nil, nil
		}
		// HTTP path: CurrentACR non-empty OR CompletedFactors non-nil (populated after first factor).
		isHTTP := pectx.CurrentACR != "" || pectx.CompletedFactors != nil
		if !isHTTP {
			// Legacy protocol (IMAP/SMTP) — cannot prompt for MFA → block (T3).
			return DecisionBlock, nil, nil
		}
		// Check ACR floor first (cheap).
		if !jwtutil.ACRSatisfies(pectx.CurrentACR, s.MinACR) {
			// Surface cheapest missing combination (first combination that is not a superset of completed).
			missing := cheapestMissing(s.Combinations, pectx.CompletedFactors)
			return DecisionStepUp, missing, nil
		}
		// Check that completed factors satisfy at least one combination (superset check).
		if satisfiesAny(s.Combinations, pectx.CompletedFactors) {
			return DecisionAllow, nil, nil
		}
		missing := cheapestMissing(s.Combinations, pectx.CompletedFactors)
		return DecisionStepUp, missing, nil
	default:
		// Unknown grant type — fail SAFE: treat as block.
		// ponytail: a misparsed/unknown grant must never silently allow.
		return DecisionBlock, nil, nil
	}
}

// satisfiesAny reports whether completedFactors is a superset of any combination.
func satisfiesAny(combinations [][]string, completed []string) bool {
	completedSet := make(map[string]bool, len(completed))
	for _, f := range completed {
		completedSet[f] = true
	}
	for _, combo := range combinations {
		if isSuperset(completedSet, combo) {
			return true
		}
	}
	return false
}

// cheapestMissing returns the missing factors for the first combination not yet satisfied.
// Falls back to the first combination if all are satisfied (should not happen in practice).
func cheapestMissing(combinations [][]string, completed []string) []string {
	completedSet := make(map[string]bool, len(completed))
	for _, f := range completed {
		completedSet[f] = true
	}
	for _, combo := range combinations {
		if isSuperset(completedSet, combo) {
			continue
		}
		var missing []string
		for _, f := range combo {
			if !completedSet[f] {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			return missing
		}
	}
	if len(combinations) > 0 {
		return combinations[0]
	}
	return []string{"totp", "webauthn"}
}

// isSuperset reports whether s is a superset of all elements in combo.
func isSuperset(s map[string]bool, combo []string) bool {
	for _, f := range combo {
		if !s[f] {
			return false
		}
	}
	return true
}

// decisionPriority maps a decision to its severity (higher = wins in "all" operator).
// block > step_up > notify > allow.
func decisionPriority(d PolicyDecision) int {
	switch d {
	case DecisionBlock:
		return 3
	case DecisionStepUp:
		return 2
	case DecisionNotify:
		return 1
	default:
		return 0
	}
}

// dispatchAction converts policy actions JSONB into a PolicyResult.
// Supports both the canonical multi-control grant form
// {"operator":"all"|"one","grants":[{"type":...},...]} and the legacy
// single-action form {"action":"block"} (read-only back-compat).
//
// operator="all": every grant is evaluated; strongest interrupt (block > step_up >
// notify > allow) wins. A block short-circuits immediately.
// operator="one": allow if ANY grant resolves to allow; else strongest interrupt.
//
// A misparsed/unknown grant type fails SAFE (deny/step-up, never silently allow).
// strengths is the engine's authStrengths cache snapshot (pass nil if not available).
func dispatchAction(actions map[string]interface{}, row PolicyRow, pectx PolicyEvalContext, strengths map[int64]AuthStrength) PolicyResult {
	// require_compliant_device: CA-2 lockdown grant. Satisfied (allow) iff the
	// device is cryptographically bound AND enroll_state='approved'; otherwise
	// block. revoked_at is already folded into DeviceBound=false by the resolver
	// (a revoked device resolves to bound=false). Evaluated BEFORE the grants
	// dispatch because it is a top-level special action, not a grant type.
	// ponytail: explicit top-level key avoids adding a new grant type to evalGrant;
	// add as a proper grant type (type:"require_compliant_device") if operators need it.
	if rcd, _ := actions["require_compliant_device"].(bool); rcd {
		result := PolicyResult{PolicyID: row.ID, PolicyName: row.Name}
		if pectx.DeviceBound && pectx.EnrollState == "approved" {
			result.Decision = DecisionAllow
			result.Reason = "compliant device (bound + approved)"
		} else {
			result.Decision = DecisionBlock
			result.Reason = "device not enrolled/approved under lockdown"
		}
		return result
	}

	// CA-3b: require_terms + require_risk_remediation — top-level block verbs
	// with a typed remediation hint so the SPA knows how to clear the 403.
	// Handled before the grant loop (like require_compliant_device) because
	// the "all" operator short-circuits on DecisionBlock before post-loop code
	// can run, and tou_id lives only at the top-level actions map.
	if act := actionStr(actions, "action"); act == "require_terms" || act == "require_risk_remediation" {
		r := PolicyResult{PolicyID: row.ID, PolicyName: row.Name}
		if act == "require_terms" {
			r.Decision = DecisionBlock
			r.Remediation = "terms"
			if id, ok := actions["tou_id"].(float64); ok {
				r.RemediationTermsID = int64(id)
			}
			r.Reason = "terms of use acceptance required"
		} else {
			// ponytail: only block when the user is actually elevated — a policy
			// that fires on ALL users (e.g. global scope) must not false-lockout
			// low-risk users. "high" and "medium" are elevated; ""/"low"/"none" pass.
			rl := pectx.RiskLevel
			if rl == "high" || rl == "medium" {
				r.Decision = DecisionBlock
				r.Remediation = "risk"
				r.Reason = "risk remediation required (re-authenticate)"
			} else {
				r.Decision = DecisionAllow
				r.Reason = "require_risk_remediation: user risk not elevated"
			}
		}
		return r
	}

	reason, _ := actions["reason"].(string)
	op, grants := parseGrants(actions)

	result := PolicyResult{
		PolicyID:   row.ID,
		PolicyName: row.Name,
		Reason:     reason,
	}

	// Evaluate each grant and combine per operator.
	// ponytail: empty grants array is fail-closed (block) — an empty allow-list is not a pass.
	if len(grants) == 0 {
		result.Decision = DecisionBlock
		result.Reason = fmt.Sprintf("policy %q blocked (empty grants — fail-closed)", row.Name)
		return result
	}

	bestDecision := DecisionAllow
	var bestMethods []string
	var notifyChannels []string

	for _, g := range grants {
		dec, methods, channels := evalGrant(g, pectx, strengths)
		notifyChannels = append(notifyChannels, channels...)

		if op == "one" && dec == DecisionAllow {
			// "one" operator: first allow wins immediately.
			result.Decision = DecisionAllow
			if result.Reason == "" {
				result.Reason = fmt.Sprintf("policy %q matched (operator=one, grant %q satisfied)", row.Name, g.Type)
			}
			// limited_web flag must be set before this early-return; the post-loop
			// scan at the bottom is never reached for op="one". ponytail: inline here,
			// not in evalGrant, because LimitedWeb is a PolicyResult decoration not a decision.
			if g.Type == "limited_web" {
				result.LimitedWeb = true
			}
			return result
		}

		if dec == DecisionBlock && op != "one" {
			// block short-circuits "all" operator only; for "one", continue to find an allow.
			result.Decision = DecisionBlock
			if result.Reason == "" {
				result.Reason = fmt.Sprintf("policy %q blocked (grant type=%q)", row.Name, g.Type)
			}
			result.NotifyChannels = notifyChannels
			return result
		}

		if decisionPriority(dec) > decisionPriority(bestDecision) {
			bestDecision = dec
			bestMethods = methods
		}
	}

	result.Decision = bestDecision

	// For "one" operator with no allow found, we land here with bestDecision = strongest interrupt.
	if result.Reason == "" {
		result.Reason = fmt.Sprintf("policy %q matched (operator=%s)", row.Name, op)
	}
	// Legacy compat: bare {"action":"notify","channels":[...]} carries channels at the top level.
	// ponytail: only applies to legacy single-action form.
	if result.Decision == DecisionNotify {
		if channels, ok := actions["channels"].([]interface{}); ok && len(channels) > 0 {
			notifyChannels = nil
			for _, c := range channels {
				if s, ok := c.(string); ok {
					notifyChannels = append(notifyChannels, s)
				}
			}
		}
	}
	result.NotifyChannels = notifyChannels

	if result.Decision == DecisionStepUp {
		result.StepUpMethods = bestMethods
		// Legacy compat: bare {"action":"step_up","methods":[...]} carries methods at the top level.
		// ponytail: only applies to legacy single-action form; canonical grants form has no top-level methods.
		if methods, ok := actions["methods"].([]interface{}); ok && len(methods) > 0 {
			result.StepUpMethods = nil
			for _, m := range methods {
				if s, ok := m.(string); ok {
					result.StepUpMethods = append(result.StepUpMethods, s)
				}
			}
		}
		if len(result.StepUpMethods) == 0 {
			result.StepUpMethods = []string{"totp", "webauthn"} // default
		}
	}

	// Preserve legacy require_acr RequiredACR for back-compat (used by EvaluateTokenACR callers).
	// If any grant was require_acr, surface the ACR.
	if result.Decision == DecisionStepUp {
		for _, g := range grants {
			if g.Type == "require_acr" {
				acr := g.ACR
				if acr == "" {
					acr = jwtutil.ACRAAL2
				}
				result.RequiredACR = acr
				break
			}
		}
	}

	// limited_web: allow + capability-restriction flag. Covers both the legacy
	// {"action":"limited_web"} form and the canonical {"grants":[{"type":"limited_web"}]}
	// form (parseGrants normalises both into the grants slice).
	// ponytail: guard on DecisionAllow so a mixed-grants policy that also blocks never
	// sets LimitedWeb on a block result.
	if result.Decision == DecisionAllow {
		for _, g := range grants {
			if g.Type == "limited_web" {
				result.LimitedWeb = true
				break
			}
		}
	}

	return result
}

// decisionFromString converts a string decision name to a PolicyDecision.
// NOTE: require_terms and require_risk_remediation are NOT handled here — they
// are top-level special actions intercepted in dispatchAction before the grant
// loop, where the Remediation field and tou_id can also be set. Their absence
// here is intentional: they never reach decisionFromString.
func decisionFromString(s string) PolicyDecision {
	switch strings.ToLower(s) {
	case "block":
		return DecisionBlock
	case "step_up":
		return DecisionStepUp
	case "notify":
		return DecisionNotify
	default:
		return DecisionAllow
	}
}
