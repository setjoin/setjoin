package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"setjoin.com/shared/threat"
)

// ca_schema.go — offline schema constants + validate/fmt/explain for CA-1 E2.
//
// This is a local mirror of shared/threat/policyschema.go's allow-list.
// mailctl is a standalone module and cannot import shared/*; keep in lockstep
// with allowedConditions / allowedActions in that file.
// ponytail: single file, no abstractions — just constants + three functions.

// caSchemaVersion mirrors exportSchemaVersion on the server side.
// Bump when the import doc schema changes (guarded by BZ088 on the server).
const caSchemaVersion = 1

// The allow-lists live in ONE place: shared/threat/policyschema.go — the same
// validator the server's write reducer and import run before persist. mailctl
// validates against that seam directly (go.mod replace, same repo), so
// validate-green here == import-green on the server BY CONSTRUCTION. The
// previous hand-copied mirror drifted through three consecutive schema changes
// (false-accepted the removed auth_strength condition; false-rejected the
// CA-2/CA-3 grants limited_web/require_terms/require_risk_remediation and the
// device_bound/require_approved_client_app conditions).

// caSkeleton is the canonical skeleton shown in BZ085 errors — derived from the seam.
var caSkeleton = `{"grants":[{"type":"<` + strings.Join(threat.AllowedActionNames(), "|") + `>"}]}`

// bzDict is the offline error-code dictionary for BZ085–BZ094.
// Sourced from §10.1 of the CA spec; each entry includes a #BZnnn anchor for deep-linking.
// ponytail: embedded map, no external file — these codes rarely change.
var bzDict = map[string]string{
	"BZ080": "BZ080: CA policy lockout guard — would lock out all break-glass users. " +
		"Add at least one break-glass user_id before enabling this policy. #BZ080",
	"BZ081": "BZ081: Conditional access resource not found — the policy, named location, " +
		"or auth strength referenced by this request does not exist. #BZ081",
	"BZ082": "BZ082: Break-glass set is empty — a break-glass replacement requires at " +
		"least one user_id in the new set (cannot leave the system locked out). #BZ082",
	"BZ085": "BZ085: Unknown template slug — the policy template slug supplied does not " +
		"match any registered template. Valid actions: check `ca list` templates or " +
		"use a known grant type from: " + strings.Join(threat.AllowedActionNames(), ", ") +
		". Canonical actions shape: " + caSkeleton + " #BZ085",
	"BZ086": "BZ086: Audit row missing or not a CA-policy snapshot — the audit_log row " +
		"referenced for promote/rollback is absent or was not written by the CA policy " +
		"system. Check the audit_log entry exists and has the correct slug. #BZ086",
	"BZ087": "BZ087: Priority conflict — the target priority slot is already held by a " +
		"live (non-deleted) policy. Reorder existing policies first or choose a " +
		"different priority. #BZ087",
	"BZ088": "BZ088: Import document schemaVersion mismatch — the document's schemaVersion " +
		"does not match the server-supported version. Re-export from a compatible server " +
		"or update the schemaVersion field. #BZ088",
	"BZ089": "BZ089: Import policy name collision in merge mode — a policy with the same " +
		"name already exists and merge mode does not overwrite. Use replace mode or " +
		"rename the policy. #BZ089",
	"BZ090": "BZ090: Invalid import document shape — the document is missing required " +
		"fields or contains an unrecognised structure. Check the schemaVersion and " +
		"document format. #BZ090",
	"BZ091": "BZ091: Unknown named-location or auth-strength slug in import document — " +
		"a policy references a slug not present in the same document's named_locations " +
		"or auth_strengths. Add the missing entry or fix the reference. #BZ091",
	"BZ092": "BZ092: Invalid import mode — the ?mode= query parameter must be one of: " +
		"merge, replace, prune. #BZ092",
	"BZ093": "BZ093: Named location restore name clash — restoring a soft-deleted named " +
		"location would collide with an existing live location of the same name. " +
		"Rename or delete the existing location first. #BZ093",
	"BZ094": "BZ094: Built-in auth-strength guard — built-in auth strengths " +
		"(phishing-resistant, passwordless, mfa) cannot be deleted or mutated. " +
		"Create a custom auth strength instead. #BZ094",
}

// sortedKeys returns sorted keys of a string-bool map (used in error messages).
func sortedKeys(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// validateDoc validates a policy import document (JSON bytes) against the F6 schema:
// - schemaVersion must be present and equal to caSchemaVersion
// - each policy's conditions keys must be in caValidConditionKeys
// - each policy's actions grant types must be in caValidGrantTypes
// Returns (warnings, nil) on success; (nil, error) with "BZ085" prefix on schema violation.
// Warnings are non-fatal issues such as a shadowed allow under a block in the same grants array.
// --strict in caValidateCmd promotes warnings to errors.
// ponytail: validates only the keys the CLI can check offline; server-side BZ088/090 etc.
// fire on structural/semantic issues that require DB context.
func validateDoc(raw []byte) ([]string, error) {
	// Decode into a loose map to avoid tying to a specific struct layout.
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("BZ085: invalid JSON: %w", err)
	}

	// schemaVersion check.
	if sv, ok := doc["schemaVersion"]; ok {
		n, _ := sv.(float64)
		if int(n) != caSchemaVersion {
			return nil, fmt.Errorf("BZ085: schemaVersion %v is not supported; want %d", sv, caSchemaVersion)
		}
	}

	policies, _ := doc["policies"].([]interface{})
	var warns []string
	for i, p := range policies {
		pm, ok := p.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("BZ085: policy[%d] is not an object", i)
		}
		if err := validateConditionsMap(pm["conditions"], i); err != nil {
			return nil, err
		}
		w, err := validateActionsMap(pm["actions"], i)
		if err != nil {
			return nil, err
		}
		warns = append(warns, w...)
	}
	return warns, nil
}

func validateConditionsMap(raw interface{}, idx int) error {
	if raw == nil {
		return nil
	}
	conds, ok := raw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("BZ085: policy[%d].conditions must be an object", idx)
	}
	// The seam validates keys AND value kinds/enum domains (the hand copy only
	// ever checked key names — wrong-typed values used to validate green here
	// and bounce at the server).
	if err := threat.ValidatePolicyDocument(conds, nil); err != nil {
		return fmt.Errorf("BZ085: policy[%d]: %v; allowed condition keys: %s; actions shape: %s",
			idx, err, strings.Join(threat.AllowedConditionKeys(), ", "), caSkeleton)
	}
	return nil
}

// validateActionsMap returns (warnings, error).
// Warnings include shadowed-allow: an "allow" grant that is unreachable because
// a "block" grant appears earlier in the same grants array (--strict makes this non-zero).
func validateActionsMap(raw interface{}, idx int) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	acts, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("BZ085: policy[%d].actions must be an object", idx)
	}
	// Domain validation (legacy "action", canonical "type", operator, nested
	// grants incl. value kinds) — delegated to the server's own validator.
	if err := threat.ValidatePolicyDocument(nil, acts); err != nil {
		return nil, fmt.Errorf("BZ085: policy[%d].actions: %v; valid types: %s; canonical shape: %s",
			idx, err, strings.Join(threat.AllowedActionNames(), ", "), caSkeleton)
	}
	// Canonical grants array.
	var warns []string
	if g, ok := acts["grants"]; ok {
		arr, ok := g.([]interface{})
		if !ok {
			return nil, fmt.Errorf("BZ085: policy[%d].actions.grants must be an array; shape: %s", idx, caSkeleton)
		}
		if len(arr) == 0 {
			return nil, fmt.Errorf("BZ085: policy[%d].actions.grants must not be empty; shape: %s", idx, caSkeleton)
		}
		sawBlock := false
		for j, e := range arr {
			obj, ok := e.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("BZ085: policy[%d].actions.grants[%d] must be an object", idx, j)
			}
			t, _ := obj["type"].(string)
			// Schema v1 server exports and SQL templates still use the historic
			// grant-array discriminator {"action": ...}. The shared runtime and
			// validator deliberately accept both spellings; offline validation must
			// therefore accept its own server's export as well.
			if t == "" {
				t, _ = obj["action"].(string)
			}
			if t == "" {
				return nil, fmt.Errorf("BZ085: policy[%d].actions.grants[%d] missing 'type' or schema-v1 'action'; shape: %s", idx, j, caSkeleton)
			}
			// type-domain validation happened in ValidatePolicyDocument above;
			// this walk only computes operator-facing WARNINGS (shadowed allow).
			// Shadowed-allow: an allow after a block is unreachable (block terminates evaluation).
			if t == "allow" && sawBlock {
				warns = append(warns, fmt.Sprintf(
					"policy[%d].actions.grants[%d]: allow is shadowed by an earlier block grant (unreachable)",
					idx, j))
			}
			if t == "block" {
				sawBlock = true
			}
		}
	}
	return warns, nil
}

// fmtDoc canonically formats a policy import document: stable sorted keys,
// 2-space indent, newline-terminated. Idempotent.
// ponytail: json.Marshal uses struct-field order when encoding structs, but for
// map[string]interface{} it sorts keys automatically (Go maps are sorted in encoding/json).
func fmtDoc(raw []byte) ([]byte, error) {
	// Decode into a generic structure to preserve all fields without a fixed schema.
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// explainCode returns an offline plain-English explanation for a BZ error code
// (BZ080–BZ094). Returns a non-empty fallback for unrecognised codes.
func explainCode(code string) string {
	if s, ok := bzDict[code]; ok {
		return s
	}
	return fmt.Sprintf("%s: unrecognised error code — check the CA error reference at docs/design/security/ca-errors.md #%s", code, code)
}
