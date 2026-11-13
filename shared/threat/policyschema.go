package threat

import (
	"fmt"
	"sort"
	"strings"
)

// policyschema.go — F6: the single Go source of truth for the SHAPE of a
// conditional-access policy document (conditions + actions/grants). The admin
// write path and the CA-1 import reducer call ValidatePolicyDocument BEFORE
// persist; the reducer-side ca_validate_policy_document() mirrors this allow-list
// as a defence-in-depth CHECK. This converts a silent fail-open — a typo'd
// condition key widening a block policy to match-all because matchAll only
// consults keys it recognises — into a loud rejection at authoring time.
//
// The allow-list is grounded in the ACTUAL matchers in policy.go (matchDeviceTrust,
// matchIPReputation, matchGeoRiskTier, matchUserGroup, matchAuthMethod,
// matchClientType, matchTimeOfDay). Keys not consumed by any matcher are NOT
// included (no speculative YAGNI additions). Keep in lockstep with
// ca_validate_policy_document() in V025__ca_foundation.sql.
//
// Deviations from the illustrative brief:
//   - device_trust domain: real tiers from DeviceTrustResolver.Resolve()
//     are "managed"/"known"/"unknown"/"risky" (not brief's trusted/compliant/unmanaged).
//   - ip_reputation domain: real bands from iprisk.scoreToBand()
//     are "low"/"medium"/"high"/"critical" (not brief's clean/suspect/malicious).
//   - geo_risk_tier domain: includes "critical" (not just low/medium/high); from geoTierToScore().
//   - user_group: kindInt (matchUserGroup calls toInt64() — the condition value is a
//     numeric group ID, not a free-form string).
//   - auth_method: kindString (matchAuthMethod reads condVal.(string) — single string,
//     not an array).
//   - time_of_day shape: {start, end, tz} (matchTimeOfDay reads todMap["start"]/["end"],
//     not "from"/"to").
//   - role_group, acr: OMITTED (no matcher consumes them).
//   - location_in (kindInt) + location_trusted (kindBool): ADDED — matchNamedLocation
//     wired into matchAll (CA-1 A2). SQL mirror updated in V031__ca_location_matcher.sql.
//   - device_platform (kindEnum) + country_in (kindStringArray): ADDED — matchDevicePlatform/
//     matchCountryIn wired in matchAll (CA-1 A3). SQL mirror in V032__ca_platform_country_allowlist.sql.
//   - auth_strength: REMOVED from conditions — it is enforced as the require_strength GRANT,
//     not a condition key. No matcher consumes it as a condition (fail-open if present).

// valueKind enumerates the permitted JSON value shapes for a condition.
type valueKind int

const (
	kindEnum        valueKind = iota // a string drawn from a fixed domain
	kindString                       // a free-form string
	kindInt                          // a numeric integer (JSON number → int64 via toInt64)
	kindTimeRange                    // {"start":"HH:MM","end":"HH:MM"[,"tz":"IANA"]}
	kindBool                         // a JSON boolean (true/false)
	kindStringArray                  // a JSON array of strings (e.g. country_in: ["KP","RU"])
)

// conditionSpec is the allowed kind (+ enum domain when kindEnum) for one key.
type conditionSpec struct {
	kind   valueKind
	domain map[string]bool // populated only for kindEnum
}

func enumSet(vals ...string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// allowedConditions is the complete set of permitted condition keys. Any key not
// in this map is rejected (the fail-open fix). Keep in lockstep with the matchers
// in policy.go and with ca_validate_policy_document() in V032__ca_platform_country_allowlist.sql.
var allowedConditions = map[string]conditionSpec{
	// device_trust: real tiers from DeviceTrustResolver.Resolve() — managed/known/unknown/risky.
	"device_trust": {kind: kindEnum, domain: enumSet("managed", "known", "unknown", "risky")},
	// ip_reputation: real score bands from iprisk.scoreToBand() — low/medium/high/critical.
	"ip_reputation": {kind: kindEnum, domain: enumSet("low", "medium", "high", "critical")},
	// geo_risk_tier: tiers from geo_country_tiers + geoTierToScore — includes "critical".
	"geo_risk_tier": {kind: kindEnum, domain: enumSet("low", "medium", "high", "critical")},
	// user_group: matchUserGroup calls toInt64() — the condition is a numeric group ID.
	"user_group": {kind: kindInt},
	// auth_method: matchAuthMethod does condVal.(string) — a single protocol string.
	"auth_method": {kind: kindString},
	// client_type: matchClientType does condVal.(string) against one of the known
	// types. The domain is the EXACT set clientTypeFromProtocol /
	// clientTypeFromProtocolUmbrella (interceptor.go) can emit at runtime:
	// web/mobile/imap/smtp/caldav/legacy. The previously accepted vocabulary
	// (browser/native/pop/activesync) is NEVER emitted, so a validator-accepted
	// 'browser' block policy evaluated 'skipped' with default-allow — the enum
	// had drifted from the emitter. Values that can never match are rejected at
	// authoring time (CA-SCHEMA-ENUM-DRIFT-CONDITION-NO-OP). The SQL mirror
	// (ca_validate_policy_document) is aligned to this same domain via
	// V251__ca_client_type_vocabulary_alignment.sql — persistence/runtime
	// vocabulary parity is pinned by ca_client_type_parity.pg.
	"client_type": {kind: kindEnum, domain: clientTypeConditionDomain()},
	// time_of_day: matchTimeOfDay reads todMap["start"]/["end"]/["tz"].
	"time_of_day": {kind: kindTimeRange},
	// location_in: matchNamedLocation checks the request IP/country against a named_location by id.
	"location_in": {kind: kindInt},
	// location_trusted: matchNamedLocation checks whether the request originates from any trusted location.
	// Value is a JSON boolean (true = must be trusted, false = must NOT be trusted).
	"location_trusted": {kind: kindBool},
	// device_platform: matchDevicePlatform checks the UA-derived OS family (advisory; CA-1 A3).
	// ponytail: UA is spoofable; cryptographic device identity is CA-2.
	"device_platform": {kind: kindEnum, domain: enumSet("windows", "ios", "android", "macos", "linux", "unknown")},
	// country_in: matchCountryIn checks the request country against a set of ISO 3166-1 alpha-2 codes (CA-1 A3).
	"country_in": {kind: kindStringArray},
	// device_bound: matchDeviceBound — true requires a valid X-Device-HMAC proof (CA-2).
	// FAIL-CLOSED: unprovable device resolves to bound=false, so a block policy fires.
	"device_bound": {kind: kindBool},
	// require_approved_client_app: matchApprovedClientApp — true requires a device-bound native shell (CA-2).
	// ponytail: v1 maps to DeviceBound; WebAuthn-platform browser proof deferred to spec §15.
	"require_approved_client_app": {kind: kindBool},
	// auth_strength is NOT a condition — it is enforced as the require_strength GRANT (an action).
	// Removed from allowedConditions: no matcher consumes it as a condition; leaving it here is a
	// latent fail-open (match-all on a key with no matcher). SQL mirror correctly omits it (V032).
}

// allowedActions is the set of valid top-level and nested grant action values.
// limited_web: CA-3a session-control action — restricts the session to browser-only
// access (no native app, no IMAP/SMTP). Validated by set_session_control reducer.
// require_terms: CA-3b — block until the user accepts the current ToU (Remediation="terms").
// require_risk_remediation: CA-3b — block when user_risk is elevated (Remediation="risk").
var allowedActions = enumSet("allow", "block", "step_up", "notify", "require_acr", "require_strength", "limited_web", "require_terms", "require_risk_remediation")

// allowedOperators is the set of valid operator combinator values.
var allowedOperators = enumSet("all", "one")

// ValidatePolicyDocument rejects any unknown condition key, wrong-typed value, or
// out-of-domain enum in either the conditions map or the actions/grants map,
// returning a typed error that names the offending key/value. A nil map is valid
// (no constraints / a pure allow). It is the substrate validator both CA-0a's
// write reducer and CA-1's import call before persist.
func ValidatePolicyDocument(conditions, actions map[string]interface{}) error {
	if err := validateConditions(conditions); err != nil {
		return err
	}
	return validateGrant(actions)
}

func validateConditions(conditions map[string]interface{}) error {
	for key, raw := range conditions {
		spec, ok := allowedConditions[key]
		if !ok {
			return &PolicySchemaError{
				Key:     key,
				Reason:  "unknown condition key",
				Allowed: sortedConditionKeys(),
			}
		}
		if err := validateKind(key, spec, raw); err != nil {
			return err
		}
	}
	return nil
}

func validateKind(key string, spec conditionSpec, raw interface{}) error {
	switch spec.kind {
	case kindEnum:
		s, ok := raw.(string)
		if !ok {
			return &PolicySchemaError{Key: key, Reason: "want a string enum value"}
		}
		if !spec.domain[s] {
			return &PolicySchemaError{Key: key, Value: s, Reason: "value out of enum domain"}
		}
	case kindString:
		if _, ok := raw.(string); !ok {
			return &PolicySchemaError{Key: key, Reason: "want a string"}
		}
	case kindInt:
		// JSON numbers decode to float64; require an integral value (same as toInt64).
		f, ok := raw.(float64)
		if !ok {
			// Also accept int types directly (used in unit tests).
			switch raw.(type) {
			case int, int64, int32:
			default:
				return &PolicySchemaError{Key: key, Reason: "want an integer (numeric group ID)"}
			}
		} else if f != float64(int64(f)) {
			return &PolicySchemaError{Key: key, Reason: fmt.Sprintf("want an integer, got non-integral float64 %v", f)}
		}
	case kindTimeRange:
		obj, ok := raw.(map[string]interface{})
		if !ok {
			return &PolicySchemaError{Key: key, Reason: "want a {start,end[,tz]} time-range object"}
		}
		for _, field := range []string{"start", "end"} {
			v, ok := obj[field].(string)
			if !ok {
				return &PolicySchemaError{Key: key, Reason: "time-range missing string '" + field + "'"}
			}
			// The empty string is the deliberate no-bound case; any other
			// value must be strict 24-hour HH:MM (D-SHARED-THREAT-009).
			// Field-presence-only validation let "9am" match all day before
			// 17:00 and "25:99" silently wrap into the next day — disabling
			// time-scoped blocks as authored.
			if v == "" {
				continue
			}
			if !isValidTimeOfDay(v) {
				return &PolicySchemaError{Key: key, Value: v, Reason: "time-range '" + field + "' must be strict 24-hour HH:MM (or empty for no bound)"}
			}
		}
	case kindBool:
		if _, ok := raw.(bool); !ok {
			return &PolicySchemaError{Key: key, Reason: "want a boolean (true/false)"}
		}
	case kindStringArray:
		arr, ok := raw.([]interface{})
		if !ok {
			return &PolicySchemaError{Key: key, Reason: "want an array of strings"}
		}
		for _, e := range arr {
			if _, ok := e.(string); !ok {
				return &PolicySchemaError{Key: key, Reason: "array elements must be strings"}
			}
		}
	}
	return nil
}

// isValidTimeOfDay reports whether s is strict 24-hour "HH:MM" (00:00-23:59).
// The kindTimeRange validator deliberately accepts "" as no-bound; anything
// else must parse exactly, so a typo like "9am" or "25:99" is rejected at
// authoring time instead of match-all or silently wrapping (D-SHARED-THREAT-009).
func isValidTimeOfDay(s string) bool {
	if len(s) != 5 || s[2] != ':' {
		return false
	}
	hh, mm := s[:2], s[3:]
	for i := 0; i < len(hh); i++ {
		if hh[i] < '0' || hh[i] > '9' {
			return false
		}
	}
	for i := 0; i < len(mm); i++ {
		if mm[i] < '0' || mm[i] > '9' {
			return false
		}
	}
	return hh <= "23" && mm <= "59"
}

// validateGrant validates the top-level action discriminator + optional operator,
// then recurses into a nested grants array if present.
// It checks both "action" (legacy single-action form) and "type" (canonical grant element form)
// against allowedActions, so unknown/misspelled types are rejected at write time.
func validateGrant(actions map[string]interface{}) error {
	if actions == nil {
		return nil
	}
	// require_compliant_device is a CA-2 top-level boolean special action (not a grant type string).
	if v, ok := actions["require_compliant_device"]; ok {
		if _, ok := v.(bool); !ok {
			return &PolicySchemaError{Key: "require_compliant_device", Reason: "want a boolean (true/false)"}
		}
	}
	if a, ok := actions["action"]; ok {
		s, ok := a.(string)
		if !ok {
			return &PolicySchemaError{Key: "action", Reason: "want a string"}
		}
		if !allowedActions[s] {
			return &PolicySchemaError{Key: "action", Value: s, Reason: "value out of grant-action domain"}
		}
	}
	// Canonical grant element form uses "type" (not "action").
	// Validate it against the same domain so unknown/misspelled types are rejected at write time.
	if t, ok := actions["type"]; ok {
		s, ok := t.(string)
		if !ok {
			return &PolicySchemaError{Key: "type", Reason: "want a string"}
		}
		if !allowedActions[s] {
			return &PolicySchemaError{Key: "type", Value: s, Reason: "value out of grant-action domain"}
		}
	}
	if t, tOK := actions["type"].(string); tOK && t != "" {
		if a, aOK := actions["action"].(string); aOK && a != "" && a != t {
			return &PolicySchemaError{
				Key:    "type/action",
				Value:  t + "/" + a,
				Reason: "conflicting non-empty grant discriminators",
			}
		}
	}
	if op, ok := actions["operator"]; ok {
		s, ok := op.(string)
		if !ok {
			return &PolicySchemaError{Key: "operator", Reason: "want a string"}
		}
		if !allowedOperators[s] {
			return &PolicySchemaError{Key: "operator", Value: s, Reason: "value out of operator domain"}
		}
	}
	if g, ok := actions["grants"]; ok {
		arr, ok := g.([]interface{})
		if !ok {
			return &PolicySchemaError{Key: "grants", Reason: "want an array of grant objects"}
		}
		if len(arr) == 0 {
			// ponytail: empty grants array is rejected at write time — fail-closed at both validation and eval.
			return &PolicySchemaError{Key: "grants", Reason: "grants array must not be empty"}
		}
		for _, e := range arr {
			obj, ok := e.(map[string]interface{})
			if !ok {
				return &PolicySchemaError{Key: "grants", Reason: "grant element is not an object"}
			}
			discriminator, invalid := grantDiscriminator(obj)
			if invalid {
				return &PolicySchemaError{Key: "type/action", Reason: "conflicting or malformed grant discriminators"}
			}
			if discriminator == "" {
				return &PolicySchemaError{Key: "grants", Reason: "grant element is missing a non-empty type or action discriminator"}
			}
			// require_terms and require_risk_remediation are top-level action verbs only —
			// they carry tou_id and pectx-conditional logic that the grants loop cannot handle.
			// Reject either canonical `type` or schema-v1 `action` in the nested form so
			// a policy author can't produce a
			// silently-broken document (the grants dispatcher would treat them as unknown types
			// and fail-closed, but the validator should catch this at authoring time).
			if discriminator == "require_terms" || discriminator == "require_risk_remediation" {
				return &PolicySchemaError{Key: "type/action", Value: discriminator, Reason: discriminator + " is a top-level action verb and must not appear in a grants array"}
			}
			if err := validateGrant(obj); err != nil {
				return err
			}
		}
	}
	return nil
}

// AllowedConditionKeys returns the sorted condition-key allow-list. Exported so
// out-of-process validators (mailctl ca validate) derive their help/error text
// from THIS seam instead of hand-copying the list (the hand copy drifted through
// three consecutive schema changes — false-accepting auth_strength and
// false-rejecting limited_web/require_terms/require_risk_remediation).
func AllowedConditionKeys() []string { return sortedConditionKeys() }

// AllowedActionNames returns the sorted grant-action allow-list (see AllowedConditionKeys).
func AllowedActionNames() []string { return sortedEnum(allowedActions) }

// AllowedOperatorNames returns the sorted operator allow-list (see AllowedConditionKeys).
func AllowedOperatorNames() []string { return sortedEnum(allowedOperators) }

// clientTypeConditionDomain returns the client_type condition domain: exactly the
// values clientTypeFromProtocol and clientTypeFromProtocolUmbrella (interceptor.go)
// emit. Derived from the emitter constants rather than a hand-copied list so the
// F6 validator and the runtime cannot drift apart again.
func clientTypeConditionDomain() map[string]bool {
	return enumSet(ClientTypeWeb, ClientTypeMobile, ProtocolIMAP, ProtocolSMTP, ProtocolCalDAV, ClientTypeLegacy)
}

// AllowedClientTypeValues returns the sorted client_type condition domain (see
// AllowedConditionKeys). Exported so the SQL mirror seed (ca_condition_keys
// enum) and out-of-process validators derive their lists from THIS seam instead
// of hand-copying the values.
func AllowedClientTypeValues() []string { return sortedEnum(clientTypeConditionDomain()) }

func sortedEnum(m map[string]bool) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedConditionKeys() []string {
	ks := make([]string, 0, len(allowedConditions))
	for k := range allowedConditions {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// PolicySchemaError is the typed rejection naming the offending key/value.
type PolicySchemaError struct {
	Key     string
	Value   string
	Reason  string
	Allowed []string
}

func (e *PolicySchemaError) Error() string {
	var b strings.Builder
	b.WriteString("invalid policy document: ")
	b.WriteString(e.Reason)
	b.WriteString(" [key=")
	b.WriteString(e.Key)
	if e.Value != "" {
		b.WriteString(" value=")
		b.WriteString(e.Value)
	}
	b.WriteString("]")
	if len(e.Allowed) > 0 {
		b.WriteString(" allowed: ")
		b.WriteString(strings.Join(e.Allowed, ","))
	}
	return b.String()
}
