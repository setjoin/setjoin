// Conditional access condition matchers — split out of policy.go
// (pure file reorganization; same package, no behavior change).
package threat

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// locationCache caches time.LoadLocation results keyed by IANA timezone name.
// time.LoadLocation reads the IANA database from disk on every call;
// caching avoids that filesystem hit on every auth request.
var locationCache sync.Map

// parseDevicePlatform sniffs the OS family from a User-Agent. UA is SPOOFABLE —
// this is an advisory condition, NOT a security boundary (the cryptographic
// device identity is CA-2). Order matters: iOS/Android before macOS/Linux.
// ponytail: simple strings.Contains cascade; upgrade to a UA-parser lib if
// fingerprinting accuracy becomes a product requirement.
func parseDevicePlatform(ua string) string {
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad") || strings.Contains(l, "ipod"):
		return "ios"
	case strings.Contains(l, "android"):
		return "android"
	case strings.Contains(l, "windows"):
		return "windows"
	case strings.Contains(l, "mac os x") || strings.Contains(l, "macintosh"):
		return "macos"
	case strings.Contains(l, "linux"):
		return "linux"
	default:
		return "unknown"
	}
}

// matchDevicePlatform checks the device_platform condition (advisory — UA-derived).
func matchDevicePlatform(conditions map[string]interface{}, platform string) bool {
	v, ok := conditions["device_platform"]
	if !ok || v == nil || v == "" {
		return true
	}
	s, ok := v.(string)
	return ok && s == platform
}

// matchCountryIn checks the country_in condition (array of ISO 3166-1 alpha-2 codes).
// Empty/absent condition matches all. Case-insensitive; "" matches unknown country.
func matchCountryIn(conditions map[string]interface{}, country string) bool {
	v, ok := conditions["country_in"]
	if !ok || v == nil {
		return true
	}
	arr, ok := v.([]interface{})
	if !ok {
		return false
	}
	for _, e := range arr {
		if s, ok := e.(string); ok && strings.EqualFold(s, country) {
			return true
		}
	}
	return false
}

// ── Condition matchers ──

// matchDeviceTrust checks if the device trust tier matches the condition.
func matchDeviceTrust(conditions map[string]interface{}, trustTier string) bool {
	condVal, ok := conditions["device_trust"]
	if !ok || condVal == nil || condVal == "" {
		return true
	}
	condStr, ok := condVal.(string)
	return ok && condStr == trustTier
}

// matchIPReputation checks if the IP reputation band matches the condition.
func matchIPReputation(conditions map[string]interface{}, scoreBand string) bool {
	condVal, ok := conditions["ip_reputation"]
	if !ok || condVal == nil || condVal == "" {
		return true
	}
	condStr, ok := condVal.(string)
	return ok && condStr == scoreBand
}

// matchGeoRiskTier checks if the geo risk tier matches the condition.
func matchGeoRiskTier(conditions map[string]interface{}, geoTier string) bool {
	condVal, ok := conditions["geo_risk_tier"]
	if !ok || condVal == nil || condVal == "" {
		return true
	}
	condStr, ok := condVal.(string)
	return ok && condStr == geoTier
}

// matchUserGroup checks if the user belongs to the specified group.
func matchUserGroup(conditions map[string]interface{}, groupIDs []int64) bool {
	condVal, ok := conditions["user_group"]
	if !ok || condVal == nil {
		return true
	}
	// Condition value is a numeric group ID (JSON number → float64)
	groupID, err := toInt64(condVal)
	if err != nil {
		return false
	}
	for _, gid := range groupIDs {
		if gid == groupID {
			return true
		}
	}
	return false
}

// matchAuthMethod checks if the authentication method matches the condition.
func matchAuthMethod(conditions map[string]interface{}, authMethod string) bool {
	condVal, ok := conditions["auth_method"]
	if !ok || condVal == nil || condVal == "" {
		return true
	}
	condStr, ok := condVal.(string)
	return ok && condStr == authMethod
}

// matchClientType checks if the client type matches the condition.
func matchClientType(conditions map[string]interface{}, clientType string) bool {
	condVal, ok := conditions["client_type"]
	if !ok || condVal == nil || condVal == "" {
		return true
	}
	condStr, ok := condVal.(string)
	return ok && condStr == clientType
}

// matchDeviceBound checks the device_bound condition: true means "only a
// cryptographically bound device matches"; false means "only an unbound device".
// FAIL-CLOSED: an unprovable device resolves to DeviceBound=false, so a policy
// requiring device_bound=true blocks it. An absent condition always matches.
func matchDeviceBound(conditions map[string]interface{}, deviceBound bool) bool {
	condVal, ok := conditions["device_bound"]
	if !ok || condVal == nil {
		return true
	}
	want, ok := condVal.(bool)
	return ok && want == deviceBound
}

// matchApprovedClientApp checks require_approved_client_app: the request must
// carry a valid native-shell device proof (DeviceBound). v1: a plain browser
// (unbound) never satisfies it (the WebAuthn-platform browser proof is deferred,
// spec §15). An absent/false condition always matches.
// ponytail: reuses DeviceBound signal — no separate approved-app registry yet.
func matchApprovedClientApp(conditions map[string]interface{}, deviceBound bool) bool {
	condVal, ok := conditions["require_approved_client_app"]
	if !ok || condVal == nil {
		return true
	}
	want, ok := condVal.(bool)
	if !ok || !want {
		return true
	}
	return deviceBound
}

// matchTimeOfDay checks if the request time falls within the configured window.
// Condition format: {"time_of_day": {"start": "09:00", "end": "17:00", "tz": "UTC"}}
func matchTimeOfDay(conditions map[string]interface{}, t time.Time) bool {
	todVal, ok := conditions["time_of_day"]
	if !ok || todVal == nil {
		return true
	}

	todMap, ok := todVal.(map[string]interface{})
	if !ok {
		return false
	}

	startStr, _ := todMap["start"].(string)
	endStr, _ := todMap["end"].(string)
	tzStr, _ := todMap["tz"].(string)

	if startStr == "" || endStr == "" {
		return true
	}

	loc := locationCacheGet(tzStr)

	tInLoc := t.In(loc)

	start := parseTimeOfDay(startStr, loc, tInLoc)
	end := parseTimeOfDay(endStr, loc, tInLoc)

	currentMinutes := tInLoc.Hour()*60 + tInLoc.Minute()
	startMinutes := start.Hour()*60 + start.Minute()
	endMinutes := end.Hour()*60 + end.Minute()

	if startMinutes <= endMinutes {
		// Normal window: e.g. 09:00-17:00
		return currentMinutes >= startMinutes && currentMinutes < endMinutes
	}
	// Cross-midnight window: e.g. 22:00-06:00
	return currentMinutes >= startMinutes || currentMinutes < endMinutes
}

// ipInLocation reports whether the given ip/country resolves to within loc.
// Country is checked first (cheaper); CIDR lookup follows if no country hit.
// Uses pre-parsed prefixes (parsedCIDRs) when available (set by setNamedLocations);
// falls back to parsing CIDRs inline for locations constructed directly in tests.
func ipInLocation(loc NamedLocation, ip, country string) bool {
	if country != "" {
		for _, c := range loc.Countries {
			if strings.EqualFold(c, country) {
				return true
			}
		}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	if loc.parsedCIDRs != nil {
		// Hot path: pre-parsed at setNamedLocations time, no per-request string work.
		for _, pfx := range loc.parsedCIDRs {
			if pfx.Contains(addr) {
				return true
			}
		}
		return false
	}
	// ponytail: fallback for NamedLocation values built directly (e.g. unit tests).
	// setNamedLocations always populates parsedCIDRs so this branch is never taken on
	// the live auth path.
	for _, cidr := range loc.CIDRs {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

// matchNamedLocation evaluates location_in (id match) and location_trusted (bool) conditions.
// locs is the engine's namedLocations cache snapshot.
func matchNamedLocation(conditions map[string]interface{}, pectx PolicyEvalContext, locs map[int64]NamedLocation) bool {
	if v, ok := conditions["location_in"]; ok && v != nil {
		id, err := toInt64(v)
		if err != nil {
			return false
		}
		loc, ok := locs[id]
		if !ok || !ipInLocation(loc, pectx.SourceIP, pectx.Country) {
			return false
		}
	}
	if v, ok := conditions["location_trusted"]; ok && v != nil {
		// Fail-closed: if the location cache hasn't been loaded yet we cannot determine
		// trust membership — return false so the policy condition does not match.
		// This prevents a 'block untrusted' policy from firing against all users
		// (including actually-trusted ones) before the load path wires setNamedLocations.
		if locs == nil {
			return false
		}
		want, _ := v.(bool)
		// inTrusted = the request originates from ANY trusted named location.
		// location_trusted=false fires when NOT in any trusted location (e.g. block untrusted).
		inTrusted := false
		for _, loc := range locs {
			if loc.Trusted && ipInLocation(loc, pectx.SourceIP, pectx.Country) {
				inTrusted = true
				break
			}
		}
		if inTrusted != want {
			return false
		}
	}
	return true
}

// matchAll evaluates all conditions against the policy evaluation context.
// Returns true only if every condition in the policy matches.
// platform is the pre-parsed UA-derived OS family (parseDevicePlatform); pre-computing
// it outside matchAll lets A5/A6/simulator inject a platform directly without a UA string.
// locs is the engine's named-location cache snapshot (nil = no locations loaded).
func matchAll(conditions map[string]interface{}, ctx PolicyEvalContext, trustTier, scoreBand, geoTier, platform string, locs map[int64]NamedLocation) bool {
	if len(conditions) == 0 {
		return true
	}
	if !matchDeviceTrust(conditions, trustTier) {
		return false
	}
	if !matchIPReputation(conditions, scoreBand) {
		return false
	}
	if !matchGeoRiskTier(conditions, geoTier) {
		return false
	}
	if !matchUserGroup(conditions, ctx.GroupIDs) {
		return false
	}
	if !matchAuthMethod(conditions, ctx.AuthMethod) {
		return false
	}
	if !matchTimeOfDay(conditions, ctx.RequestTime) {
		return false
	}
	if !matchClientType(conditions, ctx.ClientType) {
		return false
	}
	if !matchNamedLocation(conditions, ctx, locs) {
		return false
	}
	if !matchDevicePlatform(conditions, platform) {
		return false
	}
	if !matchCountryIn(conditions, ctx.Country) {
		return false
	}
	if !matchDeviceBound(conditions, ctx.DeviceBound) {
		return false
	}
	if !matchApprovedClientApp(conditions, ctx.DeviceBound) {
		return false
	}
	return true
}

// matchAllVerbose is the simulator-only diagnostic twin of matchAll: it calls the
// same per-condition matchers in the same order and returns (match, firstFailedKey).
// firstFailedKey is the conditions map key of the first matcher that returned false
// (e.g. "device_trust", "country_in"), or "" when all conditions match.
//
// GOLDEN invariant: matchAllVerbose(…).ok == matchAll(…) for all inputs (pinned by
// TestMatchAllVerboseEqualsMatchAll). The hot-path boolean matchAll is left untouched.
//
// ponytail: simulator-only; not called from Evaluate — the real path stays matchAll.
// If the condition set grows, add the new key here in the same order as matchAll.
func matchAllVerbose(conditions map[string]interface{}, ctx PolicyEvalContext, trustTier, scoreBand, geoTier, platform string, locs map[int64]NamedLocation) (ok bool, firstFailed string) {
	if len(conditions) == 0 {
		return true, ""
	}
	if !matchDeviceTrust(conditions, trustTier) {
		return false, "device_trust"
	}
	if !matchIPReputation(conditions, scoreBand) {
		return false, "ip_reputation"
	}
	if !matchGeoRiskTier(conditions, geoTier) {
		return false, "geo_risk_tier"
	}
	if !matchUserGroup(conditions, ctx.GroupIDs) {
		return false, "user_group"
	}
	if !matchAuthMethod(conditions, ctx.AuthMethod) {
		return false, "auth_method"
	}
	if !matchTimeOfDay(conditions, ctx.RequestTime) {
		return false, "time_of_day"
	}
	if !matchClientType(conditions, ctx.ClientType) {
		return false, "client_type"
	}
	if !matchNamedLocation(conditions, ctx, locs) {
		return false, "location_in"
	}
	if !matchDevicePlatform(conditions, platform) {
		return false, "device_platform"
	}
	if !matchCountryIn(conditions, ctx.Country) {
		return false, "country_in"
	}
	if !matchDeviceBound(conditions, ctx.DeviceBound) {
		return false, "device_bound"
	}
	if !matchApprovedClientApp(conditions, ctx.DeviceBound) {
		return false, "require_approved_client_app"
	}
	return true, ""
}

// locationCacheGet returns *time.Location for the given IANA timezone name,
// using a sync.Map cache to avoid filesystem reads on repeated calls.
// Returns time.UTC for empty string or unrecognized timezone names.
func locationCacheGet(tzStr string) *time.Location {
	if tzStr == "" {
		return time.UTC
	}
	if v, ok := locationCache.Load(tzStr); ok {
		return v.(*time.Location)
	}
	loc, err := time.LoadLocation(tzStr)
	if err != nil {
		loc = time.UTC
	}
	locationCache.Store(tzStr, loc)
	return loc
}

// parseTimeOfDay parses a "HH:MM" string and applies it to the given date.
func parseTimeOfDay(s string, loc *time.Location, ref time.Time) time.Time {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return ref
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	return time.Date(ref.Year(), ref.Month(), ref.Day(), h, m, 0, 0, loc)
}
