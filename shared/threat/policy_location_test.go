package threat

import "testing"

func TestMatchNamedLocation(t *testing.T) {
	locs := map[int64]NamedLocation{
		7: {ID: 7, Name: "corp", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}, Countries: []string{"US"}, Trusted: true},
	}
	tests := []struct {
		name string
		cond map[string]interface{}
		ip   string
		ctry string
		want bool
	}{
		{"v4 in cidr", map[string]interface{}{"location_in": float64(7)}, "10.1.2.3", "RU", true},
		{"v6 in cidr", map[string]interface{}{"location_in": float64(7)}, "2001:db8::5", "RU", true},
		{"country match", map[string]interface{}{"location_in": float64(7)}, "203.0.113.9", "US", true},
		{"no match", map[string]interface{}{"location_in": float64(7)}, "203.0.113.9", "RU", false},
		{"trusted true", map[string]interface{}{"location_trusted": true}, "10.1.2.3", "RU", true},
		{"trusted false off-net", map[string]interface{}{"location_trusted": false}, "203.0.113.9", "RU", true},
		{"trusted false on-net is false", map[string]interface{}{"location_trusted": false}, "10.1.2.3", "RU", false},
		{"no condition", map[string]interface{}{}, "10.1.2.3", "US", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pectx := PolicyEvalContext{SourceIP: tc.ip, Country: tc.ctry}
			if got := matchNamedLocation(tc.cond, pectx, locs); got != tc.want {
				t.Fatalf("matchNamedLocation(%v, ip=%s, ctry=%s) = %v, want %v", tc.cond, tc.ip, tc.ctry, got, tc.want)
			}
		})
	}
}

// TestMatchNamedLocationNilLocs guards against the fail-open regression: when
// the location cache is nil, location_trusted must return false (not match),
// preventing a 'block untrusted' policy from firing against all users.
func TestMatchNamedLocationNilLocs(t *testing.T) {
	pectx := PolicyEvalContext{SourceIP: "203.0.113.9", Country: "RU"}
	// nil locs + location_trusted=false must NOT match (fail-closed, return false).
	if matchNamedLocation(map[string]interface{}{"location_trusted": false}, pectx, nil) {
		t.Fatal("location_trusted=false with nil locs should return false (fail-closed), got true")
	}
	// nil locs + location_trusted=true must also not match (cannot confirm trust).
	if matchNamedLocation(map[string]interface{}{"location_trusted": true}, pectx, nil) {
		t.Fatal("location_trusted=true with nil locs should return false (fail-closed), got true")
	}
}

// TestSetNamedLocationsParsedCIDRs verifies setNamedLocations pre-parses CIDRs so
// the hot path never calls netip.ParsePrefix per-request.
func TestSetNamedLocationsParsedCIDRs(t *testing.T) {
	pe := &PolicyEngine{}
	pe.setNamedLocations([]NamedLocation{
		{ID: 1, CIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}, Trusted: true},
	})
	pe.cacheMu.RLock()
	loc, ok := pe.namedLocations[1]
	pe.cacheMu.RUnlock()
	if !ok {
		t.Fatal("location 1 not found after setNamedLocations")
	}
	if len(loc.parsedCIDRs) != 2 {
		t.Fatalf("expected 2 parsed prefixes, got %d", len(loc.parsedCIDRs))
	}
	// Verify the hot path (parsedCIDRs non-nil) is taken for correct CIDR matching.
	if !ipInLocation(loc, "10.1.2.3", "") {
		t.Error("10.1.2.3 should be in 10.0.0.0/8 via parsedCIDRs")
	}
	if !ipInLocation(loc, "2001:db8::1", "") {
		t.Error("2001:db8::1 should be in 2001:db8::/32 via parsedCIDRs")
	}
	if ipInLocation(loc, "1.2.3.4", "") {
		t.Error("1.2.3.4 should NOT be in any CIDR")
	}
}
