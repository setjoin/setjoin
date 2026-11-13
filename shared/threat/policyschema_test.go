package threat

import "testing"

// A fully-valid document covering every allowed condition key/type/enum and a
// grant block — the ACCEPT case the matchers actually consume.
func validDoc() (map[string]interface{}, map[string]interface{}) {
	conditions := map[string]interface{}{
		// kindEnum keys
		"device_trust":  "managed",
		"ip_reputation": "high",
		"geo_risk_tier": "critical",
		"client_type":   "imap",
		// kindInt key (user_group is a numeric group ID, matchUserGroup calls toInt64)
		"user_group": float64(99),
		// kindString key (auth_method is a single string, matchAuthMethod: condVal.(string))
		"auth_method": "totp",
		// kindTimeRange key (matchTimeOfDay reads start/end/tz)
		"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"},
	}
	actions := map[string]interface{}{
		"action":   "step_up",
		"operator": "all",
		"grants": []interface{}{
			map[string]interface{}{"action": "require_acr", "operator": "one"},
		},
	}
	return conditions, actions
}

func TestValidatePolicyDocumentAcceptsValid(t *testing.T) {
	c, a := validDoc()
	if err := ValidatePolicyDocument(c, a); err != nil {
		t.Fatalf("valid document must pass, got: %v", err)
	}
}

// The load-bearing case: a typo'd condition key on a block policy is REJECTED,
// not silently dropped (the fail-open regression test).
func TestValidatePolicyDocumentRejectsUnknownKey(t *testing.T) {
	c, _ := validDoc()
	delete(c, "geo_risk_tier")
	c["geo_risk_teir"] = "high" // typo
	err := ValidatePolicyDocument(c, map[string]interface{}{"action": "block"})
	if err == nil {
		t.Fatal("unknown condition key must be rejected, not silently dropped")
	}
	if !containsSubstr(err.Error(), "geo_risk_teir") {
		t.Fatalf("error must name the offending key, got: %v", err)
	}
}

func TestValidatePolicyDocumentRejectsWrongType(t *testing.T) {
	// user_group as a string (must be a number/int).
	c, a := validDoc()
	c["user_group"] = "engineering"
	if err := ValidatePolicyDocument(c, a); err == nil {
		t.Fatal("user_group as a string must be rejected (wants int)")
	}
	// auth_method as an array (must be a single string).
	c2, a2 := validDoc()
	c2["auth_method"] = []interface{}{"totp", "webauthn"}
	if err := ValidatePolicyDocument(c2, a2); err == nil {
		t.Fatal("auth_method as an array must be rejected (wants string)")
	}
	// time_of_day missing start key (must have start + end).
	c3, a3 := validDoc()
	c3["time_of_day"] = map[string]interface{}{"from": "09:00", "to": "17:00"}
	if err := ValidatePolicyDocument(c3, a3); err == nil {
		t.Fatal("time_of_day with from/to must be rejected (wants start/end)")
	}
}

func TestValidatePolicyDocumentRejectsBadEnum(t *testing.T) {
	// out-of-domain device_trust (brief's "trustworthy" is not a real tier)
	c, a := validDoc()
	c["device_trust"] = "trustworthy"
	if err := ValidatePolicyDocument(c, a); err == nil {
		t.Fatal(`device_trust:"trustworthy" must be rejected (out of domain)`)
	}
	// out-of-domain ip_reputation ("clean" is not a real band — real values: low/medium/high/critical)
	c2, a2 := validDoc()
	c2["ip_reputation"] = "clean"
	if err := ValidatePolicyDocument(c2, a2); err == nil {
		t.Fatal(`ip_reputation:"clean" must be rejected (real bands are low/medium/high/critical)`)
	}
	// out-of-domain grant action
	c3, _ := validDoc()
	if err := ValidatePolicyDocument(c3, map[string]interface{}{"action": "deny"}); err == nil {
		t.Fatal(`action:"deny" must be rejected (out of domain)`)
	}
	// out-of-domain operator
	c4, _ := validDoc()
	if err := ValidatePolicyDocument(c4, map[string]interface{}{"action": "block", "operator": "any"}); err == nil {
		t.Fatal(`operator:"any" must be rejected (out of domain)`)
	}
}

func TestValidatePolicyDocumentNilIsValid(t *testing.T) {
	if err := ValidatePolicyDocument(nil, nil); err != nil {
		t.Fatalf("nil conditions + nil actions must be valid, got: %v", err)
	}
}

// Fail-open guard (F6): "named_location" (bare) is NOT a valid condition key;
// the location matcher uses "location_in"/"location_trusted" (CA-1 A2).
// "auth_strength" is a GRANT (require_strength), not a condition — must be rejected.
func TestValidatePolicyDocumentRejectsUnmatchedConditionKeys(t *testing.T) {
	// named_location (bare) must still be rejected
	c := map[string]interface{}{"named_location": float64(1)}
	if err := ValidatePolicyDocument(c, map[string]interface{}{"action": "block"}); err == nil {
		t.Error(`"named_location" must be rejected (use location_in/location_trusted)`)
	}
	// auth_strength is a grant (require_strength), not a condition — must be rejected as a condition.
	// Latent fail-open: a key with no matcher silently matches all — fix is to remove it from conditions.
	c2 := map[string]interface{}{"auth_strength": float64(1)}
	if err := ValidatePolicyDocument(c2, map[string]interface{}{"action": "block"}); err == nil {
		t.Error(`"auth_strength" must be rejected as a condition (it is the require_strength grant, not a condition key)`)
	}
}

// Finding 1 guard: empty grants array must be rejected at write time.
func TestValidatePolicyDocumentRejectsEmptyGrantsArray(t *testing.T) {
	c, _ := validDoc()
	if err := ValidatePolicyDocument(c, map[string]interface{}{"grants": []interface{}{}}); err == nil {
		t.Fatal(`{"grants":[]} must be rejected (empty grants array is fail-open)`)
	}
}

// Finding 2 guard: canonical grant "type" key must be validated against allowedActions.
func TestValidatePolicyDocumentRejectsUnknownGrantType(t *testing.T) {
	c, _ := validDoc()
	bad := map[string]interface{}{"grants": []interface{}{
		map[string]interface{}{"type": "unknown_evil"},
	}}
	if err := ValidatePolicyDocument(c, bad); err == nil {
		t.Fatal(`grant {"type":"unknown_evil"} must be rejected (type not in allowedActions)`)
	}
	// known type must be accepted
	good := map[string]interface{}{"grants": []interface{}{
		map[string]interface{}{"type": "block"},
	}}
	if err := ValidatePolicyDocument(c, good); err != nil {
		t.Fatalf(`grant {"type":"block"} must be accepted, got: %v`, err)
	}
}

func TestValidatePolicyDocumentGrantDiscriminatorParity(t *testing.T) {
	tests := []struct {
		name    string
		grant   map[string]interface{}
		wantErr bool
	}{
		{name: "canonical type", grant: map[string]interface{}{"type": "block"}},
		{name: "schema v1 action", grant: map[string]interface{}{"action": "block"}},
		{name: "matching type and action", grant: map[string]interface{}{"type": "step_up", "action": "step_up"}},
		{name: "conflicting non-empty discriminators", grant: map[string]interface{}{"type": "block", "action": "notify"}, wantErr: true},
		{name: "missing discriminator", grant: map[string]interface{}{}, wantErr: true},
		{name: "empty canonical discriminator", grant: map[string]interface{}{"type": ""}, wantErr: true},
		{name: "empty canonical with legacy fallback", grant: map[string]interface{}{"type": "", "action": "allow"}, wantErr: true},
		{name: "unknown schema v1 discriminator", grant: map[string]interface{}{"action": "unknown"}, wantErr: true},
		{name: "malformed canonical discriminator", grant: map[string]interface{}{"type": true}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := map[string]interface{}{
				"operator": "all",
				"grants":   []interface{}{tt.grant},
			}
			err := ValidatePolicyDocument(nil, actions)
			if tt.wantErr && err == nil {
				t.Fatal("expected discriminator validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected discriminator validation error: %v", err)
			}
		})
	}
}

func containsSubstr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestValidatePolicyDocument_TimeOfDayFormat pins strict HH:MM validation for
// kindTimeRange (D-SHARED-THREAT-009): a non-HH:MM value like "9am" previously
// match-all'd before 17:00 and "25:99" silently wrapped into the next day,
// disabling time-scoped blocks as authored. The empty string stays the
// deliberate no-bound case.
func TestValidatePolicyDocument_TimeOfDayFormat(t *testing.T) {
	cases := []struct {
		name    string
		start   string
		end     string
		wantErr bool
	}{
		{"valid window", "09:00", "17:00", false},
		{"day bounds", "00:00", "23:59", false},
		{"empty is no-bound", "", "", false},
		{"empty start only", "", "17:00", false},
		{"meridiem typo", "9am", "17:00", true},
		{"hour overflow", "25:99", "17:00", true},
		{"minute overflow", "09:60", "17:00", true},
		{"missing colon", "0900", "17:00", true},
		{"short hour", "9:00", "17:00", true},
		{"hour 24", "24:00", "17:00", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conditions := map[string]interface{}{
				"time_of_day": map[string]interface{}{"start": tc.start, "end": tc.end, "tz": "UTC"},
			}
			err := ValidatePolicyDocument(conditions, map[string]interface{}{"action": "block"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidatePolicyDocument(start=%q end=%q) err=%v, wantErr=%v", tc.start, tc.end, err, tc.wantErr)
			}
		})
	}
}
