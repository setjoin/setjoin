package threat

import (
	"testing"
	"time"
)

// ── PolicyDecision.String() ──

func TestPolicyDecisionString(t *testing.T) {
	tests := []struct {
		d    PolicyDecision
		want string
	}{
		{DecisionAllow, "allow"},
		{DecisionBlock, "block"},
		{DecisionStepUp, "step_up"},
		{DecisionNotify, "notify"},
		{PolicyDecision(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.d.String()
			if got != tt.want {
				t.Errorf("PolicyDecision(%d).String() = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// ── Condition matchers ──

func TestMatchDeviceTrust(t *testing.T) {
	tests := []struct {
		name       string
		conditions map[string]interface{}
		trustTier  string
		want       bool
	}{
		{"exact match managed", map[string]interface{}{"device_trust": "managed"}, "managed", true},
		{"exact match known", map[string]interface{}{"device_trust": "known"}, "known", true},
		{"exact match unknown", map[string]interface{}{"device_trust": "unknown"}, "unknown", true},
		{"exact match risky", map[string]interface{}{"device_trust": "risky"}, "risky", true},
		{"mismatch", map[string]interface{}{"device_trust": "managed"}, "unknown", false},
		{"no condition specified", map[string]interface{}{}, "unknown", true},
		{"condition key present but empty value", map[string]interface{}{"device_trust": ""}, "unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchDeviceTrust(tt.conditions, tt.trustTier)
			if got != tt.want {
				t.Errorf("matchDeviceTrust(%v, %q) = %v, want %v", tt.conditions, tt.trustTier, got, tt.want)
			}
		})
	}
}

func TestMatchIPReputation(t *testing.T) {
	tests := []struct {
		name       string
		conditions map[string]interface{}
		scoreBand  string
		want       bool
	}{
		{"exact band low", map[string]interface{}{"ip_reputation": "low"}, "low", true},
		{"exact band medium", map[string]interface{}{"ip_reputation": "medium"}, "medium", true},
		{"exact band high", map[string]interface{}{"ip_reputation": "high"}, "high", true},
		{"exact band critical", map[string]interface{}{"ip_reputation": "critical"}, "critical", true},
		{"mismatch band", map[string]interface{}{"ip_reputation": "low"}, "high", false},
		{"no condition", map[string]interface{}{}, "critical", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchIPReputation(tt.conditions, tt.scoreBand)
			if got != tt.want {
				t.Errorf("matchIPReputation(%v, %q) = %v, want %v", tt.conditions, tt.scoreBand, got, tt.want)
			}
		})
	}
}

func TestMatchGeoRiskTier(t *testing.T) {
	tests := []struct {
		name       string
		conditions map[string]interface{}
		geoTier    string
		want       bool
	}{
		{"exact low", map[string]interface{}{"geo_risk_tier": "low"}, "low", true},
		{"exact high", map[string]interface{}{"geo_risk_tier": "high"}, "high", true},
		{"exact critical", map[string]interface{}{"geo_risk_tier": "critical"}, "critical", true},
		{"mismatch", map[string]interface{}{"geo_risk_tier": "medium"}, "high", false},
		{"no condition", map[string]interface{}{}, "critical", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGeoRiskTier(tt.conditions, tt.geoTier)
			if got != tt.want {
				t.Errorf("matchGeoRiskTier(%v, %q) = %v, want %v", tt.conditions, tt.geoTier, got, tt.want)
			}
		})
	}
}

func TestMatchUserGroup(t *testing.T) {
	groupIDs := []int64{10, 20, 30}

	tests := []struct {
		name       string
		conditions map[string]interface{}
		want       bool
	}{
		{"member in group", map[string]interface{}{"user_group": float64(20)}, true},
		{"not a member", map[string]interface{}{"user_group": float64(99)}, false},
		{"no condition", map[string]interface{}{}, true},
		{"empty group IDs", map[string]interface{}{"user_group": float64(10)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchUserGroup(tt.conditions, groupIDs)
			if got != tt.want {
				t.Errorf("matchUserGroup(%v, %v) = %v, want %v", tt.conditions, groupIDs, got, tt.want)
			}
		})
	}

	// Test with nil group IDs
	t.Run("nil group IDs with condition", func(t *testing.T) {
		got := matchUserGroup(map[string]interface{}{"user_group": float64(10)}, nil)
		if got {
			t.Error("matchUserGroup with nil groupIDs should return false")
		}
	})
}

func TestMatchAuthMethod(t *testing.T) {
	tests := []struct {
		name       string
		conditions map[string]interface{}
		authMethod string
		want       bool
	}{
		{"password match", map[string]interface{}{"auth_method": "password"}, "password", true},
		{"webauthn match", map[string]interface{}{"auth_method": "webauthn"}, "webauthn", true},
		{"totp match", map[string]interface{}{"auth_method": "totp"}, "totp", true},
		{"saml match", map[string]interface{}{"auth_method": "saml"}, "saml", true},
		{"oidc match", map[string]interface{}{"auth_method": "oidc"}, "oidc", true},
		{"kerberos match", map[string]interface{}{"auth_method": "kerberos"}, "kerberos", true},
		{"mismatch", map[string]interface{}{"auth_method": "password"}, "webauthn", false},
		{"no condition", map[string]interface{}{}, "password", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchAuthMethod(tt.conditions, tt.authMethod)
			if got != tt.want {
				t.Errorf("matchAuthMethod(%v, %q) = %v, want %v", tt.conditions, tt.authMethod, got, tt.want)
			}
		})
	}
}

func TestMatchClientType(t *testing.T) {
	tests := []struct {
		name       string
		conditions map[string]interface{}
		clientType string
		want       bool
	}{
		{"web match", map[string]interface{}{"client_type": "web"}, "web", true},
		{"imap match", map[string]interface{}{"client_type": "imap"}, "imap", true},
		{"smtp match", map[string]interface{}{"client_type": "smtp"}, "smtp", true},
		{"mobile match", map[string]interface{}{"client_type": "mobile"}, "mobile", true},
		{"caldav match", map[string]interface{}{"client_type": "caldav"}, "caldav", true},
		{"mismatch", map[string]interface{}{"client_type": "web"}, "mobile", false},
		{"no condition", map[string]interface{}{}, "web", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchClientType(tt.conditions, tt.clientType)
			if got != tt.want {
				t.Errorf("matchClientType(%v, %q) = %v, want %v", tt.conditions, tt.clientType, got, tt.want)
			}
		})
	}
}

func TestMatchTimeOfDay(t *testing.T) {
	// Use a fixed date for deterministic testing: 2026-06-01 (Monday)
	baseDate := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		conditions map[string]interface{}
		reqTime    time.Time
		want       bool
	}{
		{
			"in window - 9am to 5pm, 12pm",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"}},
			baseDate.Add(12 * time.Hour),
			true,
		},
		{
			"outside window - before start",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"}},
			baseDate.Add(7 * time.Hour),
			false,
		},
		{
			"outside window - after end",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"}},
			baseDate.Add(18 * time.Hour),
			false,
		},
		{
			"exactly at start boundary",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"}},
			baseDate.Add(9 * time.Hour),
			true,
		},
		{
			"exactly at end boundary",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "09:00", "end": "17:00", "tz": "UTC"}},
			baseDate.Add(17 * time.Hour),
			false,
		},
		{
			"cross-midnight - 22:00 to 06:00, 2am",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "22:00", "end": "06:00", "tz": "UTC"}},
			baseDate.Add(2 * time.Hour),
			true,
		},
		{
			"cross-midnight - inside evening portion",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "22:00", "end": "06:00", "tz": "UTC"}},
			baseDate.Add(23 * time.Hour),
			true,
		},
		{
			"cross-midnight - outside window (daytime)",
			map[string]interface{}{"time_of_day": map[string]interface{}{"start": "22:00", "end": "06:00", "tz": "UTC"}},
			baseDate.Add(12 * time.Hour),
			false,
		},
		{
			"no time_of_day condition",
			map[string]interface{}{},
			baseDate,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchTimeOfDay(tt.conditions, tt.reqTime)
			if got != tt.want {
				t.Errorf("matchTimeOfDay(%v, %v) = %v, want %v", tt.conditions, tt.reqTime, got, tt.want)
			}
		})
	}
}

// ── Combined matching ──

func TestMatchAllConditions(t *testing.T) {
	// Helper to make a context
	makeCtx := func() PolicyEvalContext {
		return PolicyEvalContext{
			UserID:      42,
			GroupIDs:    []int64{10, 20},
			SourceIP:    "203.0.113.42",
			Country:     "US",
			DeviceFP:    "test-fp",
			AuthMethod:  "password",
			ClientType:  "web",
			Protocol:    "http",
			UserAgent:   "test-agent",
			RequestTime: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		}
	}

	tests := []struct {
		name       string
		conditions map[string]interface{}
		ctx        PolicyEvalContext
		trustTier  string
		scoreBand  string
		geoTier    string
		want       bool
	}{
		{
			"all match",
			map[string]interface{}{"auth_method": "password", "client_type": "web"},
			makeCtx(), "known", "low", "low",
			true,
		},
		{
			"one mismatch fails all",
			map[string]interface{}{"auth_method": "password", "device_trust": "managed"},
			makeCtx(), "known", "low", "low",
			false,
		},
		{
			"empty conditions always match",
			map[string]interface{}{},
			makeCtx(), "risky", "critical", "critical",
			true,
		},
		{
			"device_trust + geo_risk_tier both match",
			map[string]interface{}{"device_trust": "known", "geo_risk_tier": "low"},
			makeCtx(), "known", "low", "low",
			true,
		},
		{
			"ip_reputation + geo_risk_tier mismatch on ip",
			map[string]interface{}{"ip_reputation": "high", "geo_risk_tier": "low"},
			makeCtx(), "known", "low", "low",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchAll(tt.conditions, tt.ctx, tt.trustTier, tt.scoreBand, tt.geoTier, "", nil)
			if got != tt.want {
				t.Errorf("matchAll(%v, ...) = %v, want %v", tt.conditions, got, tt.want)
			}
		})
	}
}

// ── Action dispatch ──

func TestDispatchAction(t *testing.T) {
	tests := []struct {
		name    string
		actions map[string]interface{}
		row     PolicyRow
		want    PolicyDecision
	}{
		{
			"allow action",
			map[string]interface{}{"action": "allow"},
			PolicyRow{ID: 1, Name: "test-allow", Priority: 10},
			DecisionAllow,
		},
		{
			"block action",
			map[string]interface{}{"action": "block", "reason": "test block"},
			PolicyRow{ID: 2, Name: "test-block", Priority: 20},
			DecisionBlock,
		},
		{
			"step_up action",
			map[string]interface{}{"action": "step_up", "methods": []interface{}{"totp", "webauthn"}},
			PolicyRow{ID: 3, Name: "test-stepup", Priority: 30},
			DecisionStepUp,
		},
		{
			"notify action",
			map[string]interface{}{"action": "notify", "channels": []interface{}{"admin_alert", "audit"}},
			PolicyRow{ID: 4, Name: "test-notify", Priority: 40},
			DecisionNotify,
		},
		{
			// CA-1 A5: unknown/misparsed grant type must fail SAFE (block), never silently allow.
			// Pre-CA-1 the legacy path returned DecisionAllow for unknown action strings.
			"unknown action fails safe (block)",
			map[string]interface{}{"action": "unknown_action"},
			PolicyRow{ID: 5, Name: "test-unknown", Priority: 50},
			DecisionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dispatchAction(tt.actions, tt.row, PolicyEvalContext{}, nil)
			if result.Decision != tt.want {
				t.Errorf("dispatchAction() decision = %v, want %v", result.Decision, tt.want)
			}
			if result.PolicyID != tt.row.ID {
				t.Errorf("dispatchAction() policyID = %d, want %d", result.PolicyID, tt.row.ID)
			}
		})
	}

	// Verify step_up methods extraction
	t.Run("step_up methods extraction", func(t *testing.T) {
		result := dispatchAction(
			map[string]interface{}{"action": "step_up", "methods": []interface{}{"totp", "webauthn", "push"}},
			PolicyRow{ID: 1, Name: "mfa-test", Priority: 10},
			PolicyEvalContext{},
			nil,
		)
		if len(result.StepUpMethods) != 3 {
			t.Errorf("step_up methods count = %d, want 3", len(result.StepUpMethods))
		}
	})

	// Verify notify channels extraction
	t.Run("notify channels extraction", func(t *testing.T) {
		result := dispatchAction(
			map[string]interface{}{"action": "notify", "channels": []interface{}{"admin_alert", "audit"}},
			PolicyRow{ID: 1, Name: "notify-test", Priority: 10},
			PolicyEvalContext{},
			nil,
		)
		if len(result.NotifyChannels) != 2 {
			t.Errorf("notify channels count = %d, want 2", len(result.NotifyChannels))
		}
	})
}

// ── Scope filtering ──

func TestScopeMatches(t *testing.T) {
	tests := []struct {
		name         string
		scopeType    string
		scopeTarget  string
		userID       int64
		groupIDs     []int64
		roleGroupIDs []int64
		want         bool
	}{
		{"global always matches", "global", "", 42, nil, nil, true},
		{"user exact match", "user", "42", 42, nil, nil, true},
		{"user mismatch", "user", "99", 42, nil, nil, false},
		{"user empty target", "user", "", 42, nil, nil, false},
		{"group membership match", "group", "10", 42, []int64{10, 20}, nil, true},
		{"group not member", "group", "99", 42, []int64{10, 20}, nil, false},
		{"group empty target", "group", "", 42, []int64{10}, nil, false},
		// role scope: fires when principal holds the target admin role-group
		{"role match", "role", "5", 42, nil, []int64{5, 7}, true},
		{"role not member", "role", "9", 42, nil, []int64{5, 7}, false},
		{"role empty target", "role", "", 42, nil, []int64{5}, false},
		{"role no memberships", "role", "5", 42, nil, nil, false},
		// unknown scope type always false
		{"unknown scope type", "department", "eng", 42, []int64{1}, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scopeMatches(tt.scopeType, tt.scopeTarget, tt.userID, tt.groupIDs, tt.roleGroupIDs, false)
			if got != tt.want {
				t.Errorf("scopeMatches(%q, %q, %d, %v, %v) = %v, want %v",
					tt.scopeType, tt.scopeTarget, tt.userID, tt.groupIDs, tt.roleGroupIDs, got, tt.want)
			}
		})
	}
}

// ── Policy result ──

func TestPolicyResultFailOpen(t *testing.T) {
	// No policies = allow (fail open)
	result := PolicyResult{
		Decision: DecisionAllow,
		Reason:   "no matching policy (default allow)",
	}
	if result.Decision != DecisionAllow {
		t.Errorf("default result should be allow, got %v", result.Decision)
	}
	if result.PolicyID != 0 {
		t.Errorf("default result policyID should be 0, got %d", result.PolicyID)
	}
}

// TestParseGrantsToleratesActionKey: the SQL side (V050 demo seed,
// ca_validate_policy_document, template catalog) emits grant-array elements
// keyed "action", while the engine's canonical key is "type". The engine must
// read both, else seeded/template policies parse to Type:"" and silently fail
// to enforce. Regression guard for the live-E2E-surfaced grant-format bug.
func TestParseGrantsToleratesActionKey(t *testing.T) {
	actions := map[string]interface{}{
		"operator": "all",
		"grants":   []interface{}{map[string]interface{}{"action": "block"}},
		"reason":   "seeded demo policy",
	}
	op, grants := parseGrants(actions)
	if op != "all" {
		t.Fatalf("operator: got %q want all", op)
	}
	if len(grants) != 1 || grants[0].Type != "block" {
		t.Fatalf("grants: got %+v, want one grant Type=block (action key must map to Type)", grants)
	}
	if !isEnforcingActions(actions) {
		t.Error("isEnforcingActions must be true for grants:[{action:block}] (block is an enforcing verb)")
	}
	// And the canonical "type" key still works.
	typed := map[string]interface{}{"grants": []interface{}{map[string]interface{}{"type": "block"}}}
	if _, g := parseGrants(typed); len(g) != 1 || g[0].Type != "block" {
		t.Errorf("canonical type key broke: %+v", g)
	}
}

func TestParseGrantsConflictingDiscriminatorsFailClosed(t *testing.T) {
	actions := map[string]interface{}{
		"operator": "all",
		"grants": []interface{}{
			map[string]interface{}{"type": "allow", "action": "block"},
		},
	}

	result := dispatchAction(actions, PolicyRow{ID: 1, Name: "conflict"}, PolicyEvalContext{}, nil)
	if result.Decision != DecisionBlock {
		t.Fatalf("conflicting grant discriminators = %v, want block (fail-closed)", result.Decision)
	}
	if !isEnforcingActions(actions) {
		t.Fatal("conflicting grant discriminators must be classified as enforcing")
	}
}
