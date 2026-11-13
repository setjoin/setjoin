package threat

import "testing"

func TestRiskFromRow(t *testing.T) {
	if RiskFromRow(0, "none", nil) != nil {
		t.Fatal("a clean user must produce no Risk claim (nil)")
	}
	rc := RiskFromRow(70, "medium", []string{"impossible_travel"})
	if rc == nil || !rc.RequiresMFA {
		t.Fatal("medium risk must set RequiresMFA")
	}
	if rc.UserScore != 70 {
		t.Fatalf("UserScore want 70, got %d", rc.UserScore)
	}
	if len(rc.Signals) != 1 || rc.Signals[0] != "impossible_travel" {
		t.Fatalf("signals must round-trip, got %v", rc.Signals)
	}
	if RiskFromRow(40, "low", []string{"failed_auth_velocity"}).RequiresMFA {
		t.Fatal("low risk must NOT force MFA")
	}
}
