package cron

import "testing"

// riskCronEnabled is the pure gate: the job is a no-op when the toggle is off.
func TestRiskCronGate(t *testing.T) {
	if riskCronEnabled(false) {
		t.Fatal("feature.user_risk OFF must disable the risk cron")
	}
	if !riskCronEnabled(true) {
		t.Fatal("feature.user_risk ON must enable the risk cron")
	}
}
