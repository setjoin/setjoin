package threat

import "setjoin.com/shared/jwtutil"

// Risk levels — the deterministic local user-risk bands (compute_user_risk writes
// these to user_risk.level). NOT Entra's ML bands; a coarse local heuristic.
const (
	RiskLevelNone   = "none"
	RiskLevelLow    = "low"
	RiskLevelMedium = "medium"
	RiskLevelHigh   = "high"
)

// RiskFromRow maps a user_risk row into the JWT Risk claim authserver embeds at
// login. A clean user (none/empty) yields nil so the token stays byte-compatible
// (Risk is omitempty). RequiresMFA is set at medium and above — the threshold a
// require_risk_remediation policy enforces. This is the single Go-side mapper so
// the login path and any other consumer can never derive the claim two ways.
func RiskFromRow(score int, level string, signals []string) *jwtutil.RiskClaim {
	if level == "" || level == RiskLevelNone {
		return nil
	}
	return &jwtutil.RiskClaim{
		UserScore:   score,
		Level:       level,
		RequiresMFA: level == RiskLevelMedium || level == RiskLevelHigh,
		Signals:     signals,
	}
}
