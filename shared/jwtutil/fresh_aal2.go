package jwtutil

import (
	"errors"
	"sort"
	"time"
)

// FreshAAL2Policy makes the freshness and extension bounds explicit at every
// sensitive consumer. MaxDistinctAMR bounds both known and extension AMR values;
// unknown values remain in the canonical evidence but never count as factors.
type FreshAAL2Policy struct {
	MaxAge         time.Duration
	MaxFutureSkew  time.Duration
	MaxDistinctAMR int
}

const (
	CurrentFreshAAL2MaxAge         = 5 * time.Minute
	CurrentFreshAAL2MaxFutureSkew  = 30 * time.Second
	CurrentFreshAAL2MaxDistinctAMR = 16
)

// CurrentFreshAAL2Policy returns the repository-wide security recipe for
// sensitive operation bindings. Callers still pass the policy explicitly to
// VerifyFreshAAL2; centralizing only the current defaults prevents upgrade,
// identity-transition, and recovery consumers from silently drifting.
func CurrentFreshAAL2Policy() FreshAAL2Policy {
	return FreshAAL2Policy{
		MaxAge:         CurrentFreshAAL2MaxAge,
		MaxFutureSkew:  CurrentFreshAAL2MaxFutureSkew,
		MaxDistinctAMR: CurrentFreshAAL2MaxDistinctAMR,
	}
}

// FreshAAL2Evidence is the normalized, security-checked subset callers may bind
// into their operation-specific challenge digests.
type FreshAAL2Evidence struct {
	UserID   int64
	JTI      string
	IssuedAt time.Time
	ACR      string
	AMR      []string
}

type FreshAAL2Rejection string

const (
	FreshAAL2InvalidPolicy FreshAAL2Rejection = "invalid_policy"
	FreshAAL2Incomplete    FreshAAL2Rejection = "incomplete_claims"
	FreshAAL2WrongACR      FreshAAL2Rejection = "insufficient_acr"
	FreshAAL2FromFuture    FreshAAL2Rejection = "issued_in_future"
	FreshAAL2Expired       FreshAAL2Rejection = "expired"
	FreshAAL2TooManyAMR    FreshAAL2Rejection = "too_many_amr_values"
	FreshAAL2MissingMFA    FreshAAL2Rejection = "missing_mfa_marker"
	FreshAAL2FewFactors    FreshAAL2Rejection = "insufficient_known_factors"
)

// FreshAAL2Error is deliberately safe to branch on without exposing token
// contents. Sensitive callers should log only Reason, never the rejected claims.
type FreshAAL2Error struct {
	Reason FreshAAL2Rejection
}

func (e *FreshAAL2Error) Error() string { return "fresh AAL2 rejected: " + string(e.Reason) }

func IsFreshAAL2Rejection(err error, reason FreshAAL2Rejection) bool {
	var rejection *FreshAAL2Error
	return errors.As(err, &rejection) && rejection.Reason == reason
}

var freshAAL2KnownFactors = map[string]struct{}{
	AMRPassword:    {},
	AMROTP:         {},
	AMRHardwareKey: {},
	AMRSoftwareKey: {},
}

// VerifyFreshAAL2 validates and canonicalizes the semantic AAL2 recipe shared
// by sensitive operations. Bounded unknown RFC 8176 extensions are tolerated
// for compatibility, preserved in AMR, and never promoted to trusted factors.
func VerifyFreshAAL2(claims *Claims, now time.Time, policy FreshAAL2Policy) (FreshAAL2Evidence, error) {
	reject := func(reason FreshAAL2Rejection) (FreshAAL2Evidence, error) {
		return FreshAAL2Evidence{}, &FreshAAL2Error{Reason: reason}
	}
	if policy.MaxAge <= 0 || policy.MaxFutureSkew < 0 || policy.MaxDistinctAMR <= 0 {
		return reject(FreshAAL2InvalidPolicy)
	}
	if claims == nil || claims.UserID <= 0 || claims.JTI == "" || claims.IssuedAt == nil {
		return reject(FreshAAL2Incomplete)
	}
	if !ACRSatisfies(claims.ACR, ACRAAL2) {
		return reject(FreshAAL2WrongACR)
	}
	issuedAt := claims.IssuedAt.Time
	if now.Before(issuedAt.Add(-policy.MaxFutureSkew)) {
		return reject(FreshAAL2FromFuture)
	}
	if now.Sub(issuedAt) > policy.MaxAge {
		return reject(FreshAAL2Expired)
	}

	seen := make(map[string]struct{}, len(claims.AMR))
	factors := 0
	hasMFA := false
	for _, method := range claims.AMR {
		if method == "" {
			continue
		}
		if _, duplicate := seen[method]; duplicate {
			continue
		}
		seen[method] = struct{}{}
		if len(seen) > policy.MaxDistinctAMR {
			return reject(FreshAAL2TooManyAMR)
		}
		if method == AMRMultiFactor {
			hasMFA = true
		}
		if _, known := freshAAL2KnownFactors[method]; known {
			factors++
		}
	}
	if !hasMFA {
		return reject(FreshAAL2MissingMFA)
	}
	if factors < 2 {
		return reject(FreshAAL2FewFactors)
	}

	amr := make([]string, 0, len(seen))
	for method := range seen {
		amr = append(amr, method)
	}
	sort.Strings(amr)
	return FreshAAL2Evidence{
		UserID: claims.UserID, JTI: claims.JTI, IssuedAt: issuedAt, ACR: claims.ACR, AMR: amr,
	}, nil
}
