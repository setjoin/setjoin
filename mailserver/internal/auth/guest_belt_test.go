// guest_belt_test.go — Guest Accounts P13 belt semantics (codex C-14):
// a satellite hit forces guest REGARDLESS of the token claim; no-row is not
// an error (member proceeds as claimed, but a guest-claiming token with no
// satellite row is DENIED — fail closed, never fail open); a lookup error
// DENIES (ErrGuestLookupUnavailable — 503 at the middleware), never
// defaults to member. Pool-nil (NewChainWithJWT test seam) keeps claim-only
// enforcement: a guest claim stays guest.
package auth

import (
	"testing"

	"setjoin.com/shared/jwtutil"
)

func TestGuestBelt_PoolNilKeepsClaim(t *testing.T) {
	c := &Chain{} // no guest pool wired
	claims := &Claims{UserID: 9, AccountType: jwtutil.AccountTypeGuest}
	if err := c.applyGuestBelt(t.Context(), claims); err != nil {
		t.Fatalf("pool-nil belt must not error for claim-only enforcement: %v", err)
	}
	if !claims.IsGuest() {
		t.Fatal("belt cleared a guest claim — the belt may only ever ESCALATE to guest")
	}
}

func TestGuestBelt_PoolNilMemberUnaffected(t *testing.T) {
	c := &Chain{}
	claims := &Claims{UserID: 9}
	if err := c.applyGuestBelt(t.Context(), claims); err != nil {
		t.Fatalf("member with no pool: %v", err)
	}
	if claims.IsGuest() {
		t.Fatal("member claim mutated with no satellite evidence")
	}
}
