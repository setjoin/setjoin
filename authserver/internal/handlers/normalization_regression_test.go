package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestVerifyPassword_MixedCaseLogin_Regression is the bug-#1 regression
// (login case-sensitivity). users.email is stored lower(trim()) and uniqueness
// is users_email_lower_idx UNIQUE on lower(email); the verifyPassword lookup
// used a case-SENSITIVE `WHERE email = $1`, so a user whose stored email is
// `alice@…` could NOT log in by typing `Alice@…` (while password-reset and the
// admin lookup, which use lower(email)=lower($1), found them). This drives the
// REAL verifyPassword against a live DB and proves a mixed-case login now
// succeeds and resolves the one owner row.
func TestVerifyPassword_MixedCaseLogin_Regression(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()

	uniq := randSuffix()
	dom := "pwcase-" + uniq + ".local"
	stored := "alice@" + dom // stored lower-case, as provisioning guarantees
	password := "Sup3r-Secret-" + uniq

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, dom,
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, enabled)
		 VALUES ('alice', $1, 'Alice', $2, $3, TRUE) RETURNING id`,
		stored, domID, string(hash),
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	// The bug: typing the address with different casing than stored.
	mixedCase := "Alice@" + strings.ToUpper(dom)
	got, err := h.verifyPassword(ctx, mixedCase, password, "127.0.0.1")
	if err != nil {
		t.Fatalf("mixed-case login FAILED for an existing user (bug #1 regression): verifyPassword(%q) error: %v", mixedCase, err)
	}
	if got.ID != userID {
		t.Fatalf("mixed-case login resolved user %d, want the one owner %d", got.ID, userID)
	}

	// Exact-case login still works (no regression), and a wrong password is still rejected.
	if _, err := h.verifyPassword(ctx, stored, password, "127.0.0.1"); err != nil {
		t.Fatalf("exact-case login regressed: %v", err)
	}
	if _, err := h.verifyPassword(ctx, mixedCase, "wrong-"+password, "127.0.0.1"); err == nil {
		t.Fatal("wrong password accepted — the fix must only relax CASE, not the password check")
	}
}

// TestLookupOrJITUser_NoDuplicateForDisplayNameOrWhitespace is the bug-#2
// regression (the headline duplicate-JIT-on-normalization). An SP-mode assertion
// subject carrying surrounding WHITESPACE or an RFC-5322 DISPLAY-NAME form
// (`"Alice" <a@x>`) used to match-MISS the existing person (the matcher bound the
// RAW subject to a lower-only predicate) and then JIT-provision a DUPLICATE with
// the cleaned address. Routing resolveUserByAddress through the SAME canonicalizer
// the provision path uses (identity.CanonicalizeAddress) makes the match key equal
// the provision key, so the existing person resolves and NO duplicate is created.
func TestLookupOrJITUser_NoDuplicateForDisplayNameOrWhitespace(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	p := seedAddressAwarePerson(t, pool)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), JITEnabled: true,
	})

	idpEntityID := "https://idp.example.com/" + randSuffix()
	mapper := newNoMappings("saml")

	// driveSAML runs the full lookupOrJITUser path with the given email subject.
	// Address normalization may locate an existing person, but address evidence
	// must never authenticate or create a durable provider link.
	nameID := "nameid-" + randSuffix()
	driveSAML := func(emailSubject string) {
		req := httptest.NewRequest("POST", "/auth/saml/idp/acs", nil)
		rr := httptest.NewRecorder()
		h.lookupOrJITUser(rr, req, emailSubject, "", "", nameID, idpEntityID,
			nil, true, mapper)
		if rr.Code != http.StatusConflict {
			t.Fatalf("lookupOrJITUser(%q) status = %d, want 409: %s",
				emailSubject, rr.Code, rr.Body.String())
		}
	}

	for _, tc := range []struct {
		name    string
		subject string
	}{
		{"surrounding whitespace on the primary", "  " + p.primaryEmail + "  "},
		{"display-name form on the primary", `"Alice Smith" <` + p.primaryEmail + ">"},
		{"display-name form on the UPN", `Alice Smith <` + p.upn + ">"},
		{"mixed-case + whitespace", "  " + strings.ToUpper(p.primaryEmail) + " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := p.countUsers(t, ctx, pool)
			driveSAML(tc.subject)
			if after := p.countUsers(t, ctx, pool); after != before {
				t.Fatalf("subject %q changed user count %d -> %d: JIT created a DUPLICATE (bug #2 regression)",
					tc.subject, before, after)
			}
		})
	}
}
