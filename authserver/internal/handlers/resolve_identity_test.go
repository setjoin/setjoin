package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/federation"
)

// randSuffix returns a short random hex string for collision-free seed data.
func randSuffix() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// splitDomain returns the domain part of an address.
func splitDomain(addr string) string {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return "local"
}

// ARCH-004 Half A — resolve_identity seam, SP-mode federated-auth matching.
//
// The bug: in SP mode (external IdP → setjoin) the inbound assertion subject was
// matched to a local person by PRIMARY email only. An external IdP commonly
// asserts a UPN or an alias on a sister domain, so setjoin failed to find the
// existing person and JIT-provisioned a DUPLICATE (or failed login). These tests
// drive the real resolveUserByAddress seam (and lookupOrJITUser) against a live
// DB to prove the union over users.email ∪ aliases.email ∪ users.ad_upn resolves
// the one person by ANY of their addresses, and JIT-provisions only a genuinely
// new subject.

// noMappings is a GroupMappingProvider that returns no mappings, so
// lookupOrJITUser exercises only the resolve/JIT path (no group side effects).
type noMappings struct{ providerKey string }

func (noMappings) GetGroupMappings() []federation.GroupMapping { return nil }
func (m noMappings) SSOProviderKey() string {
	if m.providerKey == "" {
		panic("noMappings requires a test-unique protocol provider key")
	}
	return m.providerKey
}

var _ federation.GroupMappingProvider = noMappings{}

func newNoMappings(kind string) noMappings {
	return noMappings{providerKey: kind + ":test-" + randSuffix()}
}

// seededPerson is one person with a full address set: a primary users.email, an
// ad_upn on a different domain, and an alias on a sister domain — the exact shape
// an external IdP can assert any of.
type seededPerson struct {
	userID          int64
	primaryDomainID int64
	sisterDomainID  int64
	primaryEmail    string // users.email
	upn             string // users.ad_upn (UPN form, distinct from primary SMTP)
	sisterAlias     string // aliases.email on a sister domain
}

// countUsers limits duplicate-JIT assertions to the unique domains owned by
// this fixture. Go runs packages in parallel, so counting the entire users
// table makes an unrelated package's cleanup look like this test deleted a
// user. Any duplicate created from one of this person's asserted addresses is
// necessarily in one of these two domains and remains visible here.
func (p seededPerson) countUsers(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE domain_id IN ($1, $2)`,
		p.primaryDomainID, p.sisterDomainID,
	).Scan(&n); err != nil {
		t.Fatalf("count fixture-domain users: %v", err)
	}
	return n
}

// seedAddressAwarePerson creates the domains, person, primary mailbox, and
// sister-domain alias used by the resolution tests, and registers cleanup.
func seedAddressAwarePerson(t *testing.T, pool *pgxpool.Pool) seededPerson {
	t.Helper()
	ctx := context.Background()

	// A unique local primary domain and a unique sister domain (a second AD
	// domain/forest of the same org). Both must be local for the alias FK.
	uniq := randSuffix()
	primaryDom := "primary-" + uniq + ".local"
	sisterDom := "sister-" + uniq + ".local"

	var primaryDomID, sisterDomID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, primaryDom,
	).Scan(&primaryDomID); err != nil {
		t.Skipf("could not seed primary domain (schema not loaded?): %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, sisterDom,
	).Scan(&sisterDomID); err != nil {
		t.Fatalf("seed sister domain: %v", err)
	}

	p := seededPerson{
		primaryDomainID: primaryDomID,
		sisterDomainID:  sisterDomID,
		primaryEmail:    "alice@" + primaryDom,
		// UPN deliberately differs from the primary SMTP address (the common
		// Azure AD / ADFS case the bug was about).
		upn:         "alice.smith@" + sisterDom,
		sisterAlias: "a.smith@" + sisterDom,
	}

	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, first_name, last_name,
		                    domain_id, ad_upn, sync_source, enabled)
		 VALUES ('alice', $1, 'Alice Smith', 'Alice', 'Smith', $2, $3, 'ad', TRUE)
		 RETURNING id`,
		p.primaryEmail, primaryDomID, p.upn,
	).Scan(&p.userID); err != nil {
		t.Fatalf("seed person: %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, email, display_name, domain_id, is_primary)
		 VALUES ($1, $2, 'Alice Smith', $3, TRUE)
		 RETURNING id`,
		p.userID, p.primaryEmail, primaryDomID,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("seed primary mailbox: %v", err)
	}

	// proxyAddress on a sister domain → aliases row (what AD sync writes).
	if _, err := pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id) VALUES ($1, $2, $3)`,
		mailboxID, p.sisterAlias, sisterDomID,
	); err != nil {
		t.Fatalf("seed sister-domain alias: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM aliases WHERE mailbox_id = $1`, mailboxID)
		pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id = $1`, p.userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, p.userID)
		pool.Exec(ctx, `DELETE FROM domains WHERE id IN ($1, $2)`, primaryDomID, sisterDomID)
	})

	return p
}

// TestResolveUserByAddress_FullAddressSet proves the resolve_identity seam
// resolves the SAME person by primary email, by UPN, and by a sister-domain
// alias — and case-insensitively — and that an unknown address does not resolve.
func TestResolveUserByAddress_FullAddressSet(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	p := seedAddressAwarePerson(t, pool)

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	cases := []struct {
		name    string
		address string
	}{
		{"primary email (no regression)", p.primaryEmail},
		{"primary email upper-cased", strings.ToUpper(p.primaryEmail)},
		{"UPN (Azure AD / ADFS case)", p.upn},
		{"UPN upper-cased", strings.ToUpper(p.upn)},
		{"sister-domain alias", p.sisterAlias},
		{"sister-domain alias upper-cased", strings.ToUpper(p.sisterAlias)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := h.resolveUserByAddress(ctx, tc.address)
			if err != nil {
				t.Fatalf("resolveUserByAddress(%q) error: %v", tc.address, err)
			}
			if got.ID != p.userID {
				t.Fatalf("resolveUserByAddress(%q) = user %d, want the existing person %d (duplicate/miss)",
					tc.address, got.ID, p.userID)
			}
			// The canonical identity is returned regardless of which address matched.
			if got.Email != p.primaryEmail {
				t.Fatalf("resolveUserByAddress(%q) returned email %q, want canonical primary %q",
					tc.address, got.Email, p.primaryEmail)
			}
		})
	}

	t.Run("genuinely-unknown address does not resolve", func(t *testing.T) {
		if _, err := h.resolveUserByAddress(ctx, "nobody-"+randSuffix()+"@nowhere.invalid"); err == nil {
			t.Fatal("expected an error for an unknown address (no row), got nil — would mask a real miss")
		}
	})
}

// TestLookupOrJITUser_NoDuplicateForUPNorAlias proves that UPN and alias
// candidates neither authenticate an existing person nor JIT-provision a
// duplicate, while a genuinely unknown immutable subject provisions once.
func TestLookupOrJITUser_NoDuplicateForUPNorAlias(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	p := seedAddressAwarePerson(t, pool)

	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), JITEnabled: true,
	})

	idpEntityID := "https://idp.example.com/" + randSuffix()
	mapper := newNoMappings("saml")

	// driveSAML runs a SAML SP-mode assertion through the full lookupOrJITUser
	// path with the given subject as both the email claim and NameID.
	driveSAML := func(subject string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/auth/saml/idp/acs", nil)
		rr := httptest.NewRecorder()
		h.lookupOrJITUser(rr, req, subject, "", "", subject, idpEntityID,
			nil, true, mapper)
		return rr
	}

	t.Run("UPN assertion requires explicit linking and creates no duplicate", func(t *testing.T) {
		before := p.countUsers(t, ctx, pool)
		rr := driveSAML(p.upn)
		if rr.Code != http.StatusConflict {
			t.Fatalf("UPN candidate status=%d want 409: %s",
				rr.Code, rr.Body.String())
		}
		if after := p.countUsers(t, ctx, pool); after != before {
			t.Fatalf("UPN assertion changed user count %d -> %d: JIT created a DUPLICATE", before, after)
		}
		var linked int64
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE saml_name_id = $1`, p.upn,
		).Scan(&linked); err != nil {
			t.Fatalf("count saml-linked: %v", err)
		}
		if linked != 0 {
			t.Fatalf("soft UPN evidence linked %d users, want 0", linked)
		}
	})

	t.Run("sister-domain alias requires explicit linking", func(t *testing.T) {
		before := p.countUsers(t, ctx, pool)
		rr := driveSAML(p.sisterAlias)
		if rr.Code != http.StatusConflict {
			t.Fatalf("alias candidate status=%d want 409: %s",
				rr.Code, rr.Body.String())
		}
		if after := p.countUsers(t, ctx, pool); after != before {
			t.Fatalf("alias assertion changed user count %d -> %d: JIT created a DUPLICATE", before, after)
		}
	})

	t.Run("genuinely-unknown subject JIT-provisions exactly one user", func(t *testing.T) {
		newSubject := "newcomer-" + randSuffix() + "@" + splitDomain(p.primaryEmail)
		t.Cleanup(func() {
			pool.Exec(ctx, `DELETE FROM mailboxes WHERE user_id IN (SELECT id FROM users WHERE email = $1)`, newSubject)
			pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, newSubject)
		})
		before := p.countUsers(t, ctx, pool)
		rr := driveSAML(newSubject)
		if rr.Code != http.StatusOK {
			t.Fatalf("unknown subject JIT status=%d want 200: %s",
				rr.Code, rr.Body.String())
		}
		after := p.countUsers(t, ctx, pool)
		if after != before+1 {
			t.Fatalf("unknown subject changed user count %d -> %d, want exactly +1", before, after)
		}
		var n int64
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, newSubject).Scan(&n); err != nil {
			t.Fatalf("count provisioned: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected exactly 1 JIT-provisioned user for the new subject, got %d", n)
		}
	})
}
