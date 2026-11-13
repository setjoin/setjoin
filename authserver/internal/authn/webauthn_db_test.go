package authn

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// TestBeginLogin_MixedCase_ResolvesOwner is the live-bug regression. The handler
// feeds BeginLogin a RAW r.URL.Query().Get("email"), so before the fix a
// mixed-case passkey user (Alice@Corp.com) match-missed the lower(email)-unique
// row and fell into the decoy path (userID 0) — unable to ever start a real
// assertion. After the fix BeginLogin canonicalizes the email, so a mixed-case
// probe for a user WITH an active credential returns the REAL owner userID, while
// an unknown email still returns the decoy (uid 0) — enumeration hardening intact.
//
// DB-gated: skips cleanly when TEST_DB_DSN is unset (DB-less CI stays green);
// exercised under load-test-schema.sh. Against the PRE-FIX code the mixed-case
// assertion below FAILS (returns uid 0, the decoy).
func TestBeginLogin_MixedCase_ResolvesOwner(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()

	p, err := NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPasskeyProvider: %v", err)
	}

	rb := make([]byte, 6)
	if _, err := rand.Read(rb); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(rb)
	dom := "pkcase-" + uniq + ".local"
	stored := "alice@" + dom // stored lower-case, as provisioning guarantees

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, dom,
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, enabled)
		 VALUES ($1, $2, 'Alice', $3, TRUE) RETURNING id`,
		"alice-"+uniq, stored, domID,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Give the user one active passkey credential so BeginLogin reaches the REAL
	// (non-decoy) path. public_key bytes need only be non-null for the seed.
	credID := []byte("cred-" + uniq + "-0123456789abcdef")
	if _, err := pool.Exec(ctx,
		`INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count)
		 VALUES ($1, $2, $3, 'none', 0)`,
		credID, userID, []byte("pk-"+uniq),
	); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})

	// The bug: typing the address with different casing than stored.
	mixedCase := "Alice@" + strings.ToUpper(dom)
	gotUID, optJSON, _, err := p.BeginLogin(ctx, mixedCase)
	if err != nil {
		t.Fatalf("BeginLogin(%q) error: %v", mixedCase, err)
	}
	if gotUID != userID {
		t.Fatalf("mixed-case BeginLogin returned uid %d (decoy=0); want the real owner %d — the live case-fold bug", gotUID, userID)
	}
	if len(optJSON) == 0 {
		t.Fatal("BeginLogin returned empty assertion options")
	}

	// Exact-case still resolves the owner (no regression).
	if exactUID, _, _, err := p.BeginLogin(ctx, stored); err != nil || exactUID != userID {
		t.Fatalf("exact-case BeginLogin regressed: uid=%d err=%v", exactUID, err)
	}

	// An unknown email still returns the decoy (uid 0) — enumeration hardening
	// preserved.
	if decoyUID, decoyOpt, _, err := p.BeginLogin(ctx, "nobody-"+uniq+"@"+dom); err != nil || decoyUID != 0 || len(decoyOpt) == 0 {
		t.Fatalf("unknown email did not yield a uid-0 decoy assertion: uid=%d err=%v optLen=%d", decoyUID, err, len(decoyOpt))
	}
}

// TestPersistCredential_CrossUserCollision is the passkey-takeover regression.
// passkey_credentials PK is (id) alone and the id is authenticator-chosen, so an
// attacker can register a credential whose id collides with a VICTIM's. Before
// the fix, persistCredential's unscoped ON CONFLICT (id) DO UPDATE overwrote the
// victim's public_key (user_id stayed victim), letting the attacker sign
// assertions as the victim. After the fix the cross-user conflict is a no-op that
// surfaces an error, and the victim's public_key is untouched.
//
// DB-gated: skips when TEST_DB_DSN is unset. Against the PRE-FIX code the
// public_key assertion below FAILS (the row gets clobbered) and no error is
// returned.
func TestPersistCredential_CrossUserCollision(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()

	p, err := NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPasskeyProvider: %v", err)
	}

	rb := make([]byte, 6)
	if _, err := rand.Read(rb); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(rb)
	dom := "pkcollide-" + uniq + ".local"

	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, dom,
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	mkUser := func(local string) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, email, display_name, domain_id, enabled)
			 VALUES ($1, $2, $1, $3, TRUE) RETURNING id`,
			local+"-"+uniq, local+"-"+uniq+"@"+dom, domID,
		).Scan(&id); err != nil {
			t.Fatalf("seed user %s: %v", local, err)
		}
		return id
	}
	victimID := mkUser("victim")
	attackerID := mkUser("attacker")
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM passkey_credentials WHERE user_id = ANY($1)`, []int64{victimID, attackerID})
		pool.Exec(ctx, `DELETE FROM users WHERE id = ANY($1)`, []int64{victimID, attackerID})
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})

	// Victim's real credential, established legitimately.
	credID := []byte("collide-cred-" + uniq)
	victimPK := []byte("victim-public-key-" + uniq)
	if err := p.persistCredential(ctx, victimID, &webauthn.Credential{
		ID: credID, PublicKey: victimPK, AttestationType: "none",
	}); err != nil {
		t.Fatalf("seed victim credential: %v", err)
	}

	// Attacker registers a credential with the SAME id but their own public key.
	attackerPK := []byte("attacker-public-key-" + uniq)
	err = p.persistCredential(ctx, attackerID, &webauthn.Credential{
		ID: credID, PublicKey: attackerPK, AttestationType: "none",
	})
	if err == nil {
		t.Fatal("cross-user credential-id collision was accepted; want an error (takeover surface)")
	}

	// The victim's row must be untouched: same owner, same public key.
	var gotUser int64
	var gotPK []byte
	if err := pool.QueryRow(ctx,
		`SELECT user_id, public_key FROM passkey_credentials WHERE id = $1`, credID,
	).Scan(&gotUser, &gotPK); err != nil {
		t.Fatalf("re-read credential: %v", err)
	}
	if gotUser != victimID {
		t.Fatalf("credential owner changed to %d; want victim %d", gotUser, victimID)
	}
	if !bytes.Equal(gotPK, victimPK) {
		t.Fatalf("victim public_key was clobbered: got %q want %q — passkey takeover", gotPK, victimPK)
	}

	// Same-user re-registration (legitimate) still works: updates the public key.
	rotatedPK := []byte("victim-rotated-key-" + uniq)
	if err := p.persistCredential(ctx, victimID, &webauthn.Credential{
		ID: credID, PublicKey: rotatedPK, AttestationType: "none",
	}); err != nil {
		t.Fatalf("legitimate same-user re-registration failed: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT public_key FROM passkey_credentials WHERE id = $1`, credID,
	).Scan(&gotPK); err != nil {
		t.Fatalf("re-read after rotate: %v", err)
	}
	if !bytes.Equal(gotPK, rotatedPK) {
		t.Fatalf("same-user re-registration did not update public_key: got %q want %q", gotPK, rotatedPK)
	}
}

// TestUserHandleInitializerPreservesCommittedWinner is the r3 defect 7
// reproduction: concurrent handle initializers (a registration begin and a
// login begin racing on a NULL handle) must all observe and return the SAME
// persisted handle — the committed winner. The historical initializer wrote
// its candidate UNCONDITIONALLY (`UPDATE users SET webauthn_user_handle = $1
// WHERE id = $2`), so a login initializer that read NULL before a
// registration initializer committed overwrote that winner: the credential
// registered under the first handle could never assert against the second.
func TestUserHandleInitializerPreservesCommittedWinner(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()

	p, err := NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("NewPasskeyProvider: %v", err)
	}

	rb := make([]byte, 6)
	if _, err := rand.Read(rb); err != nil {
		t.Fatalf("rand: %v", err)
	}
	uniq := hex.EncodeToString(rb)
	var domID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, "pkhandle-"+uniq+".local",
	).Scan(&domID); err != nil {
		t.Skipf("could not seed domain (schema not loaded?): %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, enabled)
		 VALUES ($1, $2, 'Handle Race', $3, TRUE) RETURNING id`,
		"handlerace-"+uniq, "handlerace-"+uniq+"@pkhandle-"+uniq+".local", domID,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM domains WHERE id = $1`, domID)
	})

	// Eight concurrent initializers race the NULL handle. Every one of them
	// must come back with the SAME handle, and the persisted handle must be
	// that one value — preserve-and-return, never a last-writer overwrite.
	const racers = 8
	handles := make(chan []byte, racers)
	errs := make(chan error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := p.loadUser(ctx, userID)
			if err != nil {
				errs <- err
				return
			}
			handles <- u.WebAuthnID()
		}()
	}
	wg.Wait()
	close(handles)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent loadUser: %v", err)
	}

	var first []byte
	for h := range handles {
		if len(h) != 32 {
			t.Fatalf("initializer returned a %d-byte handle, want a generated 32-byte one (the numeric-id fallback means no handle was persisted)", len(h))
		}
		if first == nil {
			first = h
			continue
		}
		if !bytes.Equal(h, first) {
			t.Fatalf("racing initializers disagreed: %x vs %x — a later initializer overwrote the committed winner", first, h)
		}
	}

	var persisted []byte
	if err := pool.QueryRow(ctx,
		`SELECT webauthn_user_handle FROM users WHERE id = $1`, userID,
	).Scan(&persisted); err != nil {
		t.Fatalf("read persisted handle: %v", err)
	}
	if !bytes.Equal(persisted, first) {
		t.Fatalf("persisted handle %x != the initializers' handle %x — the winner did not stick", persisted, first)
	}

	// A settled handle is never rewritten: a further loadUser returns exactly
	// the persisted value.
	u, err := p.loadUser(ctx, userID)
	if err != nil {
		t.Fatalf("settled loadUser: %v", err)
	}
	if !bytes.Equal(u.WebAuthnID(), persisted) {
		t.Fatalf("settled loadUser returned %x, want the persisted %x", u.WebAuthnID(), persisted)
	}
}
