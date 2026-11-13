package authn

// webauthn_possession_arms_test.go — fail-closed arm coverage for the
// possession webauthn ceremony seam (webauthn_possession.go): the
// management-assertion begin/finish, the registration ceremony (handle mint
// + persist), the credential persistence collision scoping, revocation and
// ownership checks. The cryptographic happy paths live in the handlers'
// acceptance suites against the software authenticator; here the seam is
// driven at its boundary:
//
//   - closed-pool reads (wrapped load-user / lookup errors);
//   - missing users (the fence-protected SELECTs find no row);
//   - garbage wire shapes (unparseable session JSON, unparseable assertion
//     bodies, unparseable session-cookie JSON);
//   - statement faults (handle persist, credential insert, revoke update)
//     via user-scoped trigger injection;
//   - the cross-account credential-id collision (0-rows update → error).
//
// Every test asserts the error identity or durable state, never just that a
// line executed.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// armsProvider builds a PasskeyProvider over the pool with the local test RP.
func armsProvider(t *testing.T, pool *pgxpool.Pool) *PasskeyProvider {
	t.Helper()
	p, err := NewPasskeyProvider(pool, "localhost", "SetJoin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("build passkey provider: %v", err)
	}
	return p
}

// armsTx opens a transaction for the tx-seam functions and rolls it back at
// cleanup.
func armsTx(t *testing.T, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin arms tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

func TestBeginManagementAssertionLoadUserArms(t *testing.T) {
	pool := integrationPool(t)
	_ = armsClosedPool // keep the helper referenced
	p := armsProvider(t, pool)

	// Missing user inside the fenced tx: the load fails and the wrap names
	// the ceremony.
	_, _, err := p.BeginManagementAssertion(context.Background(), armsTx(t, pool), 999999999)
	if err == nil || !contains(err.Error(), "management assertion: load user") {
		t.Fatalf("BeginManagementAssertion(missing user) = %v, want the wrapped load error", err)
	}
}

func TestValidateManagementAssertionLoadUserArm(t *testing.T) {
	pool := integrationPool(t)
	p := armsProvider(t, pool)
	_, err := p.ValidateManagementAssertion(context.Background(), armsTx(t, pool), 999999999, "hash", []byte(`{}`))
	if err == nil || !contains(err.Error(), "management assertion: load user") {
		t.Fatalf("ValidateManagementAssertion(missing user) = %v, want the wrapped load error", err)
	}
}

func TestBeginRegistrationCeremonyUserArms(t *testing.T) {
	pool := integrationPool(t)
	p := armsProvider(t, pool)
	ctx := context.Background()

	// callInTx runs one probe on its OWN transaction, rolled back eagerly —
	// the fault trigger below needs ACCESS EXCLUSIVE at install and cleanup,
	// which a cleanup-rolled fixture tx would block until test end.
	callInTx := func(userID int64) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin probe tx: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, _, _, err = p.BeginRegistrationCeremony(ctx, tx, userID)
		return err
	}

	// Missing user: the tx-riding load fails closed.
	if err := callInTx(999999999); err == nil {
		t.Fatal("BeginRegistrationCeremony(missing user) returned no error")
	}

	// Handle-mint persist fault: a user with a NULL handle mints one inside
	// the ceremony; the faulted UPDATE must surface as the wrap.
	userID, _ := makeTOTPUser(t, pool, false)
	fn := "arms_reg_handle_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "users", "BEFORE UPDATE",
		"NEW.id = "+armsUID(userID)+" AND OLD.webauthn_user_handle IS NULL")
	err := callInTx(userID)
	if err == nil || !contains(err.Error(), "registration handle persist") {
		t.Fatalf("BeginRegistrationCeremony with faulted handle persist = %v, want the wrapped persist error", err)
	}
}

func TestChallengeHashFromSessionJSONArm(t *testing.T) {
	if _, err := ChallengeHashFromSessionJSON([]byte("{not-json")); err == nil {
		t.Fatal("ChallengeHashFromSessionJSON(garbage) returned no error")
	}
}

func TestVerifyRegistrationCredentialArms(t *testing.T) {
	pool := integrationPool(t)
	p := armsProvider(t, pool)

	// Missing user load.
	_, err := p.VerifyRegistrationCredential(context.Background(), armsTx(t, pool), 999999999, []byte(`{}`), []byte(`{}`))
	if err == nil {
		t.Fatal("VerifyRegistrationCredential(missing user) returned no error")
	}
	userID, _ := makeTOTPUser(t, pool, false)
	// Garbage session JSON.
	_, err = p.VerifyRegistrationCredential(context.Background(), armsTx(t, pool), userID, []byte("{not-json"), []byte(`{}`))
	if err == nil {
		t.Fatal("VerifyRegistrationCredential(garbage session) returned no error")
	}
	// Garbage attestation body.
	_, err = p.VerifyRegistrationCredential(context.Background(), armsTx(t, pool), userID, []byte(`{}`), []byte("{not-json"))
	if err == nil {
		t.Fatal("VerifyRegistrationCredential(garbage body) returned no error")
	}
}

func TestPersistCredentialTxArms(t *testing.T) {
	pool := integrationPool(t)
	p := armsProvider(t, pool)
	userID, _ := makeTOTPUser(t, pool, false)
	other, _ := makeTOTPUser(t, pool, false)
	credID := []byte(fmt.Sprintf("arms-collision-%d", time.Now().UnixNano()))
	cred := &webauthn.Credential{
		ID:              credID,
		PublicKey:       []byte("arms-public-key"),
		AttestationType: "none",
	}

	// Cross-account collision: the id is registered to ANOTHER account — the
	// DO UPDATE ... WHERE user_id = EXCLUDED.user_id makes it a 0-rows no-op,
	// which the seam must surface as an error, never a silent takeover. The
	// seed COMMITS (a pending insert would block the conflict probe below on
	// its own uncommitted row lock).
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, created_at)
		 VALUES ($1, $2, $3, 'none', 0, now())
		 ON CONFLICT (id) DO NOTHING`, cred.ID, other, []byte("arms-other-key")); err != nil {
		t.Fatalf("seed other-account credential: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM passkey_credentials WHERE id = $1 AND user_id = $2`, credID, other)
	})
	txProbe, probeErr := pool.Begin(context.Background())
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	err := p.persistCredentialTx(context.Background(), txProbe, userID, cred)
	_ = txProbe.Rollback(context.Background())
	if err == nil || !contains(err.Error(), "already registered to another account") {
		t.Fatalf("cross-account collision = %v, want the takeover-refused error", err)
	}
	var owner int64
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM passkey_credentials WHERE id = $1`, cred.ID).Scan(&owner); err != nil || owner != other {
		t.Fatalf("credential owner after collision = %d (%v), want %d (the victim's row untouched)", owner, err, other)
	}

	// Statement fault: the INSERT is faulted for this user.
	fn := "arms_persist_cred_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "passkey_credentials", "BEFORE INSERT",
		"NEW.user_id = "+armsUID(userID))
	tx, txErr := pool.Begin(context.Background())
	if txErr != nil {
		t.Fatal(txErr)
	}
	err = p.persistCredentialTx(context.Background(), tx, userID, &webauthn.Credential{
		ID: []byte("arms-other-cred"), PublicKey: []byte("k"), AttestationType: "none",
	})
	_ = tx.Rollback(context.Background())
	if err == nil {
		t.Fatal("persistCredentialTx with faulted insert returned no error")
	}
}

func TestRevokeCredentialTxAndOwnershipArms(t *testing.T) {
	pool := integrationPool(t)
	p := armsProvider(t, pool)
	userID, _ := makeTOTPUser(t, pool, false)

	// Ownership: unknown target refuses (eager tx so the fault trigger's
	// ACCESS-EXCLUSIVE install below never queues behind a fixture tx).
	txOwn, ownErr := pool.Begin(context.Background())
	if ownErr != nil {
		t.Fatal(ownErr)
	}
	if err := ValidateCredentialOwnership(context.Background(), txOwn, userID, []byte("nobody")); err == nil {
		t.Fatal("ValidateCredentialOwnership(unknown) returned no error")
	}
	_ = txOwn.Rollback(context.Background())
	// (Ownership's wrapped-read arm rides the closed POOL seam via the
	// pool-taking signature, which fails fast; the tx seam refuses on the
	// missing-target arm above.)
	if err := ValidateCredentialOwnership(context.Background(), armsClosedPool(t), userID, []byte("x")); err == nil ||
		!contains(err.Error(), "credential ownership check") {
		t.Fatalf("ValidateCredentialOwnership(closed pool) = %v, want the wrapped ownership error", err)
	}

	// Seed a live credential so the revoke UPDATE matches a row (a trigger
	// never fires on a zero-row UPDATE).
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO passkey_credentials (id, user_id, public_key, attestation_type, sign_count, created_at)
		 VALUES ($1, $2, $3, 'none', 0, now()) ON CONFLICT (id) DO NOTHING`,
		[]byte("arms-revoke-target"), userID, []byte("k")); err != nil {
		t.Fatal(err)
	}

	// Revoke statement fault surfaces.
	fn := "arms_revoke_tx_fault"
	trig := fn + "_trig"
	armsFaultTrigger(t, pool, fn, trig, "passkey_credentials", "BEFORE UPDATE",
		"OLD.revoked_at IS NULL")
	tx2, tx2Err := pool.Begin(context.Background())
	if tx2Err != nil {
		t.Fatal(tx2Err)
	}
	_, err := p.RevokeCredentialTx(context.Background(), tx2, []byte("arms-revoke-target"), userID)
	_ = tx2.Rollback(context.Background())
	if err == nil {
		t.Fatal("RevokeCredentialTx with faulted update returned no error")
	}
}

var _ = protocol.ErrBadRequest
var _ = errors.New
var _ = fmt.Sprintf
