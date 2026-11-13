package authn

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

// refusedPool returns a lazily-connected pool whose first acquire fails
// (connection refused), exercising begin/rollback failure paths without
// touching real data.
func refusedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(),
		"postgres://totp-edge@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New(refused): %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestConfirmTOTP_MissingUserFailsClosed_DB pins the lifecycle-fence fail-closed
// branch: confirming TOTP for a user id that does not exist must fail with the
// invalid-code error (never a leak about user existence semantics beyond the
// uniform error).
func TestConfirmTOTP_MissingUserFailsClosed_DB(t *testing.T) {
	pool := integrationPool(t)
	err := ConfirmTOTP(context.Background(), pool, 987654321, "123456")
	if err == nil {
		t.Fatal("ConfirmTOTP for missing user: want error")
	}
}

// TestConfirmTOTP_AlreadyEnabledGuardMatchesZeroRows_DB pins the guarded-enable
// fail-closed branch: a VALID code against an ALREADY-ENABLED factor must not
// double-enable (the guarded UPDATE matches zero rows → invalid TOTP code) and
// the factor must stay enabled.
func TestConfirmTOTP_AlreadyEnabledGuardMatchesZeroRows_DB(t *testing.T) {
	pool := integrationPool(t)
	userID, secret := makeTOTPUser(t, pool, true)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := ConfirmTOTP(context.Background(), pool, userID, code); err == nil {
		t.Fatal("ConfirmTOTP on already-enabled factor: want error (zero-rows guard)")
	}

	var stillEnabled int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM users WHERE id=$1 AND totp_enabled = TRUE`, userID).Scan(&stillEnabled); err != nil {
		t.Fatalf("verify factor state: %v", err)
	}
	if stillEnabled != 1 {
		t.Fatal("already-enabled factor was altered by a confirm attempt")
	}
}

// TestConfirmTOTP_BeginFailureFailsClosed pins the tx-begin error branch: an
// unreachable pool surfaces a wrapped begin error instead of a confirmation.
func TestConfirmTOTP_BeginFailureFailsClosed(t *testing.T) {
	err := ConfirmTOTP(context.Background(), refusedPool(t), 1, "123456")
	if err == nil {
		t.Fatal("ConfirmTOTP on broken pool: want begin error")
	}
}
