package authn

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestVerifyBackupCode_ConcurrentSameCode_DB is the integration proof of the
// single-use TOCTOU fix: N concurrent verifies of the SAME code must yield exactly
// ONE success (the atomic array_remove claim). Against the old read-modify-write
// both racers matched the SELECTed array and both returned true — a single-use
// backup code consumed twice (MFA second-factor replay).
func TestVerifyBackupCode_ConcurrentSameCode_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeTOTPUser(t, pool, false)

	codes, err := GenerateBackupCodes(ctx, pool, id)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}

	const racers = 8
	var successes int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ok, verr := VerifyBackupCode(ctx, pool, id, codes[0]); verr == nil && ok {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt64(&successes); got != 1 {
		t.Errorf("concurrent same-code verifies succeeded %d times, want exactly 1 (single-use replay)", got)
	}
	if got := backupCodeCount(t, pool, id); got != 9 {
		t.Errorf("after consuming one code, %d remain, want 9", got)
	}
}

// TestVerifyBackupCode_ConcurrentDifferentCodes_DB proves the no-resurrection fix:
// two concurrent verifies of DIFFERENT valid codes must BOTH succeed and BOTH stay
// consumed. The old last-write-wins write-back wrote back each racer's
// original-array-minus-its-own-index, RESURRECTING whichever code the other had
// just removed (8 expected, 9 observed, and the resurrected code reusable).
func TestVerifyBackupCode_ConcurrentDifferentCodes_DB(t *testing.T) {
	pool := integrationPool(t)
	ctx := context.Background()
	id, _ := makeTOTPUser(t, pool, false)

	codes, err := GenerateBackupCodes(ctx, pool, id)
	if err != nil {
		t.Fatalf("GenerateBackupCodes: %v", err)
	}

	var ok1, ok2 bool
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; ok1, _ = VerifyBackupCode(ctx, pool, id, codes[1]) }()
	go func() { defer wg.Done(); <-start; ok2, _ = VerifyBackupCode(ctx, pool, id, codes[2]) }()
	close(start)
	wg.Wait()

	if !ok1 || !ok2 {
		t.Fatalf("both distinct valid codes must verify, got ok1=%v ok2=%v", ok1, ok2)
	}
	if got := backupCodeCount(t, pool, id); got != 8 {
		t.Errorf("after consuming two distinct codes, %d remain, want 8 (resurrection)", got)
	}
	if ok, _ := VerifyBackupCode(ctx, pool, id, codes[1]); ok {
		t.Error("a consumed code must not verify again (codes[1] resurrected)")
	}
	if ok, _ := VerifyBackupCode(ctx, pool, id, codes[2]); ok {
		t.Error("a consumed code must not verify again (codes[2] resurrected)")
	}
}

func backupCodeCount(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()
	var hashes []string
	if err := pool.QueryRow(context.Background(),
		`SELECT totp_backup_codes_enc FROM users WHERE id = $1`, userID).Scan(&hashes); err != nil {
		t.Fatalf("read backup codes: %v", err)
	}
	return len(hashes)
}
