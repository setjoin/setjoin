package startup

import (
	"context"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

func TestRunDatabaseRecoveryExecutesReducerBeforeStartup(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	if err := RunDatabaseRecovery(
		context.Background(),
		pgxutil.WorkerPool{Pool: pool},
		testsupport.TestLogger(),
	); err != nil {
		t.Fatalf("RunDatabaseRecovery: %v", err)
	}
}

func TestRunDatabaseRecoveryFailsClosedOnUnavailableWorkerPool(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	err := RunDatabaseRecovery(
		context.Background(),
		pgxutil.WorkerPool{Pool: pool},
		testsupport.TestLogger(),
	)
	if err == nil {
		t.Fatal("RunDatabaseRecovery unexpectedly succeeded with a closed worker pool")
	}
}
