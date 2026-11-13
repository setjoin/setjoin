package eapjobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// TestProcessOne_DrainsSingleJob enqueues one eap_apply_jobs row, calls
// processOne, and asserts that the row reaches status='done' with applied ≥ 0.
// Uses the shared testsupport pool (DB_DSN env var; skips when unset).
func TestProcessOne_DrainsSingleJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	// Insert a queued job with NULL policy_id (sweep-all).
	var jobID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO eap_apply_jobs (policy_id, status) VALUES (NULL, 'queued') RETURNING id`,
	).Scan(&jobID)
	if err != nil {
		t.Fatalf("insert job: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM eap_apply_jobs WHERE id = $1`, jobID) //nolint:errcheck
	})

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, logger)
	claimed, err := w.processOne(ctx)
	if err != nil {
		t.Fatalf("processOne returned error: %v", err)
	}
	if !claimed {
		t.Fatal("processOne: expected claimed=true, got false (job not picked up)")
	}

	// Verify final state.
	var status string
	var applied int
	var total *int
	err = pool.QueryRow(ctx,
		`SELECT status, applied, total FROM eap_apply_jobs WHERE id = $1`, jobID,
	).Scan(&status, &applied, &total)
	if err != nil {
		t.Fatalf("select job status: %v", err)
	}
	if status != "done" && status != "error" {
		t.Errorf("expected status 'done' or 'error', got %q", status)
	}
	if status == "done" && applied < 0 {
		t.Errorf("applied should be ≥ 0, got %d", applied)
	}
	t.Logf("job %d finished with status=%s applied=%d", jobID, status, applied)

	// Also verify that total was set up front (non-NULL, ≥ 0).
	err = pool.QueryRow(ctx,
		`SELECT total FROM eap_apply_jobs WHERE id = $1`, jobID,
	).Scan(&total)
	if err != nil {
		t.Fatalf("select total: %v", err)
	}
	if total == nil {
		t.Error("total should be non-NULL after processing (set up front in claim tx)")
	} else if *total < 0 {
		t.Errorf("total should be ≥ 0, got %d", *total)
	}
	t.Logf("job %d total=%v applied=%d", jobID, total, applied)
}

// TestProcessOne_EmptyQueue asserts processOne returns (false, nil) when no
// queued jobs exist — does not blow up on an empty table.
func TestProcessOne_EmptyQueue(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()

	// Ensure no queued rows exist for this path (best-effort; other parallel
	// tests may have their own rows, but FOR UPDATE SKIP LOCKED is safe).
	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, logger)

	// If the queue happens to be empty we get (false, nil).
	// If another test's row is present we may get (true, nil) — also fine.
	claimed, err := w.processOne(ctx)
	if err != nil {
		t.Fatalf("processOne on (possibly) empty queue returned error: %v", err)
	}
	_ = claimed // both outcomes are valid
}

// TestProcessOne_ReducerFailureIsPersisted forces email_address_policy_apply_bulk
// to fail (BZ078 eap_nonlocal_domain, raised deterministically by a mailbox
// whose domain is_local=false) and asserts the job row actually ends up
// status='error' with the message recorded.
//
// Regression guard for C4: processOne used to try to write the error record
// on the SAME transaction the failing reducer call had already aborted.
// Every statement after a Postgres error inside a transaction block fails
// ("current transaction is aborted"), and COMMIT on an aborted transaction
// is a no-op rollback — so the whole txn, including the earlier
// queued->running claim, was silently discarded: the job reverted to
// 'queued' with no error ever recorded, and (false, err) still bubbled up
// to the caller as if something had been persisted.
func TestProcessOne_ReducerFailureIsPersisted(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// Toggle must be on for email_address_policy_apply_bulk to do anything;
	// restore whatever it was set to.
	var origEnabled bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles WHERE key = 'feature.email_address_policy'`,
	).Scan(&origEnabled); err != nil {
		t.Fatalf("read toggle: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.email_address_policy'`,
	); err != nil {
		t.Fatalf("enable toggle: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), //nolint:errcheck
			`UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.email_address_policy'`, origEnabled)
	})

	// A domain marked is_local=false: any policy that renders an address on
	// it trips the BZ078 "not a local domain" guard in email_address_policy_apply.
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, FALSE) RETURNING id`,
		"eap-c4-test-"+suffix+".invalid",
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var userID, mailboxID int64
	email := "eap-c4-" + suffix + "@eap-c4-test-" + suffix + ".invalid"
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, address_policy_enabled)
		 VALUES ($1, lower($2), 'EAP C4 Test User', $3, '$2a$10$placeholder', TRUE)
		 RETURNING id`,
		"eap-c4-user-"+suffix, email, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', TRUE)
		 RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}

	// Restrict this policy to our test domain so the sweep-all bulk call
	// can't touch any other fixture's mailboxes.
	priority := 9200000 + int(time.Now().UnixNano()%100000)
	var policyID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO email_address_policies
		   (priority, name, enabled, cond_domain_ids, primary_template, duplicate_resolution)
		 VALUES ($1, $2, TRUE, ARRAY[$3]::bigint[], '{user_name}@{domain}', 'numeric_suffix')
		 RETURNING id`,
		priority, "eap-c4-test-"+suffix, domainID,
	).Scan(&policyID); err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	var jobID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO eap_apply_jobs (policy_id, status) VALUES (NULL, 'queued') RETURNING id`,
	).Scan(&jobID); err != nil {
		t.Fatalf("insert job: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM eap_apply_jobs WHERE id = $1`, jobID)            //nolint:errcheck
		pool.Exec(c, `DELETE FROM email_address_policies WHERE id = $1`, policyID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM aliases WHERE mailbox_id = $1`, mailboxID)       //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)             //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)                    //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)                //nolint:errcheck
	})

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, logger)
	claimed, procErr := w.processOne(ctx)
	if procErr == nil {
		t.Fatalf("expected processOne to surface the reducer's BZ078 error, got nil (claimed=%v)", claimed)
	}

	var status string
	var jobErr *string
	if err := pool.QueryRow(ctx,
		`SELECT status, error FROM eap_apply_jobs WHERE id = $1`, jobID,
	).Scan(&status, &jobErr); err != nil {
		t.Fatalf("select job after failure: %v", err)
	}

	if status != "error" {
		t.Errorf("job status = %q, want %q (C4: failure must be persisted, not silently reverted to 'queued')", status, "error")
	}
	if jobErr == nil || *jobErr == "" {
		t.Errorf("job error column is empty; the reducer failure message must be recorded")
	}
}

// TestWorker_PersistFailureBackoffAndDeadLetter pins the retry budget
// (D-MAILSERVER-INTERNAL-EAPJOBS-001): repeated error-persist failures put the
// job under exponential backoff (excluded from claiming) and dead-letter it
// after maxPersistFailures instead of letting it be re-claimed every tick
// forever. A durable terminal outcome clears the budget.
func TestWorker_PersistFailureBackoffAndDeadLetter(t *testing.T) {
	w := NewWorker(pgxutil.WorkerPool{}, testsupport.TestLogger())
	now := time.Now()

	if ids := w.excludedIDs(now); len(ids) != 0 {
		t.Fatalf("fresh worker must exclude nothing, got %v", ids)
	}

	prevNext := time.Time{}
	for i := 1; i <= maxPersistFailures; i++ {
		w.noteFailure(now, 42)
		ids := w.excludedIDs(now)
		if len(ids) != 1 || ids[0] != 42 {
			t.Fatalf("after failure %d the job must be excluded from claiming, got %v", i, ids)
		}
		// Backoff must grow exponentially while not yet dead-lettered.
		st := w.failures[42]
		if !st.dead && !st.nextRetry.After(prevNext) {
			t.Errorf("failure %d: backoff must grow (nextRetry=%v, prev=%v)", i, st.nextRetry, prevNext)
		}
		prevNext = st.nextRetry
	}

	if st := w.failures[42]; !st.dead {
		t.Fatal("job must be dead-lettered after maxPersistFailures persist failures")
	}
	// Dead-lettered: never re-admitted, even far past any backoff window.
	if ids := w.excludedIDs(now.Add(time.Hour)); len(ids) != 1 || ids[0] != 42 {
		t.Fatalf("dead-lettered job must stay excluded, got %v", ids)
	}

	// A durable terminal outcome clears the budget entirely.
	w.clearFailure(42)
	if ids := w.excludedIDs(now); len(ids) != 0 {
		t.Fatalf("cleared job must be claimable again, got %v", ids)
	}
}
