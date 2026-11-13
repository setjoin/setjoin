package token

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIssueAndStoreDefaultsRollingUpgradeAuthenticationTime(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	userID := seedUser(t, pool)
	prevHash := tokenHash("rolling-upgrade-parent")
	family := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
		 VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid)`,
		userID, prevHash, family,
	); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	sif := int64(3600)
	provider := newTestProvider(t)
	result, err := issueAndStore(
		ctx, tx, provider, userID, "dbtest-revoke-notify@example.com",
		false, "member", prevHash, nil, nil, nil, &sif, nil,
	)
	if err != nil {
		t.Fatalf("issueAndStore: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	access, err := provider.Validate(result.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := provider.Validate(result.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if access.SessionAuthTime == nil || refresh.SessionAuthTime == nil ||
		*access.SessionAuthTime <= 0 ||
		*access.SessionAuthTime != *refresh.SessionAuthTime {
		t.Fatalf("rolling SIF auth times = %v / %v",
			access.SessionAuthTime, refresh.SessionAuthTime)
	}
}

func TestRevokeExistingTransactionActorAndFailurePaths(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	userID := seedUser(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := revokeAndNotifyExistingTx(
		ctx, tx, userID, userID, "actor_attribution_test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var createdBy *int64
	if err := pool.QueryRow(ctx,
		`SELECT created_by FROM session_revocations WHERE id=$1`, id,
	).Scan(&createdBy); err != nil {
		t.Fatal(err)
	}
	if createdBy == nil || *createdBy != userID {
		t.Fatalf("created_by=%v, want %d", createdBy, userID)
	}

	closedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := closedTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := revokeAndNotifyExistingTx(
		ctx, closedTx, userID, 0, "closed_transaction",
	); err == nil {
		t.Fatal("closed revocation transaction unexpectedly succeeded")
	}
}

func TestRefreshFailsClosedWhenPersonFenceTimesOut(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	userID := seedUser(t, pool)
	locker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Rollback(ctx) //nolint:errcheck
	if _, err := locker.Exec(ctx,
		`SELECT identity_auth_person_fence($1)`, userID,
	); err != nil {
		t.Fatalf("hold identity person fence: %v", err)
	}

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN is required")
	}
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	timeoutPool, err := pgxpool.New(
		ctx, dsn+separator+"statement_timeout=50",
	)
	if err != nil {
		t.Fatalf("open timeout pool: %v", err)
	}
	t.Cleanup(timeoutPool.Close)
	provider := newTestProvider(t)
	raw, err := provider.IssueRefresh(userID, "fence-timeout@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshTokens(
		ctx, timeoutPool, provider, nil, raw,
	); err == nil || !strings.Contains(err.Error(), "revoked or expired") {
		t.Fatalf("person-fence timeout result=%v, want uniform closed failure", err)
	}
}

func TestRefreshRejectsUnfinishedIdentityTransition(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	userID := seedUser(t, pool)
	email := "refresh-admission-" + uuid.NewString() + "@example.com"
	if _, err := pool.Exec(ctx,
		`UPDATE users SET email=$2 WHERE id=$1`, userID, email,
	); err != nil {
		t.Fatal(err)
	}
	var hasPrimary bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(
		     SELECT 1 FROM mailboxes WHERE user_id=$1 AND is_primary
		 )`,
		userID,
	).Scan(&hasPrimary); err != nil {
		t.Fatal(err)
	}
	if !hasPrimary {
		var mailboxID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO mailboxes(
			     user_id,domain_id,email,display_name,type,is_primary
			 )
			 SELECT id,domain_id,email,display_name,'personal',TRUE
			   FROM users WHERE id=$1
			 RETURNING id`,
			userID,
		).Scan(&mailboxID); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(),
				`DELETE FROM mailboxes WHERE id=$1`, mailboxID)
		})
	}
	var sourceID, sourceGeneration, linkID int64
	if err := pool.QueryRow(ctx,
		`SELECT id,generation FROM identity_sources
		  WHERE source_key='legacy:scim'`,
	).Scan(&sourceID, &sourceGeneration); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO user_identity_links(
		     user_id,source_id,external_subject,purposes,state,link_method
		 ) VALUES($1,$2,$3,ARRAY['authenticate']::text[],'candidate','operator')
		 RETURNING id`,
		userID, sourceID, "refresh-admission:"+uuid.NewString(),
	).Scan(&linkID); err != nil {
		t.Fatal(err)
	}
	var transitionID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO identity_transitions(
		     user_id,kind,state,source_id,link_id,source_generation,
		     link_generation,lifecycle_generation,preview_digest,
		     preview_snapshot,preview_expires_at,actor_user_id,reason,
		     idempotency_key,request_digest,committed_at
		 ) VALUES(
		     $1,'directory_to_local','effects_pending',$2,$3,$4,
		     1,1,digest('refresh-admission-preview','sha256'),
		     '{}'::jsonb,statement_timestamp()+interval '15 minutes',
		     $1,'refresh admission fixture',gen_random_uuid(),
		     digest('refresh-admission-request','sha256'),statement_timestamp()
		 ) RETURNING id::text`,
		userID, sourceID, linkID, sourceGeneration,
	).Scan(&transitionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO identity_transition_effects(
		     transition_id,effect_kind,state,attempt_count
		 ) VALUES($1::uuid,'auth_sessions','pending',0)`,
		transitionID,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_transition_effects WHERE transition_id=$1::uuid`,
			transitionID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_transitions WHERE id=$1::uuid`, transitionID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM user_identity_links WHERE id=$1`, linkID)
	})

	provider, refresh := seedRefreshAnchor(
		t, userID, email,
	)
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		     user_id,token_hash,token_type,expires_at,family_id
		 ) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid)`,
		userID, tokenHash(refresh), uuid.NewString(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshTokens(ctx, pool, provider, nil, refresh); err == nil ||
		!strings.Contains(err.Error(), "revoked or expired") {
		t.Fatalf("unfinished-transition refresh error=%v", err)
	}
}

func TestRefreshRejectsSuccessorPrincipalMismatch(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	userID := seedUser(t, pool)
	const otherID int64 = 999_995
	var domainID int64
	if err := pool.QueryRow(ctx,
		`SELECT domain_id FROM users WHERE id=$1`, userID,
	).Scan(&domainID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users(id,username,domain_id,email,display_name,enabled)
		 VALUES($1,'refresh-successor-other',$2,
		        'refresh-successor-other@example.com','Other',TRUE)
		 ON CONFLICT(id) DO UPDATE SET enabled=TRUE`,
		otherID, domainID,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM oauth_tokens WHERE user_id=$1`, otherID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE id=$1`, otherID)
	})
	provider, refresh := seedRefreshAnchor(
		t, userID, "dbtest-revoke-notify@example.com",
	)
	hash := tokenHash(refresh)
	// Production rotation ALWAYS inherits the parent's family (issueAndStore),
	// so the hand-seeded successor carries the family the presented token
	// itself claims — the family-keyed grace tip lookup (ER5 er5-s08) must find
	// it and trip the principal-mismatch guard.
	parentClaims, err := provider.Validate(refresh)
	if err != nil {
		t.Fatal(err)
	}
	successorFamily := parentClaims.FamilyID
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		     user_id,token_hash,token_type,expires_at,family_id,rotated_at
		 ) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::uuid,now())`,
		userID, hash, successorFamily,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(
		     user_id,token_hash,token_type,previous_token_hash,expires_at,family_id
		 ) VALUES($1,digest($2,'sha256'),'refresh',$3,
		          now()+interval '1 hour',$4::uuid)`,
		otherID, "successor-"+uuid.NewString(), hash, successorFamily,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshTokens(ctx, pool, provider, nil, refresh); err == nil ||
		!strings.Contains(err.Error(), "revoked or expired") {
		t.Fatalf("successor mismatch refresh error=%v", err)
	}
}
