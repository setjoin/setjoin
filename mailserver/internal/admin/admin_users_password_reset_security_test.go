package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
)

func TestResetPasswordRevokesCompleteSessionStateAtomically(t *testing.T) {
	pool := mailboxTestPool(t)
	ctx := context.Background()
	domainID := ensureScopeTestDomain(t, pool, "password-reset-security.example")
	actorID := createScopeTestUser(t, pool, domainID, "password-reset-security.example")
	targetID := createScopeTestUser(t, pool, domainID, "password-reset-security.example")
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments(
		   user_id,role_group_id,granted_by
		 ) VALUES ($1,3,$1)`,
		actorID,
	); err != nil {
		t.Fatalf("seed password-reset authority: %v", err)
	}

	sessionID := "admin-password-reset-security-session-" + mailboxRandomSuffix(t)
	accessToken := "admin-reset-access-" + mailboxRandomSuffix(t)
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method)
		 VALUES ($1,$2,digest($3,'sha256'),
		         now()+interval '1 hour','password')`,
		sessionID, targetID, accessToken,
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO ws_subscriptions(connection_id,session_id,user_id)
		 VALUES ($1,$2,$3)`,
		"admin-password-reset-security-ws-"+mailboxRandomSuffix(t), sessionID, targetID,
	); err != nil {
		t.Fatalf("seed websocket subscription: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at)
		 VALUES ($1,digest($2,'sha256'),
		         'refresh',now()+interval '1 hour')`,
		targetID, "admin-reset-refresh-"+mailboxRandomSuffix(t),
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT identity_auth_link_elevation_begin(
		    $1,gen_random_uuid(),$2,digest($3,'sha256'),
		    'oidc','admin-reset-provider',now()+interval '5 minutes'
		 )`,
		targetID, sessionID, accessToken,
	).Scan(new([]byte)); err != nil {
		t.Fatalf("seed identity-link elevation: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/admin/users/%d/password", targetID),
		strings.NewReader(`{"password":"Unique-Reset-9!zQ","mustChange":true}`),
	)
	req.SetPathValue("id", fmt.Sprintf("%d", targetID))
	req = req.WithContext(middleware.ContextWithDomainScope(
		auth.ContextWithUser(req.Context(), &auth.Claims{
			UserID:  actorID,
			Email:   "admin@password-reset-security.example",
			IsAdmin: true,
		}),
		domainID,
	))

	h := NewUsersHandler(
		pool,
		pgxutil.WorkerPool{Pool: pool},
		mailboxTestLogger(),
		nil,
		"",
		"",
	)
	rec := httptest.NewRecorder()
	h.ResetPassword(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ResetPassword: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var activeTokens, sessions, subscriptions, elevations, revocations int
	if err := pool.QueryRow(ctx,
		`SELECT
		   (SELECT count(*) FROM oauth_tokens
		     WHERE user_id=$1 AND revoked_at IS NULL),
		   (SELECT count(*) FROM sessions WHERE user_id=$1),
		   (SELECT count(*) FROM ws_subscriptions WHERE user_id=$1),
		   (SELECT count(*) FROM identity_auth_link_elevations
		     WHERE user_id=$1 AND consumed_at IS NULL),
		   (SELECT count(*) FROM session_revocations
		     WHERE user_id=$1 AND scope='all'
		       AND reason='admin_password_reset')`,
		targetID,
	).Scan(
		&activeTokens,
		&sessions,
		&subscriptions,
		&elevations,
		&revocations,
	); err != nil {
		t.Fatalf("read post-reset security state: %v", err)
	}
	if activeTokens != 0 || sessions != 0 || subscriptions != 0 ||
		elevations != 0 || revocations != 1 {
		t.Fatalf(
			"password reset left active state: tokens=%d sessions=%d "+
				"subscriptions=%d elevations=%d revocations=%d",
			activeTokens, sessions, subscriptions, elevations, revocations,
		)
	}
}

func TestAdminResetPasswordSerializesAuthorityNarrowing(t *testing.T) {
	tests := []string{
		"assignment_revocation",
		"jit_deactivation",
		"department_reparent",
		"scope_set_member_removal",
	}
	for _, testName := range tests {
		testName := testName
		t.Run(testName, func(t *testing.T) {
			pool := mailboxTestPool(t)
			ctx := context.Background()
			suffix := mailboxRandomSuffix(t)
			domainID := ensureScopeTestDomain(t, pool, "reset-fence-"+suffix+".example")
			actorID := createScopeTestUser(t, pool, domainID, "reset-fence-"+suffix+".example")
			targetID := createScopeTestUser(t, pool, domainID, "reset-fence-"+suffix+".example")

			var parentDept, childDept int64
			if err := pool.QueryRow(ctx,
				`INSERT INTO departments(name,path,ldap_ou)
				 VALUES ($1,$2,$3) RETURNING id`,
				"Fence Parent "+suffix, "/fence-"+suffix, "ou=fence-parent-"+suffix,
			).Scan(&parentDept); err != nil {
				t.Fatalf("seed parent department: %v", err)
			}
			if err := pool.QueryRow(ctx,
				`INSERT INTO departments(name,path,ldap_ou)
				 VALUES ($1,$2,$3) RETURNING id`,
				"Fence Child "+suffix, "/fence-"+suffix+"/child", "ou=fence-child-"+suffix,
			).Scan(&childDept); err != nil {
				t.Fatalf("seed child department: %v", err)
			}
			if _, err := pool.Exec(ctx,
				`UPDATE users
				    SET department_id=$2,password_hash='fence-original'
				  WHERE id=$1`,
				targetID, childDept,
			); err != nil {
				t.Fatalf("place target: %v", err)
			}

			var roleGroupID int64
			if err := pool.QueryRow(ctx,
				`INSERT INTO admin_role_groups(name,permissions,domain_scope)
				 VALUES ($1,ARRAY['users.password_reset'],$2) RETURNING id`,
				"Reset Fence "+suffix, domainID,
			).Scan(&roleGroupID); err != nil {
				t.Fatalf("seed role group: %v", err)
			}

			var scopeSetID int64
			switch testName {
			case "scope_set_member_removal":
				if err := pool.QueryRow(ctx,
					`INSERT INTO admin_scope_sets(name,domain_id,created_by)
					 VALUES ($1,$2,$3) RETURNING id`,
					"Reset Fence Set "+suffix, domainID, actorID,
				).Scan(&scopeSetID); err != nil {
					t.Fatalf("seed scope set: %v", err)
				}
				if _, err := pool.Exec(ctx,
					`INSERT INTO admin_scope_set_members(set_id,member_type,member_id,added_by)
					 VALUES ($1,'user',$2,$3)`,
					scopeSetID, targetID, actorID,
				); err != nil {
					t.Fatalf("seed scope member: %v", err)
				}
				if _, err := pool.Exec(ctx,
					`INSERT INTO admin_role_assignments(
					   user_id,role_group_id,scope_type,scope_id,granted_by
					 ) VALUES ($1,$2,'set',$3,$1)`,
					actorID, roleGroupID, scopeSetID,
				); err != nil {
					t.Fatalf("seed set assignment: %v", err)
				}
			case "jit_deactivation":
				var priorJIT bool
				if err := pool.QueryRow(ctx,
					`SELECT enabled FROM feature_toggles WHERE key='rbac.jit'`,
				).Scan(&priorJIT); err != nil {
					t.Fatalf("read JIT gate: %v", err)
				}
				if _, err := pool.Exec(ctx,
					`UPDATE feature_toggles SET enabled=true WHERE key='rbac.jit'`,
				); err != nil {
					t.Fatalf("enable JIT gate: %v", err)
				}
				t.Cleanup(func() {
					_, _ = pool.Exec(context.Background(),
						`UPDATE feature_toggles SET enabled=$1 WHERE key='rbac.jit'`,
						priorJIT,
					)
				})
				if _, err := pool.Exec(ctx,
					`INSERT INTO admin_role_assignments(
					   user_id,role_group_id,scope_type,scope_id,granted_by,
					   eligible,activated_until
					 ) VALUES ($1,$2,'ou',$3,$1,true,now()+interval '1 hour')`,
					actorID, roleGroupID, parentDept,
				); err != nil {
					t.Fatalf("seed JIT assignment: %v", err)
				}
			default:
				if _, err := pool.Exec(ctx,
					`INSERT INTO admin_role_assignments(
					   user_id,role_group_id,scope_type,scope_id,granted_by
					 ) VALUES ($1,$2,'ou',$3,$1)`,
					actorID, roleGroupID, parentDept,
				); err != nil {
					t.Fatalf("seed OU assignment: %v", err)
				}
			}

			var initiallyReachable bool
			if err := pool.QueryRow(ctx,
				`SELECT admin_can_manage_with_permission(
				    $1,$2,'users.password_reset'
				 )`,
				actorID, targetID,
			).Scan(&initiallyReachable); err != nil || !initiallyReachable {
				t.Fatalf("initial reach = %v, err=%v", initiallyReachable, err)
			}

			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin authority mutation: %v", err)
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			switch testName {
			case "assignment_revocation":
				_, err = tx.Exec(ctx,
					`DELETE FROM admin_role_assignments
					  WHERE user_id=$1 AND role_group_id=$2`,
					actorID, roleGroupID,
				)
			case "jit_deactivation":
				_, err = tx.Exec(ctx,
					`SELECT admin_role_deactivate($1,$2)`,
					actorID, roleGroupID,
				)
			case "department_reparent":
				_, err = tx.Exec(ctx,
					`UPDATE departments SET path=$2 WHERE id=$1`,
					childDept, "/outside-"+suffix+"/child",
				)
			case "scope_set_member_removal":
				_, err = tx.Exec(ctx,
					`DELETE FROM admin_scope_set_members
					  WHERE set_id=$1 AND member_type='user' AND member_id=$2`,
					scopeSetID, targetID,
				)
			}
			if err != nil {
				t.Fatalf("narrow authority: %v", err)
			}

			resetDone := make(chan error, 1)
			go func() {
				var revocationID int64
				resetDone <- pool.QueryRow(context.Background(),
					`SELECT admin_reset_password($1,$2,$3,$4,true)`,
					actorID, targetID, domainID, "fence-replacement",
				).Scan(&revocationID)
			}()
			select {
			case resetErr := <-resetDone:
				t.Fatalf("password reset bypassed uncommitted authority fence: %v", resetErr)
			case <-time.After(150 * time.Millisecond):
			}

			if err := tx.Commit(ctx); err != nil {
				t.Fatalf("commit authority narrowing: %v", err)
			}
			resetErr := <-resetDone
			var pgErr *pgconn.PgError
			if !errors.As(resetErr, &pgErr) || pgErr.Code != "BZ061" {
				t.Fatalf("post-narrow reset error = %v, want BZ061", resetErr)
			}
			var passwordHash string
			if err := pool.QueryRow(ctx,
				`SELECT password_hash FROM users WHERE id=$1`,
				targetID,
			).Scan(&passwordHash); err != nil {
				t.Fatalf("read target password: %v", err)
			}
			if passwordHash != "fence-original" {
				t.Fatalf("authority race changed password to %q", passwordHash)
			}
		})
	}
}
