package approval

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// TODOS.md "approve-by-email notification gap": external-send holds +
// role_group approvers never got the approve-by-email notification — only
// approver_kind='user' rows were even queried (the old SendApprovalNotification
// SQL had `AND approver_kind = 'user'`, so a role_group row matched zero rows
// and silently no-opped). These tests cover the fan-out (every active member of
// a role_group gets an email) and the new generic entry point
// (HandleApprovalCreatedNotify) that reaches the external-send hold, which has
// no other Go call site with the request id (send() PERFORMs
// approval_request_create and RETURNs NULL).

const (
	notifyDomainID    = int64(99970)
	notifyRequesterID = int64(99971)
	notifyMember1ID   = int64(99972)
	notifyMember2ID   = int64(99973)
	notifyRoleGroupID = int64(3) // "Help Desk", pre-seeded in admin_role_groups (V001 baseline)
)

// seedNotifyFixtures creates a requester + two role-group members, each with a
// primary mailbox (SendApprovalNotification resolves emails via
// identity.ResolvePrimaryMailbox), and assigns both members to notifyRoleGroupID
// via admin_role_assignments (the resolver's data source, TODOS' suggested
// query: role_group_id=$1 AND NOW() < expires_at, generalized to include NULL
// expires_at for a standing assignment).
func seedNotifyFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}

	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES (99970,'apprnotify.test',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		(99971,'apprn_req',99970,'req@apprnotify.test','Requester',TRUE),
		(99972,'apprn_m1', 99970,'m1@apprnotify.test', 'Member 1', TRUE),
		(99973,'apprn_m2', 99970,'m2@apprnotify.test', 'Member 2', TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		(99971,99971,99970,'req@apprnotify.test','Requester','personal',TRUE),
		(99972,99972,99970,'m1@apprnotify.test', 'Member 1', 'personal',TRUE),
		(99973,99973,99970,'m2@apprnotify.test', 'Member 2', 'personal',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO admin_role_assignments (user_id, role_group_id, eligible) VALUES
		(99972, 3, false), (99973, 3, false) ON CONFLICT DO NOTHING`)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id IN (99971,99972,99973)`)                          //nolint:errcheck
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id IN (99972,99973) AND role_group_id=3`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_requests WHERE requester_user_id=99971`)                           //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id IN (99971,99972,99973)`)                                 //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN (99971,99972,99973)`)                                     //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id=99970`)                                                    //nolint:errcheck
	})
}

func insertNotifyRequest(t *testing.T, pool *pgxpool.Pool, consumerType, approverKind string, approverRef int64) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO approval_requests
		  (consumer_type, requester_user_id, subject, payload, approver_kind, approver_ref, expires_at)
		VALUES ($1, $2, 'notify test subject', '{}'::jsonb, $3, $4, now()+interval '1h')
		RETURNING id`,
		consumerType, notifyRequesterID, approverKind, approverRef,
	).Scan(&id); err != nil {
		t.Fatalf("insertNotifyRequest: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM approval_requests WHERE id = $1`, id) }) //nolint:errcheck
	return id
}

func messageCountForMailbox(t *testing.T, pool *pgxpool.Pool, mailboxID int64) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM messages WHERE mailbox_id = $1`, mailboxID,
	).Scan(&n); err != nil {
		t.Fatalf("messageCountForMailbox(%d): %v", mailboxID, err)
	}
	return n
}

// TestSendApprovalNotification_RoleGroup_NotifiesAllMembers is the gap proof:
// a role_group approver_kind request must email EVERY active member, not
// silently no-op (the pre-fix query filtered `approver_kind = 'user'`).
func TestSendApprovalNotification_RoleGroup_NotifiesAllMembers(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "mail.group_moderation", "role_group", notifyRoleGroupID)

	SendApprovalNotification(context.Background(), pool, reqID, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember1ID); got != 1 {
		t.Errorf("member 1 (mailbox %d): want 1 notification email, got %d", notifyMember1ID, got)
	}
	if got := messageCountForMailbox(t, pool, notifyMember2ID); got != 1 {
		t.Errorf("member 2 (mailbox %d): want 1 notification email, got %d", notifyMember2ID, got)
	}
}

// TestSendApprovalNotification_UserKind_StillWorks is the regression: the
// single-designated-approver path (group moderator, named-user policy) must
// still send exactly one email.
func TestSendApprovalNotification_UserKind_StillWorks(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "mail.external_send", "user", notifyMember1ID)

	SendApprovalNotification(context.Background(), pool, reqID, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember1ID); got != 1 {
		t.Errorf("user-kind approver: want 1 notification email, got %d", got)
	}
	if got := messageCountForMailbox(t, pool, notifyMember2ID); got != 0 {
		t.Errorf("user-kind approver: a non-approver must get 0 emails, got %d", got)
	}
}

// TestHandleApprovalCreatedNotify_SkipsRBAC proves rbac.jit_activation is
// console-only (spec D7): the generic NOTIFY-driven entry point must NOT send
// an email for it, even though the row's approver is otherwise reachable.
func TestHandleApprovalCreatedNotify_SkipsRBAC(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "rbac.jit_activation", "user", notifyMember1ID)

	payload, _ := json.Marshal(map[string]any{"request_id": reqID, "consumer_type": "rbac.jit_activation"})
	HandleApprovalCreatedNotify(context.Background(), pool, payload, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember1ID); got != 0 {
		t.Errorf("rbac.jit_activation: must be console-only (D7), got %d notification emails", got)
	}
}

// TestHandleApprovalCreatedNotify_MailConsumerReachesExternalSend proves the
// generic entry point is what actually reaches the external-send hold — the
// one consumer with NO other Go call site holding the request id (send()
// PERFORMs approval_request_create and RETURNs NULL).
func TestHandleApprovalCreatedNotify_MailConsumerReachesExternalSend(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "mail.external_send", "user", notifyMember2ID)

	payload, _ := json.Marshal(map[string]any{"request_id": reqID, "consumer_type": "mail.external_send"})
	HandleApprovalCreatedNotify(context.Background(), pool, payload, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember2ID); got != 1 {
		t.Errorf("mail.external_send via HandleApprovalCreatedNotify: want 1 notification email, got %d", got)
	}
}

// TestHandleApprovalCreatedNotify_HRRidesApproveByEmail proves hr.leave (and by
// extension hr.expense — same "not rbac.jit_activation" exclusion check) rides
// the existing fan-out for free: the skip list is a single explicit exclusion
// (rbac.jit_activation, D7 console-only), so any other consumer_type — HR
// included — reaches SendApprovalNotification without a code change.
func TestHandleApprovalCreatedNotify_HRRidesApproveByEmail(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "hr.leave", "user", notifyMember1ID)

	payload, _ := json.Marshal(map[string]any{"request_id": reqID, "consumer_type": "hr.leave"})
	HandleApprovalCreatedNotify(context.Background(), pool, payload, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember1ID); got != 1 {
		t.Errorf("hr.leave via HandleApprovalCreatedNotify: want 1 notification email, got %d", got)
	}
}

// TestHandleApprovalCreatedNotify_Unconfigured proves a missing baseURL/secret
// (approve-by-email not configured) is a silent no-op, not a panic.
func TestHandleApprovalCreatedNotify_Unconfigured(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)
	reqID := insertNotifyRequest(t, pool, "mail.external_send", "user", notifyMember1ID)

	payload, _ := json.Marshal(map[string]any{"request_id": reqID, "consumer_type": "mail.external_send"})
	HandleApprovalCreatedNotify(context.Background(), pool, payload, nil, "", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, notifyMember1ID); got != 0 {
		t.Errorf("unconfigured (no secret/baseURL): must not send, got %d", got)
	}
}

// TestSendApprovalNotification_RoleGroup_DormantMemberNotEmailed pins the
// issuance/use parity of resolveApproverEmails (D-MAILSERVER-INTERNAL-APPROVAL-002/003,
// owner decision A1 option a): with rbac.jit ON the fan-out tracks the decide
// path's BZ107 authority exactly —
//   - a dormant-eligible member (eligible=true, no open activation window) is
//     NOT emailed the signed approve/deny token the reducer would refuse;
//   - a member with currently-active authority (eligible=true, open window) and
//     a standing member (eligible=false) ARE emailed;
//   - with the toggle OFF admin_assignment_active is behaviorally inert, so the
//     same dormant member IS emailed too — the gate cannot outlive its toggle.
func TestSendApprovalNotification_RoleGroup_DormantMemberNotEmailed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	seedNotifyFixtures(t, pool)

	const (
		dormantMemberID      = int64(99974) // eligible=true, window never opened
		activeWindowMemberID = int64(99975) // eligible=true, open activation window
	)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("seed members: %v", err)
		}
	}
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE
		VALUES (99974,'apprn_m3',99970,'m3@apprnotify.test','Dormant Member',TRUE),
		       (99975,'apprn_m4',99970,'m4@apprnotify.test','Active Window Member',TRUE) ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE
		VALUES (99974,99974,99970,'m3@apprnotify.test','Dormant Member','personal',TRUE),
		       (99975,99975,99970,'m4@apprnotify.test','Active Window Member','personal',TRUE) ON CONFLICT DO NOTHING`)
	// eligible=true with no activated_until = dormant-eligible under JIT;
	// eligible=true with a future activated_until = currently-active authority.
	exec(`INSERT INTO admin_role_assignments (user_id, role_group_id, eligible, activated_until) VALUES
		(99974, 3, TRUE, NULL), (99975, 3, TRUE, now() + interval '1 day') ON CONFLICT DO NOTHING`)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id IN (99974,99975)`)                                //nolint:errcheck
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE user_id IN (99974,99975) AND role_group_id=3`) //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id IN (99974,99975)`)                                       //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN (99974,99975)`)                                           //nolint:errcheck
	})

	testsupport.SetFeatureToggleForTest(t, pool, "rbac.jit", true)

	reqID := insertNotifyRequest(t, pool, "mail.group_moderation", "role_group", notifyRoleGroupID)
	SendApprovalNotification(context.Background(), pool, reqID, testSecret, "https://approvals.test", testsupport.TestLogger())

	for _, tc := range []struct {
		mailbox int64
		want    int
		who     string
	}{
		{notifyMember1ID, 1, "standing member 1 (eligible=false)"},
		{notifyMember2ID, 1, "standing member 2 (eligible=false)"},
		{activeWindowMemberID, 1, "active-window member (eligible=true, open window — decidable, so emailed)"},
		{dormantMemberID, 0, "dormant-eligible member (BZ107-refused under JIT) must not be emailed"},
	} {
		if got := messageCountForMailbox(t, pool, tc.mailbox); got != tc.want {
			t.Errorf("%s (mailbox %d): want %d notification email(s), got %d", tc.who, tc.mailbox, tc.want, got)
		}
	}

	// Toggle OFF: admin_assignment_active is behaviorally inert, so the same
	// dormant member is now decidable and must appear in the fan-out (issuance
	// set tracks the gate); the previously-active member keeps receiving
	// (2 sends = 2 emails).
	// NOTE: flipped via a plain UPDATE, NOT a second SetFeatureToggleForTest —
	// the helper's session-level advisory lock is held by this test's own
	// connection until cleanup, so a second helper call would self-deadlock on
	// another pool session. This test still owns the advisory key, so
	// cross-package toggle serialization is intact, and the helper's cleanup
	// below restores the pre-test value.
	if _, err := pool.Exec(context.Background(),
		`UPDATE feature_toggles SET enabled=false, updated_at=statement_timestamp() WHERE key='rbac.jit'`,
	); err != nil {
		t.Fatalf("flip rbac.jit OFF for phase 2: %v", err)
	}
	reqID2 := insertNotifyRequest(t, pool, "mail.group_moderation", "role_group", notifyRoleGroupID)
	SendApprovalNotification(context.Background(), pool, reqID2, testSecret, "https://approvals.test", testsupport.TestLogger())

	if got := messageCountForMailbox(t, pool, dormantMemberID); got != 1 {
		t.Errorf("former dormant member with rbac.jit OFF (mailbox %d): want 1 notification email, got %d", dormantMemberID, got)
	}
	if got := messageCountForMailbox(t, pool, activeWindowMemberID); got != 2 {
		t.Errorf("active-window member across both sends (mailbox %d): want 2 notification emails, got %d", activeWindowMemberID, got)
	}
}
