package jmap

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

// task_lists_roster_scope_test.go — R1 regression for the TaskListMember/set
// roster fallback read (med-jmap-task-roster-001). task_list_get_roster takes
// the authenticated caller's id, so a stranger enumerating listIds gets the
// sibling notFound denial (BZ130 wire mapping, identical to taskListTasks)
// instead of another tenant's roster. Mirrors task_lists_test.go's DB posture
// (workerPool aliases pool; toggle ON via NewTestFlags).

func TestTaskListsMemberSet_RosterScopedToCaller(t *testing.T) {
	h := newTaskListsHandler(t, true)
	ctx := context.Background()
	ownerDom, ownerID, _ := insertTestUserWithMailbox(t, h.pool, true)
	memberDom, memberID, _ := insertTestUserWithMailbox(t, h.pool, true)
	strangerDom, strangerID, _ := insertTestUserWithMailbox(t, h.pool, true)

	// Fixture teardown (Astra waves12 finding 2: the former per-statement
	// autocommit DISABLE/ENABLE TRIGGER ALL could strand the mailboxes
	// triggers globally disabled on the shared test database, and the blanket
	// ENABLE did not preserve a deliberately-disabled trigger's prior state).
	// The primary-mailbox trigger still blocks the plain deletes
	// insertTestUserWithMailbox's own cleanup attempts, so its errors (ignored
	// there) leak the accounts; mailbox_lifecycle (RESTRICT) and
	// mailbox_address_claims must go first. The WHOLE teardown is ONE
	// transaction — the trigger disable/restore and every delete commit or
	// roll back atomically, so a mid-cleanup failure can never leave the
	// shared schema with triggers off — and after the blanket ENABLE (which
	// also re-arms the internal FK triggers) each user trigger captured with
	// non-default pg_trigger.tgenabled is put back EXACTLY ('D' disabled,
	// 'R' replica, 'A' always). Runs BEFORE the helper's cleanup (LIFO); its
	// subsequent no-op deletes are harmless, and pool.Close is registered
	// first so it still runs last.
	t.Cleanup(func() {
		c := context.Background()
		tx, err := h.pool.Begin(c)
		if err != nil {
			t.Errorf("cleanup: begin: %v", err)
			return
		}
		// No-op after a successful Commit; on any earlier return below it
		// undoes the trigger disable together with every delete.
		defer func() { _ = tx.Rollback(c) }()

		accounts := []struct{ dom, uid int64 }{
			{ownerDom, ownerID}, {memberDom, memberID}, {strangerDom, strangerID},
		}

		for _, a := range accounts {
			if _, err := tx.Exec(c,
				`DELETE FROM mailbox_address_claims WHERE mailbox_id IN
				   (SELECT id FROM mailboxes WHERE user_id = $1 OR domain_id = $2)`, a.uid, a.dom); err != nil {
				t.Errorf("cleanup: address claims for user %d: %v", a.uid, err)
			}
			if _, err := tx.Exec(c,
				`DELETE FROM mailbox_lifecycle WHERE bound_user_id = $1`, a.uid); err != nil {
				t.Errorf("cleanup: mailbox lifecycle for user %d: %v", a.uid, err)
			}
		}

		// Capture the prior non-internal trigger state so the disable can be
		// undone EXACTLY, not just blanket-ENABLEd.
		type trgState struct {
			name    string
			enabled byte
		}
		var prior []trgState
		rows, err := tx.Query(c,
			`SELECT tgname, tgenabled FROM pg_trigger
			   WHERE tgrelid = 'public.mailboxes'::regclass AND NOT tgisinternal
			   ORDER BY tgname`)
		if err != nil {
			t.Errorf("cleanup: read mailboxes trigger state: %v", err)
			return
		}
		for rows.Next() {
			var g trgState
			var en string
			if err := rows.Scan(&g.name, &en); err != nil {
				rows.Close()
				t.Errorf("cleanup: scan mailboxes trigger state: %v", err)
				return
			}
			g.enabled = en[0]
			prior = append(prior, g)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Errorf("cleanup: iterate mailboxes trigger state: %v", err)
			return
		}
		rows.Close()

		if _, err := tx.Exec(c, `ALTER TABLE mailboxes DISABLE TRIGGER ALL`); err != nil {
			t.Errorf("cleanup: disable mailboxes triggers: %v", err)
			return
		}
		for _, a := range accounts {
			if _, err := tx.Exec(c,
				`DELETE FROM mailboxes WHERE user_id = $1 OR domain_id = $2`, a.uid, a.dom); err != nil {
				t.Errorf("cleanup: mailboxes for user %d: %v", a.uid, err)
			}
		}
		// ENABLE ALL first (re-arms the internal FK triggers the blanket
		// disable took down), then restore each user trigger's captured state.
		if _, err := tx.Exec(c, `ALTER TABLE mailboxes ENABLE TRIGGER ALL`); err != nil {
			t.Errorf("cleanup: enable mailboxes triggers: %v", err)
			return
		}
		for _, g := range prior {
			var action string
			switch g.enabled {
			case 'O':
				continue // default state — ENABLE ALL already restored it
			case 'D':
				action = "DISABLE"
			case 'R':
				action = "ENABLE REPLICA"
			case 'A':
				action = "ENABLE ALWAYS"
			default:
				action = "DISABLE"
			}
			qname := `"` + strings.ReplaceAll(g.name, `"`, `""`) + `"`
			if _, err := tx.Exec(c, `ALTER TABLE mailboxes `+action+` TRIGGER `+qname); err != nil {
				t.Errorf("cleanup: restore mailboxes trigger %s state: %v", g.name, err)
			}
		}

		for _, a := range accounts {
			if _, err := tx.Exec(c, `DELETE FROM users WHERE id = $1`, a.uid); err != nil {
				t.Errorf("cleanup: user %d: %v", a.uid, err)
			}
			if _, err := tx.Exec(c, `DELETE FROM domains WHERE id = $1`, a.dom); err != nil {
				t.Errorf("cleanup: domain %d: %v", a.dom, err)
			}
		}

		if err := tx.Commit(c); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	owner := &auth.Claims{UserID: ownerID}
	member := &auth.Claims{UserID: memberID}
	stranger := &auth.Claims{UserID: strangerID}

	// owner creates the victim list
	createArgs, _ := json.Marshal(map[string]any{
		"create": map[string]any{"c1": map[string]any{"name": "Roster scope"}},
	})
	name, raw := h.taskListSet(ctx, owner, createArgs)
	if name != "TaskList/set" {
		t.Fatalf("taskListSet: got %s / %s", name, raw)
	}
	var setResp struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
	}
	if err := json.Unmarshal(raw, &setResp); err != nil {
		t.Fatalf("unmarshal taskListSet: %v (%s)", err, raw)
	}
	listID := setResp.Created["c1"].ID
	if listID == "" {
		t.Fatalf("no list id created: %s", raw)
	}

	// add the member (owner↔member relationship); the stranger never gets one
	var memberEmail string
	if err := h.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, memberID).Scan(&memberEmail); err != nil {
		t.Fatalf("lookup member email: %v", err)
	}
	addArgs, _ := json.Marshal(map[string]any{"listId": listID, "add": []string{memberEmail}})
	if name, raw = h.taskListMemberSet(ctx, owner, addArgs); name != "TaskListMember/set" {
		t.Fatalf("taskListMemberSet(add): got %s / %s", name, raw)
	}

	// empty add/remove → the roster fallback read (the fixed IDOR read) fires
	emptyArgs, _ := json.Marshal(map[string]any{"listId": listID, "add": []string{}, "remove": []string{}})

	// owner still sees the full roster (non-vacuity)
	name, raw = h.taskListMemberSet(ctx, owner, emptyArgs)
	if name != "TaskListMember/set" {
		t.Fatalf("owner roster read should succeed, got %s / %s", name, raw)
	}
	var rosterResp struct {
		Members []map[string]any `json:"members"`
	}
	if err := json.Unmarshal(raw, &rosterResp); err != nil {
		t.Fatalf("unmarshal owner roster: %v (%s)", err, raw)
	}
	if len(rosterResp.Members) != 2 {
		t.Errorf("owner roster: want 2 members, got %d (%s)", len(rosterResp.Members), raw)
	}

	// member still sees the full roster (non-vacuity)
	name, raw = h.taskListMemberSet(ctx, member, emptyArgs)
	if name != "TaskListMember/set" {
		t.Fatalf("member roster read should succeed, got %s / %s", name, raw)
	}
	rosterResp.Members = nil
	if err := json.Unmarshal(raw, &rosterResp); err != nil {
		t.Fatalf("unmarshal member roster: %v (%s)", err, raw)
	}
	if len(rosterResp.Members) != 2 {
		t.Errorf("member roster: want 2 members, got %d (%s)", len(rosterResp.Members), raw)
	}

	// stranger enumerating listIds → notFound (sibling BZ130 semantics);
	// BEFORE the fix this returned the victim list's full roster.
	name, raw = h.taskListMemberSet(ctx, stranger, emptyArgs)
	if name != "error" {
		t.Fatalf("stranger roster read must be denied, got %s / %s", name, raw)
	}
	var errResp struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &errResp); err != nil {
		t.Fatalf("unmarshal stranger denial: %v (%s)", err, raw)
	}
	if errResp.Type != "urn:ietf:params:jmap:error:notFound" {
		t.Errorf("stranger roster read: want notFound, got %s (%s)", errResp.Type, raw)
	}

	// a nonexistent list is denied with the SAME shape (no membership oracle)
	name, raw = h.taskListMemberSet(ctx, owner, json.RawMessage(`{"listId":"999999","add":[],"remove":[]}`))
	if name != "error" {
		t.Fatalf("nonexistent list must be denied, got %s / %s", name, raw)
	}
	errResp.Type = ""
	if err := json.Unmarshal(raw, &errResp); err != nil {
		t.Fatalf("unmarshal nonexistent denial: %v (%s)", err, raw)
	}
	if errResp.Type != "urn:ietf:params:jmap:error:notFound" {
		t.Errorf("nonexistent list: want notFound, got %s (%s)", errResp.Type, raw)
	}

	// the leave path still succeeds AND still returns a usable roster: the
	// leaver's view is captured before their own row is deleted (the
	// caller-scoped read would otherwise deny them post-delete).
	leaveArgs, _ := json.Marshal(map[string]any{"listId": listID, "remove": []string{strconv.FormatInt(memberID, 10)}})
	name, raw = h.taskListMemberSet(ctx, member, leaveArgs)
	if name != "TaskListMember/set" {
		t.Fatalf("member self-leave must succeed, got %s / %s", name, raw)
	}
	rosterResp.Members = nil
	if err := json.Unmarshal(raw, &rosterResp); err != nil {
		t.Fatalf("unmarshal leave roster: %v (%s)", err, raw)
	}
	if len(rosterResp.Members) == 0 {
		t.Errorf("leaver should still get a roster, got %s", raw)
	}

	// the leave actually removed the membership row
	var leftCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT count(*) FROM task_list_members WHERE list_id = $1 AND user_id = $2`,
		listID, memberID).Scan(&leftCount); err != nil {
		t.Fatalf("count membership after leave: %v", err)
	}
	if leftCount != 0 {
		t.Errorf("leaver's roster row should be gone, count = %d", leftCount)
	}

	// the owner's fallback read still works afterwards (1 member left)
	name, raw = h.taskListMemberSet(ctx, owner, emptyArgs)
	if name != "TaskListMember/set" {
		t.Fatalf("owner roster read after leave should succeed, got %s / %s", name, raw)
	}
	rosterResp.Members = nil
	if err := json.Unmarshal(raw, &rosterResp); err != nil {
		t.Fatalf("unmarshal owner roster after leave: %v (%s)", err, raw)
	}
	if len(rosterResp.Members) != 1 {
		t.Errorf("owner roster after leave: want 1 member, got %d (%s)", len(rosterResp.Members), raw)
	}
}
