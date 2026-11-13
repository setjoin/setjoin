package jmap

import (
	"context"
	"encoding/json"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// task_lists_test.go — DB-backed tests for the TaskList/*+TaskAssigned/*
// surface (plan 2026-07-08-shared-team-task-lists.md, Task 8). Mirrors the
// identity_state_test.go DB-test posture: workerPool aliases pool (W1b test
// posture — these handlers are user-scoped BYPASS reads in production).

func newTaskListsHandler(t *testing.T, enabled bool) *JMAPHandler {
	t.Helper()
	pool := testPoolDB(t)
	return &JMAPHandler{
		pool:       pool,
		workerPool: pool,
		logger:     testLoggerDB(t),
		toggles:    toggle.NewTestFlags(map[string]bool{toggle.FeatureSharedTaskLists: enabled}),
	}
}

func TestTaskLists_ToggleOff(t *testing.T) {
	h := newTaskListsHandler(t, false)
	claims := &auth.Claims{UserID: 1}
	ctx := context.Background()

	cases := []struct {
		name string
		fn   func() (string, json.RawMessage)
	}{
		{"TaskList/get", func() (string, json.RawMessage) { return h.taskListGet(ctx, claims, nil) }},
		{"TaskList/set", func() (string, json.RawMessage) { return h.taskListSet(ctx, claims, json.RawMessage(`{}`)) }},
		{"TaskListMember/set", func() (string, json.RawMessage) {
			return h.taskListMemberSet(ctx, claims, json.RawMessage(`{"listId":"1"}`))
		}},
		{"TaskList/tasks", func() (string, json.RawMessage) {
			return h.taskListTasks(ctx, claims, json.RawMessage(`{"listId":"1"}`))
		}},
		{"TaskList/taskSet", func() (string, json.RawMessage) {
			return h.taskListTaskSet(ctx, claims, json.RawMessage(`{"listId":"1"}`))
		}},
		{"TaskAssigned/get", func() (string, json.RawMessage) { return h.taskAssignedGet(ctx, claims, nil) }},
		{"TaskAssigned/setStatus", func() (string, json.RawMessage) {
			return h.taskAssignedSetStatus(ctx, claims, json.RawMessage(`{"taskId":"1","status":"completed"}`))
		}},
	}
	for _, c := range cases {
		name, raw := c.fn()
		if name != "error" {
			t.Errorf("%s: toggle OFF should return an error tuple, got name=%q", c.name, name)
			continue
		}
		var e struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Type != "urn:ietf:params:jmap:error:serverUnavailable" {
			t.Errorf("%s: toggle OFF should be serverUnavailable, got %s (%s)", c.name, e.Type, raw)
		}
	}
}

func TestTaskLists_EndToEnd(t *testing.T) {
	h := newTaskListsHandler(t, true)
	ctx := context.Background()
	_, ownerID, _ := insertTestUserWithMailbox(t, h.pool, true)
	_, memberID, _ := insertTestUserWithMailbox(t, h.pool, true)
	_, strangerID, _ := insertTestUserWithMailbox(t, h.pool, true)

	owner := &auth.Claims{UserID: ownerID}
	member := &auth.Claims{UserID: memberID}
	stranger := &auth.Claims{UserID: strangerID}

	// create list → get shows it
	createArgs, _ := json.Marshal(map[string]any{
		"create": map[string]any{"c1": map[string]any{"name": "Sprint board"}},
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

	name, raw = h.taskListGet(ctx, owner, nil)
	if name != "TaskList/get" {
		t.Fatalf("taskListGet: got %s / %s", name, raw)
	}
	var getResp struct {
		Lists []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"lists"`
	}
	json.Unmarshal(raw, &getResp)
	found := false
	for _, l := range getResp.Lists {
		if l.ID == listID && l.Name == "Sprint board" {
			found = true
		}
	}
	if !found {
		t.Fatalf("owner's TaskList/get does not show the created list: %s", raw)
	}

	// member add by email
	var memberEmail string
	h.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, memberID).Scan(&memberEmail)
	addArgs, _ := json.Marshal(map[string]any{"listId": listID, "add": []string{memberEmail}})
	name, raw = h.taskListMemberSet(ctx, owner, addArgs)
	if name != "TaskListMember/set" {
		t.Fatalf("taskListMemberSet(add): got %s / %s", name, raw)
	}

	// B (member) sees the list + TaskList/tasks (cross-mailbox)
	name, raw = h.taskListGet(ctx, member, nil)
	if name != "TaskList/get" {
		t.Fatalf("member taskListGet: got %s / %s", name, raw)
	}
	json.Unmarshal(raw, &getResp)
	found = false
	for _, l := range getResp.Lists {
		if l.ID == listID {
			found = true
		}
	}
	if !found {
		t.Fatalf("member's TaskList/get does not show the shared list: %s", raw)
	}

	name, raw = h.taskListTasks(ctx, member, json.RawMessage(`{"listId":"`+listID+`"}`))
	if name != "TaskList/tasks" {
		t.Fatalf("member taskListTasks: got %s / %s", name, raw)
	}

	// C (stranger) gets JMAP notFound (BZ132 wire mapping)
	name, raw = h.taskListTasks(ctx, stranger, json.RawMessage(`{"listId":"`+listID+`"}`))
	if name != "error" {
		t.Fatalf("stranger taskListTasks should error, got %s / %s", name, raw)
	}
	var errResp struct {
		Type string `json:"type"`
	}
	json.Unmarshal(raw, &errResp)
	if errResp.Type != "urn:ietf:params:jmap:error:notFound" {
		t.Errorf("stranger taskListTasks: want notFound, got %s (%s)", errResp.Type, raw)
	}

	// create a task in the list, assign to the owner → TaskAssigned/get
	var ownerEmail string
	h.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, ownerID).Scan(&ownerEmail)
	taskSetArgs, _ := json.Marshal(map[string]any{
		"listId": listID,
		"create": map[string]any{
			"t1": map[string]any{"title": "Ship it", "assigneeEmail": ownerEmail},
		},
	})
	name, raw = h.taskListTaskSet(ctx, member, taskSetArgs)
	if name != "TaskList/taskSet" {
		t.Fatalf("taskListTaskSet: got %s / %s", name, raw)
	}

	name, raw = h.taskAssignedGet(ctx, owner, nil)
	if name != "TaskAssigned/get" {
		t.Fatalf("taskAssignedGet: got %s / %s", name, raw)
	}
	var assignedResp struct {
		List []struct {
			Title string `json:"title"`
		} `json:"list"`
	}
	json.Unmarshal(raw, &assignedResp)
	if len(assignedResp.List) == 0 {
		t.Fatalf("owner's TaskAssigned/get is empty: %s", raw)
	}

	// bad status → invalidArguments
	var taskID string
	h.pool.QueryRow(ctx, `SELECT id::TEXT FROM tasks WHERE list_id = $1 LIMIT 1`, listID).Scan(&taskID)
	name, raw = h.taskAssignedSetStatus(ctx, owner, json.RawMessage(`{"taskId":"`+taskID+`","status":"bogus"}`))
	if name != "error" {
		t.Fatalf("bad status should error, got %s / %s", name, raw)
	}
	json.Unmarshal(raw, &errResp)
	if errResp.Type != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("bad status: want invalidArguments, got %s (%s)", errResp.Type, raw)
	}

	// malformed ids → invalidArguments without a DB call
	name, raw = h.taskAssignedSetStatus(ctx, owner, json.RawMessage(`{"taskId":"not-a-number","status":"completed"}`))
	if name != "error" {
		t.Fatalf("malformed taskId should error, got %s / %s", name, raw)
	}
	json.Unmarshal(raw, &errResp)
	if errResp.Type != "urn:ietf:params:jmap:error:invalidArguments" {
		t.Errorf("malformed taskId: want invalidArguments, got %s (%s)", errResp.Type, raw)
	}
}
