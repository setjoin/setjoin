package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// task_lists.go — TaskList/* + TaskAssigned/*: the shared/team task-list surface
// (plan 2026-07-08-shared-team-task-lists.md). User-scoped (claims.UserID), so
// unlike the Task/* family these do NOT ride CallScoped/parseAccountID: the
// reducers take p_user_id and enforce membership in every statement (R1), and
// the calls ride h.workerPool — the cross-mailbox posture every sharing read
// uses (identity.go delegate list, calendar_a3.go). Gated by
// feature.shared_task_lists (seeded OFF, V112).

func (h *JMAPHandler) sharedTaskListsEnabled() bool {
	if h.toggles == nil {
		return false
	}
	return h.toggles.IsEnabled(toggle.FeatureSharedTaskLists)
}

func taskListsDisabled() (string, json.RawMessage) {
	return methodError("serverUnavailable", "shared task lists are not enabled")
}

// setKeyError projects a reducer error onto a PER-RECORD SetError value
// ({"type":...,"description":...}) for a notCreated/notUpdated/notAdded/
// notRemoved bucket entry — the shape jmap_task_set_create's own inline
// exception blocks and addSetErrors' malformed-id entries use. Distinct from
// mapReducerErr's return value, which wraps the same two fields in a full
// RFC 7807 Problem Details object (correct for a whole-method "error" tuple,
// wrong shape nested inside a per-record bucket).
func setKeyError(err error) json.RawMessage {
	jmapType := reducererr.Classify(err).JMAPError()
	if jmapType == "" {
		jmapType = "invalidArguments"
	}
	b, _ := json.Marshal(map[string]string{"type": jmapType, "description": reducererr.Detail(err)})
	return b
}

// --- TaskList/get, TaskList/set ---

func (h *JMAPHandler) taskListGet(ctx context.Context, user *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var result json.RawMessage
	err := h.workerPool.QueryRow(ctx, `SELECT task_list_get($1)`, user.UserID).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskListGet")
	}
	return "TaskList/get", json.RawMessage(fmt.Sprintf(`{"lists":%s}`, result))
}

// taskListSet dispatches TaskList/set create/update/destroy phases. Unlike
// dispatchSet (CallScopedBatch, mailbox-scoped) this is a small hand-rolled
// fan-out over h.workerPool — there is no accountId to scope by, and each
// phase maps to a DIFFERENT reducer with a different signature
// (create(name,color) / update(id,patch) / delete(id)), not the uniform
// jmap_<x>_set_{create,update,destroy} shape dispatchSet expects.
func (h *JMAPHandler) taskListSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	var created = map[string]json.RawMessage{}
	var notCreated = map[string]json.RawMessage{}
	if len(req.Create) > 0 && string(req.Create) != "null" && jsonIsObject(req.Create) {
		var creates map[string]struct {
			Name  string  `json:"name"`
			Color *string `json:"color"`
		}
		if err := json.Unmarshal(req.Create, &creates); err != nil {
			return methodError("invalidArguments", err.Error())
		}
		for key, obj := range creates {
			var result json.RawMessage
			err := h.workerPool.QueryRow(ctx,
				`SELECT task_list_create($1, $2, $3)`, user.UserID, obj.Name, obj.Color).Scan(&result)
			if err != nil {
				notCreated[key] = setKeyError(err)
				continue
			}
			created[key] = result
		}
	}

	var updated []string
	var notUpdated = map[string]json.RawMessage{}
	if len(req.Update) > 0 && string(req.Update) != "null" && jsonIsObject(req.Update) {
		var updates map[string]json.RawMessage
		if err := json.Unmarshal(req.Update, &updates); err != nil {
			return methodError("invalidArguments", err.Error())
		}
		for idStr, patch := range updates {
			listID, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil || listID <= 0 {
				notUpdated[idStr], _ = json.Marshal(Error{Type: "invalidArguments", Description: "invalid list id"})
				continue
			}
			var result json.RawMessage
			err = h.workerPool.QueryRow(ctx,
				`SELECT task_list_update($1, $2, $3)`, user.UserID, listID, patch).Scan(&result)
			if err != nil {
				notUpdated[idStr] = setKeyError(err)
				continue
			}
			updated = append(updated, idStr)
		}
	}

	var destroyed []string
	var notDestroyed = map[string]json.RawMessage{}
	if len(req.Destroy) > 0 {
		ids, badIDs := parseIDList(req.Destroy)
		for _, bad := range badIDs {
			notDestroyed[bad], _ = json.Marshal(Error{Type: "invalidArguments", Description: "invalid list id"})
		}
		for _, listID := range ids {
			idStr := strconv.FormatInt(listID, 10)
			_, err := h.workerPool.Exec(ctx, `SELECT task_list_delete($1, $2)`, user.UserID, listID)
			if err != nil {
				notDestroyed[idStr] = setKeyError(err)
				continue
			}
			destroyed = append(destroyed, idStr)
		}
	}

	result, _ := json.Marshal(map[string]any{
		"created": created, "notCreated": notCreated,
		"updated": updated, "notUpdated": notUpdated,
		"destroyed": destroyed, "notDestroyed": notDestroyed,
	})
	return "TaskList/set", result
}

// --- TaskListMember/set ---

func (h *JMAPHandler) taskListMemberSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var req struct {
		ListID string   `json:"listId"`
		Add    []string `json:"add,omitempty"`
		Remove []string `json:"remove,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	listID, err := strconv.ParseInt(req.ListID, 10, 64)
	if err != nil || listID <= 0 {
		return methodError("invalidArguments", "invalid listId")
	}

	var roster json.RawMessage
	notAdded := map[string]json.RawMessage{}
	for _, email := range req.Add {
		err := h.workerPool.QueryRow(ctx,
			`SELECT task_list_add_member($1, $2, $3)`, user.UserID, listID, email).Scan(&roster)
		if err != nil {
			notAdded[email] = setKeyError(err)
		}
	}
	notRemoved := map[string]json.RawMessage{}
	for _, uidStr := range req.Remove {
		memberID, err := strconv.ParseInt(uidStr, 10, 64)
		if err != nil || memberID <= 0 {
			notRemoved[uidStr], _ = json.Marshal(Error{Type: "invalidArguments", Description: "invalid userId"})
			continue
		}
		err = h.workerPool.QueryRow(ctx,
			`SELECT task_list_remove_member($1, $2, $3)`, user.UserID, listID, memberID).Scan(&roster)
		if err != nil {
			notRemoved[uidStr] = setKeyError(err)
		}
	}
	if roster == nil {
		// Neither add nor remove touched anything (e.g. both empty or both
		// entirely rejected) — read the current roster so the caller still
		// gets a consistent response instead of a null members array. R1: the
		// read carries the authenticated caller; task_list_get_roster denies
		// a non-member with BZ130 (mapped to notFound, same as the sibling
		// list-scoped reads) instead of projecting another list's roster.
		if err := h.workerPool.QueryRow(ctx,
			`SELECT task_list_get_roster($1, $2)`, user.UserID, listID).Scan(&roster); err != nil {
			return "error", mapReducerErr(err, h.logger, "taskListMemberSet.roster")
		}
	}

	result, _ := json.Marshal(map[string]any{
		"listId": req.ListID, "members": roster,
		"notAdded": notAdded, "notRemoved": notRemoved,
	})
	return "TaskListMember/set", result
}

// --- TaskList/tasks, TaskList/taskSet ---

func (h *JMAPHandler) taskListTasks(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var req struct {
		ListID string `json:"listId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	listID, err := strconv.ParseInt(req.ListID, 10, 64)
	if err != nil || listID <= 0 {
		return methodError("invalidArguments", "invalid listId")
	}
	var result json.RawMessage
	err = h.workerPool.QueryRow(ctx, `SELECT task_list_tasks($1, $2)`, user.UserID, listID).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskListTasks")
	}
	return "TaskList/tasks", result
}

func (h *JMAPHandler) taskListTaskSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var req struct {
		ListID  string          `json:"listId"`
		Create  json.RawMessage `json:"create,omitempty"`
		Update  json.RawMessage `json:"update,omitempty"`
		Destroy []string        `json:"destroy,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	listID, err := strconv.ParseInt(req.ListID, 10, 64)
	if err != nil || listID <= 0 {
		return methodError("invalidArguments", "invalid listId")
	}

	var creates, updates, destroys any
	if len(req.Create) > 0 && string(req.Create) != "null" {
		creates = req.Create
	}
	if len(req.Update) > 0 && string(req.Update) != "null" {
		updates = req.Update
	}
	var badDestroy []string
	if len(req.Destroy) > 0 {
		ids, bad := parseIDList(req.Destroy)
		badDestroy = bad
		if len(ids) > 0 {
			b, _ := json.Marshal(ids)
			destroys = json.RawMessage(b)
		}
	}

	var result json.RawMessage
	err = h.workerPool.QueryRow(ctx,
		`SELECT task_list_task_set($1, $2, $3, $4, $5)`,
		user.UserID, listID, creates, updates, destroys).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskListTaskSet")
	}
	return "TaskList/taskSet", addSetErrors(result, "notDestroyed", badDestroy)
}

// --- TaskAssigned/get, TaskAssigned/setStatus ---

func (h *JMAPHandler) taskAssignedGet(ctx context.Context, user *auth.Claims, _ json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var result json.RawMessage
	err := h.workerPool.QueryRow(ctx, `SELECT tasks_assigned_to_me($1)`, user.UserID).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskAssignedGet")
	}
	return "TaskAssigned/get", json.RawMessage(fmt.Sprintf(`{"list":%s}`, result))
}

func (h *JMAPHandler) taskAssignedSetStatus(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	if !h.sharedTaskListsEnabled() {
		return taskListsDisabled()
	}
	var req struct {
		TaskID string `json:"taskId"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	taskID, err := strconv.ParseInt(req.TaskID, 10, 64)
	if err != nil || taskID <= 0 {
		return methodError("invalidArguments", "invalid taskId")
	}
	var result json.RawMessage
	err = h.workerPool.QueryRow(ctx,
		`SELECT task_assignee_set_status($1, $2, $3)`,
		user.UserID, taskID, req.Status).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "taskAssignedSetStatus")
	}
	return "TaskAssigned/setStatus", result
}
