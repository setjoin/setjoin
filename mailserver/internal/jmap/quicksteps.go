package jmap

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/dbscope"
)

// Quick-step reducer errors route through the shared mapReducerErr (c6):
// BZ040/BZ041/BZ043 → invalidArguments with the reducer message passed through,
// BZ042 → notFound "quick step not found" — all owned by the reducererr
// classification + Detail allowlist now (the former quickStepError switch).

// quickStepGet — QuickStep/get: list the account's quick steps. The mailbox id is
// resolved from auth (parseAccountID), never taken from the request (R2).
func (h *JMAPHandler) quickStepGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "list": []any{}})
		return "QuickStep/get", empty
	}
	var list json.RawMessage
	list, err := h.caller.CallScoped(ctx, accountID, "quick_step_list")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "QuickStep/get")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"list":      list,
	})
	return "QuickStep/get", out
}

// quickStepSet — QuickStep/set: create (id null) or update (id given) a macro, or
// destroy it (destroy:true). The action allowlist + ownership are enforced in the
// reducer; the handler only resolves the account id from auth.
func (h *JMAPHandler) quickStepSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		ID        string          `json:"id,omitempty"`
		Name      string          `json:"name,omitempty"`
		Icon      string          `json:"icon,omitempty"`
		Actions   json.RawMessage `json:"actions,omitempty"`
		Destroy   bool            `json:"destroy,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID})
		return "QuickStep/set", ok
	}

	// Destroy path.
	if req.Destroy {
		id, errJSON := parseArg(req.ID, "id")
		if errJSON != nil {
			return "error", errJSON
		}
		if _, err := h.pool.Exec(ctx, `SELECT quick_step_delete($1, $2)`, accountID, id); err != nil {
			return "error", mapReducerErr(err, h.logger, "QuickStep/set")
		}
		out, _ := json.Marshal(map[string]any{"accountId": strconv.FormatInt(accountID, 10), "destroyed": req.ID})
		return "QuickStep/set", out
	}

	// Create / update path. A NULL id => insert; a non-empty id => update.
	var idArg any
	if req.ID != "" {
		id, errJSON := parseArg(req.ID, "id")
		if errJSON != nil {
			return "error", errJSON
		}
		idArg = id
	}
	actions := req.Actions
	if len(actions) == 0 {
		actions = json.RawMessage(`[]`)
	}
	var newID int64
	err := h.pool.QueryRow(ctx,
		`SELECT quick_step_set($1, $2, $3, $4, $5::jsonb)`,
		accountID, idArg, req.Name, req.Icon, string(actions),
	).Scan(&newID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "QuickStep/set")
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"id":        strconv.FormatInt(newID, 10),
	})
	return "QuickStep/set", out
}

// quickStepApply — QuickStep/apply: run a macro against one of the account's
// messages. The reducer verifies the message belongs to the mailbox (R3) and runs
// each (allowlisted) action via apply_action.
func (h *JMAPHandler) quickStepApply(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		ID        string `json:"id"`
		MessageID string `json:"messageId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	id, errJSON := parseArg(req.ID, "id")
	if errJSON != nil {
		return "error", errJSON
	}
	msgID, errJSON := parseArg(req.MessageID, "messageId")
	if errJSON != nil {
		return "error", errJSON
	}
	if h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "applied": req.ID})
		return "QuickStep/apply", ok
	}
	// native-RLS: the received_at lookup AND quick_step_apply both touch
	// messages/message_tags, and the lookup feeds the apply — so run BOTH inside
	// ONE per-request tx with app.current_mailbox_id set, so they survive the W6
	// FORCE flip. dbscope.RunScoped gives the Begin→set_config→fn→Commit dance
	// (the same helper every other tenant site uses), instead of hand-rolling it.
	var notFound bool
	var applyErr error
	if err := dbscope.RunScoped(ctx, h.pool, accountID, func(tx pgx.Tx) error {
		// Resolve the partition key (received_at) for the message, scoped to the
		// account's mailbox (R1) — the reducer re-checks ownership (R3).
		var receivedAt any
		if err := tx.QueryRow(ctx,
			`SELECT received_at FROM messages WHERE id = $1 AND mailbox_id = $2`,
			msgID, accountID,
		).Scan(&receivedAt); err != nil {
			notFound = true
			return err
		}
		if _, err := tx.Exec(ctx,
			`SELECT quick_step_apply($1, $2, $3, $4)`,
			accountID, id, msgID, receivedAt,
		); err != nil {
			applyErr = err
			return err
		}
		return nil
	}); err != nil {
		switch {
		case notFound:
			return methodError("notFound", "message not found")
		case applyErr != nil:
			return "error", mapReducerErr(applyErr, h.logger, "QuickStep/apply")
		default:
			return methodError("serverFail", "database error")
		}
	}
	out, _ := json.Marshal(map[string]any{
		"accountId": strconv.FormatInt(accountID, 10),
		"applied":   req.ID,
	})
	return "QuickStep/apply", out
}
