package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"setjoin.com/mailserver/internal/auth"
)

// identity.go — JMAP Identity family handlers (RFC 8621 §6): Identity/get,
// Identity/changes, Identity/set. Kept separate from the mail family because
// it is a distinct RFC surface. Registered in registerMethods() (handler.go).
// See mailserver/internal/AGENTS.md.

// identityState is the SINGLE source of the Identity/* state token, so
// Identity/get and Identity/changes can never drift. They HAD drifted (arch A4):
// Identity/get returned the constant user id (a state that never advanced, so a
// client keyed on it never re-fetched after an identity edit), while
// Identity/changes returned users.updated_at (a different value, so a client's
// cached get-state never matched → Identity/changes reported a spurious perpetual
// "i<uid> updated" and never converged). Both now read this one token: the user's
// updated_at as unix seconds (bumped in-txn by jmap_identity_set_update), so it
// advances on an identity edit and an up-to-date client converges.
func (h *JMAPHandler) identityState(ctx context.Context, userID int64) (string, error) {
	var updatedAt time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT updated_at FROM users WHERE id = $1`, userID,
	).Scan(&updatedAt); err != nil {
		return "", err
	}
	return encodeStateToken(updatedAt.Unix()), nil
}

func (h *JMAPHandler) identityGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var identities []map[string]any

	// 1. User's primary identity (always present, isDefault=true)
	var uEmail, uName string
	var uFirstName, uLastName, uAvatar *string
	h.pool.QueryRow(ctx,
		`SELECT email, display_name, first_name, last_name, avatar_sha256
		 FROM users WHERE id = $1`, user.UserID,
	).Scan(&uEmail, &uName, &uFirstName, &uLastName, &uAvatar)

	identity := map[string]any{
		"id":        fmt.Sprintf("i%d", user.UserID),
		"name":      uName,
		"email":     uEmail,
		"isDefault": true,
		"mayDelete": false,
	}
	if uFirstName != nil && *uFirstName != "" {
		identity["givenName"] = *uFirstName
	}
	if uLastName != nil && *uLastName != "" {
		identity["familyName"] = *uLastName
	}
	if uAvatar != nil && *uAvatar != "" {
		identity["avatar"] = fmt.Sprintf("/blobs/%s", *uAvatar)
	}
	identities = append(identities, identity)

	// 2. Aliases the user owns (on any of their mailboxes)
	aliasRows, _ := h.pool.Query(ctx,
		`SELECT a.id, COALESCE(a.display_name, a.email), a.email, a.signature, a.reply_to
		 FROM aliases a
		 JOIN mailboxes m ON m.id = a.mailbox_id
		 WHERE m.user_id = $1`, user.UserID)
	if aliasRows != nil {
		defer aliasRows.Close()
		for aliasRows.Next() {
			var id int64
			var name, email string
			var sig, reply *string
			if aliasRows.Scan(&id, &name, &email, &sig, &reply) != nil {
				continue
			}
			a := map[string]any{
				"id":        fmt.Sprintf("a%d", id),
				"name":      name,
				"email":     email,
				"isDefault": false,
				"mayDelete": true,
			}
			if sig != nil && *sig != "" {
				a["signature"] = *sig
			}
			if reply != nil && *reply != "" {
				a["replyTo"] = *reply
			}
			identities = append(identities, a)
		}
	}

	// 3. Delegated mailboxes with send_as permission. On h.workerPool
	// (BYPASSRLS): a delegate-side read is cross-mailbox-for-one-user — the
	// rows live on OTHER users' mailboxes, naming the viewer (native-RLS
	// V090); R1 by md.user_id = the authenticated user.
	delRows, _ := h.workerPool.Query(ctx,
		`SELECT mb.id, COALESCE(mb.display_name, mb.email), mb.email
		 FROM mailboxes mb
		 JOIN mailbox_delegates md ON md.mailbox_id = mb.id
		 WHERE md.user_id = $1 AND md.permission IN ('send_as','full_access')
		   AND mb.user_id != $1`, user.UserID)
	if delRows != nil {
		defer delRows.Close()
		for delRows.Next() {
			var id int64
			var name, email string
			if delRows.Scan(&id, &name, &email) != nil {
				continue
			}
			identities = append(identities, map[string]any{
				"id":        fmt.Sprintf("d%d", id),
				"name":      name,
				"email":     email,
				"isDefault": false,
				"mayDelete": false,
			})
		}
	}

	// The state MUST be the same token Identity/changes advances (identityState),
	// not the constant user id — otherwise a client can never converge (see
	// identityState). On lookup failure fall back to stateUnavailable (defensive
	// — the user was just read above; never a fake "0", which is a real token).
	state, err := h.identityState(ctx, user.UserID)
	if err != nil {
		state = stateUnavailable
	}
	result, _ := json.Marshal(map[string]any{
		"list":  identities,
		"state": state,
	})
	return "Identity/get", result
}

func (h *JMAPHandler) identityChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
	}
	json.Unmarshal(args, &req)

	newState, err := h.identityState(ctx, user.UserID)
	if err != nil {
		return methodError("serverFail", "user not found")
	}
	hasChanges := req.SinceState != "" && req.SinceState != newState

	created := []string{}
	updated := []string{}
	destroyed := []string{}
	if hasChanges {
		updated = []string{fmt.Sprintf("i%d", user.UserID)}
	}

	result, _ := json.Marshal(map[string]any{
		"oldState":       req.SinceState,
		"newState":       newState,
		"hasMoreChanges": false,
		"created":        created,
		"updated":        updated,
		"destroyed":      destroyed,
	})
	return "Identity/changes", result
}

func (h *JMAPHandler) identitySet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	r, err := h.dispatchSet(ctx, accountID, &req, "jmap_identity")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "identitySet")
	}
	return "Identity/set", r
}
