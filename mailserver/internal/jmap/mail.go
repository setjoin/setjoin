package jmap

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// mail.go — JMAP Mail family handlers (RFC 8621): Mailbox/*, Email/*,
// EmailSubmission/*, Thread/*, and SearchSnippet/get. Methods are registered
// centrally in registerMethods() (handler.go); this file holds only the bodies,
// plus the snooze-extension helpers and the recover/purge batch helper used
// exclusively by the mail surface. See mailserver/internal/AGENTS.md.

// VendorCapability is the single URN under which every nonstandard JMAP
// property and method this program adds is declared (snoozeUntil on Email/set,
// submission sendAt listing). Keeping the nonstandard surface under one URN
// makes it auditable in one place — see docs/specs/JMAP.md.
const VendorCapability = "urn:setjoin:params:jmap:mail"

// splitSnoozeUpdates partitions an Email/set "update" map into patches that
// carry a non-null snoozeUntil (routed to message_snooze) and ordinary patches
// (routed to jmap_email_set_update). A patch with snoozeUntil:null is ordinary.
func splitSnoozeUpdates(update map[string]json.RawMessage) (snooze, ordinary map[string]json.RawMessage) {
	snooze = make(map[string]json.RawMessage)
	ordinary = make(map[string]json.RawMessage)
	for id, patch := range update {
		if _, ok := parseSnoozeUntil(patch); ok {
			snooze[id] = patch
		} else {
			ordinary[id] = patch
		}
	}
	if len(snooze) == 0 {
		snooze = nil
	}
	if len(ordinary) == 0 {
		ordinary = nil
	}
	return snooze, ordinary
}

// parseSnoozeUntil extracts the RFC3339 snoozeUntil timestamp from a patch.
// Returns ok=false when the property is absent, null, or unparseable.
//
// We use time.RFC3339Nano so that JavaScript's Date.toISOString() output
// (e.g. "2026-06-14T08:00:00.000Z") is accepted explicitly. RFC3339Nano is a
// superset of RFC3339 and matches both forms.
func parseSnoozeUntil(patch json.RawMessage) (time.Time, bool) {
	var p struct {
		SnoozeUntil *string `json:"snoozeUntil"`
	}
	if err := json.Unmarshal(patch, &p); err != nil || p.SnoozeUntil == nil {
		return time.Time{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, *p.SnoozeUntil)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// --- JMAP Mail method implementations ---

func (h *JMAPHandler) mailboxGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string   `json:"accountId"`
		Ids        []string `json:"ids"`
		Properties []string `json:"properties,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if len(req.Ids) > 256 {
		return methodError("requestTooLarge", "too many ids requested")
	}
	ids, badIDs := parseIDList(req.Ids)
	var idsArray interface{}
	if ids != nil { // nil only when req.Ids was absent/empty → NULL → get-all
		idsArray = ids
	}

	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_mailbox_get", idsArray, req.Properties)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailboxGet")
	}
	return "Mailbox/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) mailboxChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
		MaxChanges int    `json:"maxChanges"` // parsed for forward-compat; reducer is still 2-arg (Task 6 left it 2-arg)
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if errResp := sinceStateError(req.SinceState); errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_mailbox_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailboxChanges")
	}
	return "Mailbox/changes", result
}

// mailboxSet handles JMAP Mailbox/set (RFC 8621 §2.5). A "mailbox" in this system
// is a TAG (a folder is a tag), so create inserts a user tag and destroy removes
// one. create/update/destroy all flow through the shared dispatchSet helper, which
// fans them out to jmap_mailbox_set_{create,update,destroy} and merges the result
// — previously this handler only read the "update" key, so create/destroy were
// silently dropped (the client got a 200 with no created/destroyed keys).
func (h *JMAPHandler) mailboxSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}

	result, err := h.dispatchSet(ctx, accountID, &req, "jmap_mailbox")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailboxSet")
	}
	return "Mailbox/set", result
}

func (h *JMAPHandler) emailGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string   `json:"accountId"`
		Ids        []string `json:"ids"`
		Properties []string `json:"properties,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if len(req.Ids) > 256 {
		return methodError("requestTooLarge", "too many ids requested")
	}
	ids, badIDs := parseIDList(req.Ids)
	// Native-RLS proof slice (ARCH-006, plan 2026-06-18-native-rls-backstop.md
	// Phase 1): Email/get is the representative messages/message_tags-touching
	// path wrapped in the per-request tx that sets the transaction-scoped
	// app.current_mailbox_id GUC before the reducer runs. accountID IS the
	// caller's authenticated primary mailbox (parseAccountID above), so the GUC
	// equals the authenticated mailbox. RLS is NOT enabled in production — this
	// only proves the plumbing (the GUC the eventual policies key on is set
	// correctly, inside one PgBouncer-transaction-mode-safe BEGIN…COMMIT). The
	// JSON result is byte-identical to the prior unwrapped Call.
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_email_get", ids, req.Properties)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailGet")
	}
	h.auditMailbox(ctx, user.UserID, accountID, "email_get", nil)
	// SP1 P5: decrypt-on-read. For any returned email stored encrypted-at-rest
	// (cryptoType=='smime-encrypted', body columns NULL), load the reader's
	// keystore keys, fetch the raw_ref EnvelopedData blob, and inject TRANSIENT
	// cleartext + a read-state. Plaintext is never persisted; a failed decrypt is
	// a calm read-state, never an error. Byte-identical when nothing is encrypted.
	// accountID is the caller's authenticated PRIMARY mailbox id (parseAccountID) —
	// the genuine mailbox the decrypt-on-read audit row must reference (the JMAP
	// mailboxIds object is keyed by message_tags.tag_id, a DIFFERENT id space that
	// would FK-violate mailbox_audit_log.mailbox_id and silently drop the audit).
	result = h.decryptEmailResult(ctx, user.UserID, accountID, result)
	return "Email/get", addNotFound(result, badIDs)
}

func (h *JMAPHandler) emailQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter,omitempty"`
		Sort      json.RawMessage `json:"sort,omitempty"`
		Position  int             `json:"position,omitempty"`
		Limit     int             `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	if req.Limit <= 0 || req.Limit > 256 {
		req.Limit = 50
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_email_query", req.Filter, req.Sort, req.Position, req.Limit)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailQuery")
	}
	return "Email/query", result
}

func (h *JMAPHandler) emailChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
		MaxChanges int    `json:"maxChanges"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if errResp := sinceStateError(req.SinceState); errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	// nullIfZero passes nil when the client omits maxChanges so the reducer's
	// DEFAULT NULL applies; otherwise passes the positive value (→ hasMoreChanges).
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_email_changes", req.SinceState, nullIfZero(req.MaxChanges))
	if err != nil {
		// jmap_email_changes raises BZ011 cannotCalculateChanges (RFC 8620 §5.2:
		// the client's sinceState is too old to delta from → full resync) and
		// BZ006 accountNotFound. mapReducerErr routes both to the right JMAP type
		// instead of collapsing them to serverFail.
		return "error", mapReducerErr(err, h.logger, "emailChanges")
	}
	return "Email/changes", result
}

func (h *JMAPHandler) mailboxQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter,omitempty"`
		Sort      json.RawMessage `json:"sort,omitempty"`
		Position  int             `json:"position"`
		Limit     int             `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT jmap_mailbox_query($1, $2::JSONB, $3::JSONB, $4, $5)`,
		accountID, jsonToNull(req.Filter), jsonToNull(req.Sort), req.Position, nullIfZero(req.Limit),
	).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailboxQuery")
	}
	return "Mailbox/query", result
}

func (h *JMAPHandler) mailboxQueryChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID       string          `json:"accountId"`
		Filter          json.RawMessage `json:"filter,omitempty"`
		Sort            json.RawMessage `json:"sort,omitempty"`
		SinceQueryState string          `json:"sinceQueryState"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if req.SinceQueryState == "" {
		req.SinceQueryState = encodeStateToken(0) // historical default: full history
	}
	if errResp := sinceStateError(req.SinceQueryState); errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	err := h.pool.QueryRow(ctx,
		`SELECT jmap_mailbox_query_changes($1, $2::JSONB, $3::JSONB, $4)`,
		accountID, jsonToNull(req.Filter), jsonToNull(req.Sort), req.SinceQueryState,
	).Scan(&result)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "mailboxQueryChanges")
	}
	return "Mailbox/queryChanges", result
}

func (h *JMAPHandler) emailSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req SetRequest
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}

	// Attachment-blob ownership gate (er5-s11, sealed anchor
	// email-set-unowned-global-blob): a creation's `attachments` array names
	// content-addressed blobIds, and jmap_email_set_create links whatever id it
	// is given into the caller's own message — from where Blob/get and
	// /jmap/download then serve the bytes to the caller. Without this gate any
	// authenticated user who KNOWS (or guesses) another tenant's blob hash
	// attached it to their own draft and read the foreign content back through
	// their own authorized download path. Gate the create phase before the
	// reducer: every referenced blob must be one the caller UPLOADED (a
	// blob_user_charges row of their own — recorded by both the /blobs PUT and
	// the JMAP upload accounting) or that is ALREADY attached to mail in a
	// mailbox they own (attach-from-existing-mail). Denied creations become
	// per-record notCreated entries (RFC 8620 SetError "forbidden"); the
	// remaining creations dispatch unchanged.
	var goNotCreated map[string]json.RawMessage
	if len(req.Create) > 0 && string(req.Create) != "null" && jsonIsObject(req.Create) {
		filtered, denied, err := h.gateAttachmentBlobOwnership(ctx, user.UserID, req.Create)
		if err != nil {
			h.logger.Error("emailSet attachment ownership gate failed", "error", err)
			return methodError("serverFail", "")
		}
		req.Create = filtered
		goNotCreated = denied
	}

	// Intercept snoozeUntil extension patches (urn:setjoin:params:jmap:mail) and
	// route them to message_snooze; pass the remainder to the standard set path.
	// ponytail: snooze legs stay one CallScoped tx per message, OUTSIDE the c3
	// single-tx dispatchSet batch — they're a vendor extension with existing
	// per-item (notUpdated) semantics, not part of the RFC 8620 §3.6.2
	// create/update/destroy atomicity contract. Fold them into the batch if a
	// client ever needs snooze+move to be atomic.
	updated := make(map[string]json.RawMessage)
	notUpdated := make(map[string]json.RawMessage)
	if len(req.Update) > 0 && string(req.Update) != "null" && jsonIsObject(req.Update) {
		var allUpdates map[string]json.RawMessage
		if err := json.Unmarshal(req.Update, &allUpdates); err == nil {
			snooze, ordinary := splitSnoozeUpdates(allUpdates)
			for id, patch := range snooze {
				msgID, parseErr := strconv.ParseInt(id, 10, 64)
				if parseErr != nil {
					nu, _ := json.Marshal(map[string]string{
						"type": "invalidArguments", "description": "invalid message id",
					})
					notUpdated[id] = nu
					continue
				}
				until, _ := parseSnoozeUntil(patch)
				_, err := h.caller.CallScoped(ctx, accountID, "message_snooze", msgID, until)
				if err != nil {
					h.logger.Warn("message_snooze failed", "message_id", id, "error", err)
					nu, _ := json.Marshal(map[string]string{
						"type": "invalidArguments", "description": "snooze failed",
					})
					notUpdated[id] = nu
				} else {
					updated[id] = json.RawMessage(`null`)
				}
			}
			// Rebuild req.Update with only ordinary patches for dispatchSet.
			if len(ordinary) == 0 {
				req.Update = nil
			} else {
				req.Update, _ = json.Marshal(ordinary)
			}
		}
	}

	r, err := h.dispatchSet(ctx, accountID, &req, "jmap_email")
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailSet")
	}
	h.auditMailbox(ctx, user.UserID, accountID, "email_set", nil)

	// Merge the ownership gate's per-creation denials into the set response.
	if len(goNotCreated) > 0 {
		r = mergeNotCreated(r, goNotCreated)
	}

	// Merge snooze results into the standard set response.
	r = mergeSnoozeResults(r, updated, notUpdated)
	return "Email/set", r
}

// gateAttachmentBlobOwnership screens every creation's `attachments` blobIds
// against the authenticated caller's ownership evidence and returns the
// filtered create map (owned-only creations, unchanged JSON) plus the
// notCreated entries for denied creations. See emailSet for the threat model.
// The batched EXISTS query is R1-scoped: both arms carry the authenticated
// user_id (blob_user_charges is the upload-charge ledger keyed by the
// uploading user; the attachment arm rides mailboxes.user_id, the same
// cross-mailbox-for-one-user shape Blob/get uses).
func (h *JMAPHandler) gateAttachmentBlobOwnership(ctx context.Context, userID int64, create json.RawMessage) (json.RawMessage, map[string]json.RawMessage, error) {
	var creates map[string]json.RawMessage
	if err := json.Unmarshal(create, &creates); err != nil {
		// Not a creation map: leave it for dispatchSet/reducer validation.
		return create, nil, nil
	}

	type attachmentRefs struct {
		Attachments []struct {
			BlobID string `json:"blobId"`
		} `json:"attachments"`
	}
	perCreation := make(map[string][]string, len(creates))
	unique := make([]string, 0, len(creates))
	seen := make(map[string]bool)
	for id, raw := range creates {
		var refs attachmentRefs
		if err := json.Unmarshal(raw, &refs); err != nil {
			perCreation[id] = nil // malformed creation: the reducer's notCreated path owns it
			continue
		}
		ids := make([]string, 0, len(refs.Attachments))
		for _, a := range refs.Attachments {
			if a.BlobID == "" {
				continue
			}
			ids = append(ids, a.BlobID)
			if !seen[a.BlobID] {
				seen[a.BlobID] = true
				unique = append(unique, a.BlobID)
			}
		}
		perCreation[id] = ids
	}
	if len(unique) == 0 {
		return create, nil, nil // no blob references — nothing to gate
	}

	owned, err := h.ownedBlobSet(ctx, userID, unique)
	if err != nil {
		return nil, nil, err
	}

	denied := make(map[string]json.RawMessage)
	filtered := make(map[string]json.RawMessage, len(creates))
	for id, raw := range creates {
		foreign := false
		for _, blobID := range perCreation[id] {
			if !owned[blobID] {
				foreign = true
				break
			}
		}
		if foreign {
			denied[id], _ = json.Marshal(map[string]string{
				"type":        "forbidden",
				"description": "attachment blob is not owned by the authenticated account",
			})
			continue
		}
		filtered[id] = raw
	}
	out, err := json.Marshal(filtered)
	if err != nil {
		return nil, nil, err
	}
	return out, denied, nil
}

// ownedBlobSet returns the subset of blobIds the caller has an ownership
// relationship to: they uploaded it (blob_user_charges.user_id, recorded by
// both upload endpoints' blob_upload_account accounting) or it is already
// attached to a message in one of their mailboxes (mailboxes.user_id).
func (h *JMAPHandler) ownedBlobSet(ctx context.Context, userID int64, blobIds []string) (map[string]bool, error) {
	owned := make(map[string]bool, len(blobIds))
	if len(blobIds) == 0 {
		return owned, nil
	}
	// native-RLS posture: cross-mailbox-for-one-user EXISTS read on the
	// BYPASSRLS worker pool (same as Blob/get), R1-scoped by mb.user_id /
	// bc.user_id = the authenticated caller.
	rows, err := h.workerPool.Query(ctx, `
		SELECT q.sha
		  FROM unnest($1::text[]) AS q(sha)
		 WHERE EXISTS (
			SELECT 1 FROM blob_user_charges bc
			 WHERE bc.blob_sha256 = q.sha AND bc.user_id = $2
		 ) OR EXISTS (
			SELECT 1 FROM message_attachments ma
			 JOIN messages m ON m.id = ma.message_id
			 JOIN mailboxes mb ON mb.id = m.mailbox_id
			 WHERE ma.blob_sha256 = q.sha AND mb.user_id = $2
		 )`, blobIds, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, err
		}
		owned[sha] = true
	}
	return owned, rows.Err()
}

// mergeSnoozeResults folds message_snooze outcomes into an Email/set response's
// "updated"/"notUpdated" maps, preserving anything the standard set path returned.
func mergeSnoozeResults(base json.RawMessage, updated, notUpdated map[string]json.RawMessage) json.RawMessage {
	if len(updated) == 0 && len(notUpdated) == 0 {
		return base
	}
	merged := make(map[string]json.RawMessage)
	if len(base) > 0 {
		json.Unmarshal(base, &merged) //nolint:errcheck
	}
	mergeInto := func(key string, add map[string]json.RawMessage) {
		if len(add) == 0 {
			return
		}
		existing := make(map[string]json.RawMessage)
		if raw, ok := merged[key]; ok {
			json.Unmarshal(raw, &existing) //nolint:errcheck
		}
		for k, v := range add {
			existing[k] = v
		}
		out, _ := json.Marshal(existing)
		merged[key] = out
	}
	mergeInto("updated", updated)
	mergeInto("notUpdated", notUpdated)
	out, _ := json.Marshal(merged)
	return out
}

func (h *JMAPHandler) emailDeletedQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Limit     int    `json:"limit,omitempty"`
		Position  int    `json:"position,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 256 {
		req.Limit = 50
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_email_query_deleted", req.Limit, req.Position)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailDeletedQuery")
	}
	return "Email/deletedQuery", result
}

// emailBundles handles the vendor method Email/bundles (B5.2).
// Returns a computed newsletter bundle list grouped by list_id for the
// caller's mailbox account. Requires feature.newsletter_bundles to be on;
// if the pool is nil (unit-test mode) it returns an empty list.
func (h *JMAPHandler) emailBundles(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Limit     int    `json:"limit,omitempty"`
		Position  int    `json:"position,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	// Nil pool: return empty bundle list (unit-test / dev mode).
	if h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"bundles": []any{}, "position": 0})
		return "Email/bundles", empty
	}
	var raw json.RawMessage
	raw, err := h.caller.CallScoped(ctx, accountID, "newsletter_bundles_list", req.Limit, req.Position)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailBundles")
	}
	result, _ := json.Marshal(map[string]any{
		"accountId": req.AccountID,
		"bundles":   raw,
		"position":  req.Position,
	})
	return "Email/bundles", result
}

// staleNudgesEnabled reports whether the feature.stale_nudges toggle is ON.
// OFF (or an unseeded/nil toggle set) gates the two nudge methods to inert
// empty responses — same default-OFF idiom as the other toggle-gated vendor
// methods (assist checks IsEnabled likewise).
func (h *JMAPHandler) staleNudgesEnabled() bool {
	return h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureStaleNudges)
}

// emailNudges handles the vendor method Email/nudges (#13). Returns the computed
// stale-thread / no-reply nudge list for the caller's mailbox account. Gated
// behind feature.stale_nudges; toggle-off or a nil pool returns an empty list.
func (h *JMAPHandler) emailNudges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		Limit     int    `json:"limit,omitempty"`
		Position  int    `json:"position,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 200 {
		req.Limit = 50
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	// Toggle OFF or nil pool (unit-test / dev mode): return an empty nudge list.
	if !h.staleNudgesEnabled() || h.pool == nil {
		empty, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "nudges": []any{}, "position": 0})
		return "Email/nudges", empty
	}
	var raw json.RawMessage
	raw, err := h.caller.CallScoped(ctx, accountID, "stale_thread_nudges_list", req.Limit, req.Position)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailNudges")
	}
	result, _ := json.Marshal(map[string]any{
		"accountId": req.AccountID,
		"nudges":    raw,
		"position":  req.Position,
	})
	return "Email/nudges", result
}

// emailNudgeDismiss handles the vendor method Email/nudgeDismiss (#13): dismiss
// one stale-thread nudge by thread id (persisted in view_prefs->'nudgeDismissed'
// by the nudge_dismiss reducer). Gated behind feature.stale_nudges; toggle-off
// or nil pool is a no-op success.
func (h *JMAPHandler) emailNudgeDismiss(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		ThreadID  string `json:"threadId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if !h.staleNudgesEnabled() || h.pool == nil {
		ok, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "dismissed": []any{}})
		return "Email/nudgeDismiss", ok
	}
	var raw json.RawMessage
	raw, err := h.caller.CallScoped(ctx, accountID, "nudge_dismiss", req.ThreadID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailNudgeDismiss")
	}
	result, _ := json.Marshal(map[string]any{"accountId": req.AccountID, "dismissed": raw})
	return "Email/nudgeDismiss", result
}

func (h *JMAPHandler) emailRecover(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	return h.emailBatchOp(ctx, args, user.UserID, "jmap_email_recover", "Email/recover")
}

func (h *JMAPHandler) emailPurge(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	return h.emailBatchOp(ctx, args, user.UserID, "jmap_email_purge", "Email/purge")
}

// emailBatchOp handles recover/purge batch operations on email IDs.
func (h *JMAPHandler) emailBatchOp(ctx context.Context, args json.RawMessage, userID int64, sqlFn, method string) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		Ids       []string `json:"ids"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, userID)
	if errResp != nil {
		return "error", errResp
	}
	ids, badIDs := parseIDList(req.Ids)
	// Malformed ids land in the method's per-record bucket (c4) — and an
	// all-malformed request now sends an EMPTY array instead of NULL (which
	// errored the reducer's FOREACH).
	bucket := "notRecovered"
	if method == "Email/purge" {
		bucket = "notPurged"
	}
	// native-RLS: jmap_email_recover / jmap_email_purge touch messages +
	// message_tags → run inside the per-request GUC tx (CallScoped) so they
	// survive the W6 FORCE flip.
	result, err := h.caller.CallScoped(ctx, accountID, sqlFn, ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, sqlFn)
	}
	return method, addSetErrors(result, bucket, badIDs)
}

func (h *JMAPHandler) emailSubmissionSet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Create    json.RawMessage `json:"create,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	// Phase 3: process at submission. Parse the create map, run the combined S/MIME
	// processing pass (sign-inner and/or encrypt-outer → store), and collect
	// processedRefs (creationId→final-blob-key) for the swap seam plus isEncrypted
	// (creationId→bool) for the encrypted-at-rest body-null in send()/deliver().
	// signSMIME/encryptSMIME are stripped from every surviving creation so the
	// dormant worker path never re-processes. Failures (any missing recipient/
	// sender/journal cert) become Go-side notCreated entries — the creation is
	// DROPPED, never sent plaintext — merged into the result below.
	createArg := req.Create
	processedRefsArg := json.RawMessage(nil)
	isEncryptedArg := json.RawMessage(nil)
	var goNotCreated map[string]json.RawMessage
	if len(req.Create) > 0 {
		var createMap map[string]json.RawMessage
		if err := json.Unmarshal(req.Create, &createMap); err != nil {
			return methodError("invalidArguments", err.Error())
		}
		modified, processedRefs, isEncrypted, notCreated := h.processSubmissions(ctx, user.UserID, accountID, createMap)
		goNotCreated = notCreated
		if b, err := json.Marshal(modified); err == nil {
			createArg = b
		}
		if len(processedRefs) > 0 {
			if b, err := json.Marshal(processedRefs); err == nil {
				processedRefsArg = b
			}
		}
		// Only marshal the encrypted map when at least one creation is encrypted, so
		// the common (no-encrypt) case keeps passing a nil 5th arg.
		anyEnc := false
		for _, v := range isEncrypted {
			if v {
				anyEnc = true
				break
			}
		}
		if anyEnc {
			if b, err := json.Marshal(isEncrypted); err == nil {
				isEncryptedArg = b
			}
		}
	}

	// native-RLS W4: EmailSubmission/set is CROSS-TENANT. jmap_email_submission_set
	// → send() → deliver() writes the local-recipient copies into OTHER mailboxes
	// (the option-1 fan-out). W3 mis-classified this as a sender-scoped write and
	// wrapped it with CallScoped, which sets app.current_mailbox_id to the SENDER's
	// mailbox — under the W6 FORCE flip that tenant GUC denies the deliver() WITH
	// CHECK into a recipient mailbox (42501). The correct route is the worker
	// (BYPASSRLS) pool with NO tenant GUC. accountID is still passed as the
	// auth-resolved sender-mailbox arg (send() self-authorizes the sender:
	// ownership/delegation gates BZ003 etc. before any write — the SMTP/JMAP auth
	// layer already established WHO is sending). EmailSubmission/get + /cancel stay
	// on CallScoped: they are sender-scoped reads/writes, not cross-tenant.
	// The 4th arg is p_processed_raw_ref (signed and/or encrypted) swap map (nil =
	// nothing processed); the 5th is p_is_encrypted (creationId→bool; nil for now,
	// populated in 3.4 to drive the encrypted-at-rest body-null in send()/deliver()).
	var result json.RawMessage
	result, err := h.workerCaller.Call(ctx, "jmap_email_submission_set", accountID, user.UserID, createArg, processedRefsArg, isEncryptedArg)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailSubmissionSet")
	}
	// Merge any Go-side sign-failure notCreated entries into the reducer's result.
	result = mergeNotCreated(result, goNotCreated)
	return "EmailSubmission/set", result
}

// emailSubmissionCancel cancels a pending undo-send or scheduled send.
// Calls the message_cancel() SQL reducer which removes the Scheduled tag
// and restores the Drafts tag.
func (h *JMAPHandler) emailSubmissionCancel(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string `json:"accountId"`
		EmailID   string `json:"emailId"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}

	if req.EmailID == "" {
		return methodError("invalidArguments", "emailId is required")
	}

	emailID, errJSON := parseArg(req.EmailID, "emailId")
	if errJSON != nil {
		return "error", errJSON
	}

	result, err := h.caller.CallScoped(ctx, accountID, "message_cancel", emailID)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailSubmissionCancel")
	}
	return "EmailSubmission/cancel", result
}

// emailSubmissionGet lists pending/deferred submissions (the Scheduled view).
// Delegates to jmap_email_submission_get, which filters by accountId.
func (h *JMAPHandler) emailSubmissionGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		Ids       []string `json:"ids,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	ids, badIDs := parseIDList(req.Ids)
	var idsArg interface{}
	if ids != nil { // nil only when req.Ids was absent/empty → NULL → get-all
		idsArg = ids
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_email_submission_get", idsArg)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "emailSubmissionGet")
	}
	return "EmailSubmission/get", addNotFound(result, badIDs)
}

// emailSubmissionQuery returns ids of pending/deferred submissions ordered by
// sendAt. Delegates to jmap_email_submission_query, which filters by accountId.
func (h *JMAPHandler) emailSubmissionQuery(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter,omitempty"`
		Position  int             `json:"position,omitempty"`
		Limit     int             `json:"limit,omitempty"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}
	if req.Limit <= 0 || req.Limit > 256 {
		req.Limit = 50
	}
	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	if err := h.pool.QueryRow(ctx,
		`SELECT jmap_email_submission_query($1, $2::JSONB, $3, $4)`,
		accountID, jsonToNull(req.Filter), req.Position, req.Limit,
	).Scan(&result); err != nil {
		return "error", mapReducerErr(err, h.logger, "emailSubmissionQuery")
	}
	return "EmailSubmission/query", result
}

func (h *JMAPHandler) threadGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string   `json:"accountId"`
		Ids       []string `json:"ids"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_thread_get", req.Ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "threadGet")
	}
	return "Thread/get", result
}

func (h *JMAPHandler) threadChanges(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID  string `json:"accountId"`
		SinceState string `json:"sinceState"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	if errResp := sinceStateError(req.SinceState); errResp != nil {
		return "error", errResp
	}
	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_thread_changes", req.SinceState)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "threadChanges")
	}
	return "Thread/changes", result
}

func (h *JMAPHandler) searchSnippetGet(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	var req struct {
		AccountID string          `json:"accountId"`
		Filter    json.RawMessage `json:"filter"`
		EmailIds  []string        `json:"emailIds"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return methodError("invalidArguments", err.Error())
	}

	accountID, errResp := h.parseAccountID(ctx, req.AccountID, user.UserID)
	if errResp != nil {
		return "error", errResp
	}
	ids, badIDs := parseIDList(req.EmailIds)

	var result json.RawMessage
	result, err := h.caller.CallScoped(ctx, accountID, "jmap_search_snippet_get", req.Filter, ids)
	if err != nil {
		return "error", mapReducerErr(err, h.logger, "searchSnippetGet")
	}
	return "SearchSnippet/get", addNotFound(result, badIDs)
}
