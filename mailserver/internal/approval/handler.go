// Package approval serves the user-facing approval-engine endpoints:
//
//	GET  /me/approvals             — list pending-for-me and my submitted requests
//	POST /me/approvals/{id}/decide — approve or deny a request
//	POST /me/approvals/{id}/cancel — requester withdraws their own pending request
//
// SECURITY MODEL (CRITICAL — do not remove this comment):
//
// Every VISIBILITY query runs inside dbscope.RunUserScoped(claims.UserID), which
// sets the transaction-scoped GUC `app.current_user_id` before the first
// statement. The approval_requests table has FORCE ROW LEVEL SECURITY with a
// policy keyed on that GUC; a stranger whose ID is not the requester or approver
// cannot see the row at all.
//
// DEFENSE-IN-DEPTH (pre-flip posture): on the documented PRE-FLIP runtime RLS is
// INERT — DB_DSN connects as superuser/owner/BYPASSRLS and DB_WORKER_DSN
// defaults to DB_DSN — so the ListMyApprovals list queries ALSO carry the same
// requester-or-authorized-approver predicate in the SAME WHERE as the read
// (mirroring the V073 approval_requests_row_visibility policy and the
// approval_decide BZ107 gate). The RLS policy stays as the second layer after
// the native-RLS flip; neither layer weakens the other.
//
// WORKER-POOL CARVE-OUT (native-RLS W4 class): DECIDE for the two mail
// consumers (mail.external_send, mail.group_moderation) replays a cross-tenant
// leg inside the reducer — send() fans local-recipient deliver() into OTHER
// mailboxes (and the deny NDR delivers into the SENDER's mailbox); the group
// release deliver()s into every member's mailbox. Under the FORCE flip a tenant
// GUC pinned to the approver fails those writes closed, so — exactly like SMTP
// submission and JMAP EmailSubmission/set — that decide runs on the WORKER
// (BYPASSRLS) pool, plain (no GUC), AFTER the RLS-scoped visibility lookup.
// Authorization does not regress: approval_decide self-authorizes p_actor in
// SQL (BZ106 SoD / BZ107 not-the-approver / BZ108 idempotency); RLS only ever
// provided visibility here. guest.invite also uses the worker pool because its
// approved leg provisions a cross-domain guest and creates a worker-only invite;
// it performs the same tenant-scoped visibility lookup first. Other consumers
// stay inside the tenant tx. Pinned by routing_test.go.
//
// OPAQUE 404 vs EXPLICIT 403:
//   - Stranger probing a request ID: SELECT consumer_type returns 0 rows (RLS)
//     → opaque 404. The caller cannot distinguish "not found" from "forbidden".
//     No information oracle.
//   - Someone who CAN see the row (requester, role-group member, Super Admin)
//     but is not the designated approver: rbac_approval_decide raises BZ107
//     → explicit 403.
//
// TEST / PRODUCTION SPLIT:
//
//	handler_test.go tests BZ error paths using the superuser pool (mail role,
//	BYPASSRLS → RLS not active). The opaque-stranger behavior is separately
//	proven by dbscope.TestRunUserScoped_RLSLeakProof (non-superuser role).
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/guestinvite"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/toggle"
)

// rowQuerier is the minimal seam for the worker-pool decide leg — satisfied by
// pgxutil.WorkerPool (embedded *pgxpool.Pool); faked in routing_test.go.
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Handler serves the /me/approvals endpoints.
type Handler struct {
	pool              *pgxpool.Pool
	workerPool        rowQuerier // BYPASSRLS — mail consumers' cross-tenant decide replay ONLY (see package doc)
	workerDB          *pgxpool.Pool
	logger            *slog.Logger
	toggles           *toggle.FeatureFlags // guest invite treats nil as OFF; HR preserves existing unit-test behavior
	guestInviteMC     *minio.Client
	guestInviteBucket string
}

// NewHandler creates a Handler. workerPool is the setjoin_worker (BYPASSRLS)
// pool the mail consumers' decide replay routes onto (package doc); it aliases
// the app pool until DB_WORKER_DSN is set.
func NewHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, logger *slog.Logger) *Handler {
	return &Handler{pool: pool, workerPool: workerPool, workerDB: workerPool.Pool, logger: logger}
}

// sentinel errors — checked before the BZ map so callers can distinguish
// application-level signals from DB errors.
var (
	errNotFound                   = errors.New("approval request not found")
	errConsumerNotWired           = errors.New("consumer not yet wired")
	errInvalidDriveAccessDecision = errors.New("invalid Drive access decision payload")
)

// approvalItem is the JSON shape for a single approval_requests row.
//
// Payload is a deliberate allowlist exception to "payload is consumer-internal,
// never returned by the list endpoint" (approval_request_create.sql's comment):
// HR forms and guest.invite review evidence are small, user-facing, and contain
// no secrets (unlike mail.external_send's payload, which is the
// full send() replay arg set — recipients/subject/body — never meant for the
// wire). scanApprovalItem always scans it (cheap column), but
// scanApprovalItem zeroes it before JSON marshaling for every OTHER consumer
// type, so mail/rbac keep their existing wire contract byte-identical.
type approvalItem struct {
	ID              int64           `json:"id"`
	ConsumerType    string          `json:"consumerType"`
	Subject         string          `json:"subject"`
	Status          string          `json:"status"`
	RequesterUserID *int64          `json:"requesterUserId,omitempty"`
	ApproverKind    string          `json:"approverKind"`
	ApproverRef     int64           `json:"approverRef"`
	CreatedAt       time.Time       `json:"createdAt"`
	ExpiresAt       time.Time       `json:"expiresAt"`
	DecidedAt       *time.Time      `json:"decidedAt,omitempty"`
	DecidedByUserID *int64          `json:"decidedByUserId,omitempty"`
	DecisionComment *string         `json:"decisionComment,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
}

// scanApprovalItem scans one approval_requests row into an approvalItem, then
// clears Payload for every consumer outside the explicit safe allowlist.
// Column order must match the SELECT list used in both list queries.
func scanApprovalItem(rows pgx.Rows) (approvalItem, error) {
	var it approvalItem
	err := rows.Scan(
		&it.ID, &it.ConsumerType, &it.Subject, &it.Status,
		&it.RequesterUserID, &it.ApproverKind, &it.ApproverRef,
		&it.CreatedAt, &it.ExpiresAt,
		&it.DecidedAt, &it.DecidedByUserID, &it.DecisionComment,
		&it.Payload,
	)
	if it.ConsumerType != "hr.leave" && it.ConsumerType != "hr.expense" && it.ConsumerType != "guest.invite" && it.ConsumerType != "drive.access" {
		it.Payload = nil
	}
	return it, err
}

const approvalSelectCols = `
	id, consumer_type, subject, status, requester_user_id,
	approver_kind, approver_ref, created_at, expires_at,
	decided_at, decided_by_user_id, decision_comment,
	CASE WHEN consumer_type='drive.access' THEN COALESCE((
	  SELECT jsonb_build_object(
	    'nodeId',d.node_id::text,'spaceId',d.space_id::text,
	    'requestedCapabilities',to_jsonb(d.requested_capabilities),
	    'requestedPropagation',d.requested_propagation,
	    'requestedExpiresAt',d.requested_expires_at,
	    'requestedMaxUses',d.requested_max_uses,
	    'emergency',d.emergency,'reason',d.reason,
	    'expectedEpoch',d.expected_epoch::text,'grantId',
	      CASE WHEN d.grant_id IS NULL THEN NULL ELSE d.grant_id::text END)
	  FROM drive_access_request_details d
	  WHERE d.request_id=approval_requests.id
	), '{}'::jsonb) ELSE payload END AS payload`

// ListMyApprovals implements GET /me/approvals.
// Returns two lists: pending requests where the caller is the designated
// approver (pendingForMe) and all requests the caller submitted (myRequests).
// Visibility is fenced by an explicit application-level
// requester-or-authorized-approver predicate inside each query's WHERE (R1 —
// no check-then-filter window); dbscope.RunUserScoped still pins the tenant
// GUC and the approval_requests FORCE RLS policy remains the second layer
// (package doc: the pre-flip runtime runs with RLS inert).
func (h *Handler) ListMyApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}

	var pendingForMe, myRequests []approvalItem
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		// pending-for-me: the visibility predicate below is the application-level
		// fence (RLS is INERT on the documented pre-flip runtime — DB_DSN is
		// superuser/owner/BYPASSRLS; DB_WORKER_DSN defaults to DB_DSN), in the
		// SAME WHERE as the read so fencing cannot be raced or forgotten (R1/R3).
		// It mirrors the V073 approval_requests_row_visibility policy and the
		// approval_decide BZ107 gate: the requester or the authorized approver —
		// the designated user, or an active member of the approver role group
		// (same admin_assignment_active gate the decide path applies). The
		// requester arm is redundant under IS DISTINCT FROM but keeps the
		// predicate the complete visibility fence on its own; the RLS policy
		// stays as the second layer after the flip.
		// IS DISTINCT FROM (not <>) excludes my own submissions (they belong in
		// myRequests) while keeping a NULL requester_user_id — every
		// mail.group_moderation request, whose sender is an external address —
		// visible to its moderator: NULL <> $1 is NULL (would silently drop it),
		// but it is never "my own" request.
		rows, err := tx.Query(ctx,
			`SELECT`+approvalSelectCols+`
			 FROM approval_requests
			 WHERE status = 'pending'
			   AND requester_user_id IS DISTINCT FROM $1
			   AND (
			     requester_user_id = $1
			     OR (approver_kind = 'user' AND approver_ref = $1)
			     OR (approver_kind = 'role_group' AND EXISTS (
			       SELECT 1 FROM public.admin_role_assignments ara
			        WHERE ara.role_group_id = approval_requests.approver_ref
			          AND ara.user_id = $1
			          AND (ara.expires_at IS NULL OR ara.expires_at > now())
			          AND public.admin_assignment_active(ara.eligible, ara.activated_until)))
			   )
			 ORDER BY created_at`, claims.UserID)
		if err != nil {
			return err
		}
		for rows.Next() {
			it, err := scanApprovalItem(rows)
			if err != nil {
				rows.Close()
				return err
			}
			pendingForMe = append(pendingForMe, it)
		}
		rows.Close()
		if rows.Err() != nil {
			return rows.Err()
		}

		// my-requests: everything I submitted, any status.
		rows2, err := tx.Query(ctx,
			`SELECT`+approvalSelectCols+`
			 FROM approval_requests
			 WHERE requester_user_id = $1
			 ORDER BY created_at DESC`, claims.UserID)
		if err != nil {
			return err
		}
		for rows2.Next() {
			it, err := scanApprovalItem(rows2)
			if err != nil {
				rows2.Close()
				return err
			}
			myRequests = append(myRequests, it)
		}
		rows2.Close()
		return rows2.Err()
	})
	if err != nil {
		httputil.WriteDBErr(w, r, h.logger, "ListMyApprovals failed", err)
		return
	}

	// Return empty arrays (not null) for clean JSON clients.
	if pendingForMe == nil {
		pendingForMe = []approvalItem{}
	}
	if myRequests == nil {
		myRequests = []approvalItem{}
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"pendingForMe": pendingForMe,
		"myRequests":   myRequests,
	})
}

// Decide implements POST /me/approvals/{id}/decide.
// Body: {"decision":"approve"|"deny","comment":"..."}
//
// Decision is validated BEFORE touching the DB: a bad decision value would
// otherwise hit BZ108 inside the reducer, which shadows the input error.
//
// Inside RunUserScoped, we first SELECT consumer_type to:
//  1. Confirm the request is visible to this user (RLS enforces — missing ⇒
//     opaque 404, no "exists but forbidden" oracle).
//  2. Route to the appropriate consumer wrapper (rbac_approval_decide for
//     rbac.jit_activation; mail_external_approval_decide for mail.external_send;
//     group_moderation_approval_decide for mail.group_moderation).
func (h *Handler) Decide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}

	var body struct {
		Decision      string   `json:"decision"`
		Comment       *string  `json:"comment,omitempty"`
		Capabilities  []string `json:"capabilities,omitempty"`
		Propagation   *string  `json:"propagation,omitempty"`
		ExpiresAt     *string  `json:"expiresAt,omitempty"`
		MaxUses       *int     `json:"maxUses,omitempty"`
		ExpectedEpoch *string  `json:"expectedEpoch,omitempty"`
	}
	if err := decodeApprovalJSON(w, r, 4096, &body); err != nil {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusBadRequest, Detail: "invalid JSON"})
		return
	}

	// Validate BEFORE the DB call (Task 2 carry-forward).
	if body.Decision != "approve" && body.Decision != "deny" {
		httputil.WriteProblem(w, r, &httputil.Problem{
			Status: http.StatusBadRequest,
			Detail: `decision must be "approve" or "deny"`,
		})
		return
	}

	var resultStatus string
	var workerConsumer string // set → decide runs on the worker pool after the scoped tx (package doc)
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		// RLS-scoped lookup: no row → opaque 404 (see package doc).
		var consumerType string
		if err := tx.QueryRow(ctx,
			`SELECT consumer_type FROM approval_requests WHERE id = $1`, id,
		).Scan(&consumerType); err == pgx.ErrNoRows {
			return errNotFound
		} else if err != nil {
			return err
		}

		switch consumerType {
		case "rbac.jit_activation":
			return tx.QueryRow(ctx,
				`SELECT rbac_approval_decide($1, $2, $3, $4)`,
				id, claims.UserID, body.Decision, body.Comment,
			).Scan(&resultStatus)
		case "hr.leave", "hr.expense":
			// Tenant tx — HR has no cross-tenant mail leg (pinned by routing_test.go),
			// same lane as rbac.jit_activation. Both kinds share one wrapper.
			return tx.QueryRow(ctx,
				`SELECT hr_approval_decide($1, $2, $3, $4)`,
				id, claims.UserID, body.Decision, body.Comment,
			).Scan(&resultStatus)
		case "drive.export":
			// Tenant tx — the V116 wrapper is SECURITY DEFINER and self-contained
			// (no cross-tenant mail replay; pinned by routing_test.go), same lane
			// as rbac.jit_activation/hr.*.
			return tx.QueryRow(ctx,
				`SELECT drive_export_approval_decide($1, $2, $3, $4)`,
				id, claims.UserID, body.Decision, body.Comment,
			).Scan(&resultStatus)
		case "drive.share":
			return tx.QueryRow(ctx,
				`SELECT drive_share_approval_decide($1, $2, $3, $4)`,
				id, claims.UserID, body.Decision, body.Comment,
			).Scan(&resultStatus)
		case "drive.access":
			var expiresAt *time.Time
			if body.ExpiresAt != nil {
				parsed, parseErr := time.Parse(time.RFC3339, *body.ExpiresAt)
				if parseErr != nil {
					return errInvalidDriveAccessDecision
				}
				expiresAt = &parsed
			}
			var expectedEpoch *int64
			if body.ExpectedEpoch != nil {
				parsed, parseErr := strconv.ParseInt(*body.ExpectedEpoch, 10, 64)
				if parseErr != nil || parsed < 0 {
					return errInvalidDriveAccessDecision
				}
				expectedEpoch = &parsed
			}
			if body.Decision == "approve" && expectedEpoch == nil {
				return errInvalidDriveAccessDecision
			}
			return tx.QueryRow(ctx, `
				SELECT (drive_access_approval_decide(
				  $1,$2,$3,$4,
				  COALESCE($5::text[],d.requested_capabilities),
				  COALESCE($6,d.requested_propagation),
				  COALESCE($7::timestamptz,d.requested_expires_at),
				  COALESCE($8,d.requested_max_uses),
				  $9
				))->>'status'
				FROM drive_access_request_details d
				WHERE d.request_id=$1`, id, claims.UserID, body.Decision, body.Comment,
				body.Capabilities, body.Propagation, expiresAt, body.MaxUses, expectedEpoch,
			).Scan(&resultStatus)
		case "mail.external_send":
			workerConsumer = "mail.external_send"
			return nil
		case "mail.group_moderation":
			workerConsumer = "mail.group_moderation"
			return nil
		case "guest.invite":
			workerConsumer = "guest.invite"
			return nil
		default:
			return errConsumerNotWired
		}
	})
	if err == nil && workerConsumer != "" {
		// Cross-tenant replay leg (send fan-out / group release / deny NDR) on
		// the WORKER (BYPASSRLS) pool — native-RLS W4 treatment; the reducer
		// self-authorizes p_actor and re-checks status='pending' atomically.
		// Every call below is a server-selected SQL literal, never request input.
		switch workerConsumer {
		case "mail.external_send":
			err = h.workerPool.QueryRow(ctx, `SELECT mail_external_approval_decide($1,$2,$3,$4)`,
				id, claims.UserID, body.Decision, body.Comment).Scan(&resultStatus)
		case "mail.group_moderation":
			err = h.workerPool.QueryRow(ctx, `SELECT group_moderation_approval_decide($1,$2,$3,$4)`,
				id, claims.UserID, body.Decision, body.Comment).Scan(&resultStatus)
		case "guest.invite":
			err = h.decideGuestInvite(ctx, id, claims.UserID, body.Decision, body.Comment, &resultStatus)
		}
	}

	switch {
	case err == nil:
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": resultStatus})
	case errors.Is(err, errNotFound):
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotFound, Detail: "approval request not found"})
	case errors.Is(err, errConsumerNotWired):
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusNotImplemented, Detail: "consumer type not yet wired"})
	case errors.Is(err, errInvalidDriveAccessDecision):
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusUnprocessableEntity, Detail: "invalid Drive access decision payload"})
	default:
		if h.mapApprovalErr(w, r, err) {
			return
		}
		h.logger.Error("Decide failed", "id", id, "actor", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
	}
}

func (h *Handler) decideGuestInvite(ctx context.Context, id, actor int64, decision string, comment *string, resultStatus *string) error {
	tx, err := h.workerDB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var guestID, requesterID *int64
	var invitedEmail *string
	if err := tx.QueryRow(ctx,
		`SELECT status,guest_user_id,invited_email,requester_user_id
		   FROM guest_invite_approval_decide($1,$2,$3,$4)`, id, actor, decision, comment,
	).Scan(resultStatus, &guestID, &invitedEmail, &requesterID); err != nil {
		return err
	}
	var prepared guestinvite.Prepared
	if *resultStatus == "applied" {
		if guestID == nil || requesterID == nil || invitedEmail == nil {
			return errors.New("guest invite apply returned incomplete result")
		}
		prepared, err = guestinvite.Prepare(ctx, tx, *requesterID, *guestID)
		if err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if *resultStatus == "applied" {
		if err := guestinvite.Send(ctx, h.workerDB, h.guestInviteMC, h.guestInviteBucket, prepared, *invitedEmail); err != nil && h.logger != nil {
			// Never attach the transport error: some senders embed the MIME body,
			// including the raw invite token. The committed invite stays pending.
			h.logger.Error("guest invite email failed", "request_id", id, "error", "send_failed")
		}
	}
	return nil
}

func (h *Handler) writeApprovalDBErr(w http.ResponseWriter, r *http.Request, message string, err error) {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}
	httputil.WriteDBErr(w, r, logger, message, err)
}

// Cancel implements POST /me/approvals/{id}/cancel. Engine-level (all
// consumers, never per-consumer) — the requester withdraws their own request
// while it is still pending. approval_request_cancel self-authorizes p_actor
// (BZ125: not found / not the requester / not pending — deliberately
// indistinguishable, no ownership oracle, same posture as BZ108), so this
// handler does no visibility pre-check the way Decide does: RunUserScoped
// still pins the tenant GUC, but the reducer's WHERE clause is the actual
// authorization boundary.
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims := auth.UserFromContext(ctx)
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return
	}

	id, ok := httputil.ParseIDPath(w, r, "id", "invalid id")
	if !ok {
		return
	}

	var resultStatus string
	err := dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT approval_request_cancel($1, $2)`,
			id, claims.UserID,
		).Scan(&resultStatus)
	})

	switch {
	case err == nil:
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": resultStatus})
	default:
		if h.mapApprovalErr(w, r, err) {
			return
		}
		h.logger.Error("Cancel failed", "id", id, "actor", claims.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "database error"})
	}
}

// mapApprovalErr maps reducer business errors from the approval reducers to
// HTTP problem responses via the shared reducererr projection (c6). Returns
// true if the error was handled; unclassified errors return false (the caller
// keeps its 500 "database error" fallback).
//
// BZ106 → 409 Conflict      (SoD: requester cannot decide own request)
// BZ107 → 403 Forbidden     (actor is not the designated approver)
// BZ108 → 409 Conflict      (request not found, not pending, or bad decision)
// BZ109 → 422 Unprocessable (no approver resolved — reserved, currently unreachable)
// BZ110 → 409 Conflict      (assignment no longer eligible at apply time)
// BZ124 → 400 Bad Request   (SubmitHR: leave/expense form validation)
// BZ125 → 404 Not Found     (Cancel: not found / not the requester / not pending)
// BZ126 → 400 Bad Request   (SubmitHR: receipt_sha256 not found in blobs)
//
// The BZ10x/BZ124/BZ126 messages are in reducererr's Detail passthrough
// allowlist (BZ125 excepted — opaque, class fallback), so the reducer wording
// still reaches the client unchanged where it's meant to. (arch #A1: this
// classify-and-write body is now the shared reducererr.WriteClassified.)
func (h *Handler) mapApprovalErr(w http.ResponseWriter, r *http.Request, err error) bool {
	return reducererr.WriteClassified(w, r, err)
}
