package caldav

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
)

// ── Batch admission bounds (er5-s15, sealed anchor freebusy-batch-endpoint-
// allows-quadratic-and-database-amplified-resource-consumption) ──

const (
	// maxFreeBusyBatchBodyBytes bounds the JSON body before decode
	// (http.MaxBytesReader, telemetry/admin-config precedent). Without it the
	// decoder buffers an arbitrarily large request before Validate could
	// reject its shape.
	maxFreeBusyBatchBodyBytes = 64 << 10

	// maxFreeBusyBatchEntities caps the combined user+room entity count per
	// batch. The reducer loops per entity and the handler enriches per result
	// with one follow-up query, so entity count is the multiplier of the
	// endpoint's per-request database work.
	maxFreeBusyBatchEntities = 100

	// maxFreeBusyBatchWindow bounds the requested [start,end) span. Busy
	// projection expands RRULE recurrences across the whole window per
	// entity (calendar_busy_intervals), so an unbounded window turns one
	// request into an unbounded recurrence-expansion workload.
	maxFreeBusyBatchWindow = 366 * 24 * time.Hour
)

// ── Request / Response types ──

// FreeBusyBatchRequest is the JSON body for POST /caldav/freebusy/batch.
type FreeBusyBatchRequest struct {
	UserIDs []int64 `json:"user_ids"`
	RoomIDs []int64 `json:"room_ids"`
	Start   string  `json:"start"` // ISO 8601
	End     string  `json:"end"`   // ISO 8601
}

// Validate checks the request for required fields and semantic correctness.
func (r *FreeBusyBatchRequest) Validate() error {
	if len(r.UserIDs) == 0 && len(r.RoomIDs) == 0 {
		return fmt.Errorf("at least one user_id or room_id is required")
	}
	if len(r.UserIDs)+len(r.RoomIDs) > maxFreeBusyBatchEntities {
		return fmt.Errorf("batch is limited to %d entities per request", maxFreeBusyBatchEntities)
	}
	if r.Start == "" {
		return fmt.Errorf("start is required")
	}
	if r.End == "" {
		return fmt.Errorf("end is required")
	}

	start, err := time.Parse(time.RFC3339, r.Start)
	if err != nil {
		return fmt.Errorf("invalid start: %w", err)
	}
	end, err := time.Parse(time.RFC3339, r.End)
	if err != nil {
		return fmt.Errorf("invalid end: %w", err)
	}
	if !start.Before(end) {
		return fmt.Errorf("start must be before end")
	}
	if end.Sub(start) > maxFreeBusyBatchWindow {
		return fmt.Errorf("free/busy window is limited to %d days per request", int(maxFreeBusyBatchWindow/(24*time.Hour)))
	}
	return nil
}

// FreeBusyEntityResult holds the busy intervals for one user or room.
type FreeBusyEntityResult struct {
	EntityID  string         `json:"entity_id"`
	Email     string         `json:"email"`
	Type      string         `json:"type"` // "user" or "room"
	Intervals []BusyInterval `json:"intervals"`
}

// FreeBusyBatchResponse is the JSON response for POST /caldav/freebusy/batch.
type FreeBusyBatchResponse struct {
	Results []FreeBusyEntityResult `json:"results"`
}

// ── Handler ──

// FreeBusy handles POST /calendar/free-busy — room booking batch free/busy endpoint.
// Accepts a JSON body with user_ids, room_ids, start, end and returns
// aggregated free/busy intervals for all requested entities.
//
// Auth: RequireAuth middleware must be applied before this handler.
func (h *Handler) FreeBusy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		h.logger.Warn("freebusy batch without auth")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	var req FreeBusyBatchRequest
	// Decode under a byte cap: an unbounded json.Decoder would buffer the
	// whole request before Validate can reject its shape.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxFreeBusyBatchBodyBytes)).Decode(&req); err != nil {
		h.logger.Warn("freebusy batch bad request", "error", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if err := req.Validate(); err != nil {
		h.logger.Warn("freebusy batch validation failed", "error", err)
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	start, _ := time.Parse(time.RFC3339, req.Start)
	end, _ := time.Parse(time.RFC3339, req.End)

	// calendar_free_busy_multi's p_account_id is the caller's PRIMARY MAILBOX
	// id (parseAccountID id space — the reducer's own ADR-003 note), never a
	// users.id. Passing the raw users.id made the reducer either fail its
	// mailbox-existence check (spurious BZ001/500) or — when the numeric
	// users.id collided with an existing mailbox — resolve the VIEWER to an
	// unrelated principal, so sharing.defaults ACL decisions (and the busy
	// data they admit) were evaluated as the wrong user (sealed anchor
	// freebusy-authorization-evaluates-the-caller-as-the-owner-of-an-
	// unrelated-mailbox-id). Resolve the canonical primary mailbox like the
	// free-busy-query REPORT path does (caldav.go handleFreeBusyQuery).
	callerMailboxID, err := identity.ResolvePrimaryMailbox(ctx, h.pool, user.UserID)
	if err != nil {
		h.logger.Warn("freebusy batch caller scope resolution failed", "user_id", user.UserID, "error", err)
		httputil.WriteJSON(w, http.StatusForbidden, map[string]string{
			"error": "no primary mailbox for caller",
		})
		return
	}

	// Combine user and room IDs for the batch query
	allIDs := append(req.UserIDs, req.RoomIDs...)

	// Call the calendar_free_busy_multi reducer
	var raw json.RawMessage
	err = h.pool.QueryRow(ctx,
		`SELECT calendar_free_busy_multi($1, $2, $3, $4)`,
		callerMailboxID, // p_account_id: the caller's primary mailbox (mailbox id space)
		allIDs,
		start,
		end,
	).Scan(&raw)
	if err != nil {
		h.logger.Error("freebusy batch query failed", "error", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "free/busy query failed",
		})
		return
	}

	// Parse results from the reducer
	var results []FreeBusyEntityResult
	if err := json.Unmarshal(raw, &results); err != nil {
		h.logger.Error("freebusy batch json parse failed", "error", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to parse free/busy data",
		})
		return
	}

	// Enrich results with email addresses
	for i, result := range results {
		var email string
		h.pool.QueryRow(ctx,
			`SELECT COALESCE(
				(SELECT email FROM users u JOIN mailboxes m ON m.user_id = u.id WHERE m.id = $1::bigint),
				(SELECT name || '@resources' FROM calendars WHERE id = $1::bigint)
			)`,
			result.EntityID,
		).Scan(&email)

		if email != "" {
			results[i].Email = email
		}

		// Determine entity type
		for _, rid := range req.RoomIDs {
			if fmt.Sprintf("%d", rid) == result.EntityID {
				results[i].Type = "room"
				break
			}
		}
		if results[i].Type == "" {
			results[i].Type = "user"
		}
	}

	resp := FreeBusyBatchResponse{Results: results}
	httputil.WriteJSON(w, http.StatusOK, resp)
}
