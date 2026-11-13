// Package delivery is the single per-recipient outbound delivery read contract
// shared by the user trace path (internal/user/trace.go) and the admin trace
// path (internal/admin/admin_trace.go). It owns the delivery_attempts shapes,
// the outcome→status / queue→verdict maps, the problems-first sort, and the
// BINDING DISTINCT-ON query helpers — so the two read paths cannot drift.
//
// The query helpers make the mailbox_id filter OPTIONAL: the user path passes a
// non-nil mailbox to preserve ownership-by-filter; the admin path passes nil for
// the cross-mailbox read (RBAC replaces the per-mailbox ownership filter).
package delivery

import (
	"sort"
	"time"
)

// Attempt is one append-only delivery_attempts row, surfaced to the client as
// the per-recipient attempt history. Field names (JSON tags) match delivery.ts.
type Attempt struct {
	N        int        `json:"n"`
	At       *time.Time `json:"at"`
	MxHost   *string    `json:"mxHost"`
	SmtpCode *int       `json:"smtpCode"`
	SmtpText *string    `json:"smtpText"`
	Outcome  string     `json:"outcome"`
	TLS      bool       `json:"tls"`
}

// Recipient is the current per-recipient delivery state plus its full attempt
// history. Status is derived from the LATEST attempt (or queued when no attempt
// exists yet). Field names (JSON tags) match delivery.ts Recipient.
type Recipient struct {
	Email         string     `json:"email"`
	Status        string     `json:"status"`
	MxHost        *string    `json:"mxHost"`
	DeliveredAt   *time.Time `json:"deliveredAt"`
	NextAttemptAt *time.Time `json:"nextAttemptAt"`
	LastSmtpCode  *int       `json:"lastSmtpCode"`
	LastSmtpText  *string    `json:"lastSmtpText"`
	Attempts      []Attempt  `json:"attempts"`
}

// LatestRow is the DISTINCT-ON current state of a recipient (its newest attempt).
type LatestRow struct {
	MxHost  *string
	Code    *int
	Text    *string
	At      *time.Time
	Outcome string
}

// MapRecipientStatus maps a delivery_attempts.outcome to the per-recipient
// status. 'error' is a transient failure → deferred (will retry).
func MapRecipientStatus(outcome string) string {
	switch outcome {
	case "accepted":
		return "delivered"
	case "rejected":
		return "bounced"
	case "deferred", "error":
		return "deferred"
	default:
		return "queued"
	}
}

// MapOverallStatus maps the outbound_queue.status to the overall verdict the
// frontend digest renders. The queue status enum is the source of truth.
func MapOverallStatus(queueStatus string) string {
	switch queueStatus {
	case "delivered":
		return "delivered"
	case "bounced":
		return "bounced"
	case "deferred":
		return "deferred"
	case "sending":
		return "sending"
	case "pending":
		return "queued"
	default:
		return queueStatus
	}
}

// IsTerminalStatus reports whether the overall verdict is a settled outcome
// whose per-recipient detail could have been pruned (retention skew). A pending/
// sending/deferred send is still in flight and legitimately has no attempts yet.
func IsTerminalStatus(overallStatus string) bool {
	return overallStatus == "delivered" || overallStatus == "bounced"
}

// StatusRank orders recipient statuses problems-first (D-D1): the row to act on
// lands at the top. Lower rank sorts first.
func StatusRank(status string) int {
	switch status {
	case "bounced":
		return 0
	case "deferred":
		return 1
	case "sending":
		return 2
	case "queued":
		return 3
	case "delivered":
		return 4
	default:
		return 5
	}
}

// SortProblemsFirst sorts recipients bounced → deferred → sending → queued →
// delivered, then email asc (D-D1). Server-side; the client renders as-is.
func SortProblemsFirst(recips []Recipient) {
	sort.SliceStable(recips, func(i, j int) bool {
		ri, rj := StatusRank(recips[i].Status), StatusRank(recips[j].Status)
		if ri != rj {
			return ri < rj
		}
		return recips[i].Email < recips[j].Email
	})
}
