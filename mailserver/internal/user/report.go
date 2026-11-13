package user

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// SpamEnqueuer accepts spam-training feedback signals. Implemented by
// *spam.Trainer; kept as a narrow interface (rather than importing the spam
// package here) so report.go stays decoupled and tests can fake it without a
// DB/NOTIFY pipeline.
type SpamEnqueuer interface {
	Enqueue(userID int64, messageID int64, isSpam bool)
}

// ReportHandler provides user self-service spam/phishing reporting.
type ReportHandler struct {
	pool     *pgxpool.Pool
	logger   *slog.Logger
	trainer  SpamEnqueuer
	features senderControlFeatureGate
}

func (h *ReportHandler) SetSenderControlGate(features senderControlFeatureGate) {
	h.features = features
}

// NewReportHandler creates a new ReportHandler. trainer may be nil (training
// feedback is then skipped, e.g. in tests that don't exercise it).
func NewReportHandler(pool *pgxpool.Pool, logger *slog.Logger, trainer SpamEnqueuer) *ReportHandler {
	return &ReportHandler{pool: pool, logger: logger, trainer: trainer}
}

// reportRequest is the expected JSON body for POST /report.
type reportRequest struct {
	EmailID string `json:"emailId"`
	Type    string `json:"type"`
	Note    string `json:"note,omitempty"`
}

// Report handles POST /report — user submits a spam, phishing, or concern report.
func (h *ReportHandler) Report(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		httputil.WriteProblemStatus(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if h.features != nil && h.features.IsEnabled(toggle.FeatureSenderControlCenter) {
		httputil.WriteProblemStatus(w, http.StatusConflict, "use the message-bound sender control report action")
		return
	}

	var req reportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.EmailID == "" {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "emailId is required")
		return
	}

	switch req.Type {
	case "spam", "phishing", "concern":
		// valid
	default:
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid type; must be spam, phishing, or concern"})
		return
	}

	// Convert emailId to int64 for target_id.
	emailID, err := strconv.ParseInt(req.EmailID, 10, 64)
	if err != nil {
		httputil.WriteProblemStatus(w, http.StatusBadRequest, "invalid emailId")
		return
	}

	// R1/R3 ownership: the report (audit row + spam-training signal) may only
	// reference a message in the CALLER'S own mailbox. ResolveOwnedMessage is
	// this package's shared mailbox->user ownership resolve; before this bound
	// the legacy endpoint accepted any message ID, so a caller could attach
	// another tenant's message to an audit action and feed a foreign message
	// into the trainer. Unknown or foreign IDs read identically as 404 — no
	// cross-tenant existence oracle.
	if _, err := ResolveOwnedMessage(r.Context(), h.pool, emailID, user.UserID); err != nil {
		if h.logger != nil && !errors.Is(err, pgx.ErrNoRows) {
			h.logger.Error("report: resolve owned message failed", "error", err)
		}
		httputil.WriteProblemStatus(w, http.StatusNotFound, "message not found")
		return
	}

	note := req.Note
	if note == "" {
		note = "User-reported " + req.Type
	}

	action := "report_" + req.Type
	err = audit.Write(r.Context(), h.pool, audit.Entry{
		Actor: user.UserID, Action: action, TargetType: "message", TargetID: &emailID,
		Notes: note, Tier: audit.TierForAction(action),
	})
	if err != nil {
		if h.logger != nil {
			h.logger.Error("report insert failed", "error", err)
		}
		httputil.WriteProblemStatus(w, http.StatusInternalServerError, "database error")
		return
	}

	// A "spam" report is a training signal, same as moving a message to the
	// Spam folder (which trains via the message_tags trigger) — without this,
	// report-spam was audit-log-only and never reached the trainer.
	// "phishing"/"concern" aren't spam/ham labels, so they don't train.
	if req.Type == "spam" && h.trainer != nil {
		h.trainer.Enqueue(user.UserID, emailID, true)
	}

	httputil.WriteJSON(w, http.StatusCreated, map[string]string{"status": "reported", "type": req.Type})
}
